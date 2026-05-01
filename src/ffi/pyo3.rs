//! PyO3 bindings — the lens's FastAPI integration path (FSD §3.5).
//!
//! # Mission alignment (MISSION.md §2 — `ffi/`)
//!
//! The Phase 1 deployment shape is:
//!
//! ```text
//! agent → POST /api/v1/accord/events → FastAPI handler →
//!   ciris_persist::Engine.receive_and_persist(bytes) → Postgres
//! ```
//!
//! The lens's existing `cirislens-core` scrubber wires in via the
//! Engine constructor's `scrubber` callable parameter. Synchronous
//! from Python's view (FastAPI handler calls and gets a typed
//! result); internally async via a single tokio runtime cached on
//! the Engine instance.
//!
//! Mission constraint (MISSION.md §3 anti-pattern #4): typed errors
//! cross the FFI boundary as Python exceptions with structured
//! detail. No silent coercion; no opaque strings.

use std::sync::Arc;

use ciris_keyring::{get_platform_signer, is_hardware_available, HardwareSigner};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use tokio::runtime::Runtime;

use crate::ingest::{IngestError, IngestPipeline};
use crate::scrub::{NullScrubber, ScrubError, Scrubber};
use crate::store::{Backend, PostgresBackend};
use crate::verify::PythonJsonDumpsCanonicalizer;

/// `ciris_persist.Engine` — one instance per (DSN, scrubber)
/// configuration.
///
/// Holds the Postgres pool and the tokio runtime. Method calls are
/// synchronous from Python's perspective; internally they
/// `block_on` the runtime so the FastAPI thread that called us can
/// hand off to other workers via `py.allow_threads`.
#[pyclass(name = "Engine", module = "ciris_persist")]
pub struct PyEngine {
    backend: Arc<PostgresBackend>,
    runtime: Arc<Runtime>,
    scrubber: Arc<dyn Scrubber>,
    signer: Arc<dyn HardwareSigner>,
    signer_key_id: String,
}

#[pymethods]
impl PyEngine {
    /// Connect to Postgres, run migrations, instantiate the
    /// scrub-signing key via ciris-keyring (idempotent — generates
    /// if missing, returns existing otherwise), and build the
    /// ingest pipeline.
    ///
    /// **BREAKING CHANGE from v0.1.2**: `signing_key_id` is now
    /// REQUIRED. The v0.1.2 "no-key" path is gone — every persisted
    /// row carries a cryptographic scrub envelope (FSD §3.3 step
    /// 3.5; THREAT_MODEL.md AV-24). Same-key principle: agent
    /// deployments point this at the agent's existing wire-format
    /// §8 signing key id; lens deployments use a lens-owned id like
    /// `lens-scrub-v1`.
    ///
    /// **One key, three roles** (PoB §3.2): the signing key here is
    /// also the deployment's Reticulum destination address (when
    /// Phase 2.3 lands) and the registry-published public key.
    ///
    /// Raises `RuntimeError` if Postgres is unreachable, migrations
    /// fail, or the keyring is inaccessible.
    #[new]
    #[pyo3(signature = (dsn, signing_key_id, scrubber=None))]
    fn new(
        py: Python<'_>,
        dsn: &str,
        signing_key_id: &str,
        scrubber: Option<Py<PyAny>>,
    ) -> PyResult<Self> {
        // Build a multi-thread runtime once per Engine instance.
        let runtime =
            Runtime::new().map_err(|e| PyRuntimeError::new_err(format!("tokio runtime: {e}")))?;
        let runtime = Arc::new(runtime);

        // Connect + migrate inside the runtime.
        let backend = py.detach(|| {
            runtime.block_on(async {
                let backend = PostgresBackend::connect(dsn)
                    .await
                    .map_err(|e| PyRuntimeError::new_err(format!("connect: {e}")))?;
                backend
                    .run_migrations()
                    .await
                    .map_err(|e| PyRuntimeError::new_err(format!("migrations: {e}")))?;
                Ok::<_, PyErr>(Arc::new(backend))
            })
        })?;

        // ciris-keyring: hardware-backed signer where available,
        // SoftwareSigner fallback otherwise. get_platform_signer
        // is idempotent: returns existing key if present, generates
        // and stores under the alias if not.
        //
        // v0.1.6 — log the variant chosen at construction so ops can
        // see in deployment logs whether the deployment is on the
        // hardware path or the software fallback. Per-batch latency
        // tax (~30 µs vs ~100 µs per sign) and security tier
        // (UNLICENSED_COMMUNITY when software-fallback) both depend
        // on this. SECURITY_AUDIT_v0.1.4.md §3.4.
        let signer_key_id_owned = signing_key_id.to_owned();
        let hardware_available = is_hardware_available();
        let signer = py.detach(|| {
            get_platform_signer(&signer_key_id_owned)
                .map_err(|e| PyRuntimeError::new_err(format!("ciris-keyring: {e}")))
        })?;
        tracing::info!(
            signing_key_id = signer_key_id_owned.as_str(),
            hardware_backed = hardware_available,
            variant = if hardware_available {
                "hardware"
            } else {
                "software"
            },
            "ciris-persist: signer initialised"
        );
        let signer: Arc<dyn HardwareSigner> = Arc::from(signer);

        // Wrap the scrubber. None → NullScrubber (mission constraint:
        // explicit choice; the caller knows their trace_level).
        let scrubber: Arc<dyn Scrubber> = match scrubber {
            None => Arc::new(NullScrubber),
            Some(callable) => Arc::new(PyCallableScrubber {
                callable: Arc::new(callable),
            }),
        };

        Ok(PyEngine {
            backend,
            runtime,
            scrubber,
            signer,
            signer_key_id: signing_key_id.to_owned(),
        })
    }

    /// Return the deployment's Ed25519 public key (base64) — for
    /// publishing to the registry / lens-discovery layer at deploy
    /// time. Same key that signs every persisted row's scrub
    /// envelope; same key that becomes the Reticulum destination
    /// when Phase 2.3 lands (one key, three roles).
    fn public_key_b64(&self, py: Python<'_>) -> PyResult<String> {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        let signer = self.signer.clone();
        let runtime = self.runtime.clone();
        py.detach(|| {
            runtime.block_on(async move {
                let bytes = signer
                    .public_key()
                    .await
                    .map_err(|e| PyRuntimeError::new_err(format!("public_key: {e}")))?;
                Ok::<_, PyErr>(BASE64.encode(bytes))
            })
        })
    }

    /// Register the agent's Ed25519 public key for verification.
    ///
    /// Maps the wire-level `signature_key_id` to the lens-canonical
    /// `key_id` column (THREAT_MODEL.md AV-11; v0.1.2 Path B
    /// reconciliation).
    ///
    /// Parameters:
    /// - `signature_key_id` — the same string the agent ships on
    ///   every CompleteTrace's `signature_key_id` field. Becomes
    ///   `accord_public_keys.key_id` in storage.
    /// - `public_key_b64` — the agent's 32-byte Ed25519 verifying
    ///   key in standard base64. Becomes
    ///   `accord_public_keys.public_key_base64` in storage.
    /// - `algorithm` — defaults to `"Ed25519"` (the only supported
    ///   shape in v0.1.x; multi-algorithm hybrid PoB §6 is Phase 2+).
    /// - `description` — free-form annotation; visible in
    ///   admin tooling.
    /// - `expires_at` — optional ISO-8601 timestamp; if set, the
    ///   key stops verifying after that point. Maps to
    ///   `accord_public_keys.expires_at`.
    /// - `added_by` — operator / process annotation for audit.
    ///
    /// Idempotent: re-registering the same `signature_key_id`
    /// is a no-op (ON CONFLICT DO NOTHING). For genuine key
    /// rotation, use the lens's revocation surface (set
    /// `revoked_at` on the old row, register a new row with a
    /// different `signature_key_id`). Mission constraint
    /// (MISSION.md §3 anti-pattern #3): no automated key rotation
    /// under attacker control.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (signature_key_id, public_key_b64,
                        algorithm = None, description = None,
                        expires_at = None, added_by = None))]
    fn register_public_key(
        &self,
        py: Python<'_>,
        signature_key_id: &str,
        public_key_b64: &str,
        algorithm: Option<&str>,
        description: Option<&str>,
        expires_at: Option<&str>,
        added_by: Option<&str>,
    ) -> PyResult<()> {
        let backend = self.backend.clone();
        let runtime = self.runtime.clone();
        let key_id = signature_key_id.to_owned();
        let pub_b64 = public_key_b64.to_owned();
        let algo = algorithm.unwrap_or("Ed25519").to_owned();
        let desc = description.map(str::to_owned);
        let added = added_by.map(str::to_owned);

        // Parse expires_at ISO-8601 → DateTime<Utc>; reject
        // malformed values upfront (typed error preferred over
        // letting the SQL layer choke).
        let expires_dt: Option<chrono::DateTime<chrono::Utc>> = match expires_at {
            None => None,
            Some(s) => Some(s.parse().map_err(|e| {
                PyValueError::new_err(format!("expires_at must be ISO-8601 (got {s:?}): {e}"))
            })?),
        };

        py.detach(|| {
            runtime.block_on(async move {
                let client = backend
                    .pool()
                    .get()
                    .await
                    .map_err(|e| PyRuntimeError::new_err(format!("pool: {e}")))?;
                client
                    .execute(
                        "INSERT INTO cirislens.accord_public_keys \
                         (key_id, public_key_base64, algorithm, description, \
                          expires_at, added_by) \
                         VALUES ($1, $2, $3, $4, $5, $6) \
                         ON CONFLICT (key_id) DO NOTHING",
                        &[&key_id, &pub_b64, &algo, &desc, &expires_dt, &added],
                    )
                    .await
                    .map_err(|e| PyRuntimeError::new_err(format!("register: {e}")))?;
                Ok::<_, PyErr>(())
            })
        })
    }

    /// Run the FSD §3.3 pipeline on a batch body.
    ///
    /// Returns a Python dict with the BatchSummary fields. Raises
    /// `ValueError` for schema/verify/scrub rejections (lens
    /// translates to 4xx) and `RuntimeError` for backend issues
    /// (lens translates to 5xx).
    fn receive_and_persist<'py>(
        &self,
        py: Python<'py>,
        body: &Bound<'py, PyBytes>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let bytes = body.as_bytes().to_vec();
        let backend = self.backend.clone();
        let scrubber = self.scrubber.clone();
        let signer = self.signer.clone();
        let signer_key_id = self.signer_key_id.clone();
        let runtime = self.runtime.clone();

        let summary = py.detach(|| {
            runtime.block_on(async move {
                let pipeline = IngestPipeline {
                    backend: &*backend,
                    canonicalizer: &PythonJsonDumpsCanonicalizer,
                    scrubber: &*scrubber,
                    signer: &*signer,
                    signer_key_id: &signer_key_id,
                };
                pipeline.receive_and_persist(&bytes).await
            })
        });

        match summary {
            Ok(s) => {
                let dict = PyDict::new(py);
                dict.set_item("envelopes_processed", s.envelopes_processed)?;
                dict.set_item("trace_events_inserted", s.trace_events_inserted)?;
                dict.set_item("trace_events_conflicted", s.trace_events_conflicted)?;
                dict.set_item("trace_llm_calls_inserted", s.trace_llm_calls_inserted)?;
                dict.set_item("scrubbed_fields", s.scrubbed_fields)?;
                dict.set_item("signatures_verified", s.signatures_verified)?;
                Ok(dict)
            }
            // THREAT_MODEL.md AV-15: sanitize at the FFI boundary.
            // Verbose `Display` form (which may include
            // attacker-supplied content) goes to tracing logs; the
            // Python exception carries only the stable kind token.
            // The lens HTTP layer maps token → status code.
            Err(e) => {
                let kind = e.kind();
                tracing::warn!(error = %e, kind = kind, "ingest rejected");
                match e {
                    // Schema / verify / scrub → ValueError (caller-fault; 4xx).
                    IngestError::Schema(_) | IngestError::Verify(_) | IngestError::Scrub(_) => {
                        Err(PyValueError::new_err(kind))
                    }
                    // Store / Sign → RuntimeError (server-fault; 5xx).
                    // AV-25: signing failure is operator-side
                    // (keyring locked, hardware unavailable, etc.) —
                    // never the agent's fault, never a 4xx.
                    IngestError::Store(_) | IngestError::Sign(_) => {
                        Err(PyRuntimeError::new_err(kind))
                    }
                }
            }
        }
    }
}

/// Scrubber bridge: wraps a Python callable in the [`Scrubber`]
/// trait. The callable receives the JSON-equivalent envelope dict
/// and returns `(scrubbed_dict, modified_count)`.
struct PyCallableScrubber {
    callable: Arc<Py<PyAny>>,
}

impl Scrubber for PyCallableScrubber {
    fn scrub_batch(&self, env: &mut crate::schema::BatchEnvelope) -> Result<usize, ScrubError> {
        // Bypass GENERIC at this layer too; mission constraint
        // (MISSION.md §2 — `scrub/`): GENERIC has no content text.
        if env.trace_level == crate::schema::TraceLevel::Generic {
            return Ok(0);
        }
        let value = serde_json::to_value(&*env)?;
        Python::attach(|py| {
            let value_str = serde_json::to_string(&value)?;
            // Hand the dict to Python via json.loads so the callable
            // sees a real Python dict, not a serialized string.
            let json_mod = py
                .import("json")
                .map_err(|e| ScrubError::External(format!("import json: {e}")))?;
            let py_obj = json_mod
                .call_method1("loads", (value_str,))
                .map_err(|e| ScrubError::External(format!("json.loads: {e}")))?;
            let result = self
                .callable
                .bind(py)
                .call1((py_obj,))
                .map_err(|e| ScrubError::External(format!("scrubber call: {e}")))?;
            // Expect (scrubbed_dict, modified_count).
            let tuple: (Py<PyAny>, usize) = result
                .extract()
                .map_err(|e| ScrubError::External(format!("scrubber return shape: {e}")))?;
            // json.dumps on the returned dict.
            let dumped = json_mod
                .call_method1("dumps", (tuple.0,))
                .map_err(|e| ScrubError::External(format!("json.dumps: {e}")))?;
            let s: String = dumped
                .extract()
                .map_err(|e| ScrubError::External(format!("dumps extract: {e}")))?;
            let new_value: serde_json::Value = serde_json::from_str(&s)?;
            let new_env: crate::schema::BatchEnvelope =
                serde_json::from_value(new_value).map_err(ScrubError::Internal)?;

            // Same schema-preservation gates as CallbackScrubber.
            if new_env.trace_schema_version != env.trace_schema_version {
                return Err(ScrubError::External(
                    "scrubber altered trace_schema_version — rejected".into(),
                ));
            }
            if new_env.trace_level != env.trace_level {
                return Err(ScrubError::External(
                    "scrubber altered trace_level — rejected".into(),
                ));
            }
            if new_env.events.len() != env.events.len() {
                return Err(ScrubError::External(
                    "scrubber altered events[] count — rejected".into(),
                ));
            }
            *env = new_env;
            Ok(tuple.1)
        })
    }
}

/// `ciris_persist` Python module entry point. The build script
/// (maturin) generates the C entry that Python imports.
#[pymodule]
fn ciris_persist(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyEngine>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add(
        "SUPPORTED_SCHEMA_VERSIONS",
        crate::schema::SUPPORTED_VERSIONS.to_vec(),
    )?;
    Ok(())
}
