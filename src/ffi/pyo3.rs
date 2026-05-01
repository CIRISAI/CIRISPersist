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

use ciris_keyring::{
    get_platform_signer, is_hardware_available, HardwareSigner, KeyringScope, StorageDescriptor,
};
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

        // v0.1.9 — boot-time storage check using ciris-keyring v1.8.0's
        // `HardwareSigner::storage_descriptor()` trait method. Replaces
        // the v0.1.7 prediction shim that replicated upstream's
        // `default_key_dir()` logic in our crate (brittle on tag drift).
        //
        // The descriptor is the authoritative source: it tells us
        // exactly where the key lives. We dispatch on the typed enum:
        //
        // - `Hardware { .. }` — no warn; HSM-backed keys are stable
        //   by construction. blob_path (when present) is a wrapped
        //   envelope; deletion means "key is gone," not "ephemeral."
        // - `SoftwareFile { path }` — warn if path matches the
        //   container-writable-layer heuristic. Suppress via
        //   `CIRIS_PERSIST_KEYRING_PATH_OK=1` after operator audit.
        // - `SoftwareOsKeyring { scope: User }` — warn: user-scope
        //   secret-service entries disappear at logout; not suitable
        //   for longitudinal-score primitives.
        // - `SoftwareOsKeyring { scope: System | Unknown }` — info-level
        //   only; system-scope survives reboot.
        // - `InMemory` — warn hard: RAM-only signer in production
        //   means identity dies with the process.
        let descriptor = signer.storage_descriptor();
        let suppress = std::env::var("CIRIS_PERSIST_KEYRING_PATH_OK").is_ok();
        check_storage_descriptor(&descriptor, &signer_key_id_owned, suppress);

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

    /// v0.1.9 — return the **authoritative** seed-storage path for
    /// observability surfaces (lens `/health`).
    ///
    /// Backed by `HardwareSigner::storage_descriptor()` (ciris-keyring
    /// v1.8.0). Returns:
    /// - `None` for `Hardware` variants without a wrapped-envelope
    ///   path (iOS Secure Enclave, Windows Platform Crypto Provider)
    ///   and for `SoftwareOsKeyring` / `InMemory` (no filesystem path).
    /// - `Some(path)` for `Hardware` variants that store a wrapped
    ///   envelope on disk (Android Keystore, TPM-wrapped Ed25519) and
    ///   for `SoftwareFile`.
    ///
    /// Operators can call this after `Engine(...)` construction to
    /// confirm the seed lands at the expected mounted-volume path
    /// without grepping logs. Wired into the lens's existing
    /// `/health` handler.
    ///
    /// **v0.1.7 caveat removed**: this is now authoritative, not
    /// predicted. The vendored path-resolution shim has been
    /// deleted.
    fn keyring_path(&self) -> Option<String> {
        self.signer
            .storage_descriptor()
            .disk_path()
            .map(|p| p.to_string_lossy().into_owned())
    }

    /// v0.1.9 — return a stable string-token classifying the signer's
    /// storage location for `/health` surfacing or readiness probes.
    ///
    /// Tokens (one of):
    /// - `"hardware_hsm_only"` — HSM-resident, no on-disk envelope
    /// - `"hardware_wrapped_blob"` — HSM-resident, wrapped envelope on disk
    /// - `"software_file"` — software seed on local filesystem
    /// - `"software_os_keyring_user"` — secret-service / Keychain / DPAPI, user scope
    /// - `"software_os_keyring_system"` — secret-service / Keychain / DPAPI, system scope
    /// - `"software_os_keyring_unknown"` — OS keyring, scope not exposed
    /// - `"in_memory"` — RAM-only signer (key dies with process)
    fn keyring_storage_kind(&self) -> &'static str {
        storage_kind_token(&self.signer.storage_descriptor())
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

/// Heuristic: does a `SoftwareFile` seed path look ephemeral?
///
/// Applies only to `StorageDescriptor::SoftwareFile { path }`.
/// Container-writable-layer prefixes are flagged; persistent
/// mounts (`/var/lib/...`, `/data/...`, `/srv/...`) are not.
///
/// False-positive cases (warning fires but path is fine):
/// - host running outside Docker with `/home/user/...`
/// - bind-mount at `/tmp/keyring`
///
/// False-negative cases (warning doesn't fire but path is bad):
/// - container with writable layer mounted at a path not in this
///   list (e.g. `/data/keyring` if `/data` is the container's
///   writable root and not a mounted volume — unusual but
///   possible)
///
/// Trade-off: false positives are an extra log line; false
/// negatives are silent identity churn. Prefer false positives.
fn path_looks_ephemeral(path: &std::path::Path) -> bool {
    const EPHEMERAL_PREFIXES: &[&str] = &["/home/", "/root/", "/tmp/", "/var/cache/", "/var/tmp/"];
    let s = path.to_string_lossy();
    EPHEMERAL_PREFIXES.iter().any(|p| s.starts_with(p))
}

/// v0.1.9 — boot-time observability for the signer's storage
/// location. Authoritative via
/// `HardwareSigner::storage_descriptor()` (ciris-keyring v1.8.0).
///
/// Behavior per descriptor variant:
/// - `Hardware`: info-level log; no warn (HSM-backed keys are
///   stable by construction).
/// - `SoftwareFile`: warn if path matches the ephemeral-prefix
///   heuristic, unless `suppress`.
/// - `SoftwareOsKeyring { scope: User }`: warn (logout-bound).
/// - `SoftwareOsKeyring { scope: System | Unknown }`: info-level.
/// - `InMemory`: warn hard (RAM-only signer in production = key
///   dies with the process).
fn check_storage_descriptor(descriptor: &StorageDescriptor, signing_key_id: &str, suppress: bool) {
    match descriptor {
        StorageDescriptor::Hardware {
            hardware_type,
            blob_path,
        } => {
            tracing::info!(
                signing_key_id,
                hardware_type = ?hardware_type,
                blob_path = ?blob_path.as_ref().map(|p| p.display().to_string()),
                "ciris-persist: signer storage = hardware"
            );
        }
        StorageDescriptor::SoftwareFile { path } => {
            let ephemeral = path_looks_ephemeral(path);
            if ephemeral && !suppress {
                tracing::warn!(
                    signing_key_id,
                    path = %path.display(),
                    "ciris-persist: SoftwareSigner seed path looks ephemeral. \
                     Container writable layers / /tmp / /home are wiped on \
                     restart, which churns the deployment identity (breaks \
                     one-key-three-roles per PoB §3.2). Mount a persistent \
                     volume and set CIRIS_DATA_DIR=<volume-mount-point>. \
                     Suppress this warning with CIRIS_PERSIST_KEYRING_PATH_OK=1 \
                     once you've verified the path is on persistent storage."
                );
            } else {
                tracing::info!(
                    signing_key_id,
                    path = %path.display(),
                    suppressed = ephemeral && suppress,
                    "ciris-persist: signer storage = software_file"
                );
            }
        }
        StorageDescriptor::SoftwareOsKeyring { backend, scope } => match scope {
            KeyringScope::User if !suppress => {
                tracing::warn!(
                    signing_key_id,
                    backend = backend.as_str(),
                    "ciris-persist: signer storage = OS keyring (USER scope). \
                     User-session-scoped entries disappear at logout / session \
                     end and are NOT suitable for longitudinal-score primitives \
                     (PoB §2.4). Reconfigure ciris-keyring for system-scope \
                     storage, or move to filesystem-backed seed on a \
                     persistent volume. Suppress with \
                     CIRIS_PERSIST_KEYRING_PATH_OK=1 once audited."
                );
            }
            _ => {
                tracing::info!(
                    signing_key_id,
                    backend = backend.as_str(),
                    scope = ?scope,
                    "ciris-persist: signer storage = OS keyring"
                );
            }
        },
        StorageDescriptor::InMemory => {
            tracing::warn!(
                signing_key_id,
                "ciris-persist: signer storage = IN-MEMORY ONLY. The key dies \
                 with the process; deployment identity churns on every \
                 restart. This signer variant is for dev/test only — production \
                 deployments MUST use Hardware, SoftwareFile (persistent), or \
                 SoftwareOsKeyring (system scope)."
            );
        }
    }
}

/// v0.1.9 — stable string-token for the signer's storage class.
///
/// See [`PyEngine::keyring_storage_kind`] for the token values and
/// their meanings. Used by `/health` and readiness probes that want
/// programmatic differentiation without parsing the verbose
/// descriptor.
fn storage_kind_token(descriptor: &StorageDescriptor) -> &'static str {
    match descriptor {
        StorageDescriptor::Hardware { blob_path, .. } => match blob_path {
            Some(_) => "hardware_wrapped_blob",
            None => "hardware_hsm_only",
        },
        StorageDescriptor::SoftwareFile { .. } => "software_file",
        StorageDescriptor::SoftwareOsKeyring { scope, .. } => match scope {
            KeyringScope::User => "software_os_keyring_user",
            KeyringScope::System => "software_os_keyring_system",
            KeyringScope::Unknown => "software_os_keyring_unknown",
        },
        StorageDescriptor::InMemory => "in_memory",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_paths_flagged() {
        for ephemeral in [
            "/home/cirislens/.local/share/ciris-verify/lens-scrub-v1.key",
            "/root/.local/share/ciris-verify/lens-scrub-v1.key",
            "/tmp/ciris/lens-scrub-v1.key",
            "/var/cache/ciris/lens-scrub-v1.key",
            "/var/tmp/ciris/lens-scrub-v1.key",
        ] {
            assert!(
                path_looks_ephemeral(std::path::Path::new(ephemeral)),
                "expected ephemeral: {ephemeral}"
            );
        }
    }

    #[test]
    fn persistent_paths_not_flagged() {
        for persistent in [
            "/var/lib/cirislens/keyring/lens-scrub-v1.key",
            "/data/ciris/lens-scrub-v1.key",
            "/srv/ciris/keyring/lens-scrub-v1.key",
            "/mnt/persistent/lens-scrub-v1.key",
            "/opt/ciris/lens-scrub-v1.key",
        ] {
            assert!(
                !path_looks_ephemeral(std::path::Path::new(persistent)),
                "expected persistent: {persistent}"
            );
        }
    }

    /// v0.1.9 — `storage_kind_token` returns the right discriminant
    /// per StorageDescriptor variant. The token is what `/health`
    /// surfaces; drift here is a contract change.
    #[test]
    fn storage_kind_token_dispatch() {
        use ciris_keyring::HardwareType;
        use std::path::PathBuf;

        assert_eq!(
            storage_kind_token(&StorageDescriptor::Hardware {
                hardware_type: HardwareType::TpmDiscrete,
                blob_path: None,
            }),
            "hardware_hsm_only"
        );
        assert_eq!(
            storage_kind_token(&StorageDescriptor::Hardware {
                hardware_type: HardwareType::AndroidKeystore,
                blob_path: Some(PathBuf::from("/data/keystore.blob")),
            }),
            "hardware_wrapped_blob"
        );
        assert_eq!(
            storage_kind_token(&StorageDescriptor::SoftwareFile {
                path: PathBuf::from("/var/lib/x/y.key"),
            }),
            "software_file"
        );
        assert_eq!(
            storage_kind_token(&StorageDescriptor::SoftwareOsKeyring {
                backend: "secret-service".into(),
                scope: KeyringScope::User,
            }),
            "software_os_keyring_user"
        );
        assert_eq!(
            storage_kind_token(&StorageDescriptor::SoftwareOsKeyring {
                backend: "keychain".into(),
                scope: KeyringScope::System,
            }),
            "software_os_keyring_system"
        );
        assert_eq!(
            storage_kind_token(&StorageDescriptor::InMemory),
            "in_memory"
        );
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
