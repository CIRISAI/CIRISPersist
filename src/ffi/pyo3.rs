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
}

#[pymethods]
impl PyEngine {
    /// Connect to Postgres, run migrations, build the ingest
    /// pipeline. Optionally accepts a Python callable that receives
    /// each batch as a JSON-compatible dict and returns
    /// `(scrubbed_dict, modified_count)`.
    ///
    /// Raises `RuntimeError` if Postgres is unreachable or
    /// migrations fail.
    #[new]
    #[pyo3(signature = (dsn, scrubber=None))]
    fn new(py: Python<'_>, dsn: &str, scrubber: Option<Py<PyAny>>) -> PyResult<Self> {
        // Build a multi-thread runtime once per Engine instance.
        // Phase 1.9 leans on the conservative shape (one runtime per
        // engine) per CRATE_RECOMMENDATIONS §2.7 + FSD §7 #2.
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
        })
    }

    /// Register the agent's Ed25519 public key for verification.
    ///
    /// `signature_key_id` is the same string the agent ships in
    /// `signature_key_id` on every CompleteTrace.
    /// `public_key_b64` is the agent's 32-byte Ed25519 verifying key
    /// in standard base64.
    ///
    /// Idempotent: re-registering the same key id is fine; if a
    /// different key is registered for an existing id, this raises
    /// (mission constraint MISSION.md §3 anti-pattern #3: no
    /// silent rotation).
    fn register_public_key(
        &self,
        py: Python<'_>,
        signature_key_id: &str,
        public_key_b64: &str,
        agent_id_hash: Option<&str>,
    ) -> PyResult<()> {
        let backend = self.backend.clone();
        let runtime = self.runtime.clone();
        let key_id = signature_key_id.to_owned();
        let pub_b64 = public_key_b64.to_owned();
        let agent_id = agent_id_hash.map(str::to_owned);
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
                         (signature_key_id, public_key_b64, agent_id_hash) \
                         VALUES ($1, $2, $3) \
                         ON CONFLICT (signature_key_id) DO NOTHING",
                        &[&key_id, &pub_b64, &agent_id],
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
        let runtime = self.runtime.clone();

        let summary = py.detach(|| {
            runtime.block_on(async move {
                let pipeline = IngestPipeline {
                    backend: &*backend,
                    canonicalizer: &PythonJsonDumpsCanonicalizer,
                    scrubber: &*scrubber,
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
            // Schema / verify / scrub → ValueError (caller-fault;
            // 4xx).
            Err(IngestError::Schema(e)) => Err(PyValueError::new_err(format!("schema: {e}"))),
            Err(IngestError::Verify(e)) => Err(PyValueError::new_err(format!("verify: {e}"))),
            Err(IngestError::Scrub(e)) => Err(PyValueError::new_err(format!("scrub: {e}"))),
            // Store → RuntimeError (server-fault; 5xx).
            Err(IngestError::Store(e)) => Err(PyRuntimeError::new_err(format!("store: {e}"))),
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
