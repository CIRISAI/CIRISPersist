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
    get_platform_signer, is_hardware_available, HardwareSigner, KeyringScope, PqcSigner,
    StorageDescriptor,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use tokio::runtime::Runtime;

use crate::ingest::{IngestError, IngestPipeline};
use crate::scrub::{NullScrubber, ScrubError, Scrubber};
#[cfg(feature = "sqlite")]
use crate::store::SqliteBackend;
use crate::store::{Backend, PostgresBackend};
use crate::verify::PythonJsonDumpsCanonicalizer;

// ---------------------------------------------------------------------------
// v1.0.0-scaffold (CIRISPersist#193 + #194) — backend dispatch, typed
// exception hierarchy, URL-sniff constructor. v1.4.0 ported the 9
// federation methods (CIRISPersist#52). v1.5.1 finished the sweep:
// every PyEngine method body now matches on `self.backend` and dispatches
// to the right concrete impl. The Postgres path is byte-for-byte
// identical to v1.0.0; the SQLite arm either calls the SqliteBackend
// trait impl (Group 1) or returns a stable `lens-read primitives are
// Postgres-only` runtime error (Group 2, lens-read + ratchet primitives
// awaiting the sovereign-mode v0.6.x track per `FSD/V0_5_0_*`).
//
//     cargo check --features "pyo3"         (Postgres-only, existing)
//     cargo check --features "pyo3 sqlite"  (Postgres + SQLite, new)
// ---------------------------------------------------------------------------

/// Backend selector for [`PyEngine`]. Constructor sniffs the URL prefix
/// and instantiates exactly one arm; every method matches on this to
/// dispatch to the right concrete impl.
///
/// CIRISAgent#755 Option A: URL-sniff single Engine class, internal enum
/// dispatch. Smallest agent-side diff — the Python API is identical
/// across backends.
///
/// `Clone` is cheap — each arm wraps an `Arc`, so cloning a
/// `BackendDispatch` shares the same pool/connection (v1.6.8: the
/// process-singleton cell hands `Arc`-shared clones to every
/// `PyEngine` handle).
#[derive(Clone)]
pub(crate) enum BackendDispatch {
    Postgres(Arc<PostgresBackend>),
    /// v1.5.1 — every PyEngine method body now reads this arm via
    /// `match &self.backend { … }` dispatch. Group 1 methods call the
    /// SqliteBackend trait impl; Group 2 methods (lens-read + ratchet
    /// primitives, v0.5.0 FSD) return a stable Postgres-only error.
    #[cfg(feature = "sqlite")]
    Sqlite(Arc<SqliteBackend>),
}

// ---------------------------------------------------------------------------
// Typed Python exception hierarchy (CIRISPersist#194).
//
// Granularity is per **retry policy** rather than per **module**:
//   - NotFound   — caller's row id wasn't there; don't retry, surface 404
//   - Conflict   — uniqueness / version / state conflict; don't retry,
//                  surface 409
//   - Transient  — backend connection / timeout / pool exhaustion; the
//                  caller MAY retry with backoff (lens HTTP handler turns
//                  this into 503)
//   - Permanent  — invalid arguments, signature failures, crypto errors,
//                  rotation conflicts, "not authorized," hardware
//                  unavailable, not-implemented; the caller MUST NOT
//                  retry; surface 4xx / 5xx as appropriate
//
// All four derive from a common [`PersistError`] base so callers can
// `except PersistError:` if they want the umbrella, or branch on the
// specific subclass for retry decisions. Per-module subclasses
// (`AuditNotFound`, `CirisGraphConflict`, …) are explicitly out of scope
// for 1.0.0 — retry granularity beats module granularity for HTTP
// surfaces.
// ---------------------------------------------------------------------------

#[allow(missing_docs)] // pyo3::create_exception emits items without doc-comments
mod persist_errors {
    pyo3::create_exception!(ciris_persist, PersistError, pyo3::exceptions::PyException);
    pyo3::create_exception!(ciris_persist, NotFound, super::persist_errors::PersistError);
    pyo3::create_exception!(ciris_persist, Conflict, super::persist_errors::PersistError);
    pyo3::create_exception!(
        ciris_persist,
        Transient,
        super::persist_errors::PersistError
    );
    pyo3::create_exception!(
        ciris_persist,
        Permanent,
        super::persist_errors::PersistError
    );
    // v1.6.8 (CIRISPersist#75-78) — engine-lifecycle errors. All
    // derive from `PersistError` so `except PersistError` still
    // catches them; callers branch on the specific subclass for
    // lifecycle handling.
    pyo3::create_exception!(
        ciris_persist,
        EngineConfigMismatch,
        super::persist_errors::PersistError
    );
    pyo3::create_exception!(
        ciris_persist,
        EngineClosed,
        super::persist_errors::PersistError
    );
    pyo3::create_exception!(
        ciris_persist,
        EngineUsedAcrossFork,
        super::persist_errors::PersistError
    );
}
pub use persist_errors::{
    Conflict, EngineClosed, EngineConfigMismatch, EngineUsedAcrossFork, NotFound, Permanent,
    PersistError, Transient,
};

/// v1.0.0-scaffold helper — map a stable substrate error `kind()` token
/// (e.g. `"audit_not_found"`, `"cirisgraph_conflict"`, `"secrets_backend"`)
/// onto the right typed Python exception class.
///
/// The follow-up porting agent threads this through every
/// `err.kind()`-aware `map_err` site (currently those sites use
/// `PyRuntimeError::new_err(format!(…))` or `PyValueError::new_err(kind)`
/// — both work but lose the retry-policy granularity that lens HTTP
/// handlers want).
///
/// AV-15 / AV-43 (THREAT_MODEL.md): `kind` is a closed-set `&'static str`
/// produced by the substrate's `Error::kind()` impl; no
/// attacker-controlled string leaks across the FFI boundary. `msg` is the
/// human-readable payload (already-tracing'd at the substrate layer); the
/// Python exception carries both.
#[allow(dead_code)] // wired by the follow-up porting agent; scaffold pass leaves
                    // existing `PyRuntimeError`/`PyValueError` sites untouched
pub(crate) fn translate_error_kind(kind: &str, msg: String) -> PyErr {
    match kind {
        // NotFound family — substrate told us the row isn't there.
        "secrets_not_found"
        | "audit_not_found"
        | "cirisnode_not_found"
        | "incident_not_found"
        | "cirisgraph_not_found"
        | "telemetry_not_found"
        | "tasks_not_found"
        | "thoughts_not_found"
        | "correlations_not_found"
        | "scheduled_tasks_not_found"
        | "tickets_not_found"
        | "deferral_reports_not_found"
        | "maintenance_locks_not_found"
        | "creation_ceremonies_not_found"
        | "continuity_awareness_not_found"
        | "feedback_mappings_not_found"
        | "wa_cert_not_found"
        | "service_token_revocation_not_found"
        | "legacy_migration_not_found"
        | "sequence_not_found"
        | "occurrence_not_found" => NotFound::new_err(msg),

        // Conflict family — uniqueness / version / state-transition
        // conflict; caller MUST NOT retry, MUST re-read.
        "secrets_conflict"
        | "cirisnode_conflict"
        | "incident_conflict"
        | "audit_conflict"
        | "cirisgraph_conflict"
        | "tasks_conflict"
        | "thoughts_conflict"
        | "correlations_conflict"
        | "scheduled_tasks_conflict"
        | "tickets_conflict"
        | "deferral_reports_conflict"
        | "maintenance_locks_conflict"
        | "creation_ceremonies_conflict"
        | "continuity_awareness_conflict"
        | "feedback_mappings_conflict"
        | "wa_cert_conflict"
        | "service_token_revocation_conflict"
        | "legacy_migration_conflict"
        | "sequence_conflict"
        | "occurrence_conflict" => Conflict::new_err(msg),

        // Transient family — backend connection / timeout / pool
        // exhaustion; caller MAY retry with backoff.
        "secrets_backend"
        | "audit_backend"
        | "cirisnode_backend"
        | "incident_backend"
        | "cirisgraph_backend"
        | "telemetry_backend"
        | "maintenance_backend"
        | "tasks_backend"
        | "thoughts_backend"
        | "correlations_backend"
        | "scheduled_tasks_backend"
        | "tickets_backend"
        | "deferral_reports_backend"
        | "maintenance_locks_backend"
        | "creation_ceremonies_backend"
        | "continuity_awareness_backend"
        | "feedback_mappings_backend"
        | "wa_cert_backend"
        | "service_token_revocation_backend"
        | "legacy_migration_backend"
        | "sequence_backend"
        | "occurrence_backend" => Transient::new_err(msg),

        // Default — Permanent. Covers invalid arguments, signature
        // failures, crypto errors, rotation conflicts, "not authorized,"
        // hardware unavailable, not-implemented, maintenance
        // invalid-argument / internal, and any unknown future kind.
        // Conservative: when in doubt, don't retry.
        _ => Permanent::new_err(msg),
    }
}

// ── v1.6.8 (CIRISPersist#75-78) — process-singleton engine ──────────
//
// Pre-v1.6.8 every `Engine(...)` constructed its own multi-thread
// tokio runtime. Two `Engine`s in one process → two runtimes
// contending on the shared DB → the 39-minute deadlock CIRISAgent
// 2.9.0 testing hit (#75). The CIRIS 3.0 in-process model (agent +
// NodeCore + LensCore each consuming persist) makes this a hard
// blocker.
//
// Fix: the runtime + backend pool + signer state live in ONE
// process-global `EngineCell`, built exactly once. Every
// `Engine(...)` call consults the singleton:
//   * empty / previously-closed slot → build the cell.
//   * live slot, same config        → return a handle cloned from it.
//   * live slot, different config    → raise `EngineConfigMismatch`
//     (#76 — silent rebind would corrupt data).
//
// `close()` (#77) flips the shared `closed` flag and clears the slot
// so a fresh construction can rebuild. `ensure_usable()` guards
// every method: `EngineClosed` after close, `EngineUsedAcrossFork`
// when the calling pid differs from the construction pid (#78 — a
// tokio runtime does not survive `fork()`).

/// v1.7.4 (CIRISPersist#82) — the persist substrate-family names a
/// consumer may declare ownership of at `register_consumer` time.
/// These are the five Postgres schemas persist partitions into (and
/// their SQLite flat-name equivalents). `register_consumer` rejects
/// any declared name not in this set, catching typos.
///
/// The consumer→substrate ownership table (which consumer-class
/// *should* own which family) lives in `docs/COHABITATION.md` — it
/// is a federation design contract, not enforced per-call here.
const KNOWN_SUBSTRATES: &[&str] = &[
    "cirislens",
    "cirislens_secrets",
    "cirislens_derived",
    "cirisgraph",
    "cirisnode",
];

/// v1.7.5 (#82 review, security M1) — bounds on the shared
/// consumer registry. The registry is process-global; a buggy or
/// hostile co-resident consumer that re-registers under fresh names
/// without `deregister_consumer` would otherwise grow it without
/// limit and OOM every cohabiting consumer. 64 entries is far above
/// any real in-process deployment (agent + NodeCore + LensCore = 3).
const MAX_CONSUMERS: usize = 64;

/// v1.7.5 (#82 review, security M1) — max consumer-name length, in
/// bytes. Names are caller-supplied diagnostic labels; 256 bytes is
/// generous for `"<repo>-<adapter>"` while bounding map growth.
const MAX_CONSUMER_NAME_LEN: usize = 256;

/// v1.9.0 (CIRISPersist#84) — cap on live change-feed subscriptions.
/// The registry is process-global; a consumer that leaks `subscribe`
/// calls without `unsubscribe` would otherwise grow it without
/// limit. 256 is far above any real in-process deployment (a handful
/// of consumers, each with a few substrate callbacks).
const MAX_SUBSCRIPTIONS: usize = 256;

/// v1.7.0 (CIRISPersist#80) — one attached consumer's registry
/// record. The agent + NodeCore + LensCore each register on
/// bring-up so the engine knows who is attached (safe teardown,
/// `list_consumers()` diagnostics).
#[derive(Clone)]
struct ConsumerRecord {
    /// Substrates this consumer declared ownership of at
    /// registration (CIRISPersist#82 ties into this list). Free-form
    /// today; the per-owner migration + write-rejection enforcement
    /// is the #82 follow-on.
    substrates: Vec<String>,
    registered_at: chrono::DateTime<chrono::Utc>,
}

/// Shared consumer registry — `Arc`'d so every `PyEngine` handle
/// sees the same map (register on handle A, `list_consumers()` on
/// handle B).
type ConsumerRegistry = Arc<std::sync::Mutex<std::collections::HashMap<String, ConsumerRecord>>>;

/// v1.9.0 (CIRISPersist#84) — one change-feed subscription: a Python
/// callable bound to a substrate family. Invoked as
/// `callback(substrate, event_json)` when a producer calls
/// `publish_change` for that substrate.
struct Subscription {
    /// Substrate family the callback listens on (a [`KNOWN_SUBSTRATES`]
    /// entry).
    substrate: String,
    /// The Python callable. `Py<PyAny>` is `Send + Sync` and
    /// GIL-independent; it is invoked under the GIL in `publish_change`.
    callback: pyo3::Py<pyo3::PyAny>,
}

/// v1.9.0 (CIRISPersist#84) — change-feed subscription state. `next_id`
/// is monotonic (never reused, so a stale id can't collide with a
/// fresh subscription); `subs` is an ordered map so a `publish_change`
/// dispatch visits subscribers in stable subscription-id order.
#[derive(Default)]
struct SubscriptionState {
    next_id: u64,
    subs: std::collections::BTreeMap<u64, Subscription>,
}

/// Shared change-feed subscription registry — `Arc`'d so a
/// `subscribe` on one `PyEngine` handle is visible to a
/// `publish_change` on any other.
type SubscriptionRegistry = Arc<std::sync::Mutex<SubscriptionState>>;

/// Process-global canonical engine state. Built once; `PyEngine`
/// handles clone Arc fields out of it.
struct EngineCell {
    backend: BackendDispatch,
    runtime: Arc<Runtime>,
    scrubber: Arc<dyn Scrubber>,
    signer: Arc<dyn HardwareSigner>,
    signer_key_id: String,
    local_signer: Option<Arc<crate::signing::LocalSigner>>,
    #[cfg(all(feature = "sqlite", feature = "cirisaudit"))]
    sqlite_audit: Option<Arc<crate::audit::sqlite::SqliteAuditBackend>>,
    /// v1.7.0 (CIRISPersist#80) — attached-consumer registry.
    consumers: ConsumerRegistry,
    /// v1.9.0 (CIRISPersist#84) — change-feed subscription registry.
    subscriptions: SubscriptionRegistry,
    /// Identity of the construction config — DSN + key ids. A second
    /// `Engine(...)` whose fingerprint differs raises
    /// `EngineConfigMismatch` rather than silently rebinding.
    config_fingerprint: String,
    /// `std::process::id()` at construction. A mismatch on a later
    /// call means the process forked — the runtime's worker threads
    /// don't exist in the child.
    construction_pid: u32,
    /// Shared with every `PyEngine` handle. `close()` sets it; every
    /// method checks it.
    closed: Arc<std::sync::atomic::AtomicBool>,
    /// v1.13.0 (CIRISPersist#92) — lazily-built, cached
    /// [`Engine`](crate::Engine) view onto this cell's backend +
    /// signer, handed to co-resident Rust consumers (CIRISEdge's
    /// resolver, CIRISLensCore's `LensCore::relay`) by
    /// [`current_rust_engine`](crate::current_rust_engine).
    ///
    /// Built **once** via [`OnceLock`] so repeated calls return the
    /// SAME `Arc<Engine>` — and that `Engine` shares this cell's
    /// connection pool (the inner backend `Arc` is cloned, not
    /// reconnected) and `Arc<dyn HardwareSigner>`. No second runtime,
    /// pool, or migration run is created: the cohabitation invariant
    /// (one process, one singleton) holds.
    rust_engine: std::sync::OnceLock<Arc<crate::Engine>>,
}

/// The one global slot. `OnceLock` initializes the `Mutex` once;
/// the `Option` is `None` until first construction and after
/// `close()`.
static ENGINE_SINGLETON: std::sync::OnceLock<std::sync::Mutex<Option<Arc<EngineCell>>>> =
    std::sync::OnceLock::new();

fn engine_slot() -> std::sync::MutexGuard<'static, Option<Arc<EngineCell>>> {
    ENGINE_SINGLETON
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        // Recover from a poisoned lock rather than cascading the
        // panic — a prior panicked construction shouldn't wedge the
        // singleton permanently.
        .unwrap_or_else(|e| e.into_inner())
}

/// Fingerprint the construction config. Two `Engine(...)` calls are
/// "the same engine" iff this matches. The scrubber (an opaque
/// Python callable) is deliberately excluded — DSN + signing
/// identities are the data-affecting config; a second caller's
/// scrubber is ignored in favor of the singleton's (documented on
/// `Engine.__init__`).
fn engine_config_fingerprint(
    dsn: &str,
    signing_key_id: &str,
    local_key_id: &Option<String>,
    local_pqc_key_id: &Option<String>,
) -> String {
    format!(
        "dsn={dsn}\0sk={signing_key_id}\0lk={}\0lpk={}",
        local_key_id.as_deref().unwrap_or(""),
        local_pqc_key_id.as_deref().unwrap_or(""),
    )
}

/// `ciris_persist.Engine` — **process-singleton** handle to the
/// persistence pipeline.
///
/// v1.6.8 (CIRISPersist#75-78): the tokio runtime + backend pool are
/// built exactly once per process. Constructing `Engine(...)` again
/// with the same config returns a cheap handle to the existing
/// engine; a different config raises `EngineConfigMismatch`. Call
/// `close()` for deterministic teardown; using a closed engine
/// raises `EngineClosed`; using one across `fork()` raises
/// `EngineUsedAcrossFork`.
#[pyclass(name = "Engine", module = "ciris_persist")]
pub struct PyEngine {
    /// v1.0.0-scaffold (CIRISPersist#193) introduced; v1.5.1 finished
    /// the dispatch sweep. Every PyEngine method body reads this via
    /// `match &self.backend { Postgres(pg) => ..., Sqlite(sq) => ... }`
    /// and routes to the right concrete impl. Group 1 methods call the
    /// shared trait method on the SqliteBackend Arc; Group 2 methods
    /// (lens-read + ratchet primitives, Postgres-only per the v0.5.0
    /// FSD) return a stable runtime error on the SQLite arm.
    backend: BackendDispatch,
    runtime: Arc<Runtime>,
    scrubber: Arc<dyn Scrubber>,
    signer: Arc<dyn HardwareSigner>,
    signer_key_id: String,
    /// v0.4.2 (CIRISPersist#17) — Local-process signing identity. One
    /// struct now holds the Ed25519 + optional ML-DSA-65 identities
    /// that the pre-v0.4.2 PyEngine carried as four separate fields.
    /// The PyO3 surface methods (`local_sign`, `local_pqc_sign`,
    /// accessors) are now thin wrappers over
    /// [`crate::signing::LocalSigner`] — CIRISPersist#7
    /// single-source-of-truth pattern repeated for signing.
    ///
    /// `None` when no local signing identity is configured for this
    /// Engine instance — the `local_*` methods return ValueError in
    /// that case.
    ///
    /// Lens process never sees the seed bytes after construction;
    /// signing happens via `local_sign(message)` /
    /// `local_pqc_sign(message)` returning raw signature bytes,
    /// matching the FFI-boundary discipline of `Engine.sign()`.
    ///
    /// Held as `Arc` so the auto-fire tokio task in `put_public_key`
    /// / `put_attestation` / `put_revocation` can clone and own its
    /// own reference for the duration of the cold-path sign.
    local_signer: Option<Arc<crate::signing::LocalSigner>>,
    /// v1.5.0 Phase H — persisted [`SqliteAuditBackend`] wrapping the
    /// same connection handle as the SQLite [`BackendDispatch::Sqlite`]
    /// arm. Held on the Engine (instead of constructed fresh per call
    /// like the v1.4.0 pattern in `audit_record_entry`) so the Merkle-
    /// transparency signer installed at construction time persists for
    /// the lifetime of the Engine. The Postgres arm doesn't need this
    /// shim because the `PostgresBackend` itself impls `AuditService`
    /// and is already held by `BackendDispatch::Postgres`.
    ///
    /// `None` when the backend is Postgres, or when the `sqlite`/
    /// `cirisaudit` features are off. The Phase H trust-grant /
    /// inclusion-proof methods unwrap this on the SQLite arm and
    /// reuse the same backend for every call.
    #[cfg(all(feature = "sqlite", feature = "cirisaudit"))]
    sqlite_audit: Option<Arc<crate::audit::sqlite::SqliteAuditBackend>>,
    /// v1.6.8 (CIRISPersist#77) — shared with the process-singleton
    /// [`EngineCell`]. `close()` sets it; [`PyEngine::ensure_usable`]
    /// checks it on every method so use-after-close raises
    /// `EngineClosed` instead of hanging on a torn-down runtime.
    closed: Arc<std::sync::atomic::AtomicBool>,
    /// v1.6.8 (CIRISPersist#78) — `std::process::id()` at
    /// construction. Every method compares it against the current
    /// pid; a mismatch (the process forked) raises
    /// `EngineUsedAcrossFork` rather than deadlocking on a runtime
    /// whose worker threads don't exist in the child.
    construction_pid: u32,
    /// v1.7.0 (CIRISPersist#80) — shared attached-consumer registry.
    /// Same `Arc` every handle holds.
    consumers: ConsumerRegistry,
    /// v1.9.0 (CIRISPersist#84) — shared change-feed subscription
    /// registry. Same `Arc` every handle holds.
    subscriptions: SubscriptionRegistry,
}

impl PyEngine {
    /// Build a `PyEngine` handle from the process-singleton cell —
    /// every field is a cheap `Arc`/`String` clone. All handles
    /// share the cell's `closed` flag.
    fn from_cell(cell: &EngineCell) -> Self {
        PyEngine {
            backend: cell.backend.clone(),
            runtime: cell.runtime.clone(),
            scrubber: cell.scrubber.clone(),
            signer: cell.signer.clone(),
            signer_key_id: cell.signer_key_id.clone(),
            local_signer: cell.local_signer.clone(),
            #[cfg(all(feature = "sqlite", feature = "cirisaudit"))]
            sqlite_audit: cell.sqlite_audit.clone(),
            closed: cell.closed.clone(),
            construction_pid: cell.construction_pid,
            consumers: cell.consumers.clone(),
            subscriptions: cell.subscriptions.clone(),
        }
    }

    /// v1.11.0 (CIRISPersist#90) — borrow a per-backend
    /// [`NodeCoreService`](crate::cirisnode::NodeCoreService) handle
    /// for the Engine's underlying storage backend.
    ///
    /// # Why a plain `pub fn`, not a `#[pymethod]`
    ///
    /// This is issue-#90 **Option B**: NodeCore's PyO3 bindings live
    /// in a *sibling cdylib* that receives an injected persist
    /// `PyEngine` and calls this method via `PyRef<PyEngine>` on the
    /// Rust side — it never crosses the Python boundary. A
    /// `#[pymethod]` would force the return type to be `IntoPy`;
    /// `NodeCoreDispatch` is a pure-Rust dispatch enum, so this stays
    /// a plain `pub fn`.
    ///
    /// # Why an enum, not `Arc<dyn NodeCoreService>`
    ///
    /// [`NodeCoreService`](crate::cirisnode::NodeCoreService) uses
    /// RPITIT (`fn put_contribution(...) -> impl Future + Send`) and
    /// is therefore NOT object-safe — `Arc<dyn NodeCoreService>` will
    /// not compile. The object-safe form is a dispatch enum: the
    /// returned [`NodeCoreDispatch`] mirrors the
    /// [`BackendDispatch`](crate::BackendDispatch) variants, exactly
    /// like [`Engine::maintenance`](crate::Engine::maintenance)
    /// returns [`EngineMaintenance`](crate::engine::EngineMaintenance).
    ///
    /// Cheap: each variant clones / wraps the inner backend handle
    /// once.
    #[cfg(all(feature = "cirisnode", any(feature = "postgres", feature = "sqlite")))]
    pub fn node_core_service(&self) -> crate::engine::NodeCoreDispatch {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => crate::engine::NodeCoreDispatch::Postgres(b.clone()),
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => crate::engine::NodeCoreDispatch::Sqlite(Arc::new(
                crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(b.conn_handle()),
            )),
        }
    }

    /// v2.0 (CIRISPersist#93) — borrow a per-backend
    /// [`AuditService`](crate::audit::AuditService) handle for the
    /// Engine's underlying storage backend.
    ///
    /// Exact sibling of [`PyEngine::node_core_service`] — see that
    /// accessor's doc-comment for the issue-#90 Option B rationale
    /// (plain `pub fn`, not a `#[pymethod]`, because NodeCore's PyO3
    /// bindings call this via `PyRef<PyEngine>` on the Rust side and
    /// it never crosses the Python boundary) and for why an enum is
    /// returned rather than `Arc<dyn AuditService>` (RPITIT — not
    /// object-safe).
    ///
    /// Cheap: each variant clones / wraps the inner backend handle
    /// once.
    #[cfg(all(feature = "cirisaudit", any(feature = "postgres", feature = "sqlite")))]
    pub fn audit_service(&self) -> crate::engine::AuditDispatch {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => crate::engine::AuditDispatch::Postgres(b.clone()),
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => crate::engine::AuditDispatch::Sqlite(Arc::new(
                crate::audit::sqlite::SqliteAuditBackend::new(b.conn_handle()),
            )),
        }
    }

    /// v2.0.1 (CIRISPersist#95) — Rust-level accessor for the
    /// federation directory substrate. Returns the public
    /// [`BackendDispatch`](crate::engine::BackendDispatch) the
    /// singleton holds (cloned `Arc`s — same backend pool, no second
    /// connection); a co-resident Rust extension (CIRISEdge#16)
    /// matches the variant and calls
    /// [`FederationDirectory`](crate::federation::FederationDirectory)
    /// trait methods on the concrete backend.
    ///
    /// Plain `pub fn` (not a `#[pymethod]`) — Option-B for sibling
    /// cdylibs, same pattern as
    /// [`node_core_service`](Self::node_core_service).
    ///
    /// # Why this still returns the dispatch enum (and not
    /// `Arc<dyn FederationDirectory>`)
    ///
    /// v2.6.0 (CIRISPersist#106) made the
    /// [`FederationDirectory`](crate::federation::FederationDirectory)
    /// trait object-safe via `#[async_trait]`, and
    /// [`Engine::federation_directory`](crate::engine::Engine::federation_directory)
    /// now returns `Arc<dyn FederationDirectory>` directly. This
    /// [`PyEngine`] accessor keeps the established
    /// [`BackendDispatch`](crate::engine::BackendDispatch) shape for
    /// wire-stability — co-resident sibling cdylibs already match on
    /// the enum, and the consumers that want the dyn handle hold an
    /// [`Engine`](crate::engine::Engine) (via
    /// [`current_rust_engine`](crate::current_rust_engine)) rather
    /// than the PyEngine directly.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub fn federation_directory(&self) -> crate::engine::BackendDispatch {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => crate::engine::BackendDispatch::Postgres(b.clone()),
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => crate::engine::BackendDispatch::Sqlite(b.clone()),
        }
    }

    /// v2.0.1 (CIRISPersist#95) — Rust-level accessor for the
    /// outbound-queue substrate. Returns the public
    /// [`BackendDispatch`](crate::engine::BackendDispatch) the
    /// singleton holds; the consumer matches the variant and calls
    /// [`OutboundQueue`](crate::outbound::OutboundQueue) trait methods
    /// on the concrete backend. Returns the same backend `Arc` as
    /// [`federation_directory`](Self::federation_directory) — both
    /// traits are implemented on the same concrete type — named
    /// distinctly so the call site documents which trait surface the
    /// consumer is using.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub fn outbound_queue(&self) -> crate::engine::BackendDispatch {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => crate::engine::BackendDispatch::Postgres(b.clone()),
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => crate::engine::BackendDispatch::Sqlite(b.clone()),
        }
    }

    /// v2.0.1 (CIRISPersist#95) — Rust-level accessor for the
    /// federation keyring signer. Returns the shared signer parts the
    /// singleton holds — Edge wraps these in its own `LocalSigner`
    /// without re-bootstrapping the keyring (the cohabitation
    /// invariant: one keyring identity per host;
    /// `docs/COHABITATION.md` rule 1).
    pub fn keyring_signer(&self) -> crate::signing::KeyringSignerHandle {
        crate::signing::KeyringSignerHandle {
            signer: self.signer.clone(),
            pqc_signer: self.local_signer.as_ref().and_then(|ls| ls.pqc_signer()),
            key_id: self.signer_key_id.clone(),
        }
    }

    /// v1.6.8 — guard run at the top of every method that touches
    /// the runtime / pool. `EngineClosed` after `close()`;
    /// `EngineUsedAcrossFork` when the process forked since
    /// construction. Both fail fast with a typed error instead of
    /// the silent native-FFI hang those states otherwise produce.
    fn ensure_usable(&self) -> PyResult<()> {
        use std::sync::atomic::Ordering;
        if self.closed.load(Ordering::Acquire) {
            return Err(PyErr::new::<EngineClosed, _>(
                "engine has been closed — construct a new Engine(...)",
            ));
        }
        let pid = std::process::id();
        if pid != self.construction_pid {
            return Err(PyErr::new::<EngineUsedAcrossFork, _>(format!(
                "engine was constructed in pid {} but used in pid {} — \
                 a tokio runtime does not survive fork(); construct the \
                 Engine after all forking is done, or set the process \
                 multiprocessing start method to 'spawn'",
                self.construction_pid, pid
            )));
        }
        Ok(())
    }
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
    /// **v0.2.2** — optional `local_key_id` + `local_key_path` (renamed
    /// from `steward_key_id` / `steward_key_path` in v1.4.0; the old
    /// kwargs are fully removed — this is a clean breaking change)
    /// configure a SECOND identity for federation-directory signing
    /// (`engine.local_sign()`, `engine.local_public_key_b64()`).
    /// This identity is Ed25519 (matching the federation_keys schema),
    /// distinct from `signing_key_id` (which is the scrub-envelope
    /// identity, typically P-256 via ciris-keyring). The local-process
    /// keypair is generated externally (e.g., by CIRIS bridge); the
    /// 32-byte raw Ed25519 seed is stored in `local_key_path`. The
    /// host process never touches the seed bytes after construction —
    /// signing happens via `local_sign(message)`.
    ///
    /// "Local" here means the per-process signing identity, which is
    /// role-orthogonal — every CIRIS agent (`client`, `proxy`, or
    /// `server` role) has a local signer; the role label lives in the
    /// FederationDirectory, not on the Engine.
    ///
    /// Raises `RuntimeError` if Postgres is unreachable, migrations
    /// fail, or the keyring is inaccessible. Raises `ValueError` if
    /// only one of `local_key_id`/`local_key_path` is provided
    /// (must be both-or-neither), or if the local seed file is
    /// missing/wrong-size.
    #[new]
    #[pyo3(signature = (dsn, signing_key_id, scrubber=None,
                        local_key_id=None, local_key_path=None,
                        local_pqc_key_id=None, local_pqc_key_path=None,
                        pqc_sweep_on_init=true))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        dsn: &str,
        signing_key_id: &str,
        scrubber: Option<Py<PyAny>>,
        local_key_id: Option<String>,
        local_key_path: Option<String>,
        local_pqc_key_id: Option<String>,
        local_pqc_key_path: Option<String>,
        pqc_sweep_on_init: bool,
    ) -> PyResult<Self> {
        // ── v1.6.8 (CIRISPersist#75-78) — process-singleton gate ────
        //
        // The global slot lock is held for the WHOLE constructor.
        // This is the #75 "no check-then-init race" guarantee: two
        // threads cannot both run `Runtime::new()`. A concurrent
        // `Engine(...)` blocks here, then returns the singleton — it
        // never builds a second runtime. (Construction does
        // connect + migrate under the lock; acceptable — a process
        // builds its one engine once, and the second caller *should*
        // wait for it.)
        let fingerprint =
            engine_config_fingerprint(dsn, signing_key_id, &local_key_id, &local_pqc_key_id);
        let mut slot = engine_slot();
        if let Some(cell) = slot.as_ref() {
            use std::sync::atomic::Ordering;
            if !cell.closed.load(Ordering::Acquire) {
                if cell.config_fingerprint != fingerprint {
                    return Err(PyErr::new::<EngineConfigMismatch, _>(
                        "Engine already constructed in this process with a \
                         different config (DSN / signing-key-id). A process \
                         hosts exactly one persist engine — attach to the \
                         existing one, or close() it before constructing a \
                         differently-configured engine.",
                    ));
                }
                // Same config → return a handle to the singleton.
                // No second runtime, no second pool.
                return Ok(PyEngine::from_cell(cell));
            }
            // Slot holds a closed cell — fall through and rebuild.
        }

        // First construction (or rebuild after close()). Build the
        // multi-thread runtime exactly once for the process.
        let runtime =
            Runtime::new().map_err(|e| PyRuntimeError::new_err(format!("tokio runtime: {e}")))?;
        let runtime = Arc::new(runtime);

        // v1.0.0-scaffold (CIRISPersist#193) — URL-sniff backend
        // construction. `dsn` retains its name for the Python kwarg
        // (back-compat: `Engine(dsn="postgresql://…", …)`) but now
        // accepts either:
        //   * `postgresql://…` / `postgres://…`  → PostgresBackend
        //   * `sqlite:///path.db` / `sqlite::memory:` → SqliteBackend
        //     (only when the `sqlite` feature is compiled in)
        // Anything else → ValueError. Other arms compile to the right
        // arm of [`BackendDispatch`]; method bodies still hard-code
        // the Postgres path (follow-up agent ports them).
        //
        // `pg_backend_for_sweep` captures the Arc<PostgresBackend> for
        // the v0.3.2 cold-path PQC sweep that fires further down — that
        // primitive is Postgres-only today; on the SQLite arm we
        // simply skip the sweep (it's a Postgres-table migration
        // artifact that doesn't exist on the SQLite schema).
        #[allow(unused_variables)] // borrowed only when local_signer + sweep are wired
        let pg_backend_for_sweep: Option<Arc<PostgresBackend>>;
        let backend: BackendDispatch =
            if dsn.starts_with("postgresql://") || dsn.starts_with("postgres://") {
                let pg = py.detach(|| {
                    runtime.block_on(async {
                        let pg = PostgresBackend::connect(dsn)
                            .await
                            .map_err(|e| PyRuntimeError::new_err(format!("connect: {e}")))?;
                        pg.run_migrations()
                            .await
                            .map_err(|e| PyRuntimeError::new_err(format!("migrations: {e}")))?;
                        Ok::<_, PyErr>(Arc::new(pg))
                    })
                })?;
                pg_backend_for_sweep = Some(pg.clone());
                BackendDispatch::Postgres(pg)
            } else if dsn.starts_with("sqlite://") || dsn == "sqlite::memory:" {
                #[cfg(feature = "sqlite")]
                {
                    // URL parsing follows the SQLAlchemy / Python sqlite3
                    // convention the CIRISAgent ecosystem already uses:
                    //   `sqlite:///abs/path.db`  → file at `/abs/path.db`
                    //   `sqlite:///relative.db`  → file at `relative.db`
                    //                              (strip leading `/`)
                    //   `sqlite:///:memory:`     → in-memory
                    //   `sqlite::memory:`        → in-memory (compact form)
                    //
                    // The `sqlite://` prefix is the URL scheme;
                    // `sqlite:///` is scheme + empty authority + path.
                    let in_memory = dsn == "sqlite::memory:"
                        || dsn == "sqlite:///:memory:"
                        || dsn == "sqlite://:memory:";
                    let sq = py.detach(|| {
                        runtime.block_on(async {
                            let sq = if in_memory {
                                SqliteBackend::open_in_memory().await.map_err(|e| {
                                    PyRuntimeError::new_err(format!("sqlite open: {e}"))
                                })?
                            } else {
                                // Strip the `sqlite:///` (3-slash) or
                                // `sqlite://` (2-slash) prefix to recover
                                // the on-disk path. rusqlite::open takes a
                                // path verbatim.
                                let path = dsn
                                    .strip_prefix("sqlite:///")
                                    .or_else(|| dsn.strip_prefix("sqlite://"))
                                    .unwrap_or(dsn);
                                SqliteBackend::open(path).await.map_err(|e| {
                                    PyRuntimeError::new_err(format!("sqlite open: {e}"))
                                })?
                            };
                            sq.run_migrations()
                                .await
                                .map_err(|e| PyRuntimeError::new_err(format!("migrations: {e}")))?;
                            Ok::<_, PyErr>(Arc::new(sq))
                        })
                    })?;
                    pg_backend_for_sweep = None;
                    BackendDispatch::Sqlite(sq)
                }
                #[cfg(not(feature = "sqlite"))]
                {
                    return Err(PyValueError::new_err(format!(
                        "dsn `{dsn}` uses sqlite:// scheme but the `sqlite` feature \
                     was not compiled in for this ciris_persist build"
                    )));
                }
            } else {
                return Err(PyValueError::new_err(format!(
                    "unrecognized dsn scheme: {dsn:?} \
                 (expected `postgresql://…`, `postgres://…`, `sqlite:///…`, or `sqlite::memory:`)"
                )));
            };

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

        // v0.1.14 — cohabitation bootstrap. Persist is the runtime
        // keyring authority on its host (`docs/COHABITATION.md`);
        // multiple persist processes (e.g. `uvicorn --workers 4`)
        // would otherwise race on `get_platform_signer()`'s
        // `key_exists() → generate_key()` window. The flock around
        // `${CIRIS_DATA_DIR}/.persist-bootstrap.lock` (or
        // `/tmp/ciris-persist-bootstrap.lock` fallback) serializes
        // bootstrap across the host: the first worker through
        // generates the key; later workers block briefly,
        // see the existing key, become read-only consumers.
        //
        // POSIX `flock` auto-releases on FD close — including
        // process exit and panic — so a stuck holder isn't a
        // normal failure mode. The lock is held only for the
        // duration of `get_platform_signer()` (~50ms warm,
        // ~500ms cold-start), not for the lifetime of the Engine.
        let signer = py.detach(|| -> PyResult<Box<dyn HardwareSigner>> {
            let _bootstrap_lock = acquire_bootstrap_lock()
                .map_err(|e| PyRuntimeError::new_err(format!("bootstrap lock: {e}")))?;
            // v2.0.5 — retry with backoff for iOS Secure Enclave
            // cold-start. The enclave may not be ready on the first
            // attempt after app launch; a brief retry window avoids
            // the orphaned-hardware-marker failure path where the DB
            // has key_kind='hardware' but the signer can't load.
            const SIGNER_BACKOFFS: &[std::time::Duration] = &[
                std::time::Duration::from_millis(200),
                std::time::Duration::from_millis(500),
                std::time::Duration::from_millis(1000),
            ];
            match get_platform_signer(&signer_key_id_owned) {
                Ok(s) => Ok(s),
                Err(first_err) => {
                    let mut last_err = first_err;
                    for (i, delay) in SIGNER_BACKOFFS.iter().enumerate() {
                        tracing::warn!(
                            attempt = i + 1,
                            error = %last_err,
                            "ciris-persist: signer init transient failure, retrying"
                        );
                        std::thread::sleep(*delay);
                        match get_platform_signer(&signer_key_id_owned) {
                            Ok(s) => {
                                tracing::info!(
                                    attempt = i + 2,
                                    "ciris-persist: signer recovered after retry"
                                );
                                return Ok(s);
                            }
                            Err(e) => last_err = e,
                        }
                    }
                    Err(PyRuntimeError::new_err(format!(
                        "ciris-keyring: {last_err}"
                    )))
                }
            }
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

        // v0.4.2 (CIRISPersist#17) — Local identity wiring is now
        // [`crate::signing::LocalSigner::from_config`]. Same
        // both-or-neither contract on the Ed25519 + PQC pairs;
        // identical seed-load semantics; identical tracing::info
        // observability shape. The Rust function is the
        // single-source-of-truth — both PyO3 callers (this) and
        // Rust callers (CIRISLensCore, CIRISEdge) hit the same
        // construction path.
        let local_signer: Option<Arc<crate::signing::LocalSigner>> =
            match (local_key_id, local_key_path) {
                (None, None) => {
                    // Pair PQC config check before silently dropping a
                    // PQC-only config — surface as the same typed error
                    // the loaded path would.
                    if local_pqc_key_id.is_some() || local_pqc_key_path.is_some() {
                        return Err(PyValueError::new_err(
                            "local_pqc_key_* requires local_key_id + local_key_path",
                        ));
                    }
                    None
                }
                (Some(key_id), Some(key_path)) => {
                    let cfg = crate::signing::LocalSignerConfig {
                        key_id,
                        key_path: std::path::PathBuf::from(key_path),
                        pqc_key_id: local_pqc_key_id,
                        pqc_key_path: local_pqc_key_path.map(std::path::PathBuf::from),
                    };
                    let signer = crate::signing::LocalSigner::from_config(&cfg)
                        .map_err(local_signer_err_to_py)?;
                    Some(Arc::new(signer))
                }
                _ => {
                    return Err(PyValueError::new_err(
                        "local_key_id and local_key_path must both be provided \
                         or both omitted",
                    ));
                }
            };

        // v0.3.2 (CIRISPersist#11) — Auto-sweep on init when a local
        // PQC key is configured. Drains hybrid-pending rows authored
        // before the per-write cold-path was wired (or rows where the
        // per-write spawn failed transiently). Spawned as a background
        // task on the runtime so Engine::new returns immediately;
        // sweep result is logged at tracing::info when complete.
        //
        // v1.0.0-scaffold (CIRISPersist#193): the sweep primitive is
        // Postgres-only today (operates on cirisgraph_keys /
        // federation_attestations / federation_revocations PG tables).
        // On the SQLite arm `pg_backend_for_sweep` is `None` and the
        // sweep is silently skipped — same observable shape as
        // `pqc_sweep_on_init=false`.
        if pqc_sweep_on_init {
            if let (Some(pqc_signer), Some(backend_for_sweep)) = (
                local_signer.as_ref().and_then(|s| s.pqc_signer()),
                pg_backend_for_sweep.as_ref().cloned(),
            ) {
                runtime.spawn(async move {
                    let summary = run_pqc_sweep_inner(&backend_for_sweep, &*pqc_signer, 1000).await;
                    tracing::info!(
                        scanned = summary.total_scanned,
                        signed = summary.total_signed,
                        failed = summary.total_failed,
                        keys_signed = summary.keys.signed,
                        attestations_signed = summary.attestations.signed,
                        revocations_signed = summary.revocations.signed,
                        "ciris-persist v0.3.2: cold-path PQC sweep on init complete"
                    );
                });
            }
        }

        // v1.5.0 Phase H — wire Engine.local_signer → backend's
        // Merkle-hook signer. The Phase C audit-service hook reads
        // this on every committed entry; without it `record_entry`
        // skips the Merkle append + STH publish as a no-op (matches
        // CIRIS-RED / unconfigured-deployment shape). On the SQLite
        // path, we also persist the SqliteAuditBackend on the Engine
        // (instead of constructing fresh per call like v1.4.0's
        // `audit_record_entry`), so the installed signer survives
        // beyond one method call.
        #[cfg(all(feature = "sqlite", feature = "cirisaudit"))]
        let sqlite_audit: Option<Arc<crate::audit::sqlite::SqliteAuditBackend>> = match &backend {
            BackendDispatch::Sqlite(sq) => {
                let audit = Arc::new(crate::audit::sqlite::SqliteAuditBackend::new(
                    sq.conn_handle(),
                ));
                if let Some(signer) = local_signer.as_ref() {
                    audit.set_merkle_signer(Some(signer.clone()));
                }
                Some(audit)
            }
            BackendDispatch::Postgres(_) => None,
        };
        #[cfg(feature = "cirisaudit")]
        if let BackendDispatch::Postgres(pg) = &backend {
            if let Some(signer) = local_signer.as_ref() {
                pg.set_merkle_signer(Some(signer.clone()));
            }
        }

        // v2.0.5 — boot-time audit chain self-verification. Runs
        // independently of any external registry: even if the build
        // registry 404s (version not yet published), persist validates
        // its own audit chain integrity on startup.
        #[cfg(feature = "cirisaudit")]
        {
            let boot_backend = backend.clone();
            runtime.spawn(async move {
                match boot_audit_self_verify(&boot_backend).await {
                    Ok(summary) => {
                        if summary.all_ok {
                            tracing::info!(
                                tenants = summary.tenants_checked,
                                entries_walked = summary.total_entries_walked,
                                "ciris-persist: boot audit self-check passed"
                            );
                        } else {
                            tracing::warn!(
                                tenants = summary.tenants_checked,
                                breaks = summary.breaks.len(),
                                "ciris-persist: boot audit self-check found chain breaks"
                            );
                            for b in &summary.breaks {
                                tracing::warn!(
                                    tenant_id = b.tenant_id.as_str(),
                                    at_sequence = b.at_sequence,
                                    reason = b.reason.as_str(),
                                    "ciris-persist: audit chain break"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "ciris-persist: boot audit self-check failed"
                        );
                    }
                }
            });
        }

        // v1.6.8 — install the canonical cell into the process
        // singleton, then hand back a handle cloned from it. `slot`
        // (the global lock) has been held since the top of `new`.
        let cell = Arc::new(EngineCell {
            backend,
            runtime,
            scrubber,
            signer,
            signer_key_id: signing_key_id.to_owned(),
            local_signer,
            #[cfg(all(feature = "sqlite", feature = "cirisaudit"))]
            sqlite_audit,
            config_fingerprint: fingerprint,
            construction_pid: std::process::id(),
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            consumers: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            subscriptions: Arc::new(std::sync::Mutex::new(SubscriptionState::default())),
            rust_engine: std::sync::OnceLock::new(),
        });
        let handle = PyEngine::from_cell(&cell);
        *slot = Some(cell);
        Ok(handle)
    }

    /// v1.6.8 (CIRISPersist#77) — deterministic teardown door.
    ///
    /// Flips the process-singleton's `closed` flag (every
    /// `Engine` handle shares it, so all of them start raising
    /// `EngineClosed`) and clears the global slot so a subsequent
    /// `Engine(...)` rebuilds a fresh runtime + pool.
    ///
    /// **Lifecycle rule:** exactly one owner constructs and closes
    /// the engine. In-process adapters (NodeCore, LensCore) attach
    /// via `Engine(...)` with the same config and must NOT call
    /// `close()` — the owner does, at process shutdown / test
    /// teardown.
    ///
    /// The tokio runtime + connection pool are released when the
    /// last `Engine` handle is dropped (Python GC); `close()` makes
    /// the *logical* shutdown deterministic — no method runs against
    /// a half-torn-down runtime, it fails fast with `EngineClosed`.
    /// Idempotent: calling `close()` twice is a no-op.
    ///
    /// **v1.7.0 (CIRISPersist#80)** — `close()` refuses if consumers
    /// are still registered: a teardown while NodeCore / LensCore
    /// are attached would pull the runtime out from under them. Pass
    /// `force=True` to close anyway (process is going down hard).
    /// The well-behaved path is: every adapter `deregister_consumer`
    /// on its own teardown, then the owner's `close()` finds the
    /// registry empty.
    ///
    /// **Not a quiescence barrier.** `close()` flips the `closed`
    /// flag and clears the slot; it does NOT wait for in-flight
    /// operations on other threads to drain. An operation that
    /// already passed its `ensure_usable()` check still runs to
    /// completion against the (Arc-kept-alive) runtime — its write
    /// commits. `close()` guarantees that *subsequent* calls fail
    /// fast with `EngineClosed`, not that no call is in progress.
    /// Callers needing a hard drain must quiesce their own consumers
    /// before calling `close()`.
    #[pyo3(signature = (force=false))]
    fn close(&self, force: bool) -> PyResult<()> {
        // Hold the consumer-registry lock across the empty-check AND
        // the `closed` store: `register_consumer` re-checks `closed`
        // under this same lock, so the pair is mutually exclusive —
        // no consumer can attach into the close() window (#82 review,
        // concurrency H2 / M1).
        let registry = self.consumers.lock().unwrap_or_else(|e| e.into_inner());
        if !force && !registry.is_empty() {
            let mut names: Vec<&str> = registry.keys().map(String::as_str).collect();
            names.sort_unstable();
            return Err(PyRuntimeError::new_err(format!(
                "close() refused — {} consumer(s) still registered: [{}]. \
                 Each adapter must deregister_consumer() on teardown, or \
                 pass force=True to close anyway.",
                names.len(),
                names.join(", ")
            )));
        }
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        drop(registry);
        let mut slot = engine_slot();
        // Only clear the slot if it still points at *this* engine —
        // guard against clearing a fresh post-close rebuild.
        if let Some(cell) = slot.as_ref() {
            if Arc::ptr_eq(&cell.closed, &self.closed) {
                *slot = None;
            }
        }
        Ok(())
    }

    /// v1.6.8 — `True` once `close()` has run on this engine (or any
    /// handle sharing its singleton cell). Lets a caller check
    /// before dispatching rather than catching `EngineClosed`.
    #[getter]
    fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Acquire)
    }

    /// v1.7.0 (CIRISPersist#79) — return a fresh handle to the
    /// process-singleton engine.
    ///
    /// Every `Engine` is already a handle to the one process
    /// singleton, so this is a cheap `Arc`-clone. It exists so the
    /// lifecycle owner can hand the engine to an in-process adapter
    /// (NodeCore, LensCore) explicitly — "injected engine, first
    /// parameter" — without the adapter needing the DSN / signing
    /// key to re-call the `Engine(...)` constructor. The returned
    /// handle shares the runtime, pool, signer, `closed` flag, and
    /// consumer registry with every other handle.
    fn engine_handle(&self) -> PyResult<PyEngine> {
        self.ensure_usable()?;
        Ok(PyEngine {
            backend: self.backend.clone(),
            runtime: self.runtime.clone(),
            scrubber: self.scrubber.clone(),
            signer: self.signer.clone(),
            signer_key_id: self.signer_key_id.clone(),
            local_signer: self.local_signer.clone(),
            #[cfg(all(feature = "sqlite", feature = "cirisaudit"))]
            sqlite_audit: self.sqlite_audit.clone(),
            closed: self.closed.clone(),
            construction_pid: self.construction_pid,
            consumers: self.consumers.clone(),
            subscriptions: self.subscriptions.clone(),
        })
    }

    /// v1.7.0 (CIRISPersist#80) — register an attached consumer.
    ///
    /// In-process adapters call this on bring-up so the engine knows
    /// who is attached: safe teardown (`close()` refuses while
    /// consumers remain) and `list_consumers()` diagnostics.
    ///
    /// `substrates` declares the substrate families the consumer
    /// owns (e.g. `["cirisnode"]` for NodeCore). **v1.7.4
    /// (CIRISPersist#82)** — each name is validated against the
    /// known persist substrate-family set ([`KNOWN_SUBSTRATES`]); an
    /// unknown name raises `ValueError`, catching typos before they
    /// become silent no-ops. The declared list is queryable via
    /// `substrate_owner()` for cooperative cross-consumer ownership
    /// checks. (Hard per-call write-rejection is a deliberate
    /// non-goal for the 1.7.x line — see the v1.7.4 CHANGELOG +
    /// `docs/COHABITATION.md`.)
    ///
    /// Idempotent: re-registering an existing `name` updates its
    /// substrate list + refreshes the timestamp.
    #[pyo3(signature = (name, substrates=None))]
    fn register_consumer(&self, name: &str, substrates: Option<Vec<String>>) -> PyResult<()> {
        self.ensure_usable()?;
        if name.is_empty() {
            return Err(PyValueError::new_err("consumer name must be non-empty"));
        }
        // v1.7.5 (#82 review, security M1) — the registry is shared
        // across every co-resident consumer; cap name length so a
        // buggy/hostile consumer can't bloat the shared map.
        if name.len() > MAX_CONSUMER_NAME_LEN {
            return Err(PyValueError::new_err(format!(
                "consumer name too long ({} bytes, max {MAX_CONSUMER_NAME_LEN})",
                name.len()
            )));
        }
        let mut substrates = substrates.unwrap_or_default();
        // v1.7.4 (#82) — reject substrate-family typos at declaration
        // time. A consumer that mis-declares `cirsnode` would
        // otherwise silently own nothing.
        for s in &substrates {
            if !KNOWN_SUBSTRATES.contains(&s.as_str()) {
                return Err(PyValueError::new_err(format!(
                    "unknown substrate family {s:?} — must be one of {KNOWN_SUBSTRATES:?}"
                )));
            }
        }
        // v1.7.5 — dedupe so a repeated declaration can't grow the
        // record unboundedly; order-stable, ≤ KNOWN_SUBSTRATES.len().
        substrates.sort_unstable();
        substrates.dedup();
        let mut registry = self.consumers.lock().unwrap_or_else(|e| e.into_inner());
        // v1.7.5 (#82 review, concurrency M1) — re-check `closed`
        // under the registry lock. `close()` flips `closed` while
        // holding this same lock, so checking here makes attach and
        // close mutually exclusive: no consumer slips into the
        // close() window.
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(PyErr::new::<EngineClosed, _>(
                "register_consumer on a closed engine",
            ));
        }
        // v1.7.5 (#82 review, security M1) — cap registry size. A
        // re-registration of an existing name is always allowed (it
        // updates in place); only a brand-new name can hit the cap.
        if !registry.contains_key(name) && registry.len() >= MAX_CONSUMERS {
            return Err(PyRuntimeError::new_err(format!(
                "consumer registry full ({MAX_CONSUMERS}) — a consumer is \
                 likely leaking registrations without deregister_consumer()"
            )));
        }
        registry.insert(
            name.to_owned(),
            ConsumerRecord {
                substrates,
                registered_at: chrono::Utc::now(),
            },
        );
        Ok(())
    }

    /// v1.7.4 (CIRISPersist#82) — which registered consumer declared
    /// ownership of `substrate`, or `None` if no consumer claims it.
    ///
    /// Cooperative cross-consumer ownership check: an in-process
    /// adapter calls this before writing to a shared-engine
    /// substrate to confirm it owns it (or that nobody else does).
    /// Persist does NOT hard-reject a write to an unowned/foreign
    /// substrate — the singleton engine has no per-call consumer
    /// identity to enforce against; ownership is advisory + the
    /// ownership table in `docs/COHABITATION.md` is the contract.
    /// If two consumers both declared the same substrate, the
    /// lexicographically-first consumer name is returned (stable).
    fn substrate_owner(&self, substrate: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        let registry = self.consumers.lock().unwrap_or_else(|e| e.into_inner());
        let mut owner: Option<&str> = None;
        for (name, rec) in registry.iter() {
            if rec.substrates.iter().any(|s| s == substrate) {
                owner = Some(match owner {
                    Some(prev) if prev <= name.as_str() => prev,
                    _ => name.as_str(),
                });
            }
        }
        Ok(owner.map(str::to_owned))
    }

    /// v1.7.0 (CIRISPersist#80) — deregister an attached consumer.
    /// Adapters call this on their own teardown. Returns `True` if
    /// the consumer was registered, `False` if it wasn't (idempotent
    /// — double-deregister is not an error).
    fn deregister_consumer(&self, name: &str) -> PyResult<bool> {
        self.ensure_usable()?;
        let mut registry = self.consumers.lock().unwrap_or_else(|e| e.into_inner());
        Ok(registry.remove(name).is_some())
    }

    /// v1.7.0 (CIRISPersist#80) — JSON-encoded snapshot of the
    /// attached-consumer registry: `{name: {"substrates": [...],
    /// "registered_at": "<rfc3339>"}}`. For diagnostics — "who is
    /// using persist right now."
    fn list_consumers(&self) -> PyResult<String> {
        self.ensure_usable()?;
        let registry = self.consumers.lock().unwrap_or_else(|e| e.into_inner());
        let view: std::collections::BTreeMap<String, serde_json::Value> = registry
            .iter()
            .map(|(name, rec)| {
                (
                    name.clone(),
                    serde_json::json!({
                        "substrates": rec.substrates,
                        "registered_at": rec.registered_at.to_rfc3339(),
                    }),
                )
            })
            .collect();
        serde_json::to_string(&view)
            .map_err(|e| PyRuntimeError::new_err(format!("consumer registry encode: {e}")))
    }

    /// v1.7.0 (CIRISPersist#80) — count of currently-registered
    /// consumers. `close()` (without `force`) refuses while this is
    /// non-zero.
    #[getter]
    fn consumer_count(&self) -> usize {
        self.consumers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    // ── v1.9.0 (CIRISPersist#84) — change-feed / subscription API ──
    //
    // An in-process pub/sub bus keyed by substrate family. A producer
    // (the agent's streaming-step path, a substrate writer) calls
    // `publish_change(substrate, event_json)`; every callback a
    // co-resident consumer registered via `subscribe(substrate, cb)`
    // is invoked. Replaces cross-consumer polling under the shared
    // singleton engine.
    //
    // Delivery semantics (documented, honest — not "at-least-once"
    // with a hidden queue): dispatch is **synchronous and in-process**
    // — `publish_change` invokes every matching callback before it
    // returns, in ascending subscription-id order. Each subscriber is
    // invoked exactly once per event. A callback that raises is
    // caught and logged; the exception does not propagate to the
    // publisher and does not stop the remaining callbacks. Publishers
    // are GIL-serialized, so per-substrate event order == the order
    // `publish_change` was called. There is no persistence and no
    // replay: a subscriber that attaches after an event is published
    // does not see it (in-process notification, not a durable log).

    /// v1.9.0 (CIRISPersist#84) — register a change-feed callback.
    ///
    /// `callback` is invoked as `callback(substrate, event_json)`
    /// each time a producer calls [`PyEngine::publish_change`] for
    /// `substrate`. `substrate` must be a known substrate family
    /// (the [`KNOWN_SUBSTRATES`] set — same namespace as
    /// `register_consumer`); an unknown name raises `ValueError`.
    /// Returns an opaque subscription id for [`PyEngine::unsubscribe`].
    fn subscribe(&self, substrate: &str, callback: &Bound<'_, PyAny>) -> PyResult<u64> {
        self.ensure_usable()?;
        if !KNOWN_SUBSTRATES.contains(&substrate) {
            return Err(PyValueError::new_err(format!(
                "unknown substrate family {substrate:?} — must be one of {KNOWN_SUBSTRATES:?}"
            )));
        }
        if !callback.is_callable() {
            return Err(PyValueError::new_err("callback must be callable"));
        }
        let mut state = self.subscriptions.lock().unwrap_or_else(|e| e.into_inner());
        if state.subs.len() >= MAX_SUBSCRIPTIONS {
            return Err(PyRuntimeError::new_err(format!(
                "subscription registry full ({MAX_SUBSCRIPTIONS}) — a consumer is \
                 likely leaking subscriptions without unsubscribe()"
            )));
        }
        let id = state.next_id;
        state.next_id += 1;
        state.subs.insert(
            id,
            Subscription {
                substrate: substrate.to_owned(),
                callback: callback.clone().unbind(),
            },
        );
        Ok(id)
    }

    /// v1.9.0 (CIRISPersist#84) — remove a change-feed callback by the
    /// id `subscribe` returned. `True` if it was registered, `False`
    /// if not (idempotent — double-unsubscribe is not an error).
    fn unsubscribe(&self, subscription_id: u64) -> PyResult<bool> {
        let mut state = self.subscriptions.lock().unwrap_or_else(|e| e.into_inner());
        Ok(state.subs.remove(&subscription_id).is_some())
    }

    /// v1.9.0 (CIRISPersist#84) — publish a change event to every
    /// callback subscribed to `substrate`. Returns the number of
    /// callbacks invoked.
    ///
    /// `event_json` is an opaque JSON string — persist does not parse
    /// it; the wire shape is a contract between the producer and its
    /// subscribers. Dispatch is synchronous: every matching callback
    /// runs before this returns. A callback that raises is caught and
    /// logged (it does not abort the publish or the other callbacks).
    fn publish_change(&self, py: Python<'_>, substrate: &str, event_json: &str) -> PyResult<usize> {
        self.ensure_usable()?;
        if !KNOWN_SUBSTRATES.contains(&substrate) {
            return Err(PyValueError::new_err(format!(
                "unknown substrate family {substrate:?} — must be one of {KNOWN_SUBSTRATES:?}"
            )));
        }
        // Snapshot the matching callbacks under the lock, then release
        // it before invoking any Python — a callback is free to call
        // subscribe / unsubscribe / publish_change re-entrantly
        // without deadlocking on this (non-reentrant) Mutex.
        let targets: Vec<pyo3::Py<pyo3::PyAny>> = {
            let state = self.subscriptions.lock().unwrap_or_else(|e| e.into_inner());
            state
                .subs
                .values()
                .filter(|s| s.substrate == substrate)
                .map(|s| s.callback.clone_ref(py))
                .collect()
        };
        let delivered = targets.len();
        for cb in targets {
            if let Err(e) = cb.call1(py, (substrate, event_json)) {
                // One bad subscriber must not break the publish or the
                // other subscribers. Surface to tracing, keep going.
                tracing::warn!(
                    substrate,
                    error = %e,
                    "change-feed subscriber callback raised; continuing"
                );
            }
        }
        Ok(delivered)
    }

    /// v1.9.0 (CIRISPersist#84) — JSON snapshot of the change-feed
    /// subscription registry: `{"<id>": "<substrate>", ...}`. For
    /// diagnostics — "who is listening to what."
    fn list_subscriptions(&self) -> PyResult<String> {
        let state = self.subscriptions.lock().unwrap_or_else(|e| e.into_inner());
        let view: std::collections::BTreeMap<String, &str> = state
            .subs
            .iter()
            .map(|(id, s)| (id.to_string(), s.substrate.as_str()))
            .collect();
        serde_json::to_string(&view)
            .map_err(|e| PyRuntimeError::new_err(format!("subscription registry encode: {e}")))
    }

    /// v1.9.0 (CIRISPersist#84) — count of live change-feed
    /// subscriptions.
    #[getter]
    fn subscription_count(&self) -> usize {
        self.subscriptions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .subs
            .len()
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
        self.ensure_usable()?;
        catch_panic(|| {
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
        })
    }

    /// v0.2.1 — Sign arbitrary bytes with the deployment's Ed25519
    /// signing key (the hot-path signature in the hybrid writer
    /// contract). Returns the 64-byte raw signature.
    ///
    /// Mirrors `public_key_b64()` shape: bytes in, bytes out, no key
    /// material crossing the FFI. Lets consumers (notably the lens
    /// team's federation-envelope flow) hand canonical bytes to
    /// persist and get a signature back without pulling the keyring
    /// seed across the boundary.
    ///
    /// **Hot-path Ed25519 only.** The cold-path ML-DSA-65 sign
    /// happens elsewhere (writer's responsibility — kicked off
    /// immediately after this returns, NOT batched). This method
    /// returns when Ed25519 sign completes; the writer is responsible
    /// for the cold-path PQC kickoff per
    /// `docs/FEDERATION_DIRECTORY.md` §"Trust contract".
    fn sign<'py>(&self, py: Python<'py>, message: &Bound<'py, PyBytes>) -> PyResult<Py<PyBytes>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let signer = self.signer.clone();
            let runtime = self.runtime.clone();
            let msg = message.as_bytes().to_vec();
            let sig_bytes = py.detach(|| {
                runtime.block_on(async move {
                    signer
                        .sign(&msg)
                        .await
                        .map_err(|e| PyRuntimeError::new_err(format!("sign: {e}")))
                })
            })?;
            Ok(PyBytes::new(py, &sig_bytes).unbind())
        })
    }

    /// v0.2.1 — Canonicalize a federation envelope (KeyRecord
    /// registration_envelope, or any JSON object you intend to sign
    /// as part of a federation row's scrub envelope) using persist's
    /// `PythonJsonDumpsCanonicalizer` shape: sorted keys, no
    /// whitespace, `ensure_ascii=True`. Returns the exact byte
    /// sequence that should be signed.
    ///
    /// Lens team's preferred shape per the v0.2.x ask: hides the
    /// canonicalization rules inside persist (where they live
    /// anyway, since persist's own scrub-signing uses them) so
    /// lens/persist don't drift if either side touches the rules.
    ///
    /// Workflow:
    /// 1. Lens builds a JSON object describing the key role (e.g.
    ///    `{"role": "lens-steward", "scope": "..."}`).
    /// 2. `canonical_bytes = engine.canonicalize_envelope(json.dumps(envelope))`
    /// 3. `classical_sig = engine.sign(canonical_bytes)` — hot path.
    /// 4. Build the SignedKeyRecord; submit via put_public_key.
    /// 5. Cold path: ML-DSA-65 sign over (canonical_bytes ||
    ///    classical_sig); call attach_key_pqc_signature once done.
    fn canonicalize_envelope<'py>(
        &self,
        py: Python<'py>,
        envelope_json: &str,
    ) -> PyResult<Py<PyBytes>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let value: serde_json::Value = serde_json::from_str(envelope_json)
                .map_err(|e| PyValueError::new_err(format!("envelope JSON decode: {e}")))?;
            let bytes = <PythonJsonDumpsCanonicalizer as crate::verify::canonical::Canonicalizer>::canonicalize_value(
            &PythonJsonDumpsCanonicalizer,
            &value,
        )
        .map_err(|e| PyRuntimeError::new_err(format!("canonicalize: {e}")))?;
            Ok(PyBytes::new(py, &bytes).unbind())
        })
    }

    /// v1.4.0 (CIRISPersist#51) — Return the local-process Ed25519
    /// public key (base64) for publishing to consumers (registry
    /// pinning, federation_keys.pubkey_ed25519_base64). Distinct from
    /// `public_key_b64()` (which returns the scrub-envelope identity's
    /// pubkey).
    ///
    /// "Local" here means the per-process signing identity — the key
    /// the local Engine holds in `local_key_path`, independent of any
    /// federation-directory role tag. Every CIRIS agent (`client`,
    /// `proxy`, or `server`) has a local signer; the role label is
    /// what the FederationDirectory says, not what the Engine carries.
    ///
    /// **Renamed from `steward_public_key_b64` in v1.4.0** to remove
    /// the role-tag conceptual leak. The old name is fully removed —
    /// callers must update to `local_public_key_b64`.
    ///
    /// Raises `ValueError` if the Engine wasn't constructed with
    /// `local_key_id` + `local_key_path` (no local signing identity
    /// configured).
    fn local_public_key_b64(&self, _py: Python<'_>) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            // v0.4.2 — thin wrapper over LocalSigner::public_key_b64.
            self.local_signer
                .as_ref()
                .map(|s| s.public_key_b64())
                .ok_or_else(|| {
                    PyValueError::new_err(
                        "no local signing key configured (pass local_key_id + local_key_path \
                     to the Engine constructor)",
                    )
                })
        })
    }

    /// v1.4.0 (CIRISPersist#51) — Return the configured `local_key_id`
    /// — the stable identifier for this Engine's local Ed25519 signing
    /// identity. Used as `key_id` in the per-process federation_keys
    /// row, and as `scrub_key_id` for federation rows the process
    /// publishes.
    ///
    /// **Renamed from `steward_key_id` in v1.4.0** to remove the
    /// role-tag conceptual leak. The old name is fully removed —
    /// callers must update to `local_key_id`.
    ///
    /// Raises `ValueError` if no local signing identity is configured.
    fn local_key_id(&self, _py: Python<'_>) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            // v0.4.2 — thin wrapper over LocalSigner::key_id.
            self.local_signer
                .as_ref()
                .map(|s| s.key_id().to_owned())
                .ok_or_else(|| {
                    PyValueError::new_err(
                        "no local signing key configured (pass local_key_id + local_key_path \
                     to the Engine constructor)",
                    )
                })
        })
    }

    /// v1.4.0 (CIRISPersist#51) — Sign arbitrary bytes with the local
    /// Ed25519 signing key. Returns the 64-byte raw signature.
    ///
    /// Same FFI-boundary discipline as `Engine.sign()`: bytes in,
    /// bytes out, no key material crossing the boundary. The host
    /// process never sees the seed.
    ///
    /// **Hot-path Ed25519 only.** The cold-path ML-DSA-65 sign
    /// happens elsewhere — the caller runs ML-DSA-65 sign over
    /// `(canonical || classical_sig)` via its own pipeline and
    /// fills in via `attach_key_pqc_signature()` per the writer
    /// contract (`docs/FEDERATION_DIRECTORY.md` §"Trust contract").
    ///
    /// **Renamed from `steward_sign` in v1.4.0** to remove the
    /// role-tag conceptual leak. The old name is fully removed —
    /// callers must update to `local_sign`.
    ///
    /// Raises `ValueError` if no local signing key is configured.
    fn local_sign<'py>(
        &self,
        py: Python<'py>,
        message: &Bound<'py, PyBytes>,
    ) -> PyResult<Py<PyBytes>> {
        self.ensure_usable()?;
        catch_panic(|| {
            // v0.4.2 — thin wrapper over LocalSigner::sign_ed25519.
            // Single-source-of-truth: Rust callers (CIRISLensCore) and
            // PyO3 callers hit identical bytes-in / bytes-out logic.
            let signer = self.local_signer.as_ref().ok_or_else(|| {
                PyValueError::new_err(
                    "no local signing key configured (pass local_key_id + local_key_path \
                 to the Engine constructor)",
                )
            })?;
            let sig = signer
                .sign_ed25519(message.as_bytes())
                .map_err(local_signer_err_to_py)?;
            Ok(PyBytes::new(py, &sig).unbind())
        })
    }

    /// v1.4.0 (CIRISPersist#51) — Return the local-process ML-DSA-65
    /// public key (base64) for publishing to consumers
    /// (federation_keys.pubkey_ml_dsa_65_base64, peer pinning,
    /// fingerprint registries). Distinct from `local_public_key_b64()`
    /// (the Ed25519 identity).
    ///
    /// 1952-byte raw ML-DSA-65 public key per FIPS 204 final, base64
    /// standard alphabet → ~2604 chars.
    ///
    /// **Renamed from `steward_pqc_public_key_b64` in v1.4.0** to
    /// remove the role-tag conceptual leak. The old name is fully
    /// removed — callers must update to `local_pqc_public_key_b64`.
    ///
    /// Raises `ValueError` if the Engine wasn't constructed with both
    /// `local_pqc_key_id` + `local_pqc_key_path` (the cold-path PQC
    /// identity isn't configured).
    fn local_pqc_public_key_b64(&self, py: Python<'_>) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            // v0.4.2 — thin wrapper over LocalSigner::pqc_public_key_b64.
            let signer = self.local_signer.clone().ok_or_else(|| {
                PyValueError::new_err(
                    "no local PQC key configured (pass local_pqc_key_id + \
                 local_pqc_key_path to the Engine constructor)",
                )
            })?;
            let runtime = self.runtime.clone();
            let result =
                py.detach(|| runtime.block_on(async move { signer.pqc_public_key_b64().await }));
            result.map_err(local_signer_err_to_py)?.ok_or_else(|| {
                PyValueError::new_err(
                    "no local PQC key configured (pass local_pqc_key_id + \
                     local_pqc_key_path to the Engine constructor)",
                )
            })
        })
    }

    /// v1.4.0 (CIRISPersist#51) — Return the configured
    /// `local_pqc_key_id`. Distinct from `local_key_id` (the Ed25519
    /// identity); deployments will typically pin them equal but the
    /// alias spaces don't have to match.
    ///
    /// **Renamed from `steward_pqc_key_id` in v1.4.0** to remove the
    /// role-tag conceptual leak. The old name is fully removed —
    /// callers must update to `local_pqc_key_id`.
    fn local_pqc_key_id(&self, _py: Python<'_>) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            // v0.4.2 — thin wrapper over LocalSigner::pqc_key_id.
            self.local_signer
                .as_ref()
                .and_then(|s| s.pqc_key_id().map(str::to_owned))
                .ok_or_else(|| {
                    PyValueError::new_err(
                        "no local PQC key configured (pass local_pqc_key_id + \
                     local_pqc_key_path to the Engine constructor)",
                    )
                })
        })
    }

    /// v1.4.0 (CIRISPersist#51) — Sign arbitrary bytes with the local
    /// ML-DSA-65 signing key. Returns the 3309-byte raw signature
    /// (FIPS 204 final).
    ///
    /// Same FFI-boundary discipline as `local_sign()`: bytes in,
    /// bytes out, no key material crossing the boundary. Persist
    /// owns the cold-path PQC sign automatically after federation
    /// writes (CIRISPersist#10) — this method is the explicit-call
    /// escape hatch for consumers that need a one-off sign outside
    /// the auto-fire flow.
    ///
    /// Per the writer contract in V004 schema header, cold-path
    /// signs over `(canonical_envelope_bytes || classical_sig_bytes)`
    /// — the bound-signature pattern matching CIRISVerify's
    /// `HybridSignature` shape (`ciris-crypto/src/types.rs:156`).
    /// Callers concatenate the two byte sequences before calling.
    ///
    /// **Renamed from `steward_pqc_sign` in v1.4.0** to remove the
    /// role-tag conceptual leak. The old name is fully removed —
    /// callers must update to `local_pqc_sign`.
    ///
    /// Raises `ValueError` if no local PQC key is configured.
    fn local_pqc_sign<'py>(
        &self,
        py: Python<'py>,
        message: &Bound<'py, PyBytes>,
    ) -> PyResult<Py<PyBytes>> {
        self.ensure_usable()?;
        catch_panic(|| {
            // v0.4.2 — thin wrapper over LocalSigner::sign_ml_dsa_65.
            let signer = self.local_signer.clone().ok_or_else(|| {
                PyValueError::new_err(
                    "no local PQC key configured (pass local_pqc_key_id + \
                 local_pqc_key_path to the Engine constructor)",
                )
            })?;
            let runtime = self.runtime.clone();
            let msg = message.as_bytes().to_vec();
            let sig_bytes = py
                .detach(|| runtime.block_on(async move { signer.sign_ml_dsa_65(&msg).await }))
                .map_err(local_signer_err_to_py)?;
            Ok(PyBytes::new(py, &sig_bytes).unbind())
        })
    }

    /// v0.1.18 — debug helper for canonical-byte drift diagnosis
    /// (CIRISPersist#6 follow-up). Pipes a raw HTTP body through
    /// persist's schema parse + canonicalizer and returns BOTH
    /// canonical shapes — sha256 + base64-encoded full bytes — for
    /// each `CompleteTrace` in the envelope. Lets the bridge
    /// diff persist's canonicalization against an offline
    /// `python -c "import json, sys; ..."` reference without
    /// needing to interpret production verify-failure logs.
    ///
    /// Returns a Python list (one entry per CompleteTrace event in
    /// the body):
    ///
    /// ```python
    /// [
    ///   {
    ///     "trace_id": "trace-...",
    ///     "signature_key_id": "agent-...",
    ///     "signature": "...",                  # b64-encoded as on the wire
    ///     "canonical_9field_sha256": "abc123...",
    ///     "canonical_9field_b64": "Cgo...",    # full canonical bytes, base64
    ///     "canonical_9field_bytes_len": 16149,
    ///     "canonical_2field_sha256": "def456...",
    ///     "canonical_2field_b64": "ZGVm...",
    ///     "canonical_2field_bytes_len": 15827,
    ///   },
    ///   ...
    /// ]
    /// ```
    ///
    /// **Diagnostic-only**. Production code paths should use
    /// `receive_and_persist`; this method is a debug-print escape
    /// hatch. Doesn't verify signatures, doesn't write to the
    /// backend, doesn't increment any metric. Bypass-safe.
    fn debug_canonicalize<'py>(
        &self,
        py: Python<'py>,
        body: &Bound<'py, PyBytes>,
    ) -> PyResult<Bound<'py, pyo3::types::PyList>> {
        self.ensure_usable()?;
        catch_panic(|| {
            use crate::schema::{BatchEnvelope, BatchEvent};
            use crate::verify::ed25519::canonical_payload_sha256s;
            use base64::engine::general_purpose::STANDARD as BASE64;
            use base64::Engine as _;

            let bytes = body.as_bytes();
            let env = BatchEnvelope::from_json(bytes)
                .map_err(|e| PyValueError::new_err(format!("{e}")))?;

            let result = pyo3::types::PyList::empty(py);
            for event in &env.events {
                let BatchEvent::CompleteTrace { trace, .. } = event;
                let diag = canonical_payload_sha256s(trace, &PythonJsonDumpsCanonicalizer)
                    .map_err(|e| PyRuntimeError::new_err(format!("canonicalize: {e}")))?;
                let entry = PyDict::new(py);
                entry.set_item("trace_id", trace.trace_id.as_str())?;
                entry.set_item("signature_key_id", trace.signature_key_id.as_str())?;
                entry.set_item("signature", trace.signature.as_str())?;
                entry.set_item("canonical_9field_sha256", diag.nine_field_sha256.as_str())?;
                entry.set_item(
                    "canonical_9field_b64",
                    BASE64.encode(&diag.nine_field_bytes),
                )?;
                entry.set_item("canonical_9field_bytes_len", diag.nine_field_bytes.len())?;
                entry.set_item("canonical_2field_sha256", diag.two_field_sha256.as_str())?;
                entry.set_item("canonical_2field_b64", BASE64.encode(&diag.two_field_bytes))?;
                entry.set_item("canonical_2field_bytes_len", diag.two_field_bytes.len())?;
                result.append(entry)?;
            }
            Ok(result)
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
        self.ensure_usable()?;
        catch_panic(|| {
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

            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
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
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    // SQLite shape (migrations/sqlite/lens/V001
                    // accord_public_keys): unqualified table name (no
                    // `cirislens.` schema prefix), `?N` placeholders,
                    // TEXT-encoded ISO-8601 for `expires_at` matching
                    // the rest of the SQLite TEXT-as-TIMESTAMPTZ
                    // convention. Idempotent on `key_id` PRIMARY KEY
                    // via `ON CONFLICT DO NOTHING` (same shape as PG).
                    let conn = sq.conn_handle();
                    let expires_text: Option<String> = expires_dt.map(|t| t.to_rfc3339());
                    runtime.block_on(async move {
                        tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
                            let conn = conn.blocking_lock();
                            conn.execute(
                                    "INSERT INTO accord_public_keys \
                                     (key_id, public_key_base64, algorithm, description, \
                                      expires_at, added_by) \
                                     VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                                     ON CONFLICT (key_id) DO NOTHING",
                                    rusqlite::params![
                                        key_id,
                                        pub_b64,
                                        algo,
                                        desc,
                                        expires_text,
                                        added,
                                    ],
                                )?;
                            Ok(())
                        })
                        .await
                        .map_err(|e| {
                            PyRuntimeError::new_err(format!("register spawn_blocking join: {e}"))
                        })?
                        .map_err(|e| PyRuntimeError::new_err(format!("register: {e}")))?;
                        Ok::<_, PyErr>(())
                    })
                }
            })
        })
    }

    /// Run the FSD §3.3 pipeline on a batch body.
    ///
    /// Returns a Python dict with the BatchSummary fields. Raises
    /// `ValueError` for schema/verify/scrub rejections (lens
    /// translates to 4xx) and `RuntimeError` for backend issues
    /// (lens translates to 5xx).
    ///
    /// # `pre_verified` (CIRISPersist#91)
    ///
    /// `pre_verified=False` (the default) runs
    /// [`VerifyMode::Full`](crate::ingest::VerifyMode) — every
    /// `CompleteTrace` signature is verified. This is the only safe
    /// setting for untrusted direct-ingest input and the lens
    /// direct-ingest path MUST leave it defaulted.
    ///
    /// `pre_verified=True` runs
    /// [`VerifyMode::TrustPreVerified`](crate::ingest::VerifyMode):
    /// per-trace signature verification (and its federation-directory
    /// lookup) is skipped. Opt-in, and legitimate **only** for a relay
    /// that already holds an Edge `verify_outcome` for the batch
    /// (AV-9). The decision lives at this call site. Rows persisted
    /// this way land with `verification_source = 'edge'` — an upstream
    /// Edge verifier, not persist, established authenticity
    /// (`signature_verified` stays `true`; the trace is authentic).
    #[pyo3(signature = (body, pre_verified = false))]
    fn receive_and_persist<'py>(
        &self,
        py: Python<'py>,
        body: &Bound<'py, PyBytes>,
        pre_verified: bool,
    ) -> PyResult<Bound<'py, PyDict>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let bytes = body.as_bytes().to_vec();
            let scrubber = self.scrubber.clone();
            let signer = self.signer.clone();
            let signer_key_id = self.signer_key_id.clone();
            let runtime = self.runtime.clone();
            let verify_mode = if pre_verified {
                crate::ingest::VerifyMode::TrustPreVerified
            } else {
                crate::ingest::VerifyMode::Full
            };

            let summary = py.detach(|| match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        let pipeline = IngestPipeline {
                            backend: &*backend,
                            canonicalizer: &PythonJsonDumpsCanonicalizer,
                            scrubber: &*scrubber,
                            signer: &*signer,
                            signer_key_id: &signer_key_id,
                        };
                        pipeline.receive_and_persist_with(&bytes, verify_mode).await
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        let pipeline = IngestPipeline {
                            backend: &*backend,
                            canonicalizer: &PythonJsonDumpsCanonicalizer,
                            scrubber: &*scrubber,
                            signer: &*signer,
                            signer_key_id: &signer_key_id,
                        };
                        pipeline.receive_and_persist_with(&bytes, verify_mode).await
                    })
                }
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
                // Python exception carries only the stable kind token
                // (and, when present, a structured `detail` string —
                // closed-set field names / typed integers / version
                // stamps; never raw user-payload bytes).
                // The lens HTTP layer maps token → status code.
                //
                // v0.4.6 (CIRISPersist#22) — When `IngestError::detail()`
                // is `Some`, the Python exception's `args` is the 2-tuple
                // `(kind, detail)` so callers can extract the field name
                // (e.g. `"attempt_index"`) without source-diving the
                // persist crate. When `None`, `args` stays as `(kind,)` —
                // backward-compatible with the v0.4.5 single-string shape.
                // Lens consumers read:
                //
                //   kind = e.args[0]
                //   detail = e.args[1] if len(e.args) > 1 else None
                Err(e) => {
                    let kind = e.kind();
                    let detail = e.detail();
                    tracing::warn!(
                        error = %e, kind = kind, detail = detail.as_deref(),
                        "ingest rejected"
                    );
                    match e {
                        // Schema / verify / scrub → ValueError (caller-fault; 4xx).
                        // v1.1.0 (CIRISPersist#33 part 3) — PipelineInvariant
                        // is also caller-fault (FSD §4.3 shape violation
                        // signalled by the edge); maps to lens-side HTTP 422.
                        IngestError::Schema(_)
                        | IngestError::Verify(_)
                        | IngestError::Scrub(_)
                        | IngestError::PipelineInvariant { .. } => Err(match detail {
                            Some(d) => PyValueError::new_err((kind, d)),
                            None => PyValueError::new_err(kind),
                        }),
                        // Store / Sign → RuntimeError (server-fault; 5xx).
                        // AV-25: signing failure is operator-side
                        // (keyring locked, hardware unavailable, etc.) —
                        // never the agent's fault, never a 4xx.
                        IngestError::Store(_) | IngestError::Sign(_) => Err(match detail {
                            Some(d) => PyRuntimeError::new_err((kind, d)),
                            None => PyRuntimeError::new_err(kind),
                        }),
                    }
                }
            }
        })
    }

    // ── v0.2.0 — FederationDirectory surface ───────────────────────
    //
    // Lens team's pubkey-storage cutover target. Wire shape: JSON
    // strings in/out for complex types (KeyRecord, Attestation,
    // Revocation, Signed* wrappers); primitive types (key_id, etc.)
    // as direct &str args. Lens calls json.dumps before passing in,
    // json.loads on receiving back — adds a serde round-trip on
    // each call but keeps the API uniform across complex shapes.
    //
    // See docs/FEDERATION_DIRECTORY.md for the architectural
    // contract and types::SignedKeyRecord / Attestation / Revocation
    // for the JSON shape.

    /// Federation directory: register a public key.
    ///
    /// `signed_key_record_json` is a JSON string of `SignedKeyRecord`
    /// (`{"record": {...KeyRecord fields...}}`). The PQC fields
    /// (`pubkey_ml_dsa_65_base64`, `scrub_signature_pqc`) may be
    /// absent or null on initial write — the writer kicks off ML-DSA-65
    /// signing on the cold path and calls `attach_key_pqc_signature`
    /// to fill them in. `algorithm` MUST be `"hybrid"`.
    fn put_public_key(&self, py: Python<'_>, signed_key_record_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let record: crate::federation::SignedKeyRecord =
                serde_json::from_str(signed_key_record_json).map_err(|e| {
                    PyValueError::new_err(format!("SignedKeyRecord JSON decode: {e}"))
                })?;

            // v0.3.1 — cold-path PQC fill-in (CIRISPersist#10). Capture
            // the inputs the auto-fire task needs BEFORE backend consumes
            // the record. Cold-path skips when no local PQC key is
            // configured; row stays hybrid-pending and consumers can fill
            // via the attach_*_pqc_signature escape hatch on their own
            // schedule.
            let cold_path_inputs =
                self.local_signer
                    .as_ref()
                    .and_then(|s| s.pqc_signer())
                    .map(|signer| {
                        (
                            signer,
                            record.record.key_id.clone(),
                            record.record.registration_envelope.clone(),
                            record.record.scrub_signature_classical.clone(),
                        )
                    });

            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .put_public_key(record)
                            .await
                            .map_err(federation_err_to_py)?;

                        // Cold-path fire-and-forget. We're already inside
                        // tokio::Runtime::block_on, so tokio::spawn here
                        // schedules the task without waiting. The synchronous
                        // Python call returns as soon as the put commits;
                        // PQC catches up within seconds.
                        if let Some((signer, key_id, envelope, classical_sig_b64)) =
                            cold_path_inputs
                        {
                            let backend = backend.clone();
                            tokio::spawn(async move {
                                match cold_path_pqc_sign(&*signer, &envelope, &classical_sig_b64)
                                    .await
                                {
                                    Ok((pubkey_b64, pqc_sig_b64)) => {
                                        if let Err(e) = backend
                                            .attach_key_pqc_signature(
                                                &key_id,
                                                &pubkey_b64,
                                                &pqc_sig_b64,
                                            )
                                            .await
                                        {
                                            tracing::warn!(
                                                key_id = key_id.as_str(),
                                                error = %e,
                                                "cold-path PQC attach_key_pqc_signature failed; \
                                                 row stays hybrid-pending"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            key_id = key_id.as_str(),
                                            error = %e,
                                            "cold-path PQC sign failed; row stays hybrid-pending"
                                        );
                                    }
                                }
                            });
                        }
                        Ok(())
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .put_public_key(record)
                            .await
                            .map_err(federation_err_to_py)?;

                        // Cold-path fire-and-forget; same shape as the
                        // Postgres arm — tokio::spawn inside the tokio
                        // runtime returns immediately, PQC attach
                        // catches up out-of-band.
                        if let Some((signer, key_id, envelope, classical_sig_b64)) =
                            cold_path_inputs
                        {
                            let backend = backend.clone();
                            tokio::spawn(async move {
                                match cold_path_pqc_sign(&*signer, &envelope, &classical_sig_b64)
                                    .await
                                {
                                    Ok((pubkey_b64, pqc_sig_b64)) => {
                                        if let Err(e) = backend
                                            .attach_key_pqc_signature(
                                                &key_id,
                                                &pubkey_b64,
                                                &pqc_sig_b64,
                                            )
                                            .await
                                        {
                                            tracing::warn!(
                                                key_id = key_id.as_str(),
                                                error = %e,
                                                "cold-path PQC attach_key_pqc_signature failed; \
                                                 row stays hybrid-pending"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            key_id = key_id.as_str(),
                                            error = %e,
                                            "cold-path PQC sign failed; row stays hybrid-pending"
                                        );
                                    }
                                }
                            });
                        }
                        Ok(())
                    })
                }
            })
        })
    }

    /// v1.5.3 — One-call helper that registers THIS engine's local
    /// pubkey as a `federation_keys` row of the specified
    /// `identity_type`. Composes the existing primitives
    /// (`canonicalize_envelope` + `local_sign` + `put_public_key`) so
    /// callers don't have to re-implement persist's canonical-bytes
    /// rule in their own language.
    ///
    /// What it does:
    /// 1. Builds a `KeyRecord` with this engine's local Ed25519 pubkey
    ///    + `key_id`, the supplied `identity_type` / `identity_ref` /
    ///    `valid_until`, and `algorithm = "hybrid"`.
    /// 2. Canonicalizes the supplied `registration_envelope` JSON via
    ///    `PythonJsonDumpsCanonicalizer` (same rule the existing
    ///    `canonicalize_envelope` PyO3 method uses).
    /// 3. Signs those canonical bytes with the local Ed25519 key →
    ///    `scrub_signature_classical`.
    /// 4. `original_content_hash = hex(SHA-256(canonical_bytes))`.
    /// 5. `scrub_key_id = key_id` (self-signed bootstrap row).
    /// 6. ML-DSA-65 half left as `None` — the existing cold-path PQC
    ///    fill in `put_public_key` will attach the PQC signature
    ///    asynchronously if the engine was constructed with PQC keys.
    /// 7. Calls `put_public_key` with the assembled `SignedKeyRecord`.
    ///
    /// Returns the registered `key_id` (which equals
    /// `engine.local_key_id()`).
    ///
    /// Idempotent on `(key_id)` PRIMARY KEY of `federation_keys` — the
    /// underlying `put_public_key` writer rejects on key_id conflict
    /// with differing content, no-ops on identical re-registration.
    ///
    /// Raises:
    /// - `ValueError` if no local signing identity is configured.
    /// - `ValueError` if `valid_until` is malformed ISO-8601.
    /// - `ValueError` if `registration_envelope_json` doesn't parse.
    /// - `RuntimeError` for backend errors (pool, conflict, etc.).
    #[pyo3(signature = (identity_type, identity_ref, valid_until = None,
                        registration_envelope_json = None, roles = None))]
    fn register_federation_key(
        &self,
        py: Python<'_>,
        identity_type: &str,
        identity_ref: &str,
        valid_until: Option<&str>,
        registration_envelope_json: Option<&str>,
        roles: Option<Vec<String>>,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            use base64::engine::general_purpose::STANDARD as B64;
            use base64::Engine as _;
            use sha2::{Digest, Sha256};

            let signer = self.local_signer.clone().ok_or_else(|| {
                PyValueError::new_err(
                    "no local signing key configured (pass local_key_id + local_key_path \
                     to the Engine constructor)",
                )
            })?;

            // Parse valid_until.
            let valid_until_dt: Option<chrono::DateTime<chrono::Utc>> = match valid_until {
                None => None,
                Some(s) => Some(s.parse().map_err(|e| {
                    PyValueError::new_err(format!("valid_until must be ISO-8601 (got {s:?}): {e}"))
                })?),
            };

            // Parse registration_envelope (default to {}).
            let envelope: serde_json::Value = match registration_envelope_json {
                None => serde_json::json!({}),
                Some(s) => serde_json::from_str(s).map_err(|e| {
                    PyValueError::new_err(format!("registration_envelope JSON decode: {e}"))
                })?,
            };

            // Canonicalize envelope — same shape as canonicalize_envelope
            // PyO3 surface, which the documented manual workflow uses.
            let canonical_bytes = <PythonJsonDumpsCanonicalizer as crate::verify::canonical::Canonicalizer>::canonicalize_value(
                &PythonJsonDumpsCanonicalizer,
                &envelope,
            )
            .map_err(|e| PyRuntimeError::new_err(format!("canonicalize: {e}")))?;

            // SHA-256 hex of the canonical bytes.
            let mut hasher = Sha256::new();
            hasher.update(&canonical_bytes);
            let original_content_hash = format!("{:x}", hasher.finalize());

            // Classical Ed25519 sig over canonical_bytes — base64.
            let classical_sig_bytes = signer
                .sign_ed25519(&canonical_bytes)
                .map_err(|e| PyRuntimeError::new_err(format!("local_sign: {e}")))?;
            let classical_sig_b64 = B64.encode(classical_sig_bytes);

            // Build KeyRecord. PQC half + persist_row_hash + pqc_completed_at
            // left to the existing put_public_key cold-path + server-compute.
            let key_id = signer.key_id().to_owned();
            let pubkey_ed25519_b64 = signer.public_key_b64();
            // Truncate to microsecond precision — Postgres TIMESTAMPTZ is
            // microsecond-precision, so the post-storage round-trip would
            // otherwise differ from the pre-storage canonical bytes. Mirrors
            // crate::audit::verify::truncate_to_micros (inlined to avoid a
            // cirisaudit-feature dependency on this path).
            let now = {
                use chrono::Timelike as _;
                let dt = chrono::Utc::now();
                let micros = dt.nanosecond() / 1000;
                dt.with_nanosecond(micros * 1000).unwrap_or(dt)
            };

            let record = crate::federation::KeyRecord {
                key_id: key_id.clone(),
                pubkey_ed25519_base64: pubkey_ed25519_b64,
                pubkey_ml_dsa_65_base64: None,
                algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
                identity_type: identity_type.to_owned(),
                identity_ref: identity_ref.to_owned(),
                valid_from: now,
                valid_until: valid_until_dt,
                registration_envelope: envelope,
                original_content_hash,
                scrub_signature_classical: classical_sig_b64,
                scrub_signature_pqc: None,
                scrub_key_id: key_id.clone(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                roles: roles.unwrap_or_default(),
                // v2.5.0 (CIRISPersist#102 Ask 8) — the PyO3
                // self-signing path is used by lens/agent bootstrap
                // for steward / primitive / agent identities; it
                // does NOT mint accord-holder keys (those go through
                // a separate hardware-attestation bootstrap that
                // populates `attestation_evidence` directly via
                // `put_public_key` with a fully-formed
                // SignedKeyRecord). Default to None here.
                attestation_evidence: None,
            };
            let signed = crate::federation::SignedKeyRecord { record };
            let signed_json = serde_json::to_string(&signed).map_err(|e| {
                PyRuntimeError::new_err(format!("SignedKeyRecord JSON encode: {e}"))
            })?;

            // Delegate to put_public_key — handles backend dispatch +
            // cold-path PQC fill automatically.
            self.put_public_key(py, &signed_json)?;
            Ok(key_id)
        })
    }

    /// Federation directory: lookup a public key by `key_id`.
    /// Returns the JSON-encoded `KeyRecord` string, or `None`.
    fn lookup_public_key(&self, py: Python<'_>, key_id: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let key_id = key_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let opt = <PostgresBackend as FederationDirectory>::lookup_public_key(
                            &backend, &key_id,
                        )
                        .await
                        .map_err(federation_err_to_py)?;
                        match opt {
                            None => Ok(None),
                            Some(rec) => Ok(Some(serde_json::to_string(&rec).map_err(|e| {
                                PyRuntimeError::new_err(format!("KeyRecord JSON encode: {e}"))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let opt = <SqliteBackend as FederationDirectory>::lookup_public_key(
                            &backend, &key_id,
                        )
                        .await
                        .map_err(federation_err_to_py)?;
                        match opt {
                            None => Ok(None),
                            Some(rec) => Ok(Some(serde_json::to_string(&rec).map_err(|e| {
                                PyRuntimeError::new_err(format!("KeyRecord JSON encode: {e}"))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    /// Cold-start binding-rooting primitive (CIRISPersist#94).
    ///
    /// Confirm a claimed `(key_id, pubkey)` binding against the
    /// `federation_keys` directory and verify the row's recursive-
    /// provenance chain up to a steward bootstrap. Replaces
    /// trust-on-first-use.
    ///
    /// Returns the [`RootingVerdict`](crate::federation::RootingVerdict)
    /// as a JSON string — `{"verdict":"confirmed", ...}` or
    /// `{"verdict":"rejected","reason":...}`. A `Rejected` verdict is
    /// NOT a Python exception: rooting always produces a typed verdict
    /// (MISSION.md §1.6 — fail-honest), so the caller branches on the
    /// `verdict` field rather than catching.
    ///
    /// CIRISEdge's resolver is Rust and calls
    /// `crate::federation::root_binding` directly; this PyO3 wrapper
    /// mirrors the `lookup_public_key` surface for the lens FastAPI
    /// integration. **One implementation, both surfaces.**
    fn root_binding(
        &self,
        py: Python<'_>,
        key_id: &str,
        claimed_pubkey_ed25519_base64: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let key_id = key_id.to_owned();
            let claimed = claimed_pubkey_ed25519_base64.to_owned();
            py.detach(move || {
                let verdict = match &self.backend {
                    BackendDispatch::Postgres(pg) => {
                        let backend = pg.clone();
                        runtime.block_on(async move {
                            crate::federation::root_binding(&*backend, &key_id, &claimed).await
                        })
                    }
                    #[cfg(feature = "sqlite")]
                    BackendDispatch::Sqlite(sq) => {
                        let backend = sq.clone();
                        runtime.block_on(async move {
                            crate::federation::root_binding(&*backend, &key_id, &claimed).await
                        })
                    }
                };
                serde_json::to_string(&verdict).map_err(|e| {
                    PyRuntimeError::new_err(format!("RootingVerdict JSON encode: {e}"))
                })
            })
        })
    }

    /// Verify-consumable provenance read (CIRISVerify WS-4).
    ///
    /// Returns the `federation_keys` row for `key_id` plus its full
    /// recursive-provenance four-tuple chain as a JSON string
    /// (`ProvenanceChain`), so CIRISVerify can verify the chain
    /// verify-side off its registry-local `trusted_primitive_keys`.
    ///
    /// Raises `LensQueryError` if the chain cannot be assembled
    /// (unknown `key_id`, broken link, cycle, over-depth, backend
    /// error) — the typed
    /// [`RootingRejection`](crate::federation::RootingRejection)
    /// `kind()` token is the error message. (The verifying primitive
    /// `root_binding` folds these into a `Rejected` verdict instead;
    /// this raw read surfaces them as an error since there is no
    /// chain to return.)
    fn provenance_chain(&self, py: Python<'_>, key_id: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let key_id = key_id.to_owned();
            py.detach(move || {
                let result = match &self.backend {
                    BackendDispatch::Postgres(pg) => {
                        let backend = pg.clone();
                        runtime.block_on(async move {
                            crate::federation::provenance_chain(&*backend, &key_id).await
                        })
                    }
                    #[cfg(feature = "sqlite")]
                    BackendDispatch::Sqlite(sq) => {
                        let backend = sq.clone();
                        runtime.block_on(async move {
                            crate::federation::provenance_chain(&*backend, &key_id).await
                        })
                    }
                };
                let chain = result.map_err(|rej| {
                    PyErr::new::<LensQueryError, _>(format!("provenance_chain: {}", rej.kind()))
                })?;
                serde_json::to_string(&chain).map_err(|e| {
                    PyRuntimeError::new_err(format!("ProvenanceChain JSON encode: {e}"))
                })
            })
        })
    }

    /// Federation directory: lookup all public keys for an identity_ref.
    /// Returns a JSON array string of `KeyRecord` objects.
    fn lookup_keys_for_identity(&self, py: Python<'_>, identity_ref: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let identity_ref = identity_ref.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let rows = backend
                            .lookup_keys_for_identity(&identity_ref)
                            .await
                            .map_err(federation_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<KeyRecord> JSON encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let rows = backend
                            .lookup_keys_for_identity(&identity_ref)
                            .await
                            .map_err(federation_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<KeyRecord> JSON encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// Federation directory: write an attestation.
    fn put_attestation(&self, py: Python<'_>, signed_attestation_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let att: crate::federation::SignedAttestation =
                serde_json::from_str(signed_attestation_json).map_err(|e| {
                    PyValueError::new_err(format!("SignedAttestation JSON decode: {e}"))
                })?;

            // v0.3.1 — cold-path PQC fill-in (CIRISPersist#10).
            let cold_path_inputs =
                self.local_signer
                    .as_ref()
                    .and_then(|s| s.pqc_signer())
                    .map(|signer| {
                        (
                            signer,
                            att.attestation.attestation_id.clone(),
                            att.attestation.attestation_envelope.clone(),
                            att.attestation.scrub_signature_classical.clone(),
                        )
                    });

            py.detach(|| match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .put_attestation(att)
                            .await
                            .map_err(federation_err_to_py)?;
                        if let Some((signer, attestation_id, envelope, classical_sig_b64)) =
                            cold_path_inputs
                        {
                            let backend = backend.clone();
                            tokio::spawn(async move {
                                match cold_path_pqc_sign(&*signer, &envelope, &classical_sig_b64)
                                    .await
                                {
                                    Ok((_pubkey_b64, pqc_sig_b64)) => {
                                        // Attestations don't carry their own pubkey
                                        // (they reference scrub_key_id's federation_keys
                                        // pubkey for verification); only the PQC
                                        // signature attaches.
                                        if let Err(e) = backend
                                            .attach_attestation_pqc_signature(
                                                &attestation_id,
                                                &pqc_sig_b64,
                                            )
                                            .await
                                        {
                                            tracing::warn!(
                                                attestation_id = attestation_id.as_str(),
                                                error = %e,
                                                "cold-path PQC \
                                                 attach_attestation_pqc_signature failed; \
                                                 row stays hybrid-pending"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            attestation_id = attestation_id.as_str(),
                                            error = %e,
                                            "cold-path PQC sign failed; row stays hybrid-pending"
                                        );
                                    }
                                }
                            });
                        }
                        Ok(())
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .put_attestation(att)
                            .await
                            .map_err(federation_err_to_py)?;
                        if let Some((signer, attestation_id, envelope, classical_sig_b64)) =
                            cold_path_inputs
                        {
                            let backend = backend.clone();
                            tokio::spawn(async move {
                                match cold_path_pqc_sign(&*signer, &envelope, &classical_sig_b64)
                                    .await
                                {
                                    Ok((_pubkey_b64, pqc_sig_b64)) => {
                                        if let Err(e) = backend
                                            .attach_attestation_pqc_signature(
                                                &attestation_id,
                                                &pqc_sig_b64,
                                            )
                                            .await
                                        {
                                            tracing::warn!(
                                                attestation_id = attestation_id.as_str(),
                                                error = %e,
                                                "cold-path PQC \
                                                 attach_attestation_pqc_signature failed; \
                                                 row stays hybrid-pending"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            attestation_id = attestation_id.as_str(),
                                            error = %e,
                                            "cold-path PQC sign failed; row stays hybrid-pending"
                                        );
                                    }
                                }
                            });
                        }
                        Ok(())
                    })
                }
            })
        })
    }

    /// Federation directory: list attestations targeting `attested_key_id`.
    fn list_attestations_for(&self, py: Python<'_>, attested_key_id: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let attested_key_id = attested_key_id.to_owned();
            py.detach(|| match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let rows = backend
                            .list_attestations_for(&attested_key_id)
                            .await
                            .map_err(federation_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<Attestation> JSON encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let rows = backend
                            .list_attestations_for(&attested_key_id)
                            .await
                            .map_err(federation_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<Attestation> JSON encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// Federation directory: list attestations issued by `attesting_key_id`.
    fn list_attestations_by(&self, py: Python<'_>, attesting_key_id: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let attesting_key_id = attesting_key_id.to_owned();
            py.detach(|| match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let rows = backend
                            .list_attestations_by(&attesting_key_id)
                            .await
                            .map_err(federation_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<Attestation> JSON encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let rows = backend
                            .list_attestations_by(&attesting_key_id)
                            .await
                            .map_err(federation_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<Attestation> JSON encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// Federation directory: write a revocation.
    fn put_revocation(&self, py: Python<'_>, signed_revocation_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let rev: crate::federation::SignedRevocation =
                serde_json::from_str(signed_revocation_json).map_err(|e| {
                    PyValueError::new_err(format!("SignedRevocation JSON decode: {e}"))
                })?;

            // v0.3.1 — cold-path PQC fill-in (CIRISPersist#10).
            let cold_path_inputs =
                self.local_signer
                    .as_ref()
                    .and_then(|s| s.pqc_signer())
                    .map(|signer| {
                        (
                            signer,
                            rev.revocation.revocation_id.clone(),
                            rev.revocation.revocation_envelope.clone(),
                            rev.revocation.scrub_signature_classical.clone(),
                        )
                    });

            py.detach(|| match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .put_revocation(rev)
                            .await
                            .map_err(federation_err_to_py)?;
                        if let Some((signer, revocation_id, envelope, classical_sig_b64)) =
                            cold_path_inputs
                        {
                            let backend = backend.clone();
                            tokio::spawn(async move {
                                match cold_path_pqc_sign(&*signer, &envelope, &classical_sig_b64)
                                    .await
                                {
                                    Ok((_pubkey_b64, pqc_sig_b64)) => {
                                        if let Err(e) = backend
                                            .attach_revocation_pqc_signature(
                                                &revocation_id,
                                                &pqc_sig_b64,
                                            )
                                            .await
                                        {
                                            tracing::warn!(
                                                revocation_id = revocation_id.as_str(),
                                                error = %e,
                                                "cold-path PQC \
                                                 attach_revocation_pqc_signature failed; \
                                                 row stays hybrid-pending"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            revocation_id = revocation_id.as_str(),
                                            error = %e,
                                            "cold-path PQC sign failed; row stays hybrid-pending"
                                        );
                                    }
                                }
                            });
                        }
                        Ok(())
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .put_revocation(rev)
                            .await
                            .map_err(federation_err_to_py)?;
                        if let Some((signer, revocation_id, envelope, classical_sig_b64)) =
                            cold_path_inputs
                        {
                            let backend = backend.clone();
                            tokio::spawn(async move {
                                match cold_path_pqc_sign(&*signer, &envelope, &classical_sig_b64)
                                    .await
                                {
                                    Ok((_pubkey_b64, pqc_sig_b64)) => {
                                        if let Err(e) = backend
                                            .attach_revocation_pqc_signature(
                                                &revocation_id,
                                                &pqc_sig_b64,
                                            )
                                            .await
                                        {
                                            tracing::warn!(
                                                revocation_id = revocation_id.as_str(),
                                                error = %e,
                                                "cold-path PQC \
                                                 attach_revocation_pqc_signature failed; \
                                                 row stays hybrid-pending"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            revocation_id = revocation_id.as_str(),
                                            error = %e,
                                            "cold-path PQC sign failed; row stays hybrid-pending"
                                        );
                                    }
                                }
                            });
                        }
                        Ok(())
                    })
                }
            })
        })
    }

    /// Federation directory: list revocations targeting `revoked_key_id`.
    fn revocations_for(&self, py: Python<'_>, revoked_key_id: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let revoked_key_id = revoked_key_id.to_owned();
            py.detach(|| match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let rows = backend
                            .revocations_for(&revoked_key_id)
                            .await
                            .map_err(federation_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<Revocation> JSON encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let rows = backend
                            .revocations_for(&revoked_key_id)
                            .await
                            .map_err(federation_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<Revocation> JSON encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// Federation directory: attach the cold-path PQC signature to a
    /// hybrid-pending federation_keys row. See docs/FEDERATION_DIRECTORY.md
    /// §"Trust contract" for the writer contract — this is step 4
    /// (called once the cold-path ML-DSA-65 sign completes).
    fn attach_key_pqc_signature(
        &self,
        py: Python<'_>,
        key_id: &str,
        pubkey_ml_dsa_65_base64: &str,
        scrub_signature_pqc: &str,
    ) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let key_id = key_id.to_owned();
            let mldsa_pk = pubkey_ml_dsa_65_base64.to_owned();
            let pqc_sig = scrub_signature_pqc.to_owned();
            py.detach(|| match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .attach_key_pqc_signature(&key_id, &mldsa_pk, &pqc_sig)
                            .await
                            .map_err(federation_err_to_py)
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .attach_key_pqc_signature(&key_id, &mldsa_pk, &pqc_sig)
                            .await
                            .map_err(federation_err_to_py)
                    })
                }
            })
        })
    }

    /// Federation directory: attach PQC signature to a hybrid-pending
    /// federation_attestations row.
    fn attach_attestation_pqc_signature(
        &self,
        py: Python<'_>,
        attestation_id: &str,
        scrub_signature_pqc: &str,
    ) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let attestation_id = attestation_id.to_owned();
            let pqc_sig = scrub_signature_pqc.to_owned();
            py.detach(|| match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .attach_attestation_pqc_signature(&attestation_id, &pqc_sig)
                            .await
                            .map_err(federation_err_to_py)
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .attach_attestation_pqc_signature(&attestation_id, &pqc_sig)
                            .await
                            .map_err(federation_err_to_py)
                    })
                }
            })
        })
    }

    /// Federation directory: attach PQC signature to a hybrid-pending
    /// federation_revocations row.
    fn attach_revocation_pqc_signature(
        &self,
        py: Python<'_>,
        revocation_id: &str,
        scrub_signature_pqc: &str,
    ) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let revocation_id = revocation_id.to_owned();
            let pqc_sig = scrub_signature_pqc.to_owned();
            py.detach(|| match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .attach_revocation_pqc_signature(&revocation_id, &pqc_sig)
                            .await
                            .map_err(federation_err_to_py)
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .attach_revocation_pqc_signature(&revocation_id, &pqc_sig)
                            .await
                            .map_err(federation_err_to_py)
                    })
                }
            })
        })
    }

    // ── v2.3 (CIRISPersist#103) — BlobStorage PyO3 surface ─────────
    //
    // JSON in / JSON out. Inline bytes ride the wire as base64
    // standard-alphabet strings (mirrors the V046 delivery_attestation
    // surface and the existing scrub envelope pattern). Errors go
    // through `blob_err_to_py` — a sibling to `federation_err_to_py`
    // that maps the blob-error kind() vocabulary to typed PyErr.

    /// Federation blob storage: write a blob with hash-on-write +
    /// holder-attestation emission.
    ///
    /// `payload_json` shape:
    ///
    /// ```json
    /// {
    ///   "sha256": "<64-hex>",
    ///   "body": {"inline": "<base64>"} | {"external": {"uri": "...",
    ///     "size_bytes": N, "media_type": "...|null"}},
    ///   "media_type": "...|null",
    ///   "attestation": {
    ///     "attesting_key_id": "...",
    ///     "attestation_id": "<uuid-v4>",
    ///     "original_content_hash_hex": "<hex>",
    ///     "scrub_signature_classical": "<base64>",
    ///     "scrub_signature_pqc": "<base64>|null",
    ///     "scrub_key_id": "...",
    ///     "scrub_timestamp": "RFC3339"
    ///   }
    /// }
    /// ```
    fn put_blob_json(&self, py: Python<'_>, payload_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let payload = parse_put_blob_payload(payload_json)?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::BlobStorage;
                        backend
                            .put_blob(
                                &payload.sha256,
                                payload.body,
                                payload.media_type.as_deref(),
                                payload.attestation,
                            )
                            .await
                            .map_err(blob_err_to_py)
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::BlobStorage;
                        backend
                            .put_blob(
                                &payload.sha256,
                                payload.body,
                                payload.media_type.as_deref(),
                                payload.attestation,
                            )
                            .await
                            .map_err(blob_err_to_py)
                    })
                }
            })
        })
    }

    /// Federation blob storage: read a blob by SHA-256 (hex).
    ///
    /// Returns `None` when no row exists; otherwise a JSON string of
    /// `BlobBody`:
    ///
    /// - Inline: `{"inline": "<base64-bytes>"}`
    /// - External: `{"external": {"uri": "...", "size_bytes": N,
    ///   "media_type": "...|null"}}`
    fn get_blob_json(&self, py: Python<'_>, sha256_hex: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let sha = parse_sha256_hex(sha256_hex)?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::BlobStorage;
                        let body_opt = backend.get_blob(&sha).await.map_err(blob_err_to_py)?;
                        match body_opt {
                            None => Ok(None),
                            Some(body) => encode_blob_body_json(&body).map(Some),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::BlobStorage;
                        let body_opt = backend.get_blob(&sha).await.map_err(blob_err_to_py)?;
                        match body_opt {
                            None => Ok(None),
                            Some(body) => encode_blob_body_json(&body).map(Some),
                        }
                    })
                }
            })
        })
    }

    /// Federation blob storage: existence check by SHA-256 (hex).
    fn has_blob_json(&self, py: Python<'_>, sha256_hex: &str) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let sha = parse_sha256_hex(sha256_hex)?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::BlobStorage;
                        backend.has_blob(&sha).await.map_err(blob_err_to_py)
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::BlobStorage;
                        backend.has_blob(&sha).await.map_err(blob_err_to_py)
                    })
                }
            })
        })
    }

    /// Federation blob storage: list holders of a blob by SHA-256
    /// (hex). Returns a JSON array of attesting_key_id strings.
    fn list_holders_json(&self, py: Python<'_>, sha256_hex: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let sha = parse_sha256_hex(sha256_hex)?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::BlobStorage;
                        let holders = backend.list_holders(&sha).await.map_err(blob_err_to_py)?;
                        serde_json::to_string(&holders).map_err(|e| {
                            PyRuntimeError::new_err(format!("list_holders JSON encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::BlobStorage;
                        let holders = backend.list_holders(&sha).await.map_err(blob_err_to_py)?;
                        serde_json::to_string(&holders).map_err(|e| {
                            PyRuntimeError::new_err(format!("list_holders JSON encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── v1.3.0 (CIRISPersist#46 + #47) — Trust hierarchy wraps ─────
    //
    // Wire shape mirrors the existing FederationDirectory PyO3
    // surface: JSON strings in/out for complex types (TrustGrant,
    // TrustRow, TrustFilter); primitive types as direct &str args.
    // Lens calls json.dumps before passing in, json.loads on receiving
    // back. Errors go through `federation_err_to_py` for the same
    // stable-kind discipline as the rest of the federation methods.

    /// Federation directory: grant trust to a key.
    ///
    /// `trust_grant_json` is a JSON string of `TrustGrant`:
    /// `{"key": ..., "trust_type": "temporary"|"partnered"|"anonymous",
    ///   "trust_relationship": "direct"|"registry",
    ///   "trust_domains": [...]|null,
    ///   "trusted_by": ..., "expires_at": "...."|null}`.
    /// Raises `ValueError` on self-trust (trusted_by == key),
    /// missing-domains-on-Registry, or unknown key_id.
    fn federation_grant_trust(&self, py: Python<'_>, trust_grant_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let grant: crate::federation::TrustGrant = serde_json::from_str(trust_grant_json)
                .map_err(|e| PyValueError::new_err(format!("TrustGrant JSON decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .grant_trust(grant)
                            .await
                            .map_err(federation_err_to_py)
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .grant_trust(grant)
                            .await
                            .map_err(federation_err_to_py)
                    })
                }
            })
        })
    }

    /// Federation directory: revoke trust for a key. Idempotent —
    /// revoking an already-expired key is a no-op.
    fn federation_revoke_trust(&self, py: Python<'_>, key: &str, revoked_by: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let key = key.to_owned();
            let revoked_by = revoked_by.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .revoke_trust(&key, &revoked_by)
                            .await
                            .map_err(federation_err_to_py)
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .revoke_trust(&key, &revoked_by)
                            .await
                            .map_err(federation_err_to_py)
                    })
                }
            })
        })
    }

    /// Federation directory: look up the trust row for a key.
    /// Returns a JSON-encoded `TrustRow` string, or `None` if no
    /// trust grant exists.
    fn federation_lookup_trust(&self, py: Python<'_>, key: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let key = key.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let opt = backend
                            .lookup_trust(&key)
                            .await
                            .map_err(federation_err_to_py)?;
                        match opt {
                            None => Ok(None),
                            Some(row) => Ok(Some(serde_json::to_string(&row).map_err(|e| {
                                PyRuntimeError::new_err(format!("TrustRow JSON encode: {e}"))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let opt = backend
                            .lookup_trust(&key)
                            .await
                            .map_err(federation_err_to_py)?;
                        match opt {
                            None => Ok(None),
                            Some(row) => Ok(Some(serde_json::to_string(&row).map_err(|e| {
                                PyRuntimeError::new_err(format!("TrustRow JSON encode: {e}"))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    /// Federation directory: list trusted keys matching a filter.
    /// Returns a JSON-array string of `TrustRow` objects.
    ///
    /// `trust_filter_json` shape:
    /// `{"trust_type": "..."|null, "trust_relationship": "..."|null,
    ///   "domain": "..."|null, "include_expired": bool}`.
    /// All fields optional; `include_expired` defaults to false.
    fn federation_list_trusted_keys(
        &self,
        py: Python<'_>,
        trust_filter_json: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            // TrustFilter doesn't derive Serialize/Deserialize (the
            // shape mirrors NodeCore's local type, which is bare); we
            // parse a wire dict manually into the native type.
            let wire: TrustFilterWire = serde_json::from_str(trust_filter_json)
                .map_err(|e| PyValueError::new_err(format!("TrustFilter JSON decode: {e}")))?;
            let trust_type = match wire.trust_type.as_deref() {
                None => None,
                Some(s) => Some(
                    crate::federation::TrustType::from_wire_str(s)
                        .ok_or_else(|| PyValueError::new_err(format!("unknown trust_type: {s}")))?,
                ),
            };
            let trust_relationship = match wire.trust_relationship.as_deref() {
                None => None,
                Some(s) => Some(
                    crate::federation::TrustRelationship::from_wire_str(s).ok_or_else(|| {
                        PyValueError::new_err(format!("unknown trust_relationship: {s}"))
                    })?,
                ),
            };
            let filter = crate::federation::TrustFilter {
                trust_type,
                trust_relationship,
                domain: wire.domain,
                include_expired: wire.include_expired,
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let rows = backend
                            .list_trusted_keys(filter)
                            .await
                            .map_err(federation_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<TrustRow> JSON encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let rows = backend
                            .list_trusted_keys(filter)
                            .await
                            .map_err(federation_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<TrustRow> JSON encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── v2.10.0 (CIRISPersist#114) — typed Goal PyO3 surface ───────
    //
    // Mirrors the existing FederationDirectory wire shape: JSON
    // strings in/out for the typed `Goal` value; primitive types
    // (goal_id UUID-string, RFC3339 timestamp) as direct &str args.
    // Errors travel through `federation_err_to_py` for stable
    // `kind()` tokens — same discipline as the rest of the federation
    // wraps. M-1 alignment is structurally guaranteed by `Goal::new`;
    // the JSON deserializer either lands a valid `Goal` (with M-1
    // present) or raises `ValueError` at the FFI boundary.

    /// Federation directory: insert a typed `Goal`.
    ///
    /// `goal_json` is a JSON string of `Goal` (see
    /// [`crate::federation::goal::Goal`] for the shape). The JSON
    /// deserializer enforces the M-1-required invariant: an envelope
    /// without `meta_goal_alignment` raises `ValueError` before any
    /// DB work happens.
    ///
    /// Raises `ValueError` on missing-FK (`declared_by_key_id` not in
    /// `federation_keys`) or conflict (same `goal_id` with differing
    /// content); raises `RuntimeError` on backend failure.
    fn cirisnode_put_goal_json(&self, py: Python<'_>, goal_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let goal: crate::federation::Goal = serde_json::from_str(goal_json)
                .map_err(|e| PyValueError::new_err(format!("Goal JSON decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend.put_goal(goal).await.map_err(federation_err_to_py)
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend.put_goal(goal).await.map_err(federation_err_to_py)
                    })
                }
            })
        })
    }

    /// Federation directory: fetch a `Goal` by `goal_id`.
    ///
    /// `goal_id` is the UUID-as-text. Returns the JSON-encoded
    /// `Goal` string, or `None` when absent.
    fn cirisnode_get_goal_json(&self, py: Python<'_>, goal_id: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let goal_uuid = uuid::Uuid::parse_str(goal_id)
                .map_err(|e| PyValueError::new_err(format!("goal_id is not a valid UUID: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let opt = backend
                            .get_goal(goal_uuid)
                            .await
                            .map_err(federation_err_to_py)?;
                        match opt {
                            None => Ok(None),
                            Some(goal) => Ok(Some(serde_json::to_string(&goal).map_err(|e| {
                                PyRuntimeError::new_err(format!("Goal JSON encode: {e}"))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let opt = backend
                            .get_goal(goal_uuid)
                            .await
                            .map_err(federation_err_to_py)?;
                        match opt {
                            None => Ok(None),
                            Some(goal) => Ok(Some(serde_json::to_string(&goal).map_err(|e| {
                                PyRuntimeError::new_err(format!("Goal JSON encode: {e}"))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    /// Federation directory: list goals matching `goals_filter_json`.
    ///
    /// `goals_filter_json` shape:
    /// `{"declared_by_key_id": str|null, "m1_dimension": str|null,
    ///   "scope_kind": str|null, "cohort_id": str|null,
    ///   "include_retired": bool}`.
    /// All fields optional; `include_retired` defaults to false.
    /// Returns a JSON-array string of `Goal` objects in stable order
    /// `(declared_at, goal_id)`.
    fn cirisnode_list_goals_json(
        &self,
        py: Python<'_>,
        goals_filter_json: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let wire: GoalsFilterWire = serde_json::from_str(goals_filter_json)
                .map_err(|e| PyValueError::new_err(format!("GoalsFilter JSON decode: {e}")))?;
            let m1_dimension =
                match wire.m1_dimension.as_deref() {
                    None => None,
                    Some(s) => Some(crate::federation::M1Dimension::from_wire_str(s).ok_or_else(
                        || PyValueError::new_err(format!("unknown m1_dimension: {s}")),
                    )?),
                };
            let filter = crate::federation::GoalsFilter {
                declared_by_key_id: wire.declared_by_key_id,
                m1_dimension,
                scope_kind: wire.scope_kind,
                cohort_id: wire.cohort_id,
                include_retired: wire.include_retired,
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let rows = backend
                            .list_goals(filter)
                            .await
                            .map_err(federation_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<Goal> JSON encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        let rows = backend
                            .list_goals(filter)
                            .await
                            .map_err(federation_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<Goal> JSON encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// Federation directory: retire a `Goal`. Idempotent — a second
    /// call against an already-retired goal returns `Ok` without
    /// changing the stored `retired_at`.
    ///
    /// `goal_id` is the UUID-as-text. `retired_at_rfc3339` is the
    /// retirement timestamp as RFC3339.
    fn cirisnode_retire_goal_json(
        &self,
        py: Python<'_>,
        goal_id: &str,
        retired_at_rfc3339: &str,
    ) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let goal_uuid = uuid::Uuid::parse_str(goal_id)
                .map_err(|e| PyValueError::new_err(format!("goal_id is not a valid UUID: {e}")))?;
            let retired_at = chrono::DateTime::parse_from_rfc3339(retired_at_rfc3339)
                .map(|t| t.with_timezone(&chrono::Utc))
                .map_err(|e| {
                    PyValueError::new_err(format!("retired_at is not valid RFC3339: {e}"))
                })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .retire_goal(goal_uuid, retired_at)
                            .await
                            .map_err(federation_err_to_py)
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::federation::FederationDirectory;
                        backend
                            .retire_goal(goal_uuid, retired_at)
                            .await
                            .map_err(federation_err_to_py)
                    })
                }
            })
        })
    }

    /// v0.3.2 (CIRISPersist#11) — Walk hybrid-pending federation rows
    /// across `federation_keys` / `federation_attestations` /
    /// `federation_revocations` and drive cold-path PQC fill-in for
    /// each. Same canonicalization + signing path as the per-write
    /// auto-fire (`cold_path_pqc_sign`), just walked over the rows
    /// already in the table without per-write spawn coverage:
    ///
    /// - Rows authored before v0.3.1 wired the per-write cold-path
    /// - Rows authored before the local PQC key was configured on the
    ///   writer
    /// - Rows where the per-write `tokio::spawn` cold-path failed
    ///   transiently (sign error, attach network blip, process restart
    ///   between hot-path commit and cold-path attach)
    ///
    /// Per the writer contract in V004 schema header §"Phase
    /// transitions":
    ///
    /// > Pre-flip rows that are still pending get walked through the
    /// > upgrade pipeline.
    ///
    /// This method is that pipeline.
    ///
    /// Returns a dict shaped:
    ///
    /// ```text
    /// {
    ///   "scanned": int,        # total rows examined across the three tables
    ///   "signed":  int,        # rows successfully hybrid-completed by this call
    ///   "failed":  int,        # rows where sign or attach errored (still pending)
    ///   "by_table": {
    ///     "federation_keys":          {"scanned": ..., "signed": ..., "failed": ...},
    ///     "federation_attestations":  {...},
    ///     "federation_revocations":   {...},
    ///   }
    /// }
    /// ```
    ///
    /// Idempotent: `attach_*_pqc_signature` already guards against
    /// double-fill via `WHERE pqc_completed_at IS NULL`. Multi-worker
    /// concurrent sweeps waste signs on losers but do not produce
    /// incorrect rows; the silent-skip path on `Conflict` is not
    /// counted as failed.
    ///
    /// `batch_size` (default 1000) caps each table's scan in one call.
    /// Re-invoke until `scanned == 0` to drain larger backlogs
    /// incrementally.
    ///
    /// Raises `ValueError` if no local PQC key is configured (same
    /// shape as `local_pqc_sign`).
    #[pyo3(signature = (batch_size=1000))]
    fn run_pqc_sweep<'py>(&self, py: Python<'py>, batch_size: i64) -> PyResult<Bound<'py, PyDict>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let signer = self
                .local_signer
                .as_ref()
                .and_then(|s| s.pqc_signer())
                .ok_or_else(|| {
                    PyValueError::new_err(
                        "no local PQC key configured (pass local_pqc_key_id and \
                 local_pqc_key_path to the Engine constructor)",
                    )
                })?;
            let runtime = self.runtime.clone();

            let summary = py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        run_pqc_sweep_inner(&backend, &*signer, batch_size).await
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        run_pqc_sweep_inner(&backend, &*signer, batch_size).await
                    })
                }
            });

            let dict = PyDict::new(py);
            dict.set_item("scanned", summary.total_scanned)?;
            dict.set_item("signed", summary.total_signed)?;
            dict.set_item("failed", summary.total_failed)?;
            let by_table = PyDict::new(py);
            for (name, counts) in [
                ("federation_keys", &summary.keys),
                ("federation_attestations", &summary.attestations),
                ("federation_revocations", &summary.revocations),
            ] {
                let d = PyDict::new(py);
                d.set_item("scanned", counts.scanned)?;
                d.set_item("signed", counts.signed)?;
                d.set_item("failed", counts.failed)?;
                by_table.set_item(name, d)?;
            }
            dict.set_item("by_table", by_table)?;
            Ok(dict)
        })
    }

    /// v0.3.6 (CIRISPersist#15, CIRISLens#8 ASK 1) — GDPR Article 17
    /// / DSAR primitive. Per-key scope: deletion is scoped to
    /// `(agent_id_hash, signing_key_id)`.
    ///
    /// `signature_key_id` is the **authorization scope** of the DSAR,
    /// not just an identity filter. A request signed by key A is
    /// only authorized to delete traces signed by key A.
    ///
    /// Deletes:
    /// - `cirislens.trace_events` rows where `agent_id_hash` AND
    ///   `signing_key_id` both match
    /// - `cirislens.trace_llm_calls` rows joined by `trace_id` from
    ///   the deleted trace_events set
    ///
    /// When `include_federation_key=True`, additionally:
    /// - the single `cirislens.federation_keys` row where `key_id =
    ///   signature_key_id` AND `identity_type='agent'` AND
    ///   `identity_ref=agent_id_hash`
    /// - FK-cascade: `federation_attestations` and
    ///   `federation_revocations` rows referencing that key
    ///   (deleted first to satisfy FK integrity — persist's
    ///   federation FKs are not ON DELETE CASCADE)
    ///
    /// All deletes happen in a single transaction. Returns a dict:
    ///
    /// ```text
    /// {
    ///   "trace_events_deleted":           int,
    ///   "trace_llm_calls_deleted":        int,
    ///   "federation_keys_deleted":        int,  # 0 unless include_federation_key=True
    ///   "federation_attestations_deleted": int,  # 0 unless include_federation_key=True
    ///   "federation_revocations_deleted":  int,  # 0 unless include_federation_key=True
    ///   "deleted_at":                     str,  # ISO-8601 UTC
    /// }
    /// ```
    ///
    /// Idempotent: re-invocation returns all-zero counts.
    ///
    /// **Persist owns the substrate row delete; lens orchestrates the
    /// DSAR audit + signature verification.** This method does not
    /// validate the caller's authority — that's lens-side policy.
    #[pyo3(signature = (agent_id_hash, signature_key_id, include_federation_key=false))]
    fn delete_traces_for_agent<'py>(
        &self,
        py: Python<'py>,
        agent_id_hash: &str,
        signature_key_id: &str,
        include_federation_key: bool,
    ) -> PyResult<Bound<'py, PyDict>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let agent_id_hash = agent_id_hash.to_owned();
            let signature_key_id = signature_key_id.to_owned();

            let summary = py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::store::Backend;
                        backend
                            .delete_traces_for_agent(
                                &agent_id_hash,
                                &signature_key_id,
                                include_federation_key,
                            )
                            .await
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::store::Backend;
                        backend
                            .delete_traces_for_agent(
                                &agent_id_hash,
                                &signature_key_id,
                                include_federation_key,
                            )
                            .await
                    })
                }
            });
            let summary = summary.map_err(|e| PyRuntimeError::new_err(format!("{e}")))?;

            let dict = PyDict::new(py);
            dict.set_item("trace_events_deleted", summary.trace_events_deleted)?;
            dict.set_item("trace_llm_calls_deleted", summary.trace_llm_calls_deleted)?;
            dict.set_item("federation_keys_deleted", summary.federation_keys_deleted)?;
            dict.set_item(
                "federation_attestations_deleted",
                summary.federation_attestations_deleted,
            )?;
            dict.set_item(
                "federation_revocations_deleted",
                summary.federation_revocations_deleted,
            )?;
            dict.set_item("deleted_at", summary.deleted_at.to_rfc3339())?;
            Ok(dict)
        })
    }

    /// v0.3.5 (CIRISLens#8 ASK 3) — Page-cursor read primitive for
    /// analytical streaming. Returns up to `limit` `trace_events` rows
    /// where `event_id > after_event_id`, ordered ascending by
    /// `event_id` (the `BIGSERIAL` primary key). Optional
    /// `agent_id_hash` filter.
    ///
    /// **Caller orchestrates the cursor**: track the max returned
    /// `event_id` between calls, pass it as `after_event_id` for the
    /// next page, stop when the result set is empty.
    ///
    /// Returns a list of dicts. Each dict carries the
    /// `cirislens.trace_events` columns (one-to-one with
    /// `TraceEventRow` Rust struct), plus an explicit `event_id` field
    /// for cursor extraction.
    ///
    /// Use this when:
    /// - Lens wants typed Rust-shape rows rather than raw SQL
    /// - The caller is out-of-process and can't take cirislens_reader
    ///   role for direct SQL
    /// - Streaming over a >>memory result set (cursor pattern handles
    ///   arbitrary corpus size)
    ///
    /// For ad-hoc analytical queries inside lens-core, the
    /// `cirislens_reader` role + direct SQL is still the recommended
    /// shape — this primitive is for cross-process consumers.
    #[pyo3(signature = (after_event_id=0, limit=1000, agent_id_hash=None))]
    fn fetch_trace_events_page<'py>(
        &self,
        py: Python<'py>,
        after_event_id: i64,
        limit: i64,
        agent_id_hash: Option<&str>,
    ) -> PyResult<pyo3::Bound<'py, pyo3::types::PyList>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let agent_filter = agent_id_hash.map(str::to_owned);

            let rows: Vec<(i64, crate::store::types::TraceEventRow)> = py
                .detach(move || match &self.backend {
                    BackendDispatch::Postgres(pg) => {
                        let backend = pg.clone();
                        runtime.block_on(async move {
                            use crate::store::Backend;
                            backend
                                .fetch_trace_events_page(
                                    after_event_id,
                                    limit,
                                    agent_filter.as_deref(),
                                )
                                .await
                        })
                    }
                    #[cfg(feature = "sqlite")]
                    BackendDispatch::Sqlite(sq) => {
                        let backend = sq.clone();
                        runtime.block_on(async move {
                            use crate::store::Backend;
                            backend
                                .fetch_trace_events_page(
                                    after_event_id,
                                    limit,
                                    agent_filter.as_deref(),
                                )
                                .await
                        })
                    }
                })
                .map_err(|e| PyRuntimeError::new_err(format!("{e}")))?;

            let list = pyo3::types::PyList::empty(py);
            for (event_id, row) in rows {
                let d = PyDict::new(py);
                d.set_item("event_id", event_id)?;
                d.set_item("trace_id", &row.trace_id)?;
                d.set_item("thought_id", &row.thought_id)?;
                d.set_item("task_id", row.task_id.as_deref())?;
                d.set_item("step_point", row.step_point.as_deref())?;
                d.set_item("event_type", row.event_type.as_str())?;
                d.set_item("attempt_index", row.attempt_index)?;
                d.set_item("ts", row.ts.to_rfc3339())?;
                d.set_item("agent_name", row.agent_name.as_deref())?;
                d.set_item("agent_id_hash", &row.agent_id_hash)?;
                d.set_item("cognitive_state", row.cognitive_state.as_deref())?;
                d.set_item("trace_level", trace_level_str(row.trace_level))?;
                d.set_item(
                    "payload",
                    pyo3::types::PyString::new(
                        py,
                        &serde_json::to_string(&serde_json::Value::Object(row.payload))
                            .unwrap_or_default(),
                    ),
                )?;
                d.set_item("cost_llm_calls", row.cost_llm_calls)?;
                d.set_item("cost_tokens", row.cost_tokens)?;
                d.set_item("cost_usd", row.cost_usd)?;
                d.set_item("signature", &row.signature)?;
                d.set_item("signing_key_id", &row.signing_key_id)?;
                d.set_item("signature_verified", row.signature_verified)?;
                d.set_item("schema_version", &row.schema_version)?;
                d.set_item("pii_scrubbed", row.pii_scrubbed)?;
                d.set_item("agent_role", row.agent_role.as_deref())?;
                d.set_item("agent_template", row.agent_template.as_deref())?;
                d.set_item("deployment_domain", row.deployment_domain.as_deref())?;
                d.set_item("deployment_type", row.deployment_type.as_deref())?;
                d.set_item("deployment_region", row.deployment_region.as_deref())?;
                d.set_item(
                    "deployment_trust_mode",
                    row.deployment_trust_mode.as_deref(),
                )?;
                list.append(d)?;
            }
            Ok(list)
        })
    }

    /// v0.3.6 (CIRISPersist#14) — Hybrid Ed25519 + ML-DSA-65 verify
    /// for arbitrary canonical bytes. CIRISEdge OQ-11 day-1 posture
    /// unblocker.
    ///
    /// `policy` is one of `"strict"`, `"ed25519_fallback"`, or
    /// `"soft_freshness"`. When `"soft_freshness"`,
    /// `soft_freshness_window_seconds` is required; `row_age_seconds`
    /// MAY be passed by the caller (caller-side lookup of
    /// `pqc_completed_at`). Other policies ignore both.
    ///
    /// `ml_dsa_65_sig_b64` and `ml_dsa_65_pubkey_b64` are paired:
    /// either both Some (full hybrid verify) or both None (the row
    /// is hybrid-pending; acceptance depends on `policy`).
    ///
    /// Returns a dict:
    ///
    /// ```text
    /// {
    ///   "outcome": str,        # "hybrid_verified" | "ed25519_hybrid_pending" | "ed25519_fallback"
    ///   "row_age_seconds": float|None,  # echoed back when SoftFreshness matches
    /// }
    /// ```
    ///
    /// On verify failure raises `ValueError` with the persist
    /// error-token (`verify_hybrid_pending_rejected`,
    /// `verify_hybrid_soft_freshness_expired`,
    /// `verify_hybrid_pqc_fields_mismatch`,
    /// `verify_hybrid_base64`, `verify_hybrid_invalid_length`,
    /// `verify_hybrid_crypto`).
    ///
    /// Same error-token discipline as the rest of persist's PyO3
    /// surface — structured detail in tracing logs, stable token in
    /// the Python exception message for HTTP layer mapping.
    #[pyo3(signature = (
        canonical_bytes,
        ed25519_sig_b64,
        ml_dsa_65_sig_b64,
        ed25519_pubkey_b64,
        ml_dsa_65_pubkey_b64,
        policy,
        soft_freshness_window_seconds=None,
        row_age_seconds=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn verify_hybrid<'py>(
        &self,
        py: Python<'py>,
        canonical_bytes: &[u8],
        ed25519_sig_b64: &str,
        ml_dsa_65_sig_b64: Option<&str>,
        ed25519_pubkey_b64: &str,
        ml_dsa_65_pubkey_b64: Option<&str>,
        policy: &str,
        soft_freshness_window_seconds: Option<f64>,
        row_age_seconds: Option<f64>,
    ) -> PyResult<Bound<'py, PyDict>> {
        self.ensure_usable()?;
        catch_panic(|| {
            use crate::verify::VerifyOutcome;
            let parsed_policy = parse_hybrid_policy(policy, soft_freshness_window_seconds)?;

            let row_age = row_age_seconds.and_then(|s| {
                if s.is_finite() && s >= 0.0 {
                    Some(std::time::Duration::from_secs_f64(s))
                } else {
                    None
                }
            });

            let outcome = crate::verify::verify_hybrid(
                canonical_bytes,
                ed25519_sig_b64,
                ml_dsa_65_sig_b64,
                ed25519_pubkey_b64,
                ml_dsa_65_pubkey_b64,
                parsed_policy,
                row_age,
            )
            .map_err(|e| {
                // Stable token → ValueError per persist's FFI discipline.
                // Verbose Display goes to tracing logs only.
                tracing::warn!(error = %e, kind = e.kind(), "verify_hybrid rejected");
                PyValueError::new_err(e.kind())
            })?;

            let dict = PyDict::new(py);
            match outcome {
                VerifyOutcome::HybridVerified => {
                    dict.set_item("outcome", "hybrid_verified")?;
                    dict.set_item("row_age_seconds", py.None())?;
                }
                VerifyOutcome::Ed25519VerifiedHybridPending { row_age } => {
                    dict.set_item("outcome", "ed25519_hybrid_pending")?;
                    let secs = row_age.map(|d| d.as_secs_f64());
                    match secs {
                        Some(s) => dict.set_item("row_age_seconds", s)?,
                        None => dict.set_item("row_age_seconds", py.None())?,
                    }
                }
                VerifyOutcome::Ed25519VerifiedFallback => {
                    dict.set_item("outcome", "ed25519_fallback")?;
                    dict.set_item("row_age_seconds", py.None())?;
                }
            }
            Ok(dict)
        })
    }

    // ─── Verify surface for federation peer cutover (v0.4.0) ────

    /// v0.4.0 — Verify a CompleteTrace envelope end-to-end.
    /// Looks up `signature_key_id` via the federation directory,
    /// reconstructs canonical bytes per `trace_schema_version`
    /// (deterministic dispatch — 2.7.0 / 2.7.9), verifies the
    /// Ed25519 signature.
    ///
    /// Returns `{"verified": True, "schema_version": "2.7.0"|"2.7.9"}`
    /// on success. Raises `ValueError` with a stable verify
    /// error-token (`verify_signature_mismatch`,
    /// `verify_unknown_key`, `verify_invalid_signature`,
    /// `verify_canonicalization_internal`,
    /// `verify_unsupported_schema_version`) on failure.
    ///
    /// Use this when a peer wants to verify a CompleteTrace WITHOUT
    /// storing it (dry-run validation, pre-storage check, audit
    /// replay). Persistence still goes through
    /// `receive_and_persist` (which verifies internally before
    /// storing).
    fn verify_trace<'py>(
        &self,
        py: Python<'py>,
        complete_trace_json: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        self.ensure_usable()?;
        catch_panic(|| {
            use crate::schema::CompleteTrace;
            use crate::verify::{verify_trace_via_directory, PythonJsonDumpsCanonicalizer};
            let trace: CompleteTrace = serde_json::from_str(complete_trace_json)
                .map_err(|e| PyValueError::new_err(format!("CompleteTrace JSON decode: {e}")))?;
            let runtime = self.runtime.clone();
            match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let key_dir = TraceKeyDirectory {
                        backend: pg.clone(),
                        runtime,
                    };
                    verify_trace_via_directory(&trace, &PythonJsonDumpsCanonicalizer, &key_dir)
                        .map_err(|e| {
                            tracing::warn!(error = %e, kind = e.kind(), "verify_trace rejected");
                            PyValueError::new_err(e.kind())
                        })?;
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let key_dir = TraceKeyDirectory {
                        backend: sq.clone(),
                        runtime,
                    };
                    verify_trace_via_directory(&trace, &PythonJsonDumpsCanonicalizer, &key_dir)
                        .map_err(|e| {
                            tracing::warn!(error = %e, kind = e.kind(), "verify_trace rejected");
                            PyValueError::new_err(e.kind())
                        })?;
                }
            }
            let dict = PyDict::new(py);
            dict.set_item("verified", true)?;
            dict.set_item("schema_version", trace.trace_schema_version.as_str())?;
            Ok(dict)
        })
    }

    /// v0.4.0 / v0.4.1 — Hybrid verify with internal directory
    /// lookup. v0.4.1 backs onto the Rust free function
    /// `crate::verify::verify_hybrid_via_directory` so the PyO3
    /// surface and Rust API surface share one implementation
    /// (CIRISEdge ask 1; CIRISPersist#7 single-source-of-truth
    /// pattern).
    ///
    /// Saves the caller from doing a separate `lookup_public_key`
    /// call before each verify. Same `policy` semantics as
    /// `verify_hybrid` (Strict / SoftFreshness / Ed25519Fallback).
    /// Same return shape (`{"outcome", "row_age_seconds"}`).
    ///
    /// Raises `ValueError` with `verify_unknown_key` if
    /// `signature_key_id` doesn't resolve in federation_keys, or
    /// the standard `verify_hybrid_*` tokens for crypto failures.
    #[pyo3(signature = (
        canonical_bytes,
        signature_key_id,
        ed25519_sig_b64,
        ml_dsa_65_sig_b64,
        policy,
        soft_freshness_window_seconds=None,
        row_age_seconds=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn verify_hybrid_via_directory<'py>(
        &self,
        py: Python<'py>,
        canonical_bytes: &[u8],
        signature_key_id: &str,
        ed25519_sig_b64: &str,
        ml_dsa_65_sig_b64: Option<&str>,
        policy: &str,
        soft_freshness_window_seconds: Option<f64>,
        row_age_seconds: Option<f64>,
    ) -> PyResult<Bound<'py, PyDict>> {
        self.ensure_usable()?;
        catch_panic(|| {
            use crate::verify::{HybridPolicy, VerifyOutcome};
            let parsed_policy = parse_hybrid_policy(policy, soft_freshness_window_seconds)?;
            let row_age = row_age_seconds.and_then(|s| {
                if s.is_finite() && s >= 0.0 {
                    Some(std::time::Duration::from_secs_f64(s))
                } else {
                    None
                }
            });

            let canonical_owned = canonical_bytes.to_vec();
            let key_id_owned = signature_key_id.to_owned();
            let ed25519_owned = ed25519_sig_b64.to_owned();
            let pqc_owned = ml_dsa_65_sig_b64.map(str::to_owned);
            let runtime = self.runtime.clone();

            let outcome = py
            .detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        crate::verify::verify_hybrid_via_directory(
                            &*backend,
                            &canonical_owned,
                            &key_id_owned,
                            &ed25519_owned,
                            pqc_owned.as_deref(),
                            parsed_policy,
                            row_age,
                        )
                        .await
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        crate::verify::verify_hybrid_via_directory(
                            &*backend,
                            &canonical_owned,
                            &key_id_owned,
                            &ed25519_owned,
                            pqc_owned.as_deref(),
                            parsed_policy,
                            row_age,
                        )
                        .await
                    })
                }
            })
            .map_err(|e| {
                let s = e.to_string();
                tracing::warn!(error = %e, kind = e.kind(), "verify_hybrid_via_directory rejected");
                if s.contains("verify_unknown_key") {
                    PyValueError::new_err("verify_unknown_key")
                } else {
                    PyValueError::new_err(e.kind())
                }
            })?;

            let _ = HybridPolicy::Strict; // keep import live across feature combos
            let dict = PyDict::new(py);
            match outcome {
                VerifyOutcome::HybridVerified => {
                    dict.set_item("outcome", "hybrid_verified")?;
                    dict.set_item("row_age_seconds", py.None())?;
                }
                VerifyOutcome::Ed25519VerifiedHybridPending { row_age } => {
                    dict.set_item("outcome", "ed25519_hybrid_pending")?;
                    let secs = row_age.map(|d| d.as_secs_f64());
                    match secs {
                        Some(s) => dict.set_item("row_age_seconds", s)?,
                        None => dict.set_item("row_age_seconds", py.None())?,
                    }
                }
                VerifyOutcome::Ed25519VerifiedFallback => {
                    dict.set_item("outcome", "ed25519_fallback")?;
                    dict.set_item("row_age_seconds", py.None())?;
                }
            }
            Ok(dict)
        })
    }

    /// v0.4.1 (CIRISEdge ask) — Strip-then-canonicalize an envelope
    /// for signing/verifying. Removes top-level `signature` and
    /// `signature_pqc` fields, applies PythonJsonDumpsCanonicalizer.
    /// Wraps `crate::verify::canonicalize_envelope_for_signing`.
    fn canonicalize_envelope_for_signing<'py>(
        &self,
        py: Python<'py>,
        envelope_json: &str,
    ) -> PyResult<Py<PyBytes>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let value: serde_json::Value = serde_json::from_str(envelope_json)
                .map_err(|e| PyValueError::new_err(format!("envelope JSON decode: {e}")))?;
            let bytes = crate::verify::canonicalize_envelope_for_signing(&value).map_err(|e| {
                PyRuntimeError::new_err(format!("canonicalize_envelope_for_signing: {e}"))
            })?;
            Ok(PyBytes::new(py, &bytes).unbind())
        })
    }

    /// v0.4.1 (CIRISEdge ask) — SHA-256 of body verbatim wire bytes.
    /// Used by `body_sha256_prefix` forensic join key and
    /// `in_reply_to` content-derived ACK matching. Persist hashes
    /// the bytes as supplied — does NOT re-canonicalize.
    fn body_sha256<'py>(&self, py: Python<'py>, body_bytes: &[u8]) -> PyResult<Py<PyBytes>> {
        self.ensure_usable()?;
        catch_panic(|| {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(body_bytes);
            let digest: [u8; 32] = hasher.finalize().into();
            Ok(PyBytes::new(py, &digest).unbind())
        })
    }

    /// v0.4.0 — Verify a `SignedKeyRecord` envelope's scrub
    /// signature. Looks up the scrub_key_id's pubkeys, recomputes
    /// canonical bytes from `registration_envelope`, runs
    /// hybrid-verify with the supplied policy.
    ///
    /// Used by federation peers consuming key registrations from
    /// other peers (gossip / direct) to verify-before-store. The
    /// federation directory's `put_public_key` does its own write-
    /// path verification; this primitive lets a peer verify-without-
    /// storing for dry-runs or trust-graph audits.
    #[pyo3(signature = (
        signed_key_record_json,
        policy,
        soft_freshness_window_seconds=None,
        row_age_seconds=None,
    ))]
    fn verify_signed_key_record<'py>(
        &self,
        py: Python<'py>,
        signed_key_record_json: &str,
        policy: &str,
        soft_freshness_window_seconds: Option<f64>,
        row_age_seconds: Option<f64>,
    ) -> PyResult<Bound<'py, PyDict>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let signed: crate::federation::SignedKeyRecord =
                serde_json::from_str(signed_key_record_json).map_err(|e| {
                    PyValueError::new_err(format!("SignedKeyRecord JSON decode: {e}"))
                })?;
            let canonical = canonicalize_envelope_value(&signed.record.registration_envelope)?;
            self.verify_hybrid_via_directory(
                py,
                &canonical,
                &signed.record.scrub_key_id,
                &signed.record.scrub_signature_classical,
                signed.record.scrub_signature_pqc.as_deref(),
                policy,
                soft_freshness_window_seconds,
                row_age_seconds,
            )
        })
    }

    /// v0.4.0 — Verify a `SignedAttestation` envelope. Same shape
    /// as `verify_signed_key_record`; canonical bytes come from
    /// `attestation_envelope`.
    #[pyo3(signature = (
        signed_attestation_json,
        policy,
        soft_freshness_window_seconds=None,
        row_age_seconds=None,
    ))]
    fn verify_signed_attestation<'py>(
        &self,
        py: Python<'py>,
        signed_attestation_json: &str,
        policy: &str,
        soft_freshness_window_seconds: Option<f64>,
        row_age_seconds: Option<f64>,
    ) -> PyResult<Bound<'py, PyDict>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let signed: crate::federation::SignedAttestation =
                serde_json::from_str(signed_attestation_json).map_err(|e| {
                    PyValueError::new_err(format!("SignedAttestation JSON decode: {e}"))
                })?;
            let canonical = canonicalize_envelope_value(&signed.attestation.attestation_envelope)?;
            self.verify_hybrid_via_directory(
                py,
                &canonical,
                &signed.attestation.scrub_key_id,
                &signed.attestation.scrub_signature_classical,
                signed.attestation.scrub_signature_pqc.as_deref(),
                policy,
                soft_freshness_window_seconds,
                row_age_seconds,
            )
        })
    }

    /// v0.4.0 — Verify a `SignedRevocation` envelope. Same shape
    /// as `verify_signed_attestation`; canonical bytes come from
    /// `revocation_envelope`.
    #[pyo3(signature = (
        signed_revocation_json,
        policy,
        soft_freshness_window_seconds=None,
        row_age_seconds=None,
    ))]
    fn verify_signed_revocation<'py>(
        &self,
        py: Python<'py>,
        signed_revocation_json: &str,
        policy: &str,
        soft_freshness_window_seconds: Option<f64>,
        row_age_seconds: Option<f64>,
    ) -> PyResult<Bound<'py, PyDict>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let signed: crate::federation::SignedRevocation =
                serde_json::from_str(signed_revocation_json).map_err(|e| {
                    PyValueError::new_err(format!("SignedRevocation JSON decode: {e}"))
                })?;
            let canonical = canonicalize_envelope_value(&signed.revocation.revocation_envelope)?;
            self.verify_hybrid_via_directory(
                py,
                &canonical,
                &signed.revocation.scrub_key_id,
                &signed.revocation.scrub_signature_classical,
                signed.revocation.scrub_signature_pqc.as_deref(),
                policy,
                soft_freshness_window_seconds,
                row_age_seconds,
            )
        })
    }

    // ─── Edge outbound queue (v0.4.0, CIRISPersist#16) ──────────

    /// v0.4.0 (CIRISPersist#16) — Enqueue an outbound row in
    /// `pending` state. Returns the server-generated `queue_id` the
    /// caller stores in its `DurableHandle`.
    ///
    /// `body_sha256` MUST be exactly 32 bytes (sha256 digest).
    /// `body_size_bytes` is bounded 1..=8 MiB by the schema CHECK.
    /// `requires_ack=True` requires `ack_timeout_seconds > 0`.
    #[pyo3(signature = (
        sender_key_id,
        destination_key_id,
        message_type,
        edge_schema_version,
        envelope_bytes,
        body_sha256,
        body_size_bytes,
        requires_ack,
        max_attempts,
        ttl_seconds,
        initial_next_attempt_after_rfc3339,
        ack_timeout_seconds=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn enqueue_outbound(
        &self,
        py: Python<'_>,
        sender_key_id: &str,
        destination_key_id: &str,
        message_type: &str,
        edge_schema_version: &str,
        envelope_bytes: &[u8],
        body_sha256: &[u8],
        body_size_bytes: i32,
        requires_ack: bool,
        max_attempts: i32,
        ttl_seconds: i64,
        initial_next_attempt_after_rfc3339: &str,
        ack_timeout_seconds: Option<i64>,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            if body_sha256.len() != 32 {
                return Err(PyValueError::new_err(format!(
                    "body_sha256 must be 32 bytes, got {}",
                    body_sha256.len()
                )));
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(body_sha256);
            let initial_next: chrono::DateTime<chrono::Utc> =
                initial_next_attempt_after_rfc3339.parse().map_err(|e| {
                    PyValueError::new_err(format!("initial_next_attempt_after_rfc3339 parse: {e}"))
                })?;

            let runtime = self.runtime.clone();
            let sender = sender_key_id.to_owned();
            let dest = destination_key_id.to_owned();
            let mt = message_type.to_owned();
            let esv = edge_schema_version.to_owned();
            let env_bytes = envelope_bytes.to_vec();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend
                            .enqueue_outbound(
                                &sender,
                                &dest,
                                &mt,
                                &esv,
                                &env_bytes,
                                &hash,
                                body_size_bytes,
                                requires_ack,
                                ack_timeout_seconds,
                                max_attempts,
                                ttl_seconds,
                                initial_next,
                            )
                            .await
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend
                            .enqueue_outbound(
                                &sender,
                                &dest,
                                &mt,
                                &esv,
                                &env_bytes,
                                &hash,
                                body_size_bytes,
                                requires_ack,
                                ack_timeout_seconds,
                                max_attempts,
                                ttl_seconds,
                                initial_next,
                            )
                            .await
                    })
                }
            })
            .map_err(outbound_err_to_py)
        })
    }

    /// v0.4.0 — Atomic claim of up to `batch_size` pending rows.
    /// Returns a list of dicts (one per claimed row).
    #[pyo3(signature = (batch_size, claim_duration_seconds, claimed_by))]
    fn claim_pending_outbound<'py>(
        &self,
        py: Python<'py>,
        batch_size: i64,
        claim_duration_seconds: i64,
        claimed_by: &str,
    ) -> PyResult<pyo3::Bound<'py, pyo3::types::PyList>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let claimed_by_owned = claimed_by.to_owned();
            let rows = py
                .detach(move || match &self.backend {
                    BackendDispatch::Postgres(pg) => {
                        let backend = pg.clone();
                        runtime.block_on(async move {
                            use crate::outbound::OutboundQueue;
                            backend
                                .claim_pending_outbound(
                                    batch_size,
                                    claim_duration_seconds,
                                    &claimed_by_owned,
                                )
                                .await
                        })
                    }
                    #[cfg(feature = "sqlite")]
                    BackendDispatch::Sqlite(sq) => {
                        let backend = sq.clone();
                        runtime.block_on(async move {
                            use crate::outbound::OutboundQueue;
                            backend
                                .claim_pending_outbound(
                                    batch_size,
                                    claim_duration_seconds,
                                    &claimed_by_owned,
                                )
                                .await
                        })
                    }
                })
                .map_err(outbound_err_to_py)?;
            outbound_rows_to_pylist(py, rows)
        })
    }

    /// v0.4.0 — Transport reports successful delivery. Transitions
    /// the row to `delivered` (no ACK) or `awaiting_ack` (ACK
    /// required).
    fn mark_transport_delivered(
        &self,
        py: Python<'_>,
        queue_id: &str,
        transport: &str,
    ) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let qid = queue_id.to_owned();
            let transport = transport.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend.mark_transport_delivered(&qid, &transport).await
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend.mark_transport_delivered(&qid, &transport).await
                    })
                }
            })
            .map_err(outbound_err_to_py)
        })
    }

    /// v0.4.0 — Transport reports failure. Returns a dict shaped
    /// `{"outcome": "retrying"|"abandoned", "attempt": int|None}`.
    fn mark_transport_failed<'py>(
        &self,
        py: Python<'py>,
        queue_id: &str,
        error_class: &str,
        error_detail: &str,
        transport: &str,
        next_attempt_after_rfc3339: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let next_attempt_after: chrono::DateTime<chrono::Utc> =
                next_attempt_after_rfc3339.parse().map_err(|e| {
                    PyValueError::new_err(format!("next_attempt_after_rfc3339 parse: {e}"))
                })?;
            let runtime = self.runtime.clone();
            let qid = queue_id.to_owned();
            let ec = error_class.to_owned();
            let ed = error_detail.to_owned();
            let transport = transport.to_owned();
            let outcome = py
                .detach(move || match &self.backend {
                    BackendDispatch::Postgres(pg) => {
                        let backend = pg.clone();
                        runtime.block_on(async move {
                            use crate::outbound::OutboundQueue;
                            backend
                                .mark_transport_failed(
                                    &qid,
                                    &ec,
                                    &ed,
                                    &transport,
                                    next_attempt_after,
                                )
                                .await
                        })
                    }
                    #[cfg(feature = "sqlite")]
                    BackendDispatch::Sqlite(sq) => {
                        let backend = sq.clone();
                        runtime.block_on(async move {
                            use crate::outbound::OutboundQueue;
                            backend
                                .mark_transport_failed(
                                    &qid,
                                    &ec,
                                    &ed,
                                    &transport,
                                    next_attempt_after,
                                )
                                .await
                        })
                    }
                })
                .map_err(outbound_err_to_py)?;
            let dict = PyDict::new(py);
            match outcome {
                crate::outbound::OutboundFailureOutcome::Retrying { attempt } => {
                    dict.set_item("outcome", "retrying")?;
                    dict.set_item("attempt", attempt)?;
                }
                crate::outbound::OutboundFailureOutcome::Abandoned => {
                    dict.set_item("outcome", "abandoned")?;
                    dict.set_item("attempt", py.None())?;
                }
            }
            Ok(dict)
        })
    }

    /// v0.4.0 — Treat a previously-sent row as delivered (the
    /// receiver replied `replay_detected`; the original send already
    /// landed before the ACK could arrive).
    fn mark_replay_resolved(&self, py: Python<'_>, queue_id: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let qid = queue_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend.mark_replay_resolved(&qid).await
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend.mark_replay_resolved(&qid).await
                    })
                }
            })
            .map_err(outbound_err_to_py)
        })
    }

    /// v0.4.0 — Look up an `awaiting_ack` row by the receiver's
    /// `in_reply_to` hash. Returns the row dict or `None`.
    fn match_ack_to_outbound<'py>(
        &self,
        py: Python<'py>,
        in_reply_to_sha256: &[u8],
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        self.ensure_usable()?;
        catch_panic(|| {
            if in_reply_to_sha256.len() != 32 {
                return Err(PyValueError::new_err(format!(
                    "in_reply_to_sha256 must be 32 bytes, got {}",
                    in_reply_to_sha256.len()
                )));
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(in_reply_to_sha256);
            let runtime = self.runtime.clone();
            let row_opt = py
                .detach(move || match &self.backend {
                    BackendDispatch::Postgres(pg) => {
                        let backend = pg.clone();
                        runtime.block_on(async move {
                            use crate::outbound::OutboundQueue;
                            backend.match_ack_to_outbound(&hash).await
                        })
                    }
                    #[cfg(feature = "sqlite")]
                    BackendDispatch::Sqlite(sq) => {
                        let backend = sq.clone();
                        runtime.block_on(async move {
                            use crate::outbound::OutboundQueue;
                            backend.match_ack_to_outbound(&hash).await
                        })
                    }
                })
                .map_err(outbound_err_to_py)?;
            match row_opt {
                None => Ok(None),
                Some(r) => Ok(Some(outbound_row_to_pydict(py, &r)?)),
            }
        })
    }

    /// v0.4.0 — Record the receiver's ACK envelope on a matched
    /// `awaiting_ack` row and transition to `delivered`.
    fn mark_ack_received(
        &self,
        py: Python<'_>,
        queue_id: &str,
        ack_envelope_bytes: &[u8],
    ) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let qid = queue_id.to_owned();
            let ack = ack_envelope_bytes.to_vec();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend.mark_ack_received(&qid, &ack).await
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend.mark_ack_received(&qid, &ack).await
                    })
                }
            })
            .map_err(outbound_err_to_py)
        })
    }

    /// v0.4.0 — Sweep ACK timeouts. Returns the count of rows
    /// touched (retried or abandoned).
    fn sweep_ack_timeouts(&self, py: Python<'_>) -> PyResult<i64> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend.sweep_ack_timeouts().await
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend.sweep_ack_timeouts().await
                    })
                }
            })
            .map_err(outbound_err_to_py)
        })
    }

    /// v0.4.0 — Sweep TTL-expired rows.
    fn sweep_ttl_expired(&self, py: Python<'_>) -> PyResult<i64> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend.sweep_ttl_expired().await
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend.sweep_ttl_expired().await
                    })
                }
            })
            .map_err(outbound_err_to_py)
        })
    }

    /// v0.4.0 — Sweep expired claims (revert sending → pending for
    /// rows whose claimed_until elapsed).
    fn sweep_expired_claims(&self, py: Python<'_>) -> PyResult<i64> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend.sweep_expired_claims().await
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend.sweep_expired_claims().await
                    })
                }
            })
            .map_err(outbound_err_to_py)
        })
    }

    /// v0.4.0 — Look up a row by queue_id. Returns the row dict or
    /// `None`. Used by `DurableHandle::status()`.
    fn outbound_status<'py>(
        &self,
        py: Python<'py>,
        queue_id: &str,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let qid = queue_id.to_owned();
            let row_opt = py
                .detach(move || match &self.backend {
                    BackendDispatch::Postgres(pg) => {
                        let backend = pg.clone();
                        runtime.block_on(async move {
                            use crate::outbound::OutboundQueue;
                            backend.outbound_status(&qid).await
                        })
                    }
                    #[cfg(feature = "sqlite")]
                    BackendDispatch::Sqlite(sq) => {
                        let backend = sq.clone();
                        runtime.block_on(async move {
                            use crate::outbound::OutboundQueue;
                            backend.outbound_status(&qid).await
                        })
                    }
                })
                .map_err(outbound_err_to_py)?;
            match row_opt {
                None => Ok(None),
                Some(r) => Ok(Some(outbound_row_to_pydict(py, &r)?)),
            }
        })
    }

    /// v0.4.0 — List outbound rows with optional filters. Returns
    /// a list of dicts. All filter parameters are optional;
    /// combine with AND.
    #[pyo3(signature = (
        limit=100,
        status=None,
        destination_key_id=None,
        sender_key_id=None,
        message_type=None,
        enqueued_after_rfc3339=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn list_outbound<'py>(
        &self,
        py: Python<'py>,
        limit: i64,
        status: Option<&str>,
        destination_key_id: Option<&str>,
        sender_key_id: Option<&str>,
        message_type: Option<&str>,
        enqueued_after_rfc3339: Option<&str>,
    ) -> PyResult<pyo3::Bound<'py, pyo3::types::PyList>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let status_parsed = match status {
                Some(s) => Some(
                    crate::outbound::OutboundStatus::from_wire_str(s)
                        .ok_or_else(|| PyValueError::new_err(format!("unknown status: {s}")))?,
                ),
                None => None,
            };
            let enqueued_after = match enqueued_after_rfc3339 {
                Some(s) => Some(s.parse::<chrono::DateTime<chrono::Utc>>().map_err(|e| {
                    PyValueError::new_err(format!("enqueued_after_rfc3339 parse: {e}"))
                })?),
                None => None,
            };
            let filter = crate::outbound::OutboundFilter {
                status: status_parsed,
                destination_key_id: destination_key_id.map(str::to_owned),
                sender_key_id: sender_key_id.map(str::to_owned),
                message_type: message_type.map(str::to_owned),
                enqueued_after,
            };
            let runtime = self.runtime.clone();
            let rows = py
                .detach(move || match &self.backend {
                    BackendDispatch::Postgres(pg) => {
                        let backend = pg.clone();
                        runtime.block_on(async move {
                            use crate::outbound::OutboundQueue;
                            backend.list_outbound(filter, limit).await
                        })
                    }
                    #[cfg(feature = "sqlite")]
                    BackendDispatch::Sqlite(sq) => {
                        let backend = sq.clone();
                        runtime.block_on(async move {
                            use crate::outbound::OutboundQueue;
                            backend.list_outbound(filter, limit).await
                        })
                    }
                })
                .map_err(outbound_err_to_py)?;
            outbound_rows_to_pylist(py, rows)
        })
    }

    /// v0.4.0 — Operator-driven cancellation. Idempotent.
    fn cancel_outbound(&self, py: Python<'_>, queue_id: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let qid = queue_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend.cancel_outbound(&qid).await
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend.cancel_outbound(&qid).await
                    })
                }
            })
            .map_err(outbound_err_to_py)
        })
    }

    /// v0.4.0 — Operator-driven replay. Resets attempt_count=0 and
    /// requeues an abandoned row.
    fn replay_abandoned(&self, py: Python<'_>, queue_id: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let qid = queue_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend.replay_abandoned(&qid).await
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::outbound::OutboundQueue;
                        backend.replay_abandoned(&qid).await
                    })
                }
            })
            .map_err(outbound_err_to_py)
        })
    }

    // ─── Lens-derived schemas (v0.4.3, CIRISPersist#18) ────────────
    //
    // CRUD surface for cirislens_derived.detection_events and
    // cirislens_derived.calibration_bundles. Wire format: JSON strings
    // in/out, mirroring the federation directory methods (put_public_key,
    // put_attestation). Lens-core / RATCHET call json.dumps before
    // passing in, json.loads on receiving back.
    //
    // Both put paths verify the hybrid (Ed25519 + ML-DSA-65) signature
    // via crate::verify::verify_hybrid_via_directory under
    // HybridPolicy::Strict BEFORE calling the backend write. Both
    // signatures must verify; no fallback. Federation evidence is
    // hybrid-mandatory (same principle as the build-manifest hybrid
    // signing edge + persist already use).

    /// Lens-derived: write a detection event.
    ///
    /// `event_json` is a JSON string of `DetectionEvent` (see
    /// `crate::derived::types::DetectionEvent`). Persist verifies the
    /// hybrid signature on `canonical_bytes` against
    /// `signing_key_id` in `federation_keys` under
    /// `HybridPolicy::Strict`. On verify failure raises `ValueError`
    /// with the standard `verify_*` token. On verify success, the
    /// row is inserted (idempotent on `detection_id`).
    fn put_detection_event(&self, py: Python<'_>, event_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let event: crate::derived::DetectionEvent = serde_json::from_str(event_json)
                .map_err(|e| PyValueError::new_err(format!("DetectionEvent JSON decode: {e}")))?;

            // Hybrid verify under Strict — both signatures required.
            // canonical_bytes carries the original signed shape; persist
            // does NOT recanonicalize (CIRISPersist#7 single-source-of-
            // truth: the canonicalizer ran ONCE upstream; persist verifies
            // the bytes the signer signed).
            let canonical_for_verify = event.canonical_bytes.clone();
            let signing_key_id = event.signing_key_id.clone();
            let ed25519_b64 = base64_encode(&event.ed25519_sig);
            let ml_dsa_b64 = base64_encode(&event.ml_dsa_65_sig);

            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        let outcome = crate::verify::verify_hybrid_via_directory(
                            &*backend,
                            &canonical_for_verify,
                            &signing_key_id,
                            &ed25519_b64,
                            Some(&ml_dsa_b64),
                            crate::verify::HybridPolicy::Strict,
                            None,
                        )
                        .await
                        .map_err(|e| {
                            let s = e.to_string();
                            tracing::warn!(
                                error = %e, kind = e.kind(),
                                "put_detection_event: hybrid verify rejected"
                            );
                            if s.contains("verify_unknown_key") {
                                PyValueError::new_err("verify_unknown_key")
                            } else {
                                PyValueError::new_err(e.kind())
                            }
                        })?;
                        if !matches!(outcome, crate::verify::VerifyOutcome::HybridVerified) {
                            return Err(PyValueError::new_err("hybrid_verify_strict_required"));
                        }

                        use crate::derived::DerivedSchema;
                        backend
                            .put_detection_event(event)
                            .await
                            .map_err(derived_err_to_py)
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        let outcome = crate::verify::verify_hybrid_via_directory(
                            &*backend,
                            &canonical_for_verify,
                            &signing_key_id,
                            &ed25519_b64,
                            Some(&ml_dsa_b64),
                            crate::verify::HybridPolicy::Strict,
                            None,
                        )
                        .await
                        .map_err(|e| {
                            let s = e.to_string();
                            tracing::warn!(
                                error = %e, kind = e.kind(),
                                "put_detection_event: hybrid verify rejected"
                            );
                            if s.contains("verify_unknown_key") {
                                PyValueError::new_err("verify_unknown_key")
                            } else {
                                PyValueError::new_err(e.kind())
                            }
                        })?;
                        if !matches!(outcome, crate::verify::VerifyOutcome::HybridVerified) {
                            return Err(PyValueError::new_err("hybrid_verify_strict_required"));
                        }

                        use crate::derived::DerivedSchema;
                        backend
                            .put_detection_event(event)
                            .await
                            .map_err(derived_err_to_py)
                    })
                }
            })
        })
    }

    /// Lens-derived: query detection events. Filter is JSON-encoded
    /// `EventFilter` (`{"trace_id": ?, "detector": ?, "since": ?}`;
    /// any field may be null/absent). Returns a JSON array string
    /// of `DetectionEvent` objects, ordered by `ts DESC`.
    fn get_detection_events(&self, py: Python<'_>, filter_json: Option<&str>) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::derived::EventFilter = match filter_json {
                None => crate::derived::EventFilter::default(),
                Some(s) => {
                    #[derive(serde::Deserialize)]
                    struct EventFilterJson {
                        trace_id: Option<String>,
                        detector: Option<String>,
                        since: Option<chrono::DateTime<chrono::Utc>>,
                    }
                    let parsed: EventFilterJson = serde_json::from_str(s).map_err(|e| {
                        PyValueError::new_err(format!("EventFilter JSON decode: {e}"))
                    })?;
                    crate::derived::EventFilter {
                        trace_id: parsed.trace_id,
                        detector: parsed.detector,
                        since: parsed.since,
                    }
                }
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::derived::DerivedSchema;
                        let rows = backend
                            .get_detection_events(filter)
                            .await
                            .map_err(derived_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("DetectionEvent JSON encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::derived::DerivedSchema;
                        let rows = backend
                            .get_detection_events(filter)
                            .await
                            .map_err(derived_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("DetectionEvent JSON encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v2.13.0 (CIRISPersist#113) — query the V020
    /// `edge_detection_events` table. Filter is JSON-encoded
    /// `EdgeEventFilter`:
    ///
    /// ```json
    /// {
    ///   "tenant_id":       "tnt-x",            // optional
    ///   "peer_key_id":     "key-suspect",       // optional
    ///   "event_type":      "unconsented_external_probe", // optional
    ///   "recorded_after":  "2026-05-01T00:00:00Z",        // optional
    ///   "limit":           500                  // optional (default 1000)
    /// }
    /// ```
    ///
    /// Returns a JSON array string of `EdgeDetectionEvent` objects,
    /// ordered ASC by `(tenant_id, observed_at, detection_id)`.
    fn get_edge_detection_events(
        &self,
        py: Python<'_>,
        filter_json: Option<&str>,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::derived::EdgeEventFilter = match filter_json {
                None => crate::derived::EdgeEventFilter::default(),
                Some(s) => {
                    #[derive(serde::Deserialize)]
                    struct EdgeEventFilterJson {
                        tenant_id: Option<String>,
                        peer_key_id: Option<String>,
                        event_type: Option<String>,
                        recorded_after: Option<chrono::DateTime<chrono::Utc>>,
                        limit: Option<usize>,
                    }
                    let parsed: EdgeEventFilterJson = serde_json::from_str(s).map_err(|e| {
                        PyValueError::new_err(format!("EdgeEventFilter JSON decode: {e}"))
                    })?;
                    crate::derived::EdgeEventFilter {
                        tenant_id: parsed.tenant_id,
                        peer_key_id: parsed.peer_key_id,
                        event_type: parsed.event_type,
                        recorded_after: parsed.recorded_after,
                        limit: parsed.limit,
                    }
                }
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::derived::DerivedSchema;
                        let rows = backend
                            .get_edge_detection_events(filter)
                            .await
                            .map_err(derived_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("EdgeDetectionEvent JSON encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::derived::DerivedSchema;
                        let rows = backend
                            .get_edge_detection_events(filter)
                            .await
                            .map_err(derived_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("EdgeDetectionEvent JSON encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// Lens-derived: write a calibration bundle.
    ///
    /// `bundle_json` is a JSON string of `CalibrationBundle`. Persist
    /// verifies the hybrid signature against `signing_key_id` in
    /// `federation_keys` under `HybridPolicy::Strict`, then atomically
    /// flips `is_current` on the previous current row and inserts the
    /// new row in a single transaction.
    fn put_calibration_bundle(&self, py: Python<'_>, bundle_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let bundle: crate::derived::CalibrationBundle = serde_json::from_str(bundle_json)
                .map_err(|e| {
                    PyValueError::new_err(format!("CalibrationBundle JSON decode: {e}"))
                })?;

            let canonical_for_verify = bundle.canonical_bytes.clone();
            let signing_key_id = bundle.signing_key_id.clone();
            let ed25519_b64 = base64_encode(&bundle.ed25519_sig);
            let ml_dsa_b64 = base64_encode(&bundle.ml_dsa_65_sig);

            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        let outcome = crate::verify::verify_hybrid_via_directory(
                            &*backend,
                            &canonical_for_verify,
                            &signing_key_id,
                            &ed25519_b64,
                            Some(&ml_dsa_b64),
                            crate::verify::HybridPolicy::Strict,
                            None,
                        )
                        .await
                        .map_err(|e| {
                            let s = e.to_string();
                            tracing::warn!(
                                error = %e, kind = e.kind(),
                                "put_calibration_bundle: hybrid verify rejected"
                            );
                            if s.contains("verify_unknown_key") {
                                PyValueError::new_err("verify_unknown_key")
                            } else {
                                PyValueError::new_err(e.kind())
                            }
                        })?;
                        if !matches!(outcome, crate::verify::VerifyOutcome::HybridVerified) {
                            return Err(PyValueError::new_err("hybrid_verify_strict_required"));
                        }

                        use crate::derived::DerivedSchema;
                        backend
                            .put_calibration_bundle(bundle)
                            .await
                            .map_err(derived_err_to_py)
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        let outcome = crate::verify::verify_hybrid_via_directory(
                            &*backend,
                            &canonical_for_verify,
                            &signing_key_id,
                            &ed25519_b64,
                            Some(&ml_dsa_b64),
                            crate::verify::HybridPolicy::Strict,
                            None,
                        )
                        .await
                        .map_err(|e| {
                            let s = e.to_string();
                            tracing::warn!(
                                error = %e, kind = e.kind(),
                                "put_calibration_bundle: hybrid verify rejected"
                            );
                            if s.contains("verify_unknown_key") {
                                PyValueError::new_err("verify_unknown_key")
                            } else {
                                PyValueError::new_err(e.kind())
                            }
                        })?;
                        if !matches!(outcome, crate::verify::VerifyOutcome::HybridVerified) {
                            return Err(PyValueError::new_err("hybrid_verify_strict_required"));
                        }

                        use crate::derived::DerivedSchema;
                        backend
                            .put_calibration_bundle(bundle)
                            .await
                            .map_err(derived_err_to_py)
                    })
                }
            })
        })
    }

    /// Lens-derived: get the bundle with `is_current = TRUE`.
    /// Returns JSON-encoded `CalibrationBundle` or `None`.
    fn get_current_calibration_bundle(&self, py: Python<'_>) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::derived::DerivedSchema;
                        let opt = backend
                            .get_current_calibration_bundle()
                            .await
                            .map_err(derived_err_to_py)?;
                        match opt {
                            None => Ok(None),
                            Some(b) => Ok(Some(serde_json::to_string(&b).map_err(|e| {
                                PyRuntimeError::new_err(format!(
                                    "CalibrationBundle JSON encode: {e}"
                                ))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::derived::DerivedSchema;
                        let opt = backend
                            .get_current_calibration_bundle()
                            .await
                            .map_err(derived_err_to_py)?;
                        match opt {
                            None => Ok(None),
                            Some(b) => Ok(Some(serde_json::to_string(&b).map_err(|e| {
                                PyRuntimeError::new_err(format!(
                                    "CalibrationBundle JSON encode: {e}"
                                ))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    /// Lens-derived: get the bundle for a specific
    /// `ratchet_calibration_version`.
    fn get_calibration_bundle_by_version(
        &self,
        py: Python<'_>,
        version: i32,
    ) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::derived::DerivedSchema;
                        let opt = backend
                            .get_calibration_bundle_by_version(version)
                            .await
                            .map_err(derived_err_to_py)?;
                        match opt {
                            None => Ok(None),
                            Some(b) => Ok(Some(serde_json::to_string(&b).map_err(|e| {
                                PyRuntimeError::new_err(format!(
                                    "CalibrationBundle JSON encode: {e}"
                                ))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::derived::DerivedSchema;
                        let opt = backend
                            .get_calibration_bundle_by_version(version)
                            .await
                            .map_err(derived_err_to_py)?;
                        match opt {
                            None => Ok(None),
                            Some(b) => Ok(Some(serde_json::to_string(&b).map_err(|e| {
                                PyRuntimeError::new_err(format!(
                                    "CalibrationBundle JSON encode: {e}"
                                ))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    // ─── Federation read primitives (v0.5.0, CIRISPersist#23) ──────
    //
    // 12 wrappers over crate::read::ReadEngine. Wire format: JSON
    // strings in/out for complex types (TraceFilter, TraceCursor,
    // TraceSummary, TraceListPage, TraceDetail, TimeWindow,
    // DivergenceRow/etc., ScoringFactorAggregate); primitives as
    // direct args (trace_id, agent_id_hash, limit, etc.). Lens calls
    // json.dumps before passing in, json.loads on receiving back —
    // adds a serde round-trip per call but keeps the API uniform
    // across complex shapes (same idiom as put_public_key /
    // put_attestation / put_detection_event).
    //
    // AV-15: read_err_to_py emits stable kind tokens at the FFI
    // boundary; verbose detail to tracing only.

    // ── Section A: trace listing ────────────────────────────────

    /// Lens-bleeding endpoint /repository/traces driver.
    /// Returns a JSON string of `TraceListPage`.
    #[pyo3(signature = (filter_json, cursor_json=None, limit=100))]
    fn list_trace_summaries(
        &self,
        py: Python<'_>,
        filter_json: &str,
        cursor_json: Option<&str>,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::read::TraceFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("TraceFilter JSON decode: {e}")))?;
            let cursor: Option<crate::read::TraceCursor> =
                match cursor_json {
                    None => None,
                    Some(s) => Some(serde_json::from_str(s).map_err(|e| {
                        PyValueError::new_err(format!("TraceCursor JSON decode: {e}"))
                    })?),
                };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let page = backend
                            .list_trace_summaries(filter, cursor, limit)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("TraceListPage encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let page = backend
                            .list_trace_summaries(filter, cursor, limit)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("TraceListPage encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// Single-trace summary lookup. Returns JSON-encoded
    /// `TraceSummary` or `None`.
    fn get_trace_summary(&self, py: Python<'_>, trace_id: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let trace_id = trace_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let opt = backend
                            .get_trace_summary(&trace_id)
                            .await
                            .map_err(read_err_to_py)?;
                        match opt {
                            None => Ok(None),
                            Some(s) => Ok(Some(serde_json::to_string(&s).map_err(|e| {
                                PyRuntimeError::new_err(format!("TraceSummary encode: {e}"))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let opt = backend
                            .get_trace_summary(&trace_id)
                            .await
                            .map_err(read_err_to_py)?;
                        match opt {
                            None => Ok(None),
                            Some(s) => Ok(Some(serde_json::to_string(&s).map_err(|e| {
                                PyRuntimeError::new_err(format!("TraceSummary encode: {e}"))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    // ── Section B: trace detail ─────────────────────────────────

    /// Full trace reconstruction. Returns JSON-encoded `TraceDetail`
    /// or `None`. Drives `/repository/traces/{trace_id}`.
    fn get_trace_detail(&self, py: Python<'_>, trace_id: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let trace_id = trace_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let opt = backend
                            .get_trace_detail(&trace_id)
                            .await
                            .map_err(read_err_to_py)?;
                        match opt {
                            None => Ok(None),
                            Some(d) => Ok(Some(serde_json::to_string(&d).map_err(|e| {
                                PyRuntimeError::new_err(format!("TraceDetail encode: {e}"))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let opt = backend
                            .get_trace_detail(&trace_id)
                            .await
                            .map_err(read_err_to_py)?;
                        match opt {
                            None => Ok(None),
                            Some(d) => Ok(Some(serde_json::to_string(&d).map_err(|e| {
                                PyRuntimeError::new_err(format!("TraceDetail encode: {e}"))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    // ── v0.6.0-α5: pipeline read surface ───────────────────────

    /// v0.6.0 (CIRISPersist#19) — read typed Features for a
    /// `(trace_id, thought_id)` pair from
    /// `cirislens.trace_events.extracted_features` (V009 column).
    ///
    /// Returns JSON-encoded `Features` or `None`. `None` when the
    /// trace/thought pair has no rows or the pipeline hasn't yet
    /// run on those rows (pre-v0.6.0 / pipeline-skipped ingest).
    #[cfg(feature = "extract")]
    fn get_features(
        &self,
        py: Python<'_>,
        trace_id: &str,
        thought_id: &str,
    ) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let trace_id = trace_id.to_owned();
            let thought_id = thought_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        let opt = backend
                            .read_features(&trace_id, &thought_id)
                            .await
                            .map_err(|e| PyRuntimeError::new_err(format!("read_features: {e}")))?;
                        match opt {
                            None => Ok(None),
                            Some(f) => Ok(Some(serde_json::to_string(&f).map_err(|e| {
                                PyRuntimeError::new_err(format!("Features encode: {e}"))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        let opt = backend
                            .read_features(&trace_id, &thought_id)
                            .await
                            .map_err(|e| PyRuntimeError::new_err(format!("read_features: {e}")))?;
                        match opt {
                            None => Ok(None),
                            Some(f) => Ok(Some(serde_json::to_string(&f).map_err(|e| {
                                PyRuntimeError::new_err(format!("Features encode: {e}"))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    /// v0.6.0 (CIRISPersist#19) — read per-component classification
    /// matches for a `(trace_id, thought_id)` pair from
    /// `cirislens.trace_events.classifications` (V009 column).
    ///
    /// Returns JSON-encoded `Vec<Vec<ContentClassMatch>>` (outer per-
    /// component, inner per-span-match). Empty array when the
    /// pipeline hasn't yet run on those rows.
    #[cfg(feature = "classify")]
    fn get_classifications(
        &self,
        py: Python<'_>,
        trace_id: &str,
        thought_id: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let trace_id = trace_id.to_owned();
            let thought_id = thought_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        let cls = backend
                            .read_classifications(&trace_id, &thought_id)
                            .await
                            .map_err(|e| {
                                PyRuntimeError::new_err(format!("read_classifications: {e}"))
                            })?;
                        serde_json::to_string(&cls).map_err(|e| {
                            PyRuntimeError::new_err(format!("classifications encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        let cls = backend
                            .read_classifications(&trace_id, &thought_id)
                            .await
                            .map_err(|e| {
                                PyRuntimeError::new_err(format!("read_classifications: {e}"))
                            })?;
                        serde_json::to_string(&cls).map_err(|e| {
                            PyRuntimeError::new_err(format!("classifications encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.8 (CIRISPersist#57) — write typed Features for a
    /// `(trace_id, thought_id)` pair into the V009 / V023
    /// `extracted_features` column.
    ///
    /// `features_json` is the JSON-encoded `Features` shape (round-trip
    /// safe with `get_features`'s return value). Caller contract: "set
    /// this if the row exists." No-op when no `trace_events` row matches
    /// — matches the pipeline classify-stage UPDATE semantics.
    #[cfg(feature = "extract")]
    fn set_features(
        &self,
        py: Python<'_>,
        trace_id: &str,
        thought_id: &str,
        features_json: &str,
    ) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let trace_id = trace_id.to_owned();
            let thought_id = thought_id.to_owned();
            let features: crate::pipeline::extract::Features = serde_json::from_str(features_json)
                .map_err(|e| PyValueError::new_err(format!("Features JSON decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        backend
                            .write_features(&trace_id, &thought_id, &features)
                            .await
                            .map_err(|e| PyRuntimeError::new_err(format!("write_features: {e}")))?;
                        Ok::<_, PyErr>(())
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        backend
                            .write_features(&trace_id, &thought_id, &features)
                            .await
                            .map_err(|e| PyRuntimeError::new_err(format!("write_features: {e}")))?;
                        Ok::<_, PyErr>(())
                    })
                }
            })
        })
    }

    /// v1.5.8 (CIRISPersist#57) — write per-component classification
    /// matches for a `(trace_id, thought_id)` pair into the V009 / V023
    /// `classifications` column.
    ///
    /// `classifications_json` is the JSON-encoded
    /// `Vec<Vec<ContentClassMatch>>` shape (round-trip safe with
    /// `get_classifications`'s return value). Caller contract: "set
    /// this if the row exists." No-op when no `trace_events` row matches
    /// — matches the pipeline classify-stage UPDATE semantics.
    #[cfg(feature = "classify")]
    fn set_classifications(
        &self,
        py: Python<'_>,
        trace_id: &str,
        thought_id: &str,
        classifications_json: &str,
    ) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let trace_id = trace_id.to_owned();
            let thought_id = thought_id.to_owned();
            let classifications: Vec<Vec<crate::pipeline::classify::ContentClassMatch>> =
                serde_json::from_str(classifications_json).map_err(|e| {
                    PyValueError::new_err(format!("classifications JSON decode: {e}"))
                })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        backend
                            .write_classifications(&trace_id, &thought_id, &classifications)
                            .await
                            .map_err(|e| {
                                PyRuntimeError::new_err(format!("write_classifications: {e}"))
                            })?;
                        Ok::<_, PyErr>(())
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        backend
                            .write_classifications(&trace_id, &thought_id, &classifications)
                            .await
                            .map_err(|e| {
                                PyRuntimeError::new_err(format!("write_classifications: {e}"))
                            })?;
                        Ok::<_, PyErr>(())
                    })
                }
            })
        })
    }

    // ── Section C: task-grouped listing ────────────────────────

    /// Page through tasks, each task carrying its component trace
    /// summaries. Drives task-axis views (qa-eval, discord, wakeup,
    /// real-user). Returns JSON-encoded `TaskListPage`.
    ///
    /// `task_class` filtering (qa_eval / discord / real_user_* /
    /// wakeup_ritual / other) is server-side via the canonical
    /// task_id-prefix mapping in `crate::read::TaskClass::from_task_id`.
    /// Cursor-paged; no OFFSET/LIMIT.
    fn list_tasks(
        &self,
        py: Python<'_>,
        filter_json: &str,
        cursor_json: Option<&str>,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::read::TaskFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("TaskFilter JSON decode: {e}")))?;
            let cursor: Option<crate::read::TaskCursor> =
                match cursor_json {
                    None => None,
                    Some(s) => Some(serde_json::from_str(s).map_err(|e| {
                        PyValueError::new_err(format!("TaskCursor JSON decode: {e}"))
                    })?),
                };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let page = backend
                            .list_tasks(filter, cursor, limit)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("TaskListPage encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let page = backend
                            .list_tasks(filter, cursor, limit)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("TaskListPage encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── Section D: LLM call surface ─────────────────────────────

    /// Page through `cirislens.trace_llm_calls` rows. Filters compose
    /// AND-style; cursor-paged newest-first. Returns JSON-encoded
    /// `LlmCallListPage`.
    fn list_llm_calls(
        &self,
        py: Python<'_>,
        filter_json: &str,
        cursor_json: Option<&str>,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::read::LlmCallFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("LlmCallFilter JSON decode: {e}")))?;
            let cursor: Option<crate::read::LlmCallCursor> = match cursor_json {
                None => None,
                Some(s) => Some(serde_json::from_str(s).map_err(|e| {
                    PyValueError::new_err(format!("LlmCallCursor JSON decode: {e}"))
                })?),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let page = backend
                            .list_llm_calls(filter, cursor, limit)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("LlmCallListPage encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let page = backend
                            .list_llm_calls(filter, cursor, limit)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("LlmCallListPage encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// Cost rollup by model / agent / deployment domain + window
    /// totals. Returns JSON-encoded `LlmCostAggregate`.
    fn aggregate_llm_costs(&self, py: Python<'_>, filter_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::read::LlmCallFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("LlmCallFilter JSON decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let agg = backend
                            .aggregate_llm_costs(filter)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&agg).map_err(|e| {
                            PyRuntimeError::new_err(format!("LlmCostAggregate encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let agg = backend
                            .aggregate_llm_costs(filter)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&agg).map_err(|e| {
                            PyRuntimeError::new_err(format!("LlmCostAggregate encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── Section G: corpus shape ─────────────────────────────────

    /// Corpus-shape rollup for a window — distinct trace counts by
    /// task_class, QA language / question_num, agent name / version,
    /// primary model, deployment region. Returns JSON-encoded
    /// `CorpusShape`.
    fn corpus_shape(&self, py: Python<'_>, filter_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::read::CorpusShapeFilter = serde_json::from_str(filter_json)
                .map_err(|e| {
                    PyValueError::new_err(format!("CorpusShapeFilter JSON decode: {e}"))
                })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let shape = backend.corpus_shape(filter).await.map_err(read_err_to_py)?;
                        serde_json::to_string(&shape).map_err(|e| {
                            PyRuntimeError::new_err(format!("CorpusShape encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let shape = backend.corpus_shape(filter).await.map_err(read_err_to_py)?;
                        serde_json::to_string(&shape).map_err(|e| {
                            PyRuntimeError::new_err(format!("CorpusShape encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── Section H: privacy / scrub observability ────────────────

    /// Scrub-stats aggregate for a window. Drives privacy dashboards.
    /// Returns JSON-encoded `ScrubAggregate`.
    ///
    /// `since_iso8601` + `until_iso8601` parse via RFC3339.
    fn aggregate_scrub_stats(
        &self,
        py: Python<'_>,
        since_iso8601: &str,
        until_iso8601: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let since = chrono::DateTime::parse_from_rfc3339(since_iso8601)
                .map_err(|e| PyValueError::new_err(format!("since RFC3339: {e}")))?
                .with_timezone(&chrono::Utc);
            let until = chrono::DateTime::parse_from_rfc3339(until_iso8601)
                .map_err(|e| PyValueError::new_err(format!("until RFC3339: {e}")))?
                .with_timezone(&chrono::Utc);
            let window = crate::read::TimeWindow::new(since, until).map_err(read_err_to_py)?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let agg = backend
                            .aggregate_scrub_stats(window)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&agg).map_err(|e| {
                            PyRuntimeError::new_err(format!("ScrubAggregate encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let agg = backend
                            .aggregate_scrub_stats(window)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&agg).map_err(|e| {
                            PyRuntimeError::new_err(format!("ScrubAggregate encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── Section I: federation observability bulk ─────────────────

    /// Bulk-list federation_keys with filter + cursor pagination.
    /// Returns JSON-encoded `FederationKeyListPage`.
    fn list_federation_keys(
        &self,
        py: Python<'_>,
        filter_json: &str,
        cursor_json: Option<&str>,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::read::FederationKeyFilter = serde_json::from_str(filter_json)
                .map_err(|e| {
                    PyValueError::new_err(format!("FederationKeyFilter JSON decode: {e}"))
                })?;
            let cursor: Option<crate::read::FederationKeyCursor> = match cursor_json {
                None => None,
                Some(s) => Some(serde_json::from_str(s).map_err(|e| {
                    PyValueError::new_err(format!("FederationKeyCursor JSON decode: {e}"))
                })?),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let page = backend
                            .list_federation_keys(filter, cursor, limit)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("FederationKeyListPage encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let page = backend
                            .list_federation_keys(filter, cursor, limit)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("FederationKeyListPage encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// Bulk-list federation_attestations. Returns JSON-encoded
    /// `AttestationListPage`.
    fn list_attestations(
        &self,
        py: Python<'_>,
        filter_json: &str,
        cursor_json: Option<&str>,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::read::AttestationFilter = serde_json::from_str(filter_json)
                .map_err(|e| {
                    PyValueError::new_err(format!("AttestationFilter JSON decode: {e}"))
                })?;
            let cursor: Option<crate::read::AttestationCursor> = match cursor_json {
                None => None,
                Some(s) => Some(serde_json::from_str(s).map_err(|e| {
                    PyValueError::new_err(format!("AttestationCursor JSON decode: {e}"))
                })?),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let page = backend
                            .list_attestations(filter, cursor, limit)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("AttestationListPage encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let page = backend
                            .list_attestations(filter, cursor, limit)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("AttestationListPage encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// Bulk-list federation_revocations. Returns JSON-encoded
    /// `RevocationListPage`.
    fn list_revocations(
        &self,
        py: Python<'_>,
        filter_json: &str,
        cursor_json: Option<&str>,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::read::RevocationFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("RevocationFilter JSON decode: {e}")))?;
            let cursor: Option<crate::read::RevocationCursor> = match cursor_json {
                None => None,
                Some(s) => Some(serde_json::from_str(s).map_err(|e| {
                    PyValueError::new_err(format!("RevocationCursor JSON decode: {e}"))
                })?),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let page = backend
                            .list_revocations(filter, cursor, limit)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("RevocationListPage encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let page = backend
                            .list_revocations(filter, cursor, limit)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("RevocationListPage encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── Section F: Coherence Ratchet inputs ─────────────────────

    /// Cross-agent divergence z-scores. `metric` is one of
    /// `"csdma_plausibility"`, `"dsdma_domain_alignment"`,
    /// `"idma_k_eff"`, `"idma_correlation_risk"`,
    /// `"conscience_override_rate"`. Returns JSON array of
    /// `DivergenceRow`.
    fn cross_agent_divergence(
        &self,
        py: Python<'_>,
        deployment_domain: &str,
        window_json: &str,
        metric: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let domain = deployment_domain.to_owned();
            let window: crate::read::TimeWindow = serde_json::from_str(window_json)
                .map_err(|e| PyValueError::new_err(format!("TimeWindow JSON decode: {e}")))?;
            let metric: crate::read::DeviationMetric =
                serde_json::from_str(&format!("\"{metric}\""))
                    .map_err(|e| PyValueError::new_err(format!("DeviationMetric decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let rows = backend
                            .cross_agent_divergence(&domain, window, metric)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("DivergenceRow encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let rows = backend
                            .cross_agent_divergence(&domain, window, metric)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("DivergenceRow encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// Temporal drift between two windows for one agent.
    /// Returns JSON array of `TemporalDriftRow`.
    fn temporal_drift(
        &self,
        py: Python<'_>,
        agent_id_hash: &str,
        baseline_json: &str,
        comparison_json: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let aid = agent_id_hash.to_owned();
            let baseline: crate::read::TimeWindow = serde_json::from_str(baseline_json)
                .map_err(|e| PyValueError::new_err(format!("baseline TimeWindow decode: {e}")))?;
            let comparison: crate::read::TimeWindow = serde_json::from_str(comparison_json)
                .map_err(|e| PyValueError::new_err(format!("comparison TimeWindow decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let rows = backend
                            .temporal_drift(&aid, baseline, comparison)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("TemporalDriftRow encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let rows = backend
                            .temporal_drift(&aid, baseline, comparison)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("TemporalDriftRow encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// Audit-chain gaps for an agent over a window. Returns JSON
    /// array of `HashChainGap`.
    fn hash_chain_gaps(
        &self,
        py: Python<'_>,
        agent_id_hash: &str,
        window_json: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let aid = agent_id_hash.to_owned();
            let window: crate::read::TimeWindow = serde_json::from_str(window_json)
                .map_err(|e| PyValueError::new_err(format!("TimeWindow decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let rows = backend
                            .hash_chain_gaps(&aid, window)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("HashChainGap encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let rows = backend
                            .hash_chain_gaps(&aid, window)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("HashChainGap encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// Per-agent conscience-override rates within a deployment
    /// domain. Returns JSON array of `OverrideRateRow`.
    fn conscience_override_rates(
        &self,
        py: Python<'_>,
        deployment_domain: &str,
        window_json: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let domain = deployment_domain.to_owned();
            let window: crate::read::TimeWindow = serde_json::from_str(window_json)
                .map_err(|e| PyValueError::new_err(format!("TimeWindow decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let rows = backend
                            .conscience_override_rates(&domain, window)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("OverrideRateRow encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let rows = backend
                            .conscience_override_rates(&domain, window)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("OverrideRateRow encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── Section E: scoring factor aggregates ────────────────────

    /// Bundled scoring factor aggregate. Replaces api/scoring.py's
    /// raw SQL. Returns JSON-encoded `ScoringFactorAggregate`.
    /// `baseline_window_json=None` → `drift_z_score` is None.
    #[pyo3(signature = (agent_id_hash, window_json, baseline_window_json=None))]
    fn aggregate_scoring_factors(
        &self,
        py: Python<'_>,
        agent_id_hash: &str,
        window_json: &str,
        baseline_window_json: Option<&str>,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let aid = agent_id_hash.to_owned();
            let window: crate::read::TimeWindow = serde_json::from_str(window_json)
                .map_err(|e| PyValueError::new_err(format!("TimeWindow decode: {e}")))?;
            let baseline: Option<crate::read::TimeWindow> = match baseline_window_json {
                None => None,
                Some(s) => Some(serde_json::from_str(s).map_err(|e| {
                    PyValueError::new_err(format!("baseline TimeWindow decode: {e}"))
                })?),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let agg = backend
                            .aggregate_scoring_factors(&aid, window, baseline)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&agg).map_err(|e| {
                            PyRuntimeError::new_err(format!("ScoringFactorAggregate encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let agg = backend
                            .aggregate_scoring_factors(&aid, window, baseline)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&agg).map_err(|e| {
                            PyRuntimeError::new_err(format!("ScoringFactorAggregate encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// Batch variant — fleet-wide score sweep. `agent_id_hashes_json`
    /// is a JSON array of strings. Returns JSON array of
    /// `ScoringFactorAggregate` in input order.
    #[pyo3(signature = (agent_id_hashes_json, window_json, baseline_window_json=None))]
    fn aggregate_scoring_factors_batch(
        &self,
        py: Python<'_>,
        agent_id_hashes_json: &str,
        window_json: &str,
        baseline_window_json: Option<&str>,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let aids: Vec<String> = serde_json::from_str(agent_id_hashes_json)
                .map_err(|e| PyValueError::new_err(format!("agent_id_hashes decode: {e}")))?;
            let window: crate::read::TimeWindow = serde_json::from_str(window_json)
                .map_err(|e| PyValueError::new_err(format!("TimeWindow decode: {e}")))?;
            let baseline: Option<crate::read::TimeWindow> = match baseline_window_json {
                None => None,
                Some(s) => Some(serde_json::from_str(s).map_err(|e| {
                    PyValueError::new_err(format!("baseline TimeWindow decode: {e}"))
                })?),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let aggs = backend
                            .aggregate_scoring_factors_batch(&aids, window, baseline)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&aggs).map_err(|e| {
                            PyRuntimeError::new_err(format!("ScoringFactorAggregate[] encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let aggs = backend
                            .aggregate_scoring_factors_batch(&aids, window, baseline)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&aggs).map_err(|e| {
                            PyRuntimeError::new_err(format!("ScoringFactorAggregate[] encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// Granular: count distinct trace_id matching filter.
    fn count_traces(&self, py: Python<'_>, filter_json: &str) -> PyResult<i64> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::read::TraceFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("TraceFilter decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        backend.count_traces(filter).await.map_err(read_err_to_py)
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        backend.count_traces(filter).await.map_err(read_err_to_py)
                    })
                }
            })
        })
    }

    /// Granular: count traces where conscience overrode the action.
    fn count_overrides(&self, py: Python<'_>, filter_json: &str) -> PyResult<i64> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::read::TraceFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("TraceFilter decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        backend
                            .count_overrides(filter)
                            .await
                            .map_err(read_err_to_py)
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        backend
                            .count_overrides(filter)
                            .await
                            .map_err(read_err_to_py)
                    })
                }
            })
        })
    }

    /// Granular: count agent_name changes (identity changes).
    fn count_identity_changes(&self, py: Python<'_>, filter_json: &str) -> PyResult<i64> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::read::TraceFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("TraceFilter decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        backend
                            .count_identity_changes(filter)
                            .await
                            .map_err(read_err_to_py)
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        backend
                            .count_identity_changes(filter)
                            .await
                            .map_err(read_err_to_py)
                    })
                }
            })
        })
    }

    /// Granular: audit-chain aggregate.
    /// Returns JSON-encoded `AuditChainAggregate`.
    fn aggregate_audit_chain(&self, py: Python<'_>, filter_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::read::TraceFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("TraceFilter decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let agg = backend
                            .aggregate_audit_chain(filter)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&agg).map_err(|e| {
                            PyRuntimeError::new_err(format!("AuditChainAggregate encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        use crate::read::ReadEngine;
                        let agg = backend
                            .aggregate_audit_chain(filter)
                            .await
                            .map_err(read_err_to_py)?;
                        serde_json::to_string(&agg).map_err(|e| {
                            PyRuntimeError::new_err(format!("AuditChainAggregate encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── v0.6.1: SecretsService PyO3 surface (CIRISPersist#19) ──────────
    //
    // 18 methods wrapping the SecretsService trait. Each goes through
    // catch_panic (v0.5.3 contract) + JSON-encodes the result.
    // SecretsError translates to PyErr via secrets_err_to_py at the
    // boundary.

    /// v0.6.1 — Store a manually-keyed secret. AES-256-GCM encrypts
    /// under the active master key; audited.
    #[cfg(feature = "secrets")]
    fn secrets_store_secret(
        &self,
        py: Python<'_>,
        key: &str,
        value: &str,
        accessor: &str,
    ) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let key = key.to_owned();
            let value = value.to_owned();
            let accessor = accessor.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        backend
                            .store_secret(key, value, accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        backend
                            .store_secret(key, value, accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.6.1 — Retrieve a manually-keyed secret. Returns plaintext
    /// or `None`.
    #[cfg(feature = "secrets")]
    fn secrets_retrieve_secret(
        &self,
        py: Python<'_>,
        key: &str,
        accessor: &str,
    ) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let key = key.to_owned();
            let accessor = accessor.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        backend
                            .retrieve_secret(&key, accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        backend
                            .retrieve_secret(&key, accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.6.1 — Recall a detected secret by UUID. Returns
    /// JSON-encoded `SecretRecallResult` or `None`.
    #[cfg(feature = "secrets")]
    fn secrets_recall_secret(
        &self,
        py: Python<'_>,
        uuid: &str,
        purpose: &str,
        accessor: &str,
        decrypt: bool,
    ) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let uuid = uuid.to_owned();
            let purpose = purpose.to_owned();
            let accessor = accessor.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let opt = backend
                            .recall_secret(&uuid, purpose, accessor, decrypt)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match opt {
                            None => Ok(None),
                            Some(r) => Ok(Some(serde_json::to_string(&r).map_err(|e| {
                                PyRuntimeError::new_err(format!("SecretRecallResult encode: {e}"))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let opt = backend
                            .recall_secret(&uuid, purpose, accessor, decrypt)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match opt {
                            None => Ok(None),
                            Some(r) => Ok(Some(serde_json::to_string(&r).map_err(|e| {
                                PyRuntimeError::new_err(format!("SecretRecallResult encode: {e}"))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    /// v0.6.1 — Metadata-only listing. Returns JSON array of
    /// `SecretReference`.
    #[cfg(feature = "secrets")]
    fn secrets_list_stored(
        &self,
        py: Python<'_>,
        limit: usize,
        filter_json: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::secrets::SecretsListFilter = serde_json::from_str(filter_json)
                .map_err(|e| {
                    PyValueError::new_err(format!("SecretsListFilter JSON decode: {e}"))
                })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let refs = backend
                            .list_stored_secrets(limit, filter)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&refs).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<SecretReference> encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let refs = backend
                            .list_stored_secrets(limit, filter)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&refs).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<SecretReference> encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v0.6.1 — Audited delete. Returns `true` if the secret existed.
    #[cfg(feature = "secrets")]
    fn secrets_forget_secret(&self, py: Python<'_>, uuid: &str, accessor: &str) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let uuid = uuid.to_owned();
            let accessor = accessor.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        backend
                            .forget_secret(&uuid, accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        backend
                            .forget_secret(&uuid, accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.5.7 (CIRISPersist#57) — Detect and encrypt-and-store every
    /// secret in `text` per the configured filter catalog.
    ///
    /// Composes [`SecretsService::get_filter_config`] +
    /// [`SecretsService::try_claim_secret`] in a default trait impl
    /// shared by both backends. Iterates each configured pattern,
    /// regex-matches against `text`, race-safely stores each unique
    /// match under a fresh UUID, and emits the filtered text with
    /// `{SECRET:<uuid>:<description>}` placeholders for the
    /// decapsulation path.
    ///
    /// Returns the JSON envelope `{"filtered_text": "...",
    /// "refs": [<SecretReference>, ...]}`. **Empty `refs` array
    /// means no patterns matched** — either the input is clean,
    /// OR the filter catalog hasn't been seeded (call
    /// `secrets_set_filter_config` first to install patterns).
    ///
    /// Patterns are JSON shape:
    /// ```json
    /// {
    ///   "patterns": [
    ///     {
    ///       "pattern_id": "openai_key",
    ///       "regex": "sk-[A-Za-z0-9]{48}",
    ///       "description": "OpenAI API key",
    ///       "sensitivity": "high",
    ///       "auto_decapsulate_for_actions": ["tool"]
    ///     }
    ///   ],
    ///   "version": 1
    /// }
    /// ```
    ///
    /// For an agent-side detection flow (caller pre-detects and
    /// assigns the UUID + full metadata), use
    /// `secrets_store_detected_secret` (v1.5.24, CIRISPersist#66)
    /// instead — that method bypasses the regex pipeline.
    #[cfg(feature = "secrets")]
    fn secrets_process_incoming_text(
        &self,
        py: Python<'_>,
        text: &str,
        source_message_id: &str,
        accessor: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let text = text.to_owned();
            let smi = source_message_id.to_owned();
            let accessor = accessor.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let (filtered, refs) = backend
                            .process_incoming_text(&text, &smi, accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        let body = serde_json::json!({
                            "filtered_text": filtered,
                            "refs": refs,
                        });
                        serde_json::to_string(&body).map_err(|e| {
                            PyRuntimeError::new_err(format!("process_incoming_text encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let (filtered, refs) = backend
                            .process_incoming_text(&text, &smi, accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        let body = serde_json::json!({
                            "filtered_text": filtered,
                            "refs": refs,
                        });
                        serde_json::to_string(&body).map_err(|e| {
                            PyRuntimeError::new_err(format!("process_incoming_text encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.24 (CIRISPersist#66) — Store an agent-detected secret
    /// with a caller-supplied UUID + full metadata bundle.
    ///
    /// `payload_json` decodes to `DetectedSecret`:
    /// ```json
    /// {
    ///   "secret_uuid": "<uuid-v4>",
    ///   "value": "<plaintext>",
    ///   "description": "...",
    ///   "sensitivity": "low" | "medium" | "high" | "critical",
    ///   "detected_pattern": "regex:openai_key_v1",
    ///   "context_hint": "in tool_args.api_key",
    ///   "source_message_id": "msg-123",
    ///   "auto_decapsulate_for_actions": ["tool"],
    ///   "manual_access_only": false
    /// }
    /// ```
    ///
    /// Returns the JSON envelope
    /// `{"outcome": "stored" | "already_claimed", "ref": <SecretReference>}`.
    ///
    /// **Race-safety** — INSERT with `content_hmac` dedup. Same
    /// plaintext under any caller path (this method or
    /// `try_claim_secret` inside `process_incoming_text`) resolves
    /// to `already_claimed` with the canonical existing
    /// `SecretReference` (which may carry a *different* UUID than
    /// the caller supplied — agent reconciles).
    ///
    /// **Idempotency** — re-supplying the same `(secret_uuid,
    /// value)` returns `already_claimed`. Re-supplying the same
    /// `secret_uuid` with a *different* `value` returns
    /// `InvalidArgument` (caller has a UUID-allocation bug).
    ///
    /// Distinct from `secrets_store_secret` (manually-keyed; persist
    /// generates the UUID; no detection metadata).
    /// Distinct from `secrets_process_incoming_text` (persist
    /// detects via regex catalog; agent has no UUID control).
    #[cfg(feature = "secrets")]
    fn secrets_store_detected_secret(
        &self,
        py: Python<'_>,
        payload_json: &str,
        accessor: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let payload: crate::secrets::DetectedSecret = serde_json::from_str(payload_json)
                .map_err(|e| PyValueError::new_err(format!("DetectedSecret decode: {e}")))?;
            let accessor = accessor.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let outcome = backend
                            .store_detected_secret(payload, accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        encode_secret_claim_result(outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!("store_detected_secret encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let outcome = backend
                            .store_detected_secret(payload, accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        encode_secret_claim_result(outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!("store_detected_secret encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// Walk `action_params_json`, replacing every
    /// `{SECRET:<uuid>:<description>}` placeholder with the
    /// decrypted plaintext (when the action_type is in the secret's
    /// `auto_decapsulate_for_actions` whitelist and
    /// `manual_access_only` is false). Returns the JSON-encoded
    /// `DecapsulateResult` carrying the rewritten params + per-secret
    /// outcomes. Audited via `access_log` with
    /// `operation = 'decrypt'`.
    #[cfg(feature = "secrets")]
    fn secrets_decapsulate(
        &self,
        py: Python<'_>,
        action_type: &str,
        action_params_json: &str,
        ctx_json: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let action_type = action_type.to_owned();
            let action_params: serde_json::Value = serde_json::from_str(action_params_json)
                .map_err(|e| PyValueError::new_err(format!("action_params decode: {e}")))?;
            let ctx: crate::secrets::DecapsulationContext = serde_json::from_str(ctx_json)
                .map_err(|e| PyValueError::new_err(format!("DecapsulationContext decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let out = backend
                            .decapsulate_secrets_in_parameters(&action_type, action_params, ctx)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&out).map_err(|e| {
                            PyRuntimeError::new_err(format!("decapsulate encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let out = backend
                            .decapsulate_secrets_in_parameters(&action_type, action_params, ctx)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&out).map_err(|e| {
                            PyRuntimeError::new_err(format!("decapsulate encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v0.6.1 — Direct AES-GCM encrypt. Returns
    /// `base64(salt || nonce || ciphertext)`.
    #[cfg(feature = "secrets")]
    fn secrets_encrypt(&self, py: Python<'_>, plaintext: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let pt = plaintext.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        backend
                            .encrypt(&pt)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        backend
                            .encrypt(&pt)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.6.1 — Direct AES-GCM decrypt.
    #[cfg(feature = "secrets")]
    fn secrets_decrypt(&self, py: Python<'_>, ciphertext: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let ct = ciphertext.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        backend
                            .decrypt(&ct)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        backend
                            .decrypt(&ct)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.6.1 — Read current filter pattern catalog. Returns
    /// JSON-encoded `FilterConfig`.
    #[cfg(feature = "secrets")]
    fn secrets_get_filter_config(&self, py: Python<'_>) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let cfg = backend
                            .get_filter_config()
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&cfg).map_err(|e| {
                            PyRuntimeError::new_err(format!("FilterConfig encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let cfg = backend
                            .get_filter_config()
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&cfg).map_err(|e| {
                            PyRuntimeError::new_err(format!("FilterConfig encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v0.6.1 — Write a new filter pattern catalog. Returns
    /// JSON-encoded `FilterUpdateResult`.
    #[cfg(feature = "secrets")]
    fn secrets_update_filter_config(
        &self,
        py: Python<'_>,
        updates_json: &str,
        accessor: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let req: crate::secrets::FilterUpdateRequest = serde_json::from_str(updates_json)
                .map_err(|e| PyValueError::new_err(format!("FilterUpdateRequest decode: {e}")))?;
            let accessor = accessor.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let res = backend
                            .update_filter_config(req, accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&res).map_err(|e| {
                            PyRuntimeError::new_err(format!("FilterUpdateResult encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let res = backend
                            .update_filter_config(req, accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&res).map_err(|e| {
                            PyRuntimeError::new_err(format!("FilterUpdateResult encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v0.6.1 — Service-wide observability stats. Returns
    /// JSON-encoded `SecretsServiceStats`.
    #[cfg(feature = "secrets")]
    fn secrets_get_service_stats(&self, py: Python<'_>) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let s = backend
                            .get_service_stats()
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&s).map_err(|e| {
                            PyRuntimeError::new_err(format!("SecretsServiceStats encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let s = backend
                            .get_service_stats()
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&s).map_err(|e| {
                            PyRuntimeError::new_err(format!("SecretsServiceStats encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v0.6.1 — Liveness probe.
    #[cfg(feature = "secrets")]
    fn secrets_is_healthy(&self, py: Python<'_>) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        backend
                            .is_healthy()
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        backend
                            .is_healthy()
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.6.1 — Audit-log query. `secret_uuid=None` returns the
    /// global tail. Returns JSON array of `AccessLogEntry`.
    #[cfg(feature = "secrets")]
    fn secrets_get_access_logs(
        &self,
        py: Python<'_>,
        secret_uuid: Option<&str>,
        limit: usize,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let uuid = secret_uuid.map(str::to_owned);
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let logs = backend
                            .get_access_logs(uuid.as_deref(), limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&logs).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<AccessLogEntry> encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let logs = backend
                            .get_access_logs(uuid.as_deref(), limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&logs).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<AccessLogEntry> encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v0.6.1 — Re-encrypt every stored secret under a new master.
    /// Atomic. Returns JSON-encoded `RotationResult`.
    #[cfg(feature = "secrets")]
    fn secrets_reencrypt_all(
        &self,
        py: Python<'_>,
        new_master_key_ref_json: &str,
        accessor: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let key_ref: crate::secrets::MasterKeyRef =
                serde_json::from_str(new_master_key_ref_json)
                    .map_err(|e| PyValueError::new_err(format!("MasterKeyRef decode: {e}")))?;
            let accessor = accessor.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let res = backend
                            .reencrypt_all(key_ref, accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&res).map_err(|e| {
                            PyRuntimeError::new_err(format!("RotationResult encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let res = backend
                            .reencrypt_all(key_ref, accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&res).map_err(|e| {
                            PyRuntimeError::new_err(format!("RotationResult encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v0.6.1 — Generate a fresh master key (or use supplied bytes).
    /// `new_master_b64` is `Some(base64(32-byte key))` or `None` to
    /// auto-generate. Returns JSON-encoded `MasterKeyRef`.
    #[cfg(feature = "secrets")]
    fn secrets_rotate_master_key(
        &self,
        py: Python<'_>,
        new_master_b64: Option<&str>,
        accessor: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let new_master: Option<Vec<u8>> = match new_master_b64 {
                None => None,
                Some(s) => {
                    use base64::engine::general_purpose::STANDARD as BASE64;
                    use base64::Engine as _;
                    Some(BASE64.decode(s).map_err(|e| {
                        PyValueError::new_err(format!("new_master base64 decode: {e}"))
                    })?)
                }
            };
            let accessor = accessor.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let r = backend
                            .rotate_master_key(new_master, accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&r).map_err(|e| {
                            PyRuntimeError::new_err(format!("MasterKeyRef encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let r = backend
                            .rotate_master_key(new_master, accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&r).map_err(|e| {
                            PyRuntimeError::new_err(format!("MasterKeyRef encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v0.6.1 — Encrypt-decrypt round-trip health check.
    #[cfg(feature = "secrets")]
    fn secrets_test_encryption(&self, py: Python<'_>) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        backend
                            .test_encryption()
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        backend
                            .test_encryption()
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.6.1 — Migrate master key to CIRISVerify hardware path.
    /// Returns SecretsError::HardwareKeyUnavailable in v0.6.1 (waits
    /// on ciris-keyring/symmetric-derivation upstream).
    #[cfg(feature = "secrets")]
    fn secrets_migrate_to_hardware_key(&self, py: Python<'_>, accessor: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let accessor = accessor.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let r = backend
                            .migrate_to_hardware_key(accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&r).map_err(|e| {
                            PyRuntimeError::new_err(format!("MasterKeyRef encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::secrets::sqlite::SqliteSecretsBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::secrets::SecretsService;
                        let r = backend
                            .migrate_to_hardware_key(accessor)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&r).map_err(|e| {
                            PyRuntimeError::new_err(format!("MasterKeyRef encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── v0.7.0-α5: NodeCoreService PyO3 surface (CIRISPersist#30) ─────
    //
    // 8 typed-writes + 6 reads wrapping NodeCoreService. Inputs come
    // across the FFI as JSON strings (typed envelope shapes from
    // CIRISNodeCore/SCHEMA.md); outputs encode the same way. Errors
    // route through cirisnode_err_to_py for stable kind() tokens.

    /// v0.7.0 — Verify-and-insert a Contribution envelope.
    #[cfg(feature = "cirisnode")]
    fn cirisnode_put_contribution(&self, py: Python<'_>, envelope_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let env: crate::cirisnode::ContributionEnvelope = serde_json::from_str(envelope_json)
                .map_err(|e| {
                PyValueError::new_err(format!("ContributionEnvelope decode: {e}"))
            })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .put_contribution(env)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .put_contribution(env)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.7.0 — Verify-and-insert a Vote envelope.
    #[cfg(feature = "cirisnode")]
    fn cirisnode_cast_vote(&self, py: Python<'_>, envelope_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let env: crate::cirisnode::VoteEnvelope = serde_json::from_str(envelope_json)
                .map_err(|e| PyValueError::new_err(format!("VoteEnvelope decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .cast_vote(env)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .cast_vote(env)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.7.0 — Upsert one row in credits_ledger.
    #[cfg(feature = "cirisnode")]
    fn cirisnode_update_credits_ledger(&self, py: Python<'_>, update_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let update: crate::cirisnode::CreditsUpdate = serde_json::from_str(update_json)
                .map_err(|e| PyValueError::new_err(format!("CreditsUpdate decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .update_credits_ledger(update)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .update_credits_ledger(update)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.7.0 — Upsert one row in expertise_ledger.
    #[cfg(feature = "cirisnode")]
    fn cirisnode_update_expertise_ledger(&self, py: Python<'_>, update_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let update: crate::cirisnode::ExpertiseUpdate = serde_json::from_str(update_json)
                .map_err(|e| PyValueError::new_err(format!("ExpertiseUpdate decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .update_expertise_ledger(update)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .update_expertise_ledger(update)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.7.0 — Verify-and-insert a ModerationEvent.
    #[cfg(feature = "cirisnode")]
    fn cirisnode_put_moderation_event(&self, py: Python<'_>, event_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let event: crate::cirisnode::ModerationEvent = serde_json::from_str(event_json)
                .map_err(|e| PyValueError::new_err(format!("ModerationEvent decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .put_moderation_event(event)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .put_moderation_event(event)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.7.0 — Verify-and-insert a SlashingAttestation.
    #[cfg(feature = "cirisnode")]
    fn cirisnode_put_slashing_attestation(&self, py: Python<'_>, att_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let att: crate::cirisnode::SlashingAttestation = serde_json::from_str(att_json)
                .map_err(|e| PyValueError::new_err(format!("SlashingAttestation decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .put_slashing_attestation(att)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .put_slashing_attestation(att)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.7.0 — Verify-and-insert a ReconsiderationRequest.
    #[cfg(feature = "cirisnode")]
    fn cirisnode_put_reconsideration_request(
        &self,
        py: Python<'_>,
        req_json: &str,
    ) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let req: crate::cirisnode::ReconsiderationRequest = serde_json::from_str(req_json)
                .map_err(|e| {
                    PyValueError::new_err(format!("ReconsiderationRequest decode: {e}"))
                })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .put_reconsideration_request(req)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .put_reconsideration_request(req)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.7.0 — Verify-and-insert a ReconsiderationAttestation.
    #[cfg(feature = "cirisnode")]
    fn cirisnode_put_reconsideration_attestation(
        &self,
        py: Python<'_>,
        att_json: &str,
    ) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let att: crate::cirisnode::ReconsiderationAttestation = serde_json::from_str(att_json)
                .map_err(|e| {
                    PyValueError::new_err(format!("ReconsiderationAttestation decode: {e}"))
                })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .put_reconsideration_attestation(att)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .put_reconsideration_attestation(att)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.7.2 (CIRISPersist#32) — Verify-and-insert a
    /// `PromotionAttestation` AND transactionally flip the named
    /// target rows' `is_canonical` to TRUE. Caller passes the
    /// envelope as JSON; on success, the named targets are
    /// canonical-tier and the attestation row is written to
    /// `cirisnode.promotion_attestations`.
    #[cfg(feature = "cirisnode")]
    fn cirisnode_put_promotion_attestation(&self, py: Python<'_>, att_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let att: crate::cirisnode::PromotionAttestation = serde_json::from_str(att_json)
                .map_err(|e| PyValueError::new_err(format!("PromotionAttestation decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .put_promotion_attestation(att)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .put_promotion_attestation(att)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.7.0 — List active routable contributors for `(domain,
    /// language)`. Returns JSON array of `RoutableContributor`.
    #[cfg(feature = "cirisnode")]
    fn cirisnode_routable_contributors(
        &self,
        py: Python<'_>,
        domain: &str,
        language: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let domain = domain.to_owned();
            let language = language.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        let rows = backend
                            .routable_contributors(&domain, &language)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("RoutableContributor encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        let rows = backend
                            .routable_contributors(&domain, &language)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("RoutableContributor encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v0.7.0 — Compute `Credits × expertise_multiplier ×
    /// active_tier_multiplier` for vote-weighting per SCHEMA.md §5.2.
    /// Returns JSON-encoded `VoteWeight` or `None`.
    #[cfg(feature = "cirisnode")]
    fn cirisnode_read_vote_weight(
        &self,
        py: Python<'_>,
        contributor_id: &str,
        domain: &str,
        language: &str,
        subject: &str,
    ) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let contributor_id = contributor_id.to_owned();
            let domain = domain.to_owned();
            let language = language.to_owned();
            let subject = subject.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        let opt = backend
                            .read_vote_weight(&contributor_id, &domain, &language, &subject)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match opt {
                            None => Ok(None),
                            Some(w) => Ok(Some(serde_json::to_string(&w).map_err(|e| {
                                PyRuntimeError::new_err(format!("VoteWeight encode: {e}"))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        let opt = backend
                            .read_vote_weight(&contributor_id, &domain, &language, &subject)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match opt {
                            None => Ok(None),
                            Some(w) => Ok(Some(serde_json::to_string(&w).map_err(|e| {
                                PyRuntimeError::new_err(format!("VoteWeight encode: {e}"))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    /// v0.7.0 — Page through `cirisnode.contributions`. Returns JSON
    /// `ContributionListPage` (items + optional next_cursor).
    #[cfg(feature = "cirisnode")]
    fn cirisnode_list_contributions(
        &self,
        py: Python<'_>,
        filter_json: &str,
        cursor_json: Option<&str>,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::cirisnode::ContributionsFilter = serde_json::from_str(filter_json)
                .map_err(|e| {
                PyValueError::new_err(format!("ContributionsFilter decode: {e}"))
            })?;
            let cursor: Option<crate::cirisnode::ListCursor> = match cursor_json {
                None => None,
                Some(s) => Some(
                    serde_json::from_str(s)
                        .map_err(|e| PyValueError::new_err(format!("ListCursor decode: {e}")))?,
                ),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        let page = backend
                            .list_contributions(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("ContributionListPage encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        let page = backend
                            .list_contributions(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("ContributionListPage encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v0.7.0 — Page through `cirisnode.votes`. Returns JSON
    /// `VoteListPage`.
    #[cfg(feature = "cirisnode")]
    fn cirisnode_list_votes(
        &self,
        py: Python<'_>,
        filter_json: &str,
        cursor_json: Option<&str>,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::cirisnode::VotesFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("VotesFilter decode: {e}")))?;
            let cursor: Option<crate::cirisnode::ListCursor> = match cursor_json {
                None => None,
                Some(s) => Some(
                    serde_json::from_str(s)
                        .map_err(|e| PyValueError::new_err(format!("ListCursor decode: {e}")))?,
                ),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        let page = backend
                            .list_votes(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("VoteListPage encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        let page = backend
                            .list_votes(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("VoteListPage encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v0.7.0 — Point-lookup one Credits ledger row.
    #[cfg(feature = "cirisnode")]
    fn cirisnode_get_credits_ledger(
        &self,
        py: Python<'_>,
        contributor_id: &str,
        domain: &str,
        language: &str,
        subject: &str,
    ) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let contributor_id = contributor_id.to_owned();
            let domain = domain.to_owned();
            let language = language.to_owned();
            let subject = subject.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        let opt = backend
                            .get_credits_ledger(&contributor_id, &domain, &language, &subject)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match opt {
                            None => Ok(None),
                            Some(r) => Ok(Some(serde_json::to_string(&r).map_err(|e| {
                                PyRuntimeError::new_err(format!("CreditsLedgerEntry encode: {e}"))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        let opt = backend
                            .get_credits_ledger(&contributor_id, &domain, &language, &subject)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match opt {
                            None => Ok(None),
                            Some(r) => Ok(Some(serde_json::to_string(&r).map_err(|e| {
                                PyRuntimeError::new_err(format!("CreditsLedgerEntry encode: {e}"))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    /// v0.7.0 — Point-lookup one Expertise ledger row.
    #[cfg(feature = "cirisnode")]
    fn cirisnode_get_expertise_ledger(
        &self,
        py: Python<'_>,
        contributor_id: &str,
        domain: &str,
        language: &str,
    ) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let contributor_id = contributor_id.to_owned();
            let domain = domain.to_owned();
            let language = language.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        let opt = backend
                            .get_expertise_ledger(&contributor_id, &domain, &language)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match opt {
                            None => Ok(None),
                            Some(r) => Ok(Some(serde_json::to_string(&r).map_err(|e| {
                                PyRuntimeError::new_err(format!("ExpertiseLedgerEntry encode: {e}"))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        let opt = backend
                            .get_expertise_ledger(&contributor_id, &domain, &language)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match opt {
                            None => Ok(None),
                            Some(r) => Ok(Some(serde_json::to_string(&r).map_err(|e| {
                                PyRuntimeError::new_err(format!("ExpertiseLedgerEntry encode: {e}"))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    // ── v2.1 (CIRISPersist#101) — Federation Delivery Attestation
    //    PyO3 surface. Three methods mirroring the NodeCoreService
    //    additions for the FSD §3.2.1 ratified wire shape.
    //    JSON-in / JSON-out, dispatching across Postgres + SQLite
    //    via the same translate_error_kind taxonomy the other
    //    cirisnode methods use.

    /// v2.1 (CIRISPersist#101) — Verify-and-insert a
    /// [`DeliveryAttestation`](crate::cirisnode::DeliveryAttestation).
    /// Idempotent on `(announcement_id, peer_key_id)`. Hybrid
    /// signature verified against `federation_keys[peer_key_id]`
    /// before INSERT.
    #[cfg(feature = "cirisnode")]
    fn cirisnode_put_delivery_attestation(
        &self,
        py: Python<'_>,
        attestation_json: &str,
    ) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let att: crate::cirisnode::DeliveryAttestation = serde_json::from_str(attestation_json)
                .map_err(|e| PyValueError::new_err(format!("DeliveryAttestation decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .put_delivery_attestation(att)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .put_delivery_attestation(att)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v2.1 (CIRISPersist#101) — List all delivery attestations for
    /// a federation_announcement, newest-first. Returns a JSON array
    /// of [`DeliveryAttestation`](crate::cirisnode::DeliveryAttestation).
    #[cfg(feature = "cirisnode")]
    fn cirisnode_list_delivery_attestations(
        &self,
        py: Python<'_>,
        announcement_id: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let announcement_id = announcement_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        let rows = backend
                            .list_delivery_attestations(&announcement_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("DeliveryAttestation list encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        let rows = backend
                            .list_delivery_attestations(&announcement_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("DeliveryAttestation list encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v2.1 (CIRISPersist#101) — Count delivery attestations for a
    /// federation_announcement.
    #[cfg(feature = "cirisnode")]
    fn cirisnode_count_delivery_attestations(
        &self,
        py: Python<'_>,
        announcement_id: &str,
    ) -> PyResult<u64> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let announcement_id = announcement_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .count_delivery_attestations(&announcement_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::cirisnode::NodeCoreService;
                        backend
                            .count_delivery_attestations(&announcement_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    // ── v0.8.0-α5: cirisgraph PyO3 surface (CIRISPersist#34) ──────────
    //
    // 7 methods wrapping GraphService. JSON-in / JSON-out across the
    // FFI boundary; catch_panic discipline; cirisgraph::Error → PyErr
    // via cirisgraph_err_to_py with stable kind() tokens.

    /// v0.8.0 — Upsert a graph node with AV-48 optimistic-concurrency
    /// gate. Pass `expected_version = 0` for new rows; current
    /// version for updates.
    ///
    /// v1.3.2 (CIRISPersist#50): `bulk_import` (default False) skips
    /// the AV-45 attributes-size cap for one-time historical
    /// migration. Use sparingly — the cap is a hot-path safety check
    /// for steady-state writes.
    #[cfg(feature = "cirisgraph")]
    #[pyo3(signature = (node_json, expected_version, bulk_import = false))]
    fn cirisgraph_upsert_node(
        &self,
        py: Python<'_>,
        node_json: &str,
        expected_version: i32,
        bulk_import: bool,
    ) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let node: crate::graph::GraphNode = serde_json::from_str(node_json)
                .map_err(|e| PyValueError::new_err(format!("GraphNode decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        backend
                            .upsert_node(node, expected_version, bulk_import)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::graph::sqlite::SqliteGraphBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        backend
                            .upsert_node(node, expected_version, bulk_import)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.8.0 — Insert a directed edge. Idempotent on edge_id.
    ///
    /// v1.3.2 (CIRISPersist#50): `bulk_import` is reserved for
    /// symmetry with `cirisgraph_upsert_node`; edges have no
    /// attributes-size cap today so the flag is a no-op currently.
    #[cfg(feature = "cirisgraph")]
    #[pyo3(signature = (edge_json, bulk_import = false))]
    fn cirisgraph_upsert_edge(
        &self,
        py: Python<'_>,
        edge_json: &str,
        bulk_import: bool,
    ) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let edge: crate::graph::GraphEdge = serde_json::from_str(edge_json)
                .map_err(|e| PyValueError::new_err(format!("GraphEdge decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        backend
                            .upsert_edge(edge, bulk_import)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::graph::sqlite::SqliteGraphBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        backend
                            .upsert_edge(edge, bulk_import)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.8.0 — Soft- or hard-delete a node. Hard delete cascades
    /// edges. Returns `true` if a row was affected.
    #[cfg(feature = "cirisgraph")]
    fn cirisgraph_delete_node(
        &self,
        py: Python<'_>,
        node_id: &str,
        scope: &str,
        hard: bool,
    ) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let node_id = node_id.to_owned();
            let scope = crate::graph::GraphScope::from_sql_str(scope)
                .ok_or_else(|| PyValueError::new_err(format!("unknown GraphScope: {scope}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        backend
                            .delete_node(&node_id, scope, hard)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::graph::sqlite::SqliteGraphBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        backend
                            .delete_node(&node_id, scope, hard)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.8.0 — Point-lookup one node. Returns JSON `GraphNode` or
    /// `None`.
    #[cfg(feature = "cirisgraph")]
    fn cirisgraph_get_node(
        &self,
        py: Python<'_>,
        node_id: &str,
        scope: &str,
    ) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let node_id = node_id.to_owned();
            let scope = crate::graph::GraphScope::from_sql_str(scope)
                .ok_or_else(|| PyValueError::new_err(format!("unknown GraphScope: {scope}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        let opt = backend
                            .get_node(&node_id, scope)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match opt {
                            None => Ok(None),
                            Some(n) => Ok(Some(serde_json::to_string(&n).map_err(|e| {
                                PyRuntimeError::new_err(format!("GraphNode encode: {e}"))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::graph::sqlite::SqliteGraphBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        let opt = backend
                            .get_node(&node_id, scope)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match opt {
                            None => Ok(None),
                            Some(n) => Ok(Some(serde_json::to_string(&n).map_err(|e| {
                                PyRuntimeError::new_err(format!("GraphNode encode: {e}"))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    /// v0.8.0 — Incident edges from a node. Returns JSON array of
    /// `GraphEdge`. `direction` is `"outgoing"` | `"incoming"` |
    /// `"both"`; `relationship_filter` is None for "all" or a
    /// JSON-encoded `[String]` array.
    #[cfg(feature = "cirisgraph")]
    fn cirisgraph_get_edges_for_node(
        &self,
        py: Python<'_>,
        node_id: &str,
        scope: &str,
        direction: &str,
        relationship_filter_json: Option<&str>,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let node_id = node_id.to_owned();
            let scope = crate::graph::GraphScope::from_sql_str(scope)
                .ok_or_else(|| PyValueError::new_err(format!("unknown GraphScope: {scope}")))?;
            let direction: crate::graph::EdgeDirection =
                serde_json::from_str(&format!("\"{direction}\""))
                    .map_err(|e| PyValueError::new_err(format!("EdgeDirection decode: {e}")))?;
            let rel_filter: Option<Vec<String>> = match relationship_filter_json {
                None => None,
                Some(s) => Some(serde_json::from_str(s).map_err(|e| {
                    PyValueError::new_err(format!("relationship_filter decode: {e}"))
                })?),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        let edges = backend
                            .get_edges_for_node(&node_id, scope, direction, rel_filter.as_deref())
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&edges).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<GraphEdge> encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::graph::sqlite::SqliteGraphBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        let edges = backend
                            .get_edges_for_node(&node_id, scope, direction, rel_filter.as_deref())
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&edges).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<GraphEdge> encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v0.8.0 — AV-46 bounded k-hop traversal. Returns JSON array of
    /// `KhopEntry`.
    #[cfg(feature = "cirisgraph")]
    fn cirisgraph_traverse_k_hop(
        &self,
        py: Python<'_>,
        start_node_id: &str,
        scope: &str,
        config_json: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let start_node_id = start_node_id.to_owned();
            let scope = crate::graph::GraphScope::from_sql_str(scope)
                .ok_or_else(|| PyValueError::new_err(format!("unknown GraphScope: {scope}")))?;
            let cfg: crate::graph::TraversalConfig = serde_json::from_str(config_json)
                .map_err(|e| PyValueError::new_err(format!("TraversalConfig decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        let entries = backend
                            .traverse_k_hop(&start_node_id, scope, cfg)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&entries).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<KhopEntry> encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::graph::sqlite::SqliteGraphBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        let entries = backend
                            .traverse_k_hop(&start_node_id, scope, cfg)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&entries).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<KhopEntry> encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v0.8.0 — Cursor-paged node listing. Returns JSON
    /// `NodeListPage`. AV-47: filter MUST name a scope.
    #[cfg(feature = "cirisgraph")]
    fn cirisgraph_query_nodes(
        &self,
        py: Python<'_>,
        filter_json: &str,
        cursor_json: Option<&str>,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::graph::NodeFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("NodeFilter decode: {e}")))?;
            let cursor: Option<crate::graph::ListCursor> = match cursor_json {
                None => None,
                Some(s) => Some(
                    serde_json::from_str(s)
                        .map_err(|e| PyValueError::new_err(format!("ListCursor decode: {e}")))?,
                ),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        let page = backend
                            .query_nodes(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("NodeListPage encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::graph::sqlite::SqliteGraphBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        let page = backend
                            .query_nodes(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("NodeListPage encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.25 (CIRISPersist#65) — Count nodes matching `filter`.
    /// Returns the raw integer (not a JSON envelope).
    /// AV-47: filter MUST name a scope.
    #[cfg(feature = "cirisgraph")]
    fn cirisgraph_count_nodes(&self, py: Python<'_>, filter_json: &str) -> PyResult<u64> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::graph::NodeFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("NodeFilter decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        backend
                            .count_nodes(filter)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::graph::sqlite::SqliteGraphBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        backend
                            .count_nodes(filter)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.5.25 (CIRISPersist#65) — Count edges within `scope`.
    /// Returns the raw integer.
    #[cfg(feature = "cirisgraph")]
    fn cirisgraph_count_edges(&self, py: Python<'_>, scope: &str) -> PyResult<u64> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let scope_parsed = crate::graph::GraphScope::from_sql_str(scope)
                .ok_or_else(|| PyValueError::new_err(format!("unknown scope: {scope}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        backend
                            .count_edges(scope_parsed)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::graph::sqlite::SqliteGraphBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        backend
                            .count_edges(scope_parsed)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.5.25 (CIRISPersist#65) — Group-by-type histogram of nodes
    /// in `scope`. Returns the JSON-encoded `dict[str, int]`
    /// `{node_type: count}`.
    #[cfg(feature = "cirisgraph")]
    fn cirisgraph_count_nodes_by_type(&self, py: Python<'_>, scope: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let scope_parsed = crate::graph::GraphScope::from_sql_str(scope)
                .ok_or_else(|| PyValueError::new_err(format!("unknown scope: {scope}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        let map = backend
                            .count_nodes_by_type(scope_parsed)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&map).map_err(|e| {
                            PyRuntimeError::new_err(format!("count_nodes_by_type encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::graph::sqlite::SqliteGraphBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::graph::GraphService;
                        let map = backend
                            .count_nodes_by_type(scope_parsed)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&map).map_err(|e| {
                            PyRuntimeError::new_err(format!("count_nodes_by_type encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── v0.8.1: audit-log PyO3 surface (CIRISPersist#35) ─────────────
    //
    // 3 methods wrapping AuditService. JSON-in / JSON-out across the
    // FFI boundary; catch_panic discipline; audit::Error → PyErr via
    // audit_err_to_py with stable kind() tokens.

    /// v1.5.4 — Return the exact canonical bytes whose SHA-256 equals
    /// the audit entry's `entry_hash`. Caller-side workflow:
    ///
    /// 1. Build the AuditEntry JSON with `entry_hash = ""` and
    ///    `signature = ""`.
    /// 2. `ch = engine.audit_canonicalize_for_hash(json.dumps(entry))`
    /// 3. `entry["entry_hash"] = base64(sha256(ch).digest())`
    ///
    /// Rule (mirrors `crate::audit::verify::compute_entry_hash`): both
    /// the top-level `entry_hash` AND `signature` fields are stripped
    /// before canonicalization via `PythonJsonDumpsCanonicalizer`
    /// (sorted keys, no whitespace, ensure_ascii=True). The hash is
    /// over canonical bytes that don't include itself.
    ///
    /// Use this rather than reimplementing the rule in caller-language
    /// — persist owns the canonicalizer; any future tightening lands
    /// here without forcing a coordinated downstream change.
    ///
    /// Companion of [`audit_canonicalize_for_signing`].
    #[cfg(feature = "cirisaudit")]
    fn audit_canonicalize_for_hash<'py>(
        &self,
        py: Python<'py>,
        entry_json: &str,
    ) -> PyResult<Py<PyBytes>> {
        self.ensure_usable()?;
        catch_panic(|| {
            // Parse the caller's JSON through the AuditEntry struct so the
            // canonical bytes match what crate::audit::verify::compute_entry_hash
            // produces internally byte-for-byte. Going through the struct
            // normalizes chrono datetime + Vec<u8> serialization; raw-JSON
            // canonicalization would diverge on those fields and produce a
            // hash that persist's verify path rejects.
            let mut entry: crate::audit::AuditEntry = serde_json::from_str(entry_json)
                .map_err(|e| PyValueError::new_err(format!("AuditEntry JSON decode: {e}")))?;
            entry.entry_hash = Vec::new();
            entry.signature = String::new();
            let bytes = crate::audit::verify::canonical_bytes_for_entry(&entry)
                .map_err(|e| PyRuntimeError::new_err(format!("canonicalize: {e}")))?;
            Ok(PyBytes::new(py, &bytes).unbind())
        })
    }

    /// v1.5.4 — Return the exact canonical bytes the audit-entry
    /// `signature` covers. Caller-side workflow:
    ///
    /// 1. Build AuditEntry with `entry_hash` already filled (per
    ///    [`audit_canonicalize_for_hash`]) and `signature = ""`.
    /// 2. `cs = engine.audit_canonicalize_for_signing(json.dumps(entry))`
    /// 3. `sig_bytes = ciris_verify.sign_ed25519(cs)`  # or engine.local_sign(cs)
    /// 4. `entry["signature"] = base64(sig_bytes)`
    /// 5. `engine.audit_record_entry(json.dumps(entry))`
    ///
    /// Rule: only the top-level `signature` field is stripped before
    /// canonicalization. `entry_hash` participates in the signed body
    /// — that binds the signature to the chain position so a chain-
    /// rewrite that flipped `prev_hash` of subsequent entries would
    /// invalidate this entry's signature too. Same persist-wide
    /// canonicalizer rule as [`canonicalize_envelope_for_signing`],
    /// applied to audit-entry JSON.
    ///
    /// Companion of [`audit_canonicalize_for_hash`].
    #[cfg(feature = "cirisaudit")]
    fn audit_canonicalize_for_signing<'py>(
        &self,
        py: Python<'py>,
        entry_json: &str,
    ) -> PyResult<Py<PyBytes>> {
        self.ensure_usable()?;
        catch_panic(|| {
            // Same parse-through-struct discipline as audit_canonicalize_for_hash
            // — guarantees byte-equal canonical bytes with what persist's
            // signature verify path computes internally. entry_hash stays in
            // the canonical body; signature is zeroed before
            // canonical_bytes_for_entry's strip-then-canonicalize.
            let mut entry: crate::audit::AuditEntry = serde_json::from_str(entry_json)
                .map_err(|e| PyValueError::new_err(format!("AuditEntry JSON decode: {e}")))?;
            entry.signature = String::new();
            let bytes = crate::audit::verify::canonical_bytes_for_entry(&entry)
                .map_err(|e| PyRuntimeError::new_err(format!("canonicalize: {e}")))?;
            Ok(PyBytes::new(py, &bytes).unbind())
        })
    }

    /// v0.8.1 — Verify-and-insert one audit entry. Persist enforces
    /// hash-chain integrity (AV-49) + sequence monotonicity + signature.
    #[cfg(feature = "cirisaudit")]
    fn audit_record_entry(&self, py: Python<'_>, entry_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let entry: crate::audit::AuditEntry = serde_json::from_str(entry_json)
                .map_err(|e| PyValueError::new_err(format!("AuditEntry decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::audit::AuditService;
                        backend
                            .record_entry(entry)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::audit::sqlite::SqliteAuditBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::audit::AuditService;
                        backend
                            .record_entry(entry)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.8.1 — List audit entries scoped to one tenant. Returns
    /// JSON `AuditListPage`. AV-51: filter MUST name a tenant.
    #[cfg(feature = "cirisaudit")]
    fn audit_list_entries(
        &self,
        py: Python<'_>,
        filter_json: &str,
        cursor_json: Option<&str>,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::audit::AuditFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("AuditFilter decode: {e}")))?;
            let cursor: Option<crate::audit::types::AuditCursor> = match cursor_json {
                None => None,
                Some(s) => Some(
                    serde_json::from_str(s)
                        .map_err(|e| PyValueError::new_err(format!("AuditCursor decode: {e}")))?,
                ),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::audit::AuditService;
                        let page = backend
                            .list_entries(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("AuditListPage encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::audit::sqlite::SqliteAuditBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::audit::AuditService;
                        let page = backend
                            .list_entries(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("AuditListPage encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v0.8.1 — AV-50 chain-walk verify. Returns JSON
    /// `ChainVerification` with typed break diagnostic on first
    /// observed integrity violation.
    #[cfg(feature = "cirisaudit")]
    fn audit_verify_chain(
        &self,
        py: Python<'_>,
        tenant_id: &str,
        from_sequence: i64,
        to_sequence: Option<i64>,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let tenant_id = tenant_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::audit::AuditService;
                        let verif = backend
                            .verify_chain(&tenant_id, from_sequence, to_sequence)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&verif).map_err(|e| {
                            PyRuntimeError::new_err(format!("ChainVerification encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::audit::sqlite::SqliteAuditBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::audit::AuditService;
                        let verif = backend
                            .verify_chain(&tenant_id, from_sequence, to_sequence)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&verif).map_err(|e| {
                            PyRuntimeError::new_err(format!("ChainVerification encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v2.0.5 — verify ALL tenants' audit chains in one call.
    /// Independent of any external registry — persist validates its
    /// own chain integrity. Returns JSON summary:
    /// `{"tenants_checked": N, "total_entries_walked": N,
    ///   "all_ok": bool, "breaks": [...]}`
    #[cfg(feature = "cirisaudit")]
    fn audit_verify_all_chains(&self, py: Python<'_>) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let backend = self.backend.clone();
            py.detach(move || {
                runtime.block_on(async move {
                    let summary = boot_audit_self_verify(&backend)
                        .await
                        .map_err(|e| PyRuntimeError::new_err(format!("audit self-verify: {e}")))?;
                    let breaks_json: Vec<serde_json::Value> = summary
                        .breaks
                        .iter()
                        .map(|b| {
                            serde_json::json!({
                                "tenant_id": b.tenant_id,
                                "at_sequence": b.at_sequence,
                                "reason": b.reason,
                            })
                        })
                        .collect();
                    let result = serde_json::json!({
                        "tenants_checked": summary.tenants_checked,
                        "total_entries_walked": summary.total_entries_walked,
                        "all_ok": summary.all_ok,
                        "breaks": breaks_json,
                    });
                    serde_json::to_string(&result)
                        .map_err(|e| PyRuntimeError::new_err(format!("audit summary encode: {e}")))
                })
            })
        })
    }

    // ── v2.7.0 (CIRISPersist#104) — Epistemic Commons aggregate queries ─
    //
    // Three JSON in / JSON out aggregate queries that feed the
    // CIRISAgent 2.10.0 Epistemic Commons Framework UI
    // (CIRISAgent#800 / Figma CIRISAgent#799):
    //
    //   1. federation_directory_query → Trust Topology
    //   2. delegates_to_graph         → Delegation screen
    //   3. audit_chain_proof          → Commons audit-lineage
    //
    // The aggregation logic lives in `crate::federation::topology`
    // (the trust-topology + delegation-graph types) and
    // `crate::audit` (the audit-chain walk). These wrappers route
    // through `BackendDispatch` exactly like the per-backend
    // federation / audit methods elsewhere in this file.
    //
    // Method shape mirrors `cirisnode_list_contributions_json` — JSON
    // string in, JSON string out — the UI consumes JSON anyway, and
    // the aggregate shapes have no sensible per-method Python class.
    // The Rust types live in `crate::federation::topology` so a
    // co-resident Rust extension (CIRISEdge) gets typed access too.

    /// v2.7.0 (CIRISPersist#104) — Trust-Topology aggregate query.
    /// Walks `federation_attestations` to produce a [`TrustTopology`]
    /// with nodes (resolved through
    /// [`crate::federation::FederationDirectory::lookup_public_key`])
    /// and edges classified `direct` / `delegated` / `adversarial`.
    ///
    /// `filter_json` decodes to
    /// [`crate::federation::FederationDirectoryFilter`]. At least one
    /// of `granter_key` / `grantee_key` must be set — see the filter's
    /// doc-comment for the trait-surface rationale.
    ///
    /// [`TrustTopology`]: crate::federation::TrustTopology
    fn federation_directory_query(&self, py: Python<'_>, filter_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::federation::FederationDirectoryFilter =
                serde_json::from_str(filter_json).map_err(|e| {
                    PyValueError::new_err(format!("FederationDirectoryFilter decode: {e}"))
                })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        let topo = crate::federation::build_trust_topology(&*backend, &filter)
                            .await
                            .map_err(federation_err_to_py)?;
                        serde_json::to_string(&topo).map_err(|e| {
                            PyRuntimeError::new_err(format!("TrustTopology encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        let topo = crate::federation::build_trust_topology(&*backend, &filter)
                            .await
                            .map_err(federation_err_to_py)?;
                        serde_json::to_string(&topo).map_err(|e| {
                            PyRuntimeError::new_err(format!("TrustTopology encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v2.7.0 (CIRISPersist#104) — Delegation-graph BFS from
    /// `from_key`. Returns a JSON
    /// [`crate::federation::DelegationGraph`] with one
    /// [`crate::federation::DelegationEdge`] per `delegates_to:*`
    /// row reachable within `max_depth` (clamped to
    /// [`crate::federation::MAX_DELEGATION_DEPTH`]).
    ///
    /// `withdraws` / `recants` rows are surfaced as a per-edge
    /// [`crate::federation::WithdrawalEntry`] annotation, not
    /// filtered out — UI policy decides whether to render the edge.
    fn delegates_to_graph(
        &self,
        py: Python<'_>,
        from_key: &str,
        max_depth: usize,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let from_key = from_key.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        let graph = crate::federation::build_delegation_graph(
                            &*backend, &from_key, max_depth,
                        )
                        .await
                        .map_err(federation_err_to_py)?;
                        serde_json::to_string(&graph).map_err(|e| {
                            PyRuntimeError::new_err(format!("DelegationGraph encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = sq.clone();
                    runtime.block_on(async move {
                        let graph = crate::federation::build_delegation_graph(
                            &*backend, &from_key, max_depth,
                        )
                        .await
                        .map_err(federation_err_to_py)?;
                        serde_json::to_string(&graph).map_err(|e| {
                            PyRuntimeError::new_err(format!("DelegationGraph encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v2.7.0 (CIRISPersist#104) — Audit-lineage walk for a
    /// `trace_id`. Locates the `cirislens_audit_log` row whose
    /// `subject_id == trace_id`, then walks back to genesis on the
    /// matching tenant's chain and returns a JSON
    /// [`crate::federation::AuditChainProof`].
    ///
    /// `head_signature` carries the JSON-serialized current
    /// [`ciris_verify_core::transparency::SignedTreeHead`] for the
    /// tenant when the Merkle hook is installed; `None` otherwise.
    /// Empty `entries` (`[]`) when no audit row references the given
    /// trace.
    #[cfg(feature = "cirisaudit")]
    fn audit_chain_proof(&self, py: Python<'_>, trace_id: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let backend = self.backend.clone();
            let trace_id = trace_id.to_owned();
            py.detach(move || {
                runtime.block_on(async move {
                    let proof = build_audit_chain_proof(&backend, &trace_id)
                        .await
                        .map_err(|e| PyRuntimeError::new_err(format!("audit_chain_proof: {e}")))?;
                    serde_json::to_string(&proof).map_err(|e| {
                        PyRuntimeError::new_err(format!("AuditChainProof encode: {e}"))
                    })
                })
            })
        })
    }

    // ── v1.5.0 Phase H: trust-grant + Merkle transparency PyO3 surface ──
    //
    // 8 methods wrapping `federation::emit` (grant_trust /
    // revoke_trust_grant) and `federation::read` (lookup_trust_grant /
    // list_trust_grants / get_trust_grant / current_sth /
    // trust_grant_inclusion_proof / trust_grant_consistency_proof).
    //
    // Return shapes are JSON strings (matching the v1.3.0
    // `federation_*` and v0.8.1 `audit_*` patterns). The Python
    // consumer parses the JSON themselves — no new pyclass wrappers
    // for Phase H. New Python classes are reserved for the Phase J
    // release cut if a typed surface is needed.
    //
    // Engine.local_signer → backend.merkle_signer is wired in
    // `Engine::new` so these methods Just Work without per-call
    // configuration.

    /// v1.5.0 Phase H — Emit a signed `TrustGrant` audit-chain entry
    /// (FSD §4.1). Returns a JSON-serialized
    /// [`crate::federation::trust_grant::TrustGrantReceipt`] string
    /// with `{ grant_id, chain_event_id, chain_event_hash, tenant_id,
    /// tree_size_at_emit, sth }`.
    ///
    /// Requires `local_key_id` / `local_key_path` were configured on
    /// the Engine (the trust grant is signed against the local
    /// identity). Raises `ValueError` if no signer is configured,
    /// `ValueError` for malformed `purpose` / `expires_at` /
    /// self-grant, or `RuntimeError` for backend / signer issues.
    #[cfg(feature = "cirisaudit")]
    #[allow(clippy::too_many_arguments)]
    fn grant_trust(
        &self,
        py: Python<'_>,
        tenant_id: &str,
        grantee_key: &str,
        purpose: &str,
        scope: &str,
        expires_at: Option<&str>,
        rationale: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let tenant_id = tenant_id.to_owned();
            let grantee_key = grantee_key.to_owned();
            let scope = scope.to_owned();
            let rationale = rationale.to_owned();
            let purpose = crate::federation::trust_grant::TrustPurpose::parse_str(purpose)
                .ok_or_else(|| {
                    PyValueError::new_err(
                        "unknown TrustPurpose (expected technical|deferral|contribution|service)",
                    )
                })?;
            let expires_dt: Option<chrono::DateTime<chrono::Utc>> = match expires_at {
                None => None,
                Some(s) => Some(s.parse().map_err(|e| {
                    PyValueError::new_err(format!("expires_at must be ISO-8601 (got {s:?}): {e}"))
                })?),
            };
            let signer = self.local_signer.clone().ok_or_else(|| {
                PyValueError::new_err(
                    "no local signing key configured (pass local_key_id + local_key_path \
                     to the Engine constructor)",
                )
            })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        let receipt = crate::federation::emit::grant_trust(
                            &*backend,
                            &signer,
                            &tenant_id,
                            &grantee_key,
                            purpose,
                            &scope,
                            expires_dt,
                            &rationale,
                        )
                        .await
                        .map_err(emit_err_to_py)?;
                        serde_json::to_string(&receipt).map_err(|e| {
                            PyRuntimeError::new_err(format!("TrustGrantReceipt encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(_) => {
                    let audit = self
                        .sqlite_audit
                        .as_ref()
                        .expect("v1.5.0 Phase H: sqlite_audit must be Some when backend is Sqlite")
                        .clone();
                    runtime.block_on(async move {
                        let receipt = crate::federation::emit::grant_trust(
                            &*audit,
                            &signer,
                            &tenant_id,
                            &grantee_key,
                            purpose,
                            &scope,
                            expires_dt,
                            &rationale,
                        )
                        .await
                        .map_err(emit_err_to_py)?;
                        serde_json::to_string(&receipt).map_err(|e| {
                            PyRuntimeError::new_err(format!("TrustGrantReceipt encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.0 Phase H — Revoke a trust grant per FSD §3.4 (re-issuance
    /// with `expires_at = now()`, rationale = `"revocation"`). Returns
    /// a JSON-serialized [`crate::federation::trust_grant::TrustGrantReceipt`]
    /// for the revocation event.
    #[cfg(feature = "cirisaudit")]
    fn revoke_trust_grant(
        &self,
        py: Python<'_>,
        tenant_id: &str,
        grantee_key: &str,
        purpose: &str,
        scope: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let tenant_id = tenant_id.to_owned();
            let grantee_key = grantee_key.to_owned();
            let scope = scope.to_owned();
            let purpose = crate::federation::trust_grant::TrustPurpose::parse_str(purpose)
                .ok_or_else(|| {
                    PyValueError::new_err(
                        "unknown TrustPurpose (expected technical|deferral|contribution|service)",
                    )
                })?;
            let signer = self.local_signer.clone().ok_or_else(|| {
                PyValueError::new_err(
                    "no local signing key configured (pass local_key_id + local_key_path \
                     to the Engine constructor)",
                )
            })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        let receipt = crate::federation::emit::revoke_trust_grant(
                            &*backend,
                            &signer,
                            &tenant_id,
                            &grantee_key,
                            purpose,
                            &scope,
                        )
                        .await
                        .map_err(emit_err_to_py)?;
                        serde_json::to_string(&receipt).map_err(|e| {
                            PyRuntimeError::new_err(format!("TrustGrantReceipt encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(_) => {
                    let audit = self
                        .sqlite_audit
                        .as_ref()
                        .expect("v1.5.0 Phase H: sqlite_audit must be Some when backend is Sqlite")
                        .clone();
                    runtime.block_on(async move {
                        let receipt = crate::federation::emit::revoke_trust_grant(
                            &*audit,
                            &signer,
                            &tenant_id,
                            &grantee_key,
                            purpose,
                            &scope,
                        )
                        .await
                        .map_err(emit_err_to_py)?;
                        serde_json::to_string(&receipt).map_err(|e| {
                            PyRuntimeError::new_err(format!("TrustGrantReceipt encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.0 Phase H — Look up live (non-revoked, non-expired) trust
    /// grants for `(grantee_key, purpose, scope)`. Returns a JSON-array
    /// string of [`crate::federation::trust_grant::TrustGrantRow`]
    /// objects. Wildcard (`scope = '*'`) grants surface alongside
    /// exact matches per FSD §3.3.
    #[cfg(feature = "cirisaudit")]
    fn lookup_trust_grant(
        &self,
        py: Python<'_>,
        grantee_key: &str,
        purpose: &str,
        scope: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let grantee_key = grantee_key.to_owned();
            let scope = scope.to_owned();
            let purpose = crate::federation::trust_grant::TrustPurpose::parse_str(purpose)
                .ok_or_else(|| {
                    PyValueError::new_err(
                        "unknown TrustPurpose (expected technical|deferral|contribution|service)",
                    )
                })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        let rows = crate::federation::read::lookup_trust_grant(
                            &*backend,
                            &grantee_key,
                            purpose,
                            &scope,
                        )
                        .await
                        .map_err(federation_read_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<TrustGrantRow> encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(_) => {
                    let audit = self
                        .sqlite_audit
                        .as_ref()
                        .expect("v1.5.0 Phase H: sqlite_audit must be Some when backend is Sqlite")
                        .clone();
                    runtime.block_on(async move {
                        let rows = crate::federation::read::lookup_trust_grant(
                            &*audit,
                            &grantee_key,
                            purpose,
                            &scope,
                        )
                        .await
                        .map_err(federation_read_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<TrustGrantRow> encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.0 Phase H — Filter query over `federation_trust_grants`.
    /// `filter_json` deserializes into
    /// [`crate::federation::trust_grant::TrustGrantFilter`]; all
    /// non-`None` fields AND-intersect. Returns a JSON-array string of
    /// [`crate::federation::trust_grant::TrustGrantRow`] objects.
    #[cfg(feature = "cirisaudit")]
    fn list_trust_grants(&self, py: Python<'_>, filter_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::federation::trust_grant::TrustGrantFilter =
                serde_json::from_str(filter_json).map_err(|e| {
                    PyValueError::new_err(format!("TrustGrantFilter JSON decode: {e}"))
                })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        let rows = crate::federation::read::list_trust_grants(&*backend, filter)
                            .await
                            .map_err(federation_read_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<TrustGrantRow> encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(_) => {
                    let audit = self
                        .sqlite_audit
                        .as_ref()
                        .expect("v1.5.0 Phase H: sqlite_audit must be Some when backend is Sqlite")
                        .clone();
                    runtime.block_on(async move {
                        let rows = crate::federation::read::list_trust_grants(&*audit, filter)
                            .await
                            .map_err(federation_read_err_to_py)?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<TrustGrantRow> encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.0 Phase H — Point lookup by canonical
    /// `federation_trust_grants.grant_id`. Returns a JSON-serialized
    /// [`crate::federation::trust_grant::TrustGrantRow`] or `None`
    /// when no projection row exists for the grant id.
    #[cfg(feature = "cirisaudit")]
    fn get_trust_grant(&self, py: Python<'_>, grant_id: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let grant_uuid: uuid::Uuid = grant_id
                .parse()
                .map_err(|e| PyValueError::new_err(format!("grant_id must be UUID: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        let row = crate::federation::read::get_trust_grant(&*backend, grant_uuid)
                            .await
                            .map_err(federation_read_err_to_py)?;
                        match row {
                            None => Ok(None),
                            Some(r) => Ok(Some(serde_json::to_string(&r).map_err(|e| {
                                PyRuntimeError::new_err(format!("TrustGrantRow encode: {e}"))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(_) => {
                    let audit = self
                        .sqlite_audit
                        .as_ref()
                        .expect("v1.5.0 Phase H: sqlite_audit must be Some when backend is Sqlite")
                        .clone();
                    runtime.block_on(async move {
                        let row = crate::federation::read::get_trust_grant(&*audit, grant_uuid)
                            .await
                            .map_err(federation_read_err_to_py)?;
                        match row {
                            None => Ok(None),
                            Some(r) => Ok(Some(serde_json::to_string(&r).map_err(|e| {
                                PyRuntimeError::new_err(format!("TrustGrantRow encode: {e}"))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    /// v1.5.0 Phase H — Fetch the current
    /// [`ciris_verify_core::transparency::SignedTreeHead`] for the
    /// per-tenant Merkle log. Returns a JSON-serialized `SignedTreeHead`
    /// or `None` if no STH has been published for `tenant_id` yet
    /// (the audit chain may be empty or the Merkle hook may be
    /// disabled).
    #[cfg(feature = "cirisaudit")]
    fn current_sth(&self, py: Python<'_>, tenant_id: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let tenant_id = tenant_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::audit::AuditService;
                        let sth = backend
                            .current_sth(&tenant_id)
                            .await
                            .map_err(audit_err_to_py)?;
                        match sth {
                            None => Ok(None),
                            Some(s) => Ok(Some(serde_json::to_string(&s).map_err(|e| {
                                PyRuntimeError::new_err(format!("SignedTreeHead encode: {e}"))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(_) => {
                    let audit = self
                        .sqlite_audit
                        .as_ref()
                        .expect("v1.5.0 Phase H: sqlite_audit must be Some when backend is Sqlite")
                        .clone();
                    runtime.block_on(async move {
                        use crate::audit::AuditService;
                        let sth = audit
                            .current_sth(&tenant_id)
                            .await
                            .map_err(audit_err_to_py)?;
                        match sth {
                            None => Ok(None),
                            Some(s) => Ok(Some(serde_json::to_string(&s).map_err(|e| {
                                PyRuntimeError::new_err(format!("SignedTreeHead encode: {e}"))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    /// v1.5.0 Phase H — Generate the full inclusion-proof bundle for
    /// a trust grant. Returns a JSON-serialized
    /// [`crate::federation::read::TrustGrantInclusionProof`] (sth +
    /// merkle_proof + leaf_canonical_bytes). Raises `KeyError`
    /// (`NotFound`-shape) if the grant_id has no projection row, the
    /// tenant has no STH, or the merkle leaf is missing.
    #[cfg(feature = "cirisaudit")]
    fn trust_grant_inclusion_proof(&self, py: Python<'_>, grant_id: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let grant_uuid: uuid::Uuid = grant_id
                .parse()
                .map_err(|e| PyValueError::new_err(format!("grant_id must be UUID: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        let bundle = crate::federation::read::trust_grant_inclusion_proof(
                            &*backend, grant_uuid,
                        )
                        .await
                        .map_err(federation_read_err_to_py)?;
                        serde_json::to_string(&trust_grant_inclusion_proof_to_wire(&bundle))
                            .map_err(|e| {
                                PyRuntimeError::new_err(format!(
                                    "TrustGrantInclusionProof encode: {e}"
                                ))
                            })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(_) => {
                    let audit = self
                        .sqlite_audit
                        .as_ref()
                        .expect("v1.5.0 Phase H: sqlite_audit must be Some when backend is Sqlite")
                        .clone();
                    runtime.block_on(async move {
                        let bundle = crate::federation::read::trust_grant_inclusion_proof(
                            &*audit, grant_uuid,
                        )
                        .await
                        .map_err(federation_read_err_to_py)?;
                        serde_json::to_string(&trust_grant_inclusion_proof_to_wire(&bundle))
                            .map_err(|e| {
                                PyRuntimeError::new_err(format!(
                                    "TrustGrantInclusionProof encode: {e}"
                                ))
                            })
                    })
                }
            })
        })
    }

    /// v1.5.0 Phase H — Generate an RFC 6962 §2.1.2 consistency proof
    /// between two tree sizes for a tenant. Returns a JSON-serialized
    /// [`ciris_verify_core::transparency::ConsistencyProof`]. Verifier
    /// composes with the two STHs.
    #[cfg(feature = "cirisaudit")]
    fn trust_grant_consistency_proof(
        &self,
        py: Python<'_>,
        tenant_id: &str,
        old_size: u64,
        new_size: u64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let tenant_id = tenant_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        let proof = crate::federation::read::trust_grant_consistency_proof(
                            &*backend, &tenant_id, old_size, new_size,
                        )
                        .await
                        .map_err(federation_read_err_to_py)?;
                        serde_json::to_string(&proof).map_err(|e| {
                            PyRuntimeError::new_err(format!("ConsistencyProof encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(_) => {
                    let audit = self
                        .sqlite_audit
                        .as_ref()
                        .expect("v1.5.0 Phase H: sqlite_audit must be Some when backend is Sqlite")
                        .clone();
                    runtime.block_on(async move {
                        let proof = crate::federation::read::trust_grant_consistency_proof(
                            &*audit, &tenant_id, old_size, new_size,
                        )
                        .await
                        .map_err(federation_read_err_to_py)?;
                        serde_json::to_string(&proof).map_err(|e| {
                            PyRuntimeError::new_err(format!("ConsistencyProof encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.0 Phase I (FSD §6.2) — One-shot V020 → V021 backfill for
    /// the supplied tenant. Walks `federation_keys` for rows where
    /// `trusted_by` equals this Engine's local signer pubkey, expands
    /// each row to one (`direct`) or N (`registry`) `TrustGrant`
    /// emissions, and records them via
    /// [`crate::federation::emit::grant_trust`] — which fires the
    /// Phase C Merkle hook + Phase D projection inline.
    ///
    /// Returns a JSON-serialized
    /// [`crate::federation::backfill::BackfillReport`] string with
    /// `{ rows_scanned, events_emitted, already_present }`.
    ///
    /// Idempotent: re-running checks the V021 projection for each
    /// `(grantee, granter, purpose, scope)` quad and skips emissions
    /// whose projection rows already exist.
    ///
    /// Requires `local_key_id` / `local_key_path` on the Engine (the
    /// re-emitted grants are signed against this identity, per FSD
    /// §6.2's "signed by the recovered `trusted_by` key" rule). Raises
    /// `ValueError` if no signer is configured.
    #[cfg(feature = "cirisaudit")]
    fn backfill_v020_trust_rows(&self, py: Python<'_>, tenant_id: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let tenant_id = tenant_id.to_owned();
            let signer = self.local_signer.clone().ok_or_else(|| {
                PyValueError::new_err(
                    "no local signing key configured (pass local_key_id + local_key_path \
                     to the Engine constructor)",
                )
            })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        let report = crate::federation::backfill::backfill_v020_trust_rows(
                            &*backend, &signer, &tenant_id,
                        )
                        .await
                        .map_err(backfill_err_to_py)?;
                        backfill_report_to_json(&report)
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(_) => {
                    let audit = self
                        .sqlite_audit
                        .as_ref()
                        .expect("v1.5.0 Phase H: sqlite_audit must be Some when backend is Sqlite")
                        .clone();
                    runtime.block_on(async move {
                        let report = crate::federation::backfill::backfill_v020_trust_rows(
                            &*audit, &signer, &tenant_id,
                        )
                        .await
                        .map_err(backfill_err_to_py)?;
                        backfill_report_to_json(&report)
                    })
                }
            })
        })
    }

    // ── v0.8.2: telemetry PyO3 surface (CIRISPersist#36) ─────────────
    //
    // 4 methods wrapping TelemetryService.

    /// v0.8.2 — Record one telemetry observation.
    #[cfg(feature = "telemetry")]
    fn telemetry_record_metric(&self, py: Python<'_>, obs_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let obs: crate::telemetry::MetricObservation = serde_json::from_str(obs_json)
                .map_err(|e| PyValueError::new_err(format!("MetricObservation decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        backend
                            .record_metric(obs)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::telemetry::sqlite::SqliteTelemetryBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        backend
                            .record_metric(obs)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.8.2 — Bulk-record N observations. Returns affected row count.
    #[cfg(feature = "telemetry")]
    fn telemetry_record_metrics_batch(&self, py: Python<'_>, obs_json: &str) -> PyResult<u64> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let obs: Vec<crate::telemetry::MetricObservation> = serde_json::from_str(obs_json)
                .map_err(|e| {
                    PyValueError::new_err(format!("Vec<MetricObservation> decode: {e}"))
                })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        backend
                            .record_metrics_batch(&obs)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::telemetry::sqlite::SqliteTelemetryBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        backend
                            .record_metrics_batch(&obs)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.8.2 — Cursor-paged tenant-scoped metric listing.
    #[cfg(feature = "telemetry")]
    fn telemetry_list_metrics(
        &self,
        py: Python<'_>,
        filter_json: &str,
        cursor_json: Option<&str>,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::telemetry::MetricFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("MetricFilter decode: {e}")))?;
            let cursor: Option<crate::telemetry::types::MetricCursor> = match cursor_json {
                None => None,
                Some(s) => Some(
                    serde_json::from_str(s)
                        .map_err(|e| PyValueError::new_err(format!("MetricCursor decode: {e}")))?,
                ),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let page = backend
                            .list_metrics(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("MetricListPage encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::telemetry::sqlite::SqliteTelemetryBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let page = backend
                            .list_metrics(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("MetricListPage encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v0.8.2 — Run 6-hour rollup for one (period, tenant) window.
    /// AV-53 stale-lock auto-break; AV-54 TEMPORAL_NEXT chain.
    /// Returns JSON `ConsolidationOutcome`.
    #[cfg(feature = "telemetry")]
    fn telemetry_consolidate_period(&self, py: Python<'_>, req_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let req: crate::telemetry::ConsolidationRequest = serde_json::from_str(req_json)
                .map_err(|e| PyValueError::new_err(format!("ConsolidationRequest decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let outcome = backend
                            .consolidate_period(req)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!("ConsolidationOutcome encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::telemetry::sqlite::SqliteTelemetryBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let outcome = backend
                            .consolidate_period(req)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!("ConsolidationOutcome encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── v1.6.0 (CIRISPersist#63) TSDB query / prune / edges ─────────

    /// v1.6.0 — Return every `MetricSummary` whose
    /// `(consolidation_level, tenant_id)` matches and whose
    /// `period_start ∈ [from, to)`. Returns the JSON-encoded
    /// `list[MetricSummary]`.
    ///
    /// `level` is one of `"basic" | "daily" | "weekly" | "monthly"`.
    /// `from` / `to` are RFC 3339 timestamps. `to` must be > `from`.
    ///
    /// Backs CIRISAgent 2.9.0 Phase 3b's "period-window queries"
    /// (Basic 6h, extensive week, profound month).
    #[cfg(feature = "telemetry")]
    fn tsdb_query_summaries(
        &self,
        py: Python<'_>,
        level: &str,
        tenant_id: &str,
        from_rfc3339: &str,
        to_rfc3339: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let level = crate::telemetry::ConsolidationLevel::from_wire_str(level)
                .ok_or_else(|| PyValueError::new_err(format!("unknown level: {level}")))?;
            let tenant_id = tenant_id.to_owned();
            let from: chrono::DateTime<chrono::Utc> =
                chrono::DateTime::parse_from_rfc3339(from_rfc3339)
                    .map_err(|e| PyValueError::new_err(format!("from parse: {e}")))?
                    .with_timezone(&chrono::Utc);
            let to: chrono::DateTime<chrono::Utc> =
                chrono::DateTime::parse_from_rfc3339(to_rfc3339)
                    .map_err(|e| PyValueError::new_err(format!("to parse: {e}")))?
                    .with_timezone(&chrono::Utc);
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let rows = backend
                            .query_summaries(level, &tenant_id, from, to)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("query_summaries encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::telemetry::sqlite::SqliteTelemetryBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let rows = backend
                            .query_summaries(level, &tenant_id, from, to)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("query_summaries encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.6.0 — Point-lookup of one summary by the deterministic
    /// `(level, tenant_id, metric_name, period_start)` key. Returns
    /// the JSON-encoded `MetricSummary` or `None`.
    #[cfg(feature = "telemetry")]
    fn tsdb_get_summary(
        &self,
        py: Python<'_>,
        level: &str,
        tenant_id: &str,
        metric_name: &str,
        period_start_rfc3339: &str,
    ) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let level = crate::telemetry::ConsolidationLevel::from_wire_str(level)
                .ok_or_else(|| PyValueError::new_err(format!("unknown level: {level}")))?;
            let tenant_id = tenant_id.to_owned();
            let metric_name = metric_name.to_owned();
            let period_start: chrono::DateTime<chrono::Utc> =
                chrono::DateTime::parse_from_rfc3339(period_start_rfc3339)
                    .map_err(|e| PyValueError::new_err(format!("period_start parse: {e}")))?
                    .with_timezone(&chrono::Utc);
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let row = backend
                            .get_summary(level, &tenant_id, &metric_name, period_start)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match row {
                            None => Ok(None),
                            Some(s) => serde_json::to_string(&s).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("MetricSummary encode: {e}"))
                            }),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::telemetry::sqlite::SqliteTelemetryBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let row = backend
                            .get_summary(level, &tenant_id, &metric_name, period_start)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match row {
                            None => Ok(None),
                            Some(s) => serde_json::to_string(&s).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("MetricSummary encode: {e}"))
                            }),
                        }
                    })
                }
            })
        })
    }

    /// v1.6.0 — Delete summary nodes older than `before` for
    /// `(level, tenant_id)`. Cascades incident TEMPORAL_NEXT edges.
    /// Returns the raw count of summary nodes deleted (edges deleted
    /// silently as part of the cascade).
    #[cfg(feature = "telemetry")]
    fn tsdb_prune_summaries(
        &self,
        py: Python<'_>,
        level: &str,
        tenant_id: &str,
        before_rfc3339: &str,
    ) -> PyResult<u64> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let level = crate::telemetry::ConsolidationLevel::from_wire_str(level)
                .ok_or_else(|| PyValueError::new_err(format!("unknown level: {level}")))?;
            let tenant_id = tenant_id.to_owned();
            let before: chrono::DateTime<chrono::Utc> =
                chrono::DateTime::parse_from_rfc3339(before_rfc3339)
                    .map_err(|e| PyValueError::new_err(format!("before parse: {e}")))?
                    .with_timezone(&chrono::Utc);
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        backend
                            .prune_summaries(level, &tenant_id, before)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::telemetry::sqlite::SqliteTelemetryBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        backend
                            .prune_summaries(level, &tenant_id, before)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    // ── v1.6.2 (CIRISPersist#68) — non-metric typed summaries ───────

    /// v1.6.2 (CIRISPersist#68) — Consolidate task source data over
    /// the request's period window into a `task_summary` graph node.
    /// `req_json` is a JSON `ConsolidationRequest`; returns a JSON
    /// `TypedConsolidationOutcome` (`{summary_written: bool,
    /// source_rows: int}`). The emitted `task_summary` attributes
    /// carry `total_tasks`, `by_status` (histogram), and
    /// `mean_thought_depth`.
    #[cfg(feature = "telemetry")]
    fn tsdb_consolidate_tasks(&self, py: Python<'_>, req_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let req: crate::telemetry::ConsolidationRequest = serde_json::from_str(req_json)
                .map_err(|e| PyValueError::new_err(format!("ConsolidationRequest decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let outcome = backend
                            .consolidate_tasks(req)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!(
                                "TypedConsolidationOutcome encode: {e}"
                            ))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::telemetry::sqlite::SqliteTelemetryBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let outcome = backend
                            .consolidate_tasks(req)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!(
                                "TypedConsolidationOutcome encode: {e}"
                            ))
                        })
                    })
                }
            })
        })
    }

    /// v1.6.2 — Consolidate conversation-shaped service correlations
    /// into a `conversation_summary` node. Returns JSON
    /// `TypedConsolidationOutcome`.
    #[cfg(feature = "telemetry")]
    fn tsdb_consolidate_conversations(&self, py: Python<'_>, req_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let req: crate::telemetry::ConsolidationRequest = serde_json::from_str(req_json)
                .map_err(|e| PyValueError::new_err(format!("ConsolidationRequest decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let outcome = backend
                            .consolidate_conversations(req)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!(
                                "TypedConsolidationOutcome encode: {e}"
                            ))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::telemetry::sqlite::SqliteTelemetryBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let outcome = backend
                            .consolidate_conversations(req)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!(
                                "TypedConsolidationOutcome encode: {e}"
                            ))
                        })
                    })
                }
            })
        })
    }

    /// v1.6.2 — Consolidate trace-shaped service correlations into a
    /// `trace_summary` node. Returns JSON `TypedConsolidationOutcome`.
    #[cfg(feature = "telemetry")]
    fn tsdb_consolidate_traces(&self, py: Python<'_>, req_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let req: crate::telemetry::ConsolidationRequest = serde_json::from_str(req_json)
                .map_err(|e| PyValueError::new_err(format!("ConsolidationRequest decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let outcome = backend
                            .consolidate_traces(req)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!(
                                "TypedConsolidationOutcome encode: {e}"
                            ))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::telemetry::sqlite::SqliteTelemetryBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let outcome = backend
                            .consolidate_traces(req)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!(
                                "TypedConsolidationOutcome encode: {e}"
                            ))
                        })
                    })
                }
            })
        })
    }

    /// v1.6.2 — Consolidate audit-log events into an `audit_summary`
    /// node. Returns JSON `TypedConsolidationOutcome`.
    #[cfg(feature = "telemetry")]
    fn tsdb_consolidate_audit(&self, py: Python<'_>, req_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let req: crate::telemetry::ConsolidationRequest = serde_json::from_str(req_json)
                .map_err(|e| PyValueError::new_err(format!("ConsolidationRequest decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let outcome = backend
                            .consolidate_audit(req)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!(
                                "TypedConsolidationOutcome encode: {e}"
                            ))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::telemetry::sqlite::SqliteTelemetryBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let outcome = backend
                            .consolidate_audit(req)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!(
                                "TypedConsolidationOutcome encode: {e}"
                            ))
                        })
                    })
                }
            })
        })
    }

    /// v1.6.2 — Query typed summary nodes by `node_type`. Returns a
    /// JSON `list[dict]` — each entry is the raw `attributes` JSON
    /// for one matching summary row. Callers deserialize per
    /// summary type (`TaskSummary`, `ConversationSummary`,
    /// `TraceSummary`, `AuditSummary`) on their side.
    ///
    /// `node_type` is one of `"task_summary" |
    /// "conversation_summary" | "trace_summary" | "audit_summary"`.
    /// `level` is one of `"basic" | "daily" | "weekly" | "monthly"`.
    /// `from` / `to` bracket `period_start` (half-open).
    #[cfg(feature = "telemetry")]
    fn tsdb_query_summary_nodes(
        &self,
        py: Python<'_>,
        node_type: &str,
        level: &str,
        tenant_id: &str,
        from_rfc3339: &str,
        to_rfc3339: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let level = crate::telemetry::ConsolidationLevel::from_wire_str(level)
                .ok_or_else(|| PyValueError::new_err(format!("unknown level: {level}")))?;
            let node_type = node_type.to_owned();
            let tenant_id = tenant_id.to_owned();
            let from: chrono::DateTime<chrono::Utc> =
                chrono::DateTime::parse_from_rfc3339(from_rfc3339)
                    .map_err(|e| PyValueError::new_err(format!("from parse: {e}")))?
                    .with_timezone(&chrono::Utc);
            let to: chrono::DateTime<chrono::Utc> =
                chrono::DateTime::parse_from_rfc3339(to_rfc3339)
                    .map_err(|e| PyValueError::new_err(format!("to parse: {e}")))?
                    .with_timezone(&chrono::Utc);
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let rows = backend
                            .query_summary_nodes(&node_type, level, &tenant_id, from, to)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("query_summary_nodes encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::telemetry::sqlite::SqliteTelemetryBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let rows = backend
                            .query_summary_nodes(&node_type, level, &tenant_id, from, to)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("query_summary_nodes encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.6.0 — Histogram of edges within `[from, to)`, grouped by
    /// `relationship`. Filters scope='ENVIRONMENT' (the TSDB scope).
    /// Returns the JSON-encoded `dict[str, int]`.
    #[cfg(feature = "telemetry")]
    fn tsdb_count_edges_by_relationship_in_window(
        &self,
        py: Python<'_>,
        from_rfc3339: &str,
        to_rfc3339: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let from: chrono::DateTime<chrono::Utc> =
                chrono::DateTime::parse_from_rfc3339(from_rfc3339)
                    .map_err(|e| PyValueError::new_err(format!("from parse: {e}")))?
                    .with_timezone(&chrono::Utc);
            let to: chrono::DateTime<chrono::Utc> =
                chrono::DateTime::parse_from_rfc3339(to_rfc3339)
                    .map_err(|e| PyValueError::new_err(format!("to parse: {e}")))?
                    .with_timezone(&chrono::Utc);
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let map = backend
                            .count_edges_by_relationship_in_window(from, to)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&map).map_err(|e| {
                            PyRuntimeError::new_err(format!(
                                "count_edges_by_relationship encode: {e}"
                            ))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::telemetry::sqlite::SqliteTelemetryBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::telemetry::TelemetryService;
                        let map = backend
                            .count_edges_by_relationship_in_window(from, to)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&map).map_err(|e| {
                            PyRuntimeError::new_err(format!(
                                "count_edges_by_relationship encode: {e}"
                            ))
                        })
                    })
                }
            })
        })
    }

    // ── v0.8.3: incident PyO3 surface (CIRISPersist#37) ──────────────
    //
    // 4 methods wrapping IncidentService.

    /// v0.8.3 — Record an incident (correlation-keyed dedup; bumps
    /// occurrences on existing open match). Returns the
    /// `incident_id` of the row that took the write.
    #[cfg(feature = "cirisincident")]
    fn incident_record(&self, py: Python<'_>, incident_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let inc: crate::incident::Incident = serde_json::from_str(incident_json)
                .map_err(|e| PyValueError::new_err(format!("Incident decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::incident::IncidentService;
                        backend
                            .record_incident(inc)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::incident::sqlite::SqliteIncidentBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::incident::IncidentService;
                        backend
                            .record_incident(inc)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.8.3 — AV-55 state-machine transition. Notes required for
    /// Resolved/Closed targets.
    #[cfg(feature = "cirisincident")]
    fn incident_transition(&self, py: Python<'_>, transition_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let t: crate::incident::IncidentTransition = serde_json::from_str(transition_json)
                .map_err(|e| PyValueError::new_err(format!("IncidentTransition decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::incident::IncidentService;
                        backend
                            .transition_state(t)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::incident::sqlite::SqliteIncidentBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::incident::IncidentService;
                        backend
                            .transition_state(t)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v0.8.3 — Cursor-paged tenant-scoped incident listing.
    #[cfg(feature = "cirisincident")]
    fn incident_list(
        &self,
        py: Python<'_>,
        filter_json: &str,
        cursor_json: Option<&str>,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::incident::IncidentFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("IncidentFilter decode: {e}")))?;
            let cursor: Option<crate::incident::types::IncidentCursor> =
                match cursor_json {
                    None => None,
                    Some(s) => Some(serde_json::from_str(s).map_err(|e| {
                        PyValueError::new_err(format!("IncidentCursor decode: {e}"))
                    })?),
                };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::incident::IncidentService;
                        let page = backend
                            .list_incidents(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("IncidentListPage encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::incident::sqlite::SqliteIncidentBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::incident::IncidentService;
                        let page = backend
                            .list_incidents(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("IncidentListPage encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v0.8.3 — Reverse-lookup incidents naming a given correlation
    /// key. Returns JSON array of `IncidentRef`.
    #[cfg(feature = "cirisincident")]
    fn incident_correlate(&self, py: Python<'_>, tenant_id: &str, key: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let tenant_id = tenant_id.to_owned();
            let key = key.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::incident::IncidentService;
                        let refs = backend
                            .correlate(&tenant_id, &key)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&refs).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<IncidentRef> encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::incident::sqlite::SqliteIncidentBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::incident::IncidentService;
                        let refs = backend
                            .correlate(&tenant_id, &key)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&refs).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<IncidentRef> encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── v1.5.9 (CIRISPersist#59 #1) tasks PyO3 surface ─────────────
    //
    // 6 methods wrapping TaskService. JSON wire format mirrors the
    // incident substrate pattern: Task struct + TaskFilter +
    // TaskCursor + TaskListPage decoded/encoded via serde at the
    // FFI boundary. ClaimResult<Task> serializes via an inline
    // wire-shape ({"outcome":"stored"|"already_claimed","task":{...}}).

    /// v1.5.9 — Idempotent upsert of a task row keyed on `task_id`.
    /// Re-insert with same payload is a no-op; re-insert with
    /// differing payload overwrites mutable columns and preserves
    /// `created_at`.
    ///
    /// v1.5.22 (CIRISPersist#61): returns the JSON-encoded outcome
    /// envelope `{"outcome": "stored" | "already_exists", "task":
    /// <Task>}`. When `context.correlation_id` is set and a
    /// different task with the same `(agent_occurrence_id,
    /// correlation_id)` already exists, the V036 unique index
    /// resolves to `already_exists` carrying the EXISTING row.
    #[cfg(feature = "cirislens_tasks")]
    fn task_upsert(&self, py: Python<'_>, task_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let task: crate::tasks::Task = serde_json::from_str(task_json)
                .map_err(|e| PyValueError::new_err(format!("Task decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        // UFCS — PostgresBackend has a Phase-3
                        // `Backend::upsert_task` placeholder; disambiguate
                        // to the concrete TaskService impl here.
                        let outcome = crate::tasks::TaskService::upsert_task(&*backend, task)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!("TaskUpsertOutcome encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::tasks::sqlite::SqliteTaskBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::tasks::TaskService;
                        let outcome = backend
                            .upsert_task(task)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!("TaskUpsertOutcome encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.9 — Read one task by id. Returns the JSON-encoded Task
    /// or None when no matching row.
    #[cfg(feature = "cirislens_tasks")]
    fn task_get(&self, py: Python<'_>, task_id: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let task_id = task_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::tasks::TaskService;
                        let row = backend
                            .get_task(&task_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match row {
                            None => Ok(None),
                            Some(t) => Ok(Some(serde_json::to_string(&t).map_err(|e| {
                                PyRuntimeError::new_err(format!("Task encode: {e}"))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::tasks::sqlite::SqliteTaskBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::tasks::TaskService;
                        let row = backend
                            .get_task(&task_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match row {
                            None => Ok(None),
                            Some(t) => Ok(Some(serde_json::to_string(&t).map_err(|e| {
                                PyRuntimeError::new_err(format!("Task encode: {e}"))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    /// v1.5.9 — Cursor-paged listing. Returns JSON-encoded
    /// `TaskListPage`.
    #[cfg(feature = "cirislens_tasks")]
    fn task_list(
        &self,
        py: Python<'_>,
        filter_json: &str,
        cursor_json: Option<&str>,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::tasks::TaskFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("TaskFilter decode: {e}")))?;
            let cursor: Option<crate::tasks::TaskCursor> = match cursor_json {
                None => None,
                Some(s) => Some(
                    serde_json::from_str(s)
                        .map_err(|e| PyValueError::new_err(format!("TaskCursor decode: {e}")))?,
                ),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::tasks::TaskService;
                        let page = backend
                            .list_tasks(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("TaskListPage encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::tasks::sqlite::SqliteTaskBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::tasks::TaskService;
                        let page = backend
                            .list_tasks(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("TaskListPage encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.9 — Focused status update + optional outcome merge.
    /// `outcome_json` is the JSON-encoded value to merge into the
    /// `outcome_json` column (None preserves the existing value).
    /// Returns true when a row was updated; false on missing task
    /// (no error — agent treats as "stale id").
    #[cfg(feature = "cirislens_tasks")]
    fn task_update_status(
        &self,
        py: Python<'_>,
        task_id: &str,
        new_status: &str,
        outcome_json: Option<&str>,
    ) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let status = crate::tasks::TaskStatus::parse_str(new_status).ok_or_else(|| {
                PyValueError::new_err(format!("unknown TaskStatus: {new_status}"))
            })?;
            let outcome: Option<serde_json::Value> = match outcome_json {
                None => None,
                Some(s) => Some(
                    serde_json::from_str(s)
                        .map_err(|e| PyValueError::new_err(format!("outcome_json decode: {e}")))?,
                ),
            };
            let task_id = task_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::tasks::TaskService;
                        backend
                            .update_task_status(&task_id, status, outcome)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::tasks::sqlite::SqliteTaskBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::tasks::TaskService;
                        backend
                            .update_task_status(&task_id, status, outcome)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.5.9 — Atomic INSERT-OR-IGNORE claim keyed on `task_id`.
    /// Returns a JSON-encoded ClaimResult shape:
    /// `{"outcome": "stored" | "already_claimed", "task": <Task>}`.
    #[cfg(feature = "cirislens_tasks")]
    fn task_try_claim_shared(&self, py: Python<'_>, task_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let task: crate::tasks::Task = serde_json::from_str(task_json)
                .map_err(|e| PyValueError::new_err(format!("Task decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        // UFCS — PostgresBackend has a Phase-3
                        // `Backend::try_claim_shared_task` placeholder;
                        // disambiguate to the concrete TaskService impl
                        // here.
                        let outcome =
                            crate::tasks::TaskService::try_claim_shared_task(&*backend, task)
                                .await
                                .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        encode_claim_result(outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!("ClaimResult encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::tasks::sqlite::SqliteTaskBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::tasks::TaskService;
                        let outcome = backend
                            .try_claim_shared_task(task)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        encode_claim_result(outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!("ClaimResult encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.9 — Delete a task by id. Returns true if a row was
    /// deleted, false on missing/already-deleted (idempotent).
    /// FK-protected: children pointing at this row reject the
    /// delete as Conflict.
    #[cfg(feature = "cirislens_tasks")]
    fn task_delete(&self, py: Python<'_>, task_id: &str) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let task_id = task_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::tasks::TaskService;
                        backend
                            .delete_task(&task_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::tasks::sqlite::SqliteTaskBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::tasks::TaskService;
                        backend
                            .delete_task(&task_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    // ── v1.5.10 (CIRISPersist#59 #2) thoughts PyO3 surface ──────────
    //
    // 5 methods wrapping ThoughtService. JSON wire format mirrors the
    // tasks substrate pattern: Thought struct + ThoughtFilter +
    // ThoughtCursor + ThoughtListPage decoded/encoded via serde at
    // the FFI boundary. `get_descendants` returns a JSON-encoded
    // `Vec<Thought>` (root + transitive descendants).

    /// v1.5.10 — Idempotent upsert of a thought row keyed on
    /// `thought_id`. Re-insert with same payload is a no-op; re-
    /// insert with differing payload overwrites mutable columns and
    /// preserves `created_at`.
    #[cfg(feature = "cirislens_thoughts")]
    fn thought_upsert(&self, py: Python<'_>, thought_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let thought: crate::thoughts::Thought = serde_json::from_str(thought_json)
                .map_err(|e| PyValueError::new_err(format!("Thought decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::thoughts::ThoughtService;
                        backend
                            .upsert_thought(thought)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::thoughts::sqlite::SqliteThoughtBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::thoughts::ThoughtService;
                        backend
                            .upsert_thought(thought)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.5.10 — Read one thought by id. Returns the JSON-encoded
    /// Thought or None when no matching row.
    #[cfg(feature = "cirislens_thoughts")]
    fn thought_get(&self, py: Python<'_>, thought_id: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let thought_id = thought_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::thoughts::ThoughtService;
                        let row = backend
                            .get_thought(&thought_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match row {
                            None => Ok(None),
                            Some(t) => Ok(Some(serde_json::to_string(&t).map_err(|e| {
                                PyRuntimeError::new_err(format!("Thought encode: {e}"))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::thoughts::sqlite::SqliteThoughtBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::thoughts::ThoughtService;
                        let row = backend
                            .get_thought(&thought_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match row {
                            None => Ok(None),
                            Some(t) => Ok(Some(serde_json::to_string(&t).map_err(|e| {
                                PyRuntimeError::new_err(format!("Thought encode: {e}"))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    /// v1.5.10 — Cursor-paged listing. Returns JSON-encoded
    /// `ThoughtListPage`.
    #[cfg(feature = "cirislens_thoughts")]
    fn thought_list(
        &self,
        py: Python<'_>,
        filter_json: &str,
        cursor_json: Option<&str>,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::thoughts::ThoughtFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("ThoughtFilter decode: {e}")))?;
            let cursor: Option<crate::thoughts::ThoughtCursor> = match cursor_json {
                None => None,
                Some(s) => Some(
                    serde_json::from_str(s)
                        .map_err(|e| PyValueError::new_err(format!("ThoughtCursor decode: {e}")))?,
                ),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::thoughts::ThoughtService;
                        let page = backend
                            .list_thoughts(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("ThoughtListPage encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::thoughts::sqlite::SqliteThoughtBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::thoughts::ThoughtService;
                        let page = backend
                            .list_thoughts(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("ThoughtListPage encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.10 — Focused status update + optional final_action merge.
    /// `final_action_json` is the JSON-encoded value to merge into
    /// the `final_action_json` column (None preserves the existing
    /// value). Returns true when a row was updated; false on missing
    /// thought (no error — agent treats as "stale id").
    #[cfg(feature = "cirislens_thoughts")]
    fn thought_update_status(
        &self,
        py: Python<'_>,
        thought_id: &str,
        new_status: &str,
        final_action_json: Option<&str>,
    ) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let status =
                crate::thoughts::ThoughtStatus::parse_str(new_status).ok_or_else(|| {
                    PyValueError::new_err(format!("unknown ThoughtStatus: {new_status}"))
                })?;
            let final_action: Option<serde_json::Value> = match final_action_json {
                None => None,
                Some(s) => Some(serde_json::from_str(s).map_err(|e| {
                    PyValueError::new_err(format!("final_action_json decode: {e}"))
                })?),
            };
            let thought_id = thought_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::thoughts::ThoughtService;
                        backend
                            .update_thought_status(&thought_id, status, final_action)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::thoughts::sqlite::SqliteThoughtBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::thoughts::ThoughtService;
                        backend
                            .update_thought_status(&thought_id, status, final_action)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.5.20 — Delete a thought by id. Returns true if a row was
    /// deleted, false on missing/already-deleted (idempotent). The
    /// self-FK on `parent_thought_id` REJECTS the delete with
    /// Conflict if children exist — caller deletes leaves-first or
    /// enumerates via `thought_get_descendants` first. The cascade
    /// on `source_task_id` (V035) flows the other way:
    /// `task_delete` of a parent task cascades its thoughts.
    #[cfg(feature = "cirislens_thoughts")]
    fn thought_delete(&self, py: Python<'_>, thought_id: &str) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let thought_id = thought_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::thoughts::ThoughtService;
                        backend
                            .delete_thought(&thought_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::thoughts::sqlite::SqliteThoughtBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::thoughts::ThoughtService;
                        backend
                            .delete_thought(&thought_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.5.10 — Walk parent_thought_id chain rooted at `thought_id`.
    /// Returns the JSON-encoded `Vec<Thought>` (root + transitive
    /// descendants) ordered by `(thought_depth ASC, thought_id ASC)`.
    /// Empty array when the root has no matching row (not an error).
    #[cfg(feature = "cirislens_thoughts")]
    fn thought_get_descendants(&self, py: Python<'_>, thought_id: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let thought_id = thought_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::thoughts::ThoughtService;
                        let rows = backend
                            .get_descendants(&thought_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<Thought> encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::thoughts::sqlite::SqliteThoughtBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::thoughts::ThoughtService;
                        let rows = backend
                            .get_descendants(&thought_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&rows).map_err(|e| {
                            PyRuntimeError::new_err(format!("Vec<Thought> encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── v1.5.11 (CIRISPersist#59 #3) correlations PyO3 surface ──────
    //
    // 4 methods wrapping CorrelationService. JSON wire format mirrors
    // the tasks/thoughts substrate pattern: Correlation struct +
    // CorrelationFilter + CorrelationCursor + CorrelationListPage
    // decoded/encoded via serde at the FFI boundary. Dual-purpose
    // schema — correlation_type discriminates service_interaction /
    // metric / trace / log.

    /// v1.5.11 — Record a correlation. INSERT-OR-IGNORE keyed on
    /// `correlation_id`. First writer wins; re-record with the same
    /// id is a silent no-op (idempotent retry). State advancement
    /// is the caller's responsibility — use
    /// `correlation_update_status` to advance an in-flight row.
    #[cfg(feature = "cirislens_correlations")]
    fn correlation_record(&self, py: Python<'_>, correlation_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let correlation: crate::correlations::Correlation =
                serde_json::from_str(correlation_json)
                    .map_err(|e| PyValueError::new_err(format!("Correlation decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        // UFCS — PostgresBackend has a Phase-3
                        // `Backend::record_correlation` placeholder
                        // (`store::backend.rs`); disambiguate to the
                        // concrete CorrelationService impl here.
                        crate::correlations::CorrelationService::record_correlation(
                            &*backend,
                            correlation,
                        )
                        .await
                        .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::correlations::sqlite::SqliteCorrelationBackend::new(
                        sq.conn_handle(),
                    );
                    runtime.block_on(async move {
                        use crate::correlations::CorrelationService;
                        backend
                            .record_correlation(correlation)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.5.11 — Read one correlation by id. Returns the JSON-encoded
    /// Correlation or None when no matching row.
    #[cfg(feature = "cirislens_correlations")]
    fn correlation_get(&self, py: Python<'_>, correlation_id: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let correlation_id = correlation_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::correlations::CorrelationService;
                        let row = backend
                            .get_correlation(&correlation_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match row {
                            None => Ok(None),
                            Some(c) => Ok(Some(serde_json::to_string(&c).map_err(|e| {
                                PyRuntimeError::new_err(format!("Correlation encode: {e}"))
                            })?)),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::correlations::sqlite::SqliteCorrelationBackend::new(
                        sq.conn_handle(),
                    );
                    runtime.block_on(async move {
                        use crate::correlations::CorrelationService;
                        let row = backend
                            .get_correlation(&correlation_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match row {
                            None => Ok(None),
                            Some(c) => Ok(Some(serde_json::to_string(&c).map_err(|e| {
                                PyRuntimeError::new_err(format!("Correlation encode: {e}"))
                            })?)),
                        }
                    })
                }
            })
        })
    }

    /// v1.5.11 — Focused status update + optional response_data merge.
    /// `new_status` is one of `pending` / `active` / `completed` /
    /// `failed` / `cancelled`. `response_data_json` (when not None)
    /// is decoded and stored into the `response_data` column; None
    /// preserves the existing value. Returns true when a row was
    /// updated; false on missing correlation (no error — caller
    /// treats as "stale id").
    #[cfg(feature = "cirislens_correlations")]
    fn correlation_update_status(
        &self,
        py: Python<'_>,
        correlation_id: &str,
        new_status: &str,
        response_data_json: Option<&str>,
    ) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let status =
                crate::correlations::CorrelationStatus::parse_str(new_status).ok_or_else(|| {
                    PyValueError::new_err(format!("unknown CorrelationStatus: {new_status}"))
                })?;
            let response_data: Option<serde_json::Value> = match response_data_json {
                None => None,
                Some(s) => Some(serde_json::from_str(s).map_err(|e| {
                    PyValueError::new_err(format!("response_data_json decode: {e}"))
                })?),
            };
            let correlation_id = correlation_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::correlations::CorrelationService;
                        backend
                            .update_correlation_status(&correlation_id, status, response_data)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::correlations::sqlite::SqliteCorrelationBackend::new(
                        sq.conn_handle(),
                    );
                    runtime.block_on(async move {
                        use crate::correlations::CorrelationService;
                        backend
                            .update_correlation_status(&correlation_id, status, response_data)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.5.11 — Cursor-paged query. Returns JSON-encoded
    /// `CorrelationListPage`. Filter shape mirrors
    /// `CorrelationFilter` — see the
    /// `ciris_persist.correlations` module for the supported fields
    /// (service_type / correlation_type / trace_id / metric_name /
    /// retention_policy / agent_occurrence_id / timestamp window /
    /// updated window).
    #[cfg(feature = "cirislens_correlations")]
    fn correlation_query(
        &self,
        py: Python<'_>,
        filter_json: &str,
        cursor_json: Option<&str>,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::correlations::CorrelationFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("CorrelationFilter decode: {e}")))?;
            let cursor: Option<crate::correlations::CorrelationCursor> = match cursor_json {
                None => None,
                Some(s) => Some(serde_json::from_str(s).map_err(|e| {
                    PyValueError::new_err(format!("CorrelationCursor decode: {e}"))
                })?),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::correlations::CorrelationService;
                        let page = backend
                            .query_correlations(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("CorrelationListPage encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::correlations::sqlite::SqliteCorrelationBackend::new(
                        sq.conn_handle(),
                    );
                    runtime.block_on(async move {
                        use crate::correlations::CorrelationService;
                        let page = backend
                            .query_correlations(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("CorrelationListPage encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── v1.5.12 (CIRISPersist#59 #4) scheduled_tasks PyO3 surface ──
    //
    // 3 methods wrapping ScheduledTaskService. JSON wire format
    // mirrors tasks/thoughts/correlations substrate patterns:
    // ScheduledTask struct decoded/encoded via serde at the FFI
    // boundary. Status vocabulary is UPPERCASE at the SQL layer;
    // the serde wire format is snake_case so callers send
    // `"pending"` / `"active"` / `"complete"` / `"failed"` in JSON.

    /// v1.5.12 — Upsert a scheduled task. INSERT on first call,
    /// UPDATE on conflict by `id`. All columns except `created_at`
    /// overwrite on conflict; `created_at` is preserved.
    #[cfg(feature = "cirislens_scheduled_tasks")]
    fn scheduled_task_upsert(&self, py: Python<'_>, task_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let task: crate::scheduled_tasks::ScheduledTask = serde_json::from_str(task_json)
                .map_err(|e| PyValueError::new_err(format!("ScheduledTask decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        // No Backend-trait collision on
                        // `upsert_scheduled_task` (verified) — but
                        // UFCS for consistency with the rest of the
                        // substrate PyO3 surface.
                        crate::scheduled_tasks::ScheduledTaskService::upsert_scheduled_task(
                            &*backend, task,
                        )
                        .await
                        .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::scheduled_tasks::sqlite::SqliteScheduledTaskBackend::new(
                        sq.conn_handle(),
                    );
                    runtime.block_on(async move {
                        use crate::scheduled_tasks::ScheduledTaskService;
                        backend
                            .upsert_scheduled_task(task)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.5.12 — Scheduler tick query. Returns JSON-encoded
    /// `list[ScheduledTask]` of tasks whose `next_trigger_at <= now`
    /// and status is `PENDING` or `ACTIVE`, scoped to one
    /// occurrence. Ordered ASC by `next_trigger_at`.
    #[cfg(feature = "cirislens_scheduled_tasks")]
    fn scheduled_task_list_due(
        &self,
        py: Python<'_>,
        agent_occurrence_id: &str,
        now_iso: &str,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let now: chrono::DateTime<chrono::Utc> = chrono::DateTime::parse_from_rfc3339(now_iso)
                .map_err(|e| PyValueError::new_err(format!("now_iso parse: {e}")))?
                .with_timezone(&chrono::Utc);
            let occ = agent_occurrence_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::scheduled_tasks::ScheduledTaskService;
                        let items = backend
                            .list_due_scheduled_tasks(&occ, now, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&items).map_err(|e| {
                            PyRuntimeError::new_err(format!("ScheduledTask list encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::scheduled_tasks::sqlite::SqliteScheduledTaskBackend::new(
                        sq.conn_handle(),
                    );
                    runtime.block_on(async move {
                        use crate::scheduled_tasks::ScheduledTaskService;
                        let items = backend
                            .list_due_scheduled_tasks(&occ, now, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&items).map_err(|e| {
                            PyRuntimeError::new_err(format!("ScheduledTask list encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.12 — Post-fire bookkeeping. Updates
    /// `last_triggered_at`, `next_trigger_at` (None → NULL),
    /// `deferral_count`, optionally `deferral_history` (None →
    /// preserve existing), optionally `new_status` (None →
    /// preserve existing). Returns True when the row existed and
    /// was updated; False when no matching row.
    ///
    /// `new_status` is one of `pending` / `active` / `complete` /
    /// `failed` (lowercase snake_case wire format; UPPERCASE on
    /// the SQL side).
    #[cfg(feature = "cirislens_scheduled_tasks")]
    #[pyo3(signature = (task_id, last_triggered_at_iso, next_trigger_at_iso, deferral_count, deferral_history_json=None, new_status=None))]
    #[allow(clippy::too_many_arguments)]
    fn scheduled_task_update_after_trigger(
        &self,
        py: Python<'_>,
        task_id: &str,
        last_triggered_at_iso: &str,
        next_trigger_at_iso: Option<&str>,
        deferral_count: i32,
        deferral_history_json: Option<&str>,
        new_status: Option<&str>,
    ) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let last_triggered_at: chrono::DateTime<chrono::Utc> =
                chrono::DateTime::parse_from_rfc3339(last_triggered_at_iso)
                    .map_err(|e| {
                        PyValueError::new_err(format!("last_triggered_at_iso parse: {e}"))
                    })?
                    .with_timezone(&chrono::Utc);
            let next_trigger_at: Option<chrono::DateTime<chrono::Utc>> = match next_trigger_at_iso {
                None => None,
                Some(s) => Some(
                    chrono::DateTime::parse_from_rfc3339(s)
                        .map_err(|e| {
                            PyValueError::new_err(format!("next_trigger_at_iso parse: {e}"))
                        })?
                        .with_timezone(&chrono::Utc),
                ),
            };
            let deferral_history: Option<serde_json::Value> = match deferral_history_json {
                None => None,
                Some(s) => Some(serde_json::from_str(s).map_err(|e| {
                    PyValueError::new_err(format!("deferral_history_json decode: {e}"))
                })?),
            };
            let new_status_parsed: Option<crate::scheduled_tasks::ScheduledTaskStatus> =
                match new_status {
                    None => None,
                    Some(s) => Some(
                        crate::scheduled_tasks::ScheduledTaskStatus::parse_str(&s.to_uppercase())
                            .ok_or_else(|| {
                            PyValueError::new_err(format!("unknown ScheduledTaskStatus: {s}"))
                        })?,
                    ),
                };
            let task_id_owned = task_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::scheduled_tasks::ScheduledTaskService;
                        backend
                            .update_after_trigger(
                                &task_id_owned,
                                last_triggered_at,
                                next_trigger_at,
                                deferral_count,
                                deferral_history,
                                new_status_parsed,
                            )
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::scheduled_tasks::sqlite::SqliteScheduledTaskBackend::new(
                        sq.conn_handle(),
                    );
                    runtime.block_on(async move {
                        use crate::scheduled_tasks::ScheduledTaskService;
                        backend
                            .update_after_trigger(
                                &task_id_owned,
                                last_triggered_at,
                                next_trigger_at,
                                deferral_count,
                                deferral_history,
                                new_status_parsed,
                            )
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    // ── v1.5.13 (CIRISPersist#59 #5) tickets PyO3 surface ───────
    //
    // 5 methods wrapping TicketService. JSON wire format mirrors
    // the tasks/thoughts/correlations/scheduled_tasks substrate
    // patterns: Ticket struct decoded/encoded via serde at the FFI
    // boundary. Status vocabulary is LOWERCASE 8-value with
    // snake_case `in_progress`; serde wire format matches the SQL
    // string directly so callers send `"pending"` / `"in_progress"`
    // etc. in JSON.

    /// v1.5.13 — Upsert a ticket. INSERT on first call, UPDATE on
    /// conflict by `ticket_id`. All columns except `created_at` and
    /// `submitted_at` overwrite on conflict; both creation-time
    /// columns are preserved.
    #[cfg(feature = "cirislens_tickets")]
    fn ticket_upsert(&self, py: Python<'_>, ticket_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let ticket: crate::tickets::Ticket = serde_json::from_str(ticket_json)
                .map_err(|e| PyValueError::new_err(format!("Ticket decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        crate::tickets::TicketService::upsert_ticket(&*backend, ticket)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::tickets::sqlite::SqliteTicketBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::tickets::TicketService;
                        backend
                            .upsert_ticket(ticket)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.5.13 — Point lookup. Returns JSON-encoded `Ticket` or
    /// `None` (Python `None`) when no matching row.
    #[cfg(feature = "cirislens_tickets")]
    fn ticket_get(&self, py: Python<'_>, ticket_id: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let ticket_id = ticket_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::tickets::TicketService;
                        let got = backend
                            .get_ticket(&ticket_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match got {
                            None => Ok(None),
                            Some(t) => serde_json::to_string(&t).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("Ticket encode: {e}"))
                            }),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::tickets::sqlite::SqliteTicketBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::tickets::TicketService;
                        let got = backend
                            .get_ticket(&ticket_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match got {
                            None => Ok(None),
                            Some(t) => serde_json::to_string(&t).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("Ticket encode: {e}"))
                            }),
                        }
                    })
                }
            })
        })
    }

    /// v1.5.13 — Cursor-paged list. `filter_json` is a JSON-encoded
    /// `TicketFilter`; `cursor_json` (optional) is a JSON-encoded
    /// `TicketCursor` from the previous page's `next_cursor`.
    /// Returns JSON-encoded `TicketListPage` (`{"items": [...],
    /// "next_cursor": {...}|None}`).
    #[cfg(feature = "cirislens_tickets")]
    #[pyo3(signature = (filter_json, cursor_json, limit))]
    fn ticket_list(
        &self,
        py: Python<'_>,
        filter_json: &str,
        cursor_json: Option<&str>,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::tickets::TicketFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("TicketFilter decode: {e}")))?;
            let cursor: Option<crate::tickets::TicketCursor> = match cursor_json {
                None => None,
                Some(s) => Some(
                    serde_json::from_str(s)
                        .map_err(|e| PyValueError::new_err(format!("TicketCursor decode: {e}")))?,
                ),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::tickets::TicketService;
                        let page = backend
                            .list_tickets(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("TicketListPage encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::tickets::sqlite::SqliteTicketBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::tickets::TicketService;
                        let page = backend
                            .list_tickets(filter, cursor, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&page).map_err(|e| {
                            PyRuntimeError::new_err(format!("TicketListPage encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.13 — Atomic assignment + status flip. Sets
    /// `user_identifier` to the supplied value, advances `status`
    /// (default `assigned`, or caller-supplied — `new_status` is
    /// the lowercase snake_case wire format), bumps `last_updated`.
    /// Idempotent on `(ticket_id, user_identifier)`. Returns True
    /// when the ticket exists, False when no matching row.
    #[cfg(feature = "cirislens_tickets")]
    #[pyo3(signature = (ticket_id, user_identifier, new_status=None))]
    fn ticket_assign(
        &self,
        py: Python<'_>,
        ticket_id: &str,
        user_identifier: &str,
        new_status: Option<&str>,
    ) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let new_status_parsed: Option<crate::tickets::TicketStatus> = match new_status {
                None => None,
                Some(s) => {
                    Some(crate::tickets::TicketStatus::parse_str(s).ok_or_else(|| {
                        PyValueError::new_err(format!("unknown TicketStatus: {s}"))
                    })?)
                }
            };
            let ticket_id_owned = ticket_id.to_owned();
            let user_identifier_owned = user_identifier.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::tickets::TicketService;
                        backend
                            .assign_ticket(
                                &ticket_id_owned,
                                &user_identifier_owned,
                                new_status_parsed,
                            )
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::tickets::sqlite::SqliteTicketBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::tickets::TicketService;
                        backend
                            .assign_ticket(
                                &ticket_id_owned,
                                &user_identifier_owned,
                                new_status_parsed,
                            )
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.5.13 — Focused status update. `new_status` is the
    /// lowercase snake_case wire format. Optional
    /// `completed_at_iso` (RFC 3339) — on terminal-state
    /// transitions (`completed`/`cancelled`/`failed`) the caller
    /// supplies the timestamp; the trait doesn't enforce.
    /// Optional `notes` overwrites the existing value when
    /// supplied. Bumps `last_updated` to NOW. Returns True when a
    /// row was updated, False when no matching ticket.
    #[cfg(feature = "cirislens_tickets")]
    #[pyo3(signature = (ticket_id, new_status, completed_at_iso=None, notes=None))]
    fn ticket_update_status(
        &self,
        py: Python<'_>,
        ticket_id: &str,
        new_status: &str,
        completed_at_iso: Option<&str>,
        notes: Option<&str>,
    ) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let new_status_parsed = crate::tickets::TicketStatus::parse_str(new_status)
                .ok_or_else(|| {
                    PyValueError::new_err(format!("unknown TicketStatus: {new_status}"))
                })?;
            let completed_at: Option<chrono::DateTime<chrono::Utc>> = match completed_at_iso {
                None => None,
                Some(s) => Some(
                    chrono::DateTime::parse_from_rfc3339(s)
                        .map_err(|e| PyValueError::new_err(format!("completed_at_iso parse: {e}")))?
                        .with_timezone(&chrono::Utc),
                ),
            };
            let ticket_id_owned = ticket_id.to_owned();
            let notes_owned = notes.map(|s| s.to_owned());
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::tickets::TicketService;
                        backend
                            .update_ticket_status(
                                &ticket_id_owned,
                                new_status_parsed,
                                completed_at,
                                notes_owned,
                            )
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::tickets::sqlite::SqliteTicketBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::tickets::TicketService;
                        backend
                            .update_ticket_status(
                                &ticket_id_owned,
                                new_status_parsed,
                                completed_at,
                                notes_owned,
                            )
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    // ── v1.5.14 (CIRISPersist#59 #6) — deferral_reports cluster ──
    //
    // 4 methods wrapping DeferralReportService. JSON wire format
    // mirrors the tasks/thoughts/correlations/scheduled_tasks/
    // tickets substrate patterns: DeferralReport struct decoded/
    // encoded via serde at the FFI boundary. `record_deferral`
    // returns a JSON-encoded ClaimResult (`{"outcome": "stored" |
    // "already_claimed", "report": <DeferralReport>}`) — race
    // winner gets Stored, loser gets AlreadyClaimed carrying the
    // existing row.

    /// v1.5.14 — Record a deferral report. INSERT ON CONFLICT
    /// (message_id) DO NOTHING — idempotent on message_id. Returns
    /// a JSON-encoded ClaimResult shape:
    /// `{"outcome": "stored" | "already_claimed", "report":
    /// <DeferralReport>}`. The race winner sees `"stored"` and
    /// their own row; race losers see `"already_claimed"` and the
    /// EXISTING row. Both arms carry the report so callers always
    /// have a stable identifier for downstream work.
    ///
    /// FK semantics: `task_id` must reference an existing row in
    /// `cirislens.tasks`, and `thought_id` must reference an
    /// existing row in `cirislens.thoughts`. PG: both FKs are
    /// `DEFERRABLE INITIALLY DEFERRED` so a single tx can write
    /// `(task, thought, deferral_report)` in order. SQLite: FKs
    /// are immediate; agent callers ensure parent rows exist
    /// before recording.
    #[cfg(feature = "cirislens_deferral_reports")]
    fn deferral_record(&self, py: Python<'_>, report_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let report: crate::deferral_reports::DeferralReport = serde_json::from_str(report_json)
                .map_err(|e| PyValueError::new_err(format!("DeferralReport decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::deferral_reports::DeferralReportService;
                        let outcome = backend
                            .record_deferral(report)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        encode_deferral_claim_result(outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!("ClaimResult encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::deferral_reports::sqlite::SqliteDeferralReportBackend::new(
                        sq.conn_handle(),
                    );
                    runtime.block_on(async move {
                        use crate::deferral_reports::DeferralReportService;
                        let outcome = backend
                            .record_deferral(report)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        encode_deferral_claim_result(outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!("ClaimResult encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.14 — Point lookup. Returns JSON-encoded
    /// `DeferralReport` or `None` (Python `None`) when no matching
    /// row.
    #[cfg(feature = "cirislens_deferral_reports")]
    fn deferral_get(&self, py: Python<'_>, message_id: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let message_id = message_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::deferral_reports::DeferralReportService;
                        let got = backend
                            .get_deferral(&message_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match got {
                            None => Ok(None),
                            Some(r) => serde_json::to_string(&r).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("DeferralReport encode: {e}"))
                            }),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::deferral_reports::sqlite::SqliteDeferralReportBackend::new(
                        sq.conn_handle(),
                    );
                    runtime.block_on(async move {
                        use crate::deferral_reports::DeferralReportService;
                        let got = backend
                            .get_deferral(&message_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match got {
                            None => Ok(None),
                            Some(r) => serde_json::to_string(&r).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("DeferralReport encode: {e}"))
                            }),
                        }
                    })
                }
            })
        })
    }

    /// v1.5.14 — WA queue: list deferrals awaiting resolution
    /// (`resolved_at IS NULL`), newest-first by `created_at`.
    /// `filter_json` is a JSON-encoded `DeferralFilter` — supported
    /// fields: `task_id`, `thought_id`, `created_after`,
    /// `created_before` (RFC 3339 timestamps for the time window).
    /// Returns JSON-encoded `Vec<DeferralReport>`. Hits the partial
    /// index `deferral_reports_active`.
    #[cfg(feature = "cirislens_deferral_reports")]
    fn deferral_list_active(
        &self,
        py: Python<'_>,
        filter_json: &str,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::deferral_reports::DeferralFilter = serde_json::from_str(filter_json)
                .map_err(|e| PyValueError::new_err(format!("DeferralFilter decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::deferral_reports::DeferralReportService;
                        let items = backend
                            .list_active_deferrals(filter, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&items).map_err(|e| {
                            PyRuntimeError::new_err(format!("DeferralReport list encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::deferral_reports::sqlite::SqliteDeferralReportBackend::new(
                        sq.conn_handle(),
                    );
                    runtime.block_on(async move {
                        use crate::deferral_reports::DeferralReportService;
                        let items = backend
                            .list_active_deferrals(filter, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&items).map_err(|e| {
                            PyRuntimeError::new_err(format!("DeferralReport list encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.14 — Mark a deferral as resolved. Sets `resolved_at`
    /// to `resolved_at_iso` (RFC 3339) and `resolution_notes` to
    /// the supplied value (overwrites; `None` clears). Returns
    /// `True` when a row was updated, `False` when no matching row
    /// (no error — callers treat as stale id).
    #[cfg(feature = "cirislens_deferral_reports")]
    #[pyo3(signature = (message_id, resolved_at, resolution_notes=None))]
    fn deferral_resolve(
        &self,
        py: Python<'_>,
        message_id: &str,
        resolved_at: &str,
        resolution_notes: Option<&str>,
    ) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let resolved_at_dt: chrono::DateTime<chrono::Utc> =
                chrono::DateTime::parse_from_rfc3339(resolved_at)
                    .map_err(|e| PyValueError::new_err(format!("resolved_at parse: {e}")))?
                    .with_timezone(&chrono::Utc);
            let message_id_owned = message_id.to_owned();
            let resolution_notes_owned = resolution_notes.map(|s| s.to_owned());
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::deferral_reports::DeferralReportService;
                        backend
                            .resolve_deferral(
                                &message_id_owned,
                                resolved_at_dt,
                                resolution_notes_owned,
                            )
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend = crate::deferral_reports::sqlite::SqliteDeferralReportBackend::new(
                        sq.conn_handle(),
                    );
                    runtime.block_on(async move {
                        use crate::deferral_reports::DeferralReportService;
                        backend
                            .resolve_deferral(
                                &message_id_owned,
                                resolved_at_dt,
                                resolution_notes_owned,
                            )
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    // ── v1.5.15 (CIRISPersist#59 #7) — maintenance_locks cluster ──
    //
    // 3 methods wrapping MaintenanceLockService. JSON wire format:
    // MaintenanceLock crosses the FFI as a serde-encoded JSON object
    // (or `None` / Python `None` on absent / contention). `metadata`
    // is an optional opaque JSON payload — callers serialize it
    // themselves and pass as a JSON string at the boundary.
    //
    // try_acquire returns `Option<json>`: `Some(...)` on win (clean
    // acquire or steal-the-stale), `None` on contention (held by
    // another active caller — caller treats as "try again later",
    // NOT an exception). release returns bool. get returns
    // `Option<json>`.

    /// v1.5.15 — Atomic try-acquire of a named lock. Returns the
    /// JSON-encoded `MaintenanceLock` (race winner) or `None`
    /// (contention — held by another active caller). Same-holder
    /// re-acquire succeeds as a refresh.
    ///
    /// `metadata_json` is an optional caller-supplied JSON string
    /// (must parse to a `serde_json::Value` if provided). It's
    /// stored verbatim in the row's `metadata` JSONB column for
    /// operator observability (worker id, occurrence id, pid, etc.).
    #[cfg(feature = "cirislens_maintenance_locks")]
    #[pyo3(signature = (lock_key, locked_by, timeout_seconds, metadata_json=None))]
    fn lock_try_acquire(
        &self,
        py: Python<'_>,
        lock_key: &str,
        locked_by: &str,
        timeout_seconds: i32,
        metadata_json: Option<&str>,
    ) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let lock_key = lock_key.to_owned();
            let locked_by = locked_by.to_owned();
            let metadata: Option<serde_json::Value> = match metadata_json {
                None => None,
                Some(raw) => Some(
                    serde_json::from_str(raw)
                        .map_err(|e| PyValueError::new_err(format!("metadata_json decode: {e}")))?,
                ),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::maintenance_locks::MaintenanceLockService;
                        let got = backend
                            .try_acquire_lock(&lock_key, &locked_by, timeout_seconds, metadata)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match got {
                            None => Ok(None),
                            Some(lock) => serde_json::to_string(&lock).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("MaintenanceLock encode: {e}"))
                            }),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::maintenance_locks::sqlite::SqliteMaintenanceLockBackend::new(
                            sq.conn_handle(),
                        );
                    runtime.block_on(async move {
                        use crate::maintenance_locks::MaintenanceLockService;
                        let got = backend
                            .try_acquire_lock(&lock_key, &locked_by, timeout_seconds, metadata)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match got {
                            None => Ok(None),
                            Some(lock) => serde_json::to_string(&lock).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("MaintenanceLock encode: {e}"))
                            }),
                        }
                    })
                }
            })
        })
    }

    /// v1.5.15 — Release a lock IFF the caller still holds it.
    /// Returns `True` when released; `False` when the row doesn't
    /// exist or is held by someone else (no-op; caller treats
    /// `False` as "not yours to release").
    #[cfg(feature = "cirislens_maintenance_locks")]
    fn lock_release(&self, py: Python<'_>, lock_key: &str, locked_by: &str) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let lock_key = lock_key.to_owned();
            let locked_by = locked_by.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::maintenance_locks::MaintenanceLockService;
                        backend
                            .release_lock(&lock_key, &locked_by)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::maintenance_locks::sqlite::SqliteMaintenanceLockBackend::new(
                            sq.conn_handle(),
                        );
                    runtime.block_on(async move {
                        use crate::maintenance_locks::MaintenanceLockService;
                        backend
                            .release_lock(&lock_key, &locked_by)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.5.15 — Read current lock state. Returns the JSON-encoded
    /// `MaintenanceLock` or `None` when no matching row. Callers
    /// inspect `locked_by` / `locked_at` to decide whether the lock
    /// is currently held.
    #[cfg(feature = "cirislens_maintenance_locks")]
    fn lock_get(&self, py: Python<'_>, lock_key: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let lock_key = lock_key.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::maintenance_locks::MaintenanceLockService;
                        let got = backend
                            .get_lock(&lock_key)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match got {
                            None => Ok(None),
                            Some(lock) => serde_json::to_string(&lock).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("MaintenanceLock encode: {e}"))
                            }),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::maintenance_locks::sqlite::SqliteMaintenanceLockBackend::new(
                            sq.conn_handle(),
                        );
                    runtime.block_on(async move {
                        use crate::maintenance_locks::MaintenanceLockService;
                        let got = backend
                            .get_lock(&lock_key)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match got {
                            None => Ok(None),
                            Some(lock) => serde_json::to_string(&lock).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("MaintenanceLock encode: {e}"))
                            }),
                        }
                    })
                }
            })
        })
    }

    // ── v1.5.16 (CIRISPersist#59 #8) — creation_ceremonies cluster ──
    //
    // 4 methods wrapping CreationCeremonyService. JSON wire format
    // mirrors the deferral_reports / tasks / tickets substrate
    // pattern: CreationCeremony struct decoded/encoded via serde at
    // the FFI boundary. `ceremony_record` returns a JSON-encoded
    // ClaimResult (`{"outcome": "stored" | "already_claimed",
    // "ceremony": <CreationCeremony>}`) — race winner gets Stored,
    // loser gets AlreadyClaimed carrying the existing row.

    /// v1.5.16 — Record a ceremony. INSERT ON CONFLICT
    /// (ceremony_id) DO NOTHING — write-once shape. Returns a
    /// JSON-encoded ClaimResult shape:
    /// `{"outcome": "stored" | "already_claimed", "ceremony":
    /// <CreationCeremony>}`. The race winner sees `"stored"` and
    /// their own row; race losers see `"already_claimed"` and the
    /// EXISTING row.
    #[cfg(feature = "cirislens_creation_ceremonies")]
    fn ceremony_record(&self, py: Python<'_>, ceremony_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let ceremony: crate::creation_ceremonies::CreationCeremony =
                serde_json::from_str(ceremony_json)
                    .map_err(|e| PyValueError::new_err(format!("CreationCeremony decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::creation_ceremonies::CreationCeremonyService;
                        let outcome = backend
                            .record_ceremony(ceremony)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        encode_ceremony_claim_result(outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!("ClaimResult encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::creation_ceremonies::sqlite::SqliteCreationCeremonyBackend::new(
                            sq.conn_handle(),
                        );
                    runtime.block_on(async move {
                        use crate::creation_ceremonies::CreationCeremonyService;
                        let outcome = backend
                            .record_ceremony(ceremony)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        encode_ceremony_claim_result(outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!("ClaimResult encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.16 — Point lookup. Returns JSON-encoded
    /// `CreationCeremony` or `None` (Python `None`) when no matching
    /// row.
    #[cfg(feature = "cirislens_creation_ceremonies")]
    fn ceremony_get(&self, py: Python<'_>, ceremony_id: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let ceremony_id = ceremony_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::creation_ceremonies::CreationCeremonyService;
                        let got = backend
                            .get_ceremony(&ceremony_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match got {
                            None => Ok(None),
                            Some(c) => serde_json::to_string(&c).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("CreationCeremony encode: {e}"))
                            }),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::creation_ceremonies::sqlite::SqliteCreationCeremonyBackend::new(
                            sq.conn_handle(),
                        );
                    runtime.block_on(async move {
                        use crate::creation_ceremonies::CreationCeremonyService;
                        let got = backend
                            .get_ceremony(&ceremony_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match got {
                            None => Ok(None),
                            Some(c) => serde_json::to_string(&c).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("CreationCeremony encode: {e}"))
                            }),
                        }
                    })
                }
            })
        })
    }

    /// v1.5.16 — History query. `filter_json` is a JSON-encoded
    /// `CeremonyFilter` — supported fields: `creator_agent_id`,
    /// `creator_human_id`, `wise_authority_id`, `new_agent_id`,
    /// `ceremony_status`, `timestamp_after`, `timestamp_before`
    /// (RFC 3339 timestamps for the time window). Returns
    /// JSON-encoded `Vec<CreationCeremony>` ordered by
    /// `timestamp DESC, ceremony_id DESC`, limited.
    #[cfg(feature = "cirislens_creation_ceremonies")]
    fn ceremony_list(&self, py: Python<'_>, filter_json: &str, limit: i64) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::creation_ceremonies::CeremonyFilter =
                serde_json::from_str(filter_json)
                    .map_err(|e| PyValueError::new_err(format!("CeremonyFilter decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::creation_ceremonies::CreationCeremonyService;
                        let items = backend
                            .list_ceremonies(filter, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&items).map_err(|e| {
                            PyRuntimeError::new_err(format!("CreationCeremony list encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::creation_ceremonies::sqlite::SqliteCreationCeremonyBackend::new(
                            sq.conn_handle(),
                        );
                    runtime.block_on(async move {
                        use crate::creation_ceremonies::CreationCeremonyService;
                        let items = backend
                            .list_ceremonies(filter, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&items).map_err(|e| {
                            PyRuntimeError::new_err(format!("CreationCeremony list encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.16 — Atomic ceremony-status advance. `new_status` is a
    /// lowercase snake_case string from the 5-value vocabulary
    /// (`pending | in_progress | completed | failed | revoked`).
    /// Returns `True` when a row was updated, `False` when no
    /// matching row (no error — callers treat as stale id).
    #[cfg(feature = "cirislens_creation_ceremonies")]
    fn ceremony_update_status(
        &self,
        py: Python<'_>,
        ceremony_id: &str,
        new_status: &str,
    ) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let new_status_parsed = crate::creation_ceremonies::CeremonyStatus::parse_str(
                new_status,
            )
            .ok_or_else(|| {
                PyValueError::new_err(format!(
                    "unknown ceremony_status `{new_status}`; \
                             expected one of pending|in_progress|completed|failed|revoked"
                ))
            })?;
            let ceremony_id_owned = ceremony_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::creation_ceremonies::CreationCeremonyService;
                        backend
                            .update_ceremony_status(&ceremony_id_owned, new_status_parsed)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::creation_ceremonies::sqlite::SqliteCreationCeremonyBackend::new(
                            sq.conn_handle(),
                        );
                    runtime.block_on(async move {
                        use crate::creation_ceremonies::CreationCeremonyService;
                        backend
                            .update_ceremony_status(&ceremony_id_owned, new_status_parsed)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    // ── v1.5.17 (CIRISPersist#59 #9) — continuity_awareness cluster ──
    //
    // 3 methods wrapping ContinuityAwarenessService. JSON wire
    // format mirrors the deferral_reports / creation_ceremonies
    // pattern: ContinuityAwareness struct decoded/encoded via serde
    // at the FFI boundary. `continuity_record` returns a
    // JSON-encoded ClaimResult (`{"outcome": "stored" |
    // "already_claimed", "record": <ContinuityAwareness>}`) — race
    // winner gets Stored, loser gets AlreadyClaimed carrying the
    // existing row.

    /// v1.5.17 — Record a shutdown event. INSERT ON CONFLICT (id)
    /// DO NOTHING — write-once shape. Returns a JSON-encoded
    /// ClaimResult shape: `{"outcome": "stored" | "already_claimed",
    /// "record": <ContinuityAwareness>}`. The race winner sees
    /// `"stored"` and their own row; race losers see
    /// `"already_claimed"` and the EXISTING row.
    ///
    /// The `(preservation_node_id, preservation_scope)` pair MUST
    /// reference an existing cirisgraph node row — a missing parent
    /// surfaces as `Conflict` (FK violation).
    #[cfg(feature = "cirislens_continuity_awareness")]
    fn continuity_record(&self, py: Python<'_>, record_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let record: crate::continuity_awareness::ContinuityAwareness =
                serde_json::from_str(record_json).map_err(|e| {
                    PyValueError::new_err(format!("ContinuityAwareness decode: {e}"))
                })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::continuity_awareness::ContinuityAwarenessService;
                        let outcome = backend
                            .record_shutdown(record)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        encode_continuity_claim_result(outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!("ClaimResult encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::continuity_awareness::sqlite::SqliteContinuityAwarenessBackend::new(
                            sq.conn_handle(),
                        );
                    runtime.block_on(async move {
                        use crate::continuity_awareness::ContinuityAwarenessService;
                        let outcome = backend
                            .record_shutdown(record)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        encode_continuity_claim_result(outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!("ClaimResult encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.17 — Get the most recent shutdown for an agent. Returns
    /// JSON-encoded `ContinuityAwareness` or `None` (Python `None`)
    /// when the agent has no recorded shutdowns.
    #[cfg(feature = "cirislens_continuity_awareness")]
    fn continuity_get_latest(&self, py: Python<'_>, agent_id: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let agent_id = agent_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::continuity_awareness::ContinuityAwarenessService;
                        let got = backend
                            .get_latest_shutdown(&agent_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match got {
                            None => Ok(None),
                            Some(r) => serde_json::to_string(&r).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("ContinuityAwareness encode: {e}"))
                            }),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::continuity_awareness::sqlite::SqliteContinuityAwarenessBackend::new(
                            sq.conn_handle(),
                        );
                    runtime.block_on(async move {
                        use crate::continuity_awareness::ContinuityAwarenessService;
                        let got = backend
                            .get_latest_shutdown(&agent_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match got {
                            None => Ok(None),
                            Some(r) => serde_json::to_string(&r).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("ContinuityAwareness encode: {e}"))
                            }),
                        }
                    })
                }
            })
        })
    }

    /// v1.5.17 — Increment `reactivation_count` on the most-recent
    /// non-terminal shutdown for `agent_id`. Returns `True` when a
    /// row was updated, `False` when the agent has only terminal
    /// shutdowns or no shutdowns (callers treat as "nothing to
    /// reactivate" — not an error).
    #[cfg(feature = "cirislens_continuity_awareness")]
    fn continuity_record_reactivation(&self, py: Python<'_>, agent_id: &str) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let agent_id = agent_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::continuity_awareness::ContinuityAwarenessService;
                        backend
                            .record_reactivation(&agent_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::continuity_awareness::sqlite::SqliteContinuityAwarenessBackend::new(
                            sq.conn_handle(),
                        );
                    runtime.block_on(async move {
                        use crate::continuity_awareness::ContinuityAwarenessService;
                        backend
                            .record_reactivation(&agent_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    // ── v1.5.18 (CIRISPersist#59 #10) — feedback_mappings cluster ──
    //
    // 3 methods wrapping FeedbackMappingService. JSON wire format
    // mirrors the deferral_reports / creation_ceremonies / continuity
    // pattern: FeedbackMapping struct decoded/encoded via serde at
    // the FFI boundary. `feedback_record` returns a JSON-encoded
    // ClaimResult (`{"outcome": "stored" | "already_claimed",
    // "feedback": <FeedbackMapping>}`).

    /// v1.5.18 — Record a feedback row. INSERT ON CONFLICT
    /// (feedback_id) DO NOTHING — write-once shape. Returns a
    /// JSON-encoded ClaimResult shape: `{"outcome": "stored" |
    /// "already_claimed", "feedback": <FeedbackMapping>}`. The race
    /// winner sees `"stored"` and their own row; race losers see
    /// `"already_claimed"` and the EXISTING row.
    ///
    /// FK semantics: when `target_thought_id` is non-NULL the
    /// referenced thought MUST exist in `cirislens.thoughts`
    /// (PG: `cirislens.thoughts`; SQLite: `cirislens_thoughts`).
    /// Missing parent surfaces as `Conflict`. NULL `target_thought_id`
    /// bypasses the FK on both backends.
    #[cfg(feature = "cirislens_feedback_mappings")]
    fn feedback_record(&self, py: Python<'_>, feedback_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let feedback: crate::feedback_mappings::FeedbackMapping =
                serde_json::from_str(feedback_json)
                    .map_err(|e| PyValueError::new_err(format!("FeedbackMapping decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::feedback_mappings::FeedbackMappingService;
                        let outcome = backend
                            .record_feedback(feedback)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        encode_feedback_claim_result(outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!("ClaimResult encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::feedback_mappings::sqlite::SqliteFeedbackMappingBackend::new(
                            sq.conn_handle(),
                        );
                    runtime.block_on(async move {
                        use crate::feedback_mappings::FeedbackMappingService;
                        let outcome = backend
                            .record_feedback(feedback)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        encode_feedback_claim_result(outcome).map_err(|e| {
                            PyRuntimeError::new_err(format!("ClaimResult encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.18 — List feedback rows attached to a specific thought.
    /// Ordered `created_at DESC`. Returns JSON-encoded
    /// `Vec<FeedbackMapping>`. Hits the partial index
    /// `feedback_mappings_thought`.
    #[cfg(feature = "cirislens_feedback_mappings")]
    fn feedback_list_for_thought(
        &self,
        py: Python<'_>,
        thought_id: &str,
        limit: i64,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let thought_id = thought_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::feedback_mappings::FeedbackMappingService;
                        let items = backend
                            .list_feedback_for_thought(&thought_id, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&items).map_err(|e| {
                            PyRuntimeError::new_err(format!("FeedbackMapping list encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::feedback_mappings::sqlite::SqliteFeedbackMappingBackend::new(
                            sq.conn_handle(),
                        );
                    runtime.block_on(async move {
                        use crate::feedback_mappings::FeedbackMappingService;
                        let items = backend
                            .list_feedback_for_thought(&thought_id, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&items).map_err(|e| {
                            PyRuntimeError::new_err(format!("FeedbackMapping list encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.18 — Filter query for feedback rows. `filter_json` is a
    /// JSON-encoded `FeedbackFilter` — supported fields:
    /// `source_message_id`, `feedback_type`, `created_after`,
    /// `created_before` (RFC 3339 timestamps for the time window).
    /// Returns JSON-encoded `Vec<FeedbackMapping>`, ordered DESC by
    /// `created_at`.
    #[cfg(feature = "cirislens_feedback_mappings")]
    fn feedback_list(&self, py: Python<'_>, filter_json: &str, limit: i64) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let filter: crate::feedback_mappings::FeedbackFilter =
                serde_json::from_str(filter_json)
                    .map_err(|e| PyValueError::new_err(format!("FeedbackFilter decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::feedback_mappings::FeedbackMappingService;
                        let items = backend
                            .list_feedback(filter, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&items).map_err(|e| {
                            PyRuntimeError::new_err(format!("FeedbackMapping list encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::feedback_mappings::sqlite::SqliteFeedbackMappingBackend::new(
                            sq.conn_handle(),
                        );
                    runtime.block_on(async move {
                        use crate::feedback_mappings::FeedbackMappingService;
                        let items = backend
                            .list_feedback(filter, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&items).map_err(|e| {
                            PyRuntimeError::new_err(format!("FeedbackMapping list encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── v1.5.19 (CIRISPersist#59 #11, FINAL) — wa_cert cluster ──
    //
    // 7 methods wrapping WaCertService. JSON wire format mirrors the
    // tasks / thoughts / ceremony / feedback patterns: WaCert struct
    // decoded/encoded via serde at the FFI boundary; lists encoded as
    // JSON arrays; set_active / update_last_login return Python
    // `bool` (true=row updated, false=missing wa_id).

    /// v1.5.19 — Idempotent upsert of a WA cert. `cert_json` is a
    /// JSON-encoded `WaCert` (24 columns). UPSERT on `wa_id` —
    /// mutables overwrite, `created` is preserved.
    ///
    /// Constraint surfaces:
    ///   * Duplicate `jwt_kid` across different `wa_id`s →
    ///     `Conflict` (UNIQUE violation).
    ///   * Non-NULL `parent_wa_id` referencing a missing parent →
    ///     `Conflict` (FK violation; PG fires at COMMIT via
    ///     DEFERRABLE, SQLite fires immediately).
    ///   * Empty `wa_id` / `name` / `pubkey` / `jwt_kid` →
    ///     `Permanent` (invalid argument).
    ///   * Unknown `role` / `token_type` (only reachable via raw
    ///     JSON typo) → serde decode error before this method runs.
    #[cfg(feature = "cirislens_wa_cert")]
    fn wa_cert_upsert(&self, py: Python<'_>, cert_json: &str) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let cert: crate::wa_cert::WaCert = serde_json::from_str(cert_json)
                .map_err(|e| PyValueError::new_err(format!("WaCert decode: {e}")))?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::wa_cert::WaCertService;
                        backend
                            .upsert_wa_cert(cert)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::wa_cert::sqlite::SqliteWaCertBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::wa_cert::WaCertService;
                        backend
                            .upsert_wa_cert(cert)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.5.19 — Point lookup by `wa_id`. Returns JSON-encoded
    /// `WaCert` or `None` when no row matches.
    #[cfg(feature = "cirislens_wa_cert")]
    fn wa_cert_get(&self, py: Python<'_>, wa_id: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let wa_id = wa_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::wa_cert::WaCertService;
                        let row = backend
                            .get_wa_cert(&wa_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match row {
                            None => Ok(None),
                            Some(r) => serde_json::to_string(&r).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("WaCert encode: {e}"))
                            }),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::wa_cert::sqlite::SqliteWaCertBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::wa_cert::WaCertService;
                        let row = backend
                            .get_wa_cert(&wa_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match row {
                            None => Ok(None),
                            Some(r) => serde_json::to_string(&r).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("WaCert encode: {e}"))
                            }),
                        }
                    })
                }
            })
        })
    }

    /// v1.5.19 — JWT verification hot path. Lookup by `jwt_kid` via
    /// the unique `wa_cert_jwt_kid` index. Returns JSON-encoded
    /// `WaCert` or `None`.
    #[cfg(feature = "cirislens_wa_cert")]
    fn wa_cert_get_by_kid(&self, py: Python<'_>, jwt_kid: &str) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let kid = jwt_kid.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::wa_cert::WaCertService;
                        let row = backend
                            .get_by_kid(&kid)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match row {
                            None => Ok(None),
                            Some(r) => serde_json::to_string(&r).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("WaCert encode: {e}"))
                            }),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::wa_cert::sqlite::SqliteWaCertBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::wa_cert::WaCertService;
                        let row = backend
                            .get_by_kid(&kid)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match row {
                            None => Ok(None),
                            Some(r) => serde_json::to_string(&r).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("WaCert encode: {e}"))
                            }),
                        }
                    })
                }
            })
        })
    }

    /// v1.5.19 — OAuth login path. Lookup by
    /// `(oauth_provider, oauth_external_id)` via the partial
    /// `wa_cert_oauth` index. Returns JSON-encoded `WaCert` or
    /// `None`.
    #[cfg(feature = "cirislens_wa_cert")]
    fn wa_cert_get_by_oauth(
        &self,
        py: Python<'_>,
        oauth_provider: &str,
        oauth_external_id: &str,
    ) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let provider = oauth_provider.to_owned();
            let ext = oauth_external_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::wa_cert::WaCertService;
                        let row = backend
                            .get_by_oauth(&provider, &ext)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match row {
                            None => Ok(None),
                            Some(r) => serde_json::to_string(&r).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("WaCert encode: {e}"))
                            }),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::wa_cert::sqlite::SqliteWaCertBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::wa_cert::WaCertService;
                        let row = backend
                            .get_by_oauth(&provider, &ext)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match row {
                            None => Ok(None),
                            Some(r) => serde_json::to_string(&r).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!("WaCert encode: {e}"))
                            }),
                        }
                    })
                }
            })
        })
    }

    /// v1.5.19 — Role-based listing. `role` is the lowercase SQL
    /// string (`"root" | "authority" | "observer"`). Returns
    /// JSON-encoded `list[WaCert]` of certs with `active = TRUE`
    /// filtered by role. Ordered `created DESC, wa_id DESC`. Hits
    /// the partial `wa_cert_role_active` index.
    #[cfg(feature = "cirislens_wa_cert")]
    fn wa_cert_list_by_role(&self, py: Python<'_>, role: &str, limit: i64) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let role_enum = crate::wa_cert::WaRole::parse_str(role).ok_or_else(|| {
                PyValueError::new_err(format!(
                    "unknown role `{role}` (expected root | authority | observer)"
                ))
            })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::wa_cert::WaCertService;
                        let items = backend
                            .list_by_role(role_enum, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&items).map_err(|e| {
                            PyRuntimeError::new_err(format!("WaCert list encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::wa_cert::sqlite::SqliteWaCertBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::wa_cert::WaCertService;
                        let items = backend
                            .list_by_role(role_enum, limit)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&items).map_err(|e| {
                            PyRuntimeError::new_err(format!("WaCert list encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.19 — Activity toggle. Sets `active` to the supplied
    /// value. Returns `True` if the row exists (idempotent for
    /// same-value toggles); `False` if `wa_id` doesn't exist.
    #[cfg(feature = "cirislens_wa_cert")]
    fn wa_cert_set_active(&self, py: Python<'_>, wa_id: &str, active: bool) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let wa_id = wa_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::wa_cert::WaCertService;
                        backend
                            .set_active(&wa_id, active)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::wa_cert::sqlite::SqliteWaCertBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::wa_cert::WaCertService;
                        backend
                            .set_active(&wa_id, active)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.5.19 — Last-login bookkeeping. `login_time_iso` is an
    /// RFC 3339 timestamp string. Returns `True` if the row was
    /// updated; `False` if `wa_id` doesn't exist.
    #[cfg(feature = "cirislens_wa_cert")]
    fn wa_cert_update_last_login(
        &self,
        py: Python<'_>,
        wa_id: &str,
        login_time_iso: &str,
    ) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let wa_id = wa_id.to_owned();
            let login_time = chrono::DateTime::parse_from_rfc3339(login_time_iso)
                .map_err(|e| {
                    PyValueError::new_err(format!(
                        "login_time_iso must be RFC 3339, got `{login_time_iso}`: {e}"
                    ))
                })?
                .with_timezone(&chrono::Utc);
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::wa_cert::WaCertService;
                        backend
                            .update_last_login(&wa_id, login_time)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::wa_cert::sqlite::SqliteWaCertBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::wa_cert::WaCertService;
                        backend
                            .update_last_login(&wa_id, login_time)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    // ── v1.5.23 (CIRISPersist#64) — service-token revocation cluster ──
    //
    // 3 methods wrapping ServiceTokenRevocationService. Absorbs
    // CIRISAgent's standalone `revoked_service_tokens.db` aiosqlite
    // file — last aiosqlite consumer in the agent. JSON wire format
    // mirrors the wa_cert pattern: RevokedServiceToken decoded /
    // encoded via serde at the FFI boundary; lists encoded as JSON
    // arrays; check_revocation returns JSON-encoded row or None.

    /// v1.5.23 — Record a service-token revocation.
    ///
    /// `revocation_json` is a JSON-encoded `RevokedServiceToken`
    /// shape: `{token_hash, revoked_at, revoked_by, reason}`. All
    /// four fields required (non-empty). Idempotent on
    /// `token_hash` (PK; `ON CONFLICT DO NOTHING` — first record
    /// wins; subsequent records with the same hash are silently
    /// ignored).
    ///
    /// Replaces CIRISAgent's standalone `revoked_service_tokens.db`
    /// aiosqlite file — last aiosqlite consumer in the agent.
    #[cfg(feature = "cirislens_service_token_revocation")]
    fn service_token_revocation_record(
        &self,
        py: Python<'_>,
        revocation_json: &str,
    ) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let revocation: crate::service_token_revocation::RevokedServiceToken =
                serde_json::from_str(revocation_json).map_err(|e| {
                    PyValueError::new_err(format!("RevokedServiceToken decode: {e}"))
                })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::service_token_revocation::ServiceTokenRevocationService;
                        backend
                            .record_revocation(revocation)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::service_token_revocation::sqlite::SqliteServiceTokenRevocationBackend::new(
                            sq.conn_handle(),
                        );
                    runtime.block_on(async move {
                        use crate::service_token_revocation::ServiceTokenRevocationService;
                        backend
                            .record_revocation(revocation)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.5.23 — List ALL revoked tokens.
    ///
    /// Returns JSON-encoded `list[RevokedServiceToken]`. Agent
    /// caches in memory on startup; this method runs once at boot.
    /// Order is unspecified (caller indexes by `token_hash`).
    #[cfg(feature = "cirislens_service_token_revocation")]
    fn service_token_revocation_list(&self, py: Python<'_>) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::service_token_revocation::ServiceTokenRevocationService;
                        let items = backend
                            .list_revocations()
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&items).map_err(|e| {
                            PyRuntimeError::new_err(format!(
                                "RevokedServiceToken list encode: {e}"
                            ))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::service_token_revocation::sqlite::SqliteServiceTokenRevocationBackend::new(
                            sq.conn_handle(),
                        );
                    runtime.block_on(async move {
                        use crate::service_token_revocation::ServiceTokenRevocationService;
                        let items = backend
                            .list_revocations()
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&items).map_err(|e| {
                            PyRuntimeError::new_err(format!(
                                "RevokedServiceToken list encode: {e}"
                            ))
                        })
                    })
                }
            })
        })
    }

    /// v1.5.23 — Point-lookup check.
    ///
    /// Returns JSON-encoded `RevokedServiceToken` row if revoked,
    /// `None` otherwise. Backed by the PRIMARY KEY index.
    #[cfg(feature = "cirislens_service_token_revocation")]
    fn service_token_revocation_check(
        &self,
        py: Python<'_>,
        token_hash: &str,
    ) -> PyResult<Option<String>> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let token_hash = token_hash.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::service_token_revocation::ServiceTokenRevocationService;
                        let row = backend
                            .check_revocation(&token_hash)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match row {
                            None => Ok(None),
                            Some(r) => serde_json::to_string(&r).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!(
                                    "RevokedServiceToken encode: {e}"
                                ))
                            }),
                        }
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::service_token_revocation::sqlite::SqliteServiceTokenRevocationBackend::new(
                            sq.conn_handle(),
                        );
                    runtime.block_on(async move {
                        use crate::service_token_revocation::ServiceTokenRevocationService;
                        let row = backend
                            .check_revocation(&token_hash)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        match row {
                            None => Ok(None),
                            Some(r) => serde_json::to_string(&r).map(Some).map_err(|e| {
                                PyRuntimeError::new_err(format!(
                                    "RevokedServiceToken encode: {e}"
                                ))
                            }),
                        }
                    })
                }
            })
        })
    }

    // ── v1.7.1 (CIRISPersist#83) — identity-sequence substrate ───
    //
    // Atomic per-identity monotonic counters. A CIRIS 3.0 runtime
    // holds one Ed25519 identity; every in-process consumer (agent,
    // NodeCore, LensCore) and every agent occurrence signs with it.
    // Anything emitting ordered signed output needs a counter
    // atomic across all of them, else the signed stream forks.
    // The bump is a single atomic UPSERT ... RETURNING.

    /// v1.7.1 — Atomically bump and return the next monotonic value
    /// for `(identity, stream)`.
    ///
    /// First call for a pair returns 1, then 2, 3, … Durable,
    /// monotonic, correct under concurrent callers across
    /// occurrences + in-process consumers sharing one Ed25519
    /// identity.
    #[cfg(feature = "cirislens_sequence")]
    fn next_sequence(&self, py: Python<'_>, identity: &str, stream: &str) -> PyResult<u64> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let identity = identity.to_owned();
            let stream = stream.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::sequence::SequenceService;
                        backend
                            .next_sequence(&identity, &stream)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::sequence::sqlite::SqliteSequenceBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::sequence::SequenceService;
                        backend
                            .next_sequence(&identity, &stream)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.7.1 — Read the last-issued value WITHOUT bumping.
    ///
    /// Returns 0 if the `(identity, stream)` pair has never been
    /// issued.
    #[cfg(feature = "cirislens_sequence")]
    fn peek_sequence(&self, py: Python<'_>, identity: &str, stream: &str) -> PyResult<u64> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let identity = identity.to_owned();
            let stream = stream.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::sequence::SequenceService;
                        backend
                            .peek_sequence(&identity, &stream)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::sequence::sqlite::SqliteSequenceBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::sequence::SequenceService;
                        backend
                            .peek_sequence(&identity, &stream)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    // ── v1.7.3 (CIRISPersist#81) occurrence registry ─────────────
    //
    // First-class occurrence registration + liveness heartbeat.
    // CIRISAgent previously inferred live occurrences by scanning
    // recent task-row activity and dedup'ing agent_occurrence_id —
    // an inference, not a registration, with no TTL and no clean
    // shutdown vs crash signal. Under the one-key model (PoB §3.2)
    // every occurrence of an agent signs with the same Ed25519
    // identity, so occurrence churn is endpoint liveness under a
    // stable identity. expires_at is TTL-based: a crashed occurrence
    // ages out without a clean deregister.

    /// v1.7.3 (CIRISPersist#81) — Register (or re-register) an
    /// occurrence with a liveness TTL.
    ///
    /// Idempotent on `occurrence_id`: re-registering refreshes
    /// `registered_at`, `last_heartbeat`, and `expires_at`.
    /// `ttl_seconds` must be > 0; `expires_at = now + ttl_seconds`.
    /// `metadata_json`, if provided, must be a JSON object/value.
    #[cfg(feature = "cirislens_occurrence")]
    #[pyo3(signature = (occurrence_id, identity, ttl_seconds, metadata_json=None))]
    fn register_occurrence(
        &self,
        py: Python<'_>,
        occurrence_id: &str,
        identity: &str,
        ttl_seconds: i64,
        metadata_json: Option<&str>,
    ) -> PyResult<()> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let occurrence_id = occurrence_id.to_owned();
            let identity = identity.to_owned();
            let metadata: Option<serde_json::Value> = match metadata_json {
                None => None,
                Some(s) => Some(serde_json::from_str(s).map_err(|e| {
                    translate_error_kind(
                        "occurrence_invalid_argument",
                        format!("metadata_json: {e}"),
                    )
                })?),
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::occurrence::OccurrenceService;
                        backend
                            .register_occurrence(&occurrence_id, &identity, ttl_seconds, metadata)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::occurrence::sqlite::SqliteOccurrenceBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::occurrence::OccurrenceService;
                        backend
                            .register_occurrence(&occurrence_id, &identity, ttl_seconds, metadata)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.7.3 (CIRISPersist#81) — Bump `last_heartbeat` + `expires_at`
    /// for an already-registered occurrence.
    ///
    /// Returns `False` if the `occurrence_id` is not in the registry
    /// (a heartbeat for an unknown occurrence is a no-op, not an
    /// error — the caller should `register_occurrence` first).
    /// `ttl_seconds` must be > 0.
    #[cfg(feature = "cirislens_occurrence")]
    fn heartbeat_occurrence(
        &self,
        py: Python<'_>,
        occurrence_id: &str,
        ttl_seconds: i64,
    ) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let occurrence_id = occurrence_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::occurrence::OccurrenceService;
                        backend
                            .heartbeat_occurrence(&occurrence_id, ttl_seconds)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::occurrence::sqlite::SqliteOccurrenceBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::occurrence::OccurrenceService;
                        backend
                            .heartbeat_occurrence(&occurrence_id, ttl_seconds)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.7.3 (CIRISPersist#81) — Clean shutdown: remove the
    /// occurrence row immediately, don't wait for TTL expiry.
    ///
    /// Returns `True` if a row was removed, `False` if it wasn't
    /// registered. Idempotent.
    #[cfg(feature = "cirislens_occurrence")]
    fn deregister_occurrence(&self, py: Python<'_>, occurrence_id: &str) -> PyResult<bool> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let occurrence_id = occurrence_id.to_owned();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::occurrence::OccurrenceService;
                        backend
                            .deregister_occurrence(&occurrence_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::occurrence::sqlite::SqliteOccurrenceBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::occurrence::OccurrenceService;
                        backend
                            .deregister_occurrence(&occurrence_id)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })
        })
    }

    /// v1.7.3 (CIRISPersist#81) — List currently-live occurrences for
    /// `identity` (rows whose `expires_at > now`).
    ///
    /// Returns a JSON-encoded array of `OccurrenceRecord`, ordered by
    /// `occurrence_id` ASC. Expired rows are filtered out (not
    /// deleted — read-only). All occurrences of one agent share a
    /// single Ed25519 identity; this is endpoint liveness under that
    /// stable identity.
    #[cfg(feature = "cirislens_occurrence")]
    fn list_live_occurrences(&self, py: Python<'_>, identity: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let identity = identity.to_owned();
            let records = py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::occurrence::OccurrenceService;
                        backend
                            .list_live_occurrences(&identity)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::occurrence::sqlite::SqliteOccurrenceBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::occurrence::OccurrenceService;
                        backend
                            .list_live_occurrences(&identity)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))
                    })
                }
            })?;
            serde_json::to_string(&records).map_err(|e| {
                translate_error_kind("occurrence_internal", format!("encode records: {e}"))
            })
        })
    }

    // ── v1.6.4 (CIRISPersist#70) legacy-graph migration ──────────
    //
    // Absorbs the agent-side `tools/ops/migrate_to_persist.py`
    // psycopg2/sqlite3 reader. The LAST raw-SQL gap in CIRISAgent
    // 2.9.0 — with this method wired, the agent drops both deps
    // from production `requirements.txt`. Options + stats cross
    // the FFI as JSON strings (matching the rest of the v1.x
    // dispatch shape); errors thread through `translate_error_kind`
    // (legacy_migration_backend → Transient,
    // legacy_migration_invalid_argument → Permanent).

    /// v1.6.4 (CIRISPersist#70) — Absorb the A0a legacy-graph
    /// migration. Reads `public.graph_nodes` + `public.graph_edges`
    /// (legacy 2.8.x agent schema) and re-upserts each row into
    /// `cirisgraph.nodes` + `cirisgraph.edges` via the existing
    /// typed-write surface.
    ///
    /// `options_json` is a JSON-encoded `LegacyMigrationOptions`:
    ///   `{"dry_run": bool, "attributes_cap_bytes": int | null,
    ///     "legacy_schema": "public", "stop_after_errors": int | null}`.
    /// All fields optional; `{}` decodes to safe defaults.
    ///
    /// Returns a JSON-encoded `LegacyMigrationStats`:
    ///   `{"outcome": "ok" | "errors" | "partial",
    ///     "nodes_read": int, "nodes_written": int,
    ///     "nodes_skipped_already_present": int,
    ///     "nodes_skipped_too_large": int,
    ///     "edges_read": int, ..., "errors": int,
    ///     "first_error_at_node_id": str | null}`.
    ///
    /// Idempotent: re-running is safe (existing substrate rows
    /// skip via `expected_version` / PK semantics). Replaces the
    /// agent-side psycopg2/sqlite3 reader so CIRISAgent#763 Phase 5
    /// can close.
    #[cfg(feature = "cirislens_legacy_migration")]
    fn run_legacy_graph_migration(&self, py: Python<'_>, options_json: &str) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let options: crate::legacy_migration::LegacyMigrationOptions =
                serde_json::from_str(options_json).map_err(|e| {
                    PyValueError::new_err(format!("LegacyMigrationOptions decode: {e}"))
                })?;
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let backend = pg.clone();
                    runtime.block_on(async move {
                        use crate::legacy_migration::LegacyMigrationService;
                        let stats = backend
                            .run_legacy_graph_migration(options)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&stats).map_err(|e| {
                            PyRuntimeError::new_err(format!("LegacyMigrationStats encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let backend =
                        crate::legacy_migration::sqlite::SqliteLegacyMigrationBackend::new(
                            sq.conn_handle(),
                        );
                    runtime.block_on(async move {
                        use crate::legacy_migration::LegacyMigrationService;
                        let stats = backend
                            .run_legacy_graph_migration(options)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&stats).map_err(|e| {
                            PyRuntimeError::new_err(format!("LegacyMigrationStats encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── v1.2.0 (CIRISPersist#48) maintenance cluster ─────────────
    //
    // Absorbs the operations side of CIRISAgent's
    // DatabaseMaintenanceService. Reports cross the FFI as JSON
    // strings so the agent-side shim can decode them
    // field-for-field via `pydantic.model_validate_json`. Errors
    // thread through `translate_error_kind` (maintenance_backend
    // → Transient, maintenance_invalid_argument → Permanent,
    // maintenance_internal → Permanent).

    /// v1.2.0 (CIRISPersist#48) — Run a substrate-wide VACUUM
    /// (PG: `VACUUM ANALYZE` via dedicated non-transactional client;
    /// SQLite: `VACUUM; ANALYZE;` via spawn_blocking). Returns a
    /// JSON-encoded `VacuumReport`.
    fn maintenance_vacuum(&self, py: Python<'_>) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let svc =
                        crate::maintenance::postgres::PostgresMaintenanceBackend::new(pg.clone());
                    runtime.block_on(async move {
                        use crate::maintenance::MaintenanceService;
                        let report = svc
                            .vacuum_substrate()
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&report).map_err(|e| {
                            PyRuntimeError::new_err(format!("VacuumReport encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let svc =
                        crate::maintenance::sqlite::SqliteMaintenanceBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::maintenance::MaintenanceService;
                        let report = svc
                            .vacuum_substrate()
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&report).map_err(|e| {
                            PyRuntimeError::new_err(format!("VacuumReport encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.2.0 (CIRISPersist#48) — Archive expired rows across
    /// substrate modules (telemetry, secrets access_log, closed
    /// incidents, expired federation_keys). `window_seconds=None`
    /// uses the substrate-default cutoff per module; passing an
    /// integer overrides with `ArchiveWindow::Custom { seconds }`.
    /// Returns a JSON-encoded `ArchiveReport`.
    #[pyo3(signature = (window_seconds=None))]
    fn maintenance_archive_expired(
        &self,
        py: Python<'_>,
        window_seconds: Option<u64>,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let window = match window_seconds {
                None => crate::maintenance::ArchiveWindow::SubstrateDefault,
                Some(seconds) => crate::maintenance::ArchiveWindow::Custom { seconds },
            };
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let svc =
                        crate::maintenance::postgres::PostgresMaintenanceBackend::new(pg.clone());
                    runtime.block_on(async move {
                        use crate::maintenance::MaintenanceService;
                        let report = svc
                            .archive_expired(window)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&report).map_err(|e| {
                            PyRuntimeError::new_err(format!("ArchiveReport encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let svc =
                        crate::maintenance::sqlite::SqliteMaintenanceBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::maintenance::MaintenanceService;
                        let report = svc
                            .archive_expired(window)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&report).map_err(|e| {
                            PyRuntimeError::new_err(format!("ArchiveReport encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.2.0 (CIRISPersist#48) — Prune audit-chain entries for
    /// `tenant` strictly older than `before` (RFC 3339). Returns a
    /// JSON-encoded `PruneReport`. **Stub in v1.2.0** — always
    /// returns `entries_removed: 0, new_anchor_id: None`. Real
    /// semantics depend on CIRISAgent#760 Counter-RII review-window
    /// guidance.
    fn maintenance_prune_audit_chain(
        &self,
        py: Python<'_>,
        tenant: &str,
        before: &str,
    ) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            let tenant = tenant.to_owned();
            let before_dt = chrono::DateTime::parse_from_rfc3339(before)
                .map_err(|e| {
                    PyValueError::new_err(format!(
                        "maintenance_prune_audit_chain: `before` must be RFC 3339: {e}"
                    ))
                })?
                .with_timezone(&chrono::Utc);
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let svc =
                        crate::maintenance::postgres::PostgresMaintenanceBackend::new(pg.clone());
                    runtime.block_on(async move {
                        use crate::maintenance::MaintenanceService;
                        let report = svc
                            .prune_audit_chain(&tenant, before_dt)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&report).map_err(|e| {
                            PyRuntimeError::new_err(format!("PruneReport encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let svc =
                        crate::maintenance::sqlite::SqliteMaintenanceBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::maintenance::MaintenanceService;
                        let report = svc
                            .prune_audit_chain(&tenant, before_dt)
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&report).map_err(|e| {
                            PyRuntimeError::new_err(format!("PruneReport encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    /// v1.2.0 (CIRISPersist#48) — Run the maintenance umbrella:
    /// vacuum → archive_expired(SubstrateDefault). Returns a
    /// JSON-encoded `MaintenanceReport`. Prune is intentionally not
    /// part of the umbrella — callers run it on a tenant-scoped
    /// schedule separately.
    fn maintain(&self, py: Python<'_>) -> PyResult<String> {
        self.ensure_usable()?;
        catch_panic(|| {
            let runtime = self.runtime.clone();
            py.detach(move || match &self.backend {
                BackendDispatch::Postgres(pg) => {
                    let svc =
                        crate::maintenance::postgres::PostgresMaintenanceBackend::new(pg.clone());
                    runtime.block_on(async move {
                        use crate::maintenance::MaintenanceService;
                        let report = svc
                            .maintain()
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&report).map_err(|e| {
                            PyRuntimeError::new_err(format!("MaintenanceReport encode: {e}"))
                        })
                    })
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(sq) => {
                    let svc =
                        crate::maintenance::sqlite::SqliteMaintenanceBackend::new(sq.conn_handle());
                    runtime.block_on(async move {
                        use crate::maintenance::MaintenanceService;
                        let report = svc
                            .maintain()
                            .await
                            .map_err(|e| translate_error_kind(e.kind(), e.to_string()))?;
                        serde_json::to_string(&report).map_err(|e| {
                            PyRuntimeError::new_err(format!("MaintenanceReport encode: {e}"))
                        })
                    })
                }
            })
        })
    }

    // ── v2.7.0 (CIRISPersist#109) — PyCapsule cross-module accessors ──
    //
    // PyO3 `#[pyclass]` registration is per-extension-module. When
    // `ciris_persist.abi3.so` and a sibling consumer wheel (e.g.
    // `ciris_edge.abi3.so`) each statically compile persist's source,
    // each module registers its own `PyTypeInfo` for `PyEngine` and any
    // `#[pyclass]` handle struct. Python's type-identity check
    // (`isinstance(x, PyEngine)`) fails across modules even though the
    // underlying Rust structs are bit-identical from the same git tag —
    // the production cohabitation init failure that CIRISEdge#22
    // reported.
    //
    // The pure-Rust accessors `federation_directory()` / `outbound_queue()`
    // / `keyring_signer()` (#95, Option-B `pub fn`s) work for sibling
    // cdylibs that share persist's compiled-in type info. For
    // Python-orchestrated cohabitation across separately-built wheels,
    // `PyCapsule` is the right primitive — it's an opaque pointer with
    // a name tag, no `PyTypeInfo` check, and the consumer extracts the
    // wrapped value via `unsafe { capsule.reference() }`.
    //
    // The longer-term endpoint where Python disappears (#106 ships in
    // 2.6.0) collapses these PyO3 layers entirely; until then, capsules
    // are the bridge.

    /// v2.7.0 (CIRISPersist#109) — cross-module accessor for the
    /// federation directory. Returns a `PyCapsule` wrapping the shared
    /// `Arc<dyn FederationDirectory>` the engine singleton holds.
    ///
    /// Consumer pattern (CIRISEdge):
    /// ```ignore
    /// let cap: Bound<PyCapsule> = engine
    ///     .call_method0("federation_directory_capsule")?
    ///     .downcast_into()?;
    /// let arc: &Arc<dyn FederationDirectory> = unsafe { cap.reference() };
    /// // Now call FederationDirectory trait methods directly in Rust.
    /// ```
    ///
    /// Name tag: `ciris_persist::federation_directory`.
    #[pyo3(name = "federation_directory_capsule")]
    fn federation_directory_capsule_py<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Bound<'py, pyo3::types::PyCapsule>> {
        let arc: Arc<dyn crate::federation::FederationDirectory> = match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.clone(),
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.clone(),
        };
        let name = std::ffi::CString::new("ciris_persist::federation_directory")
            .expect("static name has no NUL bytes");
        pyo3::types::PyCapsule::new(py, arc, Some(name)).map_err(|e| {
            PyErr::new::<LensQueryError, _>(format!("federation_directory_capsule: {e}"))
        })
    }

    /// v2.7.0 (CIRISPersist#109) — cross-module accessor for the
    /// outbound queue substrate. Returns a `PyCapsule` wrapping the
    /// shared `BackendDispatch` enum; consumer matches the variant and
    /// calls [`OutboundQueue`](crate::outbound::OutboundQueue) trait
    /// methods on the concrete backend.
    ///
    /// `OutboundQueue` is RPITIT (`impl Future + Send` returns) and
    /// therefore NOT object-safe — `Arc<dyn OutboundQueue>` won't
    /// compile. Wrapping `BackendDispatch` is the same dispatch-enum
    /// pattern the Option-B pub-fn (#95) uses.
    ///
    /// Name tag: `ciris_persist::outbound_queue`.
    #[pyo3(name = "outbound_queue_capsule")]
    fn outbound_queue_capsule_py<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Bound<'py, pyo3::types::PyCapsule>> {
        let dispatch = match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => crate::engine::BackendDispatch::Postgres(b.clone()),
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => crate::engine::BackendDispatch::Sqlite(b.clone()),
        };
        let name = std::ffi::CString::new("ciris_persist::outbound_queue")
            .expect("static name has no NUL bytes");
        pyo3::types::PyCapsule::new(py, dispatch, Some(name))
            .map_err(|e| PyErr::new::<LensQueryError, _>(format!("outbound_queue_capsule: {e}")))
    }

    /// v2.7.0 (CIRISPersist#109) — cross-module accessor for the
    /// federation keyring signer parts. Returns a `PyCapsule` wrapping
    /// the same `KeyringSignerHandle` the Option-B pub-fn (#95)
    /// returns: `Arc<dyn HardwareSigner>` + optional
    /// `Arc<dyn PqcSigner>` + `key_id`. Consumer reuses the host's
    /// already-loaded signer rather than re-bootstrapping the keyring
    /// (docs/COHABITATION.md rule 1).
    ///
    /// Name tag: `ciris_persist::keyring_signer`.
    #[pyo3(name = "keyring_signer_capsule")]
    fn keyring_signer_capsule_py<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Bound<'py, pyo3::types::PyCapsule>> {
        let handle = crate::signing::KeyringSignerHandle {
            signer: self.signer.clone(),
            pqc_signer: self.local_signer.as_ref().and_then(|ls| ls.pqc_signer()),
            key_id: self.signer_key_id.clone(),
        };
        let name = std::ffi::CString::new("ciris_persist::keyring_signer")
            .expect("static name has no NUL bytes");
        pyo3::types::PyCapsule::new(py, handle, Some(name))
            .map_err(|e| PyErr::new::<LensQueryError, _>(format!("keyring_signer_capsule: {e}")))
    }

    /// v2.8.0 (CIRISPersist#111) — cross-cdylib accessor for the tokio
    /// runtime handle. Returns a `PyCapsule` wrapping a clone of the
    /// engine's own `tokio::runtime::Handle`.
    ///
    /// Counterpart to #109's type-identity fix at the **statics** layer.
    /// When persist is linked into BOTH `ciris_persist.abi3.so` AND a
    /// consumer wheel (e.g. `ciris_edge.abi3.so`, which pulls persist
    /// as a Cargo rlib), each `.so` gets its own copy of persist's
    /// `static ENGINE_SINGLETON`. The consumer's copy is never
    /// populated, so `ciris_persist::current_runtime_handle()` from
    /// the consumer's `.so` always returns `None` in production
    /// cross-wheel deployments — the failure CIRISConformance v0.10.0's
    /// cohabitation gate caught with the `init_handshake` error.
    ///
    /// Sourcing the handle from `self.runtime` (rather than calling
    /// the free `current_runtime_handle()`) sidesteps the static
    /// entirely — `self` already IS the singleton holder in this
    /// extension module's view, and `Runtime::handle()` clones cheaply.
    ///
    /// Consumer pattern (CIRISEdge):
    /// ```ignore
    /// let cap: Bound<PyCapsule> = engine
    ///     .call_method0("runtime_handle_capsule")?
    ///     .downcast_into()?;
    /// // SAFETY: persist v2.8.0+'s runtime_handle_capsule wraps
    /// // tokio::runtime::Handle with name tag
    /// // "ciris_persist::runtime_handle"; the Cargo pin floor enforces.
    /// let handle: &tokio::runtime::Handle = unsafe {
    ///     cap.pointer_checked(Some(c"ciris_persist::runtime_handle"))?
    ///         .cast()
    ///         .as_ref()
    /// };
    /// let _enter = handle.enter();
    /// ```
    ///
    /// Name tag: `ciris_persist::runtime_handle`.
    #[pyo3(name = "runtime_handle_capsule")]
    fn runtime_handle_capsule_py<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Bound<'py, pyo3::types::PyCapsule>> {
        let handle: tokio::runtime::Handle = self.runtime.handle().clone();
        let name = std::ffi::CString::new("ciris_persist::runtime_handle")
            .expect("static name has no NUL bytes");
        pyo3::types::PyCapsule::new(py, handle, Some(name))
            .map_err(|e| PyErr::new::<LensQueryError, _>(format!("runtime_handle_capsule: {e}")))
    }

    /// v2.11.0 (CIRISPersist#115) — cross-module accessor for the blob
    /// storage substrate. Returns a `PyCapsule` wrapping the shared
    /// `BackendDispatch` enum; consumer matches the variant and calls
    /// [`BlobStorage`](crate::federation::blobs::BlobStorage) trait
    /// methods on the concrete backend.
    ///
    /// `BlobStorage` is RPITIT (`impl Future + Send` returns) and
    /// therefore NOT object-safe — `Arc<dyn BlobStorage>` won't
    /// compile. Wrapping `BackendDispatch` is the same dispatch-enum
    /// pattern `outbound_queue_capsule` (#109) uses.
    ///
    /// Unblocks CIRISNodeCore#11 (`install_node_mode_serving`'s PyO3
    /// wrapper) — same cross-module identity problem the rest of the
    /// capsule family solves.
    ///
    /// Name tag: `ciris_persist::blob_storage`.
    #[pyo3(name = "blob_storage_capsule")]
    fn blob_storage_capsule_py<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Bound<'py, pyo3::types::PyCapsule>> {
        let dispatch = match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => crate::engine::BackendDispatch::Postgres(b.clone()),
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => crate::engine::BackendDispatch::Sqlite(b.clone()),
        };
        let name = std::ffi::CString::new("ciris_persist::blob_storage")
            .expect("static name has no NUL bytes");
        pyo3::types::PyCapsule::new(py, dispatch, Some(name))
            .map_err(|e| PyErr::new::<LensQueryError, _>(format!("blob_storage_capsule: {e}")))
    }
}

/// v1.5.9 (CIRISPersist#59 #1) — encode a [`ClaimResult<Task>`] onto the
/// `{"outcome": "stored" | "already_claimed", "task": <Task>}` JSON wire
/// shape. Mirrors `ClaimResultWire` from `src/secrets/wire.rs` but lives
/// adjacent to the FFI surface because the tasks substrate has no
/// HTTP server peer to share a wire crate with.
#[cfg(feature = "cirislens_tasks")]
fn encode_claim_result(
    outcome: crate::ClaimResult<crate::tasks::Task>,
) -> Result<String, serde_json::Error> {
    let (label, task) = match outcome {
        crate::ClaimResult::Stored(t) => ("stored", t),
        crate::ClaimResult::AlreadyClaimed(t) => ("already_claimed", t),
    };
    let wire = serde_json::json!({
        "outcome": label,
        "task": task,
    });
    serde_json::to_string(&wire)
}

/// v1.5.14 (CIRISPersist#59 #6) — encode a
/// [`ClaimResult<DeferralReport>`] onto the
/// `{"outcome": "stored" | "already_claimed", "report":
/// <DeferralReport>}` JSON wire shape. Same template as
/// [`encode_claim_result`] for tasks but with a `report` key instead
/// of `task` — the deferral_reports substrate has no HTTP server peer
/// to share a wire crate with, so the helper lives adjacent to the
/// FFI surface.
#[cfg(feature = "cirislens_deferral_reports")]
fn encode_deferral_claim_result(
    outcome: crate::ClaimResult<crate::deferral_reports::DeferralReport>,
) -> Result<String, serde_json::Error> {
    let (label, report) = match outcome {
        crate::ClaimResult::Stored(r) => ("stored", r),
        crate::ClaimResult::AlreadyClaimed(r) => ("already_claimed", r),
    };
    let wire = serde_json::json!({
        "outcome": label,
        "report": report,
    });
    serde_json::to_string(&wire)
}

/// v1.5.16 (CIRISPersist#59 #8) — encode a
/// [`ClaimResult<CreationCeremony>`] onto the
/// `{"outcome": "stored" | "already_claimed", "ceremony":
/// <CreationCeremony>}` JSON wire shape. Same template as the
/// tasks / deferral helpers — keyed `"ceremony"` because the
/// substrate's row shape is named [`CreationCeremony`].
#[cfg(feature = "cirislens_creation_ceremonies")]
fn encode_ceremony_claim_result(
    outcome: crate::ClaimResult<crate::creation_ceremonies::CreationCeremony>,
) -> Result<String, serde_json::Error> {
    let (label, ceremony) = match outcome {
        crate::ClaimResult::Stored(c) => ("stored", c),
        crate::ClaimResult::AlreadyClaimed(c) => ("already_claimed", c),
    };
    let wire = serde_json::json!({
        "outcome": label,
        "ceremony": ceremony,
    });
    serde_json::to_string(&wire)
}

/// v1.5.17 (CIRISPersist#59 #9) — encode a
/// [`ClaimResult<ContinuityAwareness>`] onto the
/// `{"outcome": "stored" | "already_claimed", "record":
/// <ContinuityAwareness>}` JSON wire shape. Same template as the
/// tasks / deferral / ceremony helpers — keyed `"record"` because
/// the substrate's row shape is named [`ContinuityAwareness`]
/// (record-shaped, not a named ceremony / report).
#[cfg(feature = "cirislens_continuity_awareness")]
fn encode_continuity_claim_result(
    outcome: crate::ClaimResult<crate::continuity_awareness::ContinuityAwareness>,
) -> Result<String, serde_json::Error> {
    let (label, record) = match outcome {
        crate::ClaimResult::Stored(r) => ("stored", r),
        crate::ClaimResult::AlreadyClaimed(r) => ("already_claimed", r),
    };
    let wire = serde_json::json!({
        "outcome": label,
        "record": record,
    });
    serde_json::to_string(&wire)
}

/// v1.5.18 (CIRISPersist#59 #10) — encode a
/// [`ClaimResult<FeedbackMapping>`] onto the
/// `{"outcome": "stored" | "already_claimed", "feedback":
/// <FeedbackMapping>}` JSON wire shape. Same template as the
/// tasks / deferral / ceremony / continuity helpers — keyed
/// `"feedback"` because the substrate's row shape is named
/// [`FeedbackMapping`].
#[cfg(feature = "cirislens_feedback_mappings")]
fn encode_feedback_claim_result(
    outcome: crate::ClaimResult<crate::feedback_mappings::FeedbackMapping>,
) -> Result<String, serde_json::Error> {
    let (label, feedback) = match outcome {
        crate::ClaimResult::Stored(f) => ("stored", f),
        crate::ClaimResult::AlreadyClaimed(f) => ("already_claimed", f),
    };
    let wire = serde_json::json!({
        "outcome": label,
        "feedback": feedback,
    });
    serde_json::to_string(&wire)
}

/// v0.8.3 — Bridge `incident::Error` → `PyErr` at the FFI boundary.
///
/// v1.0.0 (CIRISPersist#193) — superseded for substrate-pyo3 dispatch by
/// [`translate_error_kind`], which maps `Error::kind()` tokens onto the
/// retry-typed exception hierarchy (NotFound / Conflict / Transient /
/// Permanent). Kept around because callers outside the substrate-pyo3
/// surface still link against it; the verify / attestation /
/// federation-keys methods (still PG-only in v1.0.0) and v1.1.0 will
/// decide whether to retire or thread it.
#[cfg(feature = "cirisincident")]
#[allow(dead_code)]
fn incident_err_to_py(e: crate::incident::Error) -> PyErr {
    let kind = e.kind();
    tracing::warn!(error = %e, kind = kind, "incident error");
    match e {
        crate::incident::Error::InvalidArgument(_)
        | crate::incident::Error::InvalidTransition(_)
        | crate::incident::Error::NotFound(_) => PyValueError::new_err(kind),
        crate::incident::Error::Backend(_)
        | crate::incident::Error::NotImplemented(_)
        | crate::incident::Error::Internal(_) => PyRuntimeError::new_err(kind),
    }
}

/// v0.8.2 — Bridge `telemetry::Error` → `PyErr` at the FFI boundary.
///
/// v1.0.0 — superseded for substrate-pyo3 dispatch by
/// [`translate_error_kind`]; see the comment on `incident_err_to_py`.
#[cfg(feature = "telemetry")]
#[allow(dead_code)]
fn telemetry_err_to_py(e: crate::telemetry::Error) -> PyErr {
    let kind = e.kind();
    tracing::warn!(error = %e, kind = kind, "telemetry error");
    match e {
        crate::telemetry::Error::InvalidArgument(_)
        | crate::telemetry::Error::LockContention(_) => PyValueError::new_err(kind),
        crate::telemetry::Error::Backend(_)
        | crate::telemetry::Error::NotImplemented(_)
        | crate::telemetry::Error::Internal(_) => PyRuntimeError::new_err(kind),
    }
}

/// v0.8.1 — Bridge `audit::Error` → `PyErr` at the FFI boundary.
/// InvalidArgument / ChainIntegrity / Signature / Conflict / NotFound
/// → ValueError (caller-fault 4xx-shape). Backend / NotImplemented /
/// Internal → RuntimeError (server-fault 5xx-shape).
/// v1.0.0 — superseded for substrate-pyo3 dispatch by
/// [`translate_error_kind`]; see the comment on `incident_err_to_py`.
/// v1.5.0 Phase H — re-wired as the audit-error mapper for the new
/// trust-grant / Merkle PyO3 methods (`current_sth`,
/// `trust_grant_inclusion_proof`, …).
#[cfg(feature = "cirisaudit")]
fn audit_err_to_py(e: crate::audit::Error) -> PyErr {
    let kind = e.kind();
    tracing::warn!(error = %e, kind = kind, "audit error");
    match e {
        crate::audit::Error::InvalidArgument(_)
        | crate::audit::Error::ChainIntegrity(_)
        | crate::audit::Error::Signature(_)
        | crate::audit::Error::Conflict(_)
        | crate::audit::Error::NotFound(_) => PyValueError::new_err(kind),
        crate::audit::Error::Backend(_)
        | crate::audit::Error::NotImplemented(_)
        | crate::audit::Error::Internal(_)
        | crate::audit::Error::Merkle(_)
        | crate::audit::Error::TrustGrant(_) => PyRuntimeError::new_err(kind),
    }
}

/// v1.5.0 Phase H — Bridge [`crate::federation::emit::EmitError`] →
/// `PyErr` at the FFI boundary. Audit-side failures route via
/// [`audit_err_to_py`] (preserves the stable kind tokens); caller-
/// fault validation → `PyValueError` (4xx); signer / post-emit
/// missing-artifact errors → `PyRuntimeError` (5xx; config-fault).
#[cfg(feature = "cirisaudit")]
fn emit_err_to_py(e: crate::federation::emit::EmitError) -> PyErr {
    use crate::federation::emit::EmitError;
    tracing::warn!(error = %e, "federation emit error");
    match e {
        EmitError::Audit(inner) => audit_err_to_py(inner),
        EmitError::InvalidArgument(_) => PyValueError::new_err(format!("{e}")),
        EmitError::Signing(_) => PyRuntimeError::new_err(format!("{e}")),
        EmitError::PostEmitSthMissing { .. } | EmitError::PostEmitProjectionMissing { .. } => {
            PyRuntimeError::new_err(format!("{e}"))
        }
    }
}

/// v1.5.0 Phase H — Bridge [`crate::federation::read::ReadError`] →
/// `PyErr`. Audit-side failures route through [`audit_err_to_py`];
/// missing artifacts → `PyKeyError` (Python convention for "key not
/// found" lookups, distinct from 4xx caller-fault validation
/// failures).
///
/// Distinct from the lens-reads [`read_err_to_py`] (bridges
/// `crate::read::Error`); kept under its own name to avoid the
/// import-path collision.
#[cfg(feature = "cirisaudit")]
fn federation_read_err_to_py(e: crate::federation::read::ReadError) -> PyErr {
    use crate::federation::read::ReadError;
    use pyo3::exceptions::PyKeyError;
    tracing::warn!(error = %e, "federation read error");
    match e {
        ReadError::Audit(inner) => audit_err_to_py(inner),
        ReadError::NotFound(_) => PyKeyError::new_err(format!("{e}")),
    }
}

/// v1.5.0 Phase I — Bridge [`crate::federation::backfill::BackfillError`]
/// → `PyErr` at the FFI boundary. Emit-side failures route through
/// [`emit_err_to_py`]; audit-side failures through [`audit_err_to_py`];
/// caller-fault validation → `PyValueError`.
#[cfg(feature = "cirisaudit")]
fn backfill_err_to_py(e: crate::federation::backfill::BackfillError) -> PyErr {
    use crate::federation::backfill::BackfillError;
    tracing::warn!(error = %e, "federation backfill error");
    match e {
        BackfillError::Emit(inner) => emit_err_to_py(inner),
        BackfillError::Audit(inner) => audit_err_to_py(inner),
        BackfillError::InvalidArgument(_) => PyValueError::new_err(format!("{e}")),
    }
}

/// v1.5.0 Phase I — Encode a
/// [`crate::federation::backfill::BackfillReport`] as a JSON string
/// for the PyO3 caller. Wraps the encode failure in `PyRuntimeError`
/// (5xx) — JSON encoding of three `u64`s shouldn't fail, but the
/// surface follows the same shape as the other Phase H encoders.
#[cfg(feature = "cirisaudit")]
fn backfill_report_to_json(
    report: &crate::federation::backfill::BackfillReport,
) -> PyResult<String> {
    let v = serde_json::json!({
        "rows_scanned": report.rows_scanned,
        "events_emitted": report.events_emitted,
        "already_present": report.already_present,
    });
    serde_json::to_string(&v)
        .map_err(|e| PyRuntimeError::new_err(format!("BackfillReport encode: {e}")))
}

/// v1.5.0 Phase H — Wire-shape adapter for
/// [`crate::federation::read::TrustGrantInclusionProof`]. The
/// substrate struct doesn't derive `Serialize` (its
/// `leaf_canonical_bytes: Vec<u8>` would default to a JSON array of
/// bytes, which isn't what verifiers want — they expect a base64
/// string matching the rest of the federation wire codec). This
/// helper builds the `serde_json::Value` payload Phase H ships
/// through the PyO3 surface.
#[cfg(feature = "cirisaudit")]
fn trust_grant_inclusion_proof_to_wire(
    bundle: &crate::federation::read::TrustGrantInclusionProof,
) -> serde_json::Value {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    serde_json::json!({
        "sth": bundle.sth,
        "merkle_proof": bundle.merkle_proof,
        "leaf_canonical_bytes": B64.encode(&bundle.leaf_canonical_bytes),
    })
}

/// v0.8.0 — Bridge `graph::Error` → `PyErr` at the FFI boundary.
/// InvalidArgument / NotAuthorized / Conflict / NotFound → ValueError
/// (caller-fault 4xx-shape). Backend / NotImplemented / Internal →
/// RuntimeError (server-fault 5xx-shape). The stable kind() token
/// crosses the boundary; verbose detail goes to tracing only.
/// v1.0.0 — superseded for substrate-pyo3 dispatch by
/// [`translate_error_kind`]; see the comment on `incident_err_to_py`.
#[cfg(feature = "cirisgraph")]
#[allow(dead_code)]
fn cirisgraph_err_to_py(e: crate::graph::Error) -> PyErr {
    let kind = e.kind();
    tracing::warn!(error = %e, kind = kind, "cirisgraph error");
    match e {
        crate::graph::Error::InvalidArgument(_)
        | crate::graph::Error::AttributesTooLarge { .. }
        | crate::graph::Error::NotAuthorized(_)
        | crate::graph::Error::Conflict(_)
        | crate::graph::Error::NotFound(_) => PyValueError::new_err(kind),
        crate::graph::Error::Backend(_)
        | crate::graph::Error::NotImplemented(_)
        | crate::graph::Error::Internal(_) => PyRuntimeError::new_err(kind),
    }
}

/// v0.7.0 — Bridge `cirisnode::Error` → `PyErr` at the FFI boundary.
/// InvalidArgument / NotAuthorized / Signature / Conflict / NotFound →
/// ValueError (caller-fault 4xx-shape). Backend / NotImplemented /
/// Internal → RuntimeError (server-fault 5xx-shape). The stable kind()
/// token crosses the boundary; verbose detail goes to tracing only.
/// v1.0.0 — superseded for substrate-pyo3 dispatch by
/// [`translate_error_kind`]; see the comment on `incident_err_to_py`.
#[cfg(feature = "cirisnode")]
#[allow(dead_code)]
fn cirisnode_err_to_py(e: crate::cirisnode::Error) -> PyErr {
    let kind = e.kind();
    tracing::warn!(error = %e, kind = kind, "cirisnode error");
    match e {
        crate::cirisnode::Error::InvalidArgument(_)
        | crate::cirisnode::Error::NotAuthorized(_)
        | crate::cirisnode::Error::Signature(_)
        | crate::cirisnode::Error::Conflict(_)
        | crate::cirisnode::Error::NotFound(_)
        | crate::cirisnode::Error::FederationAnnouncementAuthorityMismatch(_) => {
            PyValueError::new_err(kind)
        }
        crate::cirisnode::Error::Backend(_)
        | crate::cirisnode::Error::NotImplemented(_)
        | crate::cirisnode::Error::Internal(_) => PyRuntimeError::new_err(kind),
    }
}

/// v0.6.1 — Bridge `secrets::SecretsError` → `PyErr` at the FFI
/// boundary. InvalidArgument / NotAuthorized / NotFound → ValueError
/// (caller-fault 4xx-shape). Crypto / Backend / Internal /
/// HardwareKeyUnavailable / RotationConflict → RuntimeError
/// (server-fault 5xx-shape).
/// v1.0.0 — superseded for substrate-pyo3 dispatch by
/// [`translate_error_kind`]; see the comment on `incident_err_to_py`.
#[cfg(feature = "secrets")]
#[allow(dead_code)]
fn secrets_err_to_py(e: crate::secrets::SecretsError) -> PyErr {
    use crate::secrets::SecretsError;
    match e {
        SecretsError::InvalidArgument(_)
        | SecretsError::NotAuthorized(_)
        | SecretsError::NotFound(_) => PyValueError::new_err(e.to_string()),
        SecretsError::Crypto(_)
        | SecretsError::Backend(_)
        | SecretsError::Internal(_)
        | SecretsError::HardwareKeyUnavailable(_)
        | SecretsError::RotationConflict(_) => PyRuntimeError::new_err(e.to_string()),
    }
}

/// v0.4.2 — Bridge `signing::LocalSignerError` → `PyErr` at the
/// FFI boundary. Same discipline as `federation_err_to_py` and
/// `outbound_err_to_py`: typed variants → ValueError (caller-fault
/// 4xx-shape) or RuntimeError (server-fault 5xx-shape); verbose
/// detail goes to tracing.
fn local_signer_err_to_py(e: crate::signing::LocalSignerError) -> PyErr {
    use crate::signing::LocalSignerError;
    tracing::warn!(error = %e, "local signer error");
    match e {
        LocalSignerError::SeedRead { .. } | LocalSignerError::PqcSeedLoad { .. } => {
            PyRuntimeError::new_err(format!("{e}"))
        }
        LocalSignerError::SeedLength { .. }
        | LocalSignerError::PqcConfigInconsistent
        | LocalSignerError::PqcNotConfigured => PyValueError::new_err(format!("{e}")),
        LocalSignerError::PqcSign(_) => PyRuntimeError::new_err(format!("{e}")),
    }
}

/// v0.4.0 — outbound::Error → PyErr at the FFI boundary. Same
/// discipline as federation_err_to_py: stable kind tokens cross
/// boundary, structured detail goes to tracing.
fn outbound_err_to_py(e: crate::outbound::Error) -> PyErr {
    let kind = e.kind();
    tracing::warn!(error = %e, kind = kind, "outbound error");
    match e {
        crate::outbound::Error::InvalidArgument(_) => PyValueError::new_err(kind),
        crate::outbound::Error::NotFound(_) => PyValueError::new_err(kind),
        crate::outbound::Error::InvalidTransition(_) => PyValueError::new_err(kind),
        crate::outbound::Error::Backend(_) => PyRuntimeError::new_err(kind),
    }
}

/// v0.4.0 — OutboundRow → Python dict. Mirrors the column set on
/// `cirislens.edge_outbound_queue` 1:1; bytes columns return as
/// Python bytes.
fn outbound_row_to_pydict<'py>(
    py: Python<'py>,
    row: &crate::outbound::OutboundRow,
) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("queue_id", &row.queue_id)?;
    d.set_item("sender_key_id", &row.sender_key_id)?;
    d.set_item("destination_key_id", &row.destination_key_id)?;
    d.set_item("message_type", &row.message_type)?;
    d.set_item("edge_schema_version", &row.edge_schema_version)?;
    d.set_item(
        "envelope_bytes",
        pyo3::types::PyBytes::new(py, &row.envelope_bytes),
    )?;
    d.set_item(
        "body_sha256",
        pyo3::types::PyBytes::new(py, &row.body_sha256),
    )?;
    d.set_item("body_size_bytes", row.body_size_bytes)?;
    d.set_item("status", row.status.as_str())?;
    d.set_item("enqueued_at", row.enqueued_at.to_rfc3339())?;
    d.set_item("next_attempt_after", row.next_attempt_after.to_rfc3339())?;
    d.set_item(
        "last_attempt_at",
        row.last_attempt_at.map(|t| t.to_rfc3339()),
    )?;
    d.set_item(
        "transport_delivered_at",
        row.transport_delivered_at.map(|t| t.to_rfc3339()),
    )?;
    d.set_item("delivered_at", row.delivered_at.map(|t| t.to_rfc3339()))?;
    d.set_item("abandoned_at", row.abandoned_at.map(|t| t.to_rfc3339()))?;
    d.set_item("abandoned_reason", row.abandoned_reason.map(|r| r.as_str()))?;
    d.set_item("attempt_count", row.attempt_count)?;
    d.set_item("max_attempts", row.max_attempts)?;
    d.set_item("ttl_seconds", row.ttl_seconds)?;
    d.set_item("last_error_class", row.last_error_class.as_deref())?;
    d.set_item("last_error_detail", row.last_error_detail.as_deref())?;
    d.set_item("last_transport", row.last_transport.as_deref())?;
    d.set_item("requires_ack", row.requires_ack)?;
    d.set_item("ack_timeout_seconds", row.ack_timeout_seconds)?;
    d.set_item(
        "ack_envelope_bytes",
        row.ack_envelope_bytes
            .as_deref()
            .map(|b| pyo3::types::PyBytes::new(py, b)),
    )?;
    d.set_item(
        "ack_received_at",
        row.ack_received_at.map(|t| t.to_rfc3339()),
    )?;
    d.set_item("claimed_until", row.claimed_until.map(|t| t.to_rfc3339()))?;
    d.set_item("claimed_by", row.claimed_by.as_deref())?;
    Ok(d)
}

fn outbound_rows_to_pylist<'py>(
    py: Python<'py>,
    rows: Vec<crate::outbound::OutboundRow>,
) -> PyResult<pyo3::Bound<'py, pyo3::types::PyList>> {
    let list = pyo3::types::PyList::empty(py);
    for r in rows {
        list.append(outbound_row_to_pydict(py, &r)?)?;
    }
    Ok(list)
}

/// v0.4.1 — Parse the policy string + optional soft_freshness window
/// into a `HybridPolicy`. Shared by `Engine.verify_hybrid` and
/// `Engine.verify_hybrid_via_directory` so the parsing rules are
/// declared in one place.
fn parse_hybrid_policy(
    policy: &str,
    soft_freshness_window_seconds: Option<f64>,
) -> PyResult<crate::verify::HybridPolicy> {
    use crate::verify::HybridPolicy;
    match policy {
        "strict" => Ok(HybridPolicy::Strict),
        "ed25519_fallback" => Ok(HybridPolicy::Ed25519Fallback),
        "soft_freshness" => {
            let secs = soft_freshness_window_seconds.ok_or_else(|| {
                PyValueError::new_err(
                    "soft_freshness policy requires soft_freshness_window_seconds",
                )
            })?;
            if !secs.is_finite() || secs < 0.0 {
                return Err(PyValueError::new_err(
                    "soft_freshness_window_seconds must be a non-negative finite float",
                ));
            }
            Ok(HybridPolicy::SoftFreshness {
                window: std::time::Duration::from_secs_f64(secs),
            })
        }
        other => Err(PyValueError::new_err(format!(
            "unknown policy {other:?} (expected strict / ed25519_fallback / soft_freshness)"
        ))),
    }
}

/// v1.3.0 (CIRISPersist#46 + #47) — Wire shape for the `TrustFilter`
/// JSON dict that `federation_list_trusted_keys` accepts from Python.
/// All fields optional; `include_expired` defaults to false via
/// `#[serde(default)]`.
#[derive(Debug, Clone, Default, serde::Deserialize)]
struct TrustFilterWire {
    #[serde(default)]
    trust_type: Option<String>,
    #[serde(default)]
    trust_relationship: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    include_expired: bool,
}

/// v2.10.0 (CIRISPersist#114) — Wire shape for the `GoalsFilter` JSON
/// dict that `cirisnode_list_goals_json` accepts from Python. All
/// fields optional; `include_retired` defaults to false via
/// `#[serde(default)]` — F-3 hot path skips retired by default.
#[derive(Debug, Clone, Default, serde::Deserialize)]
struct GoalsFilterWire {
    #[serde(default)]
    declared_by_key_id: Option<String>,
    #[serde(default)]
    m1_dimension: Option<String>,
    #[serde(default)]
    scope_kind: Option<String>,
    #[serde(default)]
    cohort_id: Option<String>,
    #[serde(default)]
    include_retired: bool,
}

/// v0.4.0 — Adapter implementing `PublicKeyDirectory` against the
/// PyO3 Engine's backend + tokio runtime. Used by `Engine.verify_trace`
/// and `Engine.verify_hybrid_via_directory` to drive
/// `verify_*_via_directory` without requiring the caller to look up
/// the key separately.
///
/// v1.5.1 — generic over the concrete backend type so the same adapter
/// drives both PG and SQLite arms. Each call site passes its
/// dispatch-arm Arc; no enum wrapper needed because the lookup signature
/// is synchronous.
struct TraceKeyDirectory<B>
where
    B: crate::store::Backend + Send + Sync + 'static,
{
    backend: Arc<B>,
    runtime: Arc<Runtime>,
}

impl<B> crate::verify::PublicKeyDirectory for TraceKeyDirectory<B>
where
    B: crate::store::Backend + Send + Sync + 'static,
{
    fn lookup(
        &self,
        key_id: &str,
    ) -> Result<Option<ed25519_dalek::VerifyingKey>, Box<dyn std::error::Error + Send + Sync>> {
        let backend = self.backend.clone();
        let key_id = key_id.to_owned();
        // verify_trace_via_directory's PublicKeyDirectory trait is
        // synchronous; bridge to the async backend via block_on on
        // the engine's tokio runtime. Same shape used by
        // receive_and_persist's internal verify path.
        let key_opt = self
            .runtime
            .block_on(async move { backend.lookup_public_key(&key_id).await });
        key_opt.map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e.to_string()))
    }
}

/// v0.4.0 — Canonicalize a federation envelope value (registration_
/// envelope / attestation_envelope / revocation_envelope) via
/// PythonJsonDumpsCanonicalizer. Used by the verify_signed_*
/// methods to produce the bytes the scrub signature was computed
/// over.
fn canonicalize_envelope_value(envelope: &serde_json::Value) -> PyResult<Vec<u8>> {
    use crate::verify::canonical::Canonicalizer;
    crate::verify::PythonJsonDumpsCanonicalizer
        .canonicalize_value(envelope)
        .map_err(|e| PyRuntimeError::new_err(format!("canonicalize_envelope_value: {e}")))
}

/// v0.3.5 — TraceLevel → wire-format string. Same shape as the
/// trace_level_str helper in `src/store/postgres.rs` but free-standing
/// for use from this FFI module without re-exposing storage internals.
fn trace_level_str(t: crate::schema::TraceLevel) -> &'static str {
    match t {
        crate::schema::TraceLevel::Generic => "generic",
        crate::schema::TraceLevel::Detailed => "detailed",
        crate::schema::TraceLevel::FullTraces => "full_traces",
    }
}

/// Bridge `federation::Error` → `PyErr` at the FFI boundary.
/// Mission constraint (THREAT_MODEL.md AV-15): structured detail
/// goes to tracing; the Python exception carries the stable kind
/// token. Lens HTTP layer maps token → status code.
/// v0.5.0 (CIRISPersist#23) — Bridge `read::Error` → `PyErr` at the
/// FFI boundary. Federation read primitives. Same discipline as
/// `derived_err_to_py` / `outbound_err_to_py`: stable kind tokens
/// cross the boundary, structured detail goes to tracing.
///
/// AV-15 / AV-43: kind tokens are closed-set `&'static str`; no
/// attacker-controlled strings leak across the boundary.
fn read_err_to_py(e: crate::read::Error) -> PyErr {
    let kind = e.kind();
    tracing::warn!(error = %e, kind = kind, "read error");
    match e {
        crate::read::Error::InvalidArgument(_) => PyValueError::new_err(kind),
        crate::read::Error::InvalidCursor(_) => PyValueError::new_err(kind),
        crate::read::Error::Backend(_) => PyRuntimeError::new_err(kind),
        crate::read::Error::NotImplemented(_) => PyRuntimeError::new_err(kind),
    }
}

/// v0.4.3 (CIRISPersist#18) — Bridge `derived::Error` → `PyErr` at
/// the FFI boundary. Same discipline as the other err_to_py
/// helpers: stable kind tokens cross the boundary, structured
/// detail goes to tracing.
fn derived_err_to_py(e: crate::derived::Error) -> PyErr {
    let kind = e.kind();
    tracing::warn!(error = %e, kind = kind, "derived error");
    match e {
        crate::derived::Error::InvalidArgument(_) => PyValueError::new_err(kind),
        crate::derived::Error::Conflict(_) => PyValueError::new_err(kind),
        crate::derived::Error::CalibrationVersionNotFound(_) => PyValueError::new_err(kind),
        crate::derived::Error::Backend(_) => PyRuntimeError::new_err(kind),
        crate::derived::Error::NotImplemented(_) => PyRuntimeError::new_err(kind),
    }
}

/// v0.4.3 (CIRISPersist#18) — Encode raw bytes to base64 STANDARD
/// for the verify_hybrid_via_directory call (which takes &str).
fn base64_encode(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    B64.encode(bytes)
}

fn federation_err_to_py(e: crate::federation::Error) -> PyErr {
    let kind = e.kind();
    tracing::warn!(error = %e, kind = kind, "federation error");
    match e {
        // Caller-fault → ValueError (4xx).
        crate::federation::Error::InvalidArgument(_)
        | crate::federation::Error::SignatureInvalid(_) => PyValueError::new_err(kind),
        // Conflict → ValueError too; lens-side maps to 409.
        crate::federation::Error::Conflict(_) => PyValueError::new_err(kind),
        // v2.4.0 (CIRISPersist#102 Ask 3) — admission-gate rejections
        // are caller-fault malformed-content; ValueError (4xx).
        crate::federation::Error::AccordDimensionRequiresAccordHolder { .. }
        | crate::federation::Error::DimensionRejected { .. } => PyValueError::new_err(kind),
        // v2.5.0 (CIRISPersist#102 Ask 4 + Ask 8) — all the new
        // admission-hook rejections are caller-fault malformed-
        // content; ValueError (4xx).
        crate::federation::Error::EnvelopeSchemaViolation { .. }
        | crate::federation::Error::AccordHolderRequiresAttestationEvidence { .. }
        | crate::federation::Error::HardwareTypeNotAccepted { .. }
        | crate::federation::Error::AttestationEvidenceIncomplete { .. }
        | crate::federation::Error::AttestationEvidenceStale { .. } => PyValueError::new_err(kind),
        // Rate-limit → RuntimeError; lens maps to 429.
        crate::federation::Error::RateLimited { .. } => PyRuntimeError::new_err(kind),
        // Server-fault → RuntimeError (5xx).
        crate::federation::Error::Backend(_) => PyRuntimeError::new_err(kind),
    }
}

/// v2.3 (CIRISPersist#103) — translate a [`crate::federation::BlobError`]
/// into the right typed Python exception. Mirrors the
/// [`federation_err_to_py`] discipline: caller-fault → ValueError;
/// server-fault → RuntimeError. The `kind()` string travels in the
/// message for `translate_error_kind`-style retry-policy routing if
/// the consumer wants it.
fn blob_err_to_py(e: crate::federation::BlobError) -> PyErr {
    let kind = e.kind();
    tracing::warn!(error = %e, kind = kind, "blob storage error");
    match e {
        crate::federation::BlobError::HashMismatch { .. }
        | crate::federation::BlobError::InlineSizeExceeded { .. }
        | crate::federation::BlobError::InvalidArgument(_)
        | crate::federation::BlobError::AttestationEmissionFailed(_) => PyValueError::new_err(kind),
        crate::federation::BlobError::Backend(_) => PyRuntimeError::new_err(kind),
    }
}

/// v2.3 (CIRISPersist#103) — decoded `put_blob_json` payload (Rust-side
/// representation). The PyO3 wrapper deserializes the wire shape into
/// this struct and hands it to the backend's `put_blob`.
struct PutBlobPayload {
    sha256: [u8; 32],
    body: crate::federation::BlobBody,
    media_type: Option<String>,
    attestation: crate::federation::PutBlobAttestation,
}

/// v2.3 (CIRISPersist#103) — Wire-shape representation for `put_blob_json`.
/// Inline bytes ride as base64 standard-alphabet strings.
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum PutBlobWireBody {
    /// `{"inline": "<base64>"}` — base64-decoded into the inline byte
    /// payload.
    Inline(String),
    /// `{"external": {"uri": ..., "size_bytes": N, "media_type": ...}}`
    External(crate::federation::ExternalRef),
}

#[derive(serde::Deserialize)]
struct PutBlobAttestationWire {
    attesting_key_id: String,
    attestation_id: String,
    original_content_hash_hex: String,
    scrub_signature_classical: String,
    #[serde(default)]
    scrub_signature_pqc: Option<String>,
    scrub_key_id: String,
    scrub_timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(serde::Deserialize)]
struct PutBlobJsonWire {
    sha256: String,
    body: PutBlobWireBody,
    #[serde(default)]
    media_type: Option<String>,
    attestation: PutBlobAttestationWire,
}

/// v2.3 (CIRISPersist#103) — Decode the `put_blob_json` payload into
/// the trait-call argument shape.
fn parse_put_blob_payload(json: &str) -> PyResult<PutBlobPayload> {
    let wire: PutBlobJsonWire = serde_json::from_str(json)
        .map_err(|e| PyValueError::new_err(format!("put_blob_json decode: {e}")))?;
    let sha = parse_sha256_hex(&wire.sha256)?;
    let body = match wire.body {
        PutBlobWireBody::Inline(b64) => {
            use base64::engine::general_purpose::STANDARD as B64;
            use base64::Engine as _;
            let bytes = B64.decode(&b64).map_err(|e| {
                PyValueError::new_err(format!("put_blob_json inline base64 decode: {e}"))
            })?;
            crate::federation::BlobBody::Inline(bytes)
        }
        PutBlobWireBody::External(e) => crate::federation::BlobBody::External(e),
    };
    let attestation = crate::federation::PutBlobAttestation {
        attesting_key_id: wire.attestation.attesting_key_id,
        attestation_id: wire.attestation.attestation_id,
        original_content_hash_hex: wire.attestation.original_content_hash_hex,
        scrub_signature_classical: wire.attestation.scrub_signature_classical,
        scrub_signature_pqc: wire.attestation.scrub_signature_pqc,
        scrub_key_id: wire.attestation.scrub_key_id,
        scrub_timestamp: wire.attestation.scrub_timestamp,
    };
    Ok(PutBlobPayload {
        sha256: sha,
        body,
        media_type: wire.media_type,
        attestation,
    })
}

/// v2.3 (CIRISPersist#103) — parse a 64-char hex string into a
/// `[u8; 32]` SHA-256.
fn parse_sha256_hex(hex_str: &str) -> PyResult<[u8; 32]> {
    let v = hex::decode(hex_str)
        .map_err(|e| PyValueError::new_err(format!("sha256 hex decode: {e}")))?;
    if v.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "sha256 must be 32 bytes ({} hex chars), got {} bytes",
            64,
            v.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

/// v2.3 (CIRISPersist#103) — encode a [`crate::federation::BlobBody`]
/// back onto the JSON wire shape (with inline bytes as base64).
fn encode_blob_body_json(body: &crate::federation::BlobBody) -> PyResult<String> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let value = match body {
        crate::federation::BlobBody::Inline(bytes) => {
            serde_json::json!({ "inline": B64.encode(bytes) })
        }
        crate::federation::BlobBody::External(ext) => serde_json::json!({
            "external": ext,
        }),
    };
    serde_json::to_string(&value)
        .map_err(|e| PyRuntimeError::new_err(format!("BlobBody JSON encode: {e}")))
}

/// v0.3.1 — Cold-path PQC sign helper for the auto-fire flow after
/// federation writes (CIRISPersist#10). Computes the bound-signature
/// input (canonical_envelope_bytes || classical_sig_bytes), invokes
/// the local ML-DSA-65 signer, and returns base64-encoded
/// (pubkey, signature) ready for `attach_*_pqc_signature`.
///
/// Per the writer contract in `migrations/postgres/lens/V004__federation_directory.sql`:
/// "kick off IMMEDIATELY after Ed25519 sign, not delayed/batched/scheduled,
/// just off the synchronous request path." This helper runs on the
/// tokio task spawned by put_public_key / put_attestation /
/// put_revocation; the synchronous Python call has already returned.
async fn cold_path_pqc_sign(
    signer: &dyn PqcSigner,
    envelope: &serde_json::Value,
    classical_sig_b64: &str,
) -> Result<(String, String), String> {
    use crate::verify::canonical::Canonicalizer;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    let canonical = PythonJsonDumpsCanonicalizer
        .canonicalize_value(envelope)
        .map_err(|e| format!("canonicalize: {e}"))?;
    let classical_sig = B64
        .decode(classical_sig_b64)
        .map_err(|e| format!("classical_sig base64 decode: {e}"))?;

    // Bound signature: PQC covers (data || classical_sig). Same shape
    // as CIRISVerify's HybridSignature spec — prevents stripping
    // attacks where an attacker who breaks Ed25519 could otherwise
    // replace the PQC signature with their own.
    let mut input = Vec::with_capacity(canonical.len() + classical_sig.len());
    input.extend_from_slice(&canonical);
    input.extend_from_slice(&classical_sig);

    let pqc_sig = signer
        .sign(&input)
        .await
        .map_err(|e| format!("sign: {e}"))?;
    let pubkey = signer
        .public_key()
        .await
        .map_err(|e| format!("public_key: {e}"))?;
    Ok((B64.encode(&pubkey), B64.encode(&pqc_sig)))
}

/// v0.3.2 (CIRISPersist#11) — counts for one table's slice of a sweep.
struct SweepCounts {
    scanned: i64,
    signed: i64,
    failed: i64,
}

/// v0.3.2 (CIRISPersist#11) — aggregate sweep result across the three
/// federation tables. Returned by `run_pqc_sweep_inner` and surfaced
/// to Python as a dict by `Engine.run_pqc_sweep`.
struct SweepSummary {
    total_scanned: i64,
    total_signed: i64,
    total_failed: i64,
    keys: SweepCounts,
    attestations: SweepCounts,
    revocations: SweepCounts,
}

/// v0.3.2 (CIRISPersist#11) — Drive a single-batch sweep across the
/// three federation tables. Reused by both `Engine.run_pqc_sweep`
/// (synchronous from Python) and the constructor's `pqc_sweep_on_init`
/// auto-fire (background tokio task at end of `Engine::new`).
///
/// v1.5.1 — generic over [`crate::federation::FederationDirectory`] so
/// the same sweep primitive drives both PG and SQLite backends. The
/// trait already exposes `list_hybrid_pending_*` + `attach_*_pqc_signature`
/// on every concrete backend; this function just wires them together.
async fn run_pqc_sweep_inner<B>(
    backend: &Arc<B>,
    signer: &dyn PqcSigner,
    batch_size: i64,
) -> SweepSummary
where
    B: crate::federation::FederationDirectory + Send + Sync + 'static,
{
    let keys = sweep_keys(backend, signer, batch_size).await;
    let attestations = sweep_attestations(backend, signer, batch_size).await;
    let revocations = sweep_revocations(backend, signer, batch_size).await;
    let total_scanned = keys.scanned + attestations.scanned + revocations.scanned;
    let total_signed = keys.signed + attestations.signed + revocations.signed;
    let total_failed = keys.failed + attestations.failed + revocations.failed;
    SweepSummary {
        total_scanned,
        total_signed,
        total_failed,
        keys,
        attestations,
        revocations,
    }
}

async fn sweep_keys<B>(backend: &Arc<B>, signer: &dyn PqcSigner, batch_size: i64) -> SweepCounts
where
    B: crate::federation::FederationDirectory + Send + Sync + 'static,
{
    let rows = match backend.list_hybrid_pending_keys(batch_size).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "sweep_keys: list_hybrid_pending_keys failed");
            return SweepCounts {
                scanned: 0,
                signed: 0,
                failed: 0,
            };
        }
    };
    let scanned = rows.len() as i64;
    let mut signed = 0i64;
    let mut failed = 0i64;
    for row in rows {
        match cold_path_pqc_sign(signer, &row.envelope, &row.classical_sig_b64).await {
            Ok((pubkey_b64, pqc_sig_b64)) => match backend
                .attach_key_pqc_signature(&row.id, &pubkey_b64, &pqc_sig_b64)
                .await
            {
                Ok(()) => signed += 1,
                Err(crate::federation::Error::Conflict(_)) => {
                    tracing::debug!(
                        key_id = row.id.as_str(),
                        "sweep: row hybrid-completed by another worker"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        key_id = row.id.as_str(),
                        error = %e,
                        "sweep: attach_key_pqc_signature failed"
                    );
                    failed += 1;
                }
            },
            Err(e) => {
                tracing::warn!(
                    key_id = row.id.as_str(),
                    error = %e,
                    "sweep: cold_path_pqc_sign failed"
                );
                failed += 1;
            }
        }
    }
    SweepCounts {
        scanned,
        signed,
        failed,
    }
}

async fn sweep_attestations<B>(
    backend: &Arc<B>,
    signer: &dyn PqcSigner,
    batch_size: i64,
) -> SweepCounts
where
    B: crate::federation::FederationDirectory + Send + Sync + 'static,
{
    let rows = match backend.list_hybrid_pending_attestations(batch_size).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "sweep_attestations: list failed");
            return SweepCounts {
                scanned: 0,
                signed: 0,
                failed: 0,
            };
        }
    };
    let scanned = rows.len() as i64;
    let mut signed = 0i64;
    let mut failed = 0i64;
    for row in rows {
        match cold_path_pqc_sign(signer, &row.envelope, &row.classical_sig_b64).await {
            Ok((_pubkey_b64, pqc_sig_b64)) => match backend
                .attach_attestation_pqc_signature(&row.id, &pqc_sig_b64)
                .await
            {
                Ok(()) => signed += 1,
                Err(crate::federation::Error::Conflict(_)) => {
                    tracing::debug!(
                        attestation_id = row.id.as_str(),
                        "sweep: row hybrid-completed by another worker"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        attestation_id = row.id.as_str(),
                        error = %e,
                        "sweep: attach_attestation_pqc_signature failed"
                    );
                    failed += 1;
                }
            },
            Err(e) => {
                tracing::warn!(
                    attestation_id = row.id.as_str(),
                    error = %e,
                    "sweep: cold_path_pqc_sign failed"
                );
                failed += 1;
            }
        }
    }
    SweepCounts {
        scanned,
        signed,
        failed,
    }
}

async fn sweep_revocations<B>(
    backend: &Arc<B>,
    signer: &dyn PqcSigner,
    batch_size: i64,
) -> SweepCounts
where
    B: crate::federation::FederationDirectory + Send + Sync + 'static,
{
    let rows = match backend.list_hybrid_pending_revocations(batch_size).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "sweep_revocations: list failed");
            return SweepCounts {
                scanned: 0,
                signed: 0,
                failed: 0,
            };
        }
    };
    let scanned = rows.len() as i64;
    let mut signed = 0i64;
    let mut failed = 0i64;
    for row in rows {
        match cold_path_pqc_sign(signer, &row.envelope, &row.classical_sig_b64).await {
            Ok((_pubkey_b64, pqc_sig_b64)) => match backend
                .attach_revocation_pqc_signature(&row.id, &pqc_sig_b64)
                .await
            {
                Ok(()) => signed += 1,
                Err(crate::federation::Error::Conflict(_)) => {
                    tracing::debug!(
                        revocation_id = row.id.as_str(),
                        "sweep: row hybrid-completed by another worker"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        revocation_id = row.id.as_str(),
                        error = %e,
                        "sweep: attach_revocation_pqc_signature failed"
                    );
                    failed += 1;
                }
            },
            Err(e) => {
                tracing::warn!(
                    revocation_id = row.id.as_str(),
                    error = %e,
                    "sweep: cold_path_pqc_sign failed"
                );
                failed += 1;
            }
        }
    }
    SweepCounts {
        scanned,
        signed,
        failed,
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

/// v0.1.14 — resolve the cohabitation bootstrap lock path.
///
/// The lock file is created on first call; subsequent calls reuse
/// it. Path priority:
/// 1. `${CIRIS_DATA_DIR}/.persist-bootstrap.lock` — the canonical
///    location, co-located with the SoftwareSigner seed (when in
///    use) so the lock and the keyring share durability semantics.
/// 2. `/tmp/ciris-persist-bootstrap.lock` — fallback for
///    deployments that haven't set CIRIS_DATA_DIR. Acceptable
///    because the lock is ephemeral by design (only held during
///    bootstrap; auto-released on process exit).
///
/// On Linux containers without persistent volumes, the `/tmp`
/// fallback still serializes bootstrap *within a container's
/// lifetime* — exactly the v0.1.14 cohabitation guarantee. Cross-
/// container coordination is out of scope (that's an orchestrator-
/// level concern; see `docs/COHABITATION.md`).
fn bootstrap_lock_path() -> std::path::PathBuf {
    if let Ok(d) = std::env::var("CIRIS_DATA_DIR") {
        std::path::PathBuf::from(d).join(".persist-bootstrap.lock")
    } else {
        std::path::PathBuf::from("/tmp/ciris-persist-bootstrap.lock")
    }
}

/// v0.1.14 — acquire the cohabitation bootstrap lock.
///
/// Returns the locked `File` handle so the caller can drop it once
/// `get_platform_signer()` has returned. POSIX `flock` is
/// auto-released on FD close, including process exit and panic —
/// so a stuck holder isn't a normal failure mode.
///
/// Blocks until the lock is acquired. Workers 2..N on a multi-
/// worker deployment briefly wait here while worker 1 bootstraps;
/// typical wait is <1s on cold-start, <50ms warm.
fn acquire_bootstrap_lock() -> std::io::Result<Option<std::fs::File>> {
    use fs4::fs_std::FileExt;
    let path = bootstrap_lock_path();
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(
                lock_path = %path.display(),
                error = %e,
                "bootstrap lock dir creation failed — proceeding without advisory lock"
            );
            return Ok(None);
        }
    }
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(
                lock_path = %path.display(),
                error = %e,
                "bootstrap lock file open failed — proceeding without advisory lock"
            );
            return Ok(None);
        }
    };
    match file.lock_exclusive() {
        Ok(()) => {
            tracing::debug!(
                lock_path = %path.display(),
                "ciris-persist: bootstrap flock acquired"
            );
            Ok(Some(file))
        }
        Err(e)
            if matches!(
                e.raw_os_error(),
                Some(libc::EPERM) | Some(libc::ENOTSUP) | Some(libc::ENOSYS)
            ) =>
        {
            tracing::warn!(
                lock_path = %path.display(),
                os_error = e.raw_os_error(),
                "bootstrap flock unsupported on this platform — proceeding without advisory lock"
            );
            Ok(Some(file))
        }
        Err(e) => Err(e),
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

/// v2.0.5 — boot-time audit self-verification summary.
#[cfg(feature = "cirisaudit")]
struct BootAuditSummary {
    tenants_checked: usize,
    total_entries_walked: usize,
    all_ok: bool,
    breaks: Vec<BootAuditBreak>,
}

#[cfg(feature = "cirisaudit")]
struct BootAuditBreak {
    tenant_id: String,
    at_sequence: i64,
    reason: String,
}

/// v2.0.5 — walk every tenant's audit chain. Independent of any
/// external registry: persist validates its own chain integrity.
#[cfg(feature = "cirisaudit")]
async fn boot_audit_self_verify(backend: &BackendDispatch) -> Result<BootAuditSummary, String> {
    use crate::audit::AuditService;
    let tenant_ids: Vec<String> = match backend {
        BackendDispatch::Postgres(pg) => pg
            .pool()
            .get()
            .await
            .map_err(|e| format!("pool: {e}"))?
            .query("SELECT DISTINCT tenant_id FROM cirislens_audit_log", &[])
            .await
            .map_err(|e| format!("list tenants: {e}"))?
            .iter()
            .map(|r| r.get::<_, String>(0))
            .collect(),
        #[cfg(feature = "sqlite")]
        BackendDispatch::Sqlite(sq) => {
            let conn = sq.conn_handle();
            tokio::task::spawn_blocking(move || {
                let guard = conn.blocking_lock();
                let mut stmt = guard
                    .prepare("SELECT DISTINCT tenant_id FROM cirislens_audit_log")
                    .map_err(|e| format!("list tenants: {e}"))?;
                let rows = stmt
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(|e| format!("list tenants query: {e}"))?;
                let mut ids = Vec::new();
                for r in rows {
                    ids.push(r.map_err(|e| format!("tenant row: {e}"))?);
                }
                Ok::<_, String>(ids)
            })
            .await
            .map_err(|e| format!("spawn_blocking: {e}"))??
        }
    };

    let mut summary = BootAuditSummary {
        tenants_checked: tenant_ids.len(),
        total_entries_walked: 0,
        all_ok: true,
        breaks: Vec::new(),
    };

    for tid in &tenant_ids {
        let verif = match backend {
            BackendDispatch::Postgres(pg) => pg.verify_chain(tid, 1, None).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(sq) => {
                let audit = crate::audit::sqlite::SqliteAuditBackend::new(sq.conn_handle());
                audit.verify_chain(tid, 1, None).await
            }
        };
        match verif {
            Ok(v) => {
                summary.total_entries_walked += v.entries_walked;
                if let crate::audit::types::ChainVerifyOutcome::Break {
                    at_sequence,
                    reason,
                    detail,
                } = v.outcome
                {
                    summary.all_ok = false;
                    summary.breaks.push(BootAuditBreak {
                        tenant_id: tid.clone(),
                        at_sequence,
                        reason: format!("{reason:?}: {detail}"),
                    });
                }
            }
            Err(e) => {
                summary.all_ok = false;
                summary.breaks.push(BootAuditBreak {
                    tenant_id: tid.clone(),
                    at_sequence: 0,
                    reason: format!("verify_chain error: {e}"),
                });
            }
        }
    }

    Ok(summary)
}

/// v2.7.0 (CIRISPersist#104) — build an
/// [`crate::federation::AuditChainProof`] for a given `trace_id`.
///
/// Locates the row in `cirislens_audit_log` whose `subject_id` matches
/// `trace_id` (the closest analog persist's audit schema has to a
/// trace reference — the audit-log row's `subject_id` is the foreign
/// key persist uses to bind audit entries to the artifacts they
/// describe). Then walks the tenant's chain from sequence 1 up to the
/// matching row's `sequence_number`, returning each entry in order.
///
/// If multiple audit rows reference the same `trace_id` (cross-tenant
/// — AV-51 keeps them isolated), the proof chain for the FIRST
/// tenant encountered is returned. Empty proof (`entries: []`) when
/// no row matches.
///
/// `head_signature` is populated from
/// [`crate::audit::AuditService::current_sth`] when the tenant's
/// Merkle hook is installed; encoded as a JSON string of the
/// [`ciris_verify_core::transparency::SignedTreeHead`]. `None` when
/// no STH has been signed yet (Merkle hook disabled, or chain empty).
#[cfg(feature = "cirisaudit")]
async fn build_audit_chain_proof(
    backend: &BackendDispatch,
    trace_id: &str,
) -> Result<crate::federation::AuditChainProof, String> {
    use crate::audit::AuditService;
    use crate::federation::{AuditChainEntry, AuditChainProof};

    // Step 1 — locate (tenant_id, sequence_number) of the row whose
    // subject_id == trace_id. We pull the lowest sequence_number
    // because if the same trace_id is referenced multiple times
    // (re-tries / supersessions) we want the EARLIEST one — that's
    // the "first time persist saw this trace" anchor the UI cares
    // about.
    let located: Option<(String, i64)> = match backend {
        BackendDispatch::Postgres(pg) => {
            let client = pg.pool().get().await.map_err(|e| format!("pool: {e}"))?;
            let rows = client
                .query(
                    "SELECT tenant_id, sequence_number \
                     FROM cirislens.audit_log \
                     WHERE subject_id = $1 \
                     ORDER BY sequence_number ASC \
                     LIMIT 1",
                    &[&trace_id],
                )
                .await
                .map_err(|e| format!("locate trace: {e}"))?;
            rows.first().map(|r| {
                (
                    r.get::<_, String>("tenant_id"),
                    r.get::<_, i64>("sequence_number"),
                )
            })
        }
        #[cfg(feature = "sqlite")]
        BackendDispatch::Sqlite(sq) => {
            let conn = sq.conn_handle();
            let trace_id_owned = trace_id.to_owned();
            tokio::task::spawn_blocking(move || -> Result<Option<(String, i64)>, String> {
                let guard = conn.blocking_lock();
                let mut stmt = guard
                    .prepare(
                        "SELECT tenant_id, sequence_number \
                             FROM cirislens_audit_log \
                             WHERE subject_id = ?1 \
                             ORDER BY sequence_number ASC \
                             LIMIT 1",
                    )
                    .map_err(|e| format!("prepare locate: {e}"))?;
                let row = stmt
                    .query_row([&trace_id_owned], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                    })
                    .map(Some)
                    .or_else(|e| match e {
                        rusqlite::Error::QueryReturnedNoRows => Ok(None),
                        other => Err(format!("locate trace: {other}")),
                    })?;
                Ok(row)
            })
            .await
            .map_err(|e| format!("spawn_blocking: {e}"))??
        }
    };

    let Some((tenant_id, anchor_seq)) = located else {
        // No audit row references this trace_id — empty proof.
        return Ok(AuditChainProof {
            trace_id: trace_id.to_owned(),
            entries: Vec::new(),
            head_signature: None,
        });
    };

    // Step 2 — walk audit_log from sequence 1 up to anchor_seq for
    // the matched tenant. Mirrors `audit_verify_all_chains`'s
    // per-backend dispatch.
    let entries: Vec<AuditChainEntry> = match backend {
        BackendDispatch::Postgres(pg) => {
            let client = pg.pool().get().await.map_err(|e| format!("pool: {e}"))?;
            let rows = client
                .query(
                    "SELECT sequence_number, tenant_id, action_type, recorded_at, \
                            entry_hash, prev_hash \
                     FROM cirislens.audit_log \
                     WHERE tenant_id = $1 \
                       AND sequence_number BETWEEN 1 AND $2 \
                     ORDER BY sequence_number ASC",
                    &[&tenant_id, &anchor_seq],
                )
                .await
                .map_err(|e| format!("walk chain: {e}"))?;
            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                let seq: i64 = r.get("sequence_number");
                let tid: String = r.get("tenant_id");
                let at: String = r.get("action_type");
                let recorded_at: chrono::DateTime<chrono::Utc> = r.get("recorded_at");
                let entry_hash: Vec<u8> = r.get("entry_hash");
                let prev_hash: Vec<u8> = r.get("prev_hash");
                let prev_hex = if seq == 1 {
                    None
                } else {
                    Some(hex::encode(&prev_hash))
                };
                out.push(AuditChainEntry {
                    sequence_number: seq,
                    tenant_id: tid,
                    action_type: at,
                    timestamp: recorded_at,
                    row_hash: hex::encode(&entry_hash),
                    prev_hash: prev_hex,
                });
            }
            out
        }
        #[cfg(feature = "sqlite")]
        BackendDispatch::Sqlite(sq) => {
            let conn = sq.conn_handle();
            let tenant_owned = tenant_id.clone();
            tokio::task::spawn_blocking(move || -> Result<Vec<AuditChainEntry>, String> {
                let guard = conn.blocking_lock();
                let mut stmt = guard
                    .prepare(
                        "SELECT sequence_number, tenant_id, action_type, recorded_at, \
                                    entry_hash, prev_hash \
                             FROM cirislens_audit_log \
                             WHERE tenant_id = ?1 \
                               AND sequence_number BETWEEN 1 AND ?2 \
                             ORDER BY sequence_number ASC",
                    )
                    .map_err(|e| format!("prepare walk: {e}"))?;
                let row_iter = stmt
                    .query_map(rusqlite::params![tenant_owned, anchor_seq], |r| {
                        let seq: i64 = r.get(0)?;
                        let tid: String = r.get(1)?;
                        let at: String = r.get(2)?;
                        let recorded_at: String = r.get(3)?;
                        let entry_hash: Vec<u8> = r.get(4)?;
                        let prev_hash: Vec<u8> = r.get(5)?;
                        Ok((seq, tid, at, recorded_at, entry_hash, prev_hash))
                    })
                    .map_err(|e| format!("walk query: {e}"))?;
                let mut out: Vec<AuditChainEntry> = Vec::new();
                for r in row_iter {
                    let (seq, tid, at, recorded_at_str, entry_hash, prev_hash) =
                        r.map_err(|e| format!("walk row: {e}"))?;
                    // SQLite stores recorded_at as TEXT (RFC3339).
                    let normalized = if recorded_at_str.contains('T') {
                        recorded_at_str.clone()
                    } else {
                        format!("{}+00:00", recorded_at_str.replacen(' ', "T", 1))
                    };
                    let ts = chrono::DateTime::parse_from_rfc3339(&normalized)
                        .map_err(|e| format!("recorded_at parse: {e}"))?
                        .with_timezone(&chrono::Utc);
                    let prev_hex = if seq == 1 {
                        None
                    } else {
                        Some(hex::encode(&prev_hash))
                    };
                    out.push(AuditChainEntry {
                        sequence_number: seq,
                        tenant_id: tid,
                        action_type: at,
                        timestamp: ts,
                        row_hash: hex::encode(&entry_hash),
                        prev_hash: prev_hex,
                    });
                }
                Ok(out)
            })
            .await
            .map_err(|e| format!("spawn_blocking: {e}"))??
        }
    };

    // Step 3 — surface the current STH if one exists (stretch goal).
    // We tolerate `NotImplemented` / `None` cleanly — UIs that don't
    // need the proof can ignore the field.
    let head_signature: Option<String> = match backend {
        BackendDispatch::Postgres(pg) => match pg.current_sth(&tenant_id).await {
            Ok(Some(sth)) => Some(
                serde_json::to_string(&sth).map_err(|e| format!("SignedTreeHead encode: {e}"))?,
            ),
            Ok(None) => None,
            Err(_) => None,
        },
        #[cfg(feature = "sqlite")]
        BackendDispatch::Sqlite(sq) => {
            let audit = crate::audit::sqlite::SqliteAuditBackend::new(sq.conn_handle());
            match audit.current_sth(&tenant_id).await {
                Ok(Some(sth)) => Some(
                    serde_json::to_string(&sth)
                        .map_err(|e| format!("SignedTreeHead encode: {e}"))?,
                ),
                Ok(None) => None,
                Err(_) => None,
            }
        }
    };

    Ok(AuditChainProof {
        trace_id: trace_id.to_owned(),
        entries,
        head_signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v1.6.8 (CIRISPersist#76) — the config fingerprint must change
    /// when ANY of DSN / signing-key-id / local key ids change, and
    /// stay stable when they don't. This is what distinguishes a
    /// "same engine, return the singleton" call from a
    /// `EngineConfigMismatch`.
    #[test]
    fn engine_config_fingerprint_distinguishes_config() {
        let base = engine_config_fingerprint(
            "postgresql://h/db",
            "sk-1",
            &Some("lk-1".into()),
            &Some("lpk-1".into()),
        );
        // Identical inputs → identical fingerprint.
        assert_eq!(
            base,
            engine_config_fingerprint(
                "postgresql://h/db",
                "sk-1",
                &Some("lk-1".into()),
                &Some("lpk-1".into()),
            )
        );
        // Any single field change → different fingerprint.
        assert_ne!(
            base,
            engine_config_fingerprint(
                "sqlite::memory:",
                "sk-1",
                &Some("lk-1".into()),
                &Some("lpk-1".into()),
            )
        );
        assert_ne!(
            base,
            engine_config_fingerprint(
                "postgresql://h/db",
                "sk-2",
                &Some("lk-1".into()),
                &Some("lpk-1".into()),
            )
        );
        assert_ne!(
            base,
            engine_config_fingerprint("postgresql://h/db", "sk-1", &None, &Some("lpk-1".into()))
        );
        assert_ne!(
            base,
            engine_config_fingerprint("postgresql://h/db", "sk-1", &Some("lk-1".into()), &None)
        );
        // The NUL separator prevents field-boundary ambiguity — a
        // value ending where the next begins can't alias.
        assert_ne!(
            engine_config_fingerprint("a", "bc", &None, &None),
            engine_config_fingerprint("ab", "c", &None, &None),
        );
    }

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

    /// RAII guard for env-var test mutation. Saves the prior
    /// value on construction; restores on drop (including panic
    /// drop), so test failures don't pollute the env for
    /// downstream tests in the same process.
    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }
    impl EnvGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prev }
        }
        fn unset(key: &'static str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, prev }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    /// v0.1.14 — `bootstrap_lock_path` reflects `CIRIS_DATA_DIR`
    /// with the `/tmp` fallback. The cohabitation flock relies on
    /// the path being deterministic across processes on the same
    /// host; drift here breaks the multi-worker serialization.
    ///
    /// `serial(env_ciris_data_dir)` keeps env-mutating tests in
    /// this module from racing — Rust runs tests in parallel by
    /// default and a leaked `CIRIS_DATA_DIR` can pollute peer tests
    /// (CI saw `acquire_bootstrap_lock` panic with PermissionDenied
    /// because a peer test left `/var/lib/cirislens/keyring` set
    /// and the runner can't write there).
    #[test]
    #[serial_test::serial(env_ciris_data_dir)]
    fn bootstrap_lock_path_resolution() {
        let _g = EnvGuard::set("CIRIS_DATA_DIR", "/var/lib/cirislens");
        assert_eq!(
            bootstrap_lock_path(),
            std::path::PathBuf::from("/var/lib/cirislens/.persist-bootstrap.lock")
        );

        let _g = EnvGuard::unset("CIRIS_DATA_DIR");
        assert_eq!(
            bootstrap_lock_path(),
            std::path::PathBuf::from("/tmp/ciris-persist-bootstrap.lock")
        );
    }

    /// v0.1.14 — `acquire_bootstrap_lock` opens-and-locks an FD;
    /// dropping it releases the lock. Smoke test against a tempdir
    /// path so we don't pollute /tmp on the host.
    #[test]
    #[serial_test::serial(env_ciris_data_dir)]
    fn bootstrap_lock_acquire_and_release() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _g = EnvGuard::set("CIRIS_DATA_DIR", dir.path());

        let f1 = acquire_bootstrap_lock().expect("first acquire");
        assert!(f1.is_some(), "lock should be acquired on writable tempdir");
        assert!(dir.path().join(".persist-bootstrap.lock").exists());
        drop(f1);
        let f2 = acquire_bootstrap_lock().expect("second acquire");
        assert!(f2.is_some());
        drop(f2);
        // _g (EnvGuard) drops at end of scope; CIRIS_DATA_DIR
        // restored to its prior value (None or whatever the
        // outer test process had).
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

    // ── v1.13.0 (CIRISPersist#92) — current_rust_engine tests ───────
    //
    // These build an `EngineCell` directly and install it into the
    // process-global `ENGINE_SINGLETON`, then exercise the public
    // `current_rust_engine` / `current_runtime_handle` accessors.
    // They share the global slot, so `serial(engine_singleton)`
    // keeps them from racing each other and any other singleton test.

    /// Build a minimal `EngineCell` over an in-memory SQLite backend
    /// for the `current_rust_engine` tests, and install it into the
    /// process singleton. Returns the backend `Arc` so a test can
    /// assert pointer-identity with the one `current_rust_engine`
    /// yields.
    #[cfg(feature = "sqlite")]
    fn install_test_sqlite_cell() -> Arc<SqliteBackend> {
        use crate::store::Backend;

        let runtime = Arc::new(Runtime::new().expect("tokio runtime"));
        let sq = runtime.block_on(async {
            let sq = SqliteBackend::open_in_memory()
                .await
                .expect("open in-memory sqlite");
            sq.run_migrations().await.expect("migrations");
            Arc::new(sq)
        });
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x92; 32]);
        let local = Arc::new(crate::signing::LocalSigner::from_parts(
            signing_key,
            "test-rust-engine-steward".to_string(),
            None,
            None,
        ));
        let signer: Arc<dyn HardwareSigner> =
            Arc::new(crate::signing::LocalSignerHardwareAdapter::new(local));
        let cell = Arc::new(EngineCell {
            backend: BackendDispatch::Sqlite(sq.clone()),
            runtime,
            scrubber: Arc::new(crate::scrub::NullScrubber),
            signer: signer.clone(),
            signer_key_id: "test-rust-engine-steward".to_string(),
            local_signer: None,
            #[cfg(all(feature = "sqlite", feature = "cirisaudit"))]
            sqlite_audit: None,
            consumers: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            subscriptions: Arc::new(std::sync::Mutex::new(SubscriptionState::default())),
            config_fingerprint: "test-rust-engine".to_string(),
            construction_pid: std::process::id(),
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            rust_engine: std::sync::OnceLock::new(),
        });
        *engine_slot() = Some(cell);
        sq
    }

    /// Clear the singleton slot — the deterministic teardown for the
    /// `serial(engine_singleton)` tests so a leaked cell doesn't
    /// pollute a peer.
    fn clear_singleton_slot() {
        if let Some(cell) = engine_slot().as_ref() {
            cell.closed
                .store(true, std::sync::atomic::Ordering::Release);
        }
        *engine_slot() = None;
    }

    /// v1.13.0 (#92) — with no engine constructed, `current_rust_engine`
    /// yields `None` (and so does `current_runtime_handle`).
    #[test]
    #[serial_test::serial(engine_singleton)]
    fn current_rust_engine_none_when_no_engine() {
        clear_singleton_slot();
        assert!(super::current_rust_engine().is_none());
        assert!(super::current_runtime_handle().is_none());
    }

    /// v1.13.0 (#92) — after a (SQLite) engine is installed,
    /// `current_rust_engine` yields `Some`, repeated calls return the
    /// SAME cached `Arc<Engine>`, and the yielded engine's backend Arc
    /// is pointer-identical to the singleton's — the cohabitation
    /// invariant: one process, one pool.
    #[cfg(feature = "sqlite")]
    #[test]
    #[serial_test::serial(engine_singleton)]
    fn current_rust_engine_shares_singleton_backend() {
        let cell_backend = install_test_sqlite_cell();

        let e1 = super::current_rust_engine().expect("engine after install");
        let e2 = super::current_rust_engine().expect("engine on second call");
        // OnceLock cache → same `Arc<Engine>` allocation.
        assert!(
            Arc::ptr_eq(&e1, &e2),
            "repeated calls must return the cached Arc<Engine>"
        );

        // The engine's backend Arc is the SAME allocation the cell
        // holds — no second connection pool.
        let engine_sq = e1.sqlite_backend().expect("sqlite backend on engine");
        assert!(
            Arc::ptr_eq(engine_sq, &cell_backend),
            "Engine must share the singleton's backend Arc"
        );

        // The runtime handle is exposed for consumers that drive the
        // engine's async.
        assert!(super::current_runtime_handle().is_some());

        clear_singleton_slot();
    }

    /// v1.13.0 (#92) — a write through the singleton's backend is
    /// visible through the `current_rust_engine` view: same engine,
    /// same data. Drives async on the singleton's runtime handle (the
    /// `current_runtime_handle` contract).
    #[cfg(feature = "sqlite")]
    #[test]
    #[serial_test::serial(engine_singleton)]
    fn current_rust_engine_write_is_visible_through_view() {
        use crate::federation::FederationDirectory;

        let cell_backend = install_test_sqlite_cell();
        let handle = super::current_runtime_handle().expect("runtime handle");
        let engine = super::current_rust_engine().expect("engine");

        // A read against an empty federation directory through the
        // Engine view returns Ok(None) — confirms the view is live.
        let engine_sq = engine.sqlite_backend().expect("sqlite backend").clone();
        let before = handle.block_on(async {
            FederationDirectory::lookup_public_key(&*engine_sq, "rust-engine-92")
                .await
                .expect("lookup")
        });
        assert!(before.is_none(), "fresh directory has no key");

        // Pointer-identity already proves shared state; assert it once
        // more here so this test is self-contained.
        assert!(Arc::ptr_eq(&engine_sq, &cell_backend));

        // After close(), the accessor must yield None.
        clear_singleton_slot();
        assert!(super::current_rust_engine().is_none());
    }

    /// v1.13.0 (#92) — backend conformance: `current_rust_engine`
    /// yields a Postgres-backed `Engine` view when the singleton was
    /// built on Postgres, sharing the singleton's connection pool
    /// (`Arc` pointer-identity). Skips when `CIRIS_PERSIST_TEST_PG_URL`
    /// is unset.
    #[cfg(feature = "postgres")]
    #[test]
    #[serial_test::serial(engine_singleton)]
    fn current_rust_engine_shares_singleton_backend_postgres() {
        use crate::store::Backend;

        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };

        let runtime = Arc::new(Runtime::new().expect("tokio runtime"));
        let pg = runtime.block_on(async {
            let pg = PostgresBackend::connect(&dsn)
                .await
                .expect("connect postgres");
            pg.run_migrations().await.expect("migrations");
            Arc::new(pg)
        });
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x93; 32]);
        let local = Arc::new(crate::signing::LocalSigner::from_parts(
            signing_key,
            "test-rust-engine-pg-steward".to_string(),
            None,
            None,
        ));
        let signer: Arc<dyn HardwareSigner> =
            Arc::new(crate::signing::LocalSignerHardwareAdapter::new(local));
        let cell = Arc::new(EngineCell {
            backend: BackendDispatch::Postgres(pg.clone()),
            runtime,
            scrubber: Arc::new(crate::scrub::NullScrubber),
            signer: signer.clone(),
            signer_key_id: "test-rust-engine-pg-steward".to_string(),
            local_signer: None,
            #[cfg(all(feature = "sqlite", feature = "cirisaudit"))]
            sqlite_audit: None,
            consumers: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            subscriptions: Arc::new(std::sync::Mutex::new(SubscriptionState::default())),
            config_fingerprint: "test-rust-engine-pg".to_string(),
            construction_pid: std::process::id(),
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            rust_engine: std::sync::OnceLock::new(),
        });
        *engine_slot() = Some(cell);

        let e1 = super::current_rust_engine().expect("engine after install");
        let e2 = super::current_rust_engine().expect("engine on second call");
        assert!(Arc::ptr_eq(&e1, &e2), "cached Arc<Engine>");

        let engine_pg = e1.postgres_backend().expect("postgres backend on engine");
        assert!(
            Arc::ptr_eq(engine_pg, &pg),
            "Engine must share the singleton's Postgres backend Arc"
        );

        clear_singleton_slot();
    }

    /// v1.13.0 (#92) — `current_rust_engine` yields `None` once the
    /// engine is closed, even though the cell is still in the slot.
    #[cfg(feature = "sqlite")]
    #[test]
    #[serial_test::serial(engine_singleton)]
    fn current_rust_engine_none_after_close() {
        install_test_sqlite_cell();
        assert!(super::current_rust_engine().is_some());
        // Flip the closed flag without clearing the slot.
        if let Some(cell) = engine_slot().as_ref() {
            cell.closed
                .store(true, std::sync::atomic::Ordering::Release);
        }
        assert!(
            super::current_rust_engine().is_none(),
            "closed engine must not be handed out"
        );
        assert!(super::current_runtime_handle().is_none());
        clear_singleton_slot();
    }

    // ── v2.0.1 (CIRISPersist#95) — cohabitation accessor tests ──────
    //
    // `federation_directory` / `outbound_queue` / `keyring_signer` on
    // `PyEngine`. These don't touch the process-singleton slot —
    // they build a cell and construct `PyEngine` via `from_cell`
    // directly — so they don't need `#[serial(engine_singleton)]`.

    #[cfg(feature = "sqlite")]
    fn build_cell_for_cohab_test() -> (Arc<EngineCell>, Arc<SqliteBackend>) {
        use crate::store::Backend;
        let runtime = Arc::new(Runtime::new().expect("tokio runtime"));
        let sq = runtime.block_on(async {
            let sq = SqliteBackend::open_in_memory()
                .await
                .expect("open in-memory sqlite");
            sq.run_migrations().await.expect("migrations");
            Arc::new(sq)
        });
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x95; 32]);
        let local = Arc::new(crate::signing::LocalSigner::from_parts(
            signing_key,
            "test-cohab-steward".to_string(),
            None,
            None,
        ));
        let signer: Arc<dyn HardwareSigner> = Arc::new(
            crate::signing::LocalSignerHardwareAdapter::new(local.clone()),
        );
        let cell = Arc::new(EngineCell {
            backend: BackendDispatch::Sqlite(sq.clone()),
            runtime,
            scrubber: Arc::new(crate::scrub::NullScrubber),
            signer,
            signer_key_id: "test-cohab-steward".to_string(),
            local_signer: Some(local),
            #[cfg(all(feature = "sqlite", feature = "cirisaudit"))]
            sqlite_audit: None,
            consumers: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            subscriptions: Arc::new(std::sync::Mutex::new(SubscriptionState::default())),
            config_fingerprint: "test-cohab".to_string(),
            construction_pid: std::process::id(),
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            rust_engine: std::sync::OnceLock::new(),
        });
        (cell, sq)
    }

    /// #95 — `federation_directory()` yields the singleton's backend
    /// Arc (pointer-identical), wrapped in `engine::BackendDispatch`.
    /// No second pool, no second connection.
    #[cfg(feature = "sqlite")]
    #[test]
    fn federation_directory_yields_singleton_backend_sqlite() {
        let (cell, sq) = build_cell_for_cohab_test();
        let py = super::PyEngine::from_cell(&cell);
        match py.federation_directory() {
            crate::engine::BackendDispatch::Sqlite(b) => {
                assert!(
                    Arc::ptr_eq(&b, &sq),
                    "federation_directory must return the singleton's backend Arc"
                );
            }
            #[cfg(feature = "postgres")]
            crate::engine::BackendDispatch::Postgres(_) => panic!("expected sqlite arm"),
        }
    }

    /// #95 — `outbound_queue()` yields the same singleton backend Arc
    /// as `federation_directory` — both traits live on the same
    /// concrete backend type.
    #[cfg(feature = "sqlite")]
    #[test]
    fn outbound_queue_yields_singleton_backend_sqlite() {
        let (cell, sq) = build_cell_for_cohab_test();
        let py = super::PyEngine::from_cell(&cell);
        match py.outbound_queue() {
            crate::engine::BackendDispatch::Sqlite(b) => {
                assert!(Arc::ptr_eq(&b, &sq));
            }
            #[cfg(feature = "postgres")]
            crate::engine::BackendDispatch::Postgres(_) => panic!("expected sqlite arm"),
        }
    }

    /// #95 — `keyring_signer()` returns the singleton's signer Arc +
    /// key_id; `pqc_signer` is `None` for a non-PQC `LocalSigner`. The
    /// returned signer is pointer-identical to the cell's — no
    /// keyring re-bootstrap (cohabitation rule 1).
    #[cfg(feature = "sqlite")]
    #[test]
    fn keyring_signer_handle_carries_singleton_parts() {
        let (cell, _sq) = build_cell_for_cohab_test();
        let py = super::PyEngine::from_cell(&cell);
        let h = py.keyring_signer();
        assert_eq!(h.key_id, "test-cohab-steward");
        assert!(
            Arc::ptr_eq(&h.signer, &cell.signer),
            "keyring_signer must return the singleton's signer Arc — \
             no keyring re-bootstrap"
        );
        assert!(
            h.pqc_signer.is_none(),
            "non-PQC LocalSigner — pqc_signer must be None"
        );
    }

    // ── v2.7.0 (CIRISPersist#109) — PyCapsule accessor tests ──────
    //
    // The capsule round-trip test is on Edge's side (CIRISEdge#22 will
    // load both wheels separately and verify init_edge_runtime can
    // extract the capsules via PyAny.call_method0). Persist's local
    // verification is compile + clippy clean on the three accessors —
    // they're 8 lines each, no logic to regression-test.

    // ── #104 audit_chain_proof helper tests ─────────────────────────
    //
    // These exercise `build_audit_chain_proof` directly (the helper
    // the `audit_chain_proof` pymethod delegates to) so we hit the
    // backend dispatch + the per-backend audit-log walk without
    // standing up a real PyEngine — same shape as the SQLite/PG
    // topology tests in `src/store/{sqlite,postgres}.rs`.

    #[cfg(all(feature = "sqlite", feature = "cirisaudit"))]
    async fn seed_audit_entries_sqlite(
        audit: &crate::audit::sqlite::SqliteAuditBackend,
        tenant: &str,
        trace_id: &str,
        n: i64,
    ) -> Vec<u8> {
        use crate::audit::types::AuditEntry;
        use crate::audit::verify::canonical_bytes_for_entry;
        use crate::audit::AuditService;
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ed25519_dalek::Signer;
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&[0xCE; 32]);
        let pubkey_b64 = B64.encode(key.verifying_key().to_bytes());
        let mut prev_hash = crate::audit::GENESIS_PREV_HASH.to_vec();
        let mut last_hash = prev_hash.clone();
        for i in 1..=n {
            let subj = if i == n {
                trace_id.to_owned()
            } else {
                format!("seed-{i}")
            };
            // Truncate to microseconds — the SQLite layer's
            // `parse_datetime` round-trip canonicalises at micro
            // resolution, and the audit chain's `entry_hash` is
            // computed from canonical bytes, so anything finer
            // would break the chain check on re-derivation.
            let ts = chrono::Utc::now()
                .with_timezone(&chrono::Utc)
                .timestamp_micros();
            let recorded_at = chrono::DateTime::<chrono::Utc>::from_timestamp_micros(ts).unwrap();
            let mut e = AuditEntry {
                entry_id: uuid::Uuid::new_v4().to_string(),
                sequence_number: i,
                tenant_id: tenant.to_owned(),
                actor_id: pubkey_b64.clone(),
                action_type: "system_event".into(),
                subject_kind: "task".into(),
                subject_id: subj,
                payload: serde_json::json!({"i": i}),
                prev_hash: prev_hash.clone(),
                entry_hash: vec![],
                recorded_at,
                signature: String::new(),
            };
            let h = crate::audit::verify::compute_entry_hash(&e).unwrap();
            e.entry_hash = h.to_vec();
            let canon = canonical_bytes_for_entry(&e).unwrap();
            let sig = key.sign(&canon);
            e.signature = B64.encode(sig.to_bytes());
            last_hash = e.entry_hash.clone();
            audit.record_entry(e).await.unwrap();
            prev_hash = last_hash.clone();
        }
        last_hash
    }

    /// #104 — audit_chain_proof walks genesis → trace row on SQLite.
    #[cfg(all(feature = "sqlite", feature = "cirisaudit"))]
    #[tokio::test]
    async fn audit_chain_proof_walks_to_trace_sqlite() {
        let runtime = tokio::runtime::Handle::current();
        let _ = runtime;
        let backend = Arc::new(
            SqliteBackend::open_in_memory()
                .await
                .expect("open in-memory sqlite"),
        );
        backend.run_migrations().await.expect("migrations");
        let audit = crate::audit::sqlite::SqliteAuditBackend::new(backend.conn_handle());
        let tenant = format!("ap-tenant-{}", uuid::Uuid::new_v4().simple());
        let trace_id = format!("trace-104-{}", uuid::Uuid::new_v4().simple());
        seed_audit_entries_sqlite(&audit, &tenant, &trace_id, 3).await;
        let dispatch = super::BackendDispatch::Sqlite(backend);
        let proof = super::build_audit_chain_proof(&dispatch, &trace_id)
            .await
            .expect("audit_chain_proof");
        assert_eq!(proof.trace_id, trace_id);
        assert_eq!(proof.entries.len(), 3);
        assert_eq!(proof.entries[0].sequence_number, 1);
        assert_eq!(proof.entries[0].tenant_id, tenant);
        assert!(
            proof.entries[0].prev_hash.is_none(),
            "genesis row prev_hash is None"
        );
        assert_eq!(proof.entries.last().unwrap().sequence_number, 3);
        assert!(
            proof.entries[1].prev_hash.is_some(),
            "non-genesis prev_hash is hex"
        );
        // head_signature: tolerant — no Merkle signer installed in this
        // fixture, so the field is None. The assertion is loose so the
        // test stays green if a downstream change wires a signer
        // through the default test path.
        assert!(proof.head_signature.is_none());
    }

    /// #104 — audit_chain_proof returns an empty-entries proof when
    /// no row references the given trace_id.
    #[cfg(all(feature = "sqlite", feature = "cirisaudit"))]
    #[tokio::test]
    async fn audit_chain_proof_empty_sqlite() {
        let backend = Arc::new(
            SqliteBackend::open_in_memory()
                .await
                .expect("open in-memory sqlite"),
        );
        backend.run_migrations().await.expect("migrations");
        let dispatch = super::BackendDispatch::Sqlite(backend);
        let proof = super::build_audit_chain_proof(&dispatch, "no-such-trace")
            .await
            .expect("audit_chain_proof");
        assert_eq!(proof.trace_id, "no-such-trace");
        assert!(proof.entries.is_empty());
        assert!(proof.head_signature.is_none());
    }

    /// #104 — audit_chain_proof against Postgres. Skipped when
    /// `CIRIS_PERSIST_TEST_PG_URL` is unset.
    #[cfg(all(feature = "postgres", feature = "cirisaudit"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn audit_chain_proof_walks_to_trace_pg() {
        use crate::audit::types::AuditEntry;
        use crate::audit::verify::canonical_bytes_for_entry;
        use crate::audit::AuditService;
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ed25519_dalek::Signer;
        use ed25519_dalek::SigningKey;
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = Arc::new(
            PostgresBackend::connect(&dsn)
                .await
                .expect("connect postgres"),
        );
        backend.run_migrations().await.expect("migrations");
        let key = SigningKey::from_bytes(&[0xCF; 32]);
        let pubkey_b64 = B64.encode(key.verifying_key().to_bytes());
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let tenant = format!("ap-pg-{suffix}");
        let trace_id = format!("trace-pg-104-{suffix}");
        let mut prev_hash = crate::audit::GENESIS_PREV_HASH.to_vec();
        for i in 1..=3i64 {
            let subj = if i == 3 {
                trace_id.clone()
            } else {
                format!("seed-pg-{i}")
            };
            let ts = chrono::Utc::now().timestamp_micros();
            let recorded_at = chrono::DateTime::<chrono::Utc>::from_timestamp_micros(ts).unwrap();
            let mut e = AuditEntry {
                entry_id: uuid::Uuid::new_v4().to_string(),
                sequence_number: i,
                tenant_id: tenant.clone(),
                actor_id: pubkey_b64.clone(),
                action_type: "system_event".into(),
                subject_kind: "task".into(),
                subject_id: subj,
                payload: serde_json::json!({"i": i}),
                prev_hash: prev_hash.clone(),
                entry_hash: vec![],
                recorded_at,
                signature: String::new(),
            };
            let h = crate::audit::verify::compute_entry_hash(&e).unwrap();
            e.entry_hash = h.to_vec();
            let canon = canonical_bytes_for_entry(&e).unwrap();
            let sig = key.sign(&canon);
            e.signature = B64.encode(sig.to_bytes());
            prev_hash = e.entry_hash.clone();
            backend.record_entry(e).await.expect("record");
        }
        let dispatch = super::BackendDispatch::Postgres(backend);
        let proof = super::build_audit_chain_proof(&dispatch, &trace_id)
            .await
            .expect("audit_chain_proof");
        assert_eq!(proof.trace_id, trace_id);
        assert_eq!(proof.entries.len(), 3);
        assert_eq!(proof.entries[0].sequence_number, 1);
        assert!(proof.entries[0].prev_hash.is_none());
        assert!(proof.entries.last().unwrap().prev_hash.is_some());
    }

    /// #104 — Postgres parity for the empty case.
    #[cfg(all(feature = "postgres", feature = "cirisaudit"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn audit_chain_proof_empty_pg() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = Arc::new(
            PostgresBackend::connect(&dsn)
                .await
                .expect("connect postgres"),
        );
        backend.run_migrations().await.expect("migrations");
        let dispatch = super::BackendDispatch::Postgres(backend);
        let proof = super::build_audit_chain_proof(&dispatch, "no-such-trace-pg")
            .await
            .expect("audit_chain_proof");
        assert!(proof.entries.is_empty());
        assert!(proof.head_signature.is_none());
    }
}

/// v0.5.3 (CIRISPersist#27) — typed Python exception that PyO3's
/// `catch_panic` wrapper raises when a Rust panic propagates through
/// the FFI boundary.
///
/// Derives from Python's `Exception` (not `BaseException`) so that
/// uvicorn's normal `try: except Exception` request-handler error
/// path catches it as a 500 — the request fails cleanly without
/// poisoning the worker. PyO3's built-in trampoline raises
/// `pyo3.exceptions.PanicException` which derives from
/// `BaseException` and is NOT caught by `except Exception`, so a
/// panic that bypasses our `catch_panic` would still surface as a
/// BaseException-uncaught-in-uvicorn-handler — recoverable but ugly.
///
/// v0.5.4 (CIRISPersist#28) — the explicit-wrap sweep is now complete
/// across every PyO3 method (~70 entry points). Every panic that
/// would have escaped as `PanicException` (BaseException, slips past
/// `except Exception`) is now converted to `LensQueryError`
/// (Exception, caught by uvicorn's normal request-handler error path).
#[allow(missing_docs)] // pyo3::create_exception macro emits items without doc-comments
mod lens_query_error {
    pyo3::create_exception!(ciris_persist, LensQueryError, pyo3::exceptions::PyException);
}
pub use lens_query_error::LensQueryError;

/// v0.5.3 (CIRISPersist#27) — wrap a PyO3 method body with explicit
/// panic catching. Converts any panic payload into a typed
/// [`LensQueryError`] (derives from `Exception`, not `BaseException`)
/// so uvicorn catches as a normal 500.
///
/// Use `AssertUnwindSafe` because `&self` on PyO3 methods isn't
/// `UnwindSafe` by default — we assert that the panic-then-continue
/// path is acceptable for our method bodies (every method's state is
/// already typed-error guarded via `safe_get` and explicit
/// `map_err`s; a panic implies a bug, not a recoverable state).
fn catch_panic<F, R>(f: F) -> PyResult<R>
where
    F: FnOnce() -> PyResult<R>,
{
    use std::panic::{catch_unwind, AssertUnwindSafe};
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(payload) => {
            let msg = panic_payload_to_string(payload);
            tracing::error!(panic = %msg, "PyO3 catch_panic caught Rust panic");
            Err(PyErr::new::<LensQueryError, _>(format!(
                "rust_panic: {msg}"
            )))
        }
    }
}

/// v0.5.3 (CIRISPersist#27) — extract a human-readable string from
/// a `catch_unwind` payload (Box<dyn Any + Send>). Tries `String`
/// then `&str` then falls back to a generic label.
fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else {
        "(opaque panic payload)".to_string()
    }
}

/// v0.5.4 (CIRISPersist#29) — test-only module-level panic injector.
/// Bypasses Engine construction (no Postgres / keyring setup needed)
/// so the Python regression suite can isolate the FFI catch_panic
/// layer's behavior. Compiled in only with `--features test-panic`;
/// release wheels don't expose this function.
///
/// Asserts the same invariant as the v0.5.3 wrap: a Rust panic
/// crossing the FFI boundary must surface as `LensQueryError`
/// (subclass of `Exception`, caught by `except Exception:`) rather
/// than `PanicException` (subclass of `BaseException`, the
/// CIRISPersist#24 wedge mode).
#[cfg(feature = "test-panic")]
#[pyfunction]
fn _test_inject_panic(panic_msg: &str) -> PyResult<()> {
    catch_panic(|| {
        panic!("{panic_msg}");
    })
}

/// `ciris_persist` Python module entry point. The build script
/// v1.5.24 (CIRISPersist#66) — encode a
/// [`ClaimResult<SecretReference>`] onto the
/// `{"outcome": "stored" | "already_claimed", "ref": <SecretReference>}`
/// JSON wire shape. Used by `secrets_store_detected_secret`.
#[cfg(feature = "secrets")]
fn encode_secret_claim_result(
    outcome: crate::ClaimResult<crate::secrets::SecretReference>,
) -> Result<String, serde_json::Error> {
    let (label, secret_ref) = match outcome {
        crate::ClaimResult::Stored(r) => ("stored", r),
        crate::ClaimResult::AlreadyClaimed(r) => ("already_claimed", r),
    };
    let wire = serde_json::json!({
        "outcome": label,
        "ref": secret_ref,
    });
    serde_json::to_string(&wire)
}

/// v1.10.1 (CIRISPersist#88) — handle-free reset of the
/// process-singleton engine.
///
/// `Engine.close()` needs a live `Engine` handle. A consumer test
/// fixture that drops its Python reference without calling `close()`
/// leaves the Rust process-singleton pinned with nothing able to
/// reference it (the "orphan case") — and the next `Engine(...)`,
/// even with a correct different config, raises `EngineConfigMismatch`
/// forever. `reset_engine()` operates on the process-global slot
/// directly, so no handle is needed:
///
/// * flips the current engine's `closed` flag — any surviving handle
///   then fails fast with `EngineClosed` rather than touching a
///   torn-down runtime;
/// * clears the singleton slot **synchronously** — an
///   immediately-following `Engine(...)` with any config constructs
///   cleanly;
/// * drops the engine cell (tearing down its tokio runtime +
///   connection pools) before returning, with the slot lock released
///   first so the teardown cannot wedge a concurrent constructor;
/// * is a no-op when no engine is pinned.
///
/// Idempotent and correct under repeated reset/construct cycles —
/// the deterministic teardown door for consumer test suites, and for
/// the in-process cohabitation epic (CIRISPersist#85), that
/// `close()`-needing-a-handle cannot provide.
#[pyfunction]
fn reset_engine(py: Python<'_>) {
    py.detach(|| {
        // Take the cell out under the slot lock — set the slot to
        // `None` and flip `closed` so a racing handle sees the
        // shutdown — then release the lock before the teardown drop.
        let taken = {
            let mut slot = engine_slot();
            if let Some(cell) = slot.as_ref() {
                cell.closed
                    .store(true, std::sync::atomic::Ordering::Release);
            }
            slot.take()
        };
        // Drop outside the lock: if this is the last `Arc<EngineCell>`
        // (the orphan / clean-teardown case), the runtime + pools tear
        // down here. Blocking is fine — Python thread, GIL released.
        drop(taken);
    });
}

impl EngineCell {
    /// v1.13.0 (CIRISPersist#92) — re-wrap this cell's
    /// `pyo3::BackendDispatch` into the public
    /// [`engine::BackendDispatch`](crate::engine::BackendDispatch) by
    /// cloning the inner `Arc<…Backend>`.
    ///
    /// The two same-named enums (`pyo3.rs`'s `pub(crate)` one and
    /// `engine.rs`'s `pub` one) wrap byte-identical inner types; this
    /// is a cheap `match` + `Arc::clone` — the same connection pool,
    /// **no second pool**.
    fn engine_backend_dispatch(&self) -> crate::engine::BackendDispatch {
        match &self.backend {
            BackendDispatch::Postgres(pg) => crate::engine::BackendDispatch::Postgres(pg.clone()),
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(sq) => crate::engine::BackendDispatch::Sqlite(sq.clone()),
        }
    }
}

/// v1.13.0 (CIRISPersist#92) — hand a co-resident Rust consumer the
/// process-singleton's [`Engine`](crate::Engine).
///
/// `PyEngine` (the PyO3 wheel surface) and the Rust
/// [`Engine`](crate::Engine) are **siblings**, not wrapper/wrapped: a
/// co-resident Rust extension that holds the host's `PyEngine` has no
/// route to an `Arc<Engine>`. This accessor closes that gap. It is the
/// piece CIRISEdge's resolver and CIRISLensCore's
/// `LensCore::relay(engine: Arc<Engine>, …)` were blocked on — both
/// shipped their halves and wait on persist to hand out the
/// singleton's Rust `Arc<Engine>`.
///
/// # Cohabitation invariant
///
/// The returned `Arc<Engine>` is the **same** engine `PyEngine`
/// dispatches to:
///
/// * the backend is the singleton's own backend `Arc`, re-wrapped from
///   `pyo3::BackendDispatch` into [`engine::BackendDispatch`](crate::engine::BackendDispatch)
///   by cloning the inner `Arc<PostgresBackend>` / `Arc<SqliteBackend>`
///   — the same connection pool, **no second pool**;
/// * the signer is the singleton's `Arc<dyn HardwareSigner>`, passed
///   straight through.
///
/// No second `Engine`, tokio runtime, or connection pool is created.
/// The `Arc<Engine>` is built **once** and cached on the `EngineCell`
/// (an `OnceLock`), so repeated calls return the same `Arc`.
///
/// # Runtime
///
/// `Engine`'s methods are plain `async fn` and embed no runtime; the
/// `Engine` itself needs no runtime handle. The consumer drives the
/// async — `LensCore::init_edge_runtime` `block_on`s `LensCore::relay`.
/// One subtlety: the singleton's Postgres pool spawns its connection
/// driver tasks via `tokio::spawn` onto whatever runtime is current
/// when a pooled connection is first acquired. A consumer that
/// `block_on`s `Engine` work on a *throwaway* runtime would strand
/// those driver tasks when that runtime is dropped. To remove the
/// ambiguity, [`current_runtime_handle`] exposes the singleton's
/// long-lived [`tokio::runtime::Handle`]; a co-resident consumer
/// should `handle.block_on(...)` (or `handle.enter()` then drive its
/// own loop) so backend driver tasks land on the runtime that lives
/// for the whole process. SQLite (`spawn_blocking`) is runtime-
/// agnostic and unaffected either way.
///
/// Returns `None` when no engine is constructed yet, or after
/// `close()` / `reset_engine()` cleared the slot.
pub fn current_rust_engine() -> Option<Arc<crate::Engine>> {
    let slot = engine_slot();
    let cell = slot.as_ref()?;
    if cell.closed.load(std::sync::atomic::Ordering::Acquire) {
        return None;
    }
    let engine = cell.rust_engine.get_or_init(|| {
        // v2.12.0 (#112) — propagate the EngineCell's local_signer so
        // `Engine::sign_hybrid` works on co-resident Rust consumers
        // (CIRISLensCore client-mode trace signing, EgressFilter
        // re-sign). The singleton already holds the LocalSigner;
        // sharing it across the cohabitation boundary doesn't
        // duplicate identity.
        Arc::new(crate::Engine::from_shared_with_local(
            cell.engine_backend_dispatch(),
            cell.signer.clone(),
            cell.local_signer.clone(),
        ))
    });
    Some(engine.clone())
}

/// v1.13.0 (CIRISPersist#92) — the process-singleton's long-lived
/// [`tokio::runtime::Handle`].
///
/// A co-resident Rust consumer that drives the
/// [`Engine`](crate::Engine) returned by [`current_rust_engine`]
/// should run its `block_on` on this handle (or `enter()` it), so
/// backend connection-driver tasks spawned by the Postgres pool land
/// on the runtime that lives for the whole process rather than a
/// throwaway one. See [`current_rust_engine`]'s *Runtime* section.
///
/// Returns `None` when no engine is constructed yet, or after
/// `close()` / `reset_engine()` cleared the slot.
pub fn current_runtime_handle() -> Option<tokio::runtime::Handle> {
    let slot = engine_slot();
    let cell = slot.as_ref()?;
    if cell.closed.load(std::sync::atomic::Ordering::Acquire) {
        return None;
    }
    Some(cell.runtime.handle().clone())
}

/// (maturin) generates the C entry that Python imports.
#[pymodule]
fn ciris_persist(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyEngine>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add(
        "SUPPORTED_SCHEMA_VERSIONS",
        crate::schema::SUPPORTED_VERSIONS.to_vec(),
    )?;
    // v0.5.3 (CIRISPersist#27) — register LensQueryError so the
    // catch_panic wrapper has a typed exception class to raise.
    m.add("LensQueryError", py.get_type::<LensQueryError>())?;
    // v1.0.0-scaffold (CIRISPersist#194) — typed retry-policy
    // exception hierarchy. The follow-up porting agent threads
    // `translate_error_kind` through each `Error::kind()`-aware
    // map_err site; for now the classes are registered + importable
    // (`from ciris_persist import PersistError, NotFound, Conflict,
    // Transient, Permanent`) so the lens HTTP layer can pre-wire
    // its retry / status-code dispatch.
    m.add("PersistError", py.get_type::<PersistError>())?;
    m.add("NotFound", py.get_type::<NotFound>())?;
    m.add("Conflict", py.get_type::<Conflict>())?;
    m.add("Transient", py.get_type::<Transient>())?;
    m.add("Permanent", py.get_type::<Permanent>())?;
    // v1.6.8 (CIRISPersist#75-78) — engine-lifecycle exceptions.
    m.add(
        "EngineConfigMismatch",
        py.get_type::<EngineConfigMismatch>(),
    )?;
    m.add("EngineClosed", py.get_type::<EngineClosed>())?;
    m.add(
        "EngineUsedAcrossFork",
        py.get_type::<EngineUsedAcrossFork>(),
    )?;
    // v1.10.1 (CIRISPersist#88) — handle-free process-singleton
    // reset; the deterministic teardown door for consumer test
    // suites and the cohabitation epic.
    m.add_function(pyo3::wrap_pyfunction!(reset_engine, m)?)?;
    // v0.5.4 (CIRISPersist#29) — feature-gated panic injector for the
    // Python regression suite. Off in release wheels.
    #[cfg(feature = "test-panic")]
    m.add_function(pyo3::wrap_pyfunction!(_test_inject_panic, m)?)?;
    Ok(())
}
