//! v1.1.0 (CIRISPersist#43) — Rust-side substrate composition handle.
//!
//! Composes a storage backend (Postgres or SQLite, behind a public
//! [`BackendDispatch`] enum) with a pre-loaded
//! [`LocalSigner`](crate::signing::LocalSigner) `Arc`. Used by
//! sovereign-mode Reticulum agents (CIRISEdge) and in-process lens-core
//! consumers (CIRISLensCore) that want to construct substrate primitives
//! without dragging in the full PyO3 [`PyEngine`](crate::ffi::pyo3::PyEngine)
//! wheel surface.
//!
//! # Why this lives alongside (not inside) PyEngine
//!
//! PyEngine is purely additive's older sibling: it bundles ciris-keyring
//! bootstrap, scrub-signer init, scrubber pipeline wiring, cold-path PQC
//! sweep scheduler, ingest pipeline, and tokio runtime ownership behind
//! a Python-callable surface. Sovereign-mode and lens-core consumers
//! want *substrate handles only* — just the FederationDirectory +
//! OutboundQueue trait surfaces, plus a signer they can sign with.
//!
//! Keeping `Engine` and `PyEngine` separate keeps the wheel surface
//! frozen while landing the Rust-side composition primitive consumers
//! actually need.
//!
//! # Trait-object note
//!
//! `FederationDirectory` and `OutboundQueue` use Rust 1.75+
//! `impl Future + Send` return-position syntax — these traits are NOT
//! object-safe (you cannot construct `Arc<dyn FederationDirectory>`).
//! Consumers either:
//!
//! 1. Match on [`Engine::backend()`] to dispatch per concrete backend
//!    (`Arc<PostgresBackend>` / `Arc<SqliteBackend>`), or
//! 2. Call the `*_sqlite` / `*_postgres` accessors directly when the
//!    deployment shape pins one backend.
//!
//! # Example
//!
//! ```ignore
//! use std::sync::Arc;
//! use ciris_persist::{Engine, signing::LocalSigner};
//!
//! let signer = Arc::new(LocalSigner::from_config(/* … */)?);
//! let engine = Engine::with_signer(signer.clone(), "sqlite:///agent.db").await?;
//!
//! // Sign a canonical envelope with the composed federation signer.
//! // `Engine::signer()` returns `&Arc<dyn HardwareSigner>` (v1.13.0):
//! use ciris_keyring::HardwareSigner;
//! let sig = engine.signer().sign(canonical_bytes).await?;
//!
//! // Dispatch on the backend to use the federation directory.
//! match engine.backend() {
//!     ciris_persist::BackendDispatch::Sqlite(sq) => {
//!         use ciris_persist::federation::FederationDirectory;
//!         sq.put_public_key(signed_record).await?;
//!     }
//!     #[cfg(feature = "postgres")]
//!     ciris_persist::BackendDispatch::Postgres(pg) => {
//!         use ciris_persist::federation::FederationDirectory;
//!         pg.put_public_key(signed_record).await?;
//!     }
//! }
//! ```

use std::sync::Arc;

use ciris_keyring::HardwareSigner;

use crate::signing::{LocalSigner, LocalSignerHardwareAdapter};
// Re-exported so `Engine::receive_and_persist`'s signature resolves
// for consumers that `use ciris_persist::Engine` without separately
// importing the scrub module.
pub use crate::scrub::Scrubber;
#[cfg(feature = "postgres")]
use crate::store::PostgresBackend;
#[cfg(feature = "sqlite")]
use crate::store::SqliteBackend;
// `Backend` is only reachable via the postgres / sqlite trait impls;
// gate the import so a no-backend build (e.g.
// `cargo test --test wire_format_fixtures`) doesn't see it as
// unused under the CI's `-D warnings`.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
use crate::store::Backend;
use crate::store::Error as StoreError;

/// v1.1.0 (CIRISPersist#43) — public dispatch enum over the
/// substrate's storage backends.
///
/// Held internally by [`Engine`]; exposed publicly so consumers can
/// `match` on the variant and use the concrete backend's trait
/// implementations (`FederationDirectory`, `OutboundQueue`, `Backend`).
///
/// Variants are gated behind the corresponding cargo feature
/// (`postgres` / `sqlite`); a build with both features sees both arms.
#[derive(Clone)]
pub enum BackendDispatch {
    /// Postgres-backed substrate. Available when the `postgres`
    /// cargo feature is enabled.
    #[cfg(feature = "postgres")]
    Postgres(Arc<PostgresBackend>),
    /// SQLite-backed substrate. Available when the `sqlite` cargo
    /// feature is enabled.
    #[cfg(feature = "sqlite")]
    Sqlite(Arc<SqliteBackend>),
}

/// v1.1.0 (CIRISPersist#43) — Rust-side substrate handle composing
/// a storage backend plus a federation signer.
///
/// v1.13.0 (CIRISPersist#92): the signer is held as
/// `Arc<dyn HardwareSigner>` — the federation signer abstraction —
/// rather than the concrete `Arc<LocalSigner>` it carried through
/// v1.12.x. This makes `Engine` and the PyO3 process-singleton's
/// `EngineCell` signer-compatible (the singleton already holds an
/// `Arc<dyn HardwareSigner>`), so the singleton can hand a co-resident
/// Rust consumer an `Arc<Engine>` view via
/// [`current_rust_engine`](crate::current_rust_engine), and makes
/// `Engine` correct on hardware-attested deployments — not just
/// software [`LocalSigner`](crate::signing::LocalSigner) ones.
///
/// The `with_signer*` constructors stay source-compatible: they still
/// accept an `Arc<LocalSigner>` and wrap it in
/// [`LocalSignerHardwareAdapter`](crate::signing::LocalSignerHardwareAdapter)
/// before storing.
///
/// See module-level documentation for usage.
#[derive(Clone)]
pub struct Engine {
    backend: BackendDispatch,
    signer: Arc<dyn HardwareSigner>,
}

impl Engine {
    /// Construct an Engine with a pre-loaded
    /// [`LocalSigner`](crate::signing::LocalSigner) `Arc` plus a
    /// backend DSN.
    ///
    /// DSN URL-sniff (mirrors
    /// [`PyEngine`](crate::ffi::pyo3::PyEngine) for cross-surface
    /// consistency):
    ///
    /// - `postgresql://…` / `postgres://…` → Postgres
    /// - `sqlite:///path.db` → SQLite (file at `/path.db`)
    /// - `sqlite::memory:` / `sqlite:///:memory:` → SQLite in-memory
    ///
    /// Runs the backend's migrations as part of construction (the
    /// same `Backend::run_migrations` path the PyO3 surface uses), so
    /// the returned Engine is ready to read/write immediately.
    pub async fn with_signer(signer: Arc<LocalSigner>, dsn: &str) -> Result<Self, EngineError> {
        let backend = build_backend(dsn).await?;
        // v1.13.0 (#92): the stored field is `Arc<dyn HardwareSigner>`;
        // wrap the caller's `Arc<LocalSigner>` so the constructor stays
        // source-compatible.
        let signer: Arc<dyn HardwareSigner> = Arc::new(LocalSignerHardwareAdapter::new(signer));
        Ok(Engine { backend, signer })
    }

    /// Variant accepting raw signer Arcs — matches the issue's
    /// `Engine::with_signer_arcs(classical, pqc, dsn)` shape from
    /// CIRISPersist#43.
    ///
    /// Wraps the components into a
    /// [`LocalSigner`](crate::signing::LocalSigner) via
    /// [`LocalSigner::from_parts`] before composing the Engine. Use
    /// [`Engine::with_signer`] when you already hold an
    /// `Arc<LocalSigner>`.
    pub async fn with_signer_arcs(
        signing_key: ed25519_dalek::SigningKey,
        key_id: String,
        pqc_signer: Option<Arc<dyn ciris_keyring::PqcSigner>>,
        pqc_key_id: Option<String>,
        dsn: &str,
    ) -> Result<Self, EngineError> {
        let signer = Arc::new(LocalSigner::from_parts(
            signing_key,
            key_id,
            pqc_signer,
            pqc_key_id,
        ));
        Self::with_signer(signer, dsn).await
    }

    /// Borrow the public [`BackendDispatch`] enum the Engine
    /// composes. Consumers `match` on the variant and call the
    /// concrete backend's trait methods (`FederationDirectory`,
    /// `OutboundQueue`, `Backend`).
    ///
    /// Cloning the inner `Arc<...Backend>` is cheap and is the
    /// idiomatic way to hand a backend handle to a worker task.
    pub fn backend(&self) -> &BackendDispatch {
        &self.backend
    }

    /// Accessor for the composed federation signer `Arc`.
    ///
    /// v1.13.0 (CIRISPersist#92): returns `&Arc<dyn HardwareSigner>`
    /// (previously `&Arc<LocalSigner>`). The federation signer
    /// abstraction is the right type — a hardware-attested deployment
    /// composes a real [`HardwareSigner`]; a software deployment
    /// composes a [`LocalSigner`](crate::signing::LocalSigner) wrapped
    /// in [`LocalSignerHardwareAdapter`](crate::signing::LocalSignerHardwareAdapter).
    /// The signing-identity alias is reachable via
    /// [`HardwareSigner::current_alias`].
    pub fn signer(&self) -> &Arc<dyn HardwareSigner> {
        &self.signer
    }

    /// v1.13.0 (CIRISPersist#92) — construct an `Engine` from
    /// **already-live** parts: a connected + migrated backend and a
    /// federation signer.
    ///
    /// Unlike [`Engine::with_signer`], this opens **no** connection and
    /// runs **no** migrations — the caller's `backend` is presumed
    /// already connected and migrated. It is the constructor the
    /// process-singleton accessor
    /// [`current_rust_engine`](crate::current_rust_engine) uses to hand
    /// a co-resident Rust consumer an `Arc<Engine>` view onto the
    /// singleton's backend + signer, with no second connection pool,
    /// runtime, or migration run.
    ///
    /// `backend` is this module's [`BackendDispatch`]; cloning it (or
    /// re-wrapping the singleton's own `BackendDispatch` by cloning the
    /// inner `Arc<…Backend>`) shares the same connection pool.
    pub fn from_shared(backend: BackendDispatch, signer: Arc<dyn HardwareSigner>) -> Engine {
        Engine { backend, signer }
    }

    /// Borrow the SQLite backend Arc, if this Engine was constructed
    /// with a `sqlite://` DSN. Returns `None` for Postgres-backed
    /// Engines (or when the `sqlite` feature is off).
    ///
    /// The returned `Arc<SqliteBackend>` implements
    /// [`FederationDirectory`](crate::federation::FederationDirectory)
    /// and [`OutboundQueue`](crate::outbound::OutboundQueue)
    /// directly — consumers call those trait methods through the
    /// concrete handle.
    #[cfg(feature = "sqlite")]
    pub fn sqlite_backend(&self) -> Option<&Arc<SqliteBackend>> {
        match &self.backend {
            BackendDispatch::Sqlite(b) => Some(b),
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(_) => None,
        }
    }

    /// Borrow the Postgres backend Arc, if this Engine was
    /// constructed with a `postgresql://` / `postgres://` DSN.
    /// Returns `None` for SQLite-backed Engines (or when the
    /// `postgres` feature is off).
    ///
    /// The returned `Arc<PostgresBackend>` implements
    /// [`FederationDirectory`](crate::federation::FederationDirectory)
    /// and [`OutboundQueue`](crate::outbound::OutboundQueue)
    /// directly — consumers call those trait methods through the
    /// concrete handle.
    #[cfg(feature = "postgres")]
    pub fn postgres_backend(&self) -> Option<&Arc<PostgresBackend>> {
        match &self.backend {
            BackendDispatch::Postgres(b) => Some(b),
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(_) => None,
        }
    }

    /// v1.2.0 (CIRISPersist#48) — borrow a per-backend
    /// [`MaintenanceService`](crate::maintenance::MaintenanceService)
    /// handle wrapping the Engine's underlying backend Arc.
    ///
    /// Returns an [`EngineMaintenance`] enum that mirrors the
    /// [`BackendDispatch`] variants. Consumers `match` on the
    /// returned variant to call the trait methods (the trait isn't
    /// object-safe — RPITIT precludes `&dyn MaintenanceService`).
    ///
    /// Cheap: each variant clones the inner backend `Arc` once.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub fn maintenance(&self) -> EngineMaintenance {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => EngineMaintenance::Postgres(
                crate::maintenance::postgres::PostgresMaintenanceBackend::new(b.clone()),
            ),
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => EngineMaintenance::Sqlite(
                crate::maintenance::sqlite::SqliteMaintenanceBackend::new(b.conn_handle()),
            ),
        }
    }

    /// v1.11.0 (CIRISPersist#89) — Rust-public ingest facade: run the
    /// FSD §3.3 pipeline (`schema → verify → scrub → decompose →
    /// backend insert`) over a raw wire body.
    ///
    /// This is the Rust-side sibling of the PyO3
    /// `Engine.receive_and_persist`: relay consumers (CIRISLensCore,
    /// sovereign-mode CIRISEdge) that hold an [`Engine`] can ingest
    /// without going through the Python wheel.
    ///
    /// # Caller-supplied scrubber
    ///
    /// The `scrubber` is NOT owned by the `Engine` and is NOT
    /// defaulted. A relay consumer (already-scrubbed upstream) passes
    /// `&NullScrubber`; a first-hop deployment passes its real
    /// PII-scrubber. `Scrubber` is object-safe, so `&dyn Scrubber`
    /// works for any impl.
    ///
    /// # Facade-internal dependencies
    ///
    /// - **Canonicalizer**: persist's default
    ///   [`PythonJsonDumpsCanonicalizer`](crate::verify::PythonJsonDumpsCanonicalizer)
    ///   — a stateless unit struct; no `Engine` state.
    /// - **Signer**: the `Engine`'s composed `Arc<dyn HardwareSigner>`
    ///   — the federation signer abstraction `IngestPipeline`'s
    ///   `&dyn HardwareSigner` bound wants directly (v1.13.0 / #92: no
    ///   `LocalSignerHardwareAdapter` wrap is built here any more — the
    ///   field is already the right type). The scrub-envelope
    ///   `scrub_key_id` is the signer's [`current_alias`](ciris_keyring::HardwareSigner::current_alias).
    ///
    /// Adds zero new `Engine` fields — every dependency is either
    /// already composed (`signer`) or facade-internal.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn receive_and_persist(
        &self,
        bytes: &[u8],
        scrubber: &dyn Scrubber,
    ) -> Result<crate::ingest::BatchSummary, crate::ingest::IngestError> {
        let key_id = self.signer.current_alias().to_owned();
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(arc) => {
                let pipeline = crate::ingest::IngestPipeline {
                    backend: &**arc,
                    canonicalizer: &crate::verify::PythonJsonDumpsCanonicalizer,
                    scrubber,
                    signer: &*self.signer,
                    signer_key_id: &key_id,
                };
                pipeline.receive_and_persist(bytes).await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(arc) => {
                let pipeline = crate::ingest::IngestPipeline {
                    backend: &**arc,
                    canonicalizer: &crate::verify::PythonJsonDumpsCanonicalizer,
                    scrubber,
                    signer: &*self.signer,
                    signer_key_id: &key_id,
                };
                pipeline.receive_and_persist(bytes).await
            }
        }
    }

    /// v1.11.0 (CIRISPersist#90) — borrow a per-backend
    /// [`NodeCoreService`](crate::cirisnode::NodeCoreService) handle
    /// wrapping the Engine's underlying backend Arc.
    ///
    /// This is the [`Engine`]-side sibling of
    /// [`PyEngine::node_core_service`](crate::ffi::pyo3::PyEngine::node_core_service);
    /// see that accessor's doc-comment for the issue-#90 Option B
    /// rationale. Returns a [`NodeCoreDispatch`] enum mirroring the
    /// [`BackendDispatch`] variants — `NodeCoreService` uses RPITIT
    /// and is not object-safe, so an enum is the object-safe form.
    ///
    /// Cheap: each variant clones / wraps the inner backend handle
    /// once.
    #[cfg(all(feature = "cirisnode", any(feature = "postgres", feature = "sqlite")))]
    pub fn node_core_service(&self) -> NodeCoreDispatch {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => NodeCoreDispatch::Postgres(b.clone()),
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => NodeCoreDispatch::Sqlite(Arc::new(
                crate::cirisnode::sqlite::SqliteNodeCoreBackend::new(b.conn_handle()),
            )),
        }
    }
}

/// v1.11.0 (CIRISPersist#90) — per-backend
/// [`NodeCoreService`](crate::cirisnode::NodeCoreService) handle
/// returned by [`Engine::node_core_service`] /
/// [`PyEngine::node_core_service`](crate::ffi::pyo3::PyEngine::node_core_service).
///
/// `NodeCoreService` uses RPITIT (`fn put_contribution(...) -> impl
/// Future + Send`) and is therefore NOT object-safe — you cannot
/// build `Arc<dyn NodeCoreService>`. This enum is the object-safe
/// dispatch form: callers `match` on the variant and call the trait
/// methods on the concrete backend. Mirrors [`EngineMaintenance`].
#[cfg(all(feature = "cirisnode", any(feature = "postgres", feature = "sqlite")))]
pub enum NodeCoreDispatch {
    /// Postgres-backed NodeCore handle. `PostgresBackend` implements
    /// [`NodeCoreService`](crate::cirisnode::NodeCoreService)
    /// directly.
    #[cfg(feature = "postgres")]
    Postgres(Arc<PostgresBackend>),
    /// SQLite-backed NodeCore handle wrapping
    /// [`SqliteNodeCoreBackend`](crate::cirisnode::sqlite::SqliteNodeCoreBackend).
    #[cfg(feature = "sqlite")]
    Sqlite(Arc<crate::cirisnode::sqlite::SqliteNodeCoreBackend>),
}

/// v1.2.0 (CIRISPersist#48) — per-backend
/// [`MaintenanceService`](crate::maintenance::MaintenanceService)
/// handle returned by [`Engine::maintenance`].
///
/// The trait uses RPITIT and isn't object-safe; this enum lets
/// callers dispatch over the concrete backend without rebuilding
/// the [`BackendDispatch`] match each time.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub enum EngineMaintenance {
    /// Postgres-backed maintenance handle.
    #[cfg(feature = "postgres")]
    Postgres(crate::maintenance::postgres::PostgresMaintenanceBackend),
    /// SQLite-backed maintenance handle.
    #[cfg(feature = "sqlite")]
    Sqlite(crate::maintenance::sqlite::SqliteMaintenanceBackend),
}

/// Build the backend dispatch for an `Engine` from a DSN string.
///
/// Factored out so `Engine::with_signer` and any future Engine
/// constructors share the same URL-sniff + migration shape.
async fn build_backend(dsn: &str) -> Result<BackendDispatch, EngineError> {
    if dsn.starts_with("postgresql://") || dsn.starts_with("postgres://") {
        #[cfg(feature = "postgres")]
        {
            let pg = PostgresBackend::connect(dsn)
                .await
                .map_err(EngineError::Store)?;
            pg.run_migrations().await.map_err(EngineError::Store)?;
            Ok(BackendDispatch::Postgres(Arc::new(pg)))
        }
        #[cfg(not(feature = "postgres"))]
        {
            Err(EngineError::FeatureMissing {
                dsn: dsn.to_string(),
                feature: "postgres",
            })
        }
    } else if dsn.starts_with("sqlite://") || dsn == "sqlite::memory:" {
        #[cfg(feature = "sqlite")]
        {
            let in_memory = dsn == "sqlite::memory:"
                || dsn == "sqlite:///:memory:"
                || dsn == "sqlite://:memory:";
            let sq = if in_memory {
                SqliteBackend::open_in_memory()
                    .await
                    .map_err(EngineError::Store)?
            } else {
                let path = dsn
                    .strip_prefix("sqlite:///")
                    .or_else(|| dsn.strip_prefix("sqlite://"))
                    .unwrap_or(dsn);
                SqliteBackend::open(path)
                    .await
                    .map_err(EngineError::Store)?
            };
            sq.run_migrations().await.map_err(EngineError::Store)?;
            Ok(BackendDispatch::Sqlite(Arc::new(sq)))
        }
        #[cfg(not(feature = "sqlite"))]
        {
            Err(EngineError::FeatureMissing {
                dsn: dsn.to_string(),
                feature: "sqlite",
            })
        }
    } else {
        Err(EngineError::UnrecognizedDsn(dsn.to_string()))
    }
}

/// Errors from [`Engine`] construction.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// DSN didn't match any recognized scheme. Expected
    /// `postgresql://…`, `postgres://…`, `sqlite:///…`, or
    /// `sqlite::memory:`.
    #[error("unrecognized DSN scheme: {0} (expected postgresql:// or sqlite:///...)")]
    UnrecognizedDsn(String),

    /// DSN scheme is recognized but the corresponding cargo feature
    /// wasn't compiled into this build of ciris-persist. Rebuild
    /// with `--features "<feature>"`.
    #[error("DSN `{dsn}` requires the `{feature}` cargo feature, which is not compiled in")]
    FeatureMissing {
        /// The DSN string the caller passed.
        dsn: String,
        /// The cargo feature flag the build is missing
        /// (`"postgres"` or `"sqlite"`).
        feature: &'static str,
    },

    /// Wraps a [`store::Error`](crate::store::Error) from
    /// connect / open / migrate.
    #[error("store: {0}")]
    Store(#[from] StoreError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_signer() -> Arc<LocalSigner> {
        // Deterministic 32-byte seed for fixture reproducibility.
        let seed = [0x7Au8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        Arc::new(LocalSigner::from_parts(
            signing_key,
            "test-engine-steward".to_string(),
            None,
            None,
        ))
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn with_signer_constructs_sqlite_engine_in_memory() {
        let signer = test_signer();
        let engine = Engine::with_signer(signer.clone(), "sqlite::memory:")
            .await
            .expect("construct engine");

        // Backend variant is SQLite when DSN is in-memory.
        match engine.backend() {
            BackendDispatch::Sqlite(_) => {}
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(_) => panic!("expected sqlite arm"),
        }

        // SQLite-specific accessor returns Some.
        let sq = engine.sqlite_backend().expect("sqlite backend present");
        // Holding the Arc independently doesn't disturb the engine.
        let _held: Arc<SqliteBackend> = sq.clone();

        // Signer is reachable through the Arc accessor — v1.13.0 (#92)
        // returns `&Arc<dyn HardwareSigner>`, so sign via the trait
        // (`HardwareSigner` is in module scope via the file-top `use`).
        let sig = engine
            .signer()
            .sign(b"engine-handle-roundtrip")
            .await
            .expect("sign");
        assert_eq!(sig.len(), 64);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn with_signer_arcs_constructs_engine_with_raw_parts() {
        let seed = [0x5Au8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let engine = Engine::with_signer_arcs(
            signing_key,
            "test-arcs-steward".to_string(),
            None,
            None,
            "sqlite::memory:",
        )
        .await
        .expect("construct engine via raw arcs");

        // v1.13.0 (#92): `signer()` is `&Arc<dyn HardwareSigner>`; the
        // signing-identity alias is exposed via `current_alias()`
        // (`HardwareSigner` is in module scope via the file-top `use`).
        assert_eq!(engine.signer().current_alias(), "test-arcs-steward");
        assert!(engine.sqlite_backend().is_some());
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn engine_backend_exposes_concrete_backend_for_trait_dispatch() {
        // Smoke-check: the FederationDirectory + OutboundQueue trait
        // impls are reachable through the concrete `Arc<SqliteBackend>`
        // the Engine composes — the value-add of the substrate API.
        let signer = test_signer();
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("construct engine");

        // FederationDirectory trait reachability (compile-time check —
        // every consumer that holds `engine.backend()` can do this).
        use crate::federation::FederationDirectory;
        let sq = engine.sqlite_backend().expect("sqlite present");
        // A read against an empty directory returns Ok(None).
        // Disambiguate from `Backend::lookup_public_key` (different
        // return type — VerifyingKey vs KeyRecord — but same name).
        let lookup = FederationDirectory::lookup_public_key(&**sq, "not-present-yet")
            .await
            .expect("federation lookup");
        assert!(lookup.is_none());

        // OutboundQueue trait reachability — list with default filter
        // returns an empty page on a fresh DB.
        use crate::outbound::{OutboundFilter, OutboundQueue};
        let rows = sq
            .list_outbound(OutboundFilter::default(), 10)
            .await
            .expect("outbound list");
        assert!(rows.is_empty());
    }

    /// v1.11.0 (CIRISPersist#89) — `receive_and_persist` round-trip on
    /// an in-memory SQLite Engine: a real signed batch + `NullScrubber`
    /// must land rows and report a populated `BatchSummary`.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn receive_and_persist_round_trips_signed_batch() {
        use crate::schema::{
            CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion, TraceComponent,
            TraceLevel,
        };
        use crate::scrub::NullScrubber;
        use crate::verify::{
            ed25519::canonical_payload_value, Canonicalizer, PythonJsonDumpsCanonicalizer,
        };
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ed25519_dalek::{Signer as _, SigningKey};

        // Agent identity that signs the trace (distinct from the
        // Engine's local scrub-signer identity).
        let agent_sk = SigningKey::from_bytes(&[0x42; 32]);
        let agent_key_id = "ciris-agent-key:engine-89";

        let mut trace = CompleteTrace {
            trace_id: "trace-engine-89".into(),
            thought_id: "th-1".into(),
            task_id: Some("task-1".into()),
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-30T00:15:53.123456Z".parse().unwrap(),
            completed_at: "2026-04-30T00:16:12.789012Z".parse().unwrap(),
            trace_level: TraceLevel::Generic,
            trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
            components: vec![TraceComponent {
                component_type: ComponentType::Observation,
                event_type: ReasoningEventType::ThoughtStart,
                timestamp: "2026-04-30T00:15:53.123Z".parse().unwrap(),
                data: {
                    let mut m = serde_json::Map::new();
                    m.insert("attempt_index".into(), 0.into());
                    m
                },
                agent_id_hash: None,
            }],
            deployment_profile: None,
            signature: String::new(),
            signature_key_id: agent_key_id.into(),
        };
        let payload = canonical_payload_value(&trace);
        let canonical = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&payload)
            .unwrap();
        trace.signature = B64.encode(agent_sk.sign(&canonical).to_bytes());

        let trace_json = serde_json::to_value(&trace).unwrap();
        let envelope = serde_json::json!({
            "events": [{
                "event_type": "complete_trace",
                "trace_level": "generic",
                "trace": trace_json,
            }],
            "batch_timestamp": "2026-04-30T15:00:00+00:00",
            "consent_timestamp": "2025-01-01T00:00:00Z",
            "trace_level": "generic",
            "trace_schema_version": "2.7.0",
        });
        let bytes = envelope.to_string().into_bytes();

        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct engine");

        // Register the agent's pubkey in the SQLite federation_keys
        // directory so the verify step can resolve it. The federation
        // ingest path is exercised elsewhere; here we seed the row
        // directly through the public connection handle.
        let sq = engine.sqlite_backend().expect("sqlite backend");
        let conn = sq.conn_handle();
        let agent_pk_b64 = B64.encode(agent_sk.verifying_key().to_bytes());
        let key_id_owned = agent_key_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO federation_keys (\
                    key_id, pubkey_ed25519_base64, algorithm, \
                    identity_type, identity_ref, valid_from, \
                    registration_envelope, original_content_hash, \
                    scrub_signature_classical, scrub_key_id, \
                    scrub_timestamp, persist_row_hash\
                 ) VALUES (?1, ?2, 'hybrid', 'agent', ?1, ?3, '{}', \
                          x'00', '', ?1, ?3, '0')",
                rusqlite::params![key_id_owned, agent_pk_b64, "2026-04-30T00:00:00+00:00"],
            )
            .expect("seed federation key");
        })
        .await
        .expect("spawn_blocking join");

        let summary = engine
            .receive_and_persist(&bytes, &NullScrubber)
            .await
            .expect("receive_and_persist succeeds");

        assert_eq!(summary.envelopes_processed, 1);
        assert_eq!(summary.signatures_verified, 1);
        assert_eq!(summary.trace_events_inserted, 1, "one component → one row");
        assert_eq!(summary.trace_events_conflicted, 0);
        assert_eq!(summary.scrubbed_fields, 0, "NullScrubber modifies nothing");

        // Idempotency: replaying the same bytes conflicts, inserts 0.
        let replay = engine
            .receive_and_persist(&bytes, &NullScrubber)
            .await
            .expect("replay succeeds");
        assert_eq!(replay.trace_events_inserted, 0);
        assert_eq!(replay.trace_events_conflicted, 1);
    }

    /// v1.11.0 (CIRISPersist#89) — `receive_and_persist` rejects an
    /// unverifiable batch (unknown signing key) with a typed
    /// `IngestError::Verify` and writes nothing.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn receive_and_persist_rejects_unknown_key() {
        use crate::ingest::IngestError;
        use crate::scrub::NullScrubber;

        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct engine");

        // A syntactically valid envelope whose signing key was never
        // registered. `from_json` parses, verify rejects.
        let body = serde_json::json!({
            "events": [],
            "batch_timestamp": "2026-04-30T15:00:00+00:00",
            "consent_timestamp": "2025-01-01T00:00:00Z",
            "trace_level": "generic",
            "trace_schema_version": "2.7.0"
        });
        let err = engine
            .receive_and_persist(body.to_string().as_bytes(), &NullScrubber)
            .await
            .expect_err("empty events array must be rejected");
        // Empty events[] is a schema reject — confirms the facade
        // surfaces typed IngestError variants unchanged.
        assert!(matches!(err, IngestError::Schema(_)), "got: {err:?}");
    }

    /// v1.11.0 (CIRISPersist#90) — `Engine::node_core_service` returns
    /// the SQLite dispatch variant and a `put_contribution` /
    /// `list_contributions` round-trips through it.
    #[cfg(all(feature = "cirisnode", feature = "sqlite"))]
    #[tokio::test]
    async fn node_core_service_sqlite_round_trip() {
        use crate::cirisnode::{
            Cell, ContributionEnvelope, ContributionType, ContributionsFilter, HybridSignature,
            NodeCoreService,
        };
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use chrono::Utc;
        use ed25519_dalek::{Signer as _, SigningKey};
        use uuid::Uuid;

        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct engine");

        let dispatch = engine.node_core_service();
        let backend = match dispatch {
            NodeCoreDispatch::Sqlite(b) => b,
            #[cfg(feature = "postgres")]
            NodeCoreDispatch::Postgres(_) => panic!("expected sqlite NodeCore variant"),
        };

        // Build + sign a Contribution envelope (the contributor's
        // pubkey IS the author_id, per SCHEMA.md §2.2).
        let author_key = SigningKey::from_bytes(&[0xA1; 32]);
        let author = B64.encode(author_key.verifying_key().to_bytes());
        let domain = format!("engine90-dom-{}", Uuid::new_v4());
        let mut env = ContributionEnvelope {
            contribution_id: Uuid::new_v4().to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author.clone(),
            subject: Cell {
                domain: domain.clone(),
                language: "en".into(),
                subject: Some("arc_question".into()),
            },
            payload: serde_json::json!({"question_id": "engine90_q01"}),
            witness_set: None,
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            submitted_at: Utc::now(),
        };
        let canonical =
            crate::cirisnode::verify::canonical_bytes_for_envelope(&env).expect("canonical bytes");
        env.signature.ed25519 = B64.encode(author_key.sign(&canonical).to_bytes());

        backend
            .put_contribution(env.clone())
            .await
            .expect("put_contribution through NodeCoreDispatch");

        let page = backend
            .list_contributions(
                ContributionsFilter {
                    domain: Some(domain.clone()),
                    ..Default::default()
                },
                None,
                10,
            )
            .await
            .expect("list_contributions through NodeCoreDispatch");
        assert_eq!(page.items.len(), 1, "the contribution we inserted");
        assert_eq!(page.items[0].contribution_id, env.contribution_id);
    }

    #[tokio::test]
    async fn with_signer_rejects_unrecognized_dsn() {
        let signer = test_signer();
        // `Result::expect_err` requires Debug on the Ok value;
        // Engine intentionally doesn't derive Debug (the underlying
        // backend types don't either). Use `match` instead.
        match Engine::with_signer(signer, "redis://nope").await {
            Ok(_) => panic!("must reject unknown scheme"),
            Err(EngineError::UnrecognizedDsn(_)) => {}
            Err(other) => panic!("unexpected error variant: {other:?}"),
        }
    }
}
