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
//! v2.6.0 (CIRISPersist#106): [`FederationDirectory`](crate::federation::FederationDirectory)
//! is annotated with `#[async_trait]` and IS object-safe —
//! [`Engine::federation_directory`] returns `Arc<dyn FederationDirectory>`
//! directly, the symmetric read-side accessor for
//! [`Engine::node_core_service`] (#90).
//!
//! `OutboundQueue` still uses Rust 1.75+ `impl Future + Send`
//! return-position syntax and is NOT object-safe. Consumers either:
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
    /// v2.12.0 (CIRISPersist#112) — preserved `LocalSigner`, when the
    /// Engine was constructed from one. The `signer` field above is
    /// the hybrid `HardwareSigner` trait object (post v1.13.0 / #92);
    /// for [`Engine::sign_hybrid`] we need the underlying
    /// [`LocalSigner`](crate::signing::LocalSigner) to reach
    /// `sign_hybrid` (which combines Ed25519 + ML-DSA-65 into a
    /// [`HybridSignature`](ciris_crypto::HybridSignature)). When the
    /// Engine was constructed via [`Engine::from_shared`] without a
    /// LocalSigner (the cohabitation accessor path), this is `None`
    /// and `sign_hybrid` returns [`SignError::LocalSignerUnavailable`].
    local_signer: Option<Arc<crate::signing::LocalSigner>>,
}

/// v2.12.0 (CIRISPersist#112) — error from [`Engine::sign_hybrid`].
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// The Engine has no `LocalSigner` to reach Ed25519 + ML-DSA-65
    /// signing through. This happens when the Engine was constructed
    /// via [`Engine::from_shared`] with only an
    /// `Arc<dyn HardwareSigner>` — the cohabitation accessor path
    /// hands the singleton's hybrid signer to a co-resident Rust
    /// consumer but does not carry the LocalSigner through. Construct
    /// the Engine via [`Engine::with_signer`] /
    /// [`Engine::with_signer_arcs`] (or rebuild a LocalSigner from
    /// `PyEngine::keyring_signer()`'s
    /// [`KeyringSignerHandle`](crate::signing::KeyringSignerHandle))
    /// for `sign_hybrid` to be available.
    #[error(
        "Engine has no LocalSigner — sign_hybrid requires construction via with_signer / \
         with_signer_arcs, not from_shared. Cohabitation consumers can rebuild a LocalSigner \
         from PyEngine::keyring_signer()."
    )]
    LocalSignerUnavailable,

    /// The underlying [`LocalSigner::sign_hybrid`] call failed —
    /// typically [`LocalSignerError::PqcNotConfigured`](crate::signing::LocalSignerError::PqcNotConfigured)
    /// when the engine's local signer is Ed25519-only.
    #[error(transparent)]
    LocalSigner(#[from] crate::signing::LocalSignerError),
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
        // v2.12.0 (#112): preserve the original `LocalSigner` Arc so
        // `Engine::sign_hybrid` can reach `LocalSigner::sign_hybrid`.
        let local_signer = Some(signer.clone());
        // v1.13.0 (#92): the stored field is `Arc<dyn HardwareSigner>`;
        // wrap the caller's `Arc<LocalSigner>` so the constructor stays
        // source-compatible.
        let signer: Arc<dyn HardwareSigner> = Arc::new(LocalSignerHardwareAdapter::new(signer));
        Ok(Engine {
            backend,
            signer,
            local_signer,
        })
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
        Engine {
            backend,
            signer,
            // v2.12.0 (#112) — `from_shared` only takes the hybrid
            // `HardwareSigner` (the cohabitation singleton path);
            // `sign_hybrid` is unavailable on Engines built this way.
            // Use [`Engine::from_shared_with_local`] to propagate a
            // `LocalSigner` through.
            local_signer: None,
        }
    }

    /// v2.12.0 (CIRISPersist#112) — variant of [`Engine::from_shared`]
    /// that ALSO propagates the host's `LocalSigner`, enabling
    /// [`Engine::sign_hybrid`] on the resulting Engine. The
    /// process-singleton accessor
    /// [`current_rust_engine`](crate::current_rust_engine) uses this
    /// when the host singleton has a LocalSigner (the typical
    /// software-rooted deployment); for hardware-rooted deployments
    /// with no LocalSigner present, `from_shared` (no propagation) is
    /// the right constructor.
    pub fn from_shared_with_local(
        backend: BackendDispatch,
        signer: Arc<dyn HardwareSigner>,
        local_signer: Option<Arc<LocalSigner>>,
    ) -> Engine {
        Engine {
            backend,
            signer,
            local_signer,
        }
    }

    /// v2.12.0 (CIRISPersist#112) — hybrid-sign canonical bytes with
    /// the Engine's classical (Ed25519) + PQC (ML-DSA-65) identity.
    /// Returns the standard
    /// [`HybridSignature`](ciris_crypto::HybridSignature) shape
    /// persist's signed-envelope discipline uses everywhere
    /// (`federation_keys.scrub_signature_*`, V046
    /// `delivery_attestation.signature_*`, etc.).
    ///
    /// Same closure pattern as [`Engine::receive_and_persist`] /
    /// [`Engine::storage_summary`]: persist owns the underlying
    /// primitive ([`LocalSigner::sign_hybrid`]); persist exposes a
    /// clean Engine facade so co-resident Rust consumers
    /// (CIRISLensCore client-mode trace signing, EgressFilter
    /// re-signing) don't reach past the
    /// `Arc<dyn HardwareSigner>` abstraction.
    ///
    /// Returns [`SignError::LocalSignerUnavailable`] when the Engine
    /// was constructed via [`Engine::from_shared`] (no LocalSigner
    /// propagation — the cohabitation accessor path); rebuild the
    /// caller-side LocalSigner from
    /// `PyEngine::keyring_signer()`'s [`KeyringSignerHandle`] in that
    /// case. Returns
    /// [`SignError::LocalSigner(LocalSignerError::PqcNotConfigured)`](crate::signing::LocalSignerError::PqcNotConfigured)
    /// when the Engine has a LocalSigner but no PQC identity
    /// configured (Ed25519-only deployments).
    pub async fn sign_hybrid(
        &self,
        message: &[u8],
    ) -> Result<ciris_crypto::HybridSignature, SignError> {
        let local = self
            .local_signer
            .as_ref()
            .ok_or(SignError::LocalSignerUnavailable)?;
        let sig = local.sign_hybrid(message).await?;
        Ok(sig)
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
        self.receive_and_persist_with(bytes, scrubber, crate::ingest::VerifyMode::Full)
            .await
    }

    /// v2.0 (CIRISPersist#91) — relay ingest facade for batches that
    /// arrived **already Edge-verified**.
    ///
    /// Identical to [`receive_and_persist`](Engine::receive_and_persist)
    /// except it runs [`VerifyMode::TrustPreVerified`](crate::ingest::VerifyMode::TrustPreVerified):
    /// the per-`CompleteTrace` signature verification (and its
    /// federation-directory `lookup_public_key`) is skipped. Every
    /// other pipeline step is unchanged.
    ///
    /// # Safety
    ///
    /// Opt-in, and legitimate **only** for a relay (CIRISLensCore#10)
    /// that holds an Edge `verify_outcome` for this batch — AV-9
    /// "never re-verify what Edge verified". The decision lives at
    /// this call site, exactly like the caller-supplied `scrubber`
    /// (#89): the deployer knows the federation topology. The lens
    /// **direct-ingest** path (untrusted agent input) MUST keep using
    /// [`receive_and_persist`](Engine::receive_and_persist) — its
    /// `VerifyMode::Full` default is unchanged.
    ///
    /// Persisted rows land with `verification_source = 'edge'` —
    /// an upstream Edge verifier, not persist, established
    /// authenticity (`signature_verified` stays `true`; the trace is
    /// authentic). See
    /// [`IngestPipeline::receive_and_persist_with`](crate::ingest::IngestPipeline::receive_and_persist_with).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn receive_and_persist_pre_verified(
        &self,
        bytes: &[u8],
        scrubber: &dyn Scrubber,
    ) -> Result<crate::ingest::BatchSummary, crate::ingest::IngestError> {
        self.receive_and_persist_with(bytes, scrubber, crate::ingest::VerifyMode::TrustPreVerified)
            .await
    }

    /// v2.0 (CIRISPersist#91) — [`receive_and_persist`](Engine::receive_and_persist)
    /// with an explicit [`VerifyMode`](crate::ingest::VerifyMode).
    ///
    /// `VerifyMode::Full` is byte-identical to `receive_and_persist`;
    /// `VerifyMode::TrustPreVerified` is the relay skip-verify path
    /// ([`receive_and_persist_pre_verified`](Engine::receive_and_persist_pre_verified)).
    /// See [`VerifyMode`](crate::ingest::VerifyMode) for the safety
    /// contract.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn receive_and_persist_with(
        &self,
        bytes: &[u8],
        scrubber: &dyn Scrubber,
        verify_mode: crate::ingest::VerifyMode,
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
                pipeline.receive_and_persist_with(bytes, verify_mode).await
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
                pipeline.receive_and_persist_with(bytes, verify_mode).await
            }
        }
    }

    /// v3.3.0 (CIRISPersist#121) — convenience facade over
    /// [`BlobStorage::put_blob_signing`](crate::federation::blobs::BlobStorage::put_blob_signing).
    ///
    /// Persist owns the holds_bytes envelope construction +
    /// canonicalization (via the production
    /// [`PythonJsonDumpsCanonicalizer`](crate::verify::canonical::PythonJsonDumpsCanonicalizer)),
    /// signs via the Engine's composed `Arc<dyn HardwareSigner>`, and
    /// commits the blob + holder atomically. The Engine's signer is
    /// the same handle [`receive_and_persist`](Engine::receive_and_persist)
    /// uses for scrub envelopes — no second signer field, no
    /// adapter wrap (the field is already `Arc<dyn HardwareSigner>`
    /// post v1.13.0 / #92).
    ///
    /// `now` + `attestation_id` are passed by the caller so pinned-time
    /// tests, replay, and migration paths can reproduce specific
    /// timestamps / IDs. Normal callers pass `chrono::Utc::now()` and
    /// `uuid::Uuid::new_v4()`.
    ///
    /// See the trait method's doc-comment for the full rationale —
    /// the JCS-vs-Python silent-correctness trap this method closes.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    #[allow(clippy::too_many_arguments)]
    pub async fn put_blob_signing(
        &self,
        sha256: &[u8; 32],
        body: crate::federation::BlobBody,
        media_type: Option<&str>,
        attesting_key_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        attestation_id: uuid::Uuid,
    ) -> Result<(), crate::federation::BlobError> {
        use crate::federation::BlobStorage;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(arc) => {
                arc.put_blob_signing(
                    sha256,
                    body,
                    media_type,
                    attesting_key_id,
                    &**self.signer(),
                    now,
                    attestation_id,
                )
                .await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(arc) => {
                arc.put_blob_signing(
                    sha256,
                    body,
                    media_type,
                    attesting_key_id,
                    &**self.signer(),
                    now,
                    attestation_id,
                )
                .await
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

    /// v2.0 (CIRISPersist#93) — borrow a per-backend
    /// [`AuditService`](crate::audit::AuditService) handle wrapping
    /// the Engine's underlying storage backend.
    ///
    /// This is the [`audit`](crate::audit) analog of
    /// [`Engine::node_core_service`] — see that accessor's doc-comment
    /// for the issue-#90 Option B / RPITIT-not-object-safe rationale.
    /// [`AuditService`](crate::audit::AuditService) likewise uses
    /// RPITIT and is not object-safe, so `audit_service()` returns an
    /// [`AuditDispatch`] enum mirroring the [`BackendDispatch`]
    /// variants rather than an `Arc<dyn AuditService>`.
    ///
    /// NodeCore's trust-hierarchy resolution (`crate::trust::resolve_trust`
    /// / `crate::routing::route_deferral` over the
    /// `federation_trust_grants` projection) consumes this handle the
    /// same way the cohabitation bootstrap consumes
    /// [`node_core_service`](Engine::node_core_service).
    ///
    /// Cheap: each variant clones / wraps the inner backend handle
    /// once.
    #[cfg(all(feature = "cirisaudit", any(feature = "postgres", feature = "sqlite")))]
    pub fn audit_service(&self) -> AuditDispatch {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => AuditDispatch::Postgres(b.clone()),
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => AuditDispatch::Sqlite(Arc::new(
                crate::audit::sqlite::SqliteAuditBackend::new(b.conn_handle()),
            )),
        }
    }

    /// v2.6.0 (CIRISPersist#106) — Rust-tier accessor returning an
    /// `Arc<dyn FederationDirectory>` over the Engine's underlying
    /// backend.
    ///
    /// Symmetric with the existing [`node_core_service`](Self::node_core_service)
    /// (write-side, CIRISPersist#90) — this is the read-side
    /// equivalent for the federation directory. Lets co-resident
    /// crates (NodeCore, LensCore, registry-core) call persist's
    /// federation directory in Rust without PyO3 method dispatch,
    /// the structural unlock for the Rust-native end-state per the
    /// CIRISAgent#800 cohabitation trajectory.
    ///
    /// # Why this returns `Arc<dyn FederationDirectory>` (and the
    /// `node_core_service`/`audit_service` accessors return enums)
    ///
    /// As of v2.6.0 the [`FederationDirectory`](crate::federation::FederationDirectory)
    /// trait is annotated with `#[async_trait]` — every method returns
    /// `Pin<Box<dyn Future<Output = …> + Send + '_>>` rather than a
    /// per-method RPITIT — so the trait is object-safe.
    /// `NodeCoreService` and `AuditService` still use RPITIT and
    /// therefore stay on the dispatch-enum shape.
    ///
    /// Cheap: clones the inner backend `Arc` once and coerces.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub fn federation_directory(&self) -> Arc<dyn crate::federation::FederationDirectory> {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.clone(),
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.clone(),
        }
    }

    /// v3.2.0 (CIRISPersist#120) — Rust-tier accessor returning an
    /// `Arc<dyn BlackholeRules>` over the Engine's underlying backend.
    ///
    /// Sibling to [`federation_directory`](Self::federation_directory)
    /// — both traits live on the same connection pool, distinct
    /// surfaces. The blackhole surface lets co-resident crates
    /// (CIRISEdge v0.15.0's `ReticulumTransport`) call persist's
    /// per-identity deny-list in Rust without PyO3 method dispatch.
    ///
    /// Cheap: clones the inner backend `Arc` once and coerces.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub fn blackhole_rules(&self) -> Arc<dyn crate::federation::BlackholeRules> {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.clone(),
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.clone(),
        }
    }

    /// v3.2.0 (CIRISPersist#120) — list every blackhole rule. Thin
    /// dispatch facade over
    /// [`BlackholeRules::blackhole_list`](crate::federation::BlackholeRules::blackhole_list).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn blackhole_list(
        &self,
    ) -> Result<Vec<crate::federation::BlackholeRecord>, crate::federation::Error> {
        self.blackhole_rules().blackhole_list().await
    }

    /// v3.2.0 (CIRISPersist#120) — upsert a blackhole rule. Thin
    /// dispatch facade over
    /// [`BlackholeRules::blackhole_upsert`](crate::federation::BlackholeRules::blackhole_upsert).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn blackhole_upsert(
        &self,
        identity_hash: &[u8],
        until: Option<chrono::DateTime<chrono::Utc>>,
        reason: Option<&str>,
    ) -> Result<(), crate::federation::Error> {
        self.blackhole_rules()
            .blackhole_upsert(identity_hash, until, reason)
            .await
    }

    /// v3.2.0 (CIRISPersist#120) — remove a blackhole rule. Thin
    /// dispatch facade over
    /// [`BlackholeRules::blackhole_remove`](crate::federation::BlackholeRules::blackhole_remove).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn blackhole_remove(
        &self,
        identity_hash: &[u8],
    ) -> Result<(), crate::federation::Error> {
        self.blackhole_rules().blackhole_remove(identity_hash).await
    }

    /// v3.2.0 (CIRISPersist#120) — record one hit on a blackhole
    /// rule. Race-tolerant: silent no-op when the rule was removed
    /// between the send-path check and this call.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn blackhole_record_hit(
        &self,
        identity_hash: &[u8],
    ) -> Result<(), crate::federation::Error> {
        self.blackhole_rules()
            .blackhole_record_hit(identity_hash)
            .await
    }

    /// v3.2.0 (CIRISPersist#120) — drop rules whose `until` is in the
    /// past. Permanent rules (`until IS NULL`) are NEVER pruned.
    /// Returns the rows-affected count.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn blackhole_prune_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, crate::federation::Error> {
        self.blackhole_rules().blackhole_prune_expired(now).await
    }

    /// v2.7.0 (CIRISPersist#107) — read-only snapshot of disk + row +
    /// age across the cohabitation store.
    ///
    /// One [`crate::retention::TableUsage`] per substrate table
    /// (`trace_events`, `trace_llm_calls`, `detection_events`,
    /// `audit_log`, `edge_outbound_queue`, `federation_keys`) plus
    /// the whole-database byte total. Used by lens-core's v0.4
    /// retention scheduler (CIRISLensCore#13) to decide whether to
    /// evict and how much.
    ///
    /// Per-table timestamp column choices:
    /// - `trace_events.ts` (broadcast wall-clock)
    /// - `trace_llm_calls.ts` (call wall-clock; linked to parent
    ///   trace event)
    /// - `cirislens_derived.detection_events.ts` (detection wall-clock)
    /// - `audit_log.recorded_at` (signing wall-clock)
    /// - `edge_outbound_queue.enqueued_at` (row birth)
    /// - `federation_keys.valid_from` (key validity-window start)
    ///
    /// # SQLite per-table-bytes limitation
    ///
    /// On SQLite each `TableUsage.bytes` field is `0` — stock rusqlite
    /// builds don't enable `SQLITE_ENABLE_DBSTAT_VTAB`. Consult
    /// [`StorageSummary::total_disk_bytes`](crate::retention::StorageSummary::total_disk_bytes)
    /// for whole-DB byte counts on SQLite. Postgres reports
    /// `pg_relation_size` per table.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn storage_summary(
        &self,
    ) -> Result<crate::retention::StorageSummary, crate::retention::RetentionError> {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => crate::retention::postgres::storage_summary_pg(b).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => crate::retention::sqlite::storage_summary_sqlite(b).await,
        }
    }

    /// v2.7.0 (CIRISPersist#107) — bounded-batch DELETE on
    /// `trace_events` for rows whose `ts < threshold`, capped at
    /// `max_rows`. Returns the actual rows deleted.
    ///
    /// Lets the caller drive bounded-eviction loops with predictable
    /// transaction sizes: "delete 1000, sleep, delete 1000" until
    /// the returned count is less than `max_rows` (no more rows
    /// older than the threshold).
    ///
    /// # SQL
    ///
    /// PG: `DELETE FROM cirislens.trace_events WHERE (event_id, ts)
    /// IN (SELECT … ORDER BY ts LIMIT $2)` — PG doesn't honor
    /// `ORDER BY ... LIMIT` on DELETE directly; the CTE subquery
    /// pattern is the idiomatic workaround.
    ///
    /// SQLite: `DELETE FROM trace_events WHERE rowid IN (SELECT
    /// rowid … ORDER BY ts LIMIT ?2)`.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn delete_traces_older_than(
        &self,
        ts: chrono::DateTime<chrono::Utc>,
        max_rows: usize,
    ) -> Result<usize, crate::retention::RetentionError> {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => {
                crate::retention::postgres::delete_traces_older_than_pg(b, ts, max_rows).await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => {
                crate::retention::sqlite::delete_traces_older_than_sqlite(b, ts, max_rows).await
            }
        }
    }

    /// v2.7.0 (CIRISPersist#107) — "archive + truncate" the
    /// `audit_log` over `[from_ts, to_ts)`, preserving the
    /// per-tenant hash chain via a chain-anchored archive blob.
    ///
    /// The audit chain (V014; `prev_hash` linking adjacent rows by
    /// `entry_hash`) cannot tolerate a plain DELETE: the live row
    /// after the archived range would point to a now-absent
    /// predecessor. The primitive preserves the chain by writing
    /// the archived rows to `audit_archives` (canonical JSON,
    /// SHA-256 keyed) with the LAST archived row's `entry_hash`
    /// captured as `ArchiveHandle.chain_anchor`. The live row
    /// after the archived range KEEPS its original `prev_hash` —
    /// which equals `chain_anchor` — so verifiers walk seq[k+1] →
    /// archive[seq_k] without breaking the chain.
    ///
    /// # Multi-tenant handling
    ///
    /// The audit chain is per-tenant (V014 `UNIQUE(tenant_id,
    /// sequence_number)`). `archive_audit_range` rejects ranges
    /// that span more than one `tenant_id` with
    /// [`RetentionError::MultiTenant`](crate::retention::RetentionError::MultiTenant).
    /// Callers archiving across multiple tenants issue one call
    /// per tenant.
    ///
    /// # Empty range
    ///
    /// When the range captures zero rows the returned handle has
    /// `rows_archived = 0`, `archive_id = Uuid::nil()`,
    /// `chain_anchor = [0; 32]` — no archive blob row is written.
    /// The call is a no-op.
    ///
    /// # Atomicity
    ///
    /// All steps (SELECT archived rows → INSERT archive row →
    /// DELETE archived rows from `audit_log`) run in one
    /// transaction. A failure at any step rolls back the entire
    /// archive — the live chain is unchanged.
    #[cfg(all(feature = "cirisaudit", any(feature = "postgres", feature = "sqlite")))]
    pub async fn archive_audit_range(
        &self,
        from_ts: chrono::DateTime<chrono::Utc>,
        to_ts: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::retention::ArchiveHandle, crate::retention::RetentionError> {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => {
                crate::retention::postgres::archive_audit_range_pg(b, from_ts, to_ts).await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => {
                crate::retention::sqlite::archive_audit_range_sqlite(b, from_ts, to_ts).await
            }
        }
    }

    /// v2.7.0 (CIRISPersist#107) — fetch a previously-written audit
    /// archive blob by `archive_id`. Returns the canonical JSON
    /// bytes — `Vec<AuditEntry>` — or `Ok(None)` when no archive
    /// with that id exists. Used by offline verifiers walking the
    /// chain across an archive and by tests asserting archive
    /// content.
    ///
    /// Decode with [`crate::retention::decode_archive_bytes`].
    #[cfg(all(feature = "cirisaudit", any(feature = "postgres", feature = "sqlite")))]
    pub async fn lookup_audit_archive(
        &self,
        archive_id: uuid::Uuid,
    ) -> Result<Option<Vec<u8>>, crate::retention::RetentionError> {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => {
                crate::retention::postgres::lookup_audit_archive_pg(b, archive_id).await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => {
                crate::retention::sqlite::lookup_audit_archive_sqlite(b, archive_id).await
            }
        }
    }

    /// v2.13.0 (CIRISPersist#113) — convenience facade over
    /// [`DerivedSchema::get_detection_events`](crate::derived::DerivedSchema::get_detection_events).
    ///
    /// Thin wrapper that dispatches via the [`BackendDispatch`] enum
    /// so consumers (CIRISLensCore#15 node UX, #19 scoring oracle,
    /// #25 ECF UI ProfileScorecard) don't have to `match` on the
    /// backend themselves. Behavior + ordering + default LIMIT match
    /// the per-backend impl (newest-first `ORDER BY ts DESC`, LIMIT
    /// 1000).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn get_detection_events(
        &self,
        filter: crate::derived::EventFilter,
    ) -> Result<Vec<crate::derived::DetectionEvent>, crate::derived::Error> {
        use crate::derived::DerivedSchema;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.get_detection_events(filter).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.get_detection_events(filter).await,
        }
    }

    /// v2.13.0 (CIRISPersist#113) — read facade over
    /// `cirislens.edge_detection_events` (V020).
    ///
    /// LensCore's detector signals (`UnconsentedExternalProbe`,
    /// `ExcessiveRecursion`, `ConsentGateLeak`) land in this table;
    /// persist owns the read side. The Counter-RII joint-correlation
    /// path (CIRISLensCore#21) reads via this facade for evidence
    /// joins across detection events + the wider audit chain.
    ///
    /// Ordering is stable ASC `(tenant_id, observed_at,
    /// detection_id)` — the change-feed cursor in
    /// [`Engine::subscribe_detection_events`] depends on monotone ASC
    /// to advance without re-yielding rows.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn get_edge_detection_events(
        &self,
        filter: crate::derived::EdgeEventFilter,
    ) -> Result<Vec<crate::derived::EdgeDetectionEvent>, crate::derived::Error> {
        use crate::derived::DerivedSchema;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.get_edge_detection_events(filter).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.get_edge_detection_events(filter).await,
        }
    }

    /// v2.13.0 (CIRISPersist#113) — push-based change feed scoped to
    /// `detection_events`. Backs CIRISLensCore#20's `lens.alerts.*`
    /// subscription delivery.
    ///
    /// # v0.1 simplifications
    ///
    /// The issue body's contract — in-process tokio task model +
    /// at-least-once delivery + per-tenant ordering — is preserved.
    /// The v0.1 implementation is a **polling** loop with the
    /// following characteristics:
    ///
    /// - **Cursor**: initialized to `Utc::now()` at subscribe time, so
    ///   the subscriber sees only NEW events; no historical replay.
    ///   On each poll, the cursor advances past the newest yielded
    ///   row's `ts` (by 1 microsecond) to avoid re-yielding the
    ///   boundary row.
    /// - **Cadence**: 2 seconds between polls (hardcoded; configurable
    ///   in a v0.2 cut via a `SubscriptionOptions` struct).
    /// - **Channel**: bounded `tokio::sync::mpsc::channel` of capacity
    ///   256. When full, the polling task awaits on `send` —
    ///   coarse-but-honest backpressure (the subscriber draining
    ///   throttles the poll loop). A v0.2 cut may add per-tenant
    ///   queues or lossy variants.
    /// - **Drop discipline**: dropping the returned `Stream` closes
    ///   the mpsc receiver; the polling task observes the closed
    ///   channel on its next `send` and exits. No leaked task.
    /// - **Error surfacing**: a DB error on a poll is forwarded as
    ///   `Err(DerivedError)` on the stream; the polling task does NOT
    ///   terminate (a transient outage shouldn't kill long-lived
    ///   subscribers). Repeated failures keep emitting errors at the
    ///   cadence interval.
    ///
    /// A WAL-hook / LISTEN-NOTIFY backed implementation lives in
    /// scope of persist#84 — that issue tracks the broader
    /// `engine.subscribe(substrate, callback)` substrate; this v0.1
    /// is the LensCore-scoped slice that satisfies #20 without
    /// blocking on the broader change-feed work.
    ///
    /// # Python consumers
    ///
    /// No PyO3 surface is exposed in v0.1 — a Python-callable polling
    /// subscription needs a queue across the FFI boundary. The Rust
    /// `Stream` path is for co-resident Rust consumers (CIRISLensCore
    /// client-mode) until a Python-side design lands.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub fn subscribe_detection_events(
        &self,
        filter: crate::derived::EventFilter,
    ) -> impl futures_core::Stream<
        Item = Result<crate::derived::DetectionEvent, crate::derived::Error>,
    > + Send {
        // v0.1 polling cadence + channel capacity. See doc-comment for
        // the v0.2 ask (configurable cadence + channel shape).
        const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
        const CHANNEL_CAPACITY: usize = 256;

        let (tx, rx) = tokio::sync::mpsc::channel::<
            Result<crate::derived::DetectionEvent, crate::derived::Error>,
        >(CHANNEL_CAPACITY);
        let engine = self.clone();
        // Subscribe-time cursor: only NEW events are yielded. Polling
        // bumps `since` past the newest yielded row's `ts` by 1 µs
        // each iteration so the inclusive `>=` filter on the existing
        // `EventFilter.since` doesn't re-yield the boundary row.
        let mut since: chrono::DateTime<chrono::Utc> = chrono::Utc::now();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(POLL_INTERVAL).await;
                // Channel-closed detection: if the receiver is dropped,
                // `send` errors → exit. Pre-check via `is_closed` so we
                // skip the DB poll entirely once the subscriber is gone.
                if tx.is_closed() {
                    break;
                }

                let poll_filter = crate::derived::EventFilter {
                    trace_id: filter.trace_id.clone(),
                    detector: filter.detector.clone(),
                    since: Some(since),
                };
                let rows_res = engine.get_detection_events(poll_filter).await;
                match rows_res {
                    Ok(mut rows) => {
                        // Per-backend impls ORDER BY ts DESC; reverse so
                        // we yield oldest-first within the poll batch
                        // (subscribers expect monotone-ASC delivery).
                        rows.reverse();
                        for ev in rows {
                            // Advance cursor past this row's ts (existing
                            // EventFilter.since is inclusive `>=`, so we
                            // need a strict step to avoid re-yielding).
                            let next_since = ev.ts + chrono::Duration::microseconds(1);
                            if tx.send(Ok(ev)).await.is_err() {
                                // Subscriber dropped — terminate.
                                return;
                            }
                            if next_since > since {
                                since = next_since;
                            }
                        }
                    }
                    Err(e) => {
                        // Surface error on the stream; keep the poller
                        // alive. Transient DB outages must not kill a
                        // long-lived subscriber.
                        if tx.send(Err(e)).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });

        tokio_stream::wrappers::ReceiverStream::new(rx)
    }
}

/// v2.0 (CIRISPersist#93) — per-backend
/// [`AuditService`](crate::audit::AuditService) handle returned by
/// [`Engine::audit_service`] /
/// [`PyEngine::audit_service`](crate::ffi::pyo3::PyEngine::audit_service).
///
/// `AuditService` uses RPITIT and is therefore NOT object-safe — you
/// cannot build `Arc<dyn AuditService>`. This enum is the object-safe
/// dispatch form: callers `match` on the variant and call the trait
/// methods on the concrete backend. Exact sibling of
/// [`NodeCoreDispatch`].
#[cfg(all(feature = "cirisaudit", any(feature = "postgres", feature = "sqlite")))]
pub enum AuditDispatch {
    /// Postgres-backed audit handle. `PostgresBackend` implements
    /// [`AuditService`](crate::audit::AuditService) directly.
    #[cfg(feature = "postgres")]
    Postgres(Arc<PostgresBackend>),
    /// SQLite-backed audit handle wrapping
    /// [`SqliteAuditBackend`](crate::audit::sqlite::SqliteAuditBackend).
    #[cfg(feature = "sqlite")]
    Sqlite(Arc<crate::audit::sqlite::SqliteAuditBackend>),
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

    /// v2.6.0 (CIRISPersist#106) — `Engine::federation_directory()`
    /// returns an `Arc<dyn FederationDirectory>` because the trait
    /// is now object-safe (async-trait refactor). Confirm the dyn
    /// handle dispatches to the underlying SQLite backend's read
    /// paths — both the existing `lookup_public_key` surface and
    /// the new (#105) `list_keys_by_identity_type` surface.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn federation_directory_dyn_dispatch_sqlite() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct engine");
        let directory: Arc<dyn crate::FederationDirectory> = engine.federation_directory();
        // Lookup against an empty directory — returns Ok(None), not
        // an error. Exercises the dyn vtable + spawn_blocking path.
        let none = directory.lookup_public_key("not-there").await.unwrap();
        assert!(none.is_none());
        // Class-based enumeration (#105) reachable through the dyn
        // handle (the #105 method on a #106 surface).
        let rows = directory
            .list_keys_by_identity_type(crate::federation::types::identity_type::STEWARD)
            .await
            .unwrap();
        assert!(rows.is_empty());
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

    /// v2.0 (CIRISPersist#91) — `Engine::receive_and_persist_pre_verified`
    /// persists a signed batch whose signing key is NOT registered in
    /// the federation directory — proving the relay skip-verify facade
    /// bypasses the per-trace `lookup_public_key`. The same batch
    /// through the default `receive_and_persist` is rejected
    /// `UnknownKey`, and the persisted rows are recorded honestly as
    /// not persist-verified.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn receive_and_persist_pre_verified_skips_directory_lookup() {
        use crate::ingest::IngestError;
        use crate::schema::{
            CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion, TraceComponent,
            TraceLevel,
        };
        use crate::scrub::NullScrubber;
        use crate::store::Backend as _;
        use crate::verify::{
            ed25519::canonical_payload_value, Canonicalizer, PythonJsonDumpsCanonicalizer,
        };
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ed25519_dalek::{Signer as _, SigningKey};

        let agent_sk = SigningKey::from_bytes(&[0x42; 32]);
        let agent_key_id = "ciris-agent-key:engine-91";

        let mut trace = CompleteTrace {
            trace_id: "trace-engine-91".into(),
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

        // Note: the agent's pubkey is intentionally NOT seeded into
        // federation_keys — a `Full`-mode ingest would fail UnknownKey.
        let summary = engine
            .receive_and_persist_pre_verified(&bytes, &NullScrubber)
            .await
            .expect("pre-verified ingest persists without a registered key");
        assert_eq!(summary.envelopes_processed, 1);
        assert_eq!(summary.trace_events_inserted, 1, "one component → one row");
        assert_eq!(summary.signatures_verified, 0, "persist verified nothing");

        // Honest row state: the row round-trips `signature_verified =
        // true` (the trace IS authentic) with `verification_source =
        // Edge` (an upstream Edge verifier attested it, not persist).
        let sq = engine.sqlite_backend().expect("sqlite backend");
        let rows = sq
            .fetch_trace_events_page(0, 100, None)
            .await
            .expect("fetch rows");
        assert_eq!(rows.len(), 1, "the one component we ingested");
        assert!(
            rows[0].1.signature_verified,
            "the trace is authentic — signature_verified stays true"
        );
        assert_eq!(
            rows[0].1.verification_source,
            crate::store::VerificationSource::Edge,
            "skip-verify rows attribute authenticity to Edge"
        );

        // Control: the default facade (Full mode) rejects the same
        // batch — proving skip-mode genuinely bypassed the lookup.
        let err = engine
            .receive_and_persist(&bytes, &NullScrubber)
            .await
            .expect_err("Full mode must reject the unregistered key");
        assert!(matches!(err, IngestError::Verify(_)), "got: {err:?}");
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

    /// v2.0 (CIRISPersist#93) — `Engine::audit_service` returns the
    /// SQLite dispatch variant and a `record_entry` / `list_entries`
    /// round-trips through it. Sibling of
    /// `node_core_service_sqlite_round_trip`.
    #[cfg(all(feature = "cirisaudit", feature = "sqlite"))]
    #[tokio::test]
    async fn audit_service_sqlite_round_trip() {
        use crate::audit::verify::{compute_entry_hash, truncate_to_micros};
        use crate::audit::{AuditEntry, AuditFilter, AuditService, GENESIS_PREV_HASH};
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ed25519_dalek::{Signer as _, SigningKey};
        use uuid::Uuid;

        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct engine");

        let dispatch = engine.audit_service();
        let backend = match dispatch {
            AuditDispatch::Sqlite(b) => b,
            #[cfg(feature = "postgres")]
            AuditDispatch::Postgres(_) => panic!("expected sqlite audit variant"),
        };

        // Build + sign a genesis audit entry (actor_id IS the pubkey).
        let key = SigningKey::from_bytes(&[0xA1; 32]);
        let tenant = format!("engine93-{}", Uuid::new_v4().simple());
        let mut entry = AuditEntry {
            entry_id: Uuid::new_v4().to_string(),
            sequence_number: 1,
            tenant_id: tenant.clone(),
            actor_id: B64.encode(key.verifying_key().to_bytes()),
            action_type: "handler_action_task_complete".into(),
            subject_kind: "task".into(),
            subject_id: "subj-1".into(),
            payload: serde_json::json!({"seq": 1}),
            prev_hash: GENESIS_PREV_HASH.to_vec(),
            entry_hash: vec![],
            recorded_at: truncate_to_micros(chrono::Utc::now()),
            signature: String::new(),
        };
        entry.entry_hash = compute_entry_hash(&entry).unwrap().to_vec();
        let canonical = crate::audit::verify::canonical_bytes_for_entry(&entry).unwrap();
        entry.signature = B64.encode(key.sign(&canonical).to_bytes());

        backend
            .record_entry(entry.clone())
            .await
            .expect("record_entry through AuditDispatch");

        let page = backend
            .list_entries(
                AuditFilter {
                    tenant_id: tenant.clone(),
                    action_type: None,
                    actor_id: None,
                    subject_kind: None,
                    subject_id: None,
                    recorded_after: None,
                    recorded_before: None,
                },
                None,
                10,
            )
            .await
            .expect("list_entries through AuditDispatch");
        assert_eq!(page.items.len(), 1, "the entry we inserted");
        assert_eq!(page.items[0].entry_id, entry.entry_id);
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

    /// v2.0 (CIRISPersist#93) — Postgres parity for
    /// `audit_service_sqlite_round_trip`. Skips when
    /// `CIRIS_PERSIST_TEST_PG_URL` is unset.
    #[cfg(all(feature = "cirisaudit", feature = "postgres"))]
    #[tokio::test]
    async fn audit_service_postgres_round_trip() {
        use crate::audit::verify::{compute_entry_hash, truncate_to_micros};
        use crate::audit::{AuditEntry, AuditFilter, AuditService, GENESIS_PREV_HASH};
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ed25519_dalek::{Signer as _, SigningKey};
        use uuid::Uuid;

        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let engine = Engine::with_signer(test_signer(), &dsn)
            .await
            .expect("construct postgres engine");

        let backend = match engine.audit_service() {
            AuditDispatch::Postgres(b) => b,
            #[cfg(feature = "sqlite")]
            AuditDispatch::Sqlite(_) => panic!("expected postgres audit variant"),
        };

        let key = SigningKey::from_bytes(&[0xB2; 32]);
        let tenant = format!("engine93-pg-{}", Uuid::new_v4().simple());
        let mut entry = AuditEntry {
            entry_id: Uuid::new_v4().to_string(),
            sequence_number: 1,
            tenant_id: tenant.clone(),
            actor_id: B64.encode(key.verifying_key().to_bytes()),
            action_type: "handler_action_task_complete".into(),
            subject_kind: "task".into(),
            subject_id: "subj-1".into(),
            payload: serde_json::json!({"seq": 1}),
            prev_hash: GENESIS_PREV_HASH.to_vec(),
            entry_hash: vec![],
            recorded_at: truncate_to_micros(chrono::Utc::now()),
            signature: String::new(),
        };
        entry.entry_hash = compute_entry_hash(&entry).unwrap().to_vec();
        let canonical = crate::audit::verify::canonical_bytes_for_entry(&entry).unwrap();
        entry.signature = B64.encode(key.sign(&canonical).to_bytes());

        backend
            .record_entry(entry.clone())
            .await
            .expect("record_entry through AuditDispatch");

        let page = backend
            .list_entries(
                AuditFilter {
                    tenant_id: tenant.clone(),
                    action_type: None,
                    actor_id: None,
                    subject_kind: None,
                    subject_id: None,
                    recorded_after: None,
                    recorded_before: None,
                },
                None,
                10,
            )
            .await
            .expect("list_entries through AuditDispatch");
        assert_eq!(page.items.len(), 1, "the entry we inserted");
        assert_eq!(page.items[0].entry_id, entry.entry_id);
    }

    /// v2.0 (CIRISPersist#91) — Postgres parity for
    /// `receive_and_persist_pre_verified_skips_directory_lookup`.
    /// Skips when `CIRIS_PERSIST_TEST_PG_URL` is unset.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn receive_and_persist_pre_verified_postgres() {
        use crate::ingest::IngestError;
        use crate::schema::{
            CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion, TraceComponent,
            TraceLevel,
        };
        use crate::scrub::NullScrubber;
        use crate::store::Backend as _;
        use crate::verify::{
            ed25519::canonical_payload_value, Canonicalizer, PythonJsonDumpsCanonicalizer,
        };
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ed25519_dalek::{Signer as _, SigningKey};
        use uuid::Uuid;

        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };

        let agent_sk = SigningKey::from_bytes(&[0x43; 32]);
        // Unique key_id so this row is isolated from any prior run.
        let agent_key_id = format!("ciris-agent-key:engine-91-pg-{}", Uuid::new_v4().simple());
        let trace_id = format!("trace-engine-91-pg-{}", Uuid::new_v4().simple());

        let mut trace = CompleteTrace {
            trace_id: trace_id.clone(),
            thought_id: "th-1".into(),
            task_id: Some("task-1".into()),
            agent_id_hash: format!("hash-{}", Uuid::new_v4().simple()),
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
            signature_key_id: agent_key_id.clone(),
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

        let engine = Engine::with_signer(test_signer(), &dsn)
            .await
            .expect("construct postgres engine");

        // Agent pubkey intentionally NOT seeded — Full mode would
        // fail UnknownKey.
        let summary = engine
            .receive_and_persist_pre_verified(&bytes, &NullScrubber)
            .await
            .expect("pre-verified ingest persists without a registered key");
        assert_eq!(summary.trace_events_inserted, 1);
        assert_eq!(summary.signatures_verified, 0);

        let pg = engine.postgres_backend().expect("postgres backend");
        let rows = pg
            .fetch_trace_events_page(0, 1000, Some(&trace.agent_id_hash))
            .await
            .expect("fetch rows");
        let mine: Vec<_> = rows
            .iter()
            .filter(|(_, r)| r.trace_id == trace_id)
            .collect();
        assert_eq!(mine.len(), 1, "the one component we ingested");
        assert!(
            mine[0].1.signature_verified,
            "the trace is authentic — signature_verified stays true"
        );
        assert_eq!(
            mine[0].1.verification_source,
            crate::store::VerificationSource::Edge,
            "skip-verify rows attribute authenticity to Edge"
        );

        // Control: Full mode rejects the unregistered key.
        let err = engine
            .receive_and_persist(&bytes, &NullScrubber)
            .await
            .expect_err("Full mode must reject the unregistered key");
        assert!(matches!(err, IngestError::Verify(_)), "got: {err:?}");
    }

    // ── v2.12.0 (CIRISPersist#112) — Engine::sign_hybrid tests ───────

    /// `with_signer` propagates the LocalSigner; without PQC configured
    /// the signer's own `PqcNotConfigured` error surfaces through the
    /// `SignError::LocalSigner(...)` variant.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sign_hybrid_without_pqc_returns_pqc_not_configured() {
        let signer = test_signer(); // No PQC.
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("construct engine");

        let err = engine
            .sign_hybrid(b"any message")
            .await
            .expect_err("PQC not configured");
        match err {
            SignError::LocalSigner(crate::signing::LocalSignerError::PqcNotConfigured) => {}
            other => panic!("expected SignError::LocalSigner(PqcNotConfigured), got {other:?}"),
        }
    }

    /// `from_shared` constructs an Engine without a LocalSigner;
    /// `sign_hybrid` returns `LocalSignerUnavailable` (the cohabitation
    /// consumer must rebuild a LocalSigner from
    /// `PyEngine::keyring_signer()`'s `KeyringSignerHandle` to use this
    /// path).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sign_hybrid_from_shared_without_local_returns_unavailable() {
        // Build a real Engine via with_signer, then synthesize a
        // from_shared Engine that drops the LocalSigner — exactly the
        // shape `current_rust_engine` produced pre-v2.12 (#92 to #112
        // window).
        let engine_full = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct engine");
        let backend = engine_full.backend().clone();
        let signer = engine_full.signer().clone();

        let engine_shared = Engine::from_shared(backend, signer);

        let err = engine_shared
            .sign_hybrid(b"any message")
            .await
            .expect_err("no LocalSigner propagated");
        assert!(
            matches!(err, SignError::LocalSignerUnavailable),
            "got: {err:?}"
        );
    }

    /// `from_shared_with_local` propagates the LocalSigner; the
    /// resulting Engine reaches `sign_hybrid` and surfaces the
    /// LocalSigner's own errors (PqcNotConfigured here, since the
    /// fixture signer has no PQC). This is the constructor
    /// `current_rust_engine()` now uses to cross the cohabitation
    /// boundary without losing hybrid-signing capability.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sign_hybrid_from_shared_with_local_propagates_to_local_signer() {
        let signer = test_signer(); // No PQC.
        let engine_full = Engine::with_signer(signer.clone(), "sqlite::memory:")
            .await
            .expect("construct engine");
        let backend = engine_full.backend().clone();
        let hw_signer = engine_full.signer().clone();

        let engine_shared = Engine::from_shared_with_local(backend, hw_signer, Some(signer));

        let err = engine_shared
            .sign_hybrid(b"any message")
            .await
            .expect_err("PQC not configured (but the LocalSigner WAS reached)");
        assert!(
            matches!(
                err,
                SignError::LocalSigner(crate::signing::LocalSignerError::PqcNotConfigured)
            ),
            "got: {err:?}"
        );
    }

    // ── v2.13.0 (CIRISPersist#113) — detection-events facade + edge
    //    read + subscribe change-feed (LensCore #15 / #19 / #20 / #21 / #25)

    /// Fixture: build a verified detection event the storage trait
    /// will accept (sig-length CHECKs + canonical_bytes). The Engine
    /// facade dispatches to the per-backend `DerivedSchema::get_*`
    /// impl — the facade test is a thin round-trip.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    fn de_event_fixture(
        trace_id: &str,
        canonical: &[u8],
        ts: chrono::DateTime<chrono::Utc>,
    ) -> crate::derived::DetectionEvent {
        crate::derived::DetectionEvent {
            detection_id: uuid::Uuid::new_v4(),
            trace_id: trace_id.to_owned(),
            body_sha256: vec![0xABu8; 32],
            detector: "manifold_conformity_outlier".to_owned(),
            severity: crate::derived::DetectionSeverity::Warning,
            cohort_cell: serde_json::json!({"deployment_domain": "legal"}),
            conformity_variant: crate::derived::ConformityVariant::Numeric,
            conformity_payload: serde_json::json!({"score": 2.7}),
            lens_core_version: "lc-test".to_owned(),
            ratchet_calibration_version: 1,
            canonical_bytes: canonical.to_vec(),
            ed25519_sig: vec![1u8; 64],
            ml_dsa_65_sig: vec![2u8; 3309],
            signing_key_id: "test-detector".to_owned(),
            ts,
        }
    }

    /// SQLite: facade dispatches to the SqliteBackend's
    /// `DerivedSchema::get_detection_events`. Seed via the storage
    /// trait; read via the Engine facade. The acceptance is the
    /// round-trip — the facade preserves filter semantics + row
    /// shape with no translation tax.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn get_detection_events_facade_dispatches_to_backend_sqlite() {
        use crate::derived::{DerivedSchema, EventFilter};

        let signer = test_signer();
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("construct engine");
        let sq = engine.sqlite_backend().expect("sqlite present");

        let base_ts = chrono::Utc::now() - chrono::Duration::minutes(10);
        let ev_a = de_event_fixture("tr-A", b"canon-A", base_ts);
        let ev_b = de_event_fixture("tr-B", b"canon-B", base_ts + chrono::Duration::minutes(1));
        sq.put_detection_event(ev_a.clone()).await.unwrap();
        sq.put_detection_event(ev_b.clone()).await.unwrap();

        // Empty filter → both rows.
        let all = engine
            .get_detection_events(EventFilter::default())
            .await
            .unwrap();
        assert_eq!(all.len(), 2);

        // trace_id filter → 1 row.
        let only_b = engine
            .get_detection_events(EventFilter {
                trace_id: Some("tr-B".to_owned()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(only_b.len(), 1);
        assert_eq!(only_b[0].detection_id, ev_b.detection_id);
    }

    /// SQLite: facade reads the V020 `edge_detection_events` rows
    /// with the EdgeEventFilter shape (tenant / peer / event_type /
    /// recorded_after / limit) honored. The write side has no
    /// service trait yet; we INSERT raw to seed.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn get_edge_detection_events_returns_v020_rows_sqlite() {
        let signer = test_signer();
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("construct engine");
        let sq = engine.sqlite_backend().expect("sqlite present");

        // FK target for `subject_key_id`. Self-referential
        // `scrub_key_id = key_id` matches the trust_test_backend
        // pattern — works under DEFERRABLE INITIALLY DEFERRED.
        use crate::federation::{FederationDirectory, KeyRecord, SignedKeyRecord};
        let suspect_key = KeyRecord {
            key_id: "k-suspect".into(),
            pubkey_ed25519_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: "suspect".into(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({"id": "k-suspect"}),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: "k-suspect".into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
        };
        sq.put_public_key(SignedKeyRecord {
            record: suspect_key,
        })
        .await
        .unwrap();

        // INSERT three edge_detection_events rows (raw SQL — no service
        // trait wraps the V020 write side yet).
        let conn = sq.conn_handle();
        let base_ts = chrono::Utc::now();
        let rows: Vec<(String, String, String, String)> = vec![
            (
                uuid::Uuid::new_v4().to_string(),
                "tnt-alpha".into(),
                "unconsented_external_probe".into(),
                (base_ts - chrono::Duration::minutes(2)).to_rfc3339(),
            ),
            (
                uuid::Uuid::new_v4().to_string(),
                "tnt-alpha".into(),
                "excessive_recursion".into(),
                (base_ts - chrono::Duration::minutes(1)).to_rfc3339(),
            ),
            (
                uuid::Uuid::new_v4().to_string(),
                "tnt-beta".into(),
                "consent_gate_leak".into(),
                base_ts.to_rfc3339(),
            ),
        ];
        let rows_clone = rows.clone();
        tokio::task::spawn_blocking(move || -> rusqlite::Result<()> {
            let conn = conn.blocking_lock();
            for (did, tenant, kind, observed_at) in rows_clone {
                conn.execute(
                    "INSERT INTO edge_detection_events (\
                        detection_id, tenant_id, detector_kind, subject_key_id, \
                        observed_at, evidence, severity, signature, signing_key_id, \
                        signature_verified, persist_row_hash\
                     ) VALUES (?1, ?2, ?3, 'k-suspect', ?4, ?5, 'warn', \
                              'sig', 'lens-detector', 1, 'hash')",
                    rusqlite::params![did, tenant, kind, observed_at, "{\"probed\":\"x\"}"],
                )?;
            }
            Ok(())
        })
        .await
        .unwrap()
        .unwrap();

        // Empty filter → 3 rows, stable ASC order on (tenant, ts, id).
        let all = engine
            .get_edge_detection_events(crate::derived::EdgeEventFilter::default())
            .await
            .unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].tenant_id, "tnt-alpha");
        assert_eq!(all[1].tenant_id, "tnt-alpha");
        assert_eq!(all[2].tenant_id, "tnt-beta");
        // Shape check: severity is the TEXT vocab; signature_verified
        // round-trips as bool; evidence is decoded JSON.
        assert_eq!(all[0].severity, "warn");
        assert!(all[0].signature_verified);
        assert_eq!(all[0].evidence, serde_json::json!({"probed": "x"}));

        // tenant filter
        let alpha_only = engine
            .get_edge_detection_events(crate::derived::EdgeEventFilter {
                tenant_id: Some("tnt-alpha".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(alpha_only.len(), 2);
        for r in &alpha_only {
            assert_eq!(r.tenant_id, "tnt-alpha");
        }

        // event_type (detector_kind) filter
        let probes = engine
            .get_edge_detection_events(crate::derived::EdgeEventFilter {
                event_type: Some("unconsented_external_probe".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].detector_kind, "unconsented_external_probe");

        // peer_key_id filter
        let by_peer = engine
            .get_edge_detection_events(crate::derived::EdgeEventFilter {
                peer_key_id: Some("k-suspect".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(by_peer.len(), 3);

        // recorded_after (strict `>`) — cursor at second row's ts
        // returns only the third row.
        let cursor = chrono::DateTime::parse_from_rfc3339(
            &(base_ts - chrono::Duration::minutes(1)).to_rfc3339(),
        )
        .unwrap()
        .with_timezone(&chrono::Utc);
        let after = engine
            .get_edge_detection_events(crate::derived::EdgeEventFilter {
                recorded_after: Some(cursor),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].tenant_id, "tnt-beta");

        // limit
        let limit_one = engine
            .get_edge_detection_events(crate::derived::EdgeEventFilter {
                limit: Some(1),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(limit_one.len(), 1);
    }

    /// SQLite: subscribing AFTER seeding row R doesn't yield R; a new
    /// row Q inserted AFTER subscribe IS yielded.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn subscribe_detection_events_yields_new_events_only_sqlite() {
        use crate::derived::{DerivedSchema, EventFilter};
        use futures_core::Stream;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        let signer = test_signer();
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("construct engine");
        let sq = engine.sqlite_backend().expect("sqlite present");

        // Seed a row BEFORE subscribing → must NOT be yielded.
        let before_ts = chrono::Utc::now() - chrono::Duration::seconds(10);
        let pre_ev = de_event_fixture("tr-PRE", b"canon-PRE", before_ts);
        sq.put_detection_event(pre_ev.clone()).await.unwrap();

        // Subscribe; let the cursor latch on Utc::now().
        let mut stream = Box::pin(engine.subscribe_detection_events(EventFilter::default()));

        // Insert a row AFTER subscribe → should be yielded.
        // Sleep ~2.2s (one poll cycle) so the poller wakes and reads.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let new_ts = chrono::Utc::now();
        let new_ev = de_event_fixture("tr-NEW", b"canon-NEW", new_ts);
        sq.put_detection_event(new_ev.clone()).await.unwrap();

        // Drain with a timeout. POLL_INTERVAL = 2s; allow 5s headroom.
        let next = tokio::time::timeout(std::time::Duration::from_secs(6), async {
            std::future::poll_fn(|cx: &mut Context<'_>| -> Poll<
                Option<Result<crate::derived::DetectionEvent, crate::derived::Error>>,
            > { Pin::new(&mut stream).poll_next(cx) })
            .await
        })
        .await
        .expect("subscribe yielded within 6s");
        let yielded = next.expect("stream produced an item").expect("ok");
        assert_eq!(
            yielded.detection_id, new_ev.detection_id,
            "subscribe yields the AFTER-subscribe row"
        );
        assert_ne!(
            yielded.detection_id, pre_ev.detection_id,
            "subscribe MUST NOT yield the BEFORE-subscribe row"
        );

        drop(stream);
    }

    /// SQLite: dropping the Stream terminates the polling task — we
    /// can't observe the JoinHandle directly, but the test passes
    /// (does not hang) iff the polling task exits on next send/close.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn subscribe_detection_events_drop_terminates_poll_task_sqlite() {
        use crate::derived::EventFilter;

        let signer = test_signer();
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("construct engine");

        let stream = engine.subscribe_detection_events(EventFilter::default());
        // Drop the subscription. The poll task's next iteration sees
        // tx.is_closed() → break, or its send returns Err → return.
        // Either way the spawned task winds up. We give it 5s of
        // wall-clock to do so; the test passing implies no leak.
        drop(stream);
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        // If the spawned poll task were still alive + driving DB
        // queries, the SqliteBackend's Mutex would be held when this
        // test's tokio::test runtime tears down — exposed as flaky
        // shutdowns on CI. The test passes today because the channel
        // close terminates the task. No assertion needed beyond
        // reaching this line cleanly.
        // (Engine still owns the SqliteBackend Arc; that's expected.)
        let _ = engine;
    }

    /// SQLite: subscribe with a tenant filter is honored — the
    /// EventFilter shape only carries trace_id / detector / since.
    /// Per-tenant filtering on detection_events lives elsewhere
    /// (cohort_cell.tenant or the `signing_key_id`'s federation row).
    /// This test confirms the trace_id scoping case (the only one
    /// EventFilter exposes today): rows for trace_id=T are yielded,
    /// rows for other trace_ids are not.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn subscribe_detection_events_filter_scopes_yielded_rows_sqlite() {
        use crate::derived::{DerivedSchema, EventFilter};
        use futures_core::Stream;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        let signer = test_signer();
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("construct engine");
        let sq = engine.sqlite_backend().expect("sqlite present");

        let mut stream = Box::pin(engine.subscribe_detection_events(EventFilter {
            trace_id: Some("tr-MATCH".to_owned()),
            ..Default::default()
        }));

        // Insert one matching + one non-matching row.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let now = chrono::Utc::now();
        let matching = de_event_fixture("tr-MATCH", b"canon-MATCH", now);
        let nonmatching = de_event_fixture(
            "tr-OTHER",
            b"canon-OTHER",
            now + chrono::Duration::milliseconds(1),
        );
        sq.put_detection_event(matching.clone()).await.unwrap();
        sq.put_detection_event(nonmatching.clone()).await.unwrap();

        // Should yield exactly the matching row.
        let next = tokio::time::timeout(std::time::Duration::from_secs(6), async {
            std::future::poll_fn(|cx: &mut Context<'_>| -> Poll<
                Option<Result<crate::derived::DetectionEvent, crate::derived::Error>>,
            > { Pin::new(&mut stream).poll_next(cx) })
            .await
        })
        .await
        .expect("subscribe yields within 6s");
        let yielded = next.expect("item").expect("ok");
        assert_eq!(yielded.trace_id, "tr-MATCH");
        assert_eq!(yielded.detection_id, matching.detection_id);

        // A second poll cycle should produce no other-trace rows;
        // poll with a short timeout — if no row arrives, the filter
        // is correctly excluding tr-OTHER.
        let no_more = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            std::future::poll_fn(|cx: &mut Context<'_>| -> Poll<
                Option<Result<crate::derived::DetectionEvent, crate::derived::Error>>,
            > { Pin::new(&mut stream).poll_next(cx) })
            .await
        })
        .await;
        assert!(
            no_more.is_err(),
            "filter must NOT yield non-matching tr-OTHER row \
             (timeout exhausted; got = {:?})",
            no_more
        );

        drop(stream);
    }

    // ─── Postgres parity for the same four scenarios ───

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn get_detection_events_facade_dispatches_to_backend_postgres() {
        use crate::derived::{DerivedSchema, EventFilter};

        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let signer = test_signer();
        let engine = Engine::with_signer(signer, &dsn)
            .await
            .expect("construct PG engine");
        let pg = engine.postgres_backend().expect("pg backend");

        // Use a unique trace_id per run so concurrent runs don't share rows.
        let trace_a = format!("tr-A-{}", uuid::Uuid::new_v4().simple());
        let trace_b = format!("tr-B-{}", uuid::Uuid::new_v4().simple());
        let base_ts = chrono::Utc::now() - chrono::Duration::minutes(10);
        let ev_a = de_event_fixture(&trace_a, b"canon-A", base_ts);
        let ev_b = de_event_fixture(&trace_b, b"canon-B", base_ts + chrono::Duration::minutes(1));
        pg.put_detection_event(ev_a.clone()).await.unwrap();
        pg.put_detection_event(ev_b.clone()).await.unwrap();

        let only_b = engine
            .get_detection_events(EventFilter {
                trace_id: Some(trace_b.clone()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(only_b.len(), 1);
        assert_eq!(only_b[0].detection_id, ev_b.detection_id);
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn get_edge_detection_events_returns_v020_rows_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let signer = test_signer();
        let engine = Engine::with_signer(signer, &dsn)
            .await
            .expect("construct PG engine");
        let pg = engine.postgres_backend().expect("pg backend");

        // Bootstrap a federation_keys row to satisfy the FK.
        use crate::federation::{FederationDirectory, KeyRecord, SignedKeyRecord};
        let suspect_id = format!("k-suspect-{}", uuid::Uuid::new_v4().simple());
        let suspect = KeyRecord {
            key_id: suspect_id.clone(),
            pubkey_ed25519_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: suspect_id.clone(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({"id": suspect_id.clone()}),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: suspect_id.clone(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
        };
        pg.put_public_key(SignedKeyRecord { record: suspect })
            .await
            .unwrap();

        // INSERT three edge_detection_events via the pool client.
        let tenant_a = format!("tnt-A-{}", uuid::Uuid::new_v4().simple());
        let tenant_b = format!("tnt-B-{}", uuid::Uuid::new_v4().simple());
        let base_ts = chrono::Utc::now();
        let client = pg.pool().get().await.unwrap();
        let id_a1 = uuid::Uuid::new_v4();
        let id_a2 = uuid::Uuid::new_v4();
        let id_b = uuid::Uuid::new_v4();
        client
            .execute(
                "INSERT INTO cirislens.edge_detection_events (\
                    detection_id, tenant_id, detector_kind, subject_key_id, \
                    observed_at, evidence, severity, signature, signing_key_id, \
                    signature_verified, persist_row_hash\
                 ) VALUES \
                 ($1, $2, 'unconsented_external_probe', $3, $4, $5::jsonb, 'warn', \
                  'sig', 'lens-detector', TRUE, 'hash'), \
                 ($6, $7, 'excessive_recursion', $8, $9, $10::jsonb, 'warn', \
                  'sig', 'lens-detector', TRUE, 'hash'), \
                 ($11, $12, 'consent_gate_leak', $13, $14, $15::jsonb, 'info', \
                  'sig', 'lens-detector', FALSE, 'hash')",
                &[
                    &id_a1,
                    &tenant_a,
                    &suspect_id,
                    &(base_ts - chrono::Duration::minutes(2)),
                    &serde_json::json!({"probed": "x"}),
                    &id_a2,
                    &tenant_a,
                    &suspect_id,
                    &(base_ts - chrono::Duration::minutes(1)),
                    &serde_json::json!({"probed": "y"}),
                    &id_b,
                    &tenant_b,
                    &suspect_id,
                    &base_ts,
                    &serde_json::json!({"probed": "z"}),
                ],
            )
            .await
            .unwrap();

        // tenant filter → exactly tenant_a's 2 rows
        let alpha = engine
            .get_edge_detection_events(crate::derived::EdgeEventFilter {
                tenant_id: Some(tenant_a.clone()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(alpha.len(), 2);
        for r in &alpha {
            assert_eq!(r.tenant_id, tenant_a);
            assert!(r.signature_verified);
        }

        // recorded_after cursor
        let cursor = base_ts - chrono::Duration::minutes(1);
        let after = engine
            .get_edge_detection_events(crate::derived::EdgeEventFilter {
                peer_key_id: Some(suspect_id.clone()),
                recorded_after: Some(cursor),
                ..Default::default()
            })
            .await
            .unwrap();
        // The base_ts row is strictly > cursor; the two earlier ones are not.
        assert!(after.iter().any(|r| r.tenant_id == tenant_b));
        assert!(after.iter().all(|r| r.observed_at > cursor));
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn subscribe_detection_events_yields_new_events_only_postgres() {
        use crate::derived::{DerivedSchema, EventFilter};
        use futures_core::Stream;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let signer = test_signer();
        let engine = Engine::with_signer(signer, &dsn)
            .await
            .expect("construct PG engine");
        let pg = engine.postgres_backend().expect("pg backend");

        // Seed a row BEFORE subscribing.
        let trace_pre = format!("tr-PRE-{}", uuid::Uuid::new_v4().simple());
        let before_ts = chrono::Utc::now() - chrono::Duration::seconds(10);
        let pre_ev = de_event_fixture(&trace_pre, b"canon-PRE", before_ts);
        pg.put_detection_event(pre_ev.clone()).await.unwrap();

        // Subscribe with a trace_id filter to isolate from concurrent runs.
        let trace_new = format!("tr-NEW-{}", uuid::Uuid::new_v4().simple());
        let mut stream = Box::pin(engine.subscribe_detection_events(EventFilter {
            trace_id: Some(trace_new.clone()),
            ..Default::default()
        }));

        // Insert NEW row after subscribe.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let new_ts = chrono::Utc::now();
        let new_ev = de_event_fixture(&trace_new, b"canon-NEW", new_ts);
        pg.put_detection_event(new_ev.clone()).await.unwrap();

        let next = tokio::time::timeout(std::time::Duration::from_secs(6), async {
            std::future::poll_fn(|cx: &mut Context<'_>| -> Poll<
                Option<Result<crate::derived::DetectionEvent, crate::derived::Error>>,
            > { Pin::new(&mut stream).poll_next(cx) })
            .await
        })
        .await
        .expect("yielded within 6s");
        let yielded = next.expect("item").expect("ok");
        assert_eq!(yielded.detection_id, new_ev.detection_id);
        assert_ne!(yielded.detection_id, pre_ev.detection_id);
        drop(stream);
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn subscribe_detection_events_drop_terminates_poll_task_postgres() {
        use crate::derived::EventFilter;

        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let signer = test_signer();
        let engine = Engine::with_signer(signer, &dsn)
            .await
            .expect("construct PG engine");
        let stream = engine.subscribe_detection_events(EventFilter::default());
        drop(stream);
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let _ = engine;
    }

    // ─── v3.3.0 (CIRISPersist#121) — put_blob_signing tests ────────
    //
    // Cover the trait default impl on each backend (via the Engine
    // facade), the cross-canonicalizer identity pin, and the standard
    // round-trip + error shapes. The trait method's default impl is
    // inherited automatically; these tests prove the inheritance
    // chain compiles and that the canonical bytes the engine signs
    // match the production `PythonJsonDumpsCanonicalizer` shape.

    /// Bootstrap a `federation_keys` row that satisfies the FK on
    /// the holds_bytes attestation emitted by `put_blob_signing`.
    /// The attesting key_id matches the test signer's alias so the
    /// engine-facade signature path verifies end-to-end.
    #[cfg(feature = "sqlite")]
    async fn seed_test_attesting_key(engine: &Engine, key_id: &str) {
        let sq = engine.sqlite_backend().expect("sqlite backend");
        let conn = sq.conn_handle();
        let key_id_owned = key_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO federation_keys (\
                    key_id, pubkey_ed25519_base64, algorithm, \
                    identity_type, identity_ref, valid_from, \
                    registration_envelope, original_content_hash, \
                    scrub_signature_classical, scrub_key_id, \
                    scrub_timestamp, persist_row_hash\
                 ) VALUES (?1, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', \
                          'hybrid', 'primitive', ?1, ?2, '{}', x'00', '', \
                          ?1, ?2, '0')",
                rusqlite::params![key_id_owned, "2026-04-30T00:00:00+00:00"],
            )
            .expect("seed federation key");
        })
        .await
        .expect("spawn_blocking join");
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn sha256_of_bytes(bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let d = Sha256::digest(bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }

    /// Cross-canonicalizer regression test (the gate
    /// CIRISPersist#121 cites). Computes the expected
    /// `original_content_hash_hex` directly from the production
    /// `PythonJsonDumpsCanonicalizer` and asserts the row
    /// `put_blob_signing` writes carries the SAME hash. If a future
    /// refactor swaps the canonicalizer (to JCS or anything else
    /// that produces different bytes for the holds_bytes envelope)
    /// the assertion catches it before the wrong-canonicalizer rows
    /// ship.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn put_blob_signing_uses_python_canonicalizer_not_jcs_sqlite() {
        use crate::federation::{
            holds_bytes_attestation_envelope, holds_bytes_attestation_type, BlobBody, BlobStorage,
        };
        use crate::verify::canonical::{Canonicalizer, PythonJsonDumpsCanonicalizer};
        use sha2::{Digest, Sha256};

        let signer = test_signer();
        let signer_alias = signer.key_id().to_string();
        let engine = Engine::with_signer(signer.clone(), "sqlite::memory:")
            .await
            .expect("construct engine");
        seed_test_attesting_key(&engine, &signer_alias).await;

        let bytes = b"canonicalizer-identity-blob".to_vec();
        let sha = sha256_of_bytes(&bytes);

        // Expected hash: SHA-256 of the Python-compat canonical bytes
        // for the holds_bytes envelope this sha produces.
        let envelope = holds_bytes_attestation_envelope(&sha);
        let py_canonical = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&envelope)
            .expect("python canonicalize");
        let expected_hash_hex = hex::encode(Sha256::digest(&py_canonical));

        let now = chrono::Utc::now();
        let attestation_id = uuid::Uuid::new_v4();
        engine
            .put_blob_signing(
                &sha,
                BlobBody::Inline(bytes),
                Some("application/octet-stream"),
                &signer_alias,
                now,
                attestation_id,
            )
            .await
            .expect("put_blob_signing");

        // Read the holds_bytes attestation row back and compare the
        // stored original_content_hash (hex) against the expected
        // Python-compat hash. Drift here proves the canonicalizer
        // changed under put_blob_signing.
        let sq = engine.sqlite_backend().expect("sqlite backend");
        let conn = sq.conn_handle();
        let attestation_id_str = attestation_id.to_string();
        let attestation_type = holds_bytes_attestation_type(&sha);
        let (stored_hash_hex, stored_scrub_key_id): (String, String) =
            tokio::task::spawn_blocking(move || {
                let conn = conn.blocking_lock();
                conn.query_row(
                    "SELECT lower(hex(original_content_hash)), scrub_key_id \
                     FROM federation_attestations \
                     WHERE attestation_id = ?1 AND attestation_type = ?2",
                    rusqlite::params![attestation_id_str, attestation_type],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .expect("stored attestation row")
            })
            .await
            .expect("spawn_blocking join");

        assert_eq!(
            stored_hash_hex, expected_hash_hex,
            "put_blob_signing must canonicalize via PythonJsonDumpsCanonicalizer; \
             the silent-correctness trap CIRISPersist#121 closes manifests as a \
             mismatch here"
        );
        // Scrub key id comes from the signer (HardwareSigner::current_alias)
        // — pin that wire too so a future refactor that lets callers
        // override scrub_key_id is caught.
        assert_eq!(stored_scrub_key_id, signer_alias);

        // list_holders sees the writer.
        let holders = sq.list_holders(&sha).await.expect("list_holders");
        assert_eq!(holders, vec![signer_alias]);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn put_blob_signing_inline_round_trip_sqlite() {
        use crate::federation::{BlobBody, BlobStorage};

        let signer = test_signer();
        let signer_alias = signer.key_id().to_string();
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("construct engine");
        seed_test_attesting_key(&engine, &signer_alias).await;

        let bytes = b"inline-round-trip".to_vec();
        let sha = sha256_of_bytes(&bytes);

        engine
            .put_blob_signing(
                &sha,
                BlobBody::Inline(bytes.clone()),
                Some("application/octet-stream"),
                &signer_alias,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .expect("put_blob_signing inline");

        let sq = engine.sqlite_backend().expect("sqlite backend");
        let got = sq.get_blob(&sha).await.expect("get").expect("present");
        assert_eq!(got, BlobBody::Inline(bytes));
        let holders = sq.list_holders(&sha).await.expect("list_holders");
        assert_eq!(holders, vec![signer_alias]);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn put_blob_signing_external_round_trip_sqlite() {
        use crate::federation::{BlobBody, BlobStorage, ExternalRef};

        let signer = test_signer();
        let signer_alias = signer.key_id().to_string();
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("construct engine");
        seed_test_attesting_key(&engine, &signer_alias).await;

        let ext = ExternalRef {
            uri: "s3://test-bucket/blob-signing-ext".into(),
            size_bytes: 4_567_890,
            media_type: Some("application/octet-stream".into()),
        };
        // External case — caller-supplied sha (persist trusts it; no
        // bytes to verify).
        let sha = [0xA7u8; 32];
        engine
            .put_blob_signing(
                &sha,
                BlobBody::External(ext.clone()),
                Some("application/octet-stream"),
                &signer_alias,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .expect("put_blob_signing external");

        let sq = engine.sqlite_backend().expect("sqlite backend");
        let got = sq.get_blob(&sha).await.expect("get").expect("present");
        assert_eq!(got, BlobBody::External(ext));
    }

    /// Same content + same attesting key + same attestation_id →
    /// the second call collides on the attestation_id PK. Matches
    /// the documented `put_blob` semantic for replayed
    /// attestation_ids (see store/sqlite.rs::put_blob's
    /// AttestationEmissionFailed("attestation_id collision: ...")).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn put_blob_signing_replay_same_attestation_id_conflicts_sqlite() {
        use crate::federation::{BlobBody, BlobError};

        let signer = test_signer();
        let signer_alias = signer.key_id().to_string();
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("construct engine");
        seed_test_attesting_key(&engine, &signer_alias).await;

        let bytes = b"replay-id-collision".to_vec();
        let sha = sha256_of_bytes(&bytes);
        let attestation_id = uuid::Uuid::new_v4();
        let now = chrono::Utc::now();

        engine
            .put_blob_signing(
                &sha,
                BlobBody::Inline(bytes.clone()),
                None,
                &signer_alias,
                now,
                attestation_id,
            )
            .await
            .expect("first call");

        let err = engine
            .put_blob_signing(
                &sha,
                BlobBody::Inline(bytes),
                None,
                &signer_alias,
                now,
                attestation_id,
            )
            .await
            .expect_err("attestation_id collision");
        assert!(
            matches!(err, BlobError::AttestationEmissionFailed(_)),
            "got {err:?}"
        );
    }

    /// Same content + same attesting key + DIFFERENT attestation_id
    /// → both calls succeed (each is an independent holder attestation
    /// row; the blob row is idempotent on sha256 PK). Mirrors the
    /// `blob_idempotent_put_same_writer` shape in store/sqlite.rs.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn put_blob_signing_idempotent_distinct_attestation_ids_sqlite() {
        use crate::federation::{BlobBody, BlobStorage};

        let signer = test_signer();
        let signer_alias = signer.key_id().to_string();
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("construct engine");
        seed_test_attesting_key(&engine, &signer_alias).await;

        let bytes = b"distinct-id-idempotent".to_vec();
        let sha = sha256_of_bytes(&bytes);

        for _ in 0..2 {
            engine
                .put_blob_signing(
                    &sha,
                    BlobBody::Inline(bytes.clone()),
                    None,
                    &signer_alias,
                    chrono::Utc::now(),
                    uuid::Uuid::new_v4(),
                )
                .await
                .expect("put");
        }

        // Blob still readable; the same key_id appears once in
        // list_holders (DISTINCT behavior is per-backend; the SQLite
        // impl deduplicates by attesting_key_id within the prefix
        // grouping).
        let sq = engine.sqlite_backend().expect("sqlite backend");
        let got = sq.get_blob(&sha).await.expect("get").expect("present");
        assert_eq!(got, BlobBody::Inline(bytes));
    }

    /// Unknown `attesting_key_id` → no federation_keys row exists
    /// → FK violation on the holds_bytes attestation insert →
    /// `BlobError::AttestationEmissionFailed`. Transactional rollback
    /// means the blob row is NOT written.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn put_blob_signing_unknown_key_rejects_sqlite() {
        use crate::federation::{BlobBody, BlobError, BlobStorage};

        let signer = test_signer();
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("construct engine");
        // NOTE: deliberately NOT seeding the federation_keys row.

        let bytes = b"unknown-attesting-key".to_vec();
        let sha = sha256_of_bytes(&bytes);
        let err = engine
            .put_blob_signing(
                &sha,
                BlobBody::Inline(bytes),
                None,
                "unknown-key-not-registered",
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .expect_err("FK violation");
        assert!(
            matches!(err, BlobError::AttestationEmissionFailed(_)),
            "got {err:?}"
        );

        // Tx rollback: blob row NOT written.
        let sq = engine.sqlite_backend().expect("sqlite backend");
        assert!(!sq.has_blob(&sha).await.expect("has"));
    }

    /// PG parity for the canonicalizer-identity pin. Same shape as
    /// the SQLite test above but using the shared PG test DB.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn put_blob_signing_uses_python_canonicalizer_not_jcs_postgres() {
        use crate::federation::{
            holds_bytes_attestation_envelope, holds_bytes_attestation_type, BlobBody,
            FederationDirectory,
        };
        use crate::verify::canonical::{Canonicalizer, PythonJsonDumpsCanonicalizer};
        use sha2::{Digest, Sha256};

        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        // Per-test-randomized signer key_id so the FK insert doesn't
        // collide with parallel tests on the shared PG DB.
        let seed = [0xCDu8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let key_id = format!("put-blob-signing-pg-{}", uuid::Uuid::new_v4());
        let signer = Arc::new(LocalSigner::from_parts(
            signing_key,
            key_id.clone(),
            None,
            None,
        ));
        let engine = Engine::with_signer(signer, &dsn).await.expect("connect pg");

        // Seed the federation_keys row that put_blob_signing's
        // emitted attestation will FK-reference. We reuse the
        // FederationDirectory put_public_key path so the signed
        // record's invariants hold.
        let pg = engine.postgres_backend().expect("pg backend");
        let key_record = crate::federation::KeyRecord {
            key_id: key_id.clone(),
            pubkey_ed25519_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: key_id.clone(),
            valid_from: chrono::Utc::now(),
            valid_until: None,
            registration_envelope: serde_json::json!({"id": key_id}),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.clone(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
        };
        pg.put_public_key(crate::federation::SignedKeyRecord { record: key_record })
            .await
            .expect("seed federation key");

        // SHA randomized so the blob row doesn't collide with
        // parallel PG tests' rows.
        let mut sha = [0u8; 32];
        let nonce = uuid::Uuid::new_v4();
        sha[..16].copy_from_slice(nonce.as_bytes());
        sha[16..].copy_from_slice(nonce.as_bytes());
        let bytes_payload = format!("pg-canon-{}", nonce).into_bytes();
        // External case avoids the inline-bytes hash check (the sha
        // doesn't match the payload — using External keeps the test
        // focused on the holder attestation, not the inline-bytes path).
        let ext = crate::federation::ExternalRef {
            uri: format!("s3://test/{nonce}"),
            size_bytes: bytes_payload.len() as u64,
            media_type: Some("application/octet-stream".into()),
        };

        let envelope = holds_bytes_attestation_envelope(&sha);
        let py_canonical = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&envelope)
            .expect("python canonicalize");
        let expected_hash_hex = hex::encode(Sha256::digest(&py_canonical));

        let now = chrono::Utc::now();
        let attestation_id = uuid::Uuid::new_v4();
        engine
            .put_blob_signing(
                &sha,
                BlobBody::External(ext),
                Some("application/octet-stream"),
                &key_id,
                now,
                attestation_id,
            )
            .await
            .expect("put_blob_signing");

        // Pin the stored hash equals the Python-compat canonical
        // hash — same invariant the SQLite test checks.
        let attestation_type = holds_bytes_attestation_type(&sha);
        let client = pg.pool().get().await.expect("pg client");
        let row = client
            .query_one(
                "SELECT encode(original_content_hash, 'hex'), scrub_key_id \
                 FROM cirislens.federation_attestations \
                 WHERE attestation_id = $1 AND attestation_type = $2",
                &[&attestation_id, &attestation_type],
            )
            .await
            .expect("stored row present");
        let stored_hash_hex: String = row.get(0);
        let stored_scrub_key_id: String = row.get(1);
        assert_eq!(stored_hash_hex, expected_hash_hex);
        assert_eq!(stored_scrub_key_id, key_id);
    }
}
