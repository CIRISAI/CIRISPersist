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
#![allow(clippy::redundant_closure_call)]
// v3.14.0 (CIRISPersist#158) — inline-sync rewrite of all
// tokio::task::spawn_blocking sites uses (closure)() to invoke
// the closure inline. Clippy's redundant_closure_call lint flags
// this; we allow it because the mechanical transformation kept
// each closure's typed return signature load-bearing for error
// propagation and any other refactor would be a much larger diff.
// each closure's typed return signature load-bearing for error

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
    /// v3.4.0 (CIRISPersist#123) — replication-layer config (trust
    /// threshold, recursion depth, storage budget, eviction cadence).
    /// `None` = defaults (bootstrap-permissive, sweeper inactive).
    /// Cheaply clonable into the spawned sweeper task.
    replication_config: Option<Arc<crate::federation::ReplicationConfig>>,
    /// v6.8.0 (CIRISPersist#149) — disk-pressure operator config. `None`
    /// = the disk-pressure response is not installed on this Engine view
    /// (the monitor + cached tier live on the PyO3 `EngineCell` /
    /// sovereign owner). Carried here so the eviction sweeper's
    /// force-evict-proxy-first classification can consult the
    /// local/family predicate. Cheaply clonable into spawned tasks.
    disk_pressure_config: Option<Arc<crate::federation::DiskPressureConfig>>,
    /// v6.8.0 (CIRISPersist#149) — live disk-pressure snapshot receiver,
    /// fed by the background monitor loop on the `EngineCell` /
    /// sovereign owner. The proxy-accept (`put_blob_signing`) and
    /// proxy-serve (`serve_blob_to_peer`) enforcement paths read
    /// `borrow()` from this — O(1), no statvfs per call. `None` ⇒ no
    /// monitor installed on this view (enforcement is a no-op: the
    /// substrate refuses nothing).
    disk_pressure_state:
        Option<tokio::sync::watch::Receiver<crate::federation::DiskPressureSnapshot>>,
    /// v3.6.0 (CIRISPersist#134) — media-sharing operator config
    /// (counter-notice window + immediate-eviction basis set). `None`
    /// = persist defaults (14-day window; child-safety + terrorist
    /// content classes evict immediately). Interior-mutable so the
    /// runtime PyO3 setter can update without consuming the engine.
    #[cfg(feature = "cirisnode")]
    multimedia_config: Arc<std::sync::RwLock<Option<Arc<crate::cirisnode::MultimediaConfig>>>>,
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

/// v6.5.0 (CIRISPersist#183, CEG §8.1.12.7) — one occurrence (app or
/// agent) being co-admitted at login. The `occurrence_key_id` must
/// already exist as a `federation_keys` row.
#[derive(Debug, Clone)]
pub struct SelfAtLoginOccurrence {
    /// The occurrence's signing key — a `federation_keys.key_id`.
    pub occurrence_key_id: String,
    /// Closed-set per [`crate::federation::device_class`] —
    /// `phone`/`laptop` for the app, `agent` for the agent.
    pub device_class: String,
    /// Optional opaque hardware-attestation blob (TPM / Secure Enclave
    /// / StrongBox / …).
    pub hardware_attestation: Option<String>,
    /// The occurrence's content-encryption pubkeys (the §8.1.12.4 Self
    /// DEK wrap-target). `None` ⇒ fail-secure excluded from the DEK
    /// cascade (reported in
    /// [`SelfAtLoginOutcome::self_dek_excluded`]).
    pub encryption_pubkeys: Option<crate::federation::EncryptionPubkeys>,
    /// Reachability addresses to register for this occurrence
    /// (§5.6.8.8.1): `(transport_kind, destination)` pairs, e.g.
    /// `("reticulum", "<dest-hash>")`. May be empty.
    pub transport_destinations: Vec<(String, String)>,
}

/// v6.5.0 (CIRISPersist#183, CEG §8.1.12.7) — inputs to the
/// [`Engine::self_at_login`] flow.
#[derive(Debug, Clone)]
pub struct SelfAtLoginInput {
    /// The user's root identity key — a `federation_keys.key_id`. Both
    /// occurrences are bound under it.
    pub identity_key_id: String,
    /// The app occurrence (`device_class: phone | laptop`).
    pub app: SelfAtLoginOccurrence,
    /// The agent occurrence (`device_class: agent`).
    pub agent: SelfAtLoginOccurrence,
    /// The shared `bilateral_pair_id` linking the partnership
    /// grant/accept + delegation. Caller-minted (e.g.
    /// `Uuid::new_v4()`).
    pub bilateral_pair_id: String,
    /// Override the delegation scope set. `None` ⇒ the full §8.1.12.7
    /// set `[act_on_behalf, message_io, network_presence,
    /// sub_delegation]`.
    pub delegation_scope: Option<Vec<String>>,
}

/// v6.5.0 (CIRISPersist#183, CEG §8.1.12.7) — what
/// [`Engine::self_at_login`] landed.
#[derive(Debug, Clone)]
pub struct SelfAtLoginOutcome {
    /// `attestation_id` of the user-side `consent:partnership_grant`.
    pub partnership_grant_id: String,
    /// `attestation_id` of the agent-side `consent:partnership_accept`.
    pub partnership_accept_id: String,
    /// `attestation_id` of the `delegates_to` delegation.
    pub delegation_id: String,
    /// `true` if the delegation was promoted to the federation tier
    /// (`false` if it was already federation — idempotent).
    pub delegation_promoted: bool,
    /// Count of occurrences the Self DEK cascade granted to (newly).
    pub self_dek_granted: usize,
    /// Occurrence keys fail-secure **excluded** from the DEK cascade
    /// (registered no `encryption_pubkeys`). Empty in the happy path.
    pub self_dek_excluded: Vec<String>,
    /// Count of `transport_destination` rows registered across both
    /// occurrences.
    pub transport_destinations_registered: usize,
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
        let backend = build_backend(dsn, true).await?;
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
            replication_config: None,
            disk_pressure_config: None,
            disk_pressure_state: None,
            #[cfg(feature = "cirisnode")]
            multimedia_config: Arc::new(std::sync::RwLock::new(None)),
        })
    }

    /// v13.3.1 (CIRISPersist#387) — **TEST-ONLY** constructor: identical to
    /// [`with_signer`](Self::with_signer) (connect + run migrations) but it
    /// **SKIPS the HUMANITY_ACCORD genesis seed** — no baked A1/B1/C1 holder
    /// rows, no entrenched family row. Gated behind the `test-genesis-seam`
    /// cargo feature (default OFF, absent from release builds), so this cannot
    /// be reached in production — a node without the baked trust root is broken.
    ///
    /// The seed is deliberately **unconditional** in prod ([`with_signer`]): the
    /// baked accord family IS the immutable trust root, and the assemble
    /// ceremony is idempotent (an already-entrenched family is a no-op, never a
    /// replacement — else a node owner could overwrite the constitutional family
    /// with their own holders). This seam exists ONLY so downstream integration
    /// tests can assemble a *controllable* custom-holder `humanity-accord`
    /// family (with holders they can sign as) without the baked A1/B1/C1 +
    /// family causing a UNIQUE conflict or an unsignable roster. Enable it in
    /// `[dev-dependencies]` (e.g. CIRISServer's test build), never in
    /// `[dependencies]`.
    #[cfg(feature = "test-genesis-seam")]
    pub async fn with_signer_no_genesis_seed(
        signer: Arc<LocalSigner>,
        dsn: &str,
    ) -> Result<Self, EngineError> {
        let backend = build_backend(dsn, false).await?;
        let local_signer = Some(signer.clone());
        let signer: Arc<dyn HardwareSigner> = Arc::new(LocalSignerHardwareAdapter::new(signer));
        Ok(Engine {
            backend,
            signer,
            local_signer,
            replication_config: None,
            disk_pressure_config: None,
            disk_pressure_state: None,
            #[cfg(feature = "cirisnode")]
            multimedia_config: Arc::new(std::sync::RwLock::new(None)),
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

    /// v6.6.0 (CIRISPersist#220) — construct a fresh Engine (connect + run
    /// migrations, exactly like [`Engine::with_signer`]) whose federation
    /// signing identity is an externally-supplied [`HardwareSigner`] — a TPM /
    /// Secure-Enclave / StrongBox key obtained via
    /// [`ciris_keyring::get_platform_signer`] (which itself falls back to a
    /// software signer when no hardware is present). Unlike `with_signer`, no
    /// raw seed is read into the process when the signer is hardware-backed.
    ///
    /// `local_signer` is `None` (as in [`Engine::from_shared`]), so
    /// [`Engine::sign_hybrid`] is unavailable on Engines built this way — a
    /// hardware signer performs its own signing through the [`HardwareSigner`]
    /// trait. This is the from-scratch counterpart to `from_shared` (which is
    /// cohabitation-only and runs no migrations).
    pub async fn with_hardware_signer(
        signer: Arc<dyn HardwareSigner>,
        dsn: &str,
    ) -> Result<Self, EngineError> {
        let backend = build_backend(dsn, true).await?;
        Ok(Engine {
            backend,
            signer,
            local_signer: None,
            replication_config: None,
            disk_pressure_config: None,
            disk_pressure_state: None,
            #[cfg(feature = "cirisnode")]
            multimedia_config: Arc::new(std::sync::RwLock::new(None)),
        })
    }

    /// v7.1.0 (CIRISPersist#224) — construct a fresh Engine (connect + run
    /// migrations, like [`Engine::with_signer`]) whose federation signing
    /// identity is **hybrid with a hardware-sealed classical key**: the
    /// Ed25519 half is custodied by `classical` (a TPM / Secure-Enclave /
    /// StrongBox key reached through [`HardwareSigner`]) and the
    /// ML-DSA-65 half is supplied by `pqc`.
    ///
    /// This closes the last Ed25519-only path for a hardware-custodied
    /// node: unlike [`Engine::with_hardware_signer`] (classical-only —
    /// `sign_hybrid` returns [`SignError::LocalSignerUnavailable`]) and
    /// unlike [`Engine::with_signer_arcs`] (hybrid but with a **plaintext**
    /// Ed25519, defeating custody), an Engine built here produces a real
    /// [`ciris_crypto::HybridSignature`] — Ed25519 from the
    /// [`HardwareSigner`], ML-DSA-65 from the [`PqcSigner`] — so the
    /// storage-tier scrub signature (the produce/promote path that calls
    /// [`Engine::sign_hybrid`]) is hybrid **without ever unsealing the
    /// Ed25519 key**.
    ///
    /// The `LocalSigner` is composed via
    /// [`LocalSigner::from_hardware_parts`] (reads + caches the classical
    /// pubkey via the async [`HardwareSigner::public_key`]) and stored as
    /// `local_signer: Some(..)`; `signer` is the same hardware classical
    /// `Arc` (as in [`Engine::with_signer`], where `signer` is the
    /// classical-signing identity). The `key_id` is read from
    /// [`HardwareSigner::current_alias`].
    ///
    /// When `pqc` is `None`, the Engine behaves like a non-PQC
    /// [`Engine::with_signer`]: [`Engine::sign_hybrid`] returns
    /// [`SignError::LocalSigner(LocalSignerError::PqcNotConfigured)`](crate::signing::LocalSignerError::PqcNotConfigured).
    pub async fn with_hardware_signer_hybrid(
        classical: Arc<dyn HardwareSigner>,
        pqc: Option<Arc<dyn ciris_keyring::PqcSigner>>,
        pqc_key_id: Option<String>,
        dsn: &str,
    ) -> Result<Self, EngineError> {
        let key_id = classical.current_alias().to_owned();
        // Compose the LocalSigner with the SEALED classical half + the
        // PQC half. `from_hardware_parts` reads the classical pubkey once
        // (async) and caches it; the Ed25519 private key is never read.
        let local = Arc::new(
            crate::signing::LocalSigner::from_hardware_parts(
                classical.clone(),
                key_id,
                pqc,
                pqc_key_id,
            )
            .await?,
        );
        let backend = build_backend(dsn, true).await?;
        Ok(Engine {
            backend,
            // `signer` is the hardware classical itself — same shape as
            // the other ctors (the classical-signing federation identity).
            signer: classical,
            // `local_signer` carries the hybrid-composition surface so
            // `Engine::sign_hybrid` composes the sealed-classical hybrid.
            local_signer: Some(local),
            replication_config: None,
            disk_pressure_config: None,
            disk_pressure_state: None,
            #[cfg(feature = "cirisnode")]
            multimedia_config: Arc::new(std::sync::RwLock::new(None)),
        })
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
            // v3.4.0 (#123) — cohabitation views do NOT spawn a
            // second sweeper; the singleton owns the JoinHandle.
            replication_config: None,
            disk_pressure_config: None,
            disk_pressure_state: None,
            #[cfg(feature = "cirisnode")]
            multimedia_config: Arc::new(std::sync::RwLock::new(None)),
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
            replication_config: None,
            disk_pressure_config: None,
            disk_pressure_state: None,
            #[cfg(feature = "cirisnode")]
            multimedia_config: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// v3.4.0 (CIRISPersist#123) — opt-in constructor that composes a
    /// [`ReplicationConfig`](crate::federation::ReplicationConfig)
    /// onto a freshly-built Engine. The config governs the
    /// trust-weighted [`AdmissionGate`](crate::federation::AdmissionGate)
    /// applied to write paths and the eviction-sweeper cadence /
    /// budget. **Does not** spawn the sweeper task; sovereign Rust
    /// callers drive single passes via [`Engine::sweep_evictions_once`].
    pub async fn with_replication_config(
        signer: Arc<LocalSigner>,
        dsn: &str,
        replication_config: crate::federation::ReplicationConfig,
    ) -> Result<Self, EngineError> {
        let mut engine = Self::with_signer(signer, dsn).await?;
        engine.replication_config = Some(Arc::new(replication_config));
        Ok(engine)
    }

    /// v3.4.0 (CIRISPersist#123) — snapshot of the active replication
    /// config. Returns `None` when the Engine was constructed without
    /// one (defaults: bootstrap-permissive trust gate, sweeper off).
    pub fn replication_config(&self) -> Option<Arc<crate::federation::ReplicationConfig>> {
        self.replication_config.clone()
    }

    /// v3.4.0 (CIRISPersist#123) — variant of
    /// [`Self::with_replication_config`] for the cohabitation path
    /// (no DSN, no migrations). Consumes `self` because the field is
    /// not interior-mutable; cheap (Arc clones).
    pub fn with_replication_config_shared(
        mut self,
        cfg: Arc<crate::federation::ReplicationConfig>,
    ) -> Self {
        self.replication_config = Some(cfg);
        self
    }

    /// v6.8.0 (CIRISPersist#148) — opt-in constructor that composes a
    /// [`CacheMode`](crate::federation::CacheMode) preset onto a
    /// freshly-built Engine. The preset is folded onto the default
    /// [`ReplicationConfig`](crate::federation::ReplicationConfig) via
    /// [`CacheMode::apply_to`](crate::federation::CacheMode::apply_to)
    /// (Proxy → small budget + aggressive sweep; Cache → standard;
    /// Server → unbounded + idle sweeper).
    pub async fn with_cache_mode(
        signer: Arc<LocalSigner>,
        dsn: &str,
        mode: crate::federation::CacheMode,
    ) -> Result<Self, EngineError> {
        let cfg = mode.apply_to(crate::federation::ReplicationConfig::default());
        Self::with_replication_config(signer, dsn, cfg).await
    }

    /// v6.8.0 (CIRISPersist#149) — install / replace the disk-pressure
    /// operator config on this Engine view. Carried so the eviction
    /// sweeper's force-evict-proxy-first classification can consult the
    /// local/family predicate. Consumes `self` (Arc clones; cheap).
    pub fn with_disk_pressure_config_shared(
        mut self,
        cfg: Arc<crate::federation::DiskPressureConfig>,
    ) -> Self {
        self.disk_pressure_config = Some(cfg);
        self
    }

    /// v6.8.0 (CIRISPersist#149) — snapshot of the installed
    /// disk-pressure config, if any.
    pub fn disk_pressure_config(&self) -> Option<Arc<crate::federation::DiskPressureConfig>> {
        self.disk_pressure_config.clone()
    }

    /// v6.8.0 (CIRISPersist#149) — install the live disk-pressure
    /// snapshot receiver (fed by the background monitor loop). The
    /// proxy-accept / proxy-serve enforcement paths read it cheaply.
    /// Consumes `self` (cheap — a watch receiver clone).
    pub fn with_disk_pressure_state_shared(
        mut self,
        rx: tokio::sync::watch::Receiver<crate::federation::DiskPressureSnapshot>,
    ) -> Self {
        self.disk_pressure_state = Some(rx);
        self
    }

    /// v6.8.0 (CIRISPersist#149) — the current cached disk-pressure
    /// snapshot. When no monitor is installed on this view, returns the
    /// all-clear (`Normal`) snapshot so enforcement is a no-op.
    pub fn current_disk_pressure(&self) -> crate::federation::DiskPressureSnapshot {
        match &self.disk_pressure_state {
            Some(rx) => *rx.borrow(),
            None => crate::federation::DiskPressureSnapshot::normal(),
        }
    }

    /// v6.8.0 (CIRISPersist#149) — is `attesting_key_id` local-or-family
    /// (and therefore NEVER refused / never proxy)? Uses the installed
    /// [`DiskPressureConfig::is_family`] predicate against the local
    /// signer key_id. With no disk-pressure config installed, only the
    /// local signer itself is treated as protected. This is the SAME
    /// classification the force-evict-proxy-first sweep uses.
    ///
    /// v9.3.0 (#247) — `attesting_key_id` on a row is the producer's
    /// DERIVED federation key_id (`<label>-<fp>`), so the local-identity
    /// comparison is against the local signer's DERIVED id (via the
    /// preserved [`LocalSigner`](crate::signing::LocalSigner)), not the
    /// keystore alias. Falls back to the alias when no LocalSigner is
    /// carried (the `from_shared` cohabitation view).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub fn is_local_or_family_key(&self, attesting_key_id: &str) -> bool {
        let signer_key_id = self
            .local_signer
            .as_ref()
            .map(|s| s.derived_key_id())
            .unwrap_or_else(|| self.signer.current_alias().to_owned());
        match &self.disk_pressure_config {
            Some(cfg) => cfg.is_local_or_family(attesting_key_id, &signer_key_id),
            None => attesting_key_id == signer_key_id,
        }
    }

    /// v3.6.0 (CIRISPersist#134) — install / replace the media-sharing
    /// operator config. `None` clears it (persist defaults apply).
    ///
    /// The
    /// [`process_takedown_admission_with_config`](crate::cirisnode::takedown_handler::process_takedown_admission_with_config)
    /// handler consults this when present; the v3.6.0 default keeps
    /// child-safety / terrorist-content bases as immediate-eviction and
    /// the counter-notice window at 14 days.
    #[cfg(feature = "cirisnode")]
    pub fn set_multimedia_config(&self, cfg: Option<crate::cirisnode::MultimediaConfig>) {
        *self
            .multimedia_config
            .write()
            .unwrap_or_else(|p| p.into_inner()) = cfg.map(Arc::new);
    }

    /// v3.6.0 (CIRISPersist#134) — snapshot of the installed
    /// media-sharing config. `None` = persist defaults apply.
    #[cfg(feature = "cirisnode")]
    pub fn multimedia_config(&self) -> Option<Arc<crate::cirisnode::MultimediaConfig>> {
        self.multimedia_config
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// v3.4.0 (CIRISPersist#123) — install / clear the trust-weighted
    /// admission gate on the Engine's underlying storage backend. The
    /// four write paths consult this gate BEFORE any DB work.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub fn set_admission_gate(&self, gate: Option<crate::federation::AdmissionGate>) {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.set_admission_gate(gate),
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.set_admission_gate(gate),
        }
    }

    /// v3.5.1 (CIRISPersist#129) — extract a clone of the inner
    /// `Arc<dyn TrustScoring>` from the currently-installed admission
    /// gate. Returns `None` when no gate is configured (the bootstrap-
    /// permissive default).
    ///
    /// CIRISEdge `init_edge_runtime` (cohabitation) consumes this for
    /// the v0.19.x trust short-circuit auto-derivation — non-cohab
    /// `EdgeBuilder` callers wire `Arc<dyn TrustScoring>` directly,
    /// but cohabitation needs to pull it out of the live persist
    /// engine.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub fn trust_scoring(&self) -> Option<std::sync::Arc<dyn crate::federation::TrustScoring>> {
        let gate = match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.admission_gate(),
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.admission_gate(),
        };
        gate.map(|g| g.scoring_arc())
    }

    /// v3.4.0 (CIRISPersist#123) — drive one sweep cycle against the
    /// underlying `federation_blobs` table. Returns a
    /// [`crate::federation::SweepReport`] summarizing the result. A
    /// no-op when no [`ReplicationConfig`] is configured or
    /// `storage_budget_bytes == u64::MAX`.
    ///
    /// Sovereign Pi-cron callers + the spawned-sweeper loop both call
    /// this method; the loop body is the same single-pass function.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn sweep_evictions_once(
        &self,
    ) -> Result<crate::federation::SweepReport, crate::federation::BlobError> {
        self.sweep_evictions_once_inner(false).await
    }

    /// v6.8.0 (CIRISPersist#149) — disk-pressure variant of
    /// [`Self::sweep_evictions_once`]. When `force_evict_proxy_first`
    /// is set, candidates with NO local `holds_bytes` attestation
    /// (proxy content this node merely relays) are evicted ahead of
    /// locally-attested (local/family) content, ignoring the standard
    /// popularity × freshness order. Local/family rows are evicted only
    /// after all proxy rows are gone. The crit/stop/host-at-risk tiers
    /// call this with the flag set; the standard background sweeper
    /// (budget watermark) calls the non-forced path.
    ///
    /// IMPORTANT: this NEVER unconditionally drops local content — it
    /// only re-orders eviction priority within the same target-freed
    /// budget. Local/family rows survive until proxy is exhausted.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn sweep_evictions_once_force_proxy(
        &self,
    ) -> Result<crate::federation::SweepReport, crate::federation::BlobError> {
        self.sweep_evictions_once_inner(true).await
    }

    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    async fn sweep_evictions_once_inner(
        &self,
        force_evict_proxy_first: bool,
    ) -> Result<crate::federation::SweepReport, crate::federation::BlobError> {
        use crate::federation::{EvictionDecay, SweepReport};

        let Some(cfg) = self.replication_config.clone() else {
            return Ok(SweepReport::default());
        };
        if !cfg.sweeper_active() {
            return Ok(SweepReport::default());
        }

        let bytes_before = self.federation_blob_bytes().await?;
        let watermark = cfg.watermark_bytes();
        if bytes_before <= watermark {
            return Ok(SweepReport {
                bytes_before,
                bytes_after: bytes_before,
                rows_evicted: 0,
                withdraws_emitted: 0,
                withdraws_failed: 0,
            });
        }

        let target_freed = bytes_before.saturating_sub(watermark);
        let decay = EvictionDecay::new(cfg.eviction_decay_half_life_days);
        let now = chrono::Utc::now();
        // v9.3.0 (#247) — the sweeper matches its OWN `holds_bytes`
        // attestations (`list_attestations_by`, the proxy-vs-local
        // classification) and emits the paired `withdraws`. A correctly-
        // registered node emits both under its DERIVED federation key_id
        // (`<label>-<fp>`), so the lookup key must be the derived id, NOT
        // the keystore alias — matching the `emit_withdraws_attestation`
        // floor. Falls back to the alias only if the derived id can't be
        // resolved (no signer pubkey), preserving prior behaviour.
        let signer_key_id = self
            .local_derived_key_id()
            .await
            .unwrap_or_else(|_| self.signer.current_alias().to_owned());

        // Pull one batch — DEFAULT_SWEEP_BATCH cap per cycle keeps
        // each pass bounded. If the cycle exhausts the batch without
        // hitting target_freed, the next tick (or the next caller of
        // sweep_evictions_once) picks up where we left off.
        let mut candidates = self.sweep_candidates_batch(&cfg).await?;

        // Lookup prior holds_bytes attestations once per cycle so we
        // don't pay an O(N) directory query for each candidate. The
        // sweeper only withdraws attestations IT (the local signer)
        // emitted — that's what the federation graph expects: each
        // host announces eviction of its OWN holds_bytes rows.
        let directory = self.federation_directory();
        let signer_attestations = directory
            .list_attestations_by(&signer_key_id)
            .await
            .map_err(|e| {
                crate::federation::BlobError::Backend(format!(
                    "sweeper: list_attestations_by failed: {e}"
                ))
            })?;
        // Index by attestation_type so per-candidate lookup is O(1).
        // A single signer may have emitted multiple holds_bytes rows
        // over time for the same SHA (replay / re-attestation); the
        // sweeper withdraws the MOST RECENT one (max asserted_at).
        let mut holds_bytes_by_type: std::collections::HashMap<
            String,
            crate::federation::Attestation,
        > = std::collections::HashMap::new();
        for att in signer_attestations {
            if !att
                .attestation_type
                .starts_with(crate::federation::HOLDS_BYTES_ATTESTATION_TYPE_PREFIX)
            {
                continue;
            }
            holds_bytes_by_type
                .entry(att.attestation_type.clone())
                .and_modify(|existing| {
                    if att.asserted_at > existing.asserted_at {
                        *existing = att.clone();
                    }
                })
                .or_insert(att);
        }

        // v6.8.0 (#149): classify each candidate as proxy vs
        // local/family using the signer's holds_bytes index. A SHA with
        // a local holds_bytes from a key the engine considers
        // local-or-family is PROTECTED (evict last under pressure); a
        // SHA with no local holds_bytes (or one whose attesting key is
        // not local/family) is PROXY (evict first under pressure).
        let pressure_cfg = self.disk_pressure_config();
        let is_proxy = |candidate: &crate::federation::EvictionCandidate| -> bool {
            let holds_bytes_type =
                crate::federation::holds_bytes_attestation_type(&candidate.sha256);
            match holds_bytes_by_type.get(&holds_bytes_type) {
                None => true, // no local provenance ⇒ proxy
                Some(att) => match &pressure_cfg {
                    Some(dp) => !dp.is_local_or_family(&att.attesting_key_id, &signer_key_id),
                    // No disk-pressure config installed: anything WE
                    // attested is local; treat all attested as protected.
                    None => att.attesting_key_id != signer_key_id,
                },
            }
        };

        // v12.7.0 (§Q B5 / CIRISPersist#370) — fold the INSTALLED
        // StorageBudgetV1 state (V092; written only after the PQC-mandatory
        // verify + B3 anti-rollback in `install_storage_budget_v1`) into
        // this cycle's pin classification:
        //   * `pinned_classes` — the union of every installed budget's
        //     `pinned_class` set (a node typically installs exactly one —
        //     its own; folding the union + summed reserve is the
        //     most-protective composition when several owners' budgets are
        //     present: ambiguity fails toward retention, mirroring how
        //     B4 dedup retains while ANY scope pins).
        //   * `pin_reserve_floor` — the summed `pin_reserve_bytes` over all
        //     scopes: the byte floor the pinned classes hold under CAPACITY
        //     pressure.
        // A candidate is PINNED iff its `media_type` (the substrate's
        // per-blob corpus-class token) is in `pinned_classes`. With no
        // installed budget both are empty ⇒ this entire block is inert and
        // the pre-#370 ordering is byte-identical.
        let installed_budgets = self.list_installed_storage_budgets().await.map_err(|e| {
            crate::federation::BlobError::Backend(format!(
                "sweeper: list_installed_storage_budgets failed: {e}"
            ))
        })?;
        let mut pinned_classes: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut pin_reserve_floor: u64 = 0;
        for budget in &installed_budgets {
            pinned_classes.extend(budget.pinned_class.iter().cloned());
            pin_reserve_floor = pin_reserve_floor.saturating_add(budget.pin_reserve_total());
        }
        let is_pinned = |candidate: &crate::federation::EvictionCandidate| -> bool {
            candidate
                .media_type
                .as_deref()
                .is_some_and(|m| pinned_classes.contains(m))
        };
        // §Q B5 consumption accounting: recomputed from HELD content (the
        // full table, not just this batch), never trusted from the wire.
        // Decremented as pinned rows are shed so the reserve floor holds
        // within the cycle.
        let mut pinned_bytes_held: u64 = if pinned_classes.is_empty() {
            0
        } else {
            let media_types: Vec<String> = pinned_classes.iter().cloned().collect();
            self.pinned_blob_bytes(&media_types).await?
        };

        // Rust-side re-rank applies on both backends. PG already ranks
        // in SQL by full decay score; SQLite ranks by the monotone
        // bound. Re-ranking is idempotent on PG (no-op reorder) and
        // load-bearing on SQLite. Sorting ascending so lowest-score
        // evicts first.
        //
        // Key order (outermost first):
        //   1. §Q B5 CACHE BEFORE PINNED (#370) — unpinned candidates sort
        //      entirely ahead of pinned ones; pinned content is reached
        //      only once unpinned is exhausted. This is the NORMATIVE
        //      descent order (CC 6.1.2.3), so it outranks…
        //   2. …the #149 force-evict-proxy-first hint (crit/stop
        //      disk-pressure tiers): a local operational reordering that
        //      applies WITHIN a pin class only.
        //   3. Decay score (popularity × freshness), ascending — the
        //      standing rarity stand-in within each (pin, proxy) band
        //      (blob-level rarity scoring is PIN-AS-RECOMMENDATION /
        //      edge-internal per CC 6.1.3; the decay order is persist's
        //      deterministic local proxy for "lowest rarity first").
        candidates.sort_by(|a, b| {
            // unpinned/cache (false) sorts before pinned (true).
            match is_pinned(a).cmp(&is_pinned(b)) {
                std::cmp::Ordering::Equal => {}
                non_eq => return non_eq,
            }
            if force_evict_proxy_first {
                let pa = is_proxy(a);
                let pb = is_proxy(b);
                // proxy (true) sorts before protected (false).
                match pb.cmp(&pa) {
                    std::cmp::Ordering::Equal => {}
                    non_eq => return non_eq,
                }
            }
            let sa = decay.score(now, a.last_accessed_at, a.access_count);
            let sb = decay.score(now, b.last_accessed_at, b.access_count);
            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut rows_evicted: u64 = 0;
        let mut withdraws_emitted: u64 = 0;
        let mut withdraws_failed: u64 = 0;
        let mut bytes_freed: u64 = 0;

        for candidate in candidates {
            if bytes_freed >= target_freed {
                break;
            }
            // §Q B5 (#370): a PINNED candidate is evictable under CAPACITY
            // pressure only down to the `pin_reserve_bytes` floor — the
            // reserve the owner elected to hold for the pinned classes.
            // Skipping (not breaking) lets a smaller pinned row later in
            // the batch still fit above the floor. The sweep may therefore
            // end short of `target_freed`: that is the pin doing its job
            // (B6 keeps REVOCATION unconditional on its separate path —
            // `evict_fountain_content_hard_delete` never consults any of
            // this state).
            let candidate_pinned = is_pinned(&candidate);
            if candidate_pinned
                && pinned_bytes_held.saturating_sub(candidate.size_bytes) < pin_reserve_floor
            {
                continue;
            }
            // Try to emit a withdraws attestation for this SHA. If
            // the local signer never emitted a holds_bytes for it
            // (cohabitation drift, signer rotation, etc.), skip the
            // withdraws emission and STILL delete — orphaned
            // withdraws is worse than no withdraws.
            let holds_bytes_type =
                crate::federation::holds_bytes_attestation_type(&candidate.sha256);
            let withdraws_outcome = match holds_bytes_by_type.get(&holds_bytes_type) {
                Some(prior) => {
                    match self
                        .emit_withdraws_attestation(&prior.attestation_id, &holds_bytes_type)
                        .await
                    {
                        Ok(()) => Some(Ok(())),
                        Err(e) => Some(Err(e)),
                    }
                }
                None => None,
            };

            // Delete the blob row regardless of withdraws outcome —
            // the local copy is gone either way. The directory now
            // either has an explicit withdraws (consumers will skip
            // the holder) or simply will see TTL-expire the
            // holds_bytes row on its own freshness window.
            let deleted = self.delete_blob(&candidate.sha256).await?;
            if deleted {
                rows_evicted += 1;
                bytes_freed = bytes_freed.saturating_add(candidate.size_bytes);
                if candidate_pinned {
                    // §Q B5 (#370): keep the held-pinned accounting live so
                    // the reserve-floor check above stays correct as pinned
                    // rows are shed within this cycle.
                    pinned_bytes_held = pinned_bytes_held.saturating_sub(candidate.size_bytes);
                }
            }
            match withdraws_outcome {
                Some(Ok(())) => withdraws_emitted += 1,
                Some(Err(e)) => {
                    withdraws_failed += 1;
                    tracing::warn!(
                        error = %e,
                        sha256_prefix = &hex::encode(candidate.sha256)[..16],
                        "ciris-persist v3.4.0 sweeper: withdraws emission failed"
                    );
                }
                None => {
                    // No prior holds_bytes from this signer — silent
                    // skip is the documented behavior.
                }
            }
        }

        let bytes_after = self.federation_blob_bytes().await?;
        Ok(SweepReport {
            bytes_before,
            bytes_after,
            rows_evicted,
            withdraws_emitted,
            withdraws_failed,
        })
    }

    /// v3.4.0 (CIRISPersist#123) — spawn the background eviction
    /// sweeper. Returns an [`EvictionSweeper`] handle whose
    /// [`EvictionSweeper::stop`] method shuts the loop down. The
    /// loop calls [`Engine::sweep_evictions_once`] every
    /// `cfg.sweep_interval` (clamped below by
    /// [`crate::federation::MIN_SWEEP_INTERVAL`]).
    ///
    /// Sovereign mode: the Rust-side caller owns the
    /// [`EvictionSweeper`] handle and calls `.stop()` on shutdown.
    /// PyO3 mode: the [`crate::ffi::pyo3::EngineCell`] owns the
    /// handle so all `PyEngine` clones share one loop —
    /// [`Engine::from_shared`] does NOT spawn a second loop.
    ///
    /// No-op (returns `None`) when no
    /// [`crate::federation::ReplicationConfig`] is composed onto this
    /// Engine, or when the budget sentinel `u64::MAX` indicates the
    /// sweeper is intentionally inactive.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub fn spawn_sweeper(&self) -> Option<crate::federation::EvictionSweeper> {
        let cfg = self.replication_config.clone()?;
        if !cfg.sweeper_active() {
            return None;
        }
        let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
        let shutdown_for_loop = shutdown.clone();
        let interval = cfg
            .sweep_interval
            .max(crate::federation::MIN_SWEEP_INTERVAL);
        let engine = self.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_for_loop.notified() => {
                        tracing::info!(
                            "ciris-persist v3.4.0 sweeper: shutdown signal received"
                        );
                        return;
                    }
                    _ = tokio::time::sleep(interval) => {}
                }
                match engine.sweep_evictions_once().await {
                    Ok(report) if !report.is_noop() => {
                        tracing::info!(
                            rows_evicted = report.rows_evicted,
                            bytes_freed = report.bytes_freed(),
                            withdraws_emitted = report.withdraws_emitted,
                            withdraws_failed = report.withdraws_failed,
                            "ciris-persist v3.4.0 sweeper cycle"
                        );
                    }
                    Ok(_) => {
                        // Watermark not crossed — silent.
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "ciris-persist v3.4.0 sweeper cycle failed"
                        );
                    }
                }
            }
        });
        Some(crate::federation::EvictionSweeper::new(handle, shutdown))
    }

    /// v3.4.0 (CIRISPersist#123) — backend-dispatched candidate fetch.
    /// Per-backend ranking strategy:
    /// - PG ranks by full decay-weighted score in SQL.
    /// - SQLite ranks by the monotone composite bound; the caller
    ///   re-ranks in Rust by full score.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    async fn sweep_candidates_batch(
        &self,
        cfg: &crate::federation::ReplicationConfig,
    ) -> Result<Vec<crate::federation::EvictionCandidate>, crate::federation::BlobError> {
        let limit = crate::federation::DEFAULT_SWEEP_BATCH;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => {
                b.sweep_candidates(limit, cfg.eviction_decay_half_life_days)
                    .await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => {
                let _ = cfg; // SQLite computes the score Rust-side; cfg unused at SQL layer.
                b.sweep_candidates(limit).await
            }
        }
    }

    /// v3.4.0 (CIRISPersist#123) — delete one blob row by SHA from
    /// the underlying backend.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    async fn delete_blob(&self, sha256: &[u8; 32]) -> Result<bool, crate::federation::BlobError> {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.delete_blob(sha256).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.delete_blob(sha256).await,
        }
    }

    /// v6.9.0 (CIRISPersist#222) — GDPR Art. 17 / DSAR **full erasure**
    /// of an agent's trace corpus, keyed on `agent_id_hash` alone (all
    /// signing keys).
    ///
    /// In one atomic transaction the backend hard-deletes the agent's
    /// `trace_events` + `trace_llm_calls`, **tombstones** the derived
    /// `detection_events` (NULLs the PII linkage + stamps `erased_at` —
    /// the analytics survive, the subject linkage is severed), and emits
    /// a `hard_case:trace_erasure` audit row. Returns an
    /// [`ErasureSummary`](crate::store::types::ErasureSummary) with the
    /// per-table counts.
    ///
    /// **Idempotent**: a second call returns all-zero counts (`Ok`); a
    /// not-found is never an error. Persist owns the atomic substrate
    /// erasure; the caller (CIRISServer's absorbed-lens slice) owns the
    /// DSAR-request authority + signature verification.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn delete_traces_for_agent_id_hash(
        &self,
        agent_id_hash: &str,
    ) -> Result<crate::store::types::ErasureSummary, crate::store::Error> {
        use crate::store::Backend;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.delete_traces_for_agent_id_hash(agent_id_hash).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.delete_traces_for_agent_id_hash(agent_id_hash).await,
        }
    }

    // ─── v8.0.0 — fountain content primitive (CIRISPersist#227) ─────

    /// v8.0.0 (CIRISPersist#227) — admit a fountain-coded content unit
    /// (manifest + N+K symbols). Verify-before-mutation: the #225 hybrid
    /// verify on the manifest + per-symbol SHA-256 auth run first; on any
    /// failure NOTHING is written. Dispatches to the backend's
    /// [`Backend::put_fountain_content`](crate::store::Backend::put_fountain_content).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn put_fountain_content(
        &self,
        manifest: &crate::fountain::FountainManifestV1,
        symbols: &[crate::fountain::FountainSymbolV1],
    ) -> Result<(), crate::store::Error> {
        use crate::store::Backend;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.put_fountain_content(manifest, symbols).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.put_fountain_content(manifest, symbols).await,
        }
    }

    /// v8.0.0 (CIRISPersist#227) — typed degraded read of a fountain
    /// content unit. `Ok(None)` when no manifest exists. Dispatches to
    /// [`Backend::get_fountain_content`](crate::store::Backend::get_fountain_content).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn get_fountain_content(
        &self,
        content_id: &str,
        corpus_kind: &str,
    ) -> Result<Option<crate::fountain::FountainContent>, crate::store::Error> {
        use crate::store::Backend;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.get_fountain_content(content_id, corpus_kind).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.get_fountain_content(content_id, corpus_kind).await,
        }
    }

    /// #227 — list the fountain-coded content a **publisher** holds (filtered
    /// to `pqc_key_id = publisher_key_id`), as
    /// [`FountainHeldMeta`](crate::fountain::FountainHeldMeta): the manifest
    /// essentials + the current degradation state (`held_symbols` vs
    /// `min_viable_symbols` ⇒ `recoverable`), so a publisher can watch their
    /// content fade (#227) without fetching symbol bytes.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn list_held_fountain_content(
        &self,
        publisher_key_id: &str,
    ) -> Result<Vec<crate::fountain::FountainHeldMeta>, crate::store::Error> {
        use crate::store::Backend;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.list_held_fountain_content(publisher_key_id).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.list_held_fountain_content(publisher_key_id).await,
        }
    }

    /// v8.0.0 (CIRISPersist#227) — evict a content unit's symbols down to
    /// the given [`FountainTier`](crate::fountain::FountainTier) keep-
    /// count (highest `retention_priority` first). The manifest is never
    /// touched. The persist-owned eviction mechanism both the
    /// DiskPressure and the consent-decay triggers call. Returns the
    /// number of symbol rows evicted.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn evict_fountain_content_to_tier(
        &self,
        content_id: &str,
        corpus_kind: &str,
        tier: crate::fountain::FountainTier,
    ) -> Result<u64, crate::store::Error> {
        use crate::store::Backend;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => {
                b.evict_fountain_content_to_tier(content_id, corpus_kind, tier)
                    .await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => {
                b.evict_fountain_content_to_tier(content_id, corpus_kind, tier)
                    .await
            }
        }
    }

    /// v8.1.0 (CEG 1.0-RC11 §19 / CIRISPersist#228 N5) — **revocation
    /// HardDelete**: drop ALL symbols for a withdrawn /
    /// `consent:state:revoked` content_id, leaving the manifest as
    /// `EnvelopeOnly` provenance. A separate path from
    /// [`evict_fountain_content_to_tier`](Self::evict_fountain_content_to_tier)
    /// that never consults `retention_priority` — so rarity reweight can
    /// never resurrect a revoked content (revocation overrides rarity;
    /// the §8.1.11.3 deletion-SLA always wins). Returns the symbol rows
    /// dropped.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn evict_fountain_content_hard_delete(
        &self,
        content_id: &str,
        corpus_kind: &str,
    ) -> Result<u64, crate::store::Error> {
        use crate::store::Backend;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => {
                b.evict_fountain_content_hard_delete(content_id, corpus_kind)
                    .await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => {
                b.evict_fountain_content_hard_delete(content_id, corpus_kind)
                    .await
            }
        }
    }

    /// v8.0.0 (CIRISPersist#227) — the **DiskPressure trigger**: evict a
    /// content unit to the tier the Engine's CURRENT disk-pressure
    /// snapshot maps to (#149 `PressureTier` →
    /// [`FountainTier::from_pressure`](crate::fountain::FountainTier::from_pressure)).
    /// When no disk-pressure monitor is installed on this Engine view the
    /// snapshot is `normal` ⇒ `Full` ⇒ a no-op keep-everything.
    ///
    /// The **consent-decay trigger** calls
    /// [`evict_fountain_content_to_tier`](Self::evict_fountain_content_to_tier)
    /// directly with the consent-clock's tier; FULL Consensual-Evolution
    /// stream scheduling is a documented follow-on (see CHANGELOG
    /// [8.0.0]).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn evict_fountain_content_for_disk_pressure(
        &self,
        content_id: &str,
        corpus_kind: &str,
    ) -> Result<u64, crate::store::Error> {
        let snapshot = self.current_disk_pressure();
        let tier = crate::fountain::FountainTier::from_pressure(snapshot.tier);
        self.evict_fountain_content_to_tier(content_id, corpus_kind, tier)
            .await
    }

    /// v8.2.0 (CEG 1.0-RC11 §19.3 / CIRISPersist#228 items 4–5) — the
    /// **consent-driven retention decision** (N5). Resolve the subject's
    /// consent stance over the content (§8.1.11.1), run it through the
    /// FROZEN verify-core
    /// [`retention_decision`](ciris_verify_core::holonomic::retention_decision),
    /// and route the verdict:
    ///
    /// - `ConsentState::Revoked` (→ `Withdrawn` → `EvictEligible`) →
    ///   [`evict_fountain_content_hard_delete`](Self::evict_fountain_content_hard_delete)
    ///   — drop ALL symbols regardless of `retention_priority` /
    ///   `is_rare`. Revocation overrides rarity (the §8.1.11.3
    ///   deletion-SLA always wins); this routing is structurally
    ///   guaranteed by the separate hard-delete path. Returns the rows
    ///   dropped.
    /// - otherwise (RetainRare / RetainNonRare) → no eviction here
    ///   (the content stays under the opaque tier ordering, which the
    ///   disk-pressure / decay triggers drive). Returns `Ok(0)`.
    ///
    /// `target_key_id` / `subject_key_id` identify the consent record
    /// (`resolve_consent_state`); `content_id` / `corpus_kind` identify
    /// the fountain content; `is_rare` is the edge's opaque rarity signal
    /// (passed through unmodified — persist does not interpret it beyond
    /// the verdict). `now` resolves consent at a point in time.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    #[allow(clippy::too_many_arguments)]
    pub async fn evict_fountain_content_by_consent(
        &self,
        content_id: &str,
        corpus_kind: &str,
        target_key_id: &str,
        subject_key_id: &str,
        is_rare: bool,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, crate::store::Error> {
        use crate::federation::FederationDirectory;
        let consent = {
            let r = match &self.backend {
                #[cfg(feature = "postgres")]
                BackendDispatch::Postgres(b) => {
                    b.resolve_consent_state(target_key_id, subject_key_id, now)
                        .await
                }
                #[cfg(feature = "sqlite")]
                BackendDispatch::Sqlite(b) => {
                    b.resolve_consent_state(target_key_id, subject_key_id, now)
                        .await
                }
            };
            r.map_err(|e| crate::store::Error::Backend(format!("resolve_consent_state: {e}")))?
        };
        // N5: the FROZEN verify-core verdict decides. Withdrawn/revoked →
        // HardDelete regardless of rarity (revocation overrides rarity).
        let action = crate::fountain::resolve_retention_action(consent, is_rare);
        if action.is_hard_delete() {
            self.evict_fountain_content_hard_delete(content_id, corpus_kind)
                .await
        } else {
            Ok(0)
        }
    }

    // ─── v12.7.0 — §Q pin-INSTALL surface (CC 6.1.5.2 / CIRISPersist#370) ──

    /// v12.7.0 (CC 6.1.5.2 §Q B2/B3 / CIRISPersist#370) — **install** a
    /// signed `StorageBudgetV1` so it GOVERNS this node's capacity
    /// eviction (#356 shipped build/verify as wire-negotiation only).
    /// Three gates, in order:
    ///
    /// 1. **PQC-mandatory bound-hybrid verify at ingest, BEFORE
    ///    persistence** (CC 5.3.2.4.3.1 store-path / CC 6.1.3): the wire's
    ///    Ed25519 + ML-DSA-65 halves must verify against the owner pubkeys
    ///    — reuses [`verify_storage_budget_wire`]. This also re-runs the
    ///    structural validation (no `self`/`family` scope, `pin_reserve ≤
    ///    budget`, sorted + deduped lists).
    /// 2. **§Q B3 anti-rollback**: a candidate whose `revision` does not
    ///    STRICTLY supersede the installed one for the same `node_id` is
    ///    rejected with
    ///    [`StorageContentionError::RevisionRollback`](crate::fountain::storage_contention::StorageContentionError)
    ///    — enforced atomically inside the backend's conditional upsert
    ///    ([`Backend::put_installed_storage_budget`](crate::store::Backend::put_installed_storage_budget)),
    ///    so racing installs cannot roll back either.
    /// 3. Persist (V093 `storage_budget_installed`, both backends): the
    ///    signed wire VERBATIM + denormalized `revision`/`scopes`/
    ///    `pinned_class`.
    ///
    /// The installed budget is what [`Self::sweep_evictions_once`] reads to
    /// order candidates CACHE-BEFORE-PINNED (§Q B5) and to hold the
    /// `pin_reserve_bytes` floor. It is **capacity-only** state: the
    /// revocation path ([`Self::evict_fountain_content_hard_delete`])
    /// never reads it — §Q B6, pinning never defeats revocation.
    ///
    /// Returns the accepted `revision`.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn install_storage_budget_v1(
        &self,
        wire_json: &str,
        ed25519_pubkey_base64: &str,
        ml_dsa_65_pubkey_base64: &str,
    ) -> Result<u64, crate::store::Error> {
        use crate::fountain::storage_contention::{
            verify_storage_budget_wire, InstalledStorageBudget, StorageContentionError,
        };
        use crate::store::Backend;
        // Gate 1 — verify at the gate; nothing persists on failure.
        verify_storage_budget_wire(wire_json, ed25519_pubkey_base64, ml_dsa_65_pubkey_base64)?;
        let budget = InstalledStorageBudget::from_wire_json(wire_json, chrono::Utc::now())?;
        // Gates 2+3 — the backend's conditional upsert IS the anti-rollback
        // check (atomic at the row).
        let written = match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.put_installed_storage_budget(&budget).await?,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.put_installed_storage_budget(&budget).await?,
        };
        if !written {
            // Refused: read the incumbent revision back for the typed error
            // (best-effort — the row existed a moment ago).
            let installed = self
                .get_installed_storage_budget(&budget.node_id)
                .await?
                .map(|b| b.revision)
                .unwrap_or(budget.revision);
            return Err(StorageContentionError::RevisionRollback {
                node_id: budget.node_id,
                installed,
                candidate: budget.revision,
            }
            .into());
        }
        Ok(budget.revision)
    }

    /// #370 — read back the installed budget for `node_id` (typed).
    /// `Ok(None)` when none installed. Dispatches to
    /// [`Backend::get_installed_storage_budget`](crate::store::Backend::get_installed_storage_budget).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn get_installed_storage_budget(
        &self,
        node_id: &str,
    ) -> Result<
        Option<crate::fountain::storage_contention::InstalledStorageBudget>,
        crate::store::Error,
    > {
        use crate::store::Backend;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.get_installed_storage_budget(node_id).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.get_installed_storage_budget(node_id).await,
        }
    }

    /// #370 — the installed budget's signed wire JSON, VERBATIM as accepted
    /// (re-verifiable end-to-end with
    /// [`verify_storage_budget_wire`](crate::fountain::storage_contention::verify_storage_budget_wire)).
    /// `Ok(None)` when none installed for `node_id`.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn get_installed_storage_budget_json(
        &self,
        node_id: &str,
    ) -> Result<Option<String>, crate::store::Error> {
        Ok(self
            .get_installed_storage_budget(node_id)
            .await?
            .map(|b| b.wire_json))
    }

    /// #370 (§Q B5) — every installed budget. The capacity sweep folds
    /// these into the effective `pinned_class` set + `pin_reserve_bytes`
    /// floor once per cycle.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    async fn list_installed_storage_budgets(
        &self,
    ) -> Result<Vec<crate::fountain::storage_contention::InstalledStorageBudget>, crate::store::Error>
    {
        use crate::store::Backend;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.list_installed_storage_budgets().await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.list_installed_storage_budgets().await,
        }
    }

    /// #370 (§Q B5) — backend-dispatched pinned-consumption accounting:
    /// total `federation_blobs` bytes whose `media_type` is in the
    /// installed `pinned_class` set. Recomputed from held content (§Q:
    /// consumption accounting is edge-internal, never trusted from the
    /// wire).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    async fn pinned_blob_bytes(
        &self,
        media_types: &[String],
    ) -> Result<u64, crate::federation::BlobError> {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.pinned_blob_bytes(media_types).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.pinned_blob_bytes(media_types).await,
        }
    }

    /// #227 (residual) — the **consent-decay sweep**: the time-driven twin
    /// of the disk-pressure sweeper
    /// ([`sweep_evictions_once`](Self::sweep_evictions_once)). Enumerate
    /// EVERY fountain content unit
    /// ([`list_fountain_decay_candidates`](crate::store::Backend::list_fountain_decay_candidates)),
    /// read each unit's consent-decay class from its signed envelope, map
    /// `now - admitted_at` through the per-class decay schedule
    /// ([`consent_decay_target_tier`](crate::fountain::consent_decay_target_tier)
    /// — TEMPORARY 14-day, pattern 90-day), and drive any unit whose clock
    /// says it should be below its current tier down via the SAME eviction
    /// mechanism the disk-pressure trigger uses
    /// ([`evict_fountain_content_to_tier`](Self::evict_fountain_content_to_tier)).
    ///
    /// **Disk-INDEPENDENT** — fires regardless of free bytes (no watermark,
    /// no `ReplicationConfig` gate). **Idempotent** — the eviction
    /// mechanism only removes symbols down to a keep-count and is a no-op
    /// once a unit is already at/below its decay tier, so re-running the
    /// sweep at the same `now` evicts nothing further. Units that declare
    /// no decay class in their envelope are left untouched (fail-safe).
    ///
    /// `now` is threaded for deterministic testing; the FFI wrapper passes
    /// wall-clock `Utc::now()`. Manifests are NEVER touched (the
    /// always-retained provenance).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn sweep_consent_decay_once(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::fountain::ConsentDecaySweepReport, crate::store::Error> {
        use crate::store::Backend;
        let candidates = match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.list_fountain_decay_candidates().await?,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.list_fountain_decay_candidates().await?,
        };
        let mut report = crate::fountain::ConsentDecaySweepReport::default();
        for c in candidates {
            report.content_scanned += 1;
            let Some(tier) =
                crate::fountain::consent_decay_target_tier(&c.envelope, c.admitted_at, now)
            else {
                // No declared decay class ⇒ the time-clock opts out.
                continue;
            };
            report.content_with_decay_class += 1;
            if tier == crate::fountain::FountainTier::Full {
                // Clock hasn't reached the first breakpoint yet.
                continue;
            }
            let evicted = self
                .evict_fountain_content_to_tier(&c.content_id, &c.corpus_kind, tier)
                .await?;
            report.symbols_evicted += evicted;
            if evicted > 0 {
                report.content_decayed += 1;
            }
        }
        Ok(report)
    }

    // ─── v8.3.0 — §19.7 inter-object aggregation (CIRISPersist#230) ──

    /// v8.3.0 (CEG 1.0-RC12 §19.7 / CIRISPersist#230) — admit an aggregate
    /// composite (a `FountainContentV1`) + record its §19.7 aggregation
    /// provenance in ONE transaction. The composite reuses the EXISTING
    /// #225 hybrid-manifest admit gate (classical-only REJECTED, hard cut);
    /// verify-before-mutation means nothing is written if the composite
    /// admit fails. `agg.aggregation_meta` is stored OPAQUE (persist never
    /// parses it — the §19.7 wire-shape firewall) and `agg.member_commitment`
    /// is stored but NOT verified this cut (§19.7-freeze-gated). Dispatches
    /// to [`Backend::put_aggregated_tier`](crate::store::Backend::put_aggregated_tier).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn put_aggregated_tier(
        &self,
        manifest: &crate::fountain::FountainManifestV1,
        symbols: &[crate::fountain::FountainSymbolV1],
        agg: &crate::fountain::AggregationMetaV1,
        aggregated_at_unix_ms: i64,
    ) -> Result<(), crate::store::Error> {
        use crate::store::Backend;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => {
                b.put_aggregated_tier(manifest, symbols, agg, aggregated_at_unix_ms)
                    .await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => {
                b.put_aggregated_tier(manifest, symbols, agg, aggregated_at_unix_ms)
                    .await
            }
        }
    }

    /// v8.3.0 (CIRISPersist#230) — read a composite's aggregation record
    /// (opaque `aggregation_meta` as bytes). `Ok(None)` when none. The
    /// O(log T) pyramid-walk point read. Dispatches to
    /// [`Backend::get_aggregation`](crate::store::Backend::get_aggregation).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn get_aggregation(
        &self,
        aggregate_content_id: &str,
    ) -> Result<Option<crate::fountain::AggregationRecordV1>, crate::store::Error> {
        use crate::store::Backend;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.get_aggregation(aggregate_content_id).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.get_aggregation(aggregate_content_id).await,
        }
    }

    /// v8.3.0 (CIRISPersist#230) — list the aggregation records at a
    /// pyramid `level`, ordered by recency then id, capped at `limit` —
    /// the level-walk for the O(log T) forever-memory navigation.
    /// Dispatches to
    /// [`Backend::list_aggregations_at_level`](crate::store::Backend::list_aggregations_at_level).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn list_aggregations_at_level(
        &self,
        level: i64,
        limit: i64,
    ) -> Result<Vec<crate::fountain::AggregationRecordV1>, crate::store::Error> {
        use crate::store::Backend;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.list_aggregations_at_level(level, limit).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.list_aggregations_at_level(level, limit).await,
        }
    }

    /// v8.4.0 (CEG 1.0-RC14 §19.7 / CIRISPersist#230) — **descent
    /// orchestration** for a completed fold, gated on §19.7.1.1 descent
    /// integrity. After N sources fold into the `aggregate_content_id`
    /// composite, each source's gist lives BELOW the noise floor (its detail
    /// is now in the composite). The descent is driven by the canonical
    /// §19.7.3 verdict and the §19.7.1.1 member-commitment gate:
    ///
    /// 1. **Descent-integrity gate (§19.7.1.1).** Load the stored aggregation
    ///    record for `aggregate_content_id` and call
    ///    [`verify_member_commitment`](crate::fountain::verify_member_commitment)
    ///    over the caller-supplied source content_ids: the provided source set
    ///    MUST re-derive the committed `member_commitment` byte-for-byte. A
    ///    forged member set (one that does not match the commitment) is
    ///    REJECTED — it cannot drive eviction. Sources are then descended in
    ///    the canonical
    ///    [`descend_order`](crate::fountain::descend_order).
    /// 2. **Verdict (§19.7.3).** The per-source step is the canonical
    ///    [`ejection_verdict`](crate::fountain::ejection_verdict)`(consent,
    ///    under_capacity_pressure)`: `Withdrawn → EjectHardDelete` (the §19.3
    ///    N5 fastest descent, never tier-shed), capacity pressure →
    ///    `EjectToTier` (degrade to `target_tier`), else `Keep` (no-op). For a
    ///    tier-shed, `target_tier = None`/`Full` is a no-op `Keep`.
    ///
    /// The composite (the collective blur) is NEVER touched — **descent does
    /// not terminate at zero**. Returns total symbol rows evicted across all
    /// sources. Reconciles with the v8.2.0
    /// [`evict_fountain_content_by_consent`](Self::evict_fountain_content_by_consent)
    /// path: both route a revoked subject to the hard-delete primitive (no
    /// double logic — the verdict decides).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn descend_aggregated_sources(
        &self,
        aggregate_content_id: &str,
        sources: &[(String, String)],
        consent: ciris_verify_core::holonomic::ConsentState,
        under_capacity_pressure: bool,
        target_tier: Option<crate::fountain::FountainTier>,
    ) -> Result<u64, crate::store::Error> {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => {
                crate::fountain::descend_aggregated_sources_on_backend(
                    b.as_ref(),
                    aggregate_content_id,
                    sources,
                    consent,
                    under_capacity_pressure,
                    target_tier,
                )
                .await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => {
                crate::fountain::descend_aggregated_sources_on_backend(
                    b.as_ref(),
                    aggregate_content_id,
                    sources,
                    consent,
                    under_capacity_pressure,
                    target_tier,
                )
                .await
            }
        }
    }

    /// v8.6.0 (§19.7.3 / verify v5.11.0 / CEG RC16) — execute an
    /// [`EjectAggregatedTierOnly`](crate::fountain::EjectionAction::EjectAggregatedTierOnly):
    /// shed **exactly one** pyramid stratum — the tier-`tier`
    /// `content_aggregation` composite — leaving BOTH the finer (lower-level)
    /// AND coarser (higher-level) composites intact. The tier-granular form of
    /// `EjectToTier`.
    ///
    /// `aggregate_content_id` names the tier-`tier` composite; its stored
    /// `aggregation_level` MUST equal `tier` or NOTHING is shed (`Ok(0)`).
    /// Mechanically hard-deletes that ONE composite's symbols (its manifest
    /// survives as `EnvelopeOnly` provenance) via
    /// [`evict_aggregated_tier_on_backend`](crate::fountain::evict_aggregated_tier_on_backend).
    /// Composites at other levels are separate rows and are never touched.
    /// Composes with hard-delete: an unknown / already-erased stratum is a
    /// no-op — this never resurrects erased content. Returns the symbol rows
    /// shed.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn evict_aggregated_tier(
        &self,
        aggregate_content_id: &str,
        tier: u32,
    ) -> Result<u64, crate::store::Error> {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => {
                crate::fountain::evict_aggregated_tier_on_backend(
                    b.as_ref(),
                    aggregate_content_id,
                    tier,
                )
                .await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => {
                crate::fountain::evict_aggregated_tier_on_backend(
                    b.as_ref(),
                    aggregate_content_id,
                    tier,
                )
                .await
            }
        }
    }

    /// v3.4.0 (CIRISPersist#123) — build, sign, and persist a
    /// `withdraws` attestation that retracts a prior `holds_bytes`
    /// emission. The canonical envelope is produced via
    /// [`crate::federation::withdraws_attestation_envelope`] and
    /// canonicalized via
    /// [`crate::verify::canonical::PythonJsonDumpsCanonicalizer`]
    /// (NOT JCS — the same #121 discipline `put_blob_signing`
    /// follows).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    async fn emit_withdraws_attestation(
        &self,
        target_attestation_id: &str,
        target_holds_bytes_type: &str,
    ) -> Result<(), crate::federation::BlobError> {
        // v9.3.0 (#248) — persist's OWN withdraws producer now composes the
        // `emit_attestation` primitive instead of hand-rolling the
        // canonicalize → SHA-256 → hybrid-sign → 20-field-`Attestation` →
        // `put_attestation` recipe. This subsumes the hand-roll AND inherits
        // the #247 derived-key_id floor for free: the attester/scrub key is
        // the signer's registered DERIVED federation key_id (was
        // `current_alias()` plumbed in from the sweeper — the same #247 FK
        // bug class as `attestation_promote`). A withdraws targets the
        // holds_bytes `attestation_id` (in the envelope), not a key, so the
        // default self-attestation (`attested_key_id == attester`) keeps the
        // FK honest: "I attest I no longer hold these bytes."
        let signer = self.local_signer.as_ref().ok_or_else(|| {
            crate::federation::BlobError::Backend(
                "withdraws emit: Engine has no LocalSigner — a conformant federation-tier withdraws \
                 requires a hybrid (Ed25519 + ML-DSA-65) signer (CC 5.3.2.4.3.1)"
                    .to_string(),
            )
        })?;
        let envelope = crate::federation::withdraws_attestation_envelope(
            target_attestation_id,
            target_holds_bytes_type,
        );
        let input = crate::federation::EmitAttestationInput::with_envelope(
            crate::federation::types::attestation_type::WITHDRAWS,
            envelope,
        );
        self.emit_attestation(signer, input).await.map_err(|e| {
            crate::federation::BlobError::Backend(format!("withdraws emit_attestation: {e}"))
        })?;
        Ok(())
    }

    /// v3.4.0 (CIRISPersist#123) — total bytes currently held by
    /// `federation_blobs`. Feeds the eviction-sweeper watermark.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn federation_blob_bytes(&self) -> Result<u64, crate::federation::BlobError> {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => {
                let client =
                    b.pool().get().await.map_err(|e| {
                        crate::federation::BlobError::Backend(format!("pool get: {e}"))
                    })?;
                let row = client
                    .query_one(
                        "SELECT COALESCE(SUM(size_bytes), 0)::BIGINT AS total \
                         FROM cirislens.federation_blobs",
                        &[],
                    )
                    .await
                    .map_err(|e| {
                        crate::federation::BlobError::Backend(format!("federation_blob_bytes: {e}"))
                    })?;
                let total: i64 = row.get("total");
                Ok(u64::try_from(total).unwrap_or(0))
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => {
                let conn = b.conn_handle();
                let total = (move || -> Result<i64, rusqlite::Error> {
                    let conn = conn.lock();
                    conn.query_row(
                        "SELECT COALESCE(SUM(size_bytes), 0) FROM federation_blobs",
                        [],
                        |r| r.get::<_, i64>(0),
                    )
                })()
                .map_err(|e| {
                    crate::federation::BlobError::Backend(format!("federation_blob_bytes: {e}"))
                })?;
                Ok(u64::try_from(total).unwrap_or(0))
            }
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

    /// v9.3.0 (CIRISPersist#247) — the local signer's **registered
    /// (derived) federation key_id**: `derive_key_id(<keystore alias>,
    /// <ed25519 pubkey>)` = `"<label>-<fingerprint>"`.
    ///
    /// This is the value that FKs to `federation_keys(key_id)` after
    /// CIRISVerify FSD-003 — distinct from the keystore alias
    /// ([`HardwareSigner::current_alias`](ciris_keyring::HardwareSigner::current_alias),
    /// the `derive_key_id` *input*). Every federation-tier emit
    /// ([`Self::attestation_promote`]'s `scrub_key_id`,
    /// [`Self::emit_attestation`]'s attester/scrub) must use this, NOT the
    /// alias — using the alias FK-violates on any node whose alias ≠
    /// derived id (i.e. every real node — CIRISPersist#247).
    ///
    /// Reaches the Ed25519 pubkey through the composed
    /// `Arc<dyn HardwareSigner>` (`self.signer.public_key()`), so it works
    /// uniformly for software ([`Self::with_signer`]) and hardware
    /// ([`Self::with_hardware_signer_hybrid`]) engines alike — the alias
    /// is [`HardwareSigner::current_alias`].
    pub async fn local_derived_key_id(&self) -> Result<String, SignError> {
        let pubkey = self.signer.public_key().await.map_err(|e| {
            SignError::LocalSigner(crate::signing::LocalSignerError::ClassicalSign(format!(
                "local_derived_key_id: hardware public_key read failed: {e}"
            )))
        })?;
        // v10.1.0 (CIRISPersist#275 hardening) — fail LOUD, not silent: a
        // federation key_id is `derive_key_id(<alias>, <32-byte Ed25519
        // pubkey>)`. If the composed signer is NOT Ed25519 (e.g. a 65-byte
        // P-256 `EcdsaP256` keystore fallback), deriving over its pubkey
        // would mint a key_id that no valid Ed25519 federation row can match
        // — and silently store an unverifiable key (the #275 3rd surface).
        // Reject here so the misconfiguration surfaces at the source instead
        // of as a downstream FK / invalid_length failure.
        // An Ed25519 public key is exactly 32 bytes.
        const ED25519_PUBLIC_KEY_LEN: usize = 32;
        if pubkey.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(SignError::LocalSigner(
                crate::signing::LocalSignerError::ClassicalSign(format!(
                    "local_derived_key_id: signer public_key is {} bytes, not a 32-byte Ed25519 \
                     key — the engine's federation signing identity must be Ed25519 (got a \
                     non-Ed25519 signer; pass an Ed25519 local_key_id/local_key_path)",
                    pubkey.len(),
                )),
            ));
        }
        Ok(ciris_verify_core::fedcode::derive_key_id(
            self.signer.current_alias(),
            &pubkey,
        ))
    }

    /// v10.0.1 (CIRISPersist#275) — register THIS engine's **own
    /// federation identity** — the composed `self.signer`, the key every
    /// emit/scrub path derives its key_id from — as a self-signed
    /// `federation_keys` row of `identity_type`.
    ///
    /// The row is keyed by the **derived** federation key_id
    /// ([`Self::local_derived_key_id`] = `derive_key_id(<alias>, <ed25519
    /// pubkey>)` = `<label>-<fp>`), carries `self.signer`'s Ed25519 pubkey,
    /// and a classical self-signature over the canonical
    /// `registration_envelope`. This is the row the holds_bytes / withdraws
    /// / emit `scrub_key_id` FK resolves against (the #247 floor).
    ///
    /// # Why `self.signer`, not a `LocalSigner`
    ///
    /// Pre-#275 the FFI bootstrap registered the **`LocalSigner`** seed's
    /// identity (and historically the bare keystore alias). But every
    /// federation-tier emit — [`Self::put_blob_signing`]'s holds_bytes
    /// scrub, [`Self::emit_attestation_self`], [`Self::attestation_promote`],
    /// the eviction `withdraws` — derives its key_id from `self.signer`
    /// ([`Self::local_derived_key_id`]). When the composed signer and the
    /// local seed are distinct identities (different Ed25519 pubkeys ⇒
    /// different derived ids — the real-node shape), the registered row and
    /// the scrub FK target diverged, so `put_blob_signing` FK-failed on the
    /// canonical "register self, then hold bytes" flow for every persist
    /// ≥ 9.3.0. Registering `self.signer`'s identity (and returning its
    /// derived id, which the caller threads back as `attesting_key_id`)
    /// closes that gap structurally.
    ///
    /// The ML-DSA half is left to the cold-path PQC fill (matches the
    /// pre-#275 shape). Returns the registered (derived) key_id.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn register_self_federation_key(
        &self,
        identity_type: &str,
        identity_ref: &str,
        valid_until: Option<chrono::DateTime<chrono::Utc>>,
        registration_envelope: serde_json::Value,
        roles: Vec<String>,
    ) -> Result<String, crate::federation::Error> {
        use crate::federation::FederationDirectory;
        use crate::verify::canonical::{Canonicalizer, PythonJsonDumpsCanonicalizer};
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        use sha2::{Digest, Sha256};

        // The federation identity is the engine's composed signer — the
        // SAME key every emit/scrub path derives its key_id from (#247/#275).
        let key_id = self.local_derived_key_id().await.map_err(|e| {
            crate::federation::Error::Backend(format!("register_self derive key_id: {e}"))
        })?;
        let pubkey = self.signer.public_key().await.map_err(|e| {
            crate::federation::Error::Backend(format!("register_self signer public_key: {e}"))
        })?;
        let pubkey_ed25519_base64 = B64.encode(&pubkey);

        // Canonicalize the registration envelope with the production
        // Python-dumps canonicalizer (the rule the manual/FFI workflow
        // signs over), SHA-256 it, and classically self-sign with the
        // composed signer.
        let canonical = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&registration_envelope)
            .map_err(|e| {
                crate::federation::Error::Backend(format!("register_self canonicalize: {e}"))
            })?;
        let original_content_hash = hex::encode(Sha256::digest(&canonical));

        // Microsecond truncation (Postgres TIMESTAMPTZ precision) — inlined
        // to avoid a cirisaudit-feature dep on this path (mirrors the FFI).
        let now = {
            use chrono::Timelike as _;
            let dt = chrono::Utc::now();
            let micros = dt.nanosecond() / 1000;
            dt.with_nanosecond(micros * 1000).unwrap_or(dt)
        };

        // v10.1.0 (CIRISPersist#275 — withdraws/eviction surface) — populate
        // the ML-DSA-65 PUBLIC KEY and a complete hybrid scrub signature when
        // the engine has a PQC identity. Pre-#275 the row left
        // `pubkey_ml_dsa_65_base64 = None` (deferred to a "cold-path fill"
        // that never runs in a standalone / SQLite wheel). A registered key
        // with NO ML-DSA pubkey makes the federation-tier ingest gate REJECT
        // every hybrid-signed emission verified against it
        // (`verify_hybrid_pqc_fields_mismatch`: "PQC signature without
        // pubkey") — e.g. the eviction `withdraws` and any `emit_attestation`.
        // So a node that registered itself could not emit. The classical half
        // of `sign_hybrid` is the engine's composed signer (== the Ed25519
        // identity in `pubkey_ed25519_base64`), so the row is internally
        // consistent.
        let pqc_pubkey_b64 = match self.local_signer.as_ref() {
            Some(ls) => ls.pqc_public_key_b64().await.map_err(|e| {
                crate::federation::Error::Backend(format!("register_self pqc public_key: {e}"))
            })?,
            None => None,
        };
        let (scrub_signature_classical, scrub_signature_pqc, pqc_completed_at) =
            if pqc_pubkey_b64.is_some() {
                let sig = self.sign_hybrid(&canonical).await.map_err(|e| {
                    crate::federation::Error::Backend(format!("register_self hybrid sign: {e}"))
                })?;
                (
                    B64.encode(&sig.classical.signature),
                    Some(B64.encode(&sig.pqc.signature)),
                    Some(now),
                )
            } else {
                // Ed25519-only identity — classical-only self-signature. A
                // non-PQC node cannot emit federation-tier rows (enforced at
                // those emit sites); the row stays Ed25519-only.
                let classical_sig = self.signer.sign(&canonical).await.map_err(|e| {
                    crate::federation::Error::Backend(format!("register_self classical sign: {e}"))
                })?;
                (B64.encode(&classical_sig), None, None)
            };

        let record = crate::federation::KeyRecord {
            key_id: key_id.clone(),
            pubkey_ed25519_base64,
            pubkey_ml_dsa_65_base64: pqc_pubkey_b64,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: identity_type.to_owned(),
            identity_ref: identity_ref.to_owned(),
            valid_from: now,
            valid_until,
            registration_envelope,
            original_content_hash,
            scrub_signature_classical,
            scrub_signature_pqc,
            scrub_key_id: key_id.clone(),
            scrub_timestamp: now,
            pqc_completed_at,
            persist_row_hash: String::new(),
            roles,
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        let signed = crate::federation::SignedKeyRecord { record };

        // Self-bootstrap write — the same path the FFI `put_public_key`
        // takes (NO `verify_key_registration`: that hybrid-mandatory
        // §5.6.8.15 gate is for PEER registration via
        // [`Self::register_federation_key`], not a node minting its own
        // bootstrap row; the PQC half is filled by the cold path). The
        // `put_public_key` writer is idempotent on the `key_id` PK.
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.put_public_key(signed).await?,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.put_public_key(signed).await?,
        }
        Ok(key_id)
    }

    /// v4.6 (CIRISPersist#171 phase 2, CEG §10.1.3/§10.1.5) — promote a
    /// **local**-tier self-attestation to **federation**: canonicalize the
    /// row's envelope through the produce-side gate (JCS post-cut, §0.9),
    /// hybrid-sign the canonical bytes (Ed25519 + ML-DSA-65), and write
    /// back the scrub envelope + flip `tier` to `federation`. The signing
    /// bytes are the §0.9-canonical envelope, so the promoted row is
    /// byte-identical on the wire to a natively-federation attestation
    /// (Registry must #1). Returns `Ok(true)` on promotion, `Ok(false)` if
    /// the row is already `federation` (idempotent). Requires a
    /// PQC-configured `LocalSigner`.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn attestation_promote(
        &self,
        attestation_id: &str,
    ) -> Result<bool, crate::federation::Error> {
        use crate::federation::FederationDirectory;
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        use sha2::{Digest, Sha256};

        // 1. Load the row (any tier).
        let row = match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.get_attestation(attestation_id).await?,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.get_attestation(attestation_id).await?,
        }
        .ok_or_else(|| {
            crate::federation::Error::InvalidArgument(format!(
                "attestation_promote: row {attestation_id} does not exist"
            ))
        })?;
        if row.tier == crate::federation::types::attestation_tier::FEDERATION {
            return Ok(false); // idempotent
        }

        // 2. Canonicalize the envelope (produce gate → JCS post-cut) + hash.
        let canonical = crate::verify::canonical::ceg_produce_canonicalize(
            &row.attestation_envelope,
        )
        .map_err(|e| {
            crate::federation::Error::Backend(format!("attestation_promote canonicalize: {e}"))
        })?;
        let original_content_hash_hex = hex::encode(Sha256::digest(&canonical));

        // 3. Hybrid-sign the canonical bytes (matches the native produce
        // path: signer.sign(canonical_bytes)).
        let sig = self.sign_hybrid(&canonical).await.map_err(|e| {
            crate::federation::Error::Backend(format!("attestation_promote sign_hybrid: {e}"))
        })?;
        let classical_b64 = B64.encode(&sig.classical.signature);
        let pqc_b64 = B64.encode(&sig.pqc.signature);
        // v9.3.0 (#247) — `scrub_key_id` FKs to `federation_keys(key_id)`,
        // which is the **derived** wire key_id (`<label>-<fp>`), NOT the
        // keystore alias `current_alias()`. Using the alias FK-violated on
        // every node whose alias ≠ derived id (i.e. every real node).
        let scrub_key_id = self.local_derived_key_id().await.map_err(|e| {
            crate::federation::Error::Backend(format!(
                "attestation_promote derive scrub_key_id: {e}"
            ))
        })?;
        let now = chrono::Utc::now();

        // 4. Write back the scrub envelope + flip tier (signed-epoch gate
        // on the verify side will read these post-cut as JCS).
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => {
                b.promote_attestation(
                    attestation_id,
                    &classical_b64,
                    Some(&pqc_b64),
                    &original_content_hash_hex,
                    &scrub_key_id,
                    now,
                )
                .await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => {
                b.promote_attestation(
                    attestation_id,
                    &classical_b64,
                    Some(&pqc_b64),
                    &original_content_hash_hex,
                    &scrub_key_id,
                    now,
                )
                .await
            }
        }
    }

    /// v9.3.0 (CIRISPersist#248) — THE high-level emit primitive: produce
    /// ONE signed, **federation-tier** CEG attestation.
    ///
    /// Canonicalize ([`ceg_produce_canonicalize`](crate::verify::canonical::ceg_produce_canonicalize))
    /// → SHA-256 (`original_content_hash`) → hybrid-sign
    /// ([`LocalSigner::sign_hybrid`](crate::signing::LocalSigner::sign_hybrid),
    /// Ed25519 + ML-DSA-65 bound, the v9.0.0 / CC 5.3.2.4.3.1 PQC
    /// requirement) → assemble the 20-field [`Attestation`] →
    /// [`put_attestation`](crate::federation::FederationDirectory::put_attestation).
    /// Returns the `attestation_id`.
    ///
    /// `attesting_key_id` == `scrub_key_id` == the signer's **DERIVED
    /// federation key_id** ([`LocalSigner::derived_key_id`](crate::signing::LocalSigner::derived_key_id)
    /// = `derive_key_id(<alias>, <pubkey>)`), computed internally — the
    /// helper NEVER trusts a caller alias, which structurally kills the
    /// #247 FK-violation class (the same bug `attestation_promote` had).
    /// `attested_key_id` defaults to the derived key_id (self-attestation)
    /// when [`EmitAttestationInput::attested_key_id`] is `None`.
    ///
    /// v12.7.0 (CIRISPersist#368, CC 3.4.11/3.4.13) —
    /// [`EmitAttestationInput::attested_key_id`] names the row's **SUBJECT**
    /// (the natural CEG cross-subject edge target, exactly how
    /// [`Self::grant_delegation`] keys a `delegates_to` by its recipient).
    /// This is the **witness-targets-subject** age-assurance surface: a
    /// `witness`-role signer emits `attestation_type =
    /// "age_assurance:{level}:{band}:v1"` with `attested_key_id =
    /// Some(subject)` and the SUBJECT's
    /// [`age_band`](crate::federation::age::age_band) graduates (the witness
    /// rung outranks the subject's `age_self_declared:*`). The identity gate
    /// is unchanged (only `identity_type ⊇ {witness}` may emit the prefix),
    /// and a subject cannot graduate ITSELF: attester==attested on
    /// `age_assurance:*` is rejected at admission
    /// ([`Error::AgeAssuranceSelfEmissionRejected`](crate::federation::Error::AgeAssuranceSelfEmissionRejected),
    /// CC 3.4.11 "a subject MUST NOT emit on `age_assurance:`").
    ///
    /// This is the single correct implementation consumers (Node / Lens /
    /// Registry / Server, and persist's own withdraws producer) compose
    /// against instead of hand-rolling the ~50-line recipe. For the
    /// local-write → promote shape (a private local-tier row first, scrub
    /// later) callers use
    /// [`attestation_upsert_local`](crate::federation::FederationDirectory::attestation_upsert_local)
    /// then [`Self::attestation_promote`]; this method covers the direct
    /// federation-emit case.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn emit_attestation(
        &self,
        signer: &crate::signing::LocalSigner,
        input: crate::federation::EmitAttestationInput,
    ) -> Result<String, crate::federation::Error> {
        // Derive the registered federation key_id from the signer itself
        // (#247 floor) — never a caller-supplied alias.
        let key_id = signer.derived_key_id();

        // Canonicalize once here so the same bytes are both hashed and
        // signed; hybrid-sign over the EXTERNAL signer. A non-PQC signer
        // cannot emit a conformant federation-tier attestation — surface
        // honestly with the same message the self-emit path uses.
        let canonical = Self::emit_canonicalize(&input.attestation_envelope)?;
        let sig = signer.sign_hybrid(&canonical).await.map_err(|e| {
            crate::federation::Error::Backend(format!(
                "emit_attestation sign_hybrid: {e} — a conformant federation-tier emit requires a \
                 hybrid (Ed25519 + ML-DSA-65) signer (CC 5.3.2.4.3.1)"
            ))
        })?;

        self.emit_attestation_assemble(key_id, &canonical, sig, input)
            .await
    }

    /// v9.4.0 (CIRISPersist#253) — node-self emit over the engine's OWN
    /// **composed signer** (`Arc<dyn HardwareSigner>`), the common case: a
    /// node emitting a federation-tier row about itself with its configured
    /// identity. Same canonicalize → hybrid-sign → 20-field [`Attestation`]
    /// → [`put_attestation`](crate::federation::FederationDirectory::put_attestation)
    /// recipe as [`Self::emit_attestation`], but signs via
    /// [`Self::sign_hybrid`] and derives `attesting_key_id`/`scrub_key_id`
    /// from [`Self::local_derived_key_id`] — so it works for **software**
    /// ([`Self::with_signer`]) AND **hardware-hybrid**
    /// ([`Self::with_hardware_signer_hybrid`]) engines alike.
    ///
    /// This is the surface a hardware-hybrid node uses to fold its own
    /// federation-tier emits onto the #249 helpers: such an engine holds
    /// only the composed signer (no [`LocalSigner`](crate::signing::LocalSigner)
    /// to pass to [`Self::emit_attestation`]), so it could not previously
    /// emit without constructing a parallel signer mirroring its identity
    /// (CIRISPersist#253, CIRISServer#45).
    ///
    /// Returns [`crate::federation::Error::Backend`] wrapping
    /// [`SignError::LocalSignerUnavailable`] (no signer composed) or the
    /// signer's own [`PqcNotConfigured`](crate::signing::LocalSignerError::PqcNotConfigured)
    /// (no ML-DSA half) — a conformant emit requires a hybrid signer.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn emit_attestation_self(
        &self,
        input: crate::federation::EmitAttestationInput,
    ) -> Result<String, crate::federation::Error> {
        // #247-correct derived federation key_id of the engine's own
        // composed signer (works for software + hardware-hybrid alike).
        let key_id = self.local_derived_key_id().await.map_err(|e| {
            crate::federation::Error::Backend(format!("emit_attestation_self derive key_id: {e}"))
        })?;

        let canonical = Self::emit_canonicalize(&input.attestation_envelope)?;
        // Hybrid-sign over the COMPOSED signer. No `LocalSigner` is needed,
        // so a hardware-hybrid engine can emit here.
        let sig = self.sign_hybrid(&canonical).await.map_err(|e| {
            crate::federation::Error::Backend(format!(
                "emit_attestation_self sign_hybrid: {e} — a conformant federation-tier emit \
                 requires a composed hybrid (Ed25519 + ML-DSA-65) signer (CC 5.3.2.4.3.1)"
            ))
        })?;

        self.emit_attestation_assemble(key_id, &canonical, sig, input)
            .await
    }

    /// Shared body of [`Self::emit_attestation`] / [`Self::emit_attestation_self`]:
    /// canonicalize the envelope (produce gate → JCS post-cut, §0.9). The
    /// canonical bytes are both SHA-256'd (`original_content_hash`) and
    /// hybrid-signed by the caller, so the two paths sign byte-identical
    /// content.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    fn emit_canonicalize(
        envelope: &serde_json::Value,
    ) -> Result<Vec<u8>, crate::federation::Error> {
        crate::verify::canonical::ceg_produce_canonicalize(envelope).map_err(|e| {
            crate::federation::Error::Backend(format!("emit_attestation canonicalize: {e}"))
        })
    }

    /// Shared body of [`Self::emit_attestation`] / [`Self::emit_attestation_self`]:
    /// assemble the 20-field [`Attestation`] from the already-derived
    /// `key_id` (the attester/scrub — #247 derived federation key_id, never
    /// a caller alias), the `canonical` bytes (for the
    /// `original_content_hash`), the computed hybrid `sig`, and `input`, then
    /// [`put_attestation`](crate::federation::FederationDirectory::put_attestation).
    /// The two public entry points differ ONLY in where the signer / key_id
    /// come from — this keeps the canonicalize→hash→assemble→put recipe
    /// single-sourced (no duplication).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    async fn emit_attestation_assemble(
        &self,
        key_id: String,
        canonical: &[u8],
        sig: ciris_crypto::HybridSignature,
        input: crate::federation::EmitAttestationInput,
    ) -> Result<String, crate::federation::Error> {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        use sha2::{Digest, Sha256};

        // CIRISPersist#293 (CC 2.6.3 / §0.6) — refuse a non-canonical
        // (uppercase / empty) subject id at admission, before the row is
        // assembled. Covers BOTH emit entry points (this is their shared
        // body), so `emit_attestation` and `emit_attestation_self` enforce
        // it identically on either backend.
        crate::federation::validate_subject_key_ids(&input.subject_key_ids)?;

        let original_content_hash = hex::encode(Sha256::digest(canonical));
        let now = chrono::Utc::now();

        let attested_key_id = input.attested_key_id.unwrap_or_else(|| key_id.clone());
        let cohort_scope = if input.cohort_scope.is_empty() {
            crate::federation::types::cohort_scope::FEDERATION.to_string()
        } else {
            input.cohort_scope
        };

        let row = crate::federation::Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: key_id.clone(),
            attested_key_id,
            attestation_type: input.attestation_type,
            // v9.4.0 (#252) — fold the optional weight onto the row. `None`
            // preserves the pre-9.4.0 default (read as `1.0` by the trust
            // model); `Some(w)` lets a weighted `scores` producer keep its
            // band instead of collapsing to `1.0`.
            weight: input.weight,
            asserted_at: now,
            expires_at: input.expires_at,
            attestation_envelope: input.attestation_envelope,
            original_content_hash,
            scrub_signature_classical: B64.encode(&sig.classical.signature),
            scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
            scrub_key_id: key_id,
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            subject_key_ids: input.subject_key_ids,
            withdraws_admission_rule: None,
            cohort_scope,
            tier: crate::federation::types::attestation_tier::FEDERATION.to_string(),
            promoted_at: None,
        };
        let attestation_id = row.attestation_id.clone();

        self.federation_directory()
            .put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await?;
        Ok(attestation_id)
    }

    // ── #249 Cut C ── delegates_to / moderation emit ceremonies ───────
    //
    // v9.3.0 (CIRISPersist#249, CEG §3.2.1 / §11.10 / CC 4.4.3.4.3) — the
    // typed emit conveniences over the #248 [`Self::emit_attestation`]
    // primitive. Each builds the right `delegates_to` / `withdraws` /
    // `scores` envelope and calls `emit_attestation` — NONE re-hand-rolls
    // the canonicalize→sign→assemble→put recipe (the #247 derived-key_id
    // floor is inherited: the attester/scrub key is always the signer's
    // DERIVED federation key_id, never a caller alias). `grant_delegation`
    // is the general primitive; `steward_bind` / `add_moderator` specialize
    // it with the CC 4.4.3.4.3 `infra:*` and §11.10 duty scopes; the
    // `revoke_*` pair emit a producer-self `withdraws` (rule-1 admitted)
    // against the prior edge.

    /// v9.3.0 (CIRISPersist#249, CEG §3.2.1) — THE general delegation emit:
    /// "I authorize `delegate_key_id` within `scopes`, optionally with
    /// `sub_delegation` (deputization)". Builds the
    /// [`delegates_to_envelope`](crate::federation::delegates_to_envelope)
    /// (the §11.10-admissible shape: `scope` as an array-set + a top-level
    /// `sub_delegation` bool) and composes
    /// [`Self::emit_attestation`] with `attestation_type = "delegates_to"`
    /// and `attested_key_id = delegate_key_id` (the recipient — required so
    /// the per-edge retraction bucketing in the duty walk + `is_steward_bound`
    /// key the edge by its recipient). Returns the `attestation_id`.
    ///
    /// `delegate_key_id` MUST exist in `federation_keys` (the
    /// `attested_key_id` FK). The CC 4.4.3.4.3 node-agency gate runs on the
    /// emitted row: a node-ONLY recipient may carry only `infra:*` scopes —
    /// use [`Self::steward_bind`] for that case. `#247`-derived
    /// `attesting_key_id` is internal.
    ///
    /// v12.7.0 (CIRISPersist#367, CC 3.2) — a **`user`-role recipient** is
    /// governed by the user-target steward-binding gate
    /// ([`check_user_target_steward_binding_admission`](crate::federation::admission::check_user_target_steward_binding_admission)):
    /// the ONLY admissible user-target shapes are **minor-guardianship**
    /// (recipient is a PROVEN minor — a witness `age_assurance:*:minor`
    /// about it, emittable cross-subject per #368 — and the signer is a
    /// PROVEN adult `user`) and the narrow CC 3.4.12 adult-incapacity
    /// aperture. Everything else rejects
    /// (`federation_user_target_steward_binding_forbidden`). Withdrawing the
    /// guardianship edge ([`Self::revoke_delegation`]) leaves the minor
    /// steward-less and
    /// [`is_steward_bound`](crate::federation::admission::is_steward_bound)
    /// fails secure (`false`).
    ///
    /// v13.2.0 (CIRISPersist#378, CC 3.2 rc2 single-owner) — `delegation_purpose`
    /// marks the edge's ownership sub-relation. `Some(`[`owner_binding::PURPOSE`](crate::federation::types::owner_binding::PURPOSE)`)`
    /// (`"responsible_for"`) builds an **owner-binding** via
    /// [`owner_binding_delegates_to_envelope`](crate::federation::owner_binding_delegates_to_envelope)
    /// — the single-valued `delegates_to(user → node)` that names the node's one
    /// responsible steward and is admitted through the single-owner gate
    /// ([`check_single_node_owner_admission`](crate::federation::admission::check_single_node_owner_admission)):
    /// a second DISTINCT owner is rejected. `None` (the default) builds the
    /// general multi-parent `delegates_to` and is untouched by the gate. Any
    /// other purpose value is treated as a general delegation.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn grant_delegation(
        &self,
        signer: &crate::signing::LocalSigner,
        delegate_key_id: &str,
        scopes: Vec<String>,
        sub_delegation: bool,
        delegation_purpose: Option<&str>,
    ) -> Result<String, crate::federation::Error> {
        let envelope = match delegation_purpose {
            // The owner-binding sub-relation (CC 3.2): single-valued ownership,
            // gated by check_single_node_owner_admission. `sub_delegation` is
            // ignored (an owner-binding is a leaf, never a deputization).
            Some(p) if p == crate::federation::types::owner_binding::PURPOSE => {
                crate::federation::owner_binding_delegates_to_envelope(delegate_key_id, &scopes)
            }
            _ => crate::federation::delegates_to_envelope(delegate_key_id, &scopes, sub_delegation),
        };
        let mut input = crate::federation::EmitAttestationInput::with_envelope(
            crate::federation::types::attestation_type::DELEGATES_TO,
            envelope,
        );
        // The edge is keyed by its RECIPIENT: the §11.10 duty walk + the
        // `is_steward_bound` retraction bucketing both match a delegation /
        // its later `withdraws` by `attested_key_id`, so a `delegates_to`
        // MUST name the delegate there (not the self-attestation default).
        input.attested_key_id = Some(delegate_key_id.to_owned());
        self.emit_attestation(signer, input).await
    }

    /// v9.3.0 (CIRISPersist#249, CC 4.4.3.4.3 steward-binding) — bind a node /
    /// agent occurrence to its steward by granting it **`infra:*`-only**
    /// scopes. A [`Self::grant_delegation`] specialization that carries ONLY
    /// server-class (`infra:*`) authority, so it passes the CC 4.4.3.4.3
    /// node-agency gate even when `node_or_agent_key_id` resolves to a
    /// node-ONLY identity (the gate rejects any non-`infra:*` token on such
    /// a key). `sub_delegation` is `false` — an steward-binding is a leaf
    /// authorization, not a deputization. Returns the `attestation_id`.
    ///
    /// `infra_scopes` SHOULD be drawn from
    /// [`delegation_scope`](crate::federation::types::delegation_scope)'s
    /// `INFRA_*` constants; an empty set or any non-`infra:*` token will be
    /// rejected by the node-agency gate (`scopes_are_infra_only`) when the
    /// recipient is a node key. The steward-binding this writes is exactly the
    /// `delegates_to(U → k)` edge [`is_steward_bound`] reads.
    ///
    /// v13.2.0 (CIRISPersist#378, CC 3.2 rc2) — pass
    /// `delegation_purpose = Some(`[`owner_binding::PURPOSE`](crate::federation::types::owner_binding::PURPOSE)`)`
    /// to make this steward-binding the node's single-valued **owner-binding**
    /// (`infra:*`-only scope IS the owner-binding shape). It is then subject to
    /// the single-owner admission gate (a second distinct owner rejects) and
    /// resolvable via [`owner_of`](Self::owner_of). `None` (default) is a plain
    /// steward-binding.
    ///
    /// [`is_steward_bound`]: crate::federation::admission::is_steward_bound
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn steward_bind(
        &self,
        signer: &crate::signing::LocalSigner,
        node_or_agent_key_id: &str,
        infra_scopes: Vec<String>,
        delegation_purpose: Option<&str>,
    ) -> Result<String, crate::federation::Error> {
        self.grant_delegation(
            signer,
            node_or_agent_key_id,
            infra_scopes,
            false,
            delegation_purpose,
        )
        .await
    }

    /// v9.3.0 (CIRISPersist#249, CEG §11.10/§11.11 appointment) — appoint
    /// `moderator_key_id` a named moderator of `community_id` for `duty`
    /// (`moderate` / `takedown` / `review`). A [`Self::grant_delegation`]
    /// specialization stamping the single `duty` scope. After this,
    /// [`is_named_moderator`](crate::federation::admission::is_named_moderator)`(moderator, community, duty)`
    /// holds IFF the `signer` is in the community's authority set
    /// (founder / consensus signer per
    /// [`community_authority_set`](crate::federation::admission)) AND
    /// steward-bound — the appointment edge `signer → moderator` is the
    /// root-out-edge the §11.10 duty walk traverses.
    ///
    /// `community_id` rides the appointment **implicitly**: the §11.10 walk
    /// resolves the community → its authority roots, then walks `root →*
    /// moderator` over `duty`-scoped `delegates_to` edges — so the binding
    /// is "this steward-bound community authority delegated `duty` to the
    /// moderator", NOT a `community_id` field on the edge. The caller is
    /// therefore responsible for `signer` BEING a community authority (this
    /// helper emits the edge; admissibility is the authority-set membership,
    /// checked by the reader). `sub_delegation` is `true` so the appointee
    /// may further-deputize within the duty (§11.10 deputization). Returns
    /// the `attestation_id`.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn add_moderator(
        &self,
        signer: &crate::signing::LocalSigner,
        community_id: &str,
        moderator_key_id: &str,
        duty: &str,
    ) -> Result<String, crate::federation::Error> {
        // `community_id` is intentionally not stamped on the edge: the
        // §11.10 walk binds a moderator to a community by reaching it from
        // the community's authority roots, not by a field match. Bind it in
        // the debug log so the appointment is traceable.
        let _ = community_id;
        self.grant_delegation(signer, moderator_key_id, vec![duty.to_owned()], true, None)
            .await
    }

    /// v9.3.0 (CIRISPersist#249, CEG §3.2.3 / FSD-002 §2.2.3 withdraws) —
    /// revoke a prior `delegates_to` edge by emitting a `withdraws` against
    /// `target_attestation_id`. Composes [`Self::emit_attestation`] with
    /// `attestation_type = "withdraws"` + the
    /// [`withdraws_attestation_envelope`](crate::federation::withdraws_attestation_envelope)
    /// referencing the target edge, and `attested_key_id = delegate_key_id`
    /// — the recipient the original edge named, so the §11.10 walk's
    /// per-edge retraction bucketing (and `is_steward_bound`'s) recognize the
    /// retraction (both match a `withdraws` by `attested_key_id == k`).
    /// Returns the `attestation_id`.
    ///
    /// The signer MUST be the original granter (`attesting_key_id` of the
    /// target edge): the withdraws gate admits a producer self-revocation
    /// under rule 1. `delegate_key_id` is the key the revoked edge
    /// delegated TO.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn revoke_delegation(
        &self,
        signer: &crate::signing::LocalSigner,
        target_attestation_id: &str,
        delegate_key_id: &str,
    ) -> Result<String, crate::federation::Error> {
        let envelope = crate::federation::withdraws_attestation_envelope(
            target_attestation_id,
            crate::federation::types::attestation_type::DELEGATES_TO,
        );
        let mut input = crate::federation::EmitAttestationInput::with_envelope(
            crate::federation::types::attestation_type::WITHDRAWS,
            envelope,
        );
        // Key the retraction by the revoked edge's recipient so the duty
        // walk's `retracted` bucket (`attested_key_id`) invalidates it.
        input.attested_key_id = Some(delegate_key_id.to_owned());
        self.emit_attestation(signer, input).await
    }

    /// v9.3.0 (CIRISPersist#249, CEG §11.10) — remove a named moderator:
    /// emit a `withdraws` against the appointment `delegates_to` edge.
    /// Composes [`Self::revoke_delegation`] (same producer-self-revocation /
    /// `attested_key_id = moderator_key_id` retraction-bucketing shape).
    /// After this,
    /// [`is_named_moderator`](crate::federation::admission::is_named_moderator)`(moderator,
    /// community, duty)` no longer holds for an appointment the `signer`
    /// granted (the §11.10 walk skips the `withdraws`-revoked edge). Returns
    /// the `attestation_id`.
    ///
    /// `target_attestation_id` is the appointment edge
    /// ([`Self::add_moderator`]'s return). `community_id` / `duty` are
    /// accepted for call-site symmetry + traceability; the retraction is
    /// keyed structurally by the target edge + the moderator recipient, not
    /// by those fields.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn remove_moderator(
        &self,
        signer: &crate::signing::LocalSigner,
        community_id: &str,
        target_attestation_id: &str,
        moderator_key_id: &str,
        duty: &str,
    ) -> Result<String, crate::federation::Error> {
        let _ = (community_id, duty);
        self.revoke_delegation(signer, target_attestation_id, moderator_key_id)
            .await
    }

    /// v9.3.0 (CIRISPersist#249, CEG §11.10 EMIT) — file a moderation report
    /// as a `scores` attestation on the `moderation:{allegation_type}`
    /// dimension over content (`content_sha256`), naming `community_id`. The
    /// §11.10 EMIT-path convenience: composes [`Self::emit_attestation`]
    /// directly (the `scores` admission gate
    /// [`check_delegated_duty_scores_admission`](crate::federation::admission::check_delegated_duty_scores_admission)
    /// runs on `put_attestation` and admits IFF the signer is a `moderate`
    /// duty-holder over the target — a named moderator of the community, or
    /// reached by one via a live `moderate`-scoped chain). Returns the
    /// `attestation_id`.
    ///
    /// # cirisnode gating
    ///
    /// This producer convenience is **feature-free** (no `--features
    /// cirisnode`): it emits a federation-tier `scores` attestation through
    /// the always-present `emit_attestation` path — the
    /// `moderation:{allegation}` dimension IS the §11.10 federation-image of
    /// a moderation report (admission.rs `MODERATION_DIMENSION_PREFIX`), and
    /// the gate that admits it (`check_delegated_duty_scores_admission`)
    /// ships unconditionally on every backend's `put_attestation`. The
    /// `cirisnode`-gated surface (the `ModerationEvent` put-path / takedown
    /// handler) is the SEPARATE node-server ingest path; this is the pure
    /// attestation emit, so no feature gate is needed here.
    ///
    /// `duty` is currently always `moderate` for a `moderation:*` report;
    /// it is accepted for symmetry with the §11.10 duty vocabulary
    /// (`takedown` / `review` ride their own dimensions/paths).
    /// `content_sha256` is routing/advisory in the envelope — the gate
    /// resolves the content's SIGNED subjects from it; `community_id` names
    /// the moderating community.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn file_moderation(
        &self,
        signer: &crate::signing::LocalSigner,
        content_sha256: &str,
        community_id: &str,
        duty: &str,
        allegation_type: &str,
    ) -> Result<String, crate::federation::Error> {
        let _ = duty;
        // The §11.10 moderation-report image: a `scores` on the
        // `moderation:{allegation}:v1` dimension (the `:v1` segment
        // satisfies the §13.1 version gate; the allegation is the report
        // taxonomy axis). `content_sha256` + `community_id` ride the
        // envelope so the gate resolves the target's duty-holders.
        let dimension = format!(
            "{}{allegation_type}:v1",
            crate::federation::admission::MODERATION_DIMENSION_PREFIX
        );
        let envelope = serde_json::json!({
            "kind": "scores",
            "dimension": dimension,
            "score": 1.0,
            "confidence": 0.9,
            "content_sha256": content_sha256,
            "community_id": community_id,
        });
        let input = crate::federation::EmitAttestationInput::with_envelope(
            crate::federation::types::attestation_type::SCORES,
            envelope,
        );
        self.emit_attestation(signer, input).await
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
        // v10.1.0 (CIRISPersist#275 hardening) — the ingest pipeline carries
        // this into each scrubbed row's `scrub_key_id`, which FKs to
        // `federation_keys(key_id)` (the #247 floor). A registered node emits
        // under its DERIVED federation key_id (`<label>-<fp>`), NOT the bare
        // keystore alias — so the lookup key must be the derived id (matching
        // the `sweep_evictions_once_inner` / `emit_withdraws_attestation`
        // floor; this was a missed site). Falls back to the alias only if the
        // derived id can't be resolved (no signer pubkey), preserving prior
        // behaviour for Ed25519-only / no-pubkey signers.
        let key_id = self
            .local_derived_key_id()
            .await
            .unwrap_or_else(|_| self.signer.current_alias().to_owned());
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

        // v6.8.0 (CIRISPersist#149) — proactive disk-pressure gate on the
        // proxy-ACCEPT path. At the stop tier (or tighter) we refuse to
        // ACCEPT new federation-proxied content (attesting key neither
        // the local signer nor family). Local + family writes are NEVER
        // refused — local content is the operator's own data. Reads the
        // cached snapshot (no statvfs per write).
        let pressure = self.current_disk_pressure();
        if pressure.refuses_proxy_writes && !self.is_local_or_family_key(attesting_key_id) {
            return Err(crate::federation::BlobError::DiskPressureProxyRefused {
                operation: "accept",
                tier: pressure.tier.label(),
            });
        }

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

    /// v4.14.0 (CIRISPersist#152, CEG 0.18 §10.1.4) — write a
    /// `cohort_scope: self | family` blob through the **at-rest DEK
    /// cascade** (the [`CryptoTier::InvisibleEncrypted`](crate::federation::types::cohort_scope::CryptoTier::InvisibleEncrypted)
    /// tier).
    ///
    /// Unlike [`put_blob_signing`](Engine::put_blob_signing) (which takes
    /// a caller-computed SHA and stores plaintext), this takes the
    /// **plaintext body** and:
    ///
    /// 1. generates a fresh per-write DEK and AES-256-GCM-seals the body
    ///    into a self-describing ciphertext envelope (the format marker);
    /// 2. stores the envelope **structurally invisible** (no `holds_bytes`),
    ///    keyed on the ciphertext SHA-256 — the returned **at-rest content
    ///    address**;
    /// 3. records persist's content-master self-retention grant (so the
    ///    default-tier [`get_blob_for_viewer`](Engine::get_blob_for_viewer)
    ///    can recover the DEK — OQ-4);
    /// 4. wraps the DEK (`wrap_algorithm: v2`, X25519+ML-KEM-768) to every
    ///    **active** recipient occurrence — `list_identity_occurrences_active`
    ///    for `self`, every member identity's active occurrences for
    ///    `family` — **fail-secure excluding** any whose occurrence carries
    ///    no valid `encryption_pubkeys` (§10.1.4: never a plaintext / v1
    ///    fallback).
    ///
    /// `owner_or_family_key_id` is the identity key (self) or the
    /// family_key_id (family). Returns the
    /// [`CascadeResult`](crate::federation::at_rest_cascade::orchestrate::CascadeResult)
    /// — the at-rest SHA + the granted/excluded recipient split. Errors
    /// with [`BlobError::InvalidArgument`](crate::federation::BlobError::InvalidArgument)
    /// if `cohort_scope` is not `self`/`family` (the CommunityDek +
    /// Plaintext tiers go through the existing
    /// [`put_blob_signing_scoped`](crate::federation::BlobStorage::put_blob_signing_scoped)
    /// path — DEFERRED for this cut).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn put_blob_encrypted_self_family(
        &self,
        cohort_scope: &str,
        owner_or_family_key_id: &str,
        plaintext: &[u8],
        media_type: Option<&str>,
    ) -> Result<
        crate::federation::at_rest_cascade::orchestrate::CascadeResult,
        crate::federation::BlobError,
    > {
        use crate::federation::at_rest_cascade::orchestrate::encrypt_and_cascade;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(arc) => {
                encrypt_and_cascade(
                    arc.as_ref(),
                    cohort_scope,
                    owner_or_family_key_id,
                    plaintext,
                    media_type,
                )
                .await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(arc) => {
                encrypt_and_cascade(
                    arc.as_ref(),
                    cohort_scope,
                    owner_or_family_key_id,
                    plaintext,
                    media_type,
                )
                .await
            }
        }
    }

    /// v6.1.0 (CIRISPersist#161 Ask 2/4, CEG §11.7.1 / §10.1.4) — the
    /// **retroactive key-grant ADD re-wrap** for a **family** member-add.
    ///
    /// Run *after* `put_family` admits a new member: for every existing
    /// family-scope at-rest blob the cohort already holds grants on, recover
    /// the DEK (via persist's content-master self-retention grant), wrap it
    /// to the new member's active occurrences, and record the grants —
    /// making the pre-existing family content reachable to the newcomer.
    /// Idempotent (re-running adds nothing) and fail-secure (a keyless
    /// newcomer occurrence is excluded, never granted — surfaced as
    /// `hard_case:recipient_excluded`). Emits one
    /// `hard_case:family_membership_change` per newcomer.
    ///
    /// Does NOT retroactively revoke past grants of *removed* members —
    /// forward secrecy is automatic (the per-write fresh DEK means future
    /// writes simply exclude them). Returns the
    /// [`RekeyResult`](crate::federation::at_rest_cascade::orchestrate::RekeyResult).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn rekey_family_member_add(
        &self,
        family_key_id: &str,
        new_member_identity_key_id: &str,
    ) -> Result<
        crate::federation::at_rest_cascade::orchestrate::RekeyResult,
        crate::federation::BlobError,
    > {
        use crate::federation::at_rest_cascade::orchestrate::rekey_family_member_add;
        let now = chrono::Utc::now();
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(arc) => {
                rekey_family_member_add(
                    arc.as_ref(),
                    family_key_id,
                    new_member_identity_key_id,
                    now,
                )
                .await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(arc) => {
                rekey_family_member_add(
                    arc.as_ref(),
                    family_key_id,
                    new_member_identity_key_id,
                    now,
                )
                .await
            }
        }
    }

    /// #249 Cut G4 (§7) — forward-secrecy re-key on **community** member
    /// REMOVAL (the symmetric of [`rekey_family_member_add`](Engine::rekey_family_member_add)):
    /// records the community membership revocation, **bumps the community DEK
    /// epoch** (CC 4.4.3.2.2) so the next cascade mints a fresh DEK wrapped only
    /// to the remaining members, and emits the §9 `community_membership_change`
    /// removed event. Returns the new epoch.
    ///
    /// Community-only by construction: `self`/`family` use a fresh-per-write DEK,
    /// so a removed member is excluded from future writes inherently (no epoch
    /// to bump) — use [`Engine::revoke_member`](crate::federation::FederationDirectory::revoke_member)
    /// there (it still emits the §9 event).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn rekey_community_member_revoke(
        &self,
        community_key_id: &str,
        removed_identity_key_id: &str,
    ) -> Result<u64, crate::federation::BlobError> {
        use crate::federation::at_rest_cascade::orchestrate::rekey_community_member_revoke;
        let now = chrono::Utc::now();
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(arc) => {
                rekey_community_member_revoke(
                    arc.as_ref(),
                    community_key_id,
                    removed_identity_key_id,
                    now,
                )
                .await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(arc) => {
                rekey_community_member_revoke(
                    arc.as_ref(),
                    community_key_id,
                    removed_identity_key_id,
                    now,
                )
                .await
            }
        }
    }

    /// v6.1.0 (CIRISPersist#161 Ask 2/4, CEG §11.7.1 / §10.1.4) — the
    /// retroactive ADD re-wrap for a **self** occurrence-add: a person
    /// admitting new device-occurrence(s) into their self-collective. Same
    /// idempotent + fail-secure contract as
    /// [`rekey_family_member_add`](Engine::rekey_family_member_add); the
    /// newcomers are `new_occurrence_key_ids`, the existing cohort is the
    /// identity's other active occurrences.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn rekey_self_occurrence_add(
        &self,
        identity_key_id: &str,
        new_occurrence_key_ids: &[String],
    ) -> Result<
        crate::federation::at_rest_cascade::orchestrate::RekeyResult,
        crate::federation::BlobError,
    > {
        use crate::federation::at_rest_cascade::orchestrate::rekey_self_occurrence_add;
        let now = chrono::Utc::now();
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(arc) => {
                rekey_self_occurrence_add(
                    arc.as_ref(),
                    identity_key_id,
                    new_occurrence_key_ids,
                    now,
                )
                .await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(arc) => {
                rekey_self_occurrence_add(
                    arc.as_ref(),
                    identity_key_id,
                    new_occurrence_key_ids,
                    now,
                )
                .await
            }
        }
    }

    /// v6.5.0 (CIRISPersist#183, CEG §8.1.12.7) — drive the full
    /// **"self at login"** flow: co-admit the app + agent occurrences of
    /// one user identity, cascade the Self DEK to both, partner +
    /// delegate, promote the delegation to the federation tier, and
    /// register reachability rows. Returns a [`SelfAtLoginOutcome`]
    /// summarizing what landed.
    ///
    /// **Precondition** (upstream of this call): the user's identity key
    /// and BOTH occurrence keys (app + agent) already exist as
    /// `federation_keys` rows (key registration is the steward/keyring
    /// path, not this flow). This method binds occurrences over those
    /// keys, it does not mint them.
    ///
    /// What it composes (none of this is reinvented here):
    /// 1. **Co-admit** — `put_identity_occurrence` for the app
    ///    (`device_class: phone|laptop`) and the agent
    ///    (`device_class: agent`) under one `identity_key` (#153).
    /// 2. **Self-DEK cascade** — [`Engine::rekey_self_occurrence_add`]
    ///    (v6.2.0) retroactively key-grant-wraps every existing
    ///    `cohort_scope: self` DEK to both newcomers (§8.1.12.4), so the
    ///    app and agent both decrypt. Fail-secure: a newcomer with no
    ///    `encryption_pubkeys` is excluded, reported in the outcome.
    /// 3. **Partner** — a `consent:partnership_grant` (user side) +
    ///    `consent:partnership_accept` (agent side) sharing one
    ///    `bilateral_pair_id`, written local-tier via
    ///    `attestation_upsert_local`.
    /// 4. **Delegate** — a `delegates_to(user → agent occurrence)` with
    ///    scope `[act_on_behalf, message_io, network_presence,
    ///    sub_delegation]` (§8.1.12.7), written local-tier.
    /// 5. **Promote** — [`Engine::attestation_promote`] (#172) flips the
    ///    delegation to the federation tier + hybrid-signs it so peers
    ///    verify the agent's authority (§10.1.5 — "show up on network").
    /// 6. **Reachability** — a `transport_destination` row per occurrence
    ///    that supplied one (§5.6.8.8.1).
    ///
    /// The `identity_type` of the user's key is expected to carry at
    /// least `{user}` per §7.0.1 (a set encoded in the TEXT column via
    /// [`crate::federation::types::identity_type::join_set`]); this flow
    /// reads occurrences, it does not rewrite the identity key's type.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn self_at_login(
        &self,
        input: SelfAtLoginInput,
    ) -> Result<SelfAtLoginOutcome, crate::federation::Error> {
        use crate::federation::types::{attestation_type, cohort_scope, LocalAttestationInput};
        use crate::federation::{
            delegates_to_agent_envelope, partnership_accept_envelope, partnership_grant_envelope,
            IdentityOccurrence, TransportDestination,
        };

        let now = chrono::Utc::now();
        let directory = self.federation_directory();

        // (1) Co-admit both occurrences under the one identity key. These are
        // engine-internal, content-only (DEK-cascade KEX target, no reticulum
        // transport) writes on behalf of the LOCAL user — not peer-received, so
        // they take the trusted-local path (#418 ask 4 grandfather-local), NOT
        // the signature gate (which requires a transport binding they lack).
        for occ in [&input.app, &input.agent] {
            let row = IdentityOccurrence {
                identity_key_id: input.identity_key_id.clone(),
                occurrence_key_id: occ.occurrence_key_id.clone(),
                device_class: occ.device_class.clone(),
                hardware_attestation: occ.hardware_attestation.clone(),
                asserted_at: now,
                valid_until: None,
                encryption_pubkeys: occ.encryption_pubkeys.clone(),
                transport_binding: None,
                persist_row_hash: String::new(),
            };
            directory.put_identity_occurrence_local(row).await?;
        }

        // (2) Self-DEK cascade to both newcomers (§8.1.12.4). Composes
        // over the v6.2.0 retroactive re-key; fail-secure exclusions are
        // surfaced, not silently dropped.
        let newcomers = vec![
            input.app.occurrence_key_id.clone(),
            input.agent.occurrence_key_id.clone(),
        ];
        let rekey = self
            .rekey_self_occurrence_add(&input.identity_key_id, &newcomers)
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("self_at_login self-DEK cascade: {e}"))
            })?;

        // (3) Partner: bilateral grant (user) + accept (agent), sharing
        // one bilateral_pair_id. Local-tier, self-cohort.
        let grant_id = directory
            .attestation_upsert_local(LocalAttestationInput {
                attesting_key_id: input.identity_key_id.clone(),
                attested_key_id: Some(input.agent.occurrence_key_id.clone()),
                attestation_type: attestation_type::SCORES.to_owned(),
                weight: None,
                expires_at: None,
                attestation_envelope: partnership_grant_envelope(
                    &input.agent.occurrence_key_id,
                    &input.bilateral_pair_id,
                ),
                subject_key_ids: Vec::new(),
                cohort_scope: cohort_scope::SELF.to_owned(),
                scrub_signature_classical: None,
                scrub_signature_pqc: None,
            })
            .await?;
        let accept_id = directory
            .attestation_upsert_local(LocalAttestationInput {
                attesting_key_id: input.agent.occurrence_key_id.clone(),
                attested_key_id: Some(input.identity_key_id.clone()),
                attestation_type: attestation_type::SCORES.to_owned(),
                weight: None,
                expires_at: None,
                attestation_envelope: partnership_accept_envelope(
                    &input.identity_key_id,
                    &input.bilateral_pair_id,
                ),
                subject_key_ids: Vec::new(),
                cohort_scope: cohort_scope::SELF.to_owned(),
                scrub_signature_classical: None,
                scrub_signature_pqc: None,
            })
            .await?;

        // (4) Delegate: user → agent occurrence with the §8.1.12.7 scope
        // set. Written local-tier so (5) can promote it.
        let scope: Vec<&str> = input
            .delegation_scope
            .as_ref()
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_else(|| crate::federation::SELF_AT_LOGIN_DELEGATION_SCOPE.to_vec());
        let delegation_id = directory
            .attestation_upsert_local(LocalAttestationInput {
                attesting_key_id: input.identity_key_id.clone(),
                attested_key_id: Some(input.agent.occurrence_key_id.clone()),
                attestation_type: attestation_type::DELEGATES_TO.to_owned(),
                weight: None,
                expires_at: None,
                attestation_envelope: delegates_to_agent_envelope(
                    &input.agent.occurrence_key_id,
                    &input.bilateral_pair_id,
                    &scope,
                ),
                subject_key_ids: Vec::new(),
                cohort_scope: cohort_scope::SELF.to_owned(),
                scrub_signature_classical: None,
                scrub_signature_pqc: None,
            })
            .await?;

        // (5) Promote the delegation to the federation tier (§10.1.5 /
        // #172) so peers verify the agent's authority.
        let delegation_promoted = self.attestation_promote(&delegation_id).await?;

        // (6) Reachability: a transport_destination per occurrence that
        // supplied one (§5.6.8.8.1).
        let mut transport_rows = 0usize;
        for occ in [&input.app, &input.agent] {
            for td in &occ.transport_destinations {
                directory
                    .put_transport_destination(&TransportDestination {
                        occurrence_key_id: occ.occurrence_key_id.clone(),
                        transport_kind: td.0.clone(),
                        destination: td.1.clone(),
                        asserted_at: now,
                        last_seen_at: Some(now),
                        // Self-at-login reachability tuple carries (kind, dest)
                        // only; the transport-tier Ed25519 (#397) + X25519 (#411)
                        // are published separately by edge on peer root.
                        transport_ed25519_pubkey_base64: None,
                        transport_x25519_pubkey_base64: None,
                        // The node registering its OWN occurrence → authoritative.
                        binding_provenance:
                            crate::federation::self_at_login::BindingProvenance::Rooted,
                    })
                    .await?;
                transport_rows += 1;
            }
        }

        Ok(SelfAtLoginOutcome {
            partnership_grant_id: grant_id,
            partnership_accept_id: accept_id,
            delegation_id,
            delegation_promoted,
            self_dek_granted: rekey.granted.len(),
            self_dek_excluded: rekey.excluded,
            transport_destinations_registered: transport_rows,
        })
    }

    /// v4.14.0 (CIRISPersist#152, CEG 0.18 §10.1.4) — the **default-tier**
    /// read for an at-rest self/family blob: recover the plaintext body
    /// for a granted `viewer_key_id`.
    ///
    /// Persist holds the DEK (OQ-4, default tier): it checks the viewer's
    /// grant (authorization), recovers the DEK via its own content-master
    /// self-retention grant, AES-GCM-decrypts the ciphertext envelope, and
    /// returns the plaintext. The zero-trust-of-host mode (return the
    /// wrapped DEK + ciphertext for in-enclave unwrap) is a LATER phase.
    ///
    /// - [`BlobError::NotGranted`](crate::federation::BlobError::NotGranted)
    ///   — the viewer holds no grant (non-recipient, revoked, or
    ///   fail-secure-excluded at write).
    /// - [`BlobError::NotHeld`](crate::federation::BlobError::NotHeld) —
    ///   the at-rest bytes are absent.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn get_blob_for_viewer(
        &self,
        at_rest_sha256: &[u8; 32],
        viewer_key_id: &str,
    ) -> Result<Vec<u8>, crate::federation::BlobError> {
        use crate::federation::at_rest_cascade::orchestrate::read_for_viewer;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(arc) => {
                read_for_viewer(arc.as_ref(), at_rest_sha256, viewer_key_id).await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(arc) => {
                read_for_viewer(arc.as_ref(), at_rest_sha256, viewer_key_id).await
            }
        }
    }

    /// v6.8.0 (CIRISPersist#149) — serve blob bytes to a federation
    /// PEER, with the proactive disk-pressure gate on the proxy-SERVE
    /// path. At the stop tier (or tighter) we refuse to SERVE
    /// federation-proxied content to peers while still serving local +
    /// family content.
    ///
    /// Proxy classification (the SAME local-truth rule the
    /// force-evict-proxy sweep uses): a blob is PROXY when NONE of its
    /// local `holds_bytes` attesters
    /// ([`list_local_holders`](crate::federation::BlobStorage::list_local_holders))
    /// is local-or-family. A blob with at least one local/family holder
    /// is protected (served even under pressure). A blob with NO local
    /// holders at all is treated as proxy (we relay it; shed first).
    ///
    /// On refusal returns
    /// [`BlobError::DiskPressureProxyRefused`](crate::federation::BlobError::DiskPressureProxyRefused)
    /// (`operation: "serve"`) — a PERMANENT signal: the peer should
    /// fetch from another holder. On the happy path returns the bytes
    /// via [`get_blob`](crate::federation::BlobStorage::get_blob)
    /// ([`BlobError::NotHeld`] when absent).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn serve_blob_to_peer(
        &self,
        sha256: &[u8; 32],
        _requesting_peer_key_id: &str,
    ) -> Result<crate::federation::BlobBody, crate::federation::BlobError> {
        use crate::federation::BlobStorage;

        let pressure = self.current_disk_pressure();
        if pressure.refuses_proxy_serves {
            // Classify: is this proxy content (no local/family holder)?
            let local_holders = self.list_local_holders(sha256).await?;
            let is_protected = local_holders.iter().any(|k| self.is_local_or_family_key(k));
            if !is_protected {
                return Err(crate::federation::BlobError::DiskPressureProxyRefused {
                    operation: "serve",
                    tier: pressure.tier.label(),
                });
            }
        }

        let body = match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(arc) => arc.get_blob(sha256).await?,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(arc) => arc.get_blob(sha256).await?,
        };
        body.ok_or_else(|| crate::federation::BlobError::NotHeld {
            sha256_hex: hex::encode(sha256),
        })
    }

    /// v6.8.0 (CIRISPersist#149) — local-truth holder query for a SHA
    /// (delegates to the backend's
    /// [`list_local_holders`](crate::federation::BlobStorage::list_local_holders)).
    /// Used by [`serve_blob_to_peer`](Self::serve_blob_to_peer) for the
    /// proxy-vs-local/family classification.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    async fn list_local_holders(
        &self,
        sha256: &[u8; 32],
    ) -> Result<Vec<String>, crate::federation::BlobError> {
        use crate::federation::BlobStorage;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(arc) => arc.list_local_holders(sha256).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(arc) => arc.list_local_holders(sha256).await,
        }
    }

    /// v5.4.0 (CIRISPersist#198, CEG 1.0 §5.6.8.8.2) — assemble this
    /// node's [`LocalIdentityAggregate`](crate::federation::LocalIdentityAggregate):
    /// a single-call snapshot of the federation hybrid identity across
    /// the three §5.6.8.8.2 keypair roles.
    ///
    /// - **Signing** (Ed25519 + ML-DSA-65) — from this Engine's local
    ///   signer. Ed25519 is required (an Engine with no local signer
    ///   errors); ML-DSA-65 is `Some` only when a PQC signer is wired.
    /// - **RET-transport** (X25519 + Ed25519) — **`None` in v1**. (#199):
    ///   populate from `engine.edge.transport_identity_pubkeys()` once
    ///   ciris-edge >= 2.1.0 is wired.
    /// - **Content-KEM** (X25519 + ML-KEM-768) — a freshly-minted,
    ///   persist-sealed keypair (NOT derived from the signing key —
    ///   §5.6.8.8.2), loaded via
    ///   [`load_or_init_content_kem_identity`](crate::federation::BlobStorage::load_or_init_content_kem_identity).
    ///
    /// The `identity_hash` is computed over the present role pubkeys; the
    /// `aggregate_version` is `1`; `evaluated_at_unix_ms` is now.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    /// v5.5.0 (CIRISPersist#199, CIRISEdge#65 v2.1.0) — the **RET-transport
    /// role** is supplied by the caller, not reached for: persist is the
    /// substrate and does not hold an edge handle (cohabitation runs
    /// edge→persist via `PyEdge::engine()` + persist's PyCapsule exporters).
    /// The cohabiting consumer reads `edge.transport_identity_pubkeys()` and
    /// passes the two classical pubkeys in; persist validates + hashes them
    /// into the single authoritative aggregate.
    ///
    /// `transport_x25519_b64` / `transport_ed25519_b64` are **both-or-neither**
    /// (32 raw bytes each, base64-standard). `None`/`None` ⇒ RET-transport
    /// stays absent (transport-less Edge). A §5.6.8.8.2 key-separation guard
    /// rejects a transport x25519 that equals the content-KEM x25519 (the
    /// wire-checkable #71-C4 reuse case).
    pub async fn local_identity_aggregate(
        &self,
        transport_x25519_b64: Option<String>,
        transport_ed25519_b64: Option<String>,
    ) -> Result<crate::federation::LocalIdentityAggregate, crate::federation::BlobError> {
        use crate::federation::blobs::BlobStorage;
        use crate::federation::LocalIdentityAggregate;

        // ── Signing role — Ed25519 required, ML-DSA-65 optional. ──
        // v7.1.0 (CIRISPersist#223): an Engine built with
        // `with_hardware_signer` (classical-only) has `local_signer: None`
        // — the signing key is the sealed `Arc<dyn HardwareSigner>` reachable
        // via `self.signer`. Fall back to it so a hardware-custodied node can
        // still produce its six-key aggregate (CIRISServer's `/v1/identity`)
        // instead of erroring. The Ed25519 pubkey is read from the seal (never
        // the private key); a classical-only HW signer carries no ML-DSA half.
        // (A `with_hardware_signer_hybrid` engine populates `local_signer`, so
        // it takes the `Some` arm and surfaces its PQC half — #224.)
        let (key_id, pqc_key_id, ed25519_pubkey_b64, ml_dsa_65_pubkey_b64) = match self
            .local_signer
            .as_ref()
        {
            Some(signer) => (
                signer.key_id().to_string(),
                signer.pqc_key_id().map(str::to_owned),
                signer.public_key_b64(),
                signer.pqc_public_key_b64().await.map_err(|e| {
                    crate::federation::BlobError::Backend(format!("ml-dsa-65 pubkey: {e}"))
                })?,
            ),
            None => {
                use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
                let hw = &self.signer;
                let pk = hw.public_key().await.map_err(|e| {
                    crate::federation::BlobError::Backend(format!("hardware ed25519 pubkey: {e}"))
                })?;
                (hw.current_alias().to_string(), None, B64.encode(&pk), None)
            }
        };

        // ── Content-KEM role — persist-minted + sealed (stable). ──
        let content = match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(arc) => arc.load_or_init_content_kem_identity().await?,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(arc) => arc.load_or_init_content_kem_identity().await?,
        };

        // ── RET-transport role — caller-supplied (#199), validated. ──
        let (reticulum_x25519_pubkey_b64, reticulum_ed25519_pubkey_b64) =
            crate::federation::identity_aggregate::validate_transport_pubkeys(
                transport_x25519_b64,
                transport_ed25519_b64,
                &content.x25519_pubkey_b64,
            )?;

        let now_ms = chrono::Utc::now().timestamp_millis();
        Ok(LocalIdentityAggregate::assemble(
            key_id,
            pqc_key_id,
            ed25519_pubkey_b64,
            ml_dsa_65_pubkey_b64,
            reticulum_x25519_pubkey_b64,
            reticulum_ed25519_pubkey_b64,
            Some(content.x25519_pubkey_b64),
            Some(content.ml_kem_768_pubkey_b64),
            now_ms,
        ))
    }

    /// v3.5.0 (CIRISPersist#125) — Engine-facade for
    /// [`BlobStorage::list_held_by`](crate::federation::BlobStorage::list_held_by).
    /// Returns the full SHA-256 of every blob this Engine has a
    /// currently-live `holds_bytes:sha256:*` attestation for from
    /// `attesting_key_id` — the inverse of
    /// [`list_holders`](crate::federation::BlobStorage::list_holders).
    ///
    /// See the trait method's doc-comment for the filter discipline
    /// (TTL window, withdraws filter, full-SHA recovery from the
    /// envelope's `evidence_refs`).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn list_held_by(
        &self,
        attesting_key_id: &str,
    ) -> Result<Vec<[u8; 32]>, crate::federation::BlobError> {
        use crate::federation::BlobStorage;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(arc) => arc.list_held_by(attesting_key_id).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(arc) => arc.list_held_by(attesting_key_id).await,
        }
    }

    /// v3.5.0 (CIRISPersist#125) — Engine-facade for
    /// [`BlobStorage::evict_actor`](crate::federation::BlobStorage::evict_actor).
    /// Sources the signer from `self.signer()` and delegates to the
    /// backend's trait impl.
    ///
    /// See the trait method's doc-comment for the fail-honest contract
    /// and race-tolerance posture; see
    /// [`crate::federation::EvictActorReport`] for the return shape.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn evict_actor(
        &self,
        attesting_key_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::federation::EvictActorReport, crate::federation::BlobError> {
        use crate::federation::BlobStorage;
        // v9.0.0 (#237, CC 5.3.2.4.3.1) — eviction emits federation-tier
        // `withdraws`, which the ingest gate requires be hybrid-signed.
        // That needs the LocalSigner (PQC-capable); an Engine built via
        // `from_shared` (cohabitation accessor, no LocalSigner) cannot
        // emit a conformant withdraws — surface that honestly rather than
        // silently skip or downgrade.
        let signer = self.local_signer.as_ref().ok_or_else(|| {
            crate::federation::BlobError::Backend(
                "evict_actor requires a LocalSigner to hybrid-sign federation-tier withdraws \
                 (CC 5.3.2.4.3.1); this Engine has none (constructed via from_shared)"
                    .to_string(),
            )
        })?;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(arc) => arc.evict_actor(attesting_key_id, signer, now).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(arc) => arc.evict_actor(attesting_key_id, signer, now).await,
        }
    }

    /// v9.1.0 (CC 1.13.3 / FSD §2.4, CIRISPersist#243) — Engine-facade for
    /// [`BlobStorage::put_scope_blob`](crate::federation::BlobStorage::put_scope_blob):
    /// admit one caller-pre-encrypted (XChaCha20-Poly1305) RaptorQ symbol
    /// addressed by `(record_id, symbol_index)`. Persist never
    /// encrypts/decrypts; it stores opaque ciphertext only. See the trait
    /// method's doc for the first-write-wins idempotency contract and the
    /// opaque-holder property.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn put_scope_blob(
        &self,
        record_id: [u8; 32],
        symbol_index: u16,
        nonce: [u8; 24],
        ciphertext: Vec<u8>,
        tag: [u8; 16],
        group_dek_ref: crate::federation::GroupDekRef,
    ) -> Result<(), crate::federation::BlobError> {
        use crate::federation::BlobStorage;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(arc) => {
                arc.put_scope_blob(
                    record_id,
                    symbol_index,
                    nonce,
                    ciphertext,
                    tag,
                    group_dek_ref,
                )
                .await
            }
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(arc) => {
                arc.put_scope_blob(
                    record_id,
                    symbol_index,
                    nonce,
                    ciphertext,
                    tag,
                    group_dek_ref,
                )
                .await
            }
        }
    }

    /// v9.1.0 (FSD §2.4, CIRISPersist#243) — Engine-facade for
    /// [`BlobStorage::get_scope_blob`](crate::federation::BlobStorage::get_scope_blob):
    /// read one scope-blob symbol back by `(record_id, symbol_index)`, or
    /// `None` if absent. Bumps the row's `last_accessed_at` (the LRU
    /// signal). Bytes round-trip exactly what `put_scope_blob` admitted.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn get_scope_blob(
        &self,
        record_id: [u8; 32],
        symbol_index: u16,
    ) -> Result<Option<crate::federation::ScopeBlobSymbol>, crate::federation::BlobError> {
        use crate::federation::BlobStorage;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(arc) => arc.get_scope_blob(record_id, symbol_index).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(arc) => arc.get_scope_blob(record_id, symbol_index).await,
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

    /// v11.5.0 (CIRISPersist#306, CC 3.3.12 / CC 1.15.6) — the **I1 age
    /// band** of `key_id`, resolved from its incoming age attestations
    /// (witness `age_assurance:*` OUTRANKS self-declared `age_self_declared:*`;
    /// a self-declared adult is ignored — the one-way ratchet). A key with no
    /// usable age proof resolves to [`crate::federation::age::AgeBand::Unknown`]
    /// (presumption of sovereignty). See [`crate::federation::age::age_band`].
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn age_band(
        &self,
        key_id: &str,
    ) -> Result<crate::federation::age::AgeBand, crate::federation::Error> {
        crate::federation::age::age_band(&*self.federation_directory(), key_id).await
    }

    // ── #249 Cut B ── CEG-native graph DX enumerators + community-roster
    //    grow, surfaced as Engine convenience wrappers over the
    //    `federation_directory()` reader + the admission free functions.

    /// #249 Cut B — active member roster of `community_key_id` (`members`
    /// MINUS effective membership revocations). See
    /// [`FederationDirectory::active_community_members`](crate::federation::FederationDirectory::active_community_members).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn active_community_members(
        &self,
        community_key_id: &str,
    ) -> Result<Vec<crate::federation::types::CommunityMember>, crate::federation::Error> {
        self.federation_directory()
            .active_community_members(community_key_id)
            .await
    }

    /// #249 Cut B — active member roster of `family_key_id`. See
    /// [`FederationDirectory::active_family_members`](crate::federation::FederationDirectory::active_family_members).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn active_family_members(
        &self,
        family_key_id: &str,
    ) -> Result<Vec<crate::federation::types::FamilyMember>, crate::federation::Error> {
        self.federation_directory()
            .active_family_members(family_key_id)
            .await
    }

    /// #249 Cut B — incrementally add `member` to `community_key_id`'s
    /// roster (idempotent on `member.key_id`). See
    /// [`FederationDirectory::add_community_member`](crate::federation::FederationDirectory::add_community_member).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn add_community_member(
        &self,
        community_key_id: &str,
        member: crate::federation::types::CommunityMember,
    ) -> Result<bool, crate::federation::Error> {
        self.federation_directory()
            .add_community_member(community_key_id, member)
            .await
    }

    /// #249 Cut B — the FULL named-moderator set of `community_key_id` for
    /// `duty` (authority roots ∪ duty-scoped delegates). See
    /// [`admission::moderators_of`](crate::federation::admission::moderators_of).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn moderators_of(
        &self,
        community_key_id: &str,
        duty: &str,
    ) -> Result<Vec<String>, crate::federation::Error> {
        crate::federation::admission::moderators_of(
            self.federation_directory().as_ref(),
            community_key_id,
            duty,
        )
        .await
    }

    /// #249 Cut B — the `user`-role key(s) that steward-bind `key_id`. See
    /// [`admission::steward_bindings_of`](crate::federation::admission::steward_bindings_of).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn steward_bindings_of(
        &self,
        key_id: &str,
    ) -> Result<Vec<String>, crate::federation::Error> {
        crate::federation::admission::steward_bindings_of(
            self.federation_directory().as_ref(),
            key_id,
        )
        .await
    }

    /// CIRISPersist#299 — the **outbound** steward-binding reader: the nodes
    /// `steward_user_key_id` owns. The exact inverse of [`Self::steward_bindings_of`]
    /// (`n ∈ nodes_stewarded_by(U)` ⟺ `U ∈ steward_bindings_of(n)`), so "list the
    /// nodes I own" (the client node-switcher) is one substrate call instead of
    /// a consumer-side scan-then-confirm. Inherits the
    /// liveness/`withdraws`-`recants`-retraction/live-`user`-role-anchor logic
    /// verbatim (membership is decided by `steward_bindings_of` itself). See
    /// [`crate::federation::admission::nodes_stewarded_by`].
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn nodes_stewarded_by(
        &self,
        steward_user_key_id: &str,
    ) -> Result<Vec<String>, crate::federation::Error> {
        crate::federation::admission::nodes_stewarded_by(
            self.federation_directory().as_ref(),
            steward_user_key_id,
        )
        .await
    }

    /// v13.2.0 (CIRISPersist#378, CC 3.2 rc2 single-owner) — the **single
    /// responsible owner** of `node_key_id`, purpose-filtered to the
    /// owner-binding sub-relation → **at most one** (`Some(owner)`), or `None`
    /// when the node is unowned. This is the resolver consumers MUST use for
    /// "who owns this node" — NEVER the purpose-conflating
    /// [`steward_bindings_of`](Self::steward_bindings_of) /
    /// [`delegations_to`](Self::delegations_to) readers, which return every
    /// `delegates_to` granter (cardinality > 1, the anti-pattern CC 3.2
    /// forbids). A pre-gate ambiguous state (two live owners from before the
    /// single-owner gate) resolves **fail-closed** with
    /// [`Error::AmbiguousNodeOwner`](crate::federation::Error::AmbiguousNodeOwner).
    /// See [`admission::owner_of`](crate::federation::admission::owner_of).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn owner_of(
        &self,
        node_key_id: &str,
    ) -> Result<Option<String>, crate::federation::Error> {
        crate::federation::admission::owner_of(self.federation_directory().as_ref(), node_key_id)
            .await
    }

    /// #249 Cut B — inbound `delegates_to` edges naming `key_id` as
    /// recipient. See
    /// [`FederationDirectory::delegations_to`](crate::federation::FederationDirectory::delegations_to).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn delegations_to(
        &self,
        key_id: &str,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        self.federation_directory().delegations_to(key_id).await
    }

    /// #249 Cut B — the general scoped-delegation reachability primitive:
    /// does `issuer_key_id` reach `target_key_id` via a `delegates_to` chain
    /// where every edge carries `scope` (⊆-attenuation + sub_delegation +
    /// withdraws-aware + depth-capped, §11.10)? See
    /// [`admission::reachable_under_scope`](crate::federation::admission::reachable_under_scope).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn reachable_under_scope(
        &self,
        issuer_key_id: &str,
        target_key_id: &str,
        scope: &str,
        max_depth: usize,
    ) -> Result<bool, crate::federation::Error> {
        crate::federation::admission::reachable_under_scope(
            self.federation_directory().as_ref(),
            issuer_key_id,
            target_key_id,
            scope,
            max_depth,
        )
        .await
    }

    /// v10.0.0 (CIRISPersist#272) — the refusal-reason companion of
    /// [`reachable_under_scope`](Self::reachable_under_scope): the same
    /// scope-bearing `delegates_to` walk, returning a typed
    /// [`ReachabilityVerdict`](crate::federation::ReachabilityVerdict) so
    /// callers route a distinct forensic audit-trail entry per refusal
    /// reason. See
    /// [`admission::reachable_under_scope_with_reasons`](crate::federation::admission::reachable_under_scope_with_reasons).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn reachable_under_scope_with_reasons(
        &self,
        issuer_key_id: &str,
        target_key_id: &str,
        scope: &str,
        max_depth: usize,
    ) -> Result<crate::federation::ReachabilityVerdict, crate::federation::Error> {
        crate::federation::admission::reachable_under_scope_with_reasons(
            self.federation_directory().as_ref(),
            issuer_key_id,
            target_key_id,
            scope,
            max_depth,
        )
        .await
    }

    /// #249 Cut B — the steward-binding PATH (`user → … → key_id`, anchor-
    /// first) for audit. See
    /// [`admission::steward_binding_chain`](crate::federation::admission::steward_binding_chain).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn steward_binding_chain(
        &self,
        key_id: &str,
    ) -> Result<Vec<String>, crate::federation::Error> {
        crate::federation::admission::steward_binding_chain(
            self.federation_directory().as_ref(),
            key_id,
        )
        .await
    }

    /// v8.8.0 (CIRISPersist#234, CEG 1.0-RC28/RC29 §5.6.8.15) — the
    /// **single canonical federation-key registration admission gate**.
    ///
    /// §5.6.8.15 (`consent:replication`) pins the normative-honesty
    /// layering for out-of-group peering: the substrate gate that lets
    /// peer **P**'s corpus admit granting node **G**'s replicated rows
    /// is **G's key existing in P's `federation_keys`** (registration),
    /// plus the §7 reserved-prefix identity rules — *not* the
    /// `consent:replication` attestation (that is the auditable,
    /// revocable governance record of intent, and stays CEG-side). So
    /// the load-bearing security check for every peering is this one
    /// operation. This method is the one canonical implementation
    /// CIRISServer / CIRISStatus call rather than re-derive (the DRY
    /// fix; previously `src/peer.rs` and `src/ceg.rs` reached the gate
    /// from two sides independently).
    ///
    /// Order (fail-secure — BEFORE any store):
    /// 1. [`verify_key_registration`](crate::federation::verify_key_registration)
    ///    — hybrid-verify (Ed25519 + ML-DSA-65, `Strict`) the scrub
    ///    signature over `ceg_produce_canonicalize(registration_envelope)`
    ///    against **`scrub_key_id`'s** pubkeys (self-attested
    ///    proof-of-possession when `scrub_key_id == key_id`; resolved
    ///    from the directory for a granting-authority signature),
    ///    cross-checking `original_content_hash`. ANY failure ⇒ typed
    ///    [`Error`](crate::federation::Error) and the row is NOT stored.
    /// 2. On success ⇒ [`put_public_key`](crate::federation::FederationDirectory::put_public_key),
    ///    which keeps its own `accord_holder` hardware-attestation gate
    ///    (§7.2 / §9.1) and `algorithm == hybrid` check — this method
    ///    composes them, it does not weaken or duplicate them.
    ///
    /// Unknown / unverified ⇒ not registered ⇒ that peer's replicated
    /// rows are not admitted. That is the whole point of §5.6.8.15.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn register_federation_key(
        &self,
        record: crate::federation::SignedKeyRecord,
    ) -> Result<(), crate::federation::Error> {
        let directory = self.federation_directory();
        // Verify BEFORE store. A reject returns here and never reaches
        // put_public_key, so a rejected registration leaves no trace.
        crate::federation::verify_key_registration(directory.as_ref(), &record.record).await?;
        // Verified — store. put_public_key re-applies the accord_holder
        // hardware-attestation gate + algorithm check + persist_row_hash
        // + idempotent insert; we deliberately keep those there.
        directory.put_public_key(record).await
    }

    /// v12.2.0 (CIRISPersist#351) — adopt-scrub-**upgrade**: replace this
    /// node's **self-signed** own-key row with the accord-anchor-**scrubbed**
    /// record (same `key_id`, same pubkey) so it can root against the seeded
    /// A1/B1/C1 anchor. The in-place seed's missing primitive:
    /// `register_federation_key` is `ON CONFLICT DO NOTHING`, so the boot-time
    /// self-signed row is otherwise sticky and no peer can root it.
    ///
    /// Verifies the incoming scrub-signature first (same
    /// [`verify_key_registration`](crate::federation::verify_key_registration)
    /// gate as `register_federation_key` — granting-authority resolves the
    /// scrubber's pubkeys from the directory), THEN applies the backend's
    /// monotonic gated UPDATE (self-signed → anchored only; pubkey change and
    /// anchored→self downgrade refused; re-applying the same record is
    /// idempotent — see [`AdoptScrubOutcome`](crate::federation::register::AdoptScrubOutcome)).
    /// Fail-secure: a reject never mutates the row.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn adopt_scrub_upgrade(
        &self,
        record: crate::federation::SignedKeyRecord,
    ) -> Result<crate::federation::register::AdoptScrubOutcome, crate::federation::Error> {
        let directory = self.federation_directory();
        crate::federation::verify_key_registration(directory.as_ref(), &record.record).await?;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.adopt_scrub_upgrade(record).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.adopt_scrub_upgrade(record).await,
        }
    }

    /// v12.7.0 (CIRISPersist#371) — **upgrade-aware replicated Key-plane
    /// apply**: the anti-entropy apply the edge replication bridge routes
    /// `apply_key` to instead of raw
    /// [`put_public_key`](crate::federation::FederationDirectory::put_public_key)
    /// (which keeps its insert-only semantics for direct
    /// claim/peering/registration — no behavior change there). With this,
    /// an accord-holder-scrubbed record for a node the receiver already
    /// holds a **self-signed** row for auto-upgrades that row in place, so
    /// the genesis-mesh seed becomes pure owned-node replication and stale
    /// self-signed copies on sibling nodes heal — no per-node
    /// `adopt-scrubbed` endpoint call ([`adopt_scrub_upgrade`](Self::adopt_scrub_upgrade)
    /// itself is unchanged and remains available; consumers retire the
    /// endpoint separately).
    ///
    /// Decision table + gate composition live in the shared
    /// [`plan_replicated_key_apply`](crate::federation::register::plan_replicated_key_apply):
    /// fresh `key_id` ⇒ insert with every `put_public_key` admission gate
    /// intact; existing self-signed row + incoming anchor-scrubbed record ⇒
    /// upgrade iff same hybrid pubkeys AND the scrub verifies through the
    /// [`verify_key_registration`](crate::federation::verify_key_registration)
    /// `Strict` gate (scrubber resolved from the directory — the seeded
    /// HUMANITY_ACCORD anchor) AND
    /// [`owner_of`](crate::federation::admission::owner_of) resolves exactly
    /// one live owner (v12.6.0; unowned/ambiguous ⇒ fail-closed);
    /// byte-identical ⇒ `Unchanged`; anything else (downgrade, re-scrub,
    /// pubkey swap, conflicting version) ⇒ `Refused`, row untouched.
    ///
    /// Unlike [`adopt_scrub_upgrade`](Self::adopt_scrub_upgrade)'s
    /// Engine-layer verify split, the verification is INSIDE the backend
    /// method (it only binds on the upgrade transition — a fresh insert
    /// keeps `put_public_key`'s as-today semantics), so no caller can reach
    /// the upgrade unverified. This wrapper is pure dispatch.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn apply_replicated_key_record(
        &self,
        record: crate::federation::SignedKeyRecord,
    ) -> Result<crate::federation::register::ReplicatedKeyOutcome, crate::federation::Error> {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.apply_replicated_key_record(record).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.apply_replicated_key_record(record).await,
        }
    }

    /// v12.7.0 (CIRISPersist#372, CC 3.4.7.1) — is `key_id` a **canonical /
    /// founding bootstrap server**? True iff its `federation_keys` row's
    /// `identity_type` set contains `canonical`. Because the admission gate
    /// [`check_canonical_role_admission`](crate::federation::check_canonical_role_admission)
    /// only ever admits `canonical` on an anchor-scrub-conferred record, a
    /// `true` here means the node was conferred the role by a HUMANITY_ACCORD
    /// holder — it cannot be self-claimed. `false` for an unknown key or a
    /// non-canonical row.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn is_canonical(&self, key_id: &str) -> Result<bool, crate::federation::Error> {
        let directory = self.federation_directory();
        // v13.1.0 (CIRISPersist#377) — tombstone-aware: a WITHDRAWN canonical
        // reads `false` (the raw set-membership still carries the role token,
        // but the quorum revoked it). See
        // [`crate::federation::is_canonical_effective`].
        crate::federation::is_canonical_effective(directory.as_ref(), key_id).await
    }

    /// v12.7.0 (CIRISPersist#372, CC 3.4.7.1) — enumerate the **canonical /
    /// founding bootstrap servers**: all `federation_keys` rows whose
    /// `identity_type` set contains `canonical`, stable-sorted by `key_id`.
    /// Every returned row is (by the admission gate) anchor-scrub-conferred —
    /// none is self-claimed. Dispatches to the backend's inherent enumerator.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn list_canonical_servers(
        &self,
    ) -> Result<Vec<crate::federation::KeyRecord>, crate::federation::Error> {
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.list_canonical_servers().await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.list_canonical_servers().await,
        }
    }

    /// v13.1.0 (CIRISPersist#381) — the **accord-attested bootstrap dial set**:
    /// every [`TransportHint`](crate::federation::types::TransportHint) carried
    /// inside the signed `registration_envelope` of each `canonical` server,
    /// paired with the server `key_id` it reaches. This is the reachability
    /// plane a cold node uses to JOIN the mesh with zero config — sourced from
    /// the baked/replicated canonical records, not a hardcoded bootstrap-peers
    /// const (which ciris-server 0.5.81 retires). Hints are the genesis/default
    /// address; the mutable `TransportDestination` overlay wins at runtime.
    /// A canonical server with no envelope hint contributes nothing (the field
    /// is optional); consumers filter by `kind` (e.g. `ip` for the TCP entry).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn canonical_bootstrap_hints(
        &self,
    ) -> Result<Vec<(String, crate::federation::types::TransportHint)>, crate::federation::Error>
    {
        let servers = self.list_canonical_servers().await?;
        Ok(servers
            .into_iter()
            .flat_map(|r| {
                r.transport_hints()
                    .into_iter()
                    .map(move |h| (r.key_id.clone(), h))
            })
            .collect())
    }

    /// v13.1.0 (CIRISPersist#377, CC 3.4.7.1 / FSD Trust Root) — **withdraw**
    /// the `canonical` founding-server role from `key_id`. The DESTRUCTIVE
    /// counterpart of the monotonic add-canonical (#372): a durable,
    /// quorum-verified TOMBSTONE (V095) that
    /// [`check_canonical_role_admission`](crate::federation::check_canonical_role_admission)
    /// consults — so withdrawal defeats a re-add over anti-entropy
    /// ([`apply_replicated_key_record`](Self::apply_replicated_key_record))
    /// rather than being silently re-conferred.
    ///
    /// `proposal_digest` names a STORED accord live-quorum proposal (#302 /
    /// V091) whose payload commits to `(withdraw, key_id)`. Persist re-tallies
    /// ITS OWN cryptographically-verified `accord_participation` rows against the
    /// accord-holder roster (A1/B1/C1) at the **2-of-3 destructive threshold** —
    /// never a caller-supplied `AccordDecision.authorized` bool (which is
    /// unauthenticated and forgeable) — before recording the tombstone
    /// (verify-before-mutation, AV-9). Symmetric m-of-n by design (v13.2.0 /
    /// CIRISPersist#383): ADD now also requires ≥2-of-3 accord co-scrubs (the
    /// 1-of-N add path was retired as a first-strike weakness), and WITHDRAW
    /// keeps the 2-of-3 family quorum. Idempotent. After this,
    /// [`is_canonical`](Self::is_canonical) reads `false`.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn withdraw_canonical_role(
        &self,
        key_id: &str,
        proposal_digest: &str,
    ) -> Result<(), crate::federation::Error> {
        let directory = self.federation_directory();
        crate::federation::withdraw_canonical_role(directory.as_ref(), key_id, proposal_digest)
            .await
    }

    /// v13.1.0 (CIRISPersist#377, CC 3.4.7.1 / FSD Trust Root) — **supersede**
    /// (rotate) a canonical server: admit `new_record`'s successor key (the
    /// normal anchor-scrub add-gate runs) AND record `old_key_id`'s withdrawal
    /// with `superseded_by = new_key_id` (the old→new audit link).
    /// `proposal_digest` names a STORED accord proposal whose payload commits to
    /// the supersede `old_key_id → new_record.key_id`; persist re-tallies its own
    /// verified participations at the 2-of-3 destructive threshold
    /// (verify-before-mutation). The authority is verified first; the successor
    /// is admitted before the predecessor is tombstoned so the canonical set is
    /// never momentarily empty.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn supersede_canonical(
        &self,
        old_key_id: &str,
        new_record: crate::federation::SignedKeyRecord,
        proposal_digest: &str,
    ) -> Result<(), crate::federation::Error> {
        let directory = self.federation_directory();
        crate::federation::supersede_canonical(
            directory.as_ref(),
            old_key_id,
            new_record,
            proposal_digest,
        )
        .await
    }

    /// v13.1.0 (CIRISPersist#377) — enumerate the canonical-role withdrawal
    /// tombstones (V095), stable-sorted by `key_id` — the withdrawn-history view
    /// alongside [`list_canonical_servers`](Self::list_canonical_servers).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn list_canonical_withdrawals(
        &self,
    ) -> Result<Vec<crate::federation::CanonicalWithdrawal>, crate::federation::Error> {
        let directory = self.federation_directory();
        directory.list_canonical_withdrawals().await
    }

    /// v8.8.0 (CIRISPersist#234, CEG 1.0-RC28/RC29 §5.6.8.15) — the
    /// symmetric **deregister** path: the revocation teeth a withdrawn
    /// `consent:replication` relies on.
    ///
    /// §5.6.8.15 revocation (normative): on revoke, the granting node
    /// MUST cease replicating the named prefixes **and SHOULD
    /// deregister/expire P's directory authorization** — admission is
    /// key-rooted, so revocation has teeth only if the directory
    /// authorization is withdrawn here. This composes the existing
    /// revocation substrate
    /// ([`put_revocation`](crate::federation::FederationDirectory::put_revocation));
    /// it does NOT invent a parallel shape. A consumer applying its
    /// revocation policy on read (`revocations_for` + the row's
    /// `valid_until`) then ceases admitting the deregistered peer's
    /// rows.
    ///
    /// The submitted [`SignedRevocation`](crate::federation::SignedRevocation)
    /// is the same signed-row shape the directory already stores; the
    /// store path keeps its trust gate, region closed-set check, and
    /// anti-rollback monotonicity. (Time-boxed peering — a key's
    /// `valid_until` lapsing — needs no call here: it is honored on
    /// read by the consumer's freshness policy.)
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn deregister_federation_key(
        &self,
        revocation: crate::federation::SignedRevocation,
    ) -> Result<(), crate::federation::Error> {
        self.federation_directory().put_revocation(revocation).await
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

    /// v6.3.0 (CIRISPersist#135, Lane C) — Rust-public read facade over
    /// [`ReadEngine::list_attestations`](crate::ceg::ReadEngine::list_attestations).
    ///
    /// CIRISLensCore#29.1's content-class-misclassification detector
    /// reads quality / authenticity / production attestations against an
    /// admitted content row to catch "declared as `film` but lacks
    /// distributor + production-credits + festival attestations." The
    /// attestation *class* is the open-vocabulary
    /// [`AttestationFilter::dimension_prefixes`](crate::ceg::AttestationFilter)
    /// axis (`content_rating:*`, CEG §10.1.5.4); the *scope* is gated by
    /// `scope` against the row's `cohort_scope` (§4.3). Newest-first
    /// `(asserted_at, attestation_id)` DESC, cursor-paged.
    ///
    /// Thin dispatch over the [`BackendDispatch`] enum so co-resident
    /// Rust consumers (LensCore client-mode) don't `match` on the backend
    /// themselves — the read-side sibling of the PyO3
    /// `list_attestations` wrapper. Behaviour + ordering + scope gate
    /// match the per-backend [`ReadEngine`](crate::ceg::ReadEngine) impl.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn list_attestations(
        &self,
        filter: crate::ceg::AttestationFilter,
        cursor: Option<crate::ceg::AttestationCursor>,
        limit: i64,
        scope: crate::scope::CallerScope,
    ) -> Result<crate::ceg::AttestationListPage, crate::ceg::Error> {
        use crate::ceg::ReadEngine;
        match &self.backend {
            #[cfg(feature = "postgres")]
            BackendDispatch::Postgres(b) => b.list_attestations(filter, cursor, limit, scope).await,
            #[cfg(feature = "sqlite")]
            BackendDispatch::Sqlite(b) => b.list_attestations(filter, cursor, limit, scope).await,
        }
    }

    /// v6.3.0 (CIRISPersist#135, Lane C) — takedowns claimed against a
    /// given `target_content_sha256` (the target of the moderation
    /// claim), cursor-paged + filterable.
    ///
    /// CIRISLensCore#29.4's takedown-abuse detector reads per-target to
    /// catch "single claimant emitting many takedowns against one
    /// target" — set [`TakedownFilter::claimant_key_id`](crate::cirisnode::TakedownFilter)
    /// for the per-target × per-claimant slice. Composes over
    /// [`NodeCoreService::list_takedowns_for`](crate::cirisnode::NodeCoreService::list_takedowns_for)
    /// (the V054-indexed `media_content_sha256` read, already
    /// newest-first by `submitted_at DESC, contribution_id DESC`) then
    /// AND-applies the claimant + `[since, until)` window and advances a
    /// [`ListCursor`](crate::cirisnode::ListCursor) on the same
    /// `(submitted_at, contribution_id)` tuple — the deterministic
    /// ordering that storage query already emits, identical to
    /// `list_contributions`'s cursor shape.
    ///
    /// The claimant secondary key lives in the Contribution `payload`
    /// JSONB (`payload.claimant_key_id`), not an indexed column, so it is
    /// applied in the facade over the already-bounded per-target row set
    /// — avoiding a backend-divergent JSON-path predicate while keeping
    /// both backends behaviourally identical (parity is structural: the
    /// only SQL is the parametrized storage query).
    #[cfg(all(feature = "cirisnode", any(feature = "postgres", feature = "sqlite")))]
    pub async fn list_takedowns_for(
        &self,
        target_content_sha256: &str,
        filter: crate::cirisnode::TakedownFilter,
        cursor: Option<crate::cirisnode::ListCursor>,
        limit: i64,
    ) -> Result<crate::cirisnode::TakedownListPage, crate::cirisnode::Error> {
        use crate::cirisnode::NodeCoreService;
        media_validate_limit(limit)?;
        let svc = self.node_core_service();
        let rows = match &svc {
            #[cfg(feature = "postgres")]
            NodeCoreDispatch::Postgres(b) => b.list_takedowns_for(target_content_sha256).await?,
            #[cfg(feature = "sqlite")]
            NodeCoreDispatch::Sqlite(b) => b.list_takedowns_for(target_content_sha256).await?,
        };
        let claimant = filter.claimant_key_id.as_deref();
        let kept = rows.into_iter().filter(|env| {
            if let Some(c) = claimant {
                if env.payload.get("claimant_key_id").and_then(|v| v.as_str()) != Some(c) {
                    return false;
                }
            }
            media_in_window(env.submitted_at, filter.since, filter.until)
        });
        let (items, next_cursor) = media_apply_cursor(kept, cursor, limit)?;
        Ok(crate::cirisnode::TakedownListPage { items, next_cursor })
    }

    /// v6.3.0 (CIRISPersist#135, Lane C) — key-grants delivered to a
    /// given `recipient_key_id`, cursor-paged + filterable.
    ///
    /// CIRISLensCore#29.3's key_grant-abuse detector reads per-recipient
    /// to catch "single recipient receiving key_grants from many
    /// unrelated publishers in a short window" (sybil sample pattern) —
    /// set [`KeyGrantFilter::publisher_key_id`](crate::cirisnode::KeyGrantFilter)
    /// for the per-recipient × per-publisher slice. Composes over
    /// [`NodeCoreService::list_key_grants_for`](crate::cirisnode::NodeCoreService::list_key_grants_for)
    /// — or the two-axis
    /// [`list_key_grants_for_content`](crate::cirisnode::NodeCoreService::list_key_grants_for_content)
    /// V054 index path when [`KeyGrantFilter::content_sha256`](crate::cirisnode::KeyGrantFilter)
    /// pins a content hash — then AND-applies the publisher
    /// (`author_id`) + `[since, until)` window and advances a
    /// [`ListCursor`](crate::cirisnode::ListCursor) on the same
    /// `(submitted_at, contribution_id)` tuple the storage query emits.
    ///
    /// The publisher secondary key is the top-level Contribution
    /// `author_id`; the window filters `submitted_at` — both applied in
    /// the facade over the already-bounded per-recipient row set, so the
    /// only SQL is the parametrized storage query and both backends are
    /// behaviourally identical.
    #[cfg(all(feature = "cirisnode", any(feature = "postgres", feature = "sqlite")))]
    pub async fn list_key_grants_for(
        &self,
        recipient_key_id: &str,
        filter: crate::cirisnode::KeyGrantFilter,
        cursor: Option<crate::cirisnode::ListCursor>,
        limit: i64,
    ) -> Result<crate::cirisnode::KeyGrantListPage, crate::cirisnode::Error> {
        use crate::cirisnode::NodeCoreService;
        media_validate_limit(limit)?;
        let svc = self.node_core_service();
        let rows = match (&svc, filter.content_sha256.as_deref()) {
            #[cfg(feature = "postgres")]
            (NodeCoreDispatch::Postgres(b), Some(sha)) => {
                b.list_key_grants_for_content(sha, recipient_key_id).await?
            }
            #[cfg(feature = "postgres")]
            (NodeCoreDispatch::Postgres(b), None) => {
                b.list_key_grants_for(recipient_key_id).await?
            }
            #[cfg(feature = "sqlite")]
            (NodeCoreDispatch::Sqlite(b), Some(sha)) => {
                b.list_key_grants_for_content(sha, recipient_key_id).await?
            }
            #[cfg(feature = "sqlite")]
            (NodeCoreDispatch::Sqlite(b), None) => b.list_key_grants_for(recipient_key_id).await?,
        };
        let publisher = filter.publisher_key_id.as_deref();
        let kept = rows.into_iter().filter(|env| {
            if let Some(p) = publisher {
                if env.author_id != p {
                    return false;
                }
            }
            media_in_window(env.submitted_at, filter.since, filter.until)
        });
        let (items, next_cursor) = media_apply_cursor(kept, cursor, limit)?;
        Ok(crate::cirisnode::KeyGrantListPage { items, next_cursor })
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

// ─── Media-detector read-facade helpers (v6.3.0, CIRISPersist#135) ──
//
// Shared by [`Engine::list_takedowns_for`] / [`Engine::list_key_grants_for`].
// Both compose over the existing unpaged `NodeCoreService` listers
// (V054-indexed, newest-first `submitted_at DESC, contribution_id DESC`)
// and apply the filter + cursor in-facade. The cursor scheme mirrors
// `list_contributions` exactly: a `(submitted_at, contribution_id)`
// tuple, DESC, with `contribution_id` as the unique tiebreaker — so a
// page boundary is deterministic even when many rows share a
// `submitted_at`.

/// Bound the page `limit` to the same `[1, 10000]` range the
/// `list_contributions` / `list_votes` storage paths enforce.
#[cfg(all(feature = "cirisnode", any(feature = "postgres", feature = "sqlite")))]
pub(crate) fn media_validate_limit(limit: i64) -> Result<(), crate::cirisnode::Error> {
    if !(1..=10_000).contains(&limit) {
        return Err(crate::cirisnode::Error::InvalidArgument(format!(
            "limit must be in [1, 10000], got {limit}"
        )));
    }
    Ok(())
}

/// Half-open `[since, until)` window test on a row `submitted_at`.
#[cfg(all(feature = "cirisnode", any(feature = "postgres", feature = "sqlite")))]
pub(crate) fn media_in_window(
    ts: chrono::DateTime<chrono::Utc>,
    since: Option<chrono::DateTime<chrono::Utc>>,
    until: Option<chrono::DateTime<chrono::Utc>>,
) -> bool {
    if let Some(s) = since {
        if ts < s {
            return false;
        }
    }
    if let Some(u) = until {
        if ts >= u {
            return false;
        }
    }
    true
}

/// Advance the `(submitted_at, contribution_id)`-DESC cursor over an
/// already newest-first iterator, returning one capped page + the
/// `next_cursor` (`Some` iff the page filled to `limit`, mirroring
/// `list_contributions`). Validates the cursor version (`v1` only).
#[cfg(all(feature = "cirisnode", any(feature = "postgres", feature = "sqlite")))]
pub(crate) fn media_apply_cursor(
    rows: impl Iterator<Item = crate::cirisnode::ContributionEnvelope>,
    cursor: Option<crate::cirisnode::ListCursor>,
    limit: i64,
) -> Result<
    (
        Vec<crate::cirisnode::ContributionEnvelope>,
        Option<crate::cirisnode::ListCursor>,
    ),
    crate::cirisnode::Error,
> {
    // Cursor predicate: in DESC `(submitted_at, contribution_id)` order,
    // keep rows STRICTLY past the trailing row — i.e.
    // `submitted_at < last_ts OR (submitted_at == last_ts AND
    // contribution_id < last_id)`. Identical tuple-compare to the
    // `list_contributions` SQL `WHERE` clause.
    let after = match cursor {
        None => None,
        Some(c) => {
            if c.version != "v1" {
                return Err(crate::cirisnode::Error::InvalidArgument(format!(
                    "ListCursor version {} unsupported (expected v1)",
                    c.version
                )));
            }
            Some((c.last_ts, c.last_id))
        }
    };
    let mut items: Vec<crate::cirisnode::ContributionEnvelope> = Vec::new();
    let cap = limit as usize;
    for env in rows {
        if let Some((last_ts, last_id)) = &after {
            let past = env.submitted_at < *last_ts
                || (env.submitted_at == *last_ts && env.contribution_id < *last_id);
            if !past {
                continue;
            }
        }
        items.push(env);
        if items.len() == cap {
            break;
        }
    }
    let next_cursor = if items.len() == cap {
        items.last().map(|last| {
            crate::cirisnode::ListCursor::from_trailing(
                last.submitted_at,
                last.contribution_id.clone(),
            )
        })
    } else {
        None
    };
    Ok((items, next_cursor))
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
// `seed_genesis` is consumed inside the postgres / sqlite `if` blocks; in a
// no-backend build both arms are cfg'd out, so silence the unused-var lint there.
#[cfg_attr(
    not(any(feature = "postgres", feature = "sqlite")),
    allow(unused_variables)
)]
async fn build_backend(dsn: &str, seed_genesis: bool) -> Result<BackendDispatch, EngineError> {
    if dsn.starts_with("postgresql://") || dsn.starts_with("postgres://") {
        #[cfg(feature = "postgres")]
        {
            let pg = PostgresBackend::connect(dsn)
                .await
                .map_err(EngineError::Store)?;
            pg.run_migrations().await.map_err(EngineError::Store)?;
            // v13.3.1 (CIRISPersist#387) — the genesis seed is UNCONDITIONAL in
            // production (`seed_genesis == true`): the baked HUMANITY_ACCORD
            // holders + family ARE the immutable trust root. `seed_genesis ==
            // false` is reachable ONLY via the feature-gated
            // `with_signer_no_genesis_seed` (test-only, absent from prod builds),
            // so downstream integration tests can assemble a controllable
            // custom-holder family without the baked A1/B1/C1 + family blocking it.
            if seed_genesis {
                // v12.0.2 (#347) — first-boot-seed the HUMANITY_ACCORD holder
                // rooting-anchor rows (idempotent), then fail-secure verify.
                pg.seed_genesis_accord_holders(
                    crate::federation::genesis::accord_holder_genesis_records(),
                )
                .await
                .map_err(|e| EngineError::GenesisSeed(e.to_string()))?;
                // v13.4.1 (#392) — the SHARED seed routine (verify anchor →
                // family #386 → canonical #390), identical to the pyo3
                // `PyEngine::new` path so they can't drift.
                crate::federation::genesis::seed_family_and_canonical(&pg)
                    .await
                    .map_err(EngineError::GenesisSeed)?;
            }
            // v13.2.0 (CIRISPersist#383) — the 1-of-N canonical genesis seed
            // (#380, `ciris-canonical-1-d7bdeu223k` scrubbed by A1 alone) was
            // REMOVED: a single-anchor founding record is a first-strike
            // weakness (one captured accord key mints a rogue canonical). Now
            // that canonical ADD requires ≥2 distinct anchor scrubs (2-of-3),
            // a fresh node ships with an EMPTY canonical set until the operator
            // bakes the 2-of-3 replacement. The accord-holder rooting anchor
            // (A1/B1/C1) above is untouched.
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
            // v13.3.1 (CIRISPersist#387) — see the postgres leg: seed is
            // unconditional in prod; skipped only via the feature-gated
            // test-only `with_signer_no_genesis_seed`.
            if seed_genesis {
                // v12.0.2 (#347) — HUMANITY_ACCORD holder anchor rows, then verify.
                sq.seed_genesis_accord_holders(
                    crate::federation::genesis::accord_holder_genesis_records(),
                )
                .await
                .map_err(|e| EngineError::GenesisSeed(e.to_string()))?;
                // v13.4.1 (#392) — shared seed routine (verify anchor → family
                // #386 → canonical #390); identical to the pyo3 path.
                crate::federation::genesis::seed_family_and_canonical(&sq)
                    .await
                    .map_err(EngineError::GenesisSeed)?;
            }
            // v13.2.0 (CIRISPersist#383) — the 1-of-N canonical genesis seed
            // (#380, `ciris-canonical-1-d7bdeu223k` scrubbed by A1 alone) was
            // REMOVED: a single-anchor founding record is a first-strike
            // weakness (one captured accord key mints a rogue canonical). Now
            // that canonical ADD requires ≥2 distinct anchor scrubs (2-of-3),
            // a fresh node ships with an EMPTY canonical set until the operator
            // bakes the 2-of-3 replacement. The accord-holder rooting anchor
            // (A1/B1/C1) above is untouched.
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

    /// v7.1.0 (CIRISPersist#224) — composing the local signing identity
    /// failed during [`Engine::with_hardware_signer_hybrid`] (e.g. the
    /// hardware classical signer's public key could not be read, or it
    /// wasn't a 32-byte Ed25519 key).
    #[error("local signer: {0}")]
    LocalSigner(#[from] crate::signing::LocalSignerError),

    /// v12.0.2 (CIRISPersist#347) — the HUMANITY_ACCORD holder genesis
    /// rooting-anchor rows could not be seeded or verified at boot.
    /// **Fail-secure**: a node that cannot establish its constitutional
    /// rooting anchor (the pinned accord holders) must not come up — else
    /// it would silently root nothing (or, worse, honor a divergent anchor).
    #[error("genesis accord-holder seed: {0}")]
    GenesisSeed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    // The top-level `SigningKey` users are all under a backend cfg
    // (sqlite `test_signer_no_pqc`/`with_signer_*`; `any(sqlite,postgres)`
    // `pqc_signer`/`self_login_signer`). Gate the import to that union so
    // the no-backend `--features server` build (`-D warnings`) doesn't see
    // it as unused, while postgres-only / pyo3+postgres builds (the
    // pre-push hook is `postgres,pyo3,server`) still have it.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    use ed25519_dalek::SigningKey;

    fn test_signer() -> Arc<LocalSigner> {
        // v9.0.0 (CC 5.3.2.4.3.1) — a PQC-configured LocalSigner keyed on
        // "test-engine-steward" (deterministic; its Ed25519 + ML-DSA-65
        // pubkeys match what `sweeper_test_key` registers via
        // `tier_ingest::test_support::hybrid_pubkeys`). The eviction
        // sweeper now hybrid-signs federation-tier withdraws, which the
        // ingest gate requires; a non-PQC signer could not emit them.
        crate::federation::tier_ingest::test_support::local_signer("test-engine-steward")
    }

    /// A NON-PQC LocalSigner — for the tests that specifically exercise
    /// the `PqcNotConfigured` / hybrid-unavailable paths. (The default
    /// `test_signer` is PQC-configured as of v9.0.0 so the eviction
    /// sweeper can hybrid-sign federation-tier withdraws.)
    ///
    /// Gated to `sqlite` — its only callers are the `#[cfg(feature =
    /// "sqlite")]` `sign_hybrid_*` tests; without this gate it is dead
    /// code under the no-backend `--features server` CI build (which runs
    /// `-D warnings`), which is what broke the v9.0.0 darwin-aarch64 job.
    #[cfg(feature = "sqlite")]
    fn test_signer_no_pqc() -> Arc<LocalSigner> {
        Arc::new(LocalSigner::from_parts(
            SigningKey::from_bytes(&[0x7Au8; 32]),
            "test-engine-steward-nopqc".to_string(),
            None,
            None,
        ))
    }

    /// v3.4.0 (CIRISPersist#123) — engine carries a replication
    /// config and `sweep_evictions_once` is a no-op when the sweeper
    /// is inactive (default).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sweep_evictions_once_is_noop_without_budget() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct engine");
        // No replication config → noop.
        let report = engine.sweep_evictions_once().await.expect("sweep");
        assert!(report.is_noop());
        assert!(engine.replication_config().is_none());
    }

    /// v3.4.0 (CIRISPersist#123) — `with_replication_config` composes
    /// the knobs onto a fresh Engine; defaults still keep the sweeper
    /// inactive (`u64::MAX` budget).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn with_replication_config_propagates_knobs() {
        let cfg = crate::federation::ReplicationConfig {
            trust_threshold: 0.7,
            storage_budget_bytes: 1_000_000,
            ..Default::default()
        };
        let engine = Engine::with_replication_config(test_signer(), "sqlite::memory:", cfg)
            .await
            .expect("construct engine");
        let got = engine.replication_config().expect("config present");
        assert_eq!(got.trust_threshold, 0.7);
        assert_eq!(got.storage_budget_bytes, 1_000_000);
        assert!(got.sweeper_active());
        // Empty federation_blobs → bytes_before == 0, no rows evicted.
        let report = engine.sweep_evictions_once().await.expect("sweep");
        assert_eq!(report.bytes_before, 0);
        assert_eq!(report.bytes_after, 0);
        assert_eq!(report.rows_evicted, 0);
    }

    /// v3.4.0 (CIRISPersist#123) — Engine::set_admission_gate dispatches
    /// to the underlying backend gate accessor.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn engine_set_admission_gate_dispatches_to_backend() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct engine");
        let gate = crate::federation::AdmissionGate::new(
            std::sync::Arc::new(crate::federation::MemoryTrustScoring::new()),
            0.5,
            0,
        );
        engine.set_admission_gate(Some(gate));
        let sq = engine.sqlite_backend().expect("sqlite");
        assert!(sq.admission_gate().is_some());
        engine.set_admission_gate(None);
        assert!(sq.admission_gate().is_none());
    }

    /// v13.3.1 (CIRISPersist#387) — the TEST-ONLY seam: `with_signer_no_genesis_seed`
    /// yields a clean engine with **no baked trust root** — no accord holders
    /// (A1 absent), no entrenched family — so downstream integration tests can
    /// assemble a controllable custom-holder `humanity-accord` family. The
    /// default `with_signer` (prev test) DOES seed both. Gated behind the
    /// `test-genesis-seam` feature so it is absent from release builds.
    #[cfg(all(feature = "sqlite", feature = "test-genesis-seam"))]
    #[tokio::test]
    async fn no_genesis_seed_seam_yields_a_clean_engine() {
        let engine = Engine::with_signer_no_genesis_seed(test_signer(), "sqlite::memory:")
            .await
            .expect("construct no-seed engine");
        let dir = engine.federation_directory();
        assert!(
            dir.lookup_family("humanity-accord")
                .await
                .unwrap()
                .is_none(),
            "the seam must NOT seed the entrenched accord family"
        );
        assert!(
            dir.lookup_public_key("A1").await.unwrap().is_none(),
            "the seam must NOT seed the A1 accord holder"
        );
        // And a normally-constructed engine DOES have both (the prod path).
        let seeded = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct seeded engine");
        assert!(seeded
            .federation_directory()
            .lookup_family("humanity-accord")
            .await
            .unwrap()
            .is_some());
    }

    /// v13.4.0 (CIRISPersist#390) — the operator's success criterion: a FRESH
    /// install (no ceremony, no manual adopt) boots with `ciris-canonical-1`
    /// already in the conferred canonical set, so the client Trust Root shows it
    /// as canonical and peers can address it by key_id.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn fresh_engine_auto_loads_2of3_canonical_server() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct engine");
        let node = &crate::federation::genesis::canonical_genesis_records()[0].record;
        assert_eq!(node.key_id, "ciris-canonical-1-d7bdeu223k");
        assert!(
            engine
                .is_canonical(&node.key_id)
                .await
                .expect("is_canonical"),
            "a fresh install must trust {} out of the box",
            node.key_id
        );
        let listed = engine.list_canonical_servers().await.expect("list");
        assert!(listed.iter().any(|r| r.key_id == node.key_id));
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn fresh_engine_auto_loads_accord_family() {
        // v13.3.0 (CIRISPersist#386) — a FRESH engine auto-loads the entrenched
        // keyless HUMANITY_ACCORD family row (quorum:2/3, A1/B1/C1), like the
        // accord holders — no manual seed, `lookup_family` resolves straight out
        // of `Engine::with_signer`.
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct engine");
        let fam = engine
            .federation_directory()
            .lookup_family("humanity-accord")
            .await
            .expect("lookup")
            .expect("fresh engine must recognize the baked accord family");
        assert_eq!(fam.consensus_protocol, "quorum:2/3");
        assert_eq!(fam.members.len(), 3);
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
            cohort_scope: "federation".into(),
            cohort_target_id: None,
            signature: String::new(),
            signature_key_id: agent_key_id.into(),
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
        };
        // v7.2.0 (#225) — hybrid-sign so the Full-mode trace-tier hard
        // cut admits: Ed25519 over canonical + ML-DSA-65 over the bound
        // input (canonical || classical_sig), plus the asserted PQC
        // pubkey. canonical_payload_value still computes the classical
        // canonical the agent signs.
        let payload = canonical_payload_value(&trace);
        let canonical = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&payload)
            .unwrap();
        let ed_sig = agent_sk.sign(&canonical).to_bytes();
        {
            use ciris_keyring::PqcSigner as _;
            let mldsa = ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(
                &[0x77; 32],
                "engine-89-mldsa",
            )
            .unwrap();
            let mut bound = Vec::with_capacity(canonical.len() + ed_sig.len());
            bound.extend_from_slice(&canonical);
            bound.extend_from_slice(&ed_sig);
            let pqc_sig = mldsa.sign(&bound).await.unwrap();
            let pqc_pk = mldsa.public_key().await.unwrap();
            trace.signature = B64.encode(ed_sig);
            trace.signature_ml_dsa_65 = Some(B64.encode(&pqc_sig));
            trace.pubkey_ml_dsa_65 = Some(B64.encode(&pqc_pk));
            trace.pqc_key_id = Some("engine-89-mldsa".to_owned());
        }

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
            let conn = conn.lock();
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
            cohort_scope: "federation".into(),
            cohort_target_id: None,
            signature: String::new(),
            signature_key_id: agent_key_id.into(),
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
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
        #[allow(clippy::infallible_destructuring_match)]
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
            cohort_scope: "federation".into(),
            cohort_target_id: None,
            signature: String::new(),
            signature_key_id: agent_key_id.clone(),
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
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
        let signer = test_signer_no_pqc(); // No PQC.
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
        let signer = test_signer_no_pqc(); // No PQC.
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

    /// v6.6.0 (CIRISPersist#220) — `with_hardware_signer` is the
    /// from-scratch counterpart to `from_shared`: it RUNS migrations (via
    /// `build_backend`, unlike `from_shared`) and stores the supplied
    /// `Arc<dyn HardwareSigner>` directly with `local_signer: None`.
    /// Successful construction proves migrations ran (`build_backend`
    /// propagates migration errors); the post-construction directory read
    /// proves the schema is live; and `sign_hybrid` being unavailable
    /// proves the hardware-only signer shape (mirrors `from_shared`).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn with_hardware_signer_migrates_and_is_hardware_only() {
        // A host obtains an Arc<dyn HardwareSigner> from ciris-keyring; here
        // we synthesize one the way `with_signer` does (adapter over a
        // LocalSigner) and hand it to the from-scratch hardware ctor.
        let seed = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("seed engine");
        let hw: Arc<dyn HardwareSigner> = seed.signer().clone();

        let engine = Engine::with_hardware_signer(hw, "sqlite::memory:")
            .await
            .expect("with_hardware_signer constructs + migrates");

        // Migrations ran: a directory read hits a live table (Ok(None)),
        // not a "no such table" error — the differentiator from from_shared.
        // (Irrefutable under a sqlite-only build where Sqlite is the sole
        // BackendDispatch variant; refutable with other backends compiled.)
        #[allow(irrefutable_let_patterns)]
        if let BackendDispatch::Sqlite(b) = engine.backend() {
            let found = crate::federation::FederationDirectory::lookup_public_key(
                b.as_ref(),
                "nonexistent-key",
            )
            .await
            .expect("schema is live");
            assert!(found.is_none());
        } else {
            panic!("expected sqlite backend");
        }

        // Hardware-only shape: no LocalSigner → sign_hybrid unavailable.
        let err = engine
            .sign_hybrid(b"any message")
            .await
            .expect_err("hardware signer has no LocalSigner");
        assert!(
            matches!(err, SignError::LocalSignerUnavailable),
            "got: {err:?}"
        );
    }

    // ── v7.1.0 (CIRISPersist#224) — hybrid hardware signer:
    //    with_hardware_signer_hybrid composes a real HybridSignature
    //    (Ed25519 from the sealed HardwareSigner + ML-DSA-65 from the
    //    PqcSigner) without unsealing the classical key. ──────────────

    /// Fixture: a software [`HardwareSigner`] standing in for a sealed
    /// classical key (TPM/SE). `Ed25519SoftwareSigner` is the
    /// test-available `HardwareSigner` whose `algorithm()` is Ed25519;
    /// production passes a real sealed signer from
    /// `ciris_keyring::get_platform_signer`.
    // Gated to `sqlite` — all callers are the sqlite-only hardware-signer
    // tests; the broader `any(sqlite,postgres)` gate left it dead under
    // no-sqlite `-D warnings` builds (postgres,pyo3,server / pyo3,server).
    #[cfg(feature = "sqlite")]
    fn hw_classical(alias: &str) -> Arc<dyn HardwareSigner> {
        let seed = [0x24u8; 32];
        Arc::new(
            ciris_keyring::Ed25519SoftwareSigner::from_bytes(&seed, alias.to_owned())
                .expect("ed25519 sw signer"),
        )
    }

    /// Fixture: an ML-DSA-65 `PqcSigner` (software) for the PQC half.
    /// Gated to `sqlite` — both callers (`with_hardware_signer_hybrid_*`,
    /// `hardware_hybrid_engine_*`) are `#[cfg(feature = "sqlite")]`; the
    /// broader `any(sqlite,postgres)` gate left it dead under the
    /// `postgres,pyo3,server` build (`-D warnings`).
    #[cfg(feature = "sqlite")]
    fn pqc_half() -> Arc<dyn ciris_keyring::PqcSigner> {
        Arc::new(
            ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&[0x71u8; 32], "hw-hybrid-pqc")
                .expect("ml-dsa-65 seed"),
        )
    }

    /// THE DELIVERABLE: a `with_hardware_signer_hybrid` Engine built from
    /// a (software) `HardwareSigner` classical half + an ML-DSA-65
    /// `PqcSigner` produces a real `HybridSignature` whose Ed25519 half
    /// verifies against the *hardware signer's* public key (proving the
    /// sealed classical never had to be unsealed) AND whose ML-DSA-65
    /// half verifies — i.e. the sealed-classical hybrid path composes a
    /// valid hybrid signature.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn with_hardware_signer_hybrid_composes_valid_hybrid_sig() {
        use ciris_crypto::{Ed25519Verifier, HybridVerifier, MlDsa65Verifier};

        let classical = hw_classical("hw-hybrid-steward");
        // The pubkey the sealed classical exposes — sign_hybrid must use
        // exactly this in the HybridSignature's classical half.
        let hw_pubkey = classical.public_key().await.expect("hw pubkey");

        let engine = Engine::with_hardware_signer_hybrid(
            classical.clone(),
            Some(pqc_half()),
            Some("hw-hybrid-pqc".to_owned()),
            "sqlite::memory:",
        )
        .await
        .expect("construct hybrid-hardware engine");

        let message = b"storage-tier scrub canonical bytes";
        let sig = engine
            .sign_hybrid(message)
            .await
            .expect("hybrid sign with sealed classical");

        // The classical half carries the hardware signer's pubkey — the
        // sealed key was never unsealed into a plaintext SigningKey.
        assert_eq!(
            sig.classical.public_key, hw_pubkey,
            "hybrid classical pubkey must be the hardware signer's"
        );
        assert_eq!(
            sig.classical.algorithm,
            ciris_crypto::ClassicalAlgorithm::Ed25519
        );
        assert_eq!(sig.pqc.algorithm, ciris_crypto::PqcAlgorithm::MlDsa65);

        // Both halves verify (HybridVerifier rebuilds the data||classical
        // binding, exactly matching sign_hybrid's composition).
        let verifier = HybridVerifier::new(Ed25519Verifier, MlDsa65Verifier::new());
        assert!(
            verifier.verify(message, &sig).expect("verify hybrid"),
            "sealed-classical hybrid signature must verify (both halves)"
        );

        // Independent Ed25519-half check against the hardware pubkey.
        use ed25519_dalek::Verifier as _;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(
            hw_pubkey
                .as_slice()
                .try_into()
                .expect("32-byte ed25519 pubkey"),
        )
        .expect("verifying key");
        let ed_sig = ed25519_dalek::Signature::from_slice(&sig.classical.signature)
            .expect("64-byte ed25519 sig");
        vk.verify(message, &ed_sig)
            .expect("Ed25519 half verifies against the hardware signer's pubkey");
    }

    /// A `with_hardware_signer_hybrid` Engine built WITHOUT a PQC half
    /// matches `with_signer`'s no-PQC semantics: `sign_hybrid` surfaces
    /// the LocalSigner's own `PqcNotConfigured` (not
    /// `LocalSignerUnavailable` — the LocalSigner IS present, it just has
    /// no PQC identity).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn with_hardware_signer_hybrid_without_pqc_returns_pqc_not_configured() {
        let engine = Engine::with_hardware_signer_hybrid(
            hw_classical("hw-hybrid-nopqc"),
            None,
            None,
            "sqlite::memory:",
        )
        .await
        .expect("construct hybrid-hardware engine without pqc");

        let err = engine
            .sign_hybrid(b"any message")
            .await
            .expect_err("no PQC configured");
        match err {
            SignError::LocalSigner(crate::signing::LocalSignerError::PqcNotConfigured) => {}
            other => panic!("expected SignError::LocalSigner(PqcNotConfigured), got {other:?}"),
        }
    }

    /// #224 + #223 — `local_identity_aggregate` surfaces the full
    /// signing role (Ed25519 + ML-DSA-65) for a hardware-signed Engine,
    /// reading the sealed classical's pubkey through the cached
    /// classical public key (the #223 six-key-aggregate consequence of
    /// the hybrid-hardware ctor).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn hardware_hybrid_engine_surfaces_signing_role_in_aggregate() {
        let classical = hw_classical("hw-hybrid-agg");
        let hw_pubkey_b64 = {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            B64.encode(classical.public_key().await.expect("hw pubkey"))
        };
        let engine = Engine::with_hardware_signer_hybrid(
            classical,
            Some(pqc_half()),
            Some("hw-hybrid-pqc".to_owned()),
            "sqlite::memory:",
        )
        .await
        .expect("construct hybrid-hardware engine");

        let agg = engine
            .local_identity_aggregate(None, None)
            .await
            .expect("aggregate for a hardware-signed engine");

        assert_eq!(
            agg.ed25519_pubkey_b64, hw_pubkey_b64,
            "aggregate's Ed25519 signing pubkey is the sealed hardware key's"
        );
        assert!(
            agg.ml_dsa_65_pubkey_b64.is_some(),
            "ML-DSA-65 signing pubkey present (PQC half configured)"
        );
    }

    /// v7.1.0 (CIRISPersist#223) — a CLASSICAL-ONLY hardware engine
    /// (`with_hardware_signer`, `local_signer: None`) now produces its
    /// six-key aggregate via the `HardwareSigner` fallback instead of
    /// erroring. This is the fix for CIRISServer's `/v1/identity` returning
    /// content-KEM = null: content-KEM is persist-minted (populated); the
    /// ML-DSA signing half is None (a classical-only HW signer has no PQC).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn classical_only_hardware_engine_surfaces_aggregate() {
        let classical = hw_classical("hw-classical-agg");
        let hw_pubkey_b64 = {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            B64.encode(classical.public_key().await.expect("hw pubkey"))
        };
        let engine = Engine::with_hardware_signer(classical, "sqlite::memory:")
            .await
            .expect("construct classical-only hardware engine");

        let agg = engine
            .local_identity_aggregate(None, None)
            .await
            .expect("#223: classical-only hardware aggregate must not error");

        assert_eq!(
            agg.ed25519_pubkey_b64, hw_pubkey_b64,
            "Ed25519 signing pubkey is the sealed hardware key's"
        );
        assert!(
            agg.ml_dsa_65_pubkey_b64.is_none(),
            "no PQC half for a classical-only hardware signer"
        );
        assert!(
            agg.content_x25519_pubkey_b64.is_some() && agg.content_ml_kem_768_pubkey_b64.is_some(),
            "content-KEM is persist-minted + populated (the /v1/identity null fix)"
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
            consent_role: None,
            additional_scrubs: Vec::new(),
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
        (move || -> rusqlite::Result<()> {
            let conn = conn.lock();
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
        })()
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
            consent_role: None,
            additional_scrubs: Vec::new(),
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
            let conn = conn.lock();
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

    // Only the sqlite put_blob_signing tests below use this; the
    // postgres canonicalizer test computes its hash inline. Gating to
    // `any(sqlite, postgres)` left it dead under postgres-only builds.
    #[cfg(feature = "sqlite")]
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
    async fn put_blob_signing_canonicalizes_via_ceg_produce_gate_sqlite() {
        use crate::federation::{
            holds_bytes_attestation_envelope, holds_bytes_attestation_type, BlobBody, BlobStorage,
        };
        use crate::verify::canonical::ceg_produce_canonicalize;
        use sha2::{Digest, Sha256};

        let signer = test_signer();
        // v9.3.0 (#247) — the holds_bytes `scrub_key_id` is the signer's
        // DERIVED federation key_id, and the attesting key registers under
        // it (the real-node shape; alias is never a federation_keys row).
        let signer_alias = signer.derived_key_id();
        let engine = Engine::with_signer(signer.clone(), "sqlite::memory:")
            .await
            .expect("construct engine");
        seed_test_attesting_key(&engine, &signer_alias).await;

        let bytes = b"canonicalizer-identity-blob".to_vec();
        let sha = sha256_of_bytes(&bytes);

        // Expected hash: SHA-256 of the canonical bytes the production
        // produce gate emits for the holds_bytes envelope. v4.15.0 (#871)
        // flipped the gate Python-compat → JCS; this envelope is
        // structured-ASCII (SHA-256 hex + attestation-type string), where
        // the two canonicalizers are byte-identical, so the invariant is
        // stable across the flip — and asserting via the gate (not a
        // pinned canonicalizer) keeps the test honest to whatever the
        // produce epoch is.
        let envelope = holds_bytes_attestation_envelope(&sha);
        let gate_canonical = ceg_produce_canonicalize(&envelope).expect("ceg produce canonicalize");
        let expected_hash_hex = hex::encode(Sha256::digest(&gate_canonical));

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
                let conn = conn.lock();
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
            "put_blob_signing must canonicalize via the CEG produce gate \
             (ceg_produce_canonicalize; JCS as of v4.15.0/#871); the \
             silent-correctness trap CIRISPersist#121 closes manifests as a \
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

    /// v10.0.1 (CIRISPersist#275) — regression: `register_self_federation_key`
    /// must register the engine's COMPOSED-signer derived id (the same id
    /// `put_blob_signing`'s holds_bytes `scrub_key_id` derives), so the
    /// canonical "register self, then hold bytes" flow does NOT FK-fail. The
    /// #247 floor (v9.3.0) made the scrub FK target the derived id while the
    /// bootstrap registered the alias / a different signer's id, breaking
    /// this on every persist >= 9.3.0.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn register_self_then_put_blob_signing_resolves_scrub_fk_275() {
        use crate::federation::BlobBody;

        let signer = test_signer();
        let engine = Engine::with_signer(signer.clone(), "sqlite::memory:")
            .await
            .expect("construct engine");

        // register_self registers the engine's federation identity, keyed
        // by the DERIVED id — not the bare alias.
        let kid = engine
            .register_self_federation_key("agent", "ref", None, serde_json::json!({}), vec![])
            .await
            .expect("register_self_federation_key");
        let derived = engine.local_derived_key_id().await.expect("derived id");
        assert_eq!(kid, derived, "must register (and return) the derived id");
        assert_ne!(
            kid,
            signer.key_id(),
            "derived id is NOT the bare keystore alias"
        );

        // The canonical self-holds-bytes ingest must resolve the holds_bytes
        // scrub_key_id FK against the row register_self just wrote.
        let bytes = b"register-self-275".to_vec();
        let sha = sha256_of_bytes(&bytes);
        engine
            .put_blob_signing(
                &sha,
                BlobBody::Inline(bytes),
                Some("application/octet-stream"),
                &kid,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .expect("put_blob_signing must resolve the scrub FK after register_self");
    }

    /// v10.1.0 (CIRISPersist#275 — withdraws/eviction surface) — the
    /// canonical "register self → hold a blob → evict the actor" lifecycle
    /// end to end: the eviction `withdraws` attestation must FK-resolve
    /// against the row `register_self_federation_key` wrote. Reproduces the
    /// conformance harness's `withdraws_failed` report.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn evict_actor_after_register_self_emits_withdraws_275() {
        use crate::federation::BlobBody;

        let signer = test_signer(); // PQC-configured (hybrid withdraws need it)
        let engine = Engine::with_signer(signer.clone(), "sqlite::memory:")
            .await
            .expect("construct engine");
        let kid = engine
            .register_self_federation_key("agent", "ref", None, serde_json::json!({}), vec![])
            .await
            .expect("register_self_federation_key");

        // Hold a blob under the registered (derived) id.
        let bytes = b"evict-275".to_vec();
        let sha = sha256_of_bytes(&bytes);
        engine
            .put_blob_signing(
                &sha,
                BlobBody::Inline(bytes),
                Some("application/octet-stream"),
                &kid,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .expect("put_blob_signing");

        // Evict the actor → emits a federation-tier withdraws whose
        // attesting/attested/scrub key_id must FK-resolve against the
        // register_self row.
        let report = engine
            .evict_actor(&kid, chrono::Utc::now())
            .await
            .expect("evict_actor");
        assert_eq!(report.blobs_evicted, 1, "the held blob is evicted");
        assert_eq!(
            report.withdraws_failed, 0,
            "the withdraws must NOT FK-fail after register_self: {report:?}"
        );
        assert_eq!(
            report.withdraws_emitted, 1,
            "one withdraws emitted: {report:?}"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn put_blob_signing_inline_round_trip_sqlite() {
        use crate::federation::{BlobBody, BlobStorage};

        let signer = test_signer();
        // v9.3.0 (#247) — register + attest under the DERIVED federation
        // key_id (the holds_bytes scrub_key_id put_blob_signing now writes).
        let signer_alias = signer.derived_key_id();
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
        // v9.3.0 (#247) — register + attest under the DERIVED federation
        // key_id (the holds_bytes scrub_key_id put_blob_signing now writes).
        let signer_alias = signer.derived_key_id();
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
        // v9.3.0 (#247) — register + attest under the DERIVED federation
        // key_id (the holds_bytes scrub_key_id put_blob_signing now writes).
        let signer_alias = signer.derived_key_id();
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
        // v9.3.0 (#247) — register + attest under the DERIVED federation
        // key_id (the holds_bytes scrub_key_id put_blob_signing now writes).
        let signer_alias = signer.derived_key_id();
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
    async fn put_blob_signing_canonicalizes_via_ceg_produce_gate_postgres() {
        use crate::federation::{
            holds_bytes_attestation_envelope, holds_bytes_attestation_type, BlobBody,
            FederationDirectory,
        };
        use crate::verify::canonical::ceg_produce_canonicalize;
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
        // v9.3.0 (#247) — the holds_bytes scrub_key_id is the signer's
        // DERIVED federation key_id; register + attest under it.
        let key_id = signer.derived_key_id();
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
            consent_role: None,
            additional_scrubs: Vec::new(),
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
        let gate_canonical = ceg_produce_canonicalize(&envelope).expect("ceg produce canonicalize");
        let expected_hash_hex = hex::encode(Sha256::digest(&gate_canonical));

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

        // Pin the stored hash equals the CEG produce-gate canonical
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

    // ─── v3.4.0 (CIRISPersist#123) — sweeper integration tests ─────

    /// Build a SignedKeyRecord whose key_id and scrub_key_id are
    /// self-referential so the FK constraints land cleanly.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn sweeper_test_key(key_id: &str) -> crate::federation::SignedKeyRecord {
        // v9.0.0 (CC 5.3.2.4.3.1) — register REAL deterministic hybrid
        // pubkeys (matching the LocalSigner `test_signer` / `local_signer`
        // builds for the same key_id) so the federation-tier withdraws the
        // sweeper emits verifies at the ingest gate.
        let (ed_pk, mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(key_id);
        crate::federation::SignedKeyRecord {
            record: crate::federation::KeyRecord {
                key_id: key_id.into(),
                pubkey_ed25519_base64: ed_pk,
                pubkey_ml_dsa_65_base64: mldsa_pk,
                algorithm: crate::federation::types::algorithm::HYBRID.into(),
                identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
                identity_ref: key_id.into(),
                valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
                valid_until: None,
                registration_envelope: serde_json::json!({"id": key_id}),
                original_content_hash: "deadbeef".into(),
                scrub_signature_classical: "c2lnbmF0dXJl".into(),
                scrub_signature_pqc: None,
                scrub_key_id: key_id.into(),
                scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        }
    }

    /// Build a SQLite engine, register the test signer's key in
    /// `federation_keys`, seed N blobs through `put_blob_signing` so
    /// each lands a holds_bytes attestation. Returns the Engine + the
    /// SHAs (in insertion order).
    #[cfg(feature = "sqlite")]
    async fn sweeper_seed_blobs(
        cfg: crate::federation::ReplicationConfig,
        n: usize,
    ) -> (Engine, Vec<[u8; 32]>) {
        use crate::federation::{BlobBody, FederationDirectory};
        let signer = test_signer();
        // v9.3.0 (#247) — the real-node shape: the steward's registered
        // federation key_id is the DERIVED id (`<alias>-<fp>`), and its
        // holds_bytes attestations are emitted under that derived id. The
        // sweeper now matches + withdraws by the derived id, so seed the
        // FK row + the holds_bytes under it (not the bare alias).
        let derived = signer.derived_key_id();
        let engine = Engine::with_replication_config(signer, "sqlite::memory:", cfg)
            .await
            .expect("construct engine");
        let sq = engine.sqlite_backend().expect("sqlite present");
        sq.put_public_key(sweeper_test_key_derived(&derived))
            .await
            .expect("seed signer key");
        let mut shas = Vec::with_capacity(n);
        for i in 0..n {
            // 1 KiB payloads so storage budgets are predictable.
            let bytes = vec![i as u8 + 1; 1024];
            let sha = {
                use sha2::{Digest, Sha256};
                let mut out = [0u8; 32];
                out.copy_from_slice(&Sha256::digest(&bytes));
                out
            };
            engine
                .put_blob_signing(
                    &sha,
                    BlobBody::Inline(bytes),
                    None,
                    &derived,
                    chrono::Utc::now(),
                    uuid::Uuid::new_v4(),
                )
                .await
                .expect("put_blob_signing");
            shas.push(sha);
        }
        (engine, shas)
    }

    /// v9.3.0 (#247) — `sweeper_test_key` for the DERIVED-id row: the row
    /// is keyed by `derived_key_id` (`<alias>-<fp>`) but carries the REAL
    /// `test-engine-steward` hybrid pubkeys, so the federation-tier
    /// withdraws the sweeper emits (signed under that key, attested as the
    /// derived id) verifies at the ingest gate AND its FK holds.
    #[cfg(feature = "sqlite")]
    fn sweeper_test_key_derived(derived_key_id: &str) -> crate::federation::SignedKeyRecord {
        sweeper_test_key_derived_for(derived_key_id, "test-engine-steward")
    }

    /// v9.3.0 (#247) — register a `federation_keys` row keyed by
    /// `derived_key_id` but carrying `pubkey_label`'s REAL deterministic
    /// hybrid pubkeys (the signer's actual keypair), so a federation-tier
    /// row attested as `derived_key_id` and signed by `pubkey_label`'s
    /// keys both FK-resolves AND hybrid-verifies at the ingest gate.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn sweeper_test_key_derived_for(
        derived_key_id: &str,
        pubkey_label: &str,
    ) -> crate::federation::SignedKeyRecord {
        let mut signed = sweeper_test_key(pubkey_label);
        signed.record.key_id = derived_key_id.into();
        signed.record.identity_ref = derived_key_id.into();
        signed.record.scrub_key_id = derived_key_id.into();
        signed.record.registration_envelope = serde_json::json!({ "id": derived_key_id });
        signed
    }

    /// v3.4.0 (CIRISPersist#123) — sweeper is a noop when total bytes
    /// sit below the watermark.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sweeper_idle_when_below_watermark_sqlite() {
        let cfg = crate::federation::ReplicationConfig {
            storage_budget_bytes: 1_000_000, // 1 MB — well above 5 KiB seed.
            steady_state_utilization: 0.92,
            ..Default::default()
        };
        let (engine, _shas) = sweeper_seed_blobs(cfg, 5).await;
        let report = engine.sweep_evictions_once().await.expect("sweep");
        assert_eq!(report.rows_evicted, 0);
        assert_eq!(report.withdraws_emitted, 0);
        assert_eq!(report.bytes_before, report.bytes_after);
        // Total stored ≈ 5 KiB.
        assert!(report.bytes_before >= 5 * 1024);
    }

    /// v3.4.0 (CIRISPersist#123) — sweeper evicts lowest-score rows
    /// first. We seed 5 blobs in age order (each 1 KiB), then bump
    /// access_count on the OLDER ones so the YOUNGER ones become the
    /// eviction targets (their `(access_count + 1) × decay` score is
    /// lower because they were never touched).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sweeper_evicts_lowest_score_first_sqlite() {
        let cfg = crate::federation::ReplicationConfig {
            // Budget = 4 KiB → watermark = 3.6 KiB → must evict so
            // post-sweep ≤ 3.6 KiB. With 5 × 1 KiB rows = 5 KiB stored,
            // target_freed = 5120 - 3686 ≈ 1.4 KiB → must evict 2 rows.
            // Those 2 evictions should hit the 2 LEAST-touched
            // (shas[3], shas[4]) — leaving the 3 hot ones (shas[0..3]).
            storage_budget_bytes: 4 * 1024,
            steady_state_utilization: 0.9,
            // Very long half-life so access_count dominates score,
            // not decay over the short test interval.
            eviction_decay_half_life_days: 365.0,
            ..Default::default()
        };
        let (engine, shas) = sweeper_seed_blobs(cfg, 5).await;
        // Bump access_count on the OLDEST three blobs so they outrank
        // the two newest. get_blob bumps access_count + last_accessed_at;
        // we call it three times on shas[0..3].
        use crate::federation::BlobStorage;
        let sq = engine.sqlite_backend().expect("sqlite");
        for sha in &shas[..3] {
            for _ in 0..3 {
                let _ = sq.get_blob(sha).await.unwrap();
            }
        }

        let report = engine.sweep_evictions_once().await.expect("sweep");
        // Expect at least one eviction; the LEAST-recently-accessed
        // never-touched rows go first.
        assert!(
            report.rows_evicted > 0,
            "sweeper should evict; got {report:?}"
        );
        assert!(report.bytes_after < report.bytes_before);
        // The 3 hot blobs (shas[0..3]) MUST still be present — they
        // have high access_count AND their last_accessed_at is
        // post-get_blob, both of which boost their score.
        for sha in &shas[..3] {
            assert!(
                sq.has_blob(sha).await.unwrap(),
                "hot blob must survive eviction"
            );
        }
        // The 2 cold blobs (shas[3], shas[4]) — at least one was
        // evicted.
        let mut cold_present_count = 0usize;
        for sha in &shas[3..5] {
            if sq.has_blob(sha).await.unwrap() {
                cold_present_count += 1;
            }
        }
        assert!(
            cold_present_count < 2,
            "at least one cold blob must have been evicted"
        );
    }

    /// v3.4.0 (CIRISPersist#123) — sweeper emits a `withdraws`
    /// attestation for each evicted row that has a prior `holds_bytes`
    /// emission from the local signer.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sweeper_emits_withdraws_on_eviction_sqlite() {
        let cfg = crate::federation::ReplicationConfig {
            storage_budget_bytes: 2 * 1024,
            steady_state_utilization: 0.5,
            eviction_decay_half_life_days: 365.0,
            ..Default::default()
        };
        let (engine, _shas) = sweeper_seed_blobs(cfg, 5).await;
        let report = engine.sweep_evictions_once().await.expect("sweep");
        assert!(report.rows_evicted > 0);
        assert_eq!(
            report.withdraws_emitted, report.rows_evicted,
            "each eviction should have a withdraws attestation"
        );
        assert_eq!(report.withdraws_failed, 0);
        // Confirm withdraws rows exist in federation_attestations.
        // v9.3.0 (#247) — the sweeper attests withdraws under the DERIVED
        // federation key_id, so query by that, not the bare alias.
        let derived = test_signer().derived_key_id();
        let directory = engine.federation_directory();
        let atts = directory.list_attestations_by(&derived).await.unwrap();
        let withdraws_count = atts
            .iter()
            .filter(|a| a.attestation_type == crate::federation::types::attestation_type::WITHDRAWS)
            .count();
        assert_eq!(
            withdraws_count, report.rows_evicted as usize,
            "withdraws rows in directory must match rows_evicted"
        );
    }

    /// v3.4.0 (CIRISPersist#123) — `list_holders` filters out the
    /// holds_bytes attestation whose attester later emitted a
    /// `withdraws` referencing it. Confirms the eviction → withdraws
    /// → list_holders loop closes end-to-end.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn list_holders_filters_evicted_rows_sqlite() {
        let cfg = crate::federation::ReplicationConfig {
            storage_budget_bytes: 2 * 1024,
            steady_state_utilization: 0.5,
            eviction_decay_half_life_days: 365.0,
            ..Default::default()
        };
        let (engine, shas) = sweeper_seed_blobs(cfg, 5).await;
        use crate::federation::BlobStorage;
        let sq = engine.sqlite_backend().expect("sqlite");
        // Confirm every blob has the local signer (its DERIVED federation
        // key_id, #247) as holder before the sweep.
        let derived = test_signer().derived_key_id();
        for sha in &shas {
            let holders = sq.list_holders(sha).await.unwrap();
            assert_eq!(holders, vec![derived.clone()]);
        }
        let report = engine.sweep_evictions_once().await.expect("sweep");
        assert!(report.rows_evicted > 0);
        // For each evicted SHA, list_holders should now be empty
        // (the local signer's holds_bytes row is now withdrawn).
        let mut empty_holder_count = 0usize;
        for sha in &shas {
            let holders = sq.list_holders(sha).await.unwrap();
            if holders.is_empty() {
                empty_holder_count += 1;
            }
        }
        assert!(
            empty_holder_count as u64 >= report.rows_evicted,
            "evicted blobs must have list_holders return empty after withdraws"
        );
    }

    // ─── v6.8.0 (CIRISPersist#149) — disk-pressure force-evict-proxy ───

    /// Seed `n` PROXY blobs: bytes + a `holds_bytes` attestation by a
    /// PEER key (not the local signer). Because the sweeper indexes only
    /// the LOCAL signer's holds_bytes, these classify as proxy. Returns
    /// the SHAs.
    #[cfg(feature = "sqlite")]
    async fn seed_proxy_blobs(engine: &Engine, peer_key: &str, n: usize) -> Vec<[u8; 32]> {
        use crate::federation::{BlobBody, BlobStorage, FederationDirectory, PutBlobAttestation};
        let sq = engine.sqlite_backend().expect("sqlite");
        // Peer key must exist (FK on the holds_bytes attestation).
        sq.put_public_key(sweeper_test_key(peer_key))
            .await
            .expect("seed peer key");
        let mut shas = Vec::with_capacity(n);
        for i in 0..n {
            // Distinct payloads from the local seed (offset the fill byte).
            let bytes = vec![0x80u8 + i as u8; 1024];
            let sha = {
                use sha2::{Digest, Sha256};
                let mut out = [0u8; 32];
                out.copy_from_slice(&Sha256::digest(&bytes));
                out
            };
            sq.put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                PutBlobAttestation {
                    attesting_key_id: peer_key.to_string(),
                    attestation_id: uuid::Uuid::new_v4().to_string(),
                    original_content_hash_hex: "ab".repeat(32),
                    scrub_signature_classical: "c2ln".to_string(),
                    scrub_signature_pqc: None,
                    scrub_key_id: peer_key.to_string(),
                    scrub_timestamp: chrono::Utc::now(),
                },
            )
            .await
            .expect("put_blob proxy");
            shas.push(sha);
        }
        shas
    }

    /// v6.8.0 (CIRISPersist#149) — `sweep_evictions_once_force_proxy`
    /// evicts proxy-attested rows BEFORE local/family rows, even when
    /// the proxy rows are HOTTER (higher access_count). The standard
    /// sweep would keep the hot proxy rows; the force-proxy variant
    /// drops them first to protect local content under disk pressure.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn force_evict_proxy_first_protects_local_sqlite() {
        use crate::federation::BlobStorage;
        // Budget tiny so exactly the proxy rows must be shed. 3 local +
        // 3 proxy = 6 KiB. Watermark 50% of 4 KiB = 2 KiB → must free
        // ~4 KiB → ≈ 4 rows. Force-proxy MUST take the 3 proxy first,
        // then one local; the 2 hot-local rows survive.
        let cfg = crate::federation::ReplicationConfig {
            storage_budget_bytes: 4 * 1024,
            steady_state_utilization: 0.5,
            eviction_decay_half_life_days: 365.0,
            ..Default::default()
        };
        // 3 local blobs (via local signer holds_bytes).
        let (engine, local_shas) = sweeper_seed_blobs(cfg, 3).await;
        // Install a disk-pressure config whose family predicate matches
        // nobody (so the peer is pure federation/proxy).
        let dp = std::sync::Arc::new(crate::federation::DiskPressureConfig {
            monitor_path: std::path::PathBuf::from("/x"),
            ..Default::default()
        });
        let engine = engine.with_disk_pressure_config_shared(dp);
        // 3 proxy blobs (via peer key holds_bytes).
        let proxy_shas = seed_proxy_blobs(&engine, "peer-relay-key", 3).await;

        let sq = engine.sqlite_backend().expect("sqlite");
        // Make the PROXY blobs HOT (high access_count) — under the
        // standard order they'd survive; force-proxy must override.
        for sha in &proxy_shas {
            for _ in 0..20 {
                let _ = sq.get_blob(sha).await.unwrap();
            }
        }
        // Local blobs stay cold (low access_count).

        let report = engine
            .sweep_evictions_once_force_proxy()
            .await
            .expect("force-proxy sweep");
        assert!(report.rows_evicted > 0, "must evict under pressure");

        // All 3 proxy blobs must be gone (evicted first despite being hot).
        let mut proxy_present = 0usize;
        for sha in &proxy_shas {
            if sq.has_blob(sha).await.unwrap() {
                proxy_present += 1;
            }
        }
        assert_eq!(
            proxy_present, 0,
            "force-evict-proxy-first must shed ALL proxy rows before local"
        );

        // At least 2 of the 3 local blobs must survive (proxy shed
        // first frees most of the target before local is touched).
        let mut local_present = 0usize;
        for sha in &local_shas {
            if sq.has_blob(sha).await.unwrap() {
                local_present += 1;
            }
        }
        assert!(
            local_present >= 2,
            "local/family content must be protected; only {local_present}/3 survived"
        );
    }

    /// v6.8.0 (CIRISPersist#149) — the STANDARD (non-forced) sweep keeps
    /// HOT proxy rows (no special proxy handling) — proving the
    /// force-proxy path is what changes the order, not the seed setup.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn standard_sweep_keeps_hot_proxy_sqlite() {
        use crate::federation::BlobStorage;
        let cfg = crate::federation::ReplicationConfig {
            storage_budget_bytes: 4 * 1024,
            steady_state_utilization: 0.5,
            eviction_decay_half_life_days: 365.0,
            ..Default::default()
        };
        let (engine, _local) = sweeper_seed_blobs(cfg, 3).await;
        let proxy_shas = seed_proxy_blobs(&engine, "peer-relay-key", 3).await;
        let sq = engine.sqlite_backend().expect("sqlite");
        // Make proxy blobs HOT.
        for sha in &proxy_shas {
            for _ in 0..20 {
                let _ = sq.get_blob(sha).await.unwrap();
            }
        }
        let report = engine.sweep_evictions_once().await.expect("standard sweep");
        assert!(report.rows_evicted > 0);
        // Standard order: hot rows survive regardless of proxy status —
        // at least one hot proxy row remains.
        let mut proxy_present = 0usize;
        for sha in &proxy_shas {
            if sq.has_blob(sha).await.unwrap() {
                proxy_present += 1;
            }
        }
        assert!(
            proxy_present > 0,
            "standard sweep should keep HOT proxy rows (no proxy-first ordering)"
        );
    }

    // ─── v12.7.0 (CC 6.1.5.2 §Q / CIRISPersist#370) — pin-install + B5 ───

    /// §Q signer for the budget wires: a deterministic-enough hybrid pair
    /// (fresh per test; the pubkeys ride along). Built + used SYNCHRONOUSLY
    /// so no multi-KiB signer is ever held across an await (the ML-DSA-65
    /// test-stack rule).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    struct QShapeId {
        ed: ciris_crypto::Ed25519Signer,
        pqc: ciris_crypto::MlDsa65Signer,
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn qshape_id() -> QShapeId {
        QShapeId {
            ed: ciris_crypto::Ed25519Signer::random().unwrap(),
            pqc: ciris_crypto::MlDsa65Signer::new().unwrap(),
        }
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn qshape_pubs(id: &QShapeId) -> (String, String) {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ciris_crypto::{ClassicalSigner, PqcSigner};
        (
            B64.encode(id.ed.public_key().unwrap()),
            B64.encode(id.pqc.public_key().unwrap()),
        )
    }

    /// Build + bound-hybrid sign a `StorageBudgetV1` wire: one `community`
    /// scope with `budget_bytes = 100_000` and the given
    /// `pin_reserve_bytes`, pinning `pinned_class` (MUST be pre-sorted).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn qshape_budget_wire(
        id: &QShapeId,
        node_id: &str,
        revision: u64,
        pinned_class: &[&str],
        pin_reserve_bytes: u64,
    ) -> String {
        use crate::fountain::storage_contention::{
            assemble_storage_budget_wire, storage_budget_preimage,
        };
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ciris_crypto::{ClassicalSigner, PqcSigner};
        let payload = serde_json::json!({
            "node_id": node_id,
            "epoch_id": "e1",
            "revision": revision,
            "scopes": [{
                "cohort_scope": "community",
                "budget_bytes": 100_000u64,
                "pin_reserve_bytes": pin_reserve_bytes,
            }],
            "pinned_class": pinned_class,
        })
        .to_string();
        let preimage = storage_budget_preimage(&payload).expect("valid §Q payload");
        let ed_sig = id.ed.sign(&preimage).unwrap();
        let mut bound = preimage.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = id.pqc.sign(&bound).unwrap();
        assemble_storage_budget_wire(&payload, B64.encode(&ed_sig), B64.encode(&pqc_sig))
            .expect("assemble signed budget wire")
    }

    /// #370 shared body — install happy path, getter read-back, and §Q B3
    /// anti-rollback (equal + lower revision rejected; higher supersedes;
    /// a tampered wire never reaches the store). `node_id` must be unique
    /// per run on shared databases (the PG twin).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn run_install_budget_assertions(engine: &Engine, node_id: &str) {
        use crate::fountain::storage_contention::verify_storage_budget_wire;
        let id = qshape_id();
        let (ed_pub, mldsa_pub) = qshape_pubs(&id);

        // Happy path: revision 3 installs.
        let wire3 = qshape_budget_wire(&id, node_id, 3, &["trace"], 2048);
        let rev = engine
            .install_storage_budget_v1(&wire3, &ed_pub, &mldsa_pub)
            .await
            .expect("install revision 3");
        assert_eq!(rev, 3);

        // Getter: the stored wire re-verifies end-to-end (PQC-mandatory)
        // against the same owner pubkeys — the budget stays provable after
        // install, not just at ingest.
        let got = engine
            .get_installed_storage_budget_json(node_id)
            .await
            .expect("getter")
            .expect("a budget is installed");
        verify_storage_budget_wire(&got, &ed_pub, &mldsa_pub)
            .expect("stored wire re-verifies (bound-hybrid)");

        // §Q B3 anti-rollback: EQUAL revision refused…
        let err = engine
            .install_storage_budget_v1(&wire3, &ed_pub, &mldsa_pub)
            .await
            .expect_err("equal revision must be refused");
        assert_eq!(err.kind(), "storage_contention_revision_rollback");
        // …and LOWER revision refused.
        let wire2 = qshape_budget_wire(&id, node_id, 2, &["trace"], 2048);
        let err = engine
            .install_storage_budget_v1(&wire2, &ed_pub, &mldsa_pub)
            .await
            .expect_err("lower revision must be refused");
        assert_eq!(err.kind(), "storage_contention_revision_rollback");

        // Strictly-higher revision supersedes.
        let wire5 = qshape_budget_wire(&id, node_id, 5, &["av_chunk", "trace"], 4096);
        assert_eq!(
            engine
                .install_storage_budget_v1(&wire5, &ed_pub, &mldsa_pub)
                .await
                .expect("higher revision supersedes"),
            5
        );
        let installed = engine
            .get_installed_storage_budget(node_id)
            .await
            .expect("typed getter")
            .expect("installed");
        assert_eq!(installed.revision, 5);
        assert_eq!(installed.pinned_class, vec!["av_chunk", "trace"]);
        assert_eq!(installed.pin_reserve_total(), 4096);

        // A tampered wire (revision bumped without re-signing) fails the
        // PQC-mandatory verify AT THE GATE — nothing persists; the
        // installed revision is unchanged.
        let mut tampered: serde_json::Value = serde_json::from_str(&wire5).unwrap();
        tampered["revision"] = serde_json::json!(9);
        let err = engine
            .install_storage_budget_v1(&tampered.to_string(), &ed_pub, &mldsa_pub)
            .await
            .expect_err("tampered wire must fail signature verify");
        assert_eq!(err.kind(), "storage_contention_signature_failed");
        assert_eq!(
            engine
                .get_installed_storage_budget(node_id)
                .await
                .unwrap()
                .unwrap()
                .revision,
            5,
            "verify-before-mutation: the tampered wire wrote nothing"
        );
    }

    /// #370 — install surface on SQLite.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn install_storage_budget_v1_happy_and_anti_rollback_sqlite() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct engine");
        run_install_budget_assertions(&engine, "n-370-sqlite").await;
    }

    /// #370 — install surface on Postgres (shared twin; uuid node_id keeps
    /// runs self-isolating). Skips when `CIRIS_PERSIST_TEST_PG_URL` unset.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn install_storage_budget_v1_happy_and_anti_rollback_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let engine = Engine::with_signer(test_signer(), &dsn)
            .await
            .expect("construct postgres engine");
        let node_id = format!("n-370-pg-{}", uuid::Uuid::new_v4().simple());
        run_install_budget_assertions(&engine, &node_id).await;
    }

    /// Seed `n` blobs of 1 KiB through `put_blob_signing` with the given
    /// `media_type` (the §Q corpus-class token), attested by the local
    /// signer's DERIVED key (which the caller must have registered).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn seed_typed_blobs(
        engine: &Engine,
        media_type: Option<&str>,
        fill_base: u8,
        n: usize,
    ) -> Vec<[u8; 32]> {
        use crate::federation::BlobBody;
        let derived = test_signer().derived_key_id();
        let mut shas = Vec::with_capacity(n);
        for i in 0..n {
            let bytes = vec![fill_base + i as u8; 1024];
            let sha = {
                use sha2::{Digest, Sha256};
                let mut out = [0u8; 32];
                out.copy_from_slice(&Sha256::digest(&bytes));
                out
            };
            engine
                .put_blob_signing(
                    &sha,
                    BlobBody::Inline(bytes),
                    media_type,
                    &derived,
                    chrono::Utc::now(),
                    uuid::Uuid::new_v4(),
                )
                .await
                .expect("put_blob_signing typed blob");
            shas.push(sha);
        }
        shas
    }

    /// Backend-agnostic `has_blob`.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn blob_present(engine: &Engine, sha: &[u8; 32]) -> bool {
        use crate::federation::BlobStorage;
        #[cfg(feature = "sqlite")]
        if let Some(sq) = engine.sqlite_backend() {
            return sq.has_blob(sha).await.expect("has_blob");
        }
        #[cfg(feature = "postgres")]
        if let Some(pg) = engine.postgres_backend() {
            return pg.has_blob(sha).await.expect("has_blob");
        }
        panic!("no durable backend on this engine");
    }

    /// Backend-agnostic access-count heater (each `get_blob` bumps V053
    /// access tracking, raising the decay score).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn heat_blob(engine: &Engine, sha: &[u8; 32], hits: usize) {
        use crate::federation::BlobStorage;
        for _ in 0..hits {
            #[cfg(feature = "sqlite")]
            if let Some(sq) = engine.sqlite_backend() {
                let _ = sq.get_blob(sha).await.expect("get_blob");
                continue;
            }
            #[cfg(feature = "postgres")]
            if let Some(pg) = engine.postgres_backend() {
                let _ = pg.get_blob(sha).await.expect("get_blob");
                continue;
            }
            #[allow(unreachable_code)]
            {
                panic!("no durable backend on this engine");
            }
        }
    }

    /// #370 §Q B5 shared body — CACHE BEFORE PINNED. 3 COLD pinned
    /// (`media_type = "trace"`) + 3 HOT unpinned blobs: under the standard
    /// decay order the cold pinned rows would be the victims; with the
    /// budget installed, the sweep must shed all 3 unpinned (hot!) rows
    /// first and hold every pinned row above the `pin_reserve_bytes` floor.
    ///
    /// Budget math: 6 × 1 KiB stored, watermark = 4 KiB × 0.5 = 2 KiB ⇒
    /// target_freed = 4 KiB. Unpinned frees 3 KiB, then the pinned floor
    /// (3 KiB reserve == pinned bytes held) blocks every pinned eviction —
    /// the sweep deliberately ends SHORT of target (the pin doing its job).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn run_b5_unpinned_before_pinned(engine: &Engine) {
        let pinned = seed_typed_blobs(engine, Some("trace"), 0x10, 3).await;
        let unpinned = seed_typed_blobs(engine, None, 0x40, 3).await;
        for sha in &unpinned {
            heat_blob(engine, sha, 20).await;
        }
        let id = qshape_id();
        let (ed_pub, mldsa_pub) = qshape_pubs(&id);
        let wire = qshape_budget_wire(&id, "n-b5-order", 1, &["trace"], 3 * 1024);
        engine
            .install_storage_budget_v1(&wire, &ed_pub, &mldsa_pub)
            .await
            .expect("install the pin");

        let report = engine.sweep_evictions_once().await.expect("B5 sweep");
        assert_eq!(
            report.rows_evicted, 3,
            "exactly the 3 unpinned rows evicted: {report:?}"
        );
        for sha in &unpinned {
            assert!(
                !blob_present(engine, sha).await,
                "unpinned (cache) content evicts FIRST, even when hot (§Q B5)"
            );
        }
        for sha in &pinned {
            assert!(
                blob_present(engine, sha).await,
                "pinned content survives capacity pressure above the reserve floor (§Q B5)"
            );
        }
    }

    /// #370 §Q B5 shared body — once unpinned is exhausted, pinned content
    /// DOES descend under continued capacity pressure, but only down to the
    /// `pin_reserve_bytes` floor.
    ///
    /// Budget math: 3 pinned + 2 unpinned × 1 KiB = 5 KiB stored, watermark
    /// = 1 KiB × 0.5 = 512 B ⇒ target_freed ≈ 4.5 KiB. Unpinned frees
    /// 2 KiB; pinned then sheds until held-pinned would drop below the
    /// 1 KiB reserve ⇒ exactly 2 of 3 pinned evicted, 1 held at the floor.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn run_b5_reserve_floor(engine: &Engine) {
        let pinned = seed_typed_blobs(engine, Some("trace"), 0x10, 3).await;
        let unpinned = seed_typed_blobs(engine, None, 0x40, 2).await;
        let id = qshape_id();
        let (ed_pub, mldsa_pub) = qshape_pubs(&id);
        let wire = qshape_budget_wire(&id, "n-b5-floor", 1, &["trace"], 1024);
        engine
            .install_storage_budget_v1(&wire, &ed_pub, &mldsa_pub)
            .await
            .expect("install the pin");

        let report = engine.sweep_evictions_once().await.expect("B5 sweep");
        for sha in &unpinned {
            assert!(
                !blob_present(engine, sha).await,
                "unpinned evicts before any pinned row (§Q B5)"
            );
        }
        let mut pinned_surviving = 0usize;
        for sha in &pinned {
            if blob_present(engine, sha).await {
                pinned_surviving += 1;
            }
        }
        assert_eq!(
            pinned_surviving, 1,
            "pinned descends only to the pin_reserve_bytes floor (1 KiB): {report:?}"
        );
        assert_eq!(report.rows_evicted, 4, "2 unpinned + 2 pinned: {report:?}");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sweeper_b5_evicts_unpinned_before_pinned_sqlite() {
        let cfg = crate::federation::ReplicationConfig {
            storage_budget_bytes: 4 * 1024,
            steady_state_utilization: 0.5,
            eviction_decay_half_life_days: 365.0,
            ..Default::default()
        };
        let (engine, _shas) = sweeper_seed_blobs(cfg, 0).await;
        run_b5_unpinned_before_pinned(&engine).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sweeper_b5_holds_pin_reserve_floor_sqlite() {
        let cfg = crate::federation::ReplicationConfig {
            storage_budget_bytes: 1024,
            steady_state_utilization: 0.5,
            eviction_decay_half_life_days: 365.0,
            ..Default::default()
        };
        let (engine, _shas) = sweeper_seed_blobs(cfg, 0).await;
        run_b5_reserve_floor(&engine).await;
    }

    /// Create an ISOLATED database on the PG twin (the sweep ranks the
    /// WHOLE `federation_blobs` table, so byte-exact ordering assertions
    /// cannot self-isolate by uuid the way row-keyed tests do). Returns
    /// `(dsn, db_name)`; `None` (skip) when the twin is unset.
    #[cfg(feature = "postgres")]
    async fn pg_isolated_db(tag: &str) -> Option<(String, String)> {
        let Ok(base) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return None;
        };
        let db = format!("persist_370_{}_{}", tag, uuid::Uuid::new_v4().simple());
        let (client, conn) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
            .await
            .expect("admin connect to PG twin");
        let conn_handle = tokio::spawn(conn);
        client
            .execute(format!("CREATE DATABASE {db}").as_str(), &[])
            .await
            .expect("create isolated database");
        drop(client);
        conn_handle.abort();
        let (prefix, _) = base.rsplit_once('/').expect("dsn has a database path");
        Some((format!("{prefix}/{db}"), db))
    }

    /// Best-effort drop of the isolated database (FORCE terminates any
    /// pool connection the dropped Engine hasn't torn down yet).
    #[cfg(feature = "postgres")]
    async fn pg_drop_isolated_db(db: &str) {
        let Ok(base) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            return;
        };
        if let Ok((client, conn)) = tokio_postgres::connect(&base, tokio_postgres::NoTls).await {
            let conn_handle = tokio::spawn(conn);
            let _ = client
                .execute(format!("DROP DATABASE {db} WITH (FORCE)").as_str(), &[])
                .await;
            drop(client);
            conn_handle.abort();
        }
    }

    /// PG twin of `sweeper_seed_blobs`'s engine setup: replication config +
    /// the local signer's DERIVED federation key registered.
    #[cfg(feature = "postgres")]
    async fn sweeper_engine_pg(cfg: crate::federation::ReplicationConfig, dsn: &str) -> Engine {
        use crate::federation::FederationDirectory;
        let signer = test_signer();
        let derived = signer.derived_key_id();
        let engine = Engine::with_replication_config(signer, dsn, cfg)
            .await
            .expect("construct postgres engine");
        let pg = engine.postgres_backend().expect("postgres present");
        pg.put_public_key(sweeper_test_key_derived_for(
            &derived,
            "test-engine-steward",
        ))
        .await
        .expect("seed signer key");
        engine
    }

    /// #370 §Q B5 on Postgres — same shared body as the SQLite twin, on an
    /// isolated database (whole-table sweep). Skips when the twin is unset.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn sweeper_b5_evicts_unpinned_before_pinned_postgres() {
        let Some((dsn, db)) = pg_isolated_db("b5order").await else {
            return;
        };
        {
            let cfg = crate::federation::ReplicationConfig {
                storage_budget_bytes: 4 * 1024,
                steady_state_utilization: 0.5,
                eviction_decay_half_life_days: 365.0,
                ..Default::default()
            };
            let engine = sweeper_engine_pg(cfg, &dsn).await;
            run_b5_unpinned_before_pinned(&engine).await;
        }
        pg_drop_isolated_db(&db).await;
    }

    /// #370 §Q B5 reserve floor on Postgres (isolated database).
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn sweeper_b5_holds_pin_reserve_floor_postgres() {
        let Some((dsn, db)) = pg_isolated_db("b5floor").await else {
            return;
        };
        {
            let cfg = crate::federation::ReplicationConfig {
                storage_budget_bytes: 1024,
                steady_state_utilization: 0.5,
                eviction_decay_half_life_days: 365.0,
                ..Default::default()
            };
            let engine = sweeper_engine_pg(cfg, &dsn).await;
            run_b5_reserve_floor(&engine).await;
        }
        pg_drop_isolated_db(&db).await;
    }

    // ─── v6.8.0 (CIRISPersist#149) — proactive disk-pressure ENFORCEMENT ───

    /// Build a disk-pressure config whose family predicate matches
    /// `"family-key"`, plus a `StubFreeBytes`-driven monitor, and attach
    /// both (config + live snapshot receiver) to `engine`. Returns the
    /// reconfigured engine, the stub (to drive tiers), and the monitor
    /// (to `poll_once` after each stub change).
    #[cfg(feature = "sqlite")]
    fn attach_disk_pressure(
        engine: Engine,
        initial_free_bytes: u64,
    ) -> (
        Engine,
        std::sync::Arc<crate::federation::StubFreeBytes>,
        std::sync::Arc<crate::federation::DiskPressureMonitor>,
    ) {
        let fam: crate::federation::FamilyPredicate =
            std::sync::Arc::new(|k: &str| k == "family-key");
        let cfg = std::sync::Arc::new(crate::federation::DiskPressureConfig {
            monitor_path: std::path::PathBuf::from("/x"),
            is_family: Some(fam),
            ..Default::default()
        });
        let stub = std::sync::Arc::new(crate::federation::StubFreeBytes::new(initial_free_bytes));
        let monitor = std::sync::Arc::new(crate::federation::DiskPressureMonitor::with_source(
            (*cfg).clone(),
            stub.clone(),
        ));
        monitor.poll_once();
        let engine = engine
            .with_disk_pressure_config_shared(cfg)
            .with_disk_pressure_state_shared(monitor.subscribe());
        (engine, stub, monitor)
    }

    #[cfg(feature = "sqlite")]
    const TWO_GIB: u64 = 2 * 1024 * 1024 * 1024;
    #[cfg(feature = "sqlite")]
    const FOUR_HUNDRED_MIB: u64 = 400 * 1024 * 1024;

    /// Seed a `federation_keys` row for `key_id` so a proxy/family
    /// `attesting_key_id` FK resolves.
    #[cfg(feature = "sqlite")]
    async fn seed_key(engine: &Engine, key_id: &str) {
        use crate::federation::FederationDirectory;
        let sq = engine.sqlite_backend().expect("sqlite");
        sq.put_public_key(sweeper_test_key(key_id))
            .await
            .expect("seed key");
    }

    #[cfg(feature = "sqlite")]
    fn blob_for(fill: u8) -> ([u8; 32], Vec<u8>) {
        let bytes = vec![fill; 256];
        use sha2::{Digest, Sha256};
        let mut sha = [0u8; 32];
        sha.copy_from_slice(&Sha256::digest(&bytes));
        (sha, bytes)
    }

    /// v6.8.0 (CIRISPersist#149) — at the STOP tier a PROXY write is
    /// refused (typed `DiskPressureProxyRefused`) while LOCAL + FAMILY
    /// writes still succeed.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn stop_tier_refuses_proxy_write_allows_local_family_sqlite() {
        use crate::federation::{BlobBody, BlobError};
        let cfg = crate::federation::ReplicationConfig::default();
        // Reuse the seeded local-signer engine (signer = test-engine-steward).
        let (engine, _shas) = sweeper_seed_blobs(cfg, 0).await;
        seed_key(&engine, "family-key").await;
        seed_key(&engine, "stranger-key").await;
        // Start above warn (Normal), then drop to stop.
        let (engine, stub, monitor) = attach_disk_pressure(engine, TWO_GIB);

        // Sanity: below stop, a proxy write succeeds.
        let (sha_a, body_a) = blob_for(1);
        engine
            .put_blob_signing(
                &sha_a,
                BlobBody::Inline(body_a),
                None,
                "stranger-key",
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .expect("proxy write below stop tier should succeed");

        // Drop to STOP tier (400 MiB free <= 500 MiB stop threshold).
        stub.set(FOUR_HUNDRED_MIB);
        monitor.poll_once();
        assert_eq!(
            engine.current_disk_pressure().tier,
            crate::federation::PressureTier::Stop
        );

        // PROXY write now refused with the typed error.
        let (sha_b, body_b) = blob_for(2);
        let err = engine
            .put_blob_signing(
                &sha_b,
                BlobBody::Inline(body_b),
                None,
                "stranger-key",
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .expect_err("proxy write at stop tier must be refused");
        match err {
            BlobError::DiskPressureProxyRefused { operation, tier } => {
                assert_eq!(operation, "accept");
                assert_eq!(tier, "stop");
            }
            other => panic!("expected DiskPressureProxyRefused, got {other:?}"),
        }

        // LOCAL write (attester == local signer's DERIVED id, #247) still
        // succeeds.
        let local_id = test_signer().derived_key_id();
        let (sha_c, body_c) = blob_for(3);
        engine
            .put_blob_signing(
                &sha_c,
                BlobBody::Inline(body_c),
                None,
                &local_id,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .expect("local write must never be refused");

        // FAMILY write still succeeds.
        let (sha_d, body_d) = blob_for(4);
        engine
            .put_blob_signing(
                &sha_d,
                BlobBody::Inline(body_d),
                None,
                "family-key",
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .expect("family write must never be refused");
    }

    /// v6.8.0 (CIRISPersist#149) — at the STOP tier a PROXY serve is
    /// refused while a LOCAL serve still returns bytes. Below stop, the
    /// proxy serve succeeds.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn stop_tier_refuses_proxy_serve_allows_local_sqlite() {
        use crate::federation::BlobError;
        let cfg = crate::federation::ReplicationConfig::default();
        let (engine, local_shas) = sweeper_seed_blobs(cfg, 1).await; // local blob (local holds_bytes)
        let local_sha = local_shas[0];
        // A proxy blob: holds_bytes by a peer (not local/family).
        let proxy_shas = seed_proxy_blobs(&engine, "peer-relay-key", 1).await;
        let proxy_sha = proxy_shas[0];

        let (engine, stub, monitor) = attach_disk_pressure(engine, TWO_GIB);

        // Below stop: proxy serve succeeds.
        engine
            .serve_blob_to_peer(&proxy_sha, "some-peer")
            .await
            .expect("proxy serve below stop tier should succeed");

        // Drop to STOP.
        stub.set(FOUR_HUNDRED_MIB);
        monitor.poll_once();
        assert!(engine.current_disk_pressure().refuses_proxy_serves);

        // PROXY serve refused.
        let err = engine
            .serve_blob_to_peer(&proxy_sha, "some-peer")
            .await
            .expect_err("proxy serve at stop tier must be refused");
        match err {
            BlobError::DiskPressureProxyRefused { operation, tier } => {
                assert_eq!(operation, "serve");
                assert_eq!(tier, "stop");
            }
            other => panic!("expected DiskPressureProxyRefused, got {other:?}"),
        }

        // LOCAL serve still returns bytes (local holds_bytes ⇒ protected).
        engine
            .serve_blob_to_peer(&local_sha, "some-peer")
            .await
            .expect("local serve must never be refused");
    }

    /// v6.8.0 (CIRISPersist#149) — below the stop tier (warn/crit), both
    /// proxy writes and proxy serves succeed (no enforcement until stop).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn below_stop_tier_proxy_write_and_serve_succeed_sqlite() {
        use crate::federation::BlobBody;
        let cfg = crate::federation::ReplicationConfig::default();
        let (engine, _shas) = sweeper_seed_blobs(cfg, 0).await;
        seed_key(&engine, "stranger-key").await;
        // Start at CRIT (1 GiB free <= 1 GiB crit, > 500 MiB stop):
        // crit force-evicts proxy but does NOT refuse writes/serves.
        let one_gib = 1024 * 1024 * 1024;
        let (engine, _stub, _monitor) = attach_disk_pressure(engine, one_gib);
        assert_eq!(
            engine.current_disk_pressure().tier,
            crate::federation::PressureTier::Crit
        );
        assert!(!engine.current_disk_pressure().refuses_proxy_writes);

        // Proxy WRITE succeeds at crit.
        let (sha_a, body_a) = blob_for(7);
        engine
            .put_blob_signing(
                &sha_a,
                BlobBody::Inline(body_a),
                None,
                "stranger-key",
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .expect("proxy write at crit tier should succeed");

        // Proxy SERVE succeeds at crit.
        engine
            .serve_blob_to_peer(&sha_a, "some-peer")
            .await
            .expect("proxy serve at crit tier should succeed");
    }

    // ── v4.6.0 (CIRISPersist#171, CEG §10.1.5) — attestation_promote:
    //    local-tier self-attestation → federation-tier hybrid-signed row.

    /// PQC-configured signer whose classical alias is `occ`, so the
    /// producing occurrence (`attesting_key_id`) and the promotion
    /// signer (`scrub_key_id = current_alias()`) are the same
    /// federation key — one seeded `federation_keys` row satisfies both
    /// FKs. `attestation_promote` calls `sign_hybrid`, so PQC is required.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn pqc_signer(alias: &str) -> Arc<LocalSigner> {
        use ciris_keyring::MlDsa65SoftwareSigner;
        let signing_key = SigningKey::from_bytes(&[0x5Au8; 32]);
        let pqc = MlDsa65SoftwareSigner::from_seed_bytes(&[0x5Au8 ^ 0x55; 32], "promote-test-pqc")
            .expect("pqc seed");
        let pqc_arc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(pqc);
        Arc::new(LocalSigner::from_parts(
            signing_key,
            alias.to_owned(),
            Some(pqc_arc),
            Some("promote-test-pqc".to_owned()),
        ))
    }

    /// Seed a `federation_keys` row for `key_id` so the local-tier write
    /// gate's `attesting_key_id` FK and the promote path's `scrub_key_id`
    /// FK both hold.
    #[cfg(feature = "sqlite")]
    async fn seed_promote_key(sq: &Arc<SqliteBackend>, key_id: &str) {
        use crate::federation::{FederationDirectory, KeyRecord, SignedKeyRecord};
        let record = KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::STEWARD.into(),
            identity_ref: key_id.into(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": key_id }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        sq.put_public_key(SignedKeyRecord { record }).await.unwrap();
    }

    /// Round-trip: write a `local` self-attestation, promote it, confirm
    /// the row flips to `federation` with a populated hybrid scrub
    /// envelope, a recomputed `original_content_hash`, and the producing
    /// occurrence as `scrub_key_id`. A second promote is idempotent
    /// (`Ok(false)`, no further mutation).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn attestation_promote_flips_local_to_federation_signed() {
        use crate::federation::types::attestation_type::SCORES;
        use crate::federation::FederationDirectory;

        let signer = pqc_signer("occ");
        // v9.3.0 (#247) — the real-node shape: keystore alias ("occ") ≠
        // registered derived federation key_id. Seed the row + the local
        // attestation under the DERIVED id; the producer attests as the
        // derived id and promote must scrub as the derived id (FK holds).
        let derived = signer.derived_key_id();
        assert_ne!(derived, "occ", "derived id differs from the alias");
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("construct engine");
        let sq = engine.sqlite_backend().expect("sqlite present").clone();
        seed_promote_key(&sq, &derived).await;

        // Write a local-tier self-attestation (signature deferred).
        let input = crate::federation::types::LocalAttestationInput {
            attesting_key_id: derived.clone(),
            attested_key_id: None,
            attestation_type: SCORES.into(),
            weight: Some(1.0),
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "id": "att-1", "dimension": "identity_binding:v1",
                "score": 1.0, "confidence": 0.9,
            }),
            subject_key_ids: vec![],
            cohort_scope: crate::federation::types::cohort_scope::SELF.to_string(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        };
        let att_id = sq.attestation_upsert_local(input).await.unwrap();

        // Pre-promote: the row is local with an empty-sentinel scrub.
        let before = sq.get_attestation(&att_id).await.unwrap().expect("row");
        assert_eq!(
            before.tier,
            crate::federation::types::attestation_tier::LOCAL
        );
        assert!(before.scrub_signature_classical.is_empty());
        assert!(before.original_content_hash.is_empty());
        assert!(before.promoted_at.is_none());

        // Promote.
        let promoted = engine.attestation_promote(&att_id).await.unwrap();
        assert!(promoted, "first promote flips the tier");

        let after = sq.get_attestation(&att_id).await.unwrap().expect("row");
        assert_eq!(
            after.tier,
            crate::federation::types::attestation_tier::FEDERATION,
            "tier flips to federation"
        );
        assert!(
            !after.scrub_signature_classical.is_empty(),
            "Ed25519 scrub signature populated"
        );
        assert!(
            after
                .scrub_signature_pqc
                .as_deref()
                .is_some_and(|s| !s.is_empty()),
            "ML-DSA-65 scrub signature populated"
        );
        assert_eq!(
            after.original_content_hash.len(),
            64,
            "original_content_hash is the hex SHA-256 of the canonical envelope"
        );
        assert_eq!(
            after.scrub_key_id, derived,
            "promoter scrub_key_id is the DERIVED federation key_id, not the alias (#247)"
        );
        assert!(after.promoted_at.is_some(), "promoted_at stamped");
        // Envelope is untouched by promotion (signing reads it, never edits).
        assert_eq!(after.attestation_envelope, before.attestation_envelope);

        // Idempotent: re-promoting a federation row is a no-op.
        let again = engine.attestation_promote(&att_id).await.unwrap();
        assert!(!again, "re-promote of a federation row returns Ok(false)");
        let after2 = sq.get_attestation(&att_id).await.unwrap().expect("row");
        assert_eq!(
            after2.scrub_signature_classical, after.scrub_signature_classical,
            "idempotent re-promote does not re-sign"
        );
        assert_eq!(after2.promoted_at, after.promoted_at);
    }

    /// Promoting a non-existent row is an `InvalidArgument`, not a panic
    /// or a silent success.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn attestation_promote_missing_row_is_invalid_argument() {
        let engine = Engine::with_signer(pqc_signer("occ"), "sqlite::memory:")
            .await
            .expect("construct engine");
        let err = engine
            .attestation_promote("00000000-0000-0000-0000-000000000000")
            .await
            .expect_err("missing row");
        assert!(
            matches!(err, crate::federation::Error::InvalidArgument(ref m) if m.contains("does not exist")),
            "got: {err:?}"
        );
    }

    /// Live-PG twin of `attestation_promote_flips_local_to_federation_signed`.
    /// Exercises the Postgres `get_attestation` + `promote_attestation`
    /// backend impls end-to-end through the Engine orchestrator. Skips
    /// when `CIRIS_PERSIST_TEST_PG_URL` is unset.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn attestation_promote_flips_local_to_federation_signed_postgres() {
        use crate::federation::types::attestation_type::SCORES;
        use crate::federation::{FederationDirectory, KeyRecord, SignedKeyRecord};

        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        // Unique occurrence alias so concurrent/shared-DB runs don't
        // collide. v9.3.0 (#247): the registered federation key_id is the
        // DERIVED id `derive_key_id(alias, pubkey)`, distinct from the
        // alias — the real-node shape that FK-violated before the fix.
        let alias = format!("occ-promote-{}", uuid::Uuid::new_v4().simple());
        let signer = pqc_signer(&alias);
        let occ = signer.derived_key_id();
        assert_ne!(occ, alias, "derived id differs from the alias");

        let engine = Engine::with_signer(signer, &dsn)
            .await
            .expect("construct PG engine");
        let pg = engine.postgres_backend().expect("pg backend");

        // Seed the federation_keys row for both attesting + scrub FKs.
        let record = KeyRecord {
            key_id: occ.clone(),
            pubkey_ed25519_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::STEWARD.into(),
            identity_ref: occ.clone(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": occ.clone() }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: occ.clone(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        pg.put_public_key(SignedKeyRecord { record }).await.unwrap();

        let input = crate::federation::types::LocalAttestationInput {
            attesting_key_id: occ.clone(),
            attested_key_id: None,
            attestation_type: SCORES.into(),
            weight: Some(1.0),
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "id": "att-pg-1", "dimension": "identity_binding:v1",
                "score": 1.0, "confidence": 0.9,
            }),
            subject_key_ids: vec![],
            cohort_scope: crate::federation::types::cohort_scope::SELF.to_string(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        };
        let att_id = pg.attestation_upsert_local(input).await.unwrap();

        let before = pg.get_attestation(&att_id).await.unwrap().expect("row");
        assert_eq!(
            before.tier,
            crate::federation::types::attestation_tier::LOCAL
        );
        assert!(before.scrub_signature_classical.is_empty());
        assert!(before.original_content_hash.is_empty());

        let promoted = engine.attestation_promote(&att_id).await.unwrap();
        assert!(promoted, "first promote flips the tier");

        let after = pg.get_attestation(&att_id).await.unwrap().expect("row");
        assert_eq!(
            after.tier,
            crate::federation::types::attestation_tier::FEDERATION
        );
        assert!(!after.scrub_signature_classical.is_empty());
        assert!(after
            .scrub_signature_pqc
            .as_deref()
            .is_some_and(|s| !s.is_empty()));
        assert_eq!(after.original_content_hash.len(), 64);
        assert_eq!(after.scrub_key_id, occ);
        assert!(after.promoted_at.is_some());
        assert_eq!(after.attestation_envelope, before.attestation_envelope);

        // Idempotent re-promote.
        let again = engine.attestation_promote(&att_id).await.unwrap();
        assert!(!again, "re-promote of a federation row returns Ok(false)");
        let after2 = pg.get_attestation(&att_id).await.unwrap().expect("row");
        assert_eq!(
            after2.scrub_signature_classical,
            after.scrub_signature_classical
        );
        assert_eq!(after2.promoted_at, after.promoted_at);
    }

    // ── v9.3.0 (CIRISPersist#247 + #248) CEG-DX foundation ──

    /// #247 — `local_derived_key_id()` reproduces
    /// `derive_key_id(<keystore alias>, <ed25519 pubkey>)`, distinct from
    /// the alias.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn local_derived_key_id_is_the_derived_not_the_alias() {
        let signer = pqc_signer("ciris-client");
        let expected = ciris_verify_core::fedcode::derive_key_id(
            "ciris-client",
            &signer.ed25519_public_key_bytes(),
        );
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine");
        let got = engine.local_derived_key_id().await.expect("derive");
        assert_eq!(got, expected, "resolver == derive_key_id(alias, pubkey)");
        assert_ne!(got, "ciris-client", "derived id ≠ keystore alias");
        assert!(
            got.starts_with("ciris-client-"),
            "derived id is `<label>-<fp>`, got {got}"
        );
    }

    /// #248 — `emit_attestation` produces a federation-tier row whose
    /// attester/scrub key is the signer's DERIVED key_id (so the FK to
    /// `federation_keys` holds when the key is registered under the derived
    /// id — the real-node shape), with a populated hybrid scrub envelope and
    /// a recomputed `original_content_hash`.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn emit_attestation_round_trip_derives_key_id_sqlite() {
        use crate::federation::types::attestation_type::SCORES;
        use crate::federation::FederationDirectory;

        // Real deterministic hybrid keypair so the federation-tier ingest
        // gate (`put_attestation`) verifies the emitted scrub signature.
        let signer = crate::federation::tier_ingest::test_support::local_signer("ciris-client");
        let derived = signer.derived_key_id();
        assert_ne!(derived, "ciris-client", "alias ≠ derived");
        let engine = Engine::with_signer(signer.clone(), "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        // Register the key under the DERIVED id (the FK target) carrying
        // "ciris-client"'s REAL pubkeys so the gate's hybrid-verify passes.
        sq.put_public_key(sweeper_test_key_derived_for(&derived, "ciris-client"))
            .await
            .expect("seed key");

        let input = crate::federation::EmitAttestationInput::with_envelope(
            SCORES,
            serde_json::json!({
                "id": "emit-1", "dimension": "identity_binding:v1",
                "score": 1.0, "confidence": 0.9,
            }),
        );
        let att_id = engine
            .emit_attestation(&signer, input)
            .await
            .expect("emit_attestation (FK holds on the derived id)");

        let row = sq.get_attestation(&att_id).await.unwrap().expect("row");
        assert_eq!(
            row.tier,
            crate::federation::types::attestation_tier::FEDERATION,
            "emitted at federation tier"
        );
        assert_eq!(
            row.attesting_key_id, derived,
            "attester is the DERIVED key_id, not the alias (#247 floor)"
        );
        assert_eq!(row.scrub_key_id, derived, "scrub == derived key_id");
        assert_eq!(
            row.attested_key_id, derived,
            "self-attestation default = derived key_id"
        );
        assert_eq!(row.cohort_scope, "federation", "default federation scope");
        assert!(
            !row.scrub_signature_classical.is_empty(),
            "Ed25519 scrub populated"
        );
        assert!(
            row.scrub_signature_pqc
                .as_deref()
                .is_some_and(|s| !s.is_empty()),
            "ML-DSA-65 scrub populated"
        );
        assert_eq!(
            row.original_content_hash.len(),
            64,
            "original_content_hash is the hex SHA-256 of the canonical envelope"
        );
    }

    /// #248 PG twin — `emit_attestation` over the live Postgres backend:
    /// the FK to `federation_keys` (registered under the derived id) holds
    /// end-to-end. Skips when `CIRIS_PERSIST_TEST_PG_URL` is unset.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn emit_attestation_round_trip_derives_key_id_postgres() {
        use crate::federation::types::attestation_type::SCORES;
        use crate::federation::FederationDirectory;

        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        // Unique label per run; real deterministic hybrid keypair so the
        // ingest gate verifies the emitted scrub signature.
        let label = format!("emit-{}", uuid::Uuid::new_v4().simple());
        let signer = crate::federation::tier_ingest::test_support::local_signer(&label);
        let derived = signer.derived_key_id();
        assert_ne!(derived, label, "alias ≠ derived");

        let engine = Engine::with_signer(signer.clone(), &dsn)
            .await
            .expect("pg engine");
        let pg = engine.postgres_backend().expect("pg backend");

        // Register the steward key under the DERIVED id (the FK target),
        // carrying `label`'s real pubkeys so hybrid-verify passes.
        pg.put_public_key(sweeper_test_key_derived_for(&derived, &label))
            .await
            .unwrap();

        let input = crate::federation::EmitAttestationInput::with_envelope(
            SCORES,
            serde_json::json!({
                "id": "emit-pg-1", "dimension": "identity_binding:v1",
                "score": 1.0, "confidence": 0.9,
            }),
        );
        let att_id = engine
            .emit_attestation(&signer, input)
            .await
            .expect("emit_attestation FK holds on derived id");

        let row = pg.get_attestation(&att_id).await.unwrap().expect("row");
        assert_eq!(
            row.tier,
            crate::federation::types::attestation_tier::FEDERATION
        );
        assert_eq!(row.attesting_key_id, derived);
        assert_eq!(row.scrub_key_id, derived);
        assert_eq!(row.original_content_hash.len(), 64);
        assert!(!row.scrub_signature_classical.is_empty());
        assert!(row
            .scrub_signature_pqc
            .as_deref()
            .is_some_and(|s| !s.is_empty()));
    }

    // ── v9.4.0 (CIRISPersist#253 / #252) — emit_attestation_self + weight ──

    /// #253 — `emit_attestation_self` on a **software** engine signs over the
    /// engine's composed signer and derives attester/scrub from
    /// `local_derived_key_id()`, producing the SAME row shape as
    /// `emit_attestation(&signer, …)`: federation tier, attester == scrub ==
    /// derived key_id, self-attested, populated hybrid scrub.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn emit_attestation_self_software_matches_emit_attestation_sqlite() {
        use crate::federation::types::attestation_type::SCORES;
        use crate::federation::FederationDirectory;

        let signer = crate::federation::tier_ingest::test_support::local_signer("ciris-self");
        let derived = signer.derived_key_id();
        let engine = Engine::with_signer(signer.clone(), "sqlite::memory:")
            .await
            .expect("engine");
        // `local_derived_key_id()` (the value emit_attestation_self uses)
        // matches the LocalSigner's derived_key_id (#247 floor).
        assert_eq!(
            engine.local_derived_key_id().await.expect("derive"),
            derived,
            "composed-signer derived id == LocalSigner derived id"
        );
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        sq.put_public_key(sweeper_test_key_derived_for(&derived, "ciris-self"))
            .await
            .expect("seed key");

        let input = crate::federation::EmitAttestationInput::with_envelope(
            SCORES,
            serde_json::json!({
                "id": "emit-self-1", "dimension": "identity_binding:v1",
                "score": 1.0, "confidence": 0.9,
            }),
        );
        let att_id = engine
            .emit_attestation_self(input)
            .await
            .expect("emit_attestation_self over composed signer");

        let row = sq.get_attestation(&att_id).await.unwrap().expect("row");
        assert_eq!(
            row.tier,
            crate::federation::types::attestation_tier::FEDERATION
        );
        assert_eq!(
            row.attesting_key_id, derived,
            "attester == derived key_id of the composed signer (#247 floor)"
        );
        assert_eq!(row.scrub_key_id, derived, "scrub == derived key_id");
        assert_eq!(
            row.attested_key_id, derived,
            "self-attestation default = derived key_id"
        );
        assert!(!row.scrub_signature_classical.is_empty());
        assert!(row
            .scrub_signature_pqc
            .as_deref()
            .is_some_and(|s| !s.is_empty()));
        assert_eq!(row.original_content_hash.len(), 64);
        assert_eq!(row.weight, None, "no weight set ⇒ default None");
    }

    /// CIRISPersist#293 (CC 2.6.3 / §0.6) — `emit_attestation_self` REFUSES a
    /// `subject_key_ids[]` element that is not canonical lowercase (the
    /// uppercase-hex case from the issue repro). The check lives in the
    /// shared assemble body, so `emit_attestation` enforces it identically.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn emit_attestation_self_rejects_uppercase_subject_key_id_293() {
        use crate::federation::types::attestation_type::SCORES;
        use crate::federation::FederationDirectory;

        let signer = crate::federation::tier_ingest::test_support::local_signer("ciris-self");
        let derived = signer.derived_key_id();
        let engine = Engine::with_signer(signer.clone(), "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        sq.put_public_key(sweeper_test_key_derived_for(&derived, "ciris-self"))
            .await
            .expect("seed key");

        // Uppercase-hex subject id (the issue repro) — must be refused.
        let upper = "FF7C5632DAE6EF3AE7F6283BD35268BC7910332414AA8A1C35A1645CA0295F61";
        let mut bad = crate::federation::EmitAttestationInput::with_envelope(
            SCORES,
            serde_json::json!({
                "id": "emit-self-293", "dimension": "identity_binding:v1",
                "score": 1.0, "confidence": 0.9,
            }),
        );
        bad.subject_key_ids = vec![upper.to_owned()];
        let err = engine
            .emit_attestation_self(bad)
            .await
            .expect_err("uppercase subject_key_id must be refused (#293)");
        assert!(
            matches!(err, crate::federation::Error::InvalidArgument(_)),
            "expected InvalidArgument, got {err:?}"
        );

        // The canonical lowercase form of the SAME id is admitted — the rule
        // rejects the encoding, not the subject.
        let mut ok = crate::federation::EmitAttestationInput::with_envelope(
            SCORES,
            serde_json::json!({
                "id": "emit-self-293-ok", "dimension": "identity_binding:v1",
                "score": 1.0, "confidence": 0.9,
            }),
        );
        ok.subject_key_ids = vec![upper.to_lowercase()];
        engine
            .emit_attestation_self(ok)
            .await
            .expect("lowercase subject_key_id is admitted");
    }

    /// #253 PG twin — `emit_attestation_self` over the composed signer on a
    /// live Postgres backend. Skips when `CIRIS_PERSIST_TEST_PG_URL` unset.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn emit_attestation_self_software_postgres() {
        use crate::federation::types::attestation_type::SCORES;
        use crate::federation::FederationDirectory;

        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let label = format!("emit-self-{}", uuid::Uuid::new_v4().simple());
        let signer = crate::federation::tier_ingest::test_support::local_signer(&label);
        let derived = signer.derived_key_id();
        let engine = Engine::with_signer(signer.clone(), &dsn)
            .await
            .expect("pg engine");
        let pg = engine.postgres_backend().expect("pg backend");
        pg.put_public_key(sweeper_test_key_derived_for(&derived, &label))
            .await
            .unwrap();

        let input = crate::federation::EmitAttestationInput::with_envelope(
            SCORES,
            serde_json::json!({
                "id": "emit-self-pg-1", "dimension": "identity_binding:v1",
                "score": 1.0, "confidence": 0.9,
            }),
        );
        let att_id = engine
            .emit_attestation_self(input)
            .await
            .expect("emit_attestation_self FK holds on derived id");

        let row = pg.get_attestation(&att_id).await.unwrap().expect("row");
        assert_eq!(
            row.tier,
            crate::federation::types::attestation_tier::FEDERATION
        );
        assert_eq!(row.attesting_key_id, derived);
        assert_eq!(row.scrub_key_id, derived);
        assert_eq!(row.original_content_hash.len(), 64);
        assert!(!row.scrub_signature_classical.is_empty());
        assert!(row
            .scrub_signature_pqc
            .as_deref()
            .is_some_and(|s| !s.is_empty()));
    }

    /// #253 — THE deliverable: a **hardware-hybrid** engine
    /// (`with_hardware_signer_hybrid`, which holds only a composed signer and
    /// no external `LocalSigner` to hand to `emit_attestation`) emits a
    /// federation-tier row via `emit_attestation_self`. We register the key
    /// under the engine's `local_derived_key_id()` carrying the HARDWARE
    /// signer's real Ed25519 pubkey + the ML-DSA-65 half's pubkey, so the
    /// federation-tier ingest gate hybrid-verifies the composed scrub sig.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn emit_attestation_self_hardware_hybrid_emits_sqlite() {
        use crate::federation::types::attestation_type::SCORES;
        use crate::federation::{FederationDirectory, KeyRecord, SignedKeyRecord};
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

        let classical = hw_classical("hw-self-steward");
        let hw_pubkey = classical.public_key().await.expect("hw pubkey");
        let pqc = pqc_half();
        let pqc_pubkey = pqc.public_key().await.expect("pqc pubkey");

        let engine = Engine::with_hardware_signer_hybrid(
            classical.clone(),
            Some(pqc),
            Some("hw-hybrid-pqc".to_owned()),
            "sqlite::memory:",
        )
        .await
        .expect("construct hybrid-hardware engine");

        // The engine has NO external LocalSigner to hand to
        // `emit_attestation` — `emit_attestation_self` is the only path.
        let derived = engine.local_derived_key_id().await.expect("derive");
        let sq = engine.sqlite_backend().expect("sqlite").clone();

        // Register the key under the derived id with the HARDWARE signer's
        // real hybrid pubkeys so the ingest gate verifies the composed scrub.
        let record = KeyRecord {
            key_id: derived.clone(),
            pubkey_ed25519_base64: B64.encode(&hw_pubkey),
            pubkey_ml_dsa_65_base64: Some(B64.encode(&pqc_pubkey)),
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: derived.clone(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": derived.clone() }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: derived.clone(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        sq.put_public_key(SignedKeyRecord { record })
            .await
            .expect("seed hw-derived key");

        let input = crate::federation::EmitAttestationInput::with_envelope(
            SCORES,
            serde_json::json!({
                "id": "emit-hw-1", "dimension": "identity_binding:v1",
                "score": 1.0, "confidence": 0.9,
            }),
        );
        let att_id = engine
            .emit_attestation_self(input)
            .await
            .expect("hardware-hybrid engine emits via the composed signer (#253)");

        let row = sq.get_attestation(&att_id).await.unwrap().expect("row");
        assert_eq!(
            row.tier,
            crate::federation::types::attestation_tier::FEDERATION
        );
        assert_eq!(
            row.attesting_key_id, derived,
            "attester == hardware-composed signer's derived key_id"
        );
        assert_eq!(row.scrub_key_id, derived);
        assert!(row
            .scrub_signature_pqc
            .as_deref()
            .is_some_and(|s| !s.is_empty()));
    }

    /// #252 — `weight: Some(w)` folds onto the assembled row's
    /// `Attestation::weight`; `None` (the default) leaves it `None`. A
    /// weighted `scores` row round-trips its band instead of collapsing to
    /// the `1.0` trust-model default.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn emit_attestation_weight_round_trips_sqlite() {
        use crate::federation::types::attestation_type::SCORES;
        use crate::federation::FederationDirectory;

        let signer = crate::federation::tier_ingest::test_support::local_signer("ciris-weight");
        let derived = signer.derived_key_id();
        let engine = Engine::with_signer(signer.clone(), "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        sq.put_public_key(sweeper_test_key_derived_for(&derived, "ciris-weight"))
            .await
            .expect("seed key");

        // Weighted scores emit (the capacity-band case): weight survives.
        let weighted = crate::federation::EmitAttestationInput::with_envelope(
            SCORES,
            serde_json::json!({
                "id": "emit-w-1", "dimension": "capacity:sustained_coherence:v1",
                "score": 0.42, "confidence": 0.9,
            }),
        )
        .with_weight(Some(0.42));
        let w_id = engine
            .emit_attestation(&signer, weighted)
            .await
            .expect("weighted emit");
        let w_row = sq.get_attestation(&w_id).await.unwrap().expect("row");
        assert_eq!(
            w_row.weight,
            Some(0.42),
            "Some(w) folds onto Attestation::weight (no collapse to 1.0)"
        );

        // Default (None) emit: weight stays None (pre-9.4.0 behavior).
        let plain = crate::federation::EmitAttestationInput::with_envelope(
            SCORES,
            serde_json::json!({
                "id": "emit-w-2", "dimension": "identity_binding:v1",
                "score": 1.0, "confidence": 0.9,
            }),
        );
        let p_id = engine
            .emit_attestation(&signer, plain)
            .await
            .expect("default emit");
        let p_row = sq.get_attestation(&p_id).await.unwrap().expect("row");
        assert_eq!(p_row.weight, None, "None ⇒ unchanged default");
    }

    // ── #249 Cut C ── delegates_to / moderation emit ceremonies ───────
    //
    // v9.3.0 (CIRISPersist#249) — round-trips for the typed emit ceremonies
    // over the #248 `emit_attestation` primitive. Each composes
    // `emit_attestation` (no re-hand-roll), so the attester/scrub key is the
    // signer's DERIVED key_id (#247 floor); we additionally assert the
    // emitted edge is ADMISSIBLE by the reader gate it targets
    // (`is_named_moderator` / `is_steward_bound` / the moderation `scores`
    // gate) — proving the moderate-scope tokens match the duty walk.

    /// A `user`-role `federation_keys` row keyed by `derived_key_id` but
    /// carrying `pubkey_label`'s REAL deterministic hybrid pubkeys — so a
    /// federation-tier row attested as `derived_key_id` and signed by
    /// `pubkey_label`'s keys both FK-resolves AND hybrid-verifies, while the
    /// `user` identity_type makes the key steward-bound (clause 1 of
    /// `is_steward_bound`). The steward-bound-authority shape the §11.10
    /// named-moderator walk requires at the root.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn user_test_key_derived_for(
        derived_key_id: &str,
        pubkey_label: &str,
    ) -> crate::federation::SignedKeyRecord {
        let mut signed = sweeper_test_key_derived_for(derived_key_id, pubkey_label);
        signed.record.identity_type = crate::federation::types::identity_type::USER.into();
        signed
    }

    /// Seed a `founder_only` community whose sole founder is
    /// `founder_key_id` (already registered + steward-bound). The community's
    /// own key is registered too (required by `community_authority_set`).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn seed_community_with_founder(
        engine: &Engine,
        community_id: &str,
        founder_key_id: &str,
    ) {
        engine
            .federation_directory()
            .put_public_key(sweeper_test_key(community_id))
            .await
            .expect("seed community key");
        engine
            .federation_directory()
            .put_community(crate::federation::SignedCommunity {
                community: crate::federation::types::Community {
                    community_key_id: community_id.into(),
                    community_name: "cut-c-community".into(),
                    members: vec![crate::federation::types::CommunityMember {
                        key_id: founder_key_id.into(),
                        joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                        role: Some("founder".into()),
                    }],
                    founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                    consensus_protocol: crate::federation::types::consensus_protocol::FOUNDER_ONLY
                        .into(),
                    policy_blob: None,
                    persist_row_hash: String::new(),
                },
            })
            .await
            .expect("seed community");
    }

    /// #249 — `grant_delegation` stores a `delegates_to` row whose
    /// attester/scrub == the signer's DERIVED key_id (#247 floor) and whose
    /// `attested_key_id` is the delegate; the row is retrievable via
    /// `list_attestations_by(derived)`.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn grant_delegation_stores_edge_under_derived_key_id_sqlite() {
        use crate::federation::FederationDirectory;
        let signer = crate::federation::tier_ingest::test_support::local_signer("granter");
        let derived = signer.derived_key_id();
        let engine = Engine::with_signer(signer.clone(), "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        sq.put_public_key(sweeper_test_key_derived_for(&derived, "granter"))
            .await
            .expect("seed granter");
        // The delegate must FK-resolve (attested_key_id).
        sq.put_public_key(sweeper_test_key("delegate"))
            .await
            .expect("seed delegate");

        let att_id = engine
            .grant_delegation(
                &signer,
                "delegate",
                vec!["message_io".into(), "review".into()],
                true,
                None,
            )
            .await
            .expect("grant_delegation");

        let row = sq.get_attestation(&att_id).await.unwrap().expect("row");
        assert_eq!(
            row.attestation_type,
            crate::federation::types::attestation_type::DELEGATES_TO
        );
        assert_eq!(row.attesting_key_id, derived, "attester == derived (#247)");
        assert_eq!(row.scrub_key_id, derived, "scrub == derived (#247)");
        assert_eq!(row.attested_key_id, "delegate", "edge keyed by recipient");
        // Stored + listable by the signer's derived id.
        let by = sq.list_attestations_by(&derived).await.unwrap();
        assert!(by.iter().any(|a| a.attestation_id == att_id));
    }

    /// #249 — `steward_bind` emits an `infra:*`-only `delegates_to` from an
    /// steward-bound (user) signer to a node-ONLY key: it PASSES the CC
    /// 4.4.3.4.3 node-agency gate (so it stores), and afterward
    /// `is_steward_bound(node)` is true (the edge the reader walks).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn steward_bind_infra_only_passes_node_agency_and_steward_binds_sqlite() {
        use crate::federation::admission::is_steward_bound;
        use crate::federation::types::delegation_scope;
        use crate::federation::FederationDirectory;
        let signer = crate::federation::tier_ingest::test_support::local_signer("owner");
        let derived = signer.derived_key_id();
        let engine = Engine::with_signer(signer.clone(), "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        // Owner is user-role (steward-bound) + verifies at the ingest gate.
        sq.put_public_key(user_test_key_derived_for(&derived, "owner"))
            .await
            .expect("seed owner");
        // The recipient is a NODE-ONLY key (the gate constrains it).
        let mut node_key = sweeper_test_key("node-1");
        node_key.record.identity_type = crate::federation::types::identity_type::NODE.into();
        sq.put_public_key(node_key).await.expect("seed node");

        // infra:*-only steward-binding → admissible on a node key.
        let att_id = engine
            .steward_bind(
                &signer,
                "node-1",
                vec![
                    delegation_scope::INFRA_NETWORK_PRESENCE.into(),
                    delegation_scope::INFRA_SERVE.into(),
                ],
                None,
            )
            .await
            .expect("steward_bind infra:* admitted on node key");
        let row = sq.get_attestation(&att_id).await.unwrap().expect("row");
        // Edge carries infra:* only (passed the node-agency gate).
        let scope = row.attestation_envelope["scope"].as_array().unwrap();
        assert!(
            scope
                .iter()
                .all(|s| s.as_str().unwrap().starts_with("infra:")),
            "steward_bind edge is infra:*-only"
        );
        // The node is now steward-bound (a live delegates_to(U → node), U user).
        assert!(
            is_steward_bound(&*sq, "node-1").await.unwrap(),
            "node is steward-bound after steward_bind"
        );

        // Negative control: an agency:* scope on the SAME node key is REJECTED
        // by the node-agency gate (so the moderate-scope tokens we add cannot
        // be smuggled as agency onto a node).
        let err = engine
            .grant_delegation(
                &signer,
                "node-1",
                vec![delegation_scope::AGENCY_ACT_ON_BEHALF.into()],
                false,
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_node_agency_forbidden");
    }

    // ── v12.7.0 (CIRISPersist#368 + #367, CC 3.4.11/3.4.13 + CC 3.2) ──
    // Witness-targets-subject age graduation over the REAL emit path, and
    // the minor-guardianship admit + steward-less-minor fail-secure driven
    // end-to-end over `emit_attestation` / `grant_delegation` /
    // `revoke_delegation`.

    /// A `witness`-role `federation_keys` row keyed by `derived_key_id` with
    /// `pubkey_label`'s REAL deterministic hybrid pubkeys — the registered
    /// age-assurance verifier shape the `age_assurance:` reserved-prefix
    /// rule requires of the emitter.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn witness_test_key_derived_for(
        derived_key_id: &str,
        pubkey_label: &str,
    ) -> crate::federation::SignedKeyRecord {
        let mut signed = sweeper_test_key_derived_for(derived_key_id, pubkey_label);
        signed.record.identity_type = crate::federation::types::identity_type::WITNESS.into();
        signed
    }

    /// #368 — the witness-targets-subject age flow over the REAL
    /// `Engine::emit_attestation` path (sqlite): a witness names a DIFFERENT
    /// subject via `EmitAttestationInput::attested_key_id` and THAT subject's
    /// `age_band` graduates (witness outranks the subject's own
    /// self-declared rung); the witness CANNOT graduate itself
    /// (attester==attested rejected); a non-witness emitter is still
    /// refused by the unchanged identity gate.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn witness_targets_subject_age_graduation_over_emit_sqlite() {
        use crate::federation::age::{age_band, age_band_fine, AgeBand, AgeBandFine};
        use crate::federation::FederationDirectory;

        let w_signer = crate::federation::tier_ingest::test_support::local_signer("age-witness");
        let t_signer = crate::federation::tier_ingest::test_support::local_signer("age-subject");
        let w = w_signer.derived_key_id();
        let t = t_signer.derived_key_id();
        let engine = Engine::with_signer(w_signer.clone(), "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        sq.put_public_key(witness_test_key_derived_for(&w, "age-witness"))
            .await
            .expect("seed witness");
        sq.put_public_key(user_test_key_derived_for(&t, "age-subject"))
            .await
            .expect("seed subject");

        // The subject self-declares MINOR (self rung; attested defaults to
        // the emitter — subject-signed by design).
        let self_minor = crate::federation::EmitAttestationInput::with_envelope(
            "age_self_declared:minor:v1",
            serde_json::json!({ "id": "wtse-self-minor" }),
        );
        engine
            .emit_attestation(&t_signer, self_minor)
            .await
            .expect("self-declared minor admits");
        assert_eq!(engine.age_band(&t).await.unwrap(), AgeBand::Minor);

        // WITNESS-TARGETS-SUBJECT: the witness emits `age_assurance:*` ABOUT
        // the subject by carrying it in `attested_key_id` — the #368 surface.
        let mut cross = crate::federation::EmitAttestationInput::with_envelope(
            "age_assurance:government:adult:v1",
            serde_json::json!({ "id": "wtse-w-adult" }),
        );
        cross.attested_key_id = Some(t.clone());
        let att_id = engine
            .emit_attestation(&w_signer, cross)
            .await
            .expect("witness-targets-subject age_assurance admitted");
        let row = sq.get_attestation(&att_id).await.unwrap().expect("row");
        assert_eq!(row.attesting_key_id, w, "attester = the witness");
        assert_eq!(row.attested_key_id, t, "subject rides attested_key_id");
        // The SUBJECT's band graduates (witness outranks its self-minor).
        assert_eq!(
            engine.age_band(&t).await.unwrap(),
            AgeBand::Adult,
            "a witness row ABOUT the subject graduates the SUBJECT's band",
        );
        assert_eq!(
            age_band_fine(&*sq, &t).await.unwrap(),
            AgeBandFine::Adult,
            "the finer resolution graduates too",
        );

        // SELF-graduation via the witness prefix is refused: the same
        // witness emitting with the default (self) attested_key_id.
        let selfie = crate::federation::EmitAttestationInput::with_envelope(
            "age_assurance:provider:adult:v1",
            serde_json::json!({ "id": "wtse-w-self" }),
        );
        let e = engine
            .emit_attestation(&w_signer, selfie)
            .await
            .expect_err("a subject must not emit its own age assurance");
        assert_eq!(e.kind(), "federation_age_assurance_self_emission_rejected");
        assert_eq!(
            age_band(&*sq, &w).await.unwrap(),
            AgeBand::Unknown,
            "the witness's own band is untouched",
        );

        // Identity gate unchanged: the (non-witness) SUBJECT cross-attesting
        // the witness's age is refused (reserved prefix needs a witness).
        let mut bad = crate::federation::EmitAttestationInput::with_envelope(
            "age_assurance:provider:adult:v1",
            serde_json::json!({ "id": "wtse-t-cross" }),
        );
        bad.attested_key_id = Some(w.clone());
        let e = engine
            .emit_attestation(&t_signer, bad)
            .await
            .expect_err("a non-witness emitter is refused");
        assert_eq!(e.kind(), "federation_reserved_prefix_emitter_mismatch");
    }

    /// #368 PG twin of
    /// [`witness_targets_subject_age_graduation_over_emit_sqlite`] — the
    /// cross-subject graduation + self-graduation rejection over the live
    /// Postgres `put_attestation` gates (pg/sqlite symmetry). Skips when
    /// `CIRIS_PERSIST_TEST_PG_URL` is unset.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn witness_targets_subject_age_graduation_over_emit_postgres() {
        use crate::federation::age::{age_band, AgeBand};
        use crate::federation::FederationDirectory;

        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let run = uuid::Uuid::new_v4().simple().to_string();
        let w_label = format!("age-w-{run}");
        let t_label = format!("age-t-{run}");
        let w_signer = crate::federation::tier_ingest::test_support::local_signer(&w_label);
        let t_signer = crate::federation::tier_ingest::test_support::local_signer(&t_label);
        let w = w_signer.derived_key_id();
        let t = t_signer.derived_key_id();
        let engine = Engine::with_signer(w_signer.clone(), &dsn)
            .await
            .expect("pg engine");
        let pg = engine.postgres_backend().expect("pg backend");
        pg.put_public_key(witness_test_key_derived_for(&w, &w_label))
            .await
            .expect("seed witness");
        pg.put_public_key(user_test_key_derived_for(&t, &t_label))
            .await
            .expect("seed subject");

        // Subject self-declares minor.
        engine
            .emit_attestation(
                &t_signer,
                crate::federation::EmitAttestationInput::with_envelope(
                    "age_self_declared:minor:v1",
                    serde_json::json!({ "id": format!("pgw-self-{run}") }),
                ),
            )
            .await
            .expect("self-declared minor admits");
        assert_eq!(engine.age_band(&t).await.unwrap(), AgeBand::Minor);

        // Witness graduates the SUBJECT cross-subject.
        let mut cross = crate::federation::EmitAttestationInput::with_envelope(
            "age_assurance:government:adult:v1",
            serde_json::json!({ "id": format!("pgw-adult-{run}") }),
        );
        cross.attested_key_id = Some(t.clone());
        engine
            .emit_attestation(&w_signer, cross)
            .await
            .expect("witness-targets-subject admitted on postgres");
        assert_eq!(engine.age_band(&t).await.unwrap(), AgeBand::Adult);

        // Self-graduation via the witness prefix rejected on PG too.
        let e = engine
            .emit_attestation(
                &w_signer,
                crate::federation::EmitAttestationInput::with_envelope(
                    "age_assurance:provider:adult:v1",
                    serde_json::json!({ "id": format!("pgw-self-adult-{run}") }),
                ),
            )
            .await
            .expect_err("self-emission rejected on postgres");
        assert_eq!(e.kind(), "federation_age_assurance_self_emission_rejected");
        assert_eq!(age_band(&**pg, &w).await.unwrap(), AgeBand::Unknown);
    }

    /// #367 — the FULL CC 3.2 minor-guardianship flow over the REAL paths
    /// (sqlite): a witness attests T minor (cross-subject, #368) → the
    /// steward-less minor fails secure → S's binding is refused until S is a
    /// PROVEN adult → witness attests S adult → `grant_delegation(S → T)` is
    /// ADMITTED → `revoke_delegation` leaves the minor steward-less again
    /// (fail-secure). An age-unverified user target stays rejected.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn minor_guardianship_grant_and_withdraw_end_to_end_sqlite() {
        use crate::federation::admission::{is_steward_bound, steward_bindings_of};
        use crate::federation::age::AgeBand;
        use crate::federation::types::delegation_scope;
        use crate::federation::FederationDirectory;

        let w_signer = crate::federation::tier_ingest::test_support::local_signer("mg-witness");
        let s_signer = crate::federation::tier_ingest::test_support::local_signer("mg-steward");
        let w = w_signer.derived_key_id();
        let s = s_signer.derived_key_id();
        let engine = Engine::with_signer(w_signer.clone(), "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        sq.put_public_key(witness_test_key_derived_for(&w, "mg-witness"))
            .await
            .expect("seed witness");
        sq.put_public_key(user_test_key_derived_for(&s, "mg-steward"))
            .await
            .expect("seed steward");
        // The ward T and an age-unverified control U (emit nothing; plain
        // registered user-role keys).
        let mut t_key = sweeper_test_key("mg-ward");
        t_key.record.identity_type = crate::federation::types::identity_type::USER.into();
        sq.put_public_key(t_key).await.expect("seed ward");
        let mut u_key = sweeper_test_key("mg-unverified");
        u_key.record.identity_type = crate::federation::types::identity_type::USER.into();
        sq.put_public_key(u_key).await.expect("seed unverified");

        // Age-unverified user self-anchors (presumption of sovereignty).
        assert!(is_steward_bound(&*sq, "mg-ward").await.unwrap());

        // Witness attests T MINOR (the #368 cross-subject emit).
        let mut minor = crate::federation::EmitAttestationInput::with_envelope(
            "age_assurance:provider:minor:v1",
            serde_json::json!({ "id": "mg-w-minor" }),
        );
        minor.attested_key_id = Some("mg-ward".to_owned());
        engine
            .emit_attestation(&w_signer, minor)
            .await
            .expect("witness attests the ward minor");
        assert_eq!(engine.age_band("mg-ward").await.unwrap(), AgeBand::Minor);
        // A PROVEN minor with no steward fails secure.
        assert!(
            !is_steward_bound(&*sq, "mg-ward").await.unwrap(),
            "a steward-less proven minor must not self-anchor",
        );
        assert!(steward_bindings_of(&*sq, "mg-ward")
            .await
            .unwrap()
            .is_empty());

        // S is not yet a PROVEN adult → the binding is refused.
        let e = engine
            .grant_delegation(
                &s_signer,
                "mg-ward",
                vec![delegation_scope::AGENCY_ACT_ON_BEHALF.into()],
                false,
                None,
            )
            .await
            .expect_err("an unproven granter cannot steward a minor");
        match e {
            crate::federation::Error::UserTargetStewardBindingForbidden { reason, .. } => {
                assert_eq!(reason, "granter_not_adult_user");
            }
            other => panic!("expected UserTargetStewardBindingForbidden, got {other:?}"),
        }

        // Witness attests S ADULT (cross-subject again).
        let mut adult = crate::federation::EmitAttestationInput::with_envelope(
            "age_assurance:government:adult:v1",
            serde_json::json!({ "id": "mg-w-adult" }),
        );
        adult.attested_key_id = Some(s.clone());
        engine
            .emit_attestation(&w_signer, adult)
            .await
            .expect("witness attests the steward adult");
        assert_eq!(engine.age_band(&s).await.unwrap(), AgeBand::Adult);

        // The CC 3.2 positive case: adult user S → proven-minor T ADMITTED
        // over the REAL `grant_delegation` path.
        let grant_id = engine
            .grant_delegation(
                &s_signer,
                "mg-ward",
                vec![delegation_scope::AGENCY_ACT_ON_BEHALF.into()],
                false,
                None,
            )
            .await
            .expect("adult-user → proven-minor guardianship is ADMITTED (CC 3.2)");
        assert!(is_steward_bound(&*sq, "mg-ward").await.unwrap());
        assert_eq!(
            steward_bindings_of(&*sq, "mg-ward").await.unwrap(),
            vec![s.clone()],
            "the minor is steward-bound to exactly S",
        );

        // Withdraw the guardianship → the minor is steward-less again and
        // the liveness predicates fail secure.
        engine
            .revoke_delegation(&s_signer, &grant_id, "mg-ward")
            .await
            .expect("revoke_delegation");
        assert!(
            !is_steward_bound(&*sq, "mg-ward").await.unwrap(),
            "a minor whose only guardianship edge was withdrawn fails secure",
        );
        assert!(
            steward_bindings_of(&*sq, "mg-ward")
                .await
                .unwrap()
                .is_empty(),
            "no anchors remain after the withdraw",
        );

        // An age-UNVERIFIED user target is still rejected (presumption of
        // sovereignty — nothing in this cut widened the wall).
        let e = engine
            .grant_delegation(
                &s_signer,
                "mg-unverified",
                vec![delegation_scope::AGENCY_ACT_ON_BEHALF.into()],
                false,
                None,
            )
            .await
            .expect_err("an unverified user target stays rejected");
        match e {
            crate::federation::Error::UserTargetStewardBindingForbidden { reason, .. } => {
                assert_eq!(reason, "target_age_unverified");
            }
            other => panic!("expected UserTargetStewardBindingForbidden, got {other:?}"),
        }
    }

    /// #367 PG twin of
    /// [`minor_guardianship_grant_and_withdraw_end_to_end_sqlite`] — the
    /// witness→minor attest → adult-steward grant → withdraw → fail-secure
    /// arc over the live Postgres gates. Skips when
    /// `CIRIS_PERSIST_TEST_PG_URL` is unset.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn minor_guardianship_grant_and_withdraw_end_to_end_postgres() {
        use crate::federation::admission::{is_steward_bound, steward_bindings_of};
        use crate::federation::age::AgeBand;
        use crate::federation::types::delegation_scope;
        use crate::federation::FederationDirectory;

        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let run = uuid::Uuid::new_v4().simple().to_string();
        let w_label = format!("mg-w-{run}");
        let s_label = format!("mg-s-{run}");
        let ward = format!("mg-ward-{run}");
        let w_signer = crate::federation::tier_ingest::test_support::local_signer(&w_label);
        let s_signer = crate::federation::tier_ingest::test_support::local_signer(&s_label);
        let w = w_signer.derived_key_id();
        let s = s_signer.derived_key_id();
        let engine = Engine::with_signer(w_signer.clone(), &dsn)
            .await
            .expect("pg engine");
        let pg = engine.postgres_backend().expect("pg backend");
        pg.put_public_key(witness_test_key_derived_for(&w, &w_label))
            .await
            .expect("seed witness");
        pg.put_public_key(user_test_key_derived_for(&s, &s_label))
            .await
            .expect("seed steward");
        let mut t_key = sweeper_test_key(&ward);
        t_key.record.identity_type = crate::federation::types::identity_type::USER.into();
        pg.put_public_key(t_key).await.expect("seed ward");

        // Witness attests T minor + S adult (cross-subject, #368).
        let mut minor = crate::federation::EmitAttestationInput::with_envelope(
            "age_assurance:provider:minor:v1",
            serde_json::json!({ "id": format!("mgp-minor-{run}") }),
        );
        minor.attested_key_id = Some(ward.clone());
        engine
            .emit_attestation(&w_signer, minor)
            .await
            .expect("witness attests ward minor");
        let mut adult = crate::federation::EmitAttestationInput::with_envelope(
            "age_assurance:government:adult:v1",
            serde_json::json!({ "id": format!("mgp-adult-{run}") }),
        );
        adult.attested_key_id = Some(s.clone());
        engine
            .emit_attestation(&w_signer, adult)
            .await
            .expect("witness attests steward adult");
        assert_eq!(engine.age_band(&ward).await.unwrap(), AgeBand::Minor);
        assert_eq!(engine.age_band(&s).await.unwrap(), AgeBand::Adult);
        assert!(
            !is_steward_bound(&**pg, &ward).await.unwrap(),
            "steward-less proven minor fails secure on postgres",
        );

        // Adult user → proven minor: ADMITTED; withdraw → fail-secure.
        let grant_id = engine
            .grant_delegation(
                &s_signer,
                &ward,
                vec![delegation_scope::AGENCY_ACT_ON_BEHALF.into()],
                false,
                None,
            )
            .await
            .expect("guardianship admitted on postgres");
        assert_eq!(
            steward_bindings_of(&**pg, &ward).await.unwrap(),
            vec![s.clone()],
        );
        engine
            .revoke_delegation(&s_signer, &grant_id, &ward)
            .await
            .expect("revoke_delegation");
        assert!(
            !is_steward_bound(&**pg, &ward).await.unwrap(),
            "withdrawn guardianship leaves the minor steward-less (fail-secure)",
        );
        assert!(steward_bindings_of(&**pg, &ward).await.unwrap().is_empty());
    }

    // ── v13.2.0 (CIRISPersist#378, CC 3.2 rc2 single-owner) ──────────────
    // The owner-binding sub-relation over the REAL emit path
    // (`steward_bind(.., Some(owner_binding::PURPOSE))`) + `owner_of`: the
    // purpose arg round-trips onto the wire, a second DISTINCT owner is
    // rejected at bind time (idempotent same-owner), and `owner_of` is
    // purpose-filtered → ≤1 (an unrelated general delegation does not count).

    /// #378 (sqlite) — `steward_bind(node, infra, Some("responsible_for"))`
    /// stamps the owner-binding wire shape, `owner_of` resolves the single
    /// owner, a second distinct owner rejects (`NodeAlreadyOwned`), a
    /// same-owner refresh is idempotent, a general (non-ownership) delegation
    /// does NOT count toward `owner_of`, and an unbound node is `None`.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn owner_binding_single_owner_end_to_end_sqlite() {
        use crate::federation::types::{delegation_scope, owner_binding};
        use crate::federation::FederationDirectory;

        let o1_signer = crate::federation::tier_ingest::test_support::local_signer("ob-owner1");
        let o2_signer = crate::federation::tier_ingest::test_support::local_signer("ob-owner2");
        let o1 = o1_signer.derived_key_id();
        let o2 = o2_signer.derived_key_id();
        let engine = Engine::with_signer(o1_signer.clone(), "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        // Two user-role would-be owners + a node-only key (owner-binding is
        // infra:*-only, so it passes the node-agency gate on a node key).
        sq.put_public_key(user_test_key_derived_for(&o1, "ob-owner1"))
            .await
            .expect("seed owner1");
        sq.put_public_key(user_test_key_derived_for(&o2, "ob-owner2"))
            .await
            .expect("seed owner2");
        let mut node = sweeper_test_key("ob-node");
        node.record.identity_type = crate::federation::types::identity_type::NODE.into();
        sq.put_public_key(node).await.expect("seed node");
        let infra = vec![
            delegation_scope::INFRA_SERVE.into(),
            delegation_scope::INFRA_NETWORK_PRESENCE.into(),
        ];

        // First owner-binding admits; the purpose arg rides the wire.
        let att_id = engine
            .steward_bind(
                &o1_signer,
                "ob-node",
                infra.clone(),
                Some(owner_binding::PURPOSE),
            )
            .await
            .expect("first owner-binding admits");
        let row = sq.get_attestation(&att_id).await.unwrap().expect("row");
        assert_eq!(
            row.attestation_envelope["dimension"],
            owner_binding::DIMENSION,
            "owner-binding carries the ownership dimension",
        );
        assert_eq!(
            row.attestation_envelope["delegation_purpose"],
            owner_binding::PURPOSE,
            "owner-binding carries the producer-side purpose marker",
        );
        assert_eq!(
            engine.owner_of("ob-node").await.unwrap(),
            Some(o1.clone()),
            "owner_of resolves the single owner",
        );

        // A second, DISTINCT owner is rejected at bind time (no trace).
        let err = engine
            .steward_bind(
                &o2_signer,
                "ob-node",
                infra.clone(),
                Some(owner_binding::PURPOSE),
            )
            .await
            .expect_err("a second distinct owner is rejected");
        assert_eq!(err.kind(), "federation_node_already_owned");
        match err {
            crate::federation::Error::NodeAlreadyOwned {
                ref node_key_id,
                ref incumbent_owner,
                ref attempted_owner,
            } => {
                assert_eq!(node_key_id, "ob-node");
                assert_eq!(incumbent_owner, &o1);
                assert_eq!(attempted_owner, &o2);
            }
            other => panic!("expected NodeAlreadyOwned, got {other:?}"),
        }
        assert_eq!(
            engine.owner_of("ob-node").await.unwrap(),
            Some(o1.clone()),
            "the rejected second owner left the owner unchanged",
        );

        // A refresh by the SAME owner is idempotently admitted.
        engine
            .steward_bind(
                &o1_signer,
                "ob-node",
                infra.clone(),
                Some(owner_binding::PURPOSE),
            )
            .await
            .expect("same-owner refresh is idempotent");
        assert_eq!(engine.owner_of("ob-node").await.unwrap(), Some(o1.clone()));

        // A general (non-ownership) delegation from a DIFFERENT user is
        // admitted (it never claims ownership) but does NOT count toward
        // owner_of — the purpose filter keeps ownership single-valued.
        engine
            .steward_bind(&o2_signer, "ob-node", infra.clone(), None)
            .await
            .expect("a plain steward-binding is not an owner-binding");
        assert_eq!(
            engine.owner_of("ob-node").await.unwrap(),
            Some(o1.clone()),
            "owner_of ignores the general delegation (purpose-filtered ≤1)",
        );

        // An unbound node reads as unowned.
        let mut node2 = sweeper_test_key("ob-node2");
        node2.record.identity_type = crate::federation::types::identity_type::NODE.into();
        sq.put_public_key(node2).await.expect("seed node2");
        assert_eq!(engine.owner_of("ob-node2").await.unwrap(), None);
    }

    /// #378 PG twin of [`owner_binding_single_owner_end_to_end_sqlite`] — the
    /// same owner-binding / single-owner-gate / purpose-filtered `owner_of`
    /// arc over the live Postgres gates. Skips when `CIRIS_PERSIST_TEST_PG_URL`
    /// is unset.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn owner_binding_single_owner_end_to_end_postgres() {
        use crate::federation::types::{delegation_scope, owner_binding};
        use crate::federation::FederationDirectory;

        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let run = uuid::Uuid::new_v4().simple().to_string();
        let o1_label = format!("ob-o1-{run}");
        let o2_label = format!("ob-o2-{run}");
        let node_label = format!("ob-node-{run}");
        let node2_label = format!("ob-node2-{run}");
        let o1_signer = crate::federation::tier_ingest::test_support::local_signer(&o1_label);
        let o2_signer = crate::federation::tier_ingest::test_support::local_signer(&o2_label);
        let o1 = o1_signer.derived_key_id();
        let o2 = o2_signer.derived_key_id();
        let engine = Engine::with_signer(o1_signer.clone(), &dsn)
            .await
            .expect("pg engine");
        let pg = engine.postgres_backend().expect("pg backend");
        pg.put_public_key(user_test_key_derived_for(&o1, &o1_label))
            .await
            .expect("seed owner1");
        pg.put_public_key(user_test_key_derived_for(&o2, &o2_label))
            .await
            .expect("seed owner2");
        let mut node = sweeper_test_key(&node_label);
        node.record.identity_type = crate::federation::types::identity_type::NODE.into();
        pg.put_public_key(node).await.expect("seed node");
        let infra = vec![
            delegation_scope::INFRA_SERVE.into(),
            delegation_scope::INFRA_NETWORK_PRESENCE.into(),
        ];

        // First owner-binding admits; purpose rides the wire; owner_of == o1.
        let att_id = engine
            .steward_bind(
                &o1_signer,
                &node_label,
                infra.clone(),
                Some(owner_binding::PURPOSE),
            )
            .await
            .expect("first owner-binding admits");
        let row = pg.get_attestation(&att_id).await.unwrap().expect("row");
        assert_eq!(
            row.attestation_envelope["dimension"],
            owner_binding::DIMENSION
        );
        assert_eq!(
            row.attestation_envelope["delegation_purpose"],
            owner_binding::PURPOSE
        );
        assert_eq!(
            engine.owner_of(&node_label).await.unwrap(),
            Some(o1.clone())
        );

        // Second distinct owner rejected; owner unchanged.
        let err = engine
            .steward_bind(
                &o2_signer,
                &node_label,
                infra.clone(),
                Some(owner_binding::PURPOSE),
            )
            .await
            .expect_err("a second distinct owner is rejected");
        assert_eq!(err.kind(), "federation_node_already_owned");
        assert_eq!(
            engine.owner_of(&node_label).await.unwrap(),
            Some(o1.clone())
        );

        // Same-owner refresh idempotent.
        engine
            .steward_bind(
                &o1_signer,
                &node_label,
                infra.clone(),
                Some(owner_binding::PURPOSE),
            )
            .await
            .expect("same-owner refresh is idempotent");
        assert_eq!(
            engine.owner_of(&node_label).await.unwrap(),
            Some(o1.clone())
        );

        // A general delegation from a different user does not count.
        engine
            .steward_bind(&o2_signer, &node_label, infra.clone(), None)
            .await
            .expect("a plain steward-binding is not an owner-binding");
        assert_eq!(
            engine.owner_of(&node_label).await.unwrap(),
            Some(o1.clone())
        );

        // Unbound node → None.
        let mut node2 = sweeper_test_key(&node2_label);
        node2.record.identity_type = crate::federation::types::identity_type::NODE.into();
        pg.put_public_key(node2).await.expect("seed node2");
        assert_eq!(engine.owner_of(&node2_label).await.unwrap(), None);
    }

    /// #249 — the add_moderator ↔ is_named_moderator round-trip: an
    /// steward-bound community founder appoints a moderator with the
    /// `moderate` duty; `is_named_moderator(moderator, community, moderate)`
    /// is true after — proving SCOPE_MODERATE matches the §11.10 duty walk.
    /// Then `remove_moderator` revokes it and the authority no longer holds.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn add_then_remove_moderator_round_trip_sqlite() {
        use crate::federation::admission::is_named_moderator;
        use crate::federation::types::delegation_scope::SCOPE_MODERATE;
        use crate::federation::FederationDirectory;
        let signer = crate::federation::tier_ingest::test_support::local_signer("founder");
        let derived = signer.derived_key_id();
        let engine = Engine::with_signer(signer.clone(), "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        // Founder: steward-bound (user) authority root of the community.
        sq.put_public_key(user_test_key_derived_for(&derived, "founder"))
            .await
            .expect("seed founder");
        sq.put_public_key(sweeper_test_key("moderator"))
            .await
            .expect("seed moderator");
        seed_community_with_founder(&engine, "comm-1", &derived).await;

        // Pre: not yet a moderator.
        assert!(
            !is_named_moderator(&*sq, "moderator", "comm-1", SCOPE_MODERATE)
                .await
                .unwrap(),
            "not a moderator before appointment"
        );

        // Appoint.
        let appt = engine
            .add_moderator(&signer, "comm-1", "moderator", SCOPE_MODERATE)
            .await
            .expect("add_moderator");
        assert!(
            is_named_moderator(&*sq, "moderator", "comm-1", SCOPE_MODERATE)
                .await
                .unwrap(),
            "is_named_moderator TRUE after add_moderator (SCOPE_MODERATE matches the duty walk)"
        );

        // Remove → the appointment edge is withdrawn; authority gone.
        engine
            .remove_moderator(&signer, "comm-1", &appt, "moderator", SCOPE_MODERATE)
            .await
            .expect("remove_moderator");
        assert!(
            !is_named_moderator(&*sq, "moderator", "comm-1", SCOPE_MODERATE)
                .await
                .unwrap(),
            "is_named_moderator FALSE after remove_moderator (withdraws revokes the edge)"
        );
    }

    /// #249 Cut G1 — the uniform cohort surface round-trips across all three
    /// rostered cohorts (`family` / `community` / `self`) over the SAME API:
    /// `active_members` / `active_member_keys` / `lookup_group` / `groups_of` /
    /// `add_member` / `revoke_member` / `swap_member`. Backend-generic body run
    /// on sqlite + live Postgres (backend parity, CIRISServer #249 §1/§2/§6).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn cohort_surface_roundtrip_body<D>(d: &D, s: &str)
    where
        D: crate::federation::FederationDirectory + ?Sized,
    {
        use crate::federation::cohort::{Cohort, RevokeSpec, RosterMember};
        use crate::federation::types;

        let founder = format!("g1-founder-{s}");
        let mem_b = format!("g1-memb-{s}");
        let mem_c = format!("g1-memc-{s}");
        let fam = format!("g1-fam-{s}");
        let comm = format!("g1-comm-{s}");
        let ident = format!("g1-ident-{s}");
        let occ1 = format!("g1-occ1-{s}");
        let occ2 = format!("g1-occ2-{s}");

        // Members / groups / occurrences all FK to federation_keys.
        for k in [&founder, &mem_b, &mem_c, &fam, &comm, &ident, &occ1, &occ2] {
            d.put_public_key(sweeper_test_key(k))
                .await
                .expect("seed key");
        }
        let joined: chrono::DateTime<chrono::Utc> = "2026-05-01T00:00:00Z".parse().unwrap();

        d.put_family(crate::federation::SignedFamily {
            family: types::Family {
                family_key_id: fam.clone(),
                family_name: "g1-fam".into(),
                members: vec![types::FamilyMember {
                    key_id: founder.clone(),
                    joined_at: joined,
                    role: Some("founder".into()),
                }],
                founded_at: joined,
                consensus_protocol: types::consensus_protocol::FOUNDER_ONLY.into(),
                consensus_protocol_entrenched: false,
                persist_row_hash: String::new(),
            },
        })
        .await
        .expect("put_family");
        d.put_community(crate::federation::SignedCommunity {
            community: types::Community {
                community_key_id: comm.clone(),
                community_name: "g1-comm".into(),
                members: vec![types::CommunityMember {
                    key_id: founder.clone(),
                    joined_at: joined,
                    role: Some("founder".into()),
                }],
                founded_at: joined,
                consensus_protocol: types::consensus_protocol::FOUNDER_ONLY.into(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        })
        .await
        .expect("put_community");

        // family + community: identical uniform ops, no per-cohort branching.
        for (cohort, group) in [(Cohort::Family, &fam), (Cohort::Community, &comm)] {
            let tag = cohort.as_str();
            let m = d
                .active_members(cohort, group)
                .await
                .expect("active_members");
            assert_eq!(m.len(), 1, "{tag} starts with founder");
            assert_eq!(m[0].key_id, founder);

            let g = d
                .lookup_group(cohort, group)
                .await
                .expect("lookup_group")
                .expect("group exists");
            assert_eq!(g.cohort, cohort);
            assert_eq!(
                g.consensus_protocol.as_deref(),
                Some(types::consensus_protocol::FOUNDER_ONLY),
                "{tag} lookup_group carries consensus_protocol"
            );
            assert!(g.name.is_some(), "{tag} lookup_group carries name");

            let gs = d.groups_of(cohort, &founder).await.expect("groups_of");
            assert!(
                gs.iter().any(|x| &x.group_key_id == group),
                "{tag} groups_of(founder) contains the group"
            );

            assert!(
                d.add_member(
                    cohort,
                    group,
                    RosterMember {
                        key_id: mem_b.clone(),
                        joined_at: joined,
                        role: None
                    },
                )
                .await
                .expect("add_member"),
                "{tag} add_member(mem_b) is a genuine add"
            );
            assert_eq!(d.active_members(cohort, group).await.unwrap().len(), 2);
            assert!(
                !d.add_member(
                    cohort,
                    group,
                    RosterMember {
                        key_id: mem_b.clone(),
                        joined_at: joined,
                        role: None
                    },
                )
                .await
                .expect("add_member idempotent"),
                "{tag} re-add(mem_b) is a no-op"
            );

            let keys = d
                .active_member_keys(cohort, group)
                .await
                .expect("active_member_keys");
            assert_eq!(keys.len(), 2, "{tag} active_member_keys resolves both pins");

            d.revoke_member(
                cohort,
                group,
                &mem_b,
                RevokeSpec {
                    effective_at: chrono::Utc::now(),
                    reason: Some("test".into()),
                    witness_set: vec![],
                },
            )
            .await
            .expect("revoke_member");
            assert_eq!(
                d.active_members(cohort, group).await.unwrap().len(),
                1,
                "{tag} revoke drops mem_b"
            );

            assert!(
                d.swap_member(
                    cohort,
                    group,
                    &founder,
                    RosterMember {
                        key_id: mem_c.clone(),
                        joined_at: joined,
                        role: None
                    },
                    RevokeSpec {
                        effective_at: chrono::Utc::now(),
                        reason: None,
                        witness_set: vec![],
                    },
                )
                .await
                .expect("swap_member"),
                "{tag} swap adds mem_c"
            );
            let after: Vec<String> = d
                .active_members(cohort, group)
                .await
                .unwrap()
                .into_iter()
                .map(|m| m.key_id)
                .collect();
            assert_eq!(after, vec![mem_c.clone()], "{tag} after swap = {{mem_c}}");
        }

        // self cohort: identity_occurrences through the SAME read API.
        for occ in [&occ1, &occ2] {
            d.put_identity_occurrence(crate::federation::SignedIdentityOccurrence {
                identity_occurrence: types::IdentityOccurrence {
                    identity_key_id: ident.clone(),
                    occurrence_key_id: occ.clone(),
                    device_class: types::device_class::SERVER.into(),
                    hardware_attestation: None,
                    asserted_at: joined,
                    valid_until: None,
                    encryption_pubkeys: None,
                    persist_row_hash: String::new(),
                },
            })
            .await
            .expect("put_identity_occurrence");
        }
        let occ_members = d
            .active_members(Cohort::SelfId, &ident)
            .await
            .expect("self active_members");
        assert_eq!(occ_members.len(), 2, "self has 2 active occurrences");
        assert!(
            occ_members
                .iter()
                .all(|m| m.role.as_deref() == Some("server")),
            "self RosterMember.role projects device_class"
        );
        let ig = d
            .groups_of(Cohort::SelfId, &occ1)
            .await
            .expect("groups_of self");
        assert_eq!(ig.len(), 1);
        assert_eq!(ig[0].group_key_id, ident, "occ1 resolves to its identity");
        assert!(
            d.lookup_group(Cohort::SelfId, &ident)
                .await
                .unwrap()
                .is_some(),
            "self lookup_group on a known identity key"
        );
        d.revoke_member(
            Cohort::SelfId,
            &ident,
            &occ1,
            RevokeSpec {
                effective_at: chrono::Utc::now(),
                reason: None,
                witness_set: vec![],
            },
        )
        .await
        .expect("revoke self occurrence");
        assert_eq!(
            d.active_members(Cohort::SelfId, &ident)
                .await
                .unwrap()
                .len(),
            1,
            "self revoke drops occ1"
        );
        // self admits occurrences via the typed put, NOT the uniform add_member.
        let err = d
            .add_member(
                Cohort::SelfId,
                &ident,
                RosterMember {
                    key_id: "nope".into(),
                    joined_at: joined,
                    role: None,
                },
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_invalid_argument");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn cohort_surface_roundtrip_sqlite() {
        let signer = crate::federation::tier_ingest::test_support::local_signer("g1");
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        cohort_surface_roundtrip_body(&*sq, "sq").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn cohort_surface_roundtrip_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let label = format!("g1-{}", uuid::Uuid::new_v4().simple());
        let signer = crate::federation::tier_ingest::test_support::local_signer(&label);
        let engine = Engine::with_signer(signer, &dsn).await.expect("pg engine");
        let pg = engine.postgres_backend().expect("pg backend").clone();
        cohort_surface_roundtrip_body(&*pg, &uuid::Uuid::new_v4().simple().to_string()).await;
    }

    /// #249 Cut G2 — supersede + versioning round-trip (CIRISServer #249 §3/§8):
    /// expand a `quorum:2/3` family of 3 to a `quorum:3/5` family of 5 (the
    /// strict-majority threshold MUST track the roster), and verify the version
    /// chain (`group_history` / `group_at`) preserves the prior version with
    /// its authorization. Backend-generic body; sqlite + live Postgres.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn supersede_versioning_body<D>(d: &D, s: &str)
    where
        D: crate::federation::FederationDirectory + ?Sized,
    {
        use crate::federation::cohort::Cohort;
        use crate::federation::types;

        let fam = format!("g2-fam-{s}");
        let m: Vec<String> = (0..5).map(|i| format!("g2-m{i}-{s}")).collect();
        for k in std::iter::once(&fam).chain(m.iter()) {
            d.put_public_key(sweeper_test_key(k))
                .await
                .expect("seed key");
        }
        let joined: chrono::DateTime<chrono::Utc> = "2026-05-01T00:00:00Z".parse().unwrap();
        let mk_members = |n: usize| -> Vec<types::FamilyMember> {
            m[..n]
                .iter()
                .map(|k| types::FamilyMember {
                    key_id: k.clone(),
                    joined_at: joined,
                    role: Some("founder".into()),
                })
                .collect()
        };

        // Genesis: 3-member quorum:2/3 family (version 1).
        d.put_family(crate::federation::SignedFamily {
            family: types::Family {
                family_key_id: fam.clone(),
                family_name: "accord".into(),
                members: mk_members(3),
                founded_at: joined,
                consensus_protocol: "quorum:2/3".into(),
                consensus_protocol_entrenched: true,
                persist_row_hash: String::new(),
            },
        })
        .await
        .expect("genesis put_family");

        // Supersede → 5-member quorum:3/5 (the expansion the write gap blocked).
        let auth = serde_json::json!({"membership_change": "expand 3->5", "quorum": "2/3"});
        let new_version = d
            .supersede_family(
                crate::federation::SignedFamily {
                    family: types::Family {
                        family_key_id: fam.clone(),
                        family_name: "accord".into(),
                        members: mk_members(5),
                        founded_at: joined,
                        consensus_protocol: "quorum:3/5".into(),
                        consensus_protocol_entrenched: true,
                        persist_row_hash: String::new(),
                    },
                },
                Some(auth.clone()),
            )
            .await
            .expect("supersede 3->5");
        assert_eq!(new_version, 2, "supersede bumps version 1 -> 2");

        // Live row is the new 5-member quorum:3/5.
        let live = d.lookup_family(&fam).await.unwrap().expect("live family");
        assert_eq!(live.members.len(), 5);
        assert_eq!(live.consensus_protocol, "quorum:3/5");

        // History chain: v1 (superseded, quorum:2/3, carries authorization) +
        // v2 (current, quorum:3/5).
        let hist = d
            .group_history(Cohort::Family, &fam)
            .await
            .expect("history");
        assert_eq!(hist.len(), 2, "two versions in the chain");
        assert_eq!(hist[0].version, 1);
        assert!(!hist[0].is_current);
        assert!(hist[0].superseded_at.is_some());
        assert_eq!(hist[0].authorization.as_ref(), Some(&auth));
        assert_eq!(hist[0].snapshot["consensus_protocol"], "quorum:2/3");
        assert_eq!(hist[1].version, 2);
        assert!(hist[1].is_current);
        assert!(hist[1].superseded_at.is_none());

        // group_at pins a specific version.
        let v1 = d
            .group_at(Cohort::Family, &fam, 1)
            .await
            .unwrap()
            .expect("v1 exists");
        assert_eq!(v1.snapshot["consensus_protocol"], "quorum:2/3");
        assert!(d.group_at(Cohort::Family, &fam, 9).await.unwrap().is_none());

        // supersede on an unknown group is rejected.
        let err = d
            .supersede_family(
                crate::federation::SignedFamily {
                    family: types::Family {
                        family_key_id: format!("g2-ghost-{s}"),
                        family_name: "ghost".into(),
                        members: vec![],
                        founded_at: joined,
                        consensus_protocol: "quorum:2/3".into(),
                        consensus_protocol_entrenched: true,
                        persist_row_hash: String::new(),
                    },
                },
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_invalid_argument");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn supersede_versioning_sqlite() {
        let signer = crate::federation::tier_ingest::test_support::local_signer("g2");
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        supersede_versioning_body(&*sq, "sq").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn supersede_versioning_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let label = format!("g2-{}", uuid::Uuid::new_v4().simple());
        let signer = crate::federation::tier_ingest::test_support::local_signer(&label);
        let engine = Engine::with_signer(signer, &dsn).await.expect("pg engine");
        let pg = engine.postgres_backend().expect("pg backend").clone();
        supersede_versioning_body(&*pg, &uuid::Uuid::new_v4().simple().to_string()).await;
    }

    /// #249 Cut G3 (robust on G3.5) — quorum-authorized membership gate
    /// (CIRISServer #249 §4/§5) composing CIRISVerify v6.9.0's
    /// `verify_membership_change`. A `quorum:2/3` family expands to `quorum:3/5`
    /// ONLY when ≥M (=2) of the PRIOR roster's real hybrid keys cosign the
    /// canonical `build_membership_change_envelope` payload; insufficient
    /// quorum, an anti-replay-tampered `supersedes`, and a one-seat
    /// (duplicate-pubkey) roster are each rejected, live row untouched. Real
    /// Ed25519 + ML-DSA-65 signers; sqlite + pg.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn quorum_supersede_body<D>(d: &D, s: &str)
    where
        D: crate::federation::FederationDirectory + ?Sized,
    {
        use crate::federation::cohort::Cohort;
        use crate::federation::tier_ingest::test_support::{
            register_hybrid_key, register_hybrid_key_aliased, threshold_sign,
        };
        use crate::federation::types;

        let fam = format!("g35-fam-{s}");
        let m: Vec<String> = (0..5).map(|i| format!("g35-m{i}-{s}")).collect();
        register_hybrid_key(d, &fam).await;
        for k in &m {
            register_hybrid_key(d, k).await;
        }
        let joined: chrono::DateTime<chrono::Utc> = "2026-05-01T00:00:00Z".parse().unwrap();
        let fam_row = |members: Vec<String>, cp: &str| -> crate::federation::SignedFamily {
            crate::federation::SignedFamily {
                family: types::Family {
                    family_key_id: fam.clone(),
                    family_name: "accord".into(),
                    members: members
                        .into_iter()
                        .map(|k| types::FamilyMember {
                            key_id: k,
                            joined_at: joined,
                            role: Some("founder".into()),
                        })
                        .collect(),
                    founded_at: joined,
                    consensus_protocol: cp.into(),
                    consensus_protocol_entrenched: true,
                    persist_row_hash: String::new(),
                },
            }
        };

        // Genesis: quorum:2/3 family (3 members, M=2).
        d.put_family(fam_row(m[..3].to_vec(), "quorum:2/3"))
            .await
            .expect("genesis");

        // Build the canonical change payload via the substrate helper (verify's
        // build_membership_change — carries the supersedes anti-replay binding).
        let change = d
            .build_membership_change_envelope(
                Cohort::Family,
                &fam,
                &m[..5],
                true,
                Some("quorum:3/5"),
            )
            .await
            .expect("build change envelope");
        let bytes = ciris_verify_core::jcs::canonicalize(&change).unwrap();

        // 2 of the 3 PRIOR members cosign → meets quorum:2/3.
        let v = d
            .supersede_family_with_quorum(
                fam_row(m[..5].to_vec(), "quorum:3/5"),
                change.clone(),
                vec![threshold_sign(&m[0], &bytes), threshold_sign(&m[1], &bytes)],
            )
            .await
            .expect("2-of-3 quorum authorizes the 3->5 expansion");
        assert_eq!(v, 2);
        let live = d.lookup_family(&fam).await.unwrap().unwrap();
        assert_eq!(live.members.len(), 5);
        assert_eq!(live.consensus_protocol, "quorum:3/5");
        let hist = d.group_history(Cohort::Family, &fam).await.unwrap();
        assert!(
            hist[0].authorization.is_some(),
            "v1 carries the authorization"
        );

        // The group is now quorum:3/5 (M=3). Build a fresh change for the
        // negatives (its supersedes binds to the current 5-roster).
        let change2 = d
            .build_membership_change_envelope(
                Cohort::Family,
                &fam,
                &m[..5],
                true,
                Some("quorum:3/5"),
            )
            .await
            .unwrap();
        let bytes2 = ciris_verify_core::jcs::canonicalize(&change2).unwrap();

        // (a) Insufficient quorum: 1 cosignature where M=3 → rejected.
        let err = d
            .supersede_family_with_quorum(
                fam_row(m[..5].to_vec(), "quorum:3/5"),
                change2.clone(),
                vec![threshold_sign(&m[0], &bytes2)],
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "federation_invalid_argument",
            "insufficient quorum"
        );

        // (b) Anti-replay: tamper the supersedes binding, cosign with a valid
        // 3-of-5 quorum → rejected (supersedes.prior_member_key_ids mismatch).
        let mut tampered = change2.clone();
        tampered["supersedes"]["prior_member_key_ids"] = serde_json::json!(["ghost"]);
        let tbytes = ciris_verify_core::jcs::canonicalize(&tampered).unwrap();
        let err = d
            .supersede_family_with_quorum(
                fam_row(m[..5].to_vec(), "quorum:3/5"),
                tampered,
                vec![
                    threshold_sign(&m[0], &tbytes),
                    threshold_sign(&m[1], &tbytes),
                    threshold_sign(&m[2], &tbytes),
                ],
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_invalid_argument", "anti-replay");

        // (c) One-seat: a new roster with two key_ids sharing one pubkey
        // (alias of m[0]) → rejected even with a valid quorum.
        let alias = format!("g35-alias-{s}");
        register_hybrid_key_aliased(d, &alias, &m[0]).await;
        let seat_roster = vec![
            m[0].clone(),
            m[1].clone(),
            m[2].clone(),
            m[3].clone(),
            alias.clone(),
        ];
        let seat_change = d
            .build_membership_change_envelope(
                Cohort::Family,
                &fam,
                &seat_roster,
                true,
                Some("quorum:3/5"),
            )
            .await
            .unwrap();
        let sbytes = ciris_verify_core::jcs::canonicalize(&seat_change).unwrap();
        let err = d
            .supersede_family_with_quorum(
                fam_row(seat_roster, "quorum:3/5"),
                seat_change,
                vec![
                    threshold_sign(&m[0], &sbytes),
                    threshold_sign(&m[1], &sbytes),
                    threshold_sign(&m[2], &sbytes),
                ],
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "federation_invalid_argument", "one-seat");

        // Every rejection left the live row untouched (still v2, 5 members).
        let live2 = d.lookup_family(&fam).await.unwrap().unwrap();
        assert_eq!(live2.members.len(), 5);
        assert_eq!(live2.consensus_protocol, "quorum:3/5");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn quorum_supersede_sqlite() {
        let signer = crate::federation::tier_ingest::test_support::local_signer("g3");
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        quorum_supersede_body(&*sq, "sq").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn quorum_supersede_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let label = format!("g3-{}", uuid::Uuid::new_v4().simple());
        let signer = crate::federation::tier_ingest::test_support::local_signer(&label);
        let engine = Engine::with_signer(signer, &dsn).await.expect("pg engine");
        let pg = engine.postgres_backend().expect("pg backend").clone();
        quorum_supersede_body(&*pg, &uuid::Uuid::new_v4().simple().to_string()).await;
    }

    /// #249 Cut G4 — forward-secrecy rekey-on-revoke (§7) + change-event hook
    /// (§9). Community removal bumps the DEK epoch (so the next cascade excludes
    /// the departed member) and emits a `community_membership_change` removed
    /// event; the cohort `revoke_member`/`add_member` paths emit the §9 events
    /// (family/community) consumers reconcile via `list_hard_case_events`.
    /// sqlite + pg.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn g4_rekey_events_body<D>(d: &D, s: &str)
    where
        D: crate::federation::FederationDirectory + crate::federation::BlobStorage + Sync,
    {
        use crate::federation::at_rest_cascade;
        use crate::federation::cohort::{Cohort, RevokeSpec, RosterMember};
        use crate::federation::hard_case::{change_kind, kind, HardCaseFilter};
        use crate::federation::types;

        // G4 rekey/events don't verify member signatures, so members are
        // registered as PRIMITIVE keys (sweeper_test_key) — non-node/agent, so
        // they pass the CC 3.2 community steward-binding gate without steward-binds.
        let joined: chrono::DateTime<chrono::Utc> = "2026-05-01T00:00:00Z".parse().unwrap();

        // ── §7 community rekey-on-revoke (epoch bump) ──
        let comm = format!("g4-comm-{s}");
        let cm: Vec<String> = (0..3).map(|i| format!("g4-cm{i}-{s}")).collect();
        d.put_public_key(sweeper_test_key(&comm))
            .await
            .expect("seed");
        for k in &cm {
            d.put_public_key(sweeper_test_key(k)).await.expect("seed");
        }
        d.put_community(crate::federation::SignedCommunity {
            community: types::Community {
                community_key_id: comm.clone(),
                community_name: "c".into(),
                members: cm
                    .iter()
                    .map(|k| types::CommunityMember {
                        key_id: k.clone(),
                        joined_at: joined,
                        role: None,
                    })
                    .collect(),
                founded_at: joined,
                consensus_protocol: "founder_only".into(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        })
        .await
        .expect("put_community");

        let e1 = d
            .community_dek_bump_epoch(&comm)
            .await
            .expect("genesis epoch");
        let e2 = at_rest_cascade::orchestrate::rekey_community_member_revoke(
            d,
            &comm,
            &cm[0],
            chrono::Utc::now(),
        )
        .await
        .expect("rekey on revoke");
        assert!(
            e2 > e1,
            "removal bumps the community DEK epoch (forward secrecy)"
        );
        let active: Vec<String> = d
            .active_members(Cohort::Community, &comm)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        assert!(
            !active.contains(&cm[0]),
            "removed member excluded from active roster"
        );
        let evs = d
            .list_hard_case_events(HardCaseFilter {
                kind: Some(kind::COMMUNITY_MEMBERSHIP_CHANGE.into()),
                since: None,
            })
            .await
            .expect("list events");
        assert!(
            evs.iter()
                .any(|e| e.subject_key_id.as_deref() == Some(cm[0].as_str())
                    && e.detail["change_kind"] == change_kind::REMOVED),
            "§9 community removed event emitted"
        );

        // ── §9 family cohort revoke + add events ──
        let fam = format!("g4-fam-{s}");
        let fmk: Vec<String> = (0..3).map(|i| format!("g4-fm{i}-{s}")).collect();
        d.put_public_key(sweeper_test_key(&fam))
            .await
            .expect("seed");
        for k in &fmk {
            d.put_public_key(sweeper_test_key(k)).await.expect("seed");
        }
        d.put_family(crate::federation::SignedFamily {
            family: types::Family {
                family_key_id: fam.clone(),
                family_name: "f".into(),
                members: vec![types::FamilyMember {
                    key_id: fmk[0].clone(),
                    joined_at: joined,
                    role: None,
                }],
                founded_at: joined,
                consensus_protocol: "founder_only".into(),
                consensus_protocol_entrenched: false,
                persist_row_hash: String::new(),
            },
        })
        .await
        .expect("put_family");

        // add → §9 added event
        assert!(d
            .add_member(
                Cohort::Family,
                &fam,
                RosterMember {
                    key_id: fmk[1].clone(),
                    joined_at: joined,
                    role: None
                },
            )
            .await
            .expect("add_member"));
        // revoke → §9 removed event (family FS is inherent fresh-per-write)
        d.revoke_member(
            Cohort::Family,
            &fam,
            &fmk[0],
            RevokeSpec {
                effective_at: chrono::Utc::now(),
                reason: None,
                witness_set: vec![],
            },
        )
        .await
        .expect("revoke_member");
        let fevs = d
            .list_hard_case_events(HardCaseFilter {
                kind: Some(kind::FAMILY_MEMBERSHIP_CHANGE.into()),
                since: None,
            })
            .await
            .expect("list family events");
        assert!(
            fevs.iter()
                .any(|e| e.subject_key_id.as_deref() == Some(fmk[1].as_str())
                    && e.detail["change_kind"] == change_kind::ADDED),
            "§9 family added event"
        );
        assert!(
            fevs.iter()
                .any(|e| e.subject_key_id.as_deref() == Some(fmk[0].as_str())
                    && e.detail["change_kind"] == change_kind::REMOVED),
            "§9 family removed event"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn g4_rekey_events_sqlite() {
        let signer = crate::federation::tier_ingest::test_support::local_signer("g4");
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        g4_rekey_events_body(&*sq, "sq").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn g4_rekey_events_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let label = format!("g4-{}", uuid::Uuid::new_v4().simple());
        let signer = crate::federation::tier_ingest::test_support::local_signer(&label);
        let engine = Engine::with_signer(signer, &dsn).await.expect("pg engine");
        let pg = engine.postgres_backend().expect("pg backend").clone();
        g4_rekey_events_body(&*pg, &uuid::Uuid::new_v4().simple().to_string()).await;
    }

    /// #249 — `file_moderation` stores a `moderation:{allegation}` scores
    /// row when the signer is a named moderator (community founder, as-self
    /// duty-holder). Proves the §11.10 EMIT path is feature-free (no
    /// `--features cirisnode`) and admitted by the always-present
    /// `check_delegated_duty_scores_admission` gate.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn file_moderation_stores_moderation_scores_sqlite() {
        use crate::federation::FederationDirectory;
        let signer = crate::federation::tier_ingest::test_support::local_signer("founder");
        let derived = signer.derived_key_id();
        let engine = Engine::with_signer(signer.clone(), "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        sq.put_public_key(user_test_key_derived_for(&derived, "founder"))
            .await
            .expect("seed founder");
        seed_community_with_founder(&engine, "comm-1", &derived).await;

        // The founder IS a named moderator (community authority root,
        // steward-bound) → as-self duty-holder → ADMIT.
        let content_sha = "a".repeat(64);
        let att_id = engine
            .file_moderation(&signer, &content_sha, "comm-1", "moderate", "rogue_action")
            .await
            .expect("file_moderation admitted for a named moderator");
        let row = sq.get_attestation(&att_id).await.unwrap().expect("row");
        assert_eq!(
            row.attestation_type,
            crate::federation::types::attestation_type::SCORES
        );
        assert_eq!(
            row.attestation_envelope["dimension"], "moderation:rogue_action:v1",
            "moderation:{{allegation}}:v1 dimension"
        );
        assert_eq!(row.attesting_key_id, derived, "attester == derived (#247)");
    }

    // ── PG twins ──────────────────────────────────────────────────────

    /// #249 PG twin of the add_moderator ↔ is_named_moderator round-trip.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn add_then_remove_moderator_round_trip_postgres() {
        use crate::federation::admission::is_named_moderator;
        use crate::federation::types::delegation_scope::SCOPE_MODERATE;
        use crate::federation::FederationDirectory;
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let label = format!("founder-{}", uuid::Uuid::new_v4().simple());
        let signer = crate::federation::tier_ingest::test_support::local_signer(&label);
        let derived = signer.derived_key_id();
        let engine = Engine::with_signer(signer.clone(), &dsn)
            .await
            .expect("pg engine");
        let pg = engine.postgres_backend().expect("pg").clone();
        let community = format!("comm-{}", uuid::Uuid::new_v4().simple());
        let moderator = format!("mod-{}", uuid::Uuid::new_v4().simple());
        pg.put_public_key(user_test_key_derived_for(&derived, &label))
            .await
            .expect("seed founder");
        pg.put_public_key(sweeper_test_key(&moderator))
            .await
            .expect("seed moderator");
        seed_community_with_founder(&engine, &community, &derived).await;

        let appt = engine
            .add_moderator(&signer, &community, &moderator, SCOPE_MODERATE)
            .await
            .expect("add_moderator");
        assert!(
            is_named_moderator(&*pg, &moderator, &community, SCOPE_MODERATE)
                .await
                .unwrap(),
            "is_named_moderator TRUE after add_moderator (PG)"
        );
        engine
            .remove_moderator(&signer, &community, &appt, &moderator, SCOPE_MODERATE)
            .await
            .expect("remove_moderator");
        assert!(
            !is_named_moderator(&*pg, &moderator, &community, SCOPE_MODERATE)
                .await
                .unwrap(),
            "is_named_moderator FALSE after remove_moderator (PG)"
        );
    }

    /// #249 PG twin — `file_moderation` stores the moderation scores row.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn file_moderation_stores_moderation_scores_postgres() {
        use crate::federation::FederationDirectory;
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let label = format!("founder-{}", uuid::Uuid::new_v4().simple());
        let signer = crate::federation::tier_ingest::test_support::local_signer(&label);
        let derived = signer.derived_key_id();
        let engine = Engine::with_signer(signer.clone(), &dsn)
            .await
            .expect("pg engine");
        let pg = engine.postgres_backend().expect("pg").clone();
        let community = format!("comm-{}", uuid::Uuid::new_v4().simple());
        pg.put_public_key(user_test_key_derived_for(&derived, &label))
            .await
            .expect("seed founder");
        seed_community_with_founder(&engine, &community, &derived).await;

        let content_sha = "b".repeat(64);
        let att_id = engine
            .file_moderation(
                &signer,
                &content_sha,
                &community,
                "moderate",
                "rogue_action",
            )
            .await
            .expect("file_moderation admitted (PG)");
        let row = pg.get_attestation(&att_id).await.unwrap().expect("row");
        assert_eq!(
            row.attestation_envelope["dimension"],
            "moderation:rogue_action:v1"
        );
        assert_eq!(row.attesting_key_id, derived);
    }

    // ── v5.4.0 (CIRISPersist#198, CEG 1.0 §5.6.8.8.2) LocalIdentityAggregate ──

    /// Assert the full v1 aggregate shape + §5.6.8.8.2 conformance on a
    /// constructed engine: signing role populated, content-KEM `Some` and
    /// independent of the signing key, RET-transport `None`, version 1,
    /// stable across two calls, and a clean serde JSON round-trip.
    ///
    /// Gated to backend builds: `local_identity_aggregate` exists only
    /// with a `postgres`/`sqlite` BackendDispatch arm, and this helper is
    /// called only from the backend-gated tests below.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    async fn assert_local_identity_aggregate_conformance(engine: &Engine) {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;

        let agg = engine
            .local_identity_aggregate(None, None)
            .await
            .expect("aggregate");

        // Version + role presence.
        assert_eq!(agg.aggregate_version, 1);
        assert!(!agg.ed25519_pubkey_b64.is_empty(), "signing role required");
        assert!(
            agg.ml_dsa_65_pubkey_b64.is_some(),
            "pqc_signer engine → ML-DSA-65 present"
        );
        assert!(
            agg.reticulum_x25519_pubkey_b64.is_none() && agg.reticulum_ed25519_pubkey_b64.is_none(),
            "RET-transport role is None in v1 (#199 seam)"
        );
        assert!(
            agg.content_x25519_pubkey_b64.is_some() && agg.content_ml_kem_768_pubkey_b64.is_some(),
            "content-KEM role populated in v1"
        );
        assert!(agg.did_key.is_none(), "did_key deferred in v1");
        assert_eq!(agg.identity_hash.len(), 64, "sha256 hex identity_hash");

        // §5.6.8.8.2: content-KEM x25519 is NOT the Ed25519 signing pubkey
        // (no derivation; independently minted).
        let content_x = agg.content_x25519_pubkey_b64.clone().unwrap();
        assert_ne!(
            content_x, agg.ed25519_pubkey_b64,
            "content-KEM x25519 must never equal the Ed25519 signing pubkey (§5.6.8.8.2)"
        );
        assert_eq!(
            B64.decode(&content_x).unwrap().len(),
            32,
            "content-KEM x25519 is 32 raw bytes"
        );
        assert_eq!(
            B64.decode(agg.content_ml_kem_768_pubkey_b64.as_ref().unwrap())
                .unwrap()
                .len(),
            ciris_crypto::ml_kem::ML_KEM_768_PUBKEY_LEN,
            "content-KEM ML-KEM-768 is 1184 raw bytes"
        );

        // Stable across two calls (idempotent content-KEM load; identical
        // pubkeys ⇒ identical identity_hash).
        let agg2 = engine
            .local_identity_aggregate(None, None)
            .await
            .expect("aggregate2");
        assert_eq!(
            agg.content_x25519_pubkey_b64, agg2.content_x25519_pubkey_b64,
            "content-KEM x25519 stable across calls"
        );
        assert_eq!(
            agg.content_ml_kem_768_pubkey_b64, agg2.content_ml_kem_768_pubkey_b64,
            "content-KEM ML-KEM-768 stable across calls"
        );
        assert_eq!(
            agg.identity_hash, agg2.identity_hash,
            "identity_hash stable across calls"
        );

        // serde JSON round-trip.
        let json = serde_json::to_string(&agg).unwrap();
        let back: crate::federation::LocalIdentityAggregate = serde_json::from_str(&json).unwrap();
        assert_eq!(agg, back);

        // ── v5.5.0 (#199) — caller-supplied RET-transport role. ──
        // A valid (distinct) transport keypair populates the role and
        // changes the identity_hash (a new role folded in).
        let t_x = B64.encode([0x11u8; 32]);
        let t_ed = B64.encode([0x22u8; 32]);
        let with_t = engine
            .local_identity_aggregate(Some(t_x.clone()), Some(t_ed.clone()))
            .await
            .expect("transport-populated aggregate");
        assert_eq!(
            with_t.reticulum_x25519_pubkey_b64.as_deref(),
            Some(t_x.as_str())
        );
        assert_eq!(
            with_t.reticulum_ed25519_pubkey_b64.as_deref(),
            Some(t_ed.as_str())
        );
        assert_ne!(
            with_t.identity_hash, agg.identity_hash,
            "RET-transport role folds into identity_hash"
        );

        // both-or-neither: exactly one half → error.
        assert!(engine
            .local_identity_aggregate(Some(t_x.clone()), None)
            .await
            .is_err());

        // §5.6.8.8.2 / #71-C4: transport x25519 == content-KEM x25519 → reject.
        assert!(
            engine
                .local_identity_aggregate(Some(content_x.clone()), Some(t_ed))
                .await
                .is_err(),
            "transport x25519 reusing the content-KEM x25519 must be rejected (§5.6.8.8.2)"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn local_identity_aggregate_v1_conformance_sqlite() {
        let engine = Engine::with_signer(pqc_signer("local-id"), "sqlite::memory:")
            .await
            .expect("construct engine");
        assert_local_identity_aggregate_conformance(&engine).await;
    }

    /// v7.1.0 (CIRISPersist#223) — `local_signer: None` (a `from_shared`
    /// cohabitation view, or a classical-only `with_hardware_signer`) NO
    /// LONGER errors: `local_identity_aggregate` falls back to the engine's
    /// `signer` (the `Arc<dyn HardwareSigner>`) for the Ed25519 signing role,
    /// so the node still produces its six-key aggregate. (Was: "signing role
    /// mandatory → error" — that invariant is intentionally removed.)
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn local_identity_aggregate_falls_back_to_signer_without_local() {
        let signed = Engine::with_signer(pqc_signer("local-id"), "sqlite::memory:")
            .await
            .expect("construct engine");
        // The Ed25519 pubkey the fallback resolves from the signer adapter.
        let ed_pubkey_b64 = {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            B64.encode(signed.signer().public_key().await.expect("signer pubkey"))
        };
        // from_shared drops the LocalSigner (local_signer: None) but keeps the
        // signer adapter — the #223 fallback path.
        let engine = Engine::from_shared(signed.backend().clone(), signed.signer().clone());
        let agg = engine
            .local_identity_aggregate(None, None)
            .await
            .expect("#223: aggregate falls back to the signer, no error");
        assert_eq!(
            agg.ed25519_pubkey_b64, ed_pubkey_b64,
            "Ed25519 signing pubkey resolved from the engine's signer"
        );
        assert!(
            agg.content_x25519_pubkey_b64.is_some() && agg.content_ml_kem_768_pubkey_b64.is_some(),
            "content-KEM minted + populated"
        );
    }

    /// Live-PG twin of the sqlite conformance test. Skips when
    /// `CIRIS_PERSIST_TEST_PG_URL` is unset.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn local_identity_aggregate_v1_conformance_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let alias = format!("local-id-{}", uuid::Uuid::new_v4().simple());
        let engine = Engine::with_signer(pqc_signer(&alias), &dsn)
            .await
            .expect("construct PG engine");
        assert_local_identity_aggregate_conformance(&engine).await;
    }

    // ── v6.3.0 (CIRISPersist#135, Lane C) — media-detector read facades ──
    //
    // Engine-level `list_takedowns_for` / `list_key_grants_for` +
    // `list_attestations`. These exercise the public Rust facade
    // end-to-end on SQLite (the lib-test backend); the PG twins are
    // env-gated (compile-checked here, runtime-verified by the lead's
    // localhost:5433 docker PG). The fixtures sign over the canonical
    // envelope so `put_contribution` admits them with no trust gate and
    // no registered author key (author_id == the signing pubkey).

    #[cfg(feature = "cirisnode")]
    fn media_pubkey_b64(key: &SigningKey) -> String {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ed25519_dalek::VerifyingKey;
        let vk: VerifyingKey = key.verifying_key();
        B64.encode(vk.to_bytes())
    }

    #[cfg(feature = "cirisnode")]
    fn media_sign(
        env: &crate::cirisnode::ContributionEnvelope,
        key: &SigningKey,
    ) -> crate::cirisnode::HybridSignature {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;
        let canonical =
            crate::cirisnode::verify::canonical_bytes_for_envelope(env).expect("canonical bytes");
        crate::cirisnode::HybridSignature {
            ed25519: B64.encode(key.sign(&canonical).to_bytes()),
            ml_dsa_65: None,
            signed_at: chrono::Utc::now(),
        }
    }

    #[cfg(feature = "cirisnode")]
    fn media_sha_hex(seed: u8) -> String {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        hex::encode(bytes)
    }

    /// Build a signed `takedown_notice` Contribution with a chosen
    /// claimant + `submitted_at` (so the secondary-key / window / cursor
    /// axes are controllable).
    #[cfg(feature = "cirisnode")]
    fn media_build_takedown(
        author_key: &SigningKey,
        sha_hex: &str,
        claimant_key_id: &str,
        submitted_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::cirisnode::ContributionEnvelope {
        use crate::cirisnode::{Cell, ContributionEnvelope, ContributionType, HybridSignature};
        let author = media_pubkey_b64(author_key);
        let payload = crate::cirisnode::TakedownNoticePayload {
            content_sha256: sha_hex.to_owned(),
            perceptual_hash: None,
            content_holder_key_ids: vec![],
            claimant_key_id: claimant_key_id.to_owned(),
            legal_basis: crate::cirisnode::LegalBasis::Dmca512,
            jurisdiction: "US".into(),
            good_faith_statement: "good faith".into(),
            claim_text: "claim".into(),
            evidence_refs: vec![],
            counter_notice_channel: None,
            asserted_at: submitted_at,
            expires_at: submitted_at + chrono::Duration::days(30),
        };
        // v8.7.1 (#233): the §11.10 gate requires the author to be a
        // duty-holder over the target. These tests exercise takedown
        // listing/filtering mechanics, not the moderation gate, so the
        // author self-declares as a subject of the target (as-self path).
        let mut payload_json = serde_json::to_value(&payload).unwrap();
        payload_json["subject_key_ids"] = serde_json::json!([author.clone()]);
        let mut env = ContributionEnvelope {
            contribution_id: uuid::Uuid::new_v4().to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author,
            subject: Cell {
                domain: format!("media-{}", uuid::Uuid::new_v4()),
                language: "en".into(),
                subject: Some(crate::cirisnode::TAKEDOWN_NOTICE_SUBJECT_KIND.into()),
            },
            payload: payload_json,
            witness_set: None,
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: submitted_at,
            },
            submitted_at,
        };
        env.signature = media_sign(&env, author_key);
        env
    }

    /// Build a signed `key_grant` Contribution with a chosen recipient +
    /// content + `submitted_at`. The grant publisher is `author_key`.
    #[cfg(feature = "cirisnode")]
    fn media_build_key_grant(
        author_key: &SigningKey,
        sha_hex: &str,
        recipient_key_id: &str,
        submitted_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::cirisnode::ContributionEnvelope {
        use crate::cirisnode::{Cell, ContributionEnvelope, ContributionType, HybridSignature};
        let author = media_pubkey_b64(author_key);
        let payload = crate::cirisnode::KeyGrantPayload {
            recipient_key_id: recipient_key_id.to_owned(),
            content_sha256: Some(sha_hex.to_owned()),
            stream_id: None,
            stream_epoch: None,
            wrapped_dek_base64: {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode([0u8; 48])
            },
            wrap_algorithm: crate::cirisnode::WrapAlgorithm::HpkeRfc9180BaseX25519AesGcm,
            ratchet_version: 1,
            key_validity_window: crate::cirisnode::KeyValidityWindow {
                not_before: submitted_at,
                not_after: submitted_at + chrono::Duration::days(30),
            },
            scope: crate::cirisnode::KeyGrantScope::SingleContent,
            scope_id: sha_hex.to_owned(),
            rotation_chain: vec![],
        };
        let mut env = ContributionEnvelope {
            contribution_id: uuid::Uuid::new_v4().to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author,
            subject: Cell {
                domain: format!("media-{}", uuid::Uuid::new_v4()),
                language: "en".into(),
                subject: Some(crate::cirisnode::KEY_GRANT_SUBJECT_KIND.into()),
            },
            payload: serde_json::to_value(&payload).unwrap(),
            witness_set: None,
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: submitted_at,
            },
            submitted_at,
        };
        env.signature = media_sign(&env, author_key);
        env
    }

    /// Seed a contribution through the SQLite NodeCore dispatch the
    /// Engine facade composes over.
    #[cfg(all(feature = "sqlite", feature = "cirisnode"))]
    async fn media_seed(engine: &Engine, env: crate::cirisnode::ContributionEnvelope) {
        use crate::cirisnode::NodeCoreService;
        match engine.node_core_service() {
            NodeCoreDispatch::Sqlite(b) => {
                b.put_contribution(env).await.expect("seed contribution")
            }
            #[cfg(feature = "postgres")]
            NodeCoreDispatch::Postgres(b) => {
                b.put_contribution(env).await.expect("seed contribution")
            }
        }
    }

    /// v8.7.2 (#233 follow-on, CEG RC27 §11.10) — seed `producer`'s
    /// federation key + a content-ESTABLISHING `scores` attestation binding
    /// `sha_hex` with SIGNED subjects=[producer], through the Engine's
    /// federation directory. The §11.10 takedown gate resolves subject-self
    /// authority over THIS, so listing/filtering tests must establish the
    /// content before filing takedowns (the payload's `subject_key_ids` is
    /// advisory only).
    #[cfg(all(feature = "sqlite", feature = "cirisnode"))]
    async fn media_seed_establishing(engine: &Engine, producer_key: &SigningKey, sha_hex: &str) {
        let producer = media_pubkey_b64(producer_key);
        let dir = engine.federation_directory();
        // v9.0.0 (CC 5.3.2.4.3.1) — register REAL deterministic hybrid
        // pubkeys + hybrid-sign the establishing content so the ingest
        // gate admits it. Takedown payloads verify self-contained against
        // their `author_id` pubkey, not this registered row.
        let (ed_pk, mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(&producer);
        dir.put_public_key(crate::federation::types::SignedKeyRecord {
            record: crate::federation::types::KeyRecord {
                key_id: producer.clone(),
                pubkey_ed25519_base64: ed_pk,
                pubkey_ml_dsa_65_base64: mldsa_pk,
                algorithm: crate::federation::types::algorithm::HYBRID.into(),
                identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
                identity_ref: producer.clone(),
                valid_from: "2026-01-01T00:00:00Z".parse().unwrap(),
                valid_until: None,
                registration_envelope: serde_json::json!({ "id": producer }),
                original_content_hash: "deadbeef".into(),
                scrub_signature_classical: "c2lnbmF0dXJl".into(),
                scrub_signature_pqc: None,
                scrub_key_id: producer.clone(),
                scrub_timestamp: "2026-01-01T00:00:00Z".parse().unwrap(),
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .map_or_else(
            |e| match e {
                // Tolerate an idempotent re-seed on a reused PG (the
                // PG-twin tests share the lead's docker DB across runs).
                crate::federation::Error::Conflict(_) => {}
                other => panic!("seed producer key: {other}"),
            },
            |()| {},
        );
        let establishing_envelope = serde_json::json!({
            "dimension": "content:established:v1",
            "evidence_refs": [sha_hex],
        });
        let (och, classical, pqc) = crate::federation::tier_ingest::test_support::sign_envelope(
            &producer,
            &establishing_envelope,
        );
        dir.put_attestation(crate::federation::types::SignedAttestation {
            attestation: crate::federation::types::Attestation {
                attestation_id: uuid::Uuid::new_v4().to_string(),
                attesting_key_id: producer.clone(),
                attested_key_id: producer.clone(),
                attestation_type: crate::federation::types::attestation_type::SCORES.into(),
                weight: None,
                asserted_at: "2026-01-01T00:00:00Z".parse().unwrap(),
                expires_at: None,
                attestation_envelope: establishing_envelope,
                original_content_hash: och,
                scrub_signature_classical: classical,
                scrub_signature_pqc: pqc,
                scrub_key_id: producer.clone(),
                scrub_timestamp: "2026-01-01T00:00:00Z".parse().unwrap(),
                pqc_completed_at: Some("2026-01-01T00:00:00Z".parse().unwrap()),
                persist_row_hash: String::new(),
                subject_key_ids: vec![producer.clone()],
                withdraws_admission_rule: None,
                cohort_scope: "federation".to_string(),
                tier: crate::federation::types::attestation_tier::FEDERATION.to_string(),
                promoted_at: None,
            },
        })
        .await
        .expect("seed establishing content");
    }

    /// `list_takedowns_for` returns only the target's takedowns, honours
    /// the `claimant_key_id` secondary filter, and respects the
    /// `[since, until)` window.
    #[cfg(all(feature = "sqlite", feature = "cirisnode"))]
    #[tokio::test]
    async fn list_takedowns_for_filters_target_claimant_and_window() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("engine");
        let k1 = SigningKey::from_bytes(&[0x11; 32]);
        let k2 = SigningKey::from_bytes(&[0x22; 32]);
        let claimant_a = media_pubkey_b64(&k1);
        let claimant_b = media_pubkey_b64(&k2);
        let target = media_sha_hex(0x40);
        let other = media_sha_hex(0x41);
        let t0 = "2026-01-01T00:00:00Z".parse().unwrap();
        let t1 = "2026-02-01T00:00:00Z".parse().unwrap();
        // v8.7.2: establish content provenance so each filer (author) is a
        // SIGNED subject of the content it takes down (subject-self path).
        media_seed_establishing(&engine, &k1, &target).await;
        media_seed_establishing(&engine, &k2, &target).await;
        media_seed_establishing(&engine, &k1, &other).await;
        // target × claimant_a @ t0, target × claimant_b @ t1, other-target.
        media_seed(&engine, media_build_takedown(&k1, &target, &claimant_a, t0)).await;
        media_seed(&engine, media_build_takedown(&k2, &target, &claimant_b, t1)).await;
        media_seed(&engine, media_build_takedown(&k1, &other, &claimant_a, t1)).await;

        // Per-target: two rows, neither from `other`.
        let page = engine
            .list_takedowns_for(&target, Default::default(), None, 100)
            .await
            .expect("per-target");
        assert_eq!(page.items.len(), 2, "both target takedowns");
        assert!(page.next_cursor.is_none());

        // Per-target × per-claimant: just claimant_a's.
        let page = engine
            .list_takedowns_for(
                &target,
                crate::cirisnode::TakedownFilter {
                    claimant_key_id: Some(claimant_a.clone()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .expect("per-claimant");
        assert_eq!(page.items.len(), 1);
        assert_eq!(
            page.items[0]
                .payload
                .get("claimant_key_id")
                .and_then(|v| v.as_str()),
            Some(claimant_a.as_str())
        );

        // Window `[t1, +inf)` excludes the t0 row.
        let page = engine
            .list_takedowns_for(
                &target,
                crate::cirisnode::TakedownFilter {
                    since: Some(t1),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .expect("window");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].submitted_at, t1);
    }

    /// `list_takedowns_for` pages deterministically: a `limit`-1 walk
    /// yields every row exactly once, newest-first, no duplicates across
    /// the cursor boundary (even with a shared `submitted_at`).
    #[cfg(all(feature = "sqlite", feature = "cirisnode"))]
    #[tokio::test]
    async fn list_takedowns_for_cursor_pages_without_gaps_or_dupes() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("engine");
        let k = SigningKey::from_bytes(&[0x33; 32]);
        let claimant = media_pubkey_b64(&k);
        let target = media_sha_hex(0x50);
        // Five rows; two share a timestamp to exercise the
        // contribution_id tiebreaker.
        let shared = "2026-03-01T00:00:00Z".parse().unwrap();
        let stamps: [chrono::DateTime<chrono::Utc>; 5] = [
            "2026-03-05T00:00:00Z".parse().unwrap(),
            "2026-03-04T00:00:00Z".parse().unwrap(),
            shared,
            shared,
            "2026-03-02T00:00:00Z".parse().unwrap(),
        ];
        // v8.7.2: establish content so the filer is a signed subject.
        media_seed_establishing(&engine, &k, &target).await;
        for ts in stamps {
            media_seed(&engine, media_build_takedown(&k, &target, &claimant, ts)).await;
        }

        let mut seen: Vec<String> = Vec::new();
        let mut cursor = None;
        loop {
            let page = engine
                .list_takedowns_for(&target, Default::default(), cursor.clone(), 2)
                .await
                .expect("page");
            for it in &page.items {
                seen.push(it.contribution_id.clone());
            }
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        assert_eq!(seen.len(), 5, "every row once");
        let mut deduped = seen.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), 5, "no duplicate across cursor boundary");
    }

    /// `list_key_grants_for` returns only the recipient's grants, honours
    /// the `publisher_key_id` secondary filter, and the `content_sha256`
    /// scope routes through the two-axis index path.
    #[cfg(all(feature = "sqlite", feature = "cirisnode"))]
    #[tokio::test]
    async fn list_key_grants_for_filters_recipient_publisher_and_content() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("engine");
        let pub_a = SigningKey::from_bytes(&[0x44; 32]);
        let pub_b = SigningKey::from_bytes(&[0x55; 32]);
        let publisher_a = media_pubkey_b64(&pub_a);
        let recipient = "recipient-key-1";
        let other_recipient = "recipient-key-2";
        let sha_x = media_sha_hex(0x60);
        let sha_y = media_sha_hex(0x61);
        let t = "2026-04-01T00:00:00Z".parse().unwrap();
        media_seed(&engine, media_build_key_grant(&pub_a, &sha_x, recipient, t)).await;
        media_seed(&engine, media_build_key_grant(&pub_b, &sha_y, recipient, t)).await;
        media_seed(
            &engine,
            media_build_key_grant(&pub_a, &sha_x, other_recipient, t),
        )
        .await;

        // Per-recipient: two grants (both publishers), none for `other`.
        let page = engine
            .list_key_grants_for(recipient, Default::default(), None, 100)
            .await
            .expect("per-recipient");
        assert_eq!(page.items.len(), 2);

        // Per-recipient × per-publisher: just publisher_a's.
        let page = engine
            .list_key_grants_for(
                recipient,
                crate::cirisnode::KeyGrantFilter {
                    publisher_key_id: Some(publisher_a.clone()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .expect("per-publisher");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].author_id, publisher_a);

        // content_sha256 scope (two-axis index path): only the sha_x grant.
        let page = engine
            .list_key_grants_for(
                recipient,
                crate::cirisnode::KeyGrantFilter {
                    content_sha256: Some(sha_x.clone()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .expect("content-scope");
        assert_eq!(page.items.len(), 1);
        assert_eq!(
            page.items[0]
                .payload
                .get("content_sha256")
                .and_then(|v| v.as_str()),
            Some(sha_x.as_str())
        );
    }

    /// `list_takedowns_for` / `list_key_grants_for` reject an
    /// out-of-range `limit` (parity with the storage cap).
    #[cfg(all(feature = "sqlite", feature = "cirisnode"))]
    #[tokio::test]
    async fn media_facades_reject_bad_limit() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("engine");
        let err = engine
            .list_takedowns_for("deadbeef", Default::default(), None, 0)
            .await
            .expect_err("limit 0 rejected");
        assert!(matches!(err, crate::cirisnode::Error::InvalidArgument(_)));
        let err = engine
            .list_key_grants_for("r", Default::default(), None, 99_999)
            .await
            .expect_err("limit too large");
        assert!(matches!(err, crate::cirisnode::Error::InvalidArgument(_)));
    }

    /// `list_attestations` facade dispatches to the backend
    /// `ReadEngine::list_attestations` — an empty store returns an empty
    /// page (no error), proving the dispatch + scope plumbing compile and
    /// run. (Row-level filter behaviour is covered by the ReadEngine
    /// suite; this asserts the Engine facade wiring.)
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn list_attestations_facade_dispatches_to_backend_sqlite() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("engine");
        let page = engine
            .list_attestations(
                crate::ceg::AttestationFilter::default(),
                None,
                100,
                crate::scope::CallerScope::Unauthenticated,
            )
            .await
            .expect("list_attestations facade");
        assert!(page.items.is_empty());
        assert!(page.next_cursor.is_none());
    }

    /// PG twin of `list_takedowns_for_filters_target_claimant_and_window`
    /// — env-gated; runtime-verified against the lead's docker PG.
    #[cfg(all(feature = "postgres", feature = "cirisnode"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn list_takedowns_for_filters_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let alias = format!("media-td-{}", uuid::Uuid::new_v4().simple());
        let engine = Engine::with_signer(pqc_signer(&alias), &dsn)
            .await
            .expect("PG engine");
        let k1 = SigningKey::from_bytes(&[0x11; 32]);
        let k2 = SigningKey::from_bytes(&[0x22; 32]);
        let claimant_a = media_pubkey_b64(&k1);
        let claimant_b = media_pubkey_b64(&k2);
        // Unique-per-run target (64-hex, sha256-shaped) so the test is
        // self-isolating against a reused PG — mirrors the key_grants twin's
        // per-run `recipient`. A fixed target accumulates rows across runs on
        // a persistent DB (CI's PG is ephemeral, but local verification reuses
        // one) and breaks the exact-count assertion.
        let target = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let t0 = "2026-01-01T00:00:00Z".parse().unwrap();
        let t1 = "2026-02-01T00:00:00Z".parse().unwrap();
        // v8.7.2: establish content provenance so each filer is a signed
        // subject of the content it takes down (per-run target ⇒ isolated).
        media_seed_establishing(&engine, &k1, &target).await;
        media_seed_establishing(&engine, &k2, &target).await;
        media_seed(&engine, media_build_takedown(&k1, &target, &claimant_a, t0)).await;
        media_seed(&engine, media_build_takedown(&k2, &target, &claimant_b, t1)).await;
        let page = engine
            .list_takedowns_for(
                &target,
                crate::cirisnode::TakedownFilter {
                    claimant_key_id: Some(claimant_a.clone()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .expect("per-claimant");
        assert_eq!(page.items.len(), 1);
    }

    /// PG twin of the key_grant facade test — env-gated.
    #[cfg(all(feature = "postgres", feature = "cirisnode"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn list_key_grants_for_filters_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let alias = format!("media-kg-{}", uuid::Uuid::new_v4().simple());
        let engine = Engine::with_signer(pqc_signer(&alias), &dsn)
            .await
            .expect("PG engine");
        let pub_a = SigningKey::from_bytes(&[0x44; 32]);
        let publisher_a = media_pubkey_b64(&pub_a);
        let recipient = format!("rec-{}", uuid::Uuid::new_v4());
        let sha_x = media_sha_hex(0x60);
        let t = "2026-04-01T00:00:00Z".parse().unwrap();
        media_seed(
            &engine,
            media_build_key_grant(&pub_a, &sha_x, &recipient, t),
        )
        .await;
        let page = engine
            .list_key_grants_for(
                &recipient,
                crate::cirisnode::KeyGrantFilter {
                    content_sha256: Some(sha_x.clone()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .expect("content-scope");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].author_id, publisher_a);
    }

    // ── v6.5.0 (CIRISPersist#183, CEG §8.1.12.7) self-at-login ─────

    /// Build a PQC-capable LocalSigner so `attestation_promote`'s
    /// `sign_hybrid` (Ed25519 + ML-DSA-65) succeeds. A unique alias per
    /// call keeps PG-side rows self-isolating.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn self_login_signer() -> (Arc<LocalSigner>, String) {
        let alias = format!("self-login-steward-{}", uuid::Uuid::new_v4().simple());
        let signing_key = SigningKey::from_bytes(&[0x3C; 32]);
        let pqc = ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(
            &[0x3C ^ 0x55; 32],
            "self-login-pqc",
        )
        .expect("pqc seed");
        let pqc_arc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(pqc);
        let signer = Arc::new(LocalSigner::from_parts(
            signing_key,
            alias.clone(),
            Some(pqc_arc),
            Some("self-login-pqc".to_owned()),
        ));
        (signer, alias)
    }

    /// Seed a `federation_keys` row directly so the FK + admission checks
    /// the self-at-login flow runs against are satisfied (key minting is
    /// upstream of the flow).
    #[cfg(feature = "sqlite")]
    async fn self_login_seed_key(engine: &Engine, key_id: &str, identity_type: &str) {
        let sq = engine.sqlite_backend().expect("sqlite");
        let conn = sq.conn_handle();
        let key_id = key_id.to_owned();
        let identity_type = identity_type.to_owned();
        (move || {
            let conn = conn.lock();
            conn.execute(
                "INSERT OR IGNORE INTO federation_keys (\
                    key_id, pubkey_ed25519_base64, algorithm, \
                    identity_type, identity_ref, valid_from, \
                    registration_envelope, original_content_hash, \
                    scrub_signature_classical, scrub_key_id, \
                    scrub_timestamp, persist_row_hash\
                 ) VALUES (?1, 'AAAA', 'hybrid', ?2, ?1, \
                          '2026-01-01T00:00:00Z', '{}', \
                          x'00', '', ?1, '2026-01-01T00:00:00Z', '0')",
                rusqlite::params![key_id, identity_type],
            )
            .unwrap();
        })();
    }

    /// Happy path: co-admit app + agent occurrences, partner + delegate,
    /// promote the delegation to federation tier, register reachability.
    /// Proves the §8.1.12.7 flow lands every artifact through the
    /// composed substrate.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn self_at_login_lands_full_flow() {
        use crate::federation::types::identity_type;

        let (signer, _steward_alias) = self_login_signer();
        // v9.3.0 (#247) — the promote path inside self_at_login stamps
        // `scrub_key_id = signer's DERIVED federation key_id`, which must
        // exist in federation_keys (FK); seed the steward row under it.
        let steward_derived = signer.derived_key_id();
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine");

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let identity_key = format!("user-{suffix}");
        let app_key = format!("app-{suffix}");
        let agent_key = format!("agent-{suffix}");
        self_login_seed_key(&engine, &steward_derived, identity_type::STEWARD).await;
        // identity_type as a §7.0.1 set: this human is also a WA.
        let set = identity_type::join_set([identity_type::USER, identity_type::WISE_AUTHORITY]);
        assert_eq!(set, "user,wise_authority");
        self_login_seed_key(&engine, &identity_key, &set).await;
        self_login_seed_key(&engine, &app_key, identity_type::USER).await;
        self_login_seed_key(&engine, &agent_key, identity_type::AGENT).await;

        // Real content-KEM pubkeys so both occurrences are valid DEK
        // wrap targets (not fail-secure-excluded).
        let mk_keys = || {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            let (_xp, x_pub, _mp, ml_pub) =
                crate::federation::identity_aggregate::mint_content_kem_keypair()
                    .expect("mint content-kem");
            crate::federation::EncryptionPubkeys {
                x25519_base64: B64.encode(x_pub),
                ml_kem_768_base64: B64.encode(ml_pub),
            }
        };

        let pair_id = uuid::Uuid::new_v4().to_string();
        let input = SelfAtLoginInput {
            identity_key_id: identity_key.clone(),
            app: SelfAtLoginOccurrence {
                occurrence_key_id: app_key.clone(),
                device_class: crate::federation::device_class::PHONE.to_owned(),
                hardware_attestation: None,
                encryption_pubkeys: Some(mk_keys()),
                transport_destinations: vec![("reticulum".to_owned(), "dest-hash-app".to_owned())],
            },
            agent: SelfAtLoginOccurrence {
                occurrence_key_id: agent_key.clone(),
                device_class: crate::federation::device_class::AGENT.to_owned(),
                hardware_attestation: None,
                encryption_pubkeys: Some(mk_keys()),
                transport_destinations: vec![(
                    "websocket".to_owned(),
                    "wss://relay/agent".to_owned(),
                )],
            },
            bilateral_pair_id: pair_id.clone(),
            delegation_scope: None,
        };

        let outcome = engine.self_at_login(input).await.expect("self_at_login");

        // (1) Both occurrences co-admitted under the one identity key.
        let dir = engine.federation_directory();
        let occs = dir
            .list_identity_occurrences_for(&identity_key)
            .await
            .expect("occurrences");
        assert_eq!(occs.len(), 2, "app + agent co-admitted");

        // (3) Partnership grant + accept written, distinct ids.
        assert!(!outcome.partnership_grant_id.is_empty());
        assert!(!outcome.partnership_accept_id.is_empty());
        assert_ne!(outcome.partnership_grant_id, outcome.partnership_accept_id);

        // (4)+(5) Delegation written + promoted to federation tier.
        assert!(outcome.delegation_promoted, "delegation promoted");
        let delegation = dir
            .get_attestation(&outcome.delegation_id)
            .await
            .expect("get delegation")
            .expect("delegation row exists");
        assert_eq!(
            delegation.attestation_type,
            crate::federation::types::attestation_type::DELEGATES_TO
        );
        assert_eq!(
            delegation.tier,
            crate::federation::types::attestation_tier::FEDERATION,
            "delegation is federation-tier after promote"
        );
        // The delegation carries the full §8.1.12.7 scope set.
        let scope = delegation.attestation_envelope["scope"]
            .as_array()
            .expect("scope array");
        assert_eq!(scope.len(), 4);

        // (6) A transport_destination per occurrence.
        assert_eq!(outcome.transport_destinations_registered, 2);
        let app_dests = dir
            .list_transport_destinations_for(&app_key)
            .await
            .expect("app dests");
        assert_eq!(app_dests.len(), 1);
        assert_eq!(app_dests[0].transport_kind, "reticulum");
        assert_eq!(app_dests[0].destination, "dest-hash-app");

        // (2) Both occurrences are valid wrap targets → neither
        // fail-secure-excluded. `self_dek_granted` counts both (0 grants
        // each since no prior self-blobs existed, but they are in the
        // cohort). The cascade composes over the v6.2.0 re-key.
        assert!(
            outcome.self_dek_excluded.is_empty(),
            "no fail-secure exclusions"
        );
        assert_eq!(
            outcome.self_dek_granted, 2,
            "both occurrences in self cohort"
        );
    }

    /// #304 — the DERIVED content-KEM model: CIRISServer derives one
    /// content-KEM keypair per identity (verify v8.3.0), so every occurrence
    /// presents the IDENTICAL enc pubkey. Persist must (a) ACCEPT the
    /// duplicate pubkeys across occurrences, and (b) wrap the self DEK ONCE
    /// per distinct pubkey — proven here by byte-identical grants for the two
    /// shared-pubkey occurrences, vs a distinct grant for a different-pubkey
    /// control.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn self_dek_wrap_once_for_derived_identity_pubkeys_304() {
        use crate::federation::types::{self, identity_type};
        use crate::federation::BlobStorage;

        let (signer, _alias) = self_login_signer();
        let steward_derived = signer.derived_key_id();
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        self_login_seed_key(&engine, &steward_derived, identity_type::STEWARD).await;

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let identity_key = format!("user-{suffix}");
        self_login_seed_key(&engine, &identity_key, identity_type::USER).await;
        let mk_keys = || {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            let (_xp, x_pub, _mp, ml_pub) =
                crate::federation::identity_aggregate::mint_content_kem_keypair().expect("mint");
            crate::federation::EncryptionPubkeys {
                x25519_base64: B64.encode(x_pub),
                ml_kem_768_base64: B64.encode(ml_pub),
            }
        };
        // The DERIVED identity keypair — shared across occurrences A/B/C.
        let derived = mk_keys();
        // A distinct (non-derived) control keypair for occurrence D.
        let control = mk_keys();

        let seed_occ = |occ: String, keys: crate::federation::EncryptionPubkeys| {
            let identity_key = identity_key.clone();
            let engine = &engine;
            async move {
                self_login_seed_key(engine, &occ, identity_type::AGENT).await;
                engine
                    .federation_directory()
                    .put_identity_occurrence(crate::federation::SignedIdentityOccurrence {
                        identity_occurrence: types::IdentityOccurrence {
                            identity_key_id: identity_key,
                            occurrence_key_id: occ,
                            device_class: types::device_class::SERVER.into(),
                            hardware_attestation: None,
                            asserted_at: chrono::Utc::now(),
                            valid_until: None,
                            encryption_pubkeys: Some(keys),
                            persist_row_hash: String::new(),
                        },
                    })
                    .await
                    .expect("put_identity_occurrence");
            }
        };

        let occ_a = format!("a-{suffix}");
        seed_occ(occ_a.clone(), derived.clone()).await;

        // Encrypt a self blob (grants occurrence A + self-retention).
        let cascade = engine
            .put_blob_encrypted_self_family("self", &identity_key, b"derived-model", None)
            .await
            .expect("encrypt self blob");
        let sha = cascade.at_rest_sha256;

        // Add B + C sharing the DERIVED pubkey, and D with the control pubkey.
        let occ_b = format!("b-{suffix}");
        let occ_c = format!("c-{suffix}");
        let occ_d = format!("d-{suffix}");
        seed_occ(occ_b.clone(), derived.clone()).await; // accepted despite duplicate pubkey
        seed_occ(occ_c.clone(), derived.clone()).await;
        seed_occ(occ_d.clone(), control.clone()).await;
        let rekey = engine
            .rekey_self_occurrence_add(
                &identity_key,
                &[occ_b.clone(), occ_c.clone(), occ_d.clone()],
            )
            .await
            .expect("rekey");
        assert!(rekey.excluded.is_empty(), "all keyed, none fail-secure");

        let grant = |r: &str| {
            let sq = sq.clone();
            let r = r.to_owned();
            async move {
                sq.get_at_rest_grant(&sha, &r)
                    .await
                    .expect("grant")
                    .expect("exists")
            }
        };
        let (gb, gc, gd) = (
            grant(&occ_b).await,
            grant(&occ_c).await,
            grant(&occ_d).await,
        );
        // Wrap-once: B and C share the derived pubkey → byte-identical wrap.
        assert_eq!(
            gb.1, gc.1,
            "#304: derived-pubkey occurrences share one wrap"
        );
        // Control: D's distinct pubkey → a different wrap (dedup is by pubkey,
        // not blanket).
        assert_ne!(gb.1, gd.1, "distinct pubkey ⇒ distinct wrap");
    }

    /// transport_destination is idempotent on the composite PK + a
    /// removed row is gone (drop+re-register reachability model).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn transport_destination_upsert_and_remove() {
        use crate::federation::types::identity_type;
        use crate::federation::TransportDestination;

        let (signer, _alias) = self_login_signer();
        let engine = Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine");
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let occ = format!("occ-{suffix}");
        self_login_seed_key(&engine, &occ, identity_type::AGENT).await;
        let dir = engine.federation_directory();
        let now = chrono::Utc::now();

        let mk = |kind: &str, dest: &str| TransportDestination {
            occurrence_key_id: occ.clone(),
            transport_kind: kind.to_owned(),
            destination: dest.to_owned(),
            asserted_at: now,
            last_seen_at: Some(now),
            transport_ed25519_pubkey_base64: None,
            transport_x25519_pubkey_base64: None,
            binding_provenance: crate::federation::self_at_login::BindingProvenance::Rooted,
        };

        dir.put_transport_destination(&mk("reticulum", "d1"))
            .await
            .expect("put 1");
        // Re-assert same PK → idempotent (still one row).
        dir.put_transport_destination(&mk("reticulum", "d1"))
            .await
            .expect("put 1 again");
        dir.put_transport_destination(&mk("websocket", "wss://r"))
            .await
            .expect("put 2");
        assert_eq!(
            dir.list_transport_destinations_for(&occ)
                .await
                .unwrap()
                .len(),
            2
        );

        // Remove one → true; remove again → false (idempotent).
        assert!(dir
            .remove_transport_destination(&occ, "reticulum", "d1")
            .await
            .unwrap());
        assert!(!dir
            .remove_transport_destination(&occ, "reticulum", "d1")
            .await
            .unwrap());
        assert_eq!(
            dir.list_transport_destinations_for(&occ)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    /// Seed a `federation_keys` row on Postgres so the FK + admission
    /// checks the self-at-login flow runs against are satisfied.
    #[cfg(feature = "postgres")]
    async fn pg_seed_key(engine: &Engine, key_id: &str, identity_type: &str) {
        let pg = engine.postgres_backend().expect("postgres");
        let client = pg.pool().get().await.expect("pool get");
        client
            .execute(
                "INSERT INTO cirislens.federation_keys (\
                    key_id, pubkey_ed25519_base64, algorithm, \
                    identity_type, identity_ref, valid_from, \
                    registration_envelope, original_content_hash, \
                    scrub_signature_classical, scrub_key_id, \
                    scrub_timestamp, persist_row_hash\
                 ) VALUES ($1, 'AAAA', 'hybrid', $2, $1, \
                          '2026-01-01T00:00:00Z', '{}'::jsonb, \
                          '', '', $1, '2026-01-01T00:00:00Z', '0') \
                 ON CONFLICT (key_id) DO NOTHING",
                &[&key_id, &identity_type],
            )
            .await
            .expect("seed federation_key");
    }

    /// Postgres parity for [`self_at_login_lands_full_flow`]. Skips when
    /// `CIRIS_PERSIST_TEST_PG_URL` is unset. Self-isolating: every key id
    /// + bilateral_pair_id is uuid-suffixed so reruns against a reused PG
    /// never collide or accumulate count-breaking rows.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn self_at_login_lands_full_flow_postgres() {
        use crate::federation::types::identity_type;

        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let (signer, _steward_alias) = self_login_signer();
        // v9.3.0 (#247) — seed the steward row under the signer's DERIVED
        // key_id (the promote scrub_key_id FK target).
        let steward_derived = signer.derived_key_id();
        let engine = Engine::with_signer(signer, &dsn)
            .await
            .expect("postgres engine");

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let identity_key = format!("user-{suffix}");
        let app_key = format!("app-{suffix}");
        let agent_key = format!("agent-{suffix}");
        let set = identity_type::join_set([identity_type::USER, identity_type::WISE_AUTHORITY]);
        pg_seed_key(&engine, &steward_derived, identity_type::STEWARD).await;
        pg_seed_key(&engine, &identity_key, &set).await;
        pg_seed_key(&engine, &app_key, identity_type::USER).await;
        pg_seed_key(&engine, &agent_key, identity_type::AGENT).await;

        let mk_keys = || {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            let (_xp, x_pub, _mp, ml_pub) =
                crate::federation::identity_aggregate::mint_content_kem_keypair()
                    .expect("mint content-kem");
            crate::federation::EncryptionPubkeys {
                x25519_base64: B64.encode(x_pub),
                ml_kem_768_base64: B64.encode(ml_pub),
            }
        };

        let pair_id = uuid::Uuid::new_v4().to_string();
        let outcome = engine
            .self_at_login(SelfAtLoginInput {
                identity_key_id: identity_key.clone(),
                app: SelfAtLoginOccurrence {
                    occurrence_key_id: app_key.clone(),
                    device_class: crate::federation::device_class::LAPTOP.to_owned(),
                    hardware_attestation: None,
                    encryption_pubkeys: Some(mk_keys()),
                    transport_destinations: vec![(
                        "reticulum".to_owned(),
                        format!("dest-{suffix}"),
                    )],
                },
                agent: SelfAtLoginOccurrence {
                    occurrence_key_id: agent_key.clone(),
                    device_class: crate::federation::device_class::AGENT.to_owned(),
                    hardware_attestation: None,
                    encryption_pubkeys: Some(mk_keys()),
                    transport_destinations: vec![],
                },
                bilateral_pair_id: pair_id,
                delegation_scope: None,
            })
            .await
            .expect("self_at_login pg");

        assert!(outcome.delegation_promoted);
        assert!(outcome.self_dek_excluded.is_empty());
        assert_eq!(outcome.self_dek_granted, 2);
        assert_eq!(outcome.transport_destinations_registered, 1);

        let dir = engine.federation_directory();
        assert_eq!(
            dir.list_identity_occurrences_for(&identity_key)
                .await
                .expect("occurrences")
                .len(),
            2
        );
        let delegation = dir
            .get_attestation(&outcome.delegation_id)
            .await
            .expect("get")
            .expect("row");
        assert_eq!(
            delegation.tier,
            crate::federation::types::attestation_tier::FEDERATION
        );
        let app_dests = dir
            .list_transport_destinations_for(&app_key)
            .await
            .expect("dests");
        assert_eq!(app_dests.len(), 1);
        assert_eq!(app_dests[0].transport_kind, "reticulum");
    }

    /// identity_type set helpers (§7.0.1): join is sorted/deduped, and
    /// set_contains sees members in both the single-value and
    /// comma-joined cases.
    #[test]
    fn identity_type_set_helpers() {
        use crate::federation::types::identity_type;
        // Sorted + deduped regardless of insertion order.
        let joined = identity_type::join_set(["wise_authority", "user", "user"]);
        assert_eq!(joined, "user,wise_authority");
        assert!(identity_type::set_contains(&joined, identity_type::USER));
        assert!(identity_type::set_contains(
            &joined,
            identity_type::WISE_AUTHORITY
        ));
        // Single-value column still parses as a one-element set.
        assert!(identity_type::set_contains("agent", identity_type::AGENT));
        assert!(!identity_type::set_contains("agent", identity_type::USER));
        assert_eq!(
            identity_type::parse_set("user,wise_authority"),
            vec!["user", "wise_authority"]
        );
    }
}
