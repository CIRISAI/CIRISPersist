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
    get_platform_signer, is_hardware_available, HardwareSigner, KeyringScope,
    MlDsa65SoftwareSigner, PqcSigner, StorageDescriptor,
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
    /// v0.2.2 — Federation steward Ed25519 signing key.
    ///
    /// Distinct from `signer` (which is the scrub-envelope identity,
    /// `signing_key_id` — typically P-256 via ciris-keyring) — the
    /// steward identity is Ed25519 (matching the federation_keys
    /// schema) and used to sign federation envelopes for keys/
    /// attestations/revocations the lens publishes to persist's
    /// federation directory.
    ///
    /// Loaded from a 32-byte raw seed file at constructor time when
    /// both `steward_key_id` and `steward_key_path` are provided.
    /// `None` when the federation steward role isn't configured for
    /// this Engine instance — the `steward_*` methods return
    /// ValueError in that case.
    ///
    /// Lens process never sees the seed bytes after construction;
    /// signing happens via `steward_sign(message)` which returns the
    /// 64-byte raw signature, matching the FFI-boundary discipline of
    /// `Engine.sign()`.
    steward_signing_key: Option<ed25519_dalek::SigningKey>,
    /// Identifier for the steward identity. Used as the `key_id` of
    /// the lens-steward `federation_keys` row and as the `scrub_key_id`
    /// for federation rows the lens publishes.
    steward_key_id: Option<String>,
    /// v0.3.1 — Steward ML-DSA-65 signer for cold-path PQC fill-in
    /// (CIRISPersist#10). Loaded from a 32-byte raw seed file at
    /// constructor time when both `steward_pqc_key_id` and
    /// `steward_pqc_key_path` are provided. Held as `Arc<dyn PqcSigner>`
    /// so the auto-fire tokio task in `put_public_key` /
    /// `put_attestation` / `put_revocation` can clone and own its own
    /// reference for the duration of the cold-path sign.
    ///
    /// Persist owns the cold-path so consumers (lens, registry,
    /// partner sites) don't reimplement it independently and drift —
    /// same lesson as `canonicalize_envelope` post-CIRISPersist#7.
    /// Per the writer contract in V004 schema header: kick off
    /// IMMEDIATELY after Ed25519 sign, not delayed/batched/scheduled,
    /// just off the synchronous request path. `tokio::spawn` post-put
    /// matches that intent — the row lands hybrid-pending, classical
    /// sig is on it, PQC catches up within seconds.
    ///
    /// `None` when no PQC steward key is configured — the auto-fire
    /// path no-ops and the row stays hybrid-pending until a writer
    /// fills it via `attach_*_pqc_signature` (the v0.2.0 escape hatch
    /// for importing rows signed elsewhere).
    steward_pqc_signer: Option<std::sync::Arc<dyn PqcSigner>>,
    /// Identifier for the PQC steward identity (e.g.,
    /// `lens-steward-pqc`). Distinct from `steward_key_id` (the
    /// Ed25519 identity) because in deployments where the keys live
    /// in different storage backends (Ed25519 in
    /// ciris-keyring's classical signer, ML-DSA-65 in
    /// `MlDsa65SoftwareSigner`'s file-backed seed) the alias spaces
    /// don't have to match. Most deployments will pin them equal.
    steward_pqc_key_id: Option<String>,
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
    /// **v0.2.2** — optional `steward_key_id` + `steward_key_path`
    /// configure a SECOND identity for federation-directory signing
    /// (`engine.steward_sign()`, `engine.steward_public_key_b64()`).
    /// This identity is Ed25519 (matching the federation_keys schema),
    /// distinct from `signing_key_id` (which is the scrub-envelope
    /// identity, typically P-256 via ciris-keyring). The lens-steward
    /// keypair is generated externally (e.g., by CIRIS bridge); the
    /// 32-byte raw Ed25519 seed is stored in `steward_key_path`. The
    /// lens process never touches the seed bytes after construction —
    /// signing happens via `steward_sign(message)`.
    ///
    /// Raises `RuntimeError` if Postgres is unreachable, migrations
    /// fail, or the keyring is inaccessible. Raises `ValueError` if
    /// only one of `steward_key_id`/`steward_key_path` is provided
    /// (must be both-or-neither), or if the steward seed file is
    /// missing/wrong-size.
    #[new]
    #[pyo3(signature = (dsn, signing_key_id, scrubber=None,
                        steward_key_id=None, steward_key_path=None,
                        steward_pqc_key_id=None, steward_pqc_key_path=None))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        dsn: &str,
        signing_key_id: &str,
        scrubber: Option<Py<PyAny>>,
        steward_key_id: Option<String>,
        steward_key_path: Option<String>,
        steward_pqc_key_id: Option<String>,
        steward_pqc_key_path: Option<String>,
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
            let s = get_platform_signer(&signer_key_id_owned)
                .map_err(|e| PyRuntimeError::new_err(format!("ciris-keyring: {e}")))?;
            // _bootstrap_lock drops at end of scope; FD closes;
            // flock releases. Other waiting workers proceed.
            Ok(s)
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

        // v0.2.2 — optional steward identity for federation-directory
        // signing. Both-or-neither: passing one without the other is
        // a config error. When configured, load the 32-byte raw
        // Ed25519 seed from `steward_key_path` (chmod 600 expected;
        // OS handles the permission check on read).
        let (steward_key_id_owned, steward_signing_key) = match (steward_key_id, steward_key_path) {
            (None, None) => (None, None),
            (Some(id), Some(path)) => {
                let seed = std::fs::read(&path).map_err(|e| {
                    PyRuntimeError::new_err(format!("steward seed read ({path}): {e}"))
                })?;
                if seed.len() != 32 {
                    return Err(PyValueError::new_err(format!(
                        "steward seed wrong length: got {} bytes from {path}, \
                             expected 32 raw Ed25519 bytes",
                        seed.len()
                    )));
                }
                let arr: [u8; 32] = seed.as_slice().try_into().expect("length-checked");
                let signing = ed25519_dalek::SigningKey::from_bytes(&arr);
                tracing::info!(
                    steward_key_id = id.as_str(),
                    steward_pubkey_b64 = %{
                        use base64::engine::general_purpose::STANDARD as B64;
                        use base64::Engine as _;
                        B64.encode(signing.verifying_key().to_bytes())
                    },
                    "ciris-persist: steward identity loaded"
                );
                (Some(id), Some(signing))
            }
            _ => {
                return Err(PyValueError::new_err(
                    "steward_key_id and steward_key_path must both be provided \
                         or both omitted",
                ));
            }
        };

        // v0.3.1 — Optional ML-DSA-65 steward signer for cold-path
        // PQC fill-in (CIRISPersist#10). Same both-or-neither
        // construction shape as the Ed25519 steward identity.
        // ciris-keyring v1.9.0's MlDsa65SoftwareSigner reads a 32-byte
        // raw seed file (parallel to Ed25519SoftwareSigner / the
        // existing steward_key_path); the seed bytes never enter the
        // Python process. HW acceleration when post-quantum HSMs land
        // is verify's responsibility (PqcSigner trait is the
        // dispatch surface).
        let (steward_pqc_key_id_owned, steward_pqc_signer): (
            Option<String>,
            Option<std::sync::Arc<dyn PqcSigner>>,
        ) = match (steward_pqc_key_id, steward_pqc_key_path) {
            (None, None) => (None, None),
            (Some(id), Some(path)) => {
                let signer = MlDsa65SoftwareSigner::from_seed_file(&path, &id).map_err(|e| {
                    PyRuntimeError::new_err(format!("ML-DSA-65 steward seed load ({path}): {e}"))
                })?;
                tracing::info!(
                    steward_pqc_key_id = id.as_str(),
                    seed_path = path.as_str(),
                    "ciris-persist: PQC steward identity loaded (ML-DSA-65, software)"
                );
                let arc: std::sync::Arc<dyn PqcSigner> = std::sync::Arc::new(signer);
                (Some(id), Some(arc))
            }
            _ => {
                return Err(PyValueError::new_err(
                    "steward_pqc_key_id and steward_pqc_key_path must both be provided \
                     or both omitted",
                ));
            }
        };

        Ok(PyEngine {
            backend,
            runtime,
            scrubber,
            signer,
            signer_key_id: signing_key_id.to_owned(),
            steward_signing_key,
            steward_key_id: steward_key_id_owned,
            steward_pqc_signer,
            steward_pqc_key_id: steward_pqc_key_id_owned,
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
        let value: serde_json::Value = serde_json::from_str(envelope_json)
            .map_err(|e| PyValueError::new_err(format!("envelope JSON decode: {e}")))?;
        let bytes = <PythonJsonDumpsCanonicalizer as crate::verify::canonical::Canonicalizer>::canonicalize_value(
            &PythonJsonDumpsCanonicalizer,
            &value,
        )
        .map_err(|e| PyRuntimeError::new_err(format!("canonicalize: {e}")))?;
        Ok(PyBytes::new(py, &bytes).unbind())
    }

    /// v0.2.2 — Return the steward Ed25519 public key (base64) for
    /// publishing to consumers (registry pinning, lens-steward
    /// fingerprint, federation_keys.pubkey_ed25519_base64). Distinct
    /// from `public_key_b64()` (which returns the scrub-envelope
    /// identity's pubkey).
    ///
    /// Raises `ValueError` if the Engine wasn't constructed with
    /// `steward_key_id` + `steward_key_path` (the federation steward
    /// role isn't configured).
    fn steward_public_key_b64(&self, _py: Python<'_>) -> PyResult<String> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        let key = self.steward_signing_key.as_ref().ok_or_else(|| {
            PyValueError::new_err(
                "no steward key configured (pass steward_key_id + steward_key_path \
                 to the Engine constructor)",
            )
        })?;
        Ok(B64.encode(key.verifying_key().to_bytes()))
    }

    /// v0.2.2 — Return the configured `steward_key_id` (the lens-
    /// steward identifier — used as `key_id` in the lens-steward
    /// federation_keys row, and as `scrub_key_id` for federation
    /// rows the lens publishes).
    ///
    /// Raises `ValueError` if no steward identity is configured.
    fn steward_key_id(&self, _py: Python<'_>) -> PyResult<String> {
        self.steward_key_id.clone().ok_or_else(|| {
            PyValueError::new_err(
                "no steward key configured (pass steward_key_id + steward_key_path \
                 to the Engine constructor)",
            )
        })
    }

    /// v0.2.2 — Sign arbitrary bytes with the steward Ed25519 signing
    /// key. Returns the 64-byte raw signature.
    ///
    /// Same FFI-boundary discipline as `Engine.sign()`: bytes in,
    /// bytes out, no key material crossing the boundary. The lens
    /// process never sees the seed.
    ///
    /// **Hot-path Ed25519 only.** The cold-path ML-DSA-65 sign
    /// happens elsewhere — lens runs ML-DSA-65 sign over
    /// `(canonical || classical_sig)` via its own pipeline and
    /// fills in via `attach_key_pqc_signature()` per the writer
    /// contract (`docs/FEDERATION_DIRECTORY.md` §"Trust contract").
    ///
    /// Raises `ValueError` if no steward key is configured.
    fn steward_sign<'py>(
        &self,
        py: Python<'py>,
        message: &Bound<'py, PyBytes>,
    ) -> PyResult<Py<PyBytes>> {
        use ed25519_dalek::Signer;
        let key = self.steward_signing_key.as_ref().ok_or_else(|| {
            PyValueError::new_err(
                "no steward key configured (pass steward_key_id + steward_key_path \
                 to the Engine constructor)",
            )
        })?;
        let sig = key.sign(message.as_bytes());
        Ok(PyBytes::new(py, &sig.to_bytes()).unbind())
    }

    /// v0.3.1 — Return the steward ML-DSA-65 public key (base64) for
    /// publishing to consumers (federation_keys.pubkey_ml_dsa_65_base64,
    /// peer pinning, fingerprint registries). Distinct from
    /// `steward_public_key_b64()` (the Ed25519 steward identity).
    ///
    /// 1952-byte raw ML-DSA-65 public key per FIPS 204 final, base64
    /// standard alphabet → ~2604 chars.
    ///
    /// Raises `ValueError` if the Engine wasn't constructed with both
    /// `steward_pqc_key_id` + `steward_pqc_key_path` (the cold-path
    /// PQC role isn't configured).
    fn steward_pqc_public_key_b64(&self, py: Python<'_>) -> PyResult<String> {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        let signer = self.steward_pqc_signer.clone().ok_or_else(|| {
            PyValueError::new_err(
                "no PQC steward key configured (pass steward_pqc_key_id + \
                 steward_pqc_key_path to the Engine constructor)",
            )
        })?;
        let runtime = self.runtime.clone();
        let bytes = py.detach(|| {
            runtime.block_on(async move {
                signer
                    .public_key()
                    .await
                    .map_err(|e| PyRuntimeError::new_err(format!("PQC public_key: {e}")))
            })
        })?;
        Ok(B64.encode(&bytes))
    }

    /// v0.3.1 — Return the configured `steward_pqc_key_id`. Distinct
    /// from `steward_key_id` (the Ed25519 identity); deployments will
    /// typically pin them equal but the alias spaces don't have to
    /// match.
    fn steward_pqc_key_id(&self, _py: Python<'_>) -> PyResult<String> {
        self.steward_pqc_key_id.clone().ok_or_else(|| {
            PyValueError::new_err(
                "no PQC steward key configured (pass steward_pqc_key_id + \
                 steward_pqc_key_path to the Engine constructor)",
            )
        })
    }

    /// v0.3.1 — Sign arbitrary bytes with the steward ML-DSA-65
    /// signing key. Returns the 3309-byte raw signature (FIPS 204
    /// final).
    ///
    /// Same FFI-boundary discipline as `steward_sign()`: bytes in,
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
    /// Raises `ValueError` if no PQC steward key is configured.
    fn steward_pqc_sign<'py>(
        &self,
        py: Python<'py>,
        message: &Bound<'py, PyBytes>,
    ) -> PyResult<Py<PyBytes>> {
        let signer = self.steward_pqc_signer.clone().ok_or_else(|| {
            PyValueError::new_err(
                "no PQC steward key configured (pass steward_pqc_key_id + \
                 steward_pqc_key_path to the Engine constructor)",
            )
        })?;
        let runtime = self.runtime.clone();
        let msg = message.as_bytes().to_vec();
        let sig_bytes = py.detach(|| {
            runtime.block_on(async move {
                signer
                    .sign(&msg)
                    .await
                    .map_err(|e| PyRuntimeError::new_err(format!("PQC sign: {e}")))
            })
        })?;
        Ok(PyBytes::new(py, &sig_bytes).unbind())
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
        use crate::schema::{BatchEnvelope, BatchEvent};
        use crate::verify::ed25519::canonical_payload_sha256s;
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;

        let bytes = body.as_bytes();
        let env =
            BatchEnvelope::from_json(bytes).map_err(|e| PyValueError::new_err(format!("{e}")))?;

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
        let backend = self.backend.clone();
        let runtime = self.runtime.clone();
        let record: crate::federation::SignedKeyRecord =
            serde_json::from_str(signed_key_record_json)
                .map_err(|e| PyValueError::new_err(format!("SignedKeyRecord JSON decode: {e}")))?;

        // v0.3.1 — cold-path PQC fill-in (CIRISPersist#10). Capture
        // the inputs the auto-fire task needs BEFORE backend consumes
        // the record. Cold-path skips when no PQC steward configured;
        // row stays hybrid-pending and consumers can fill via the
        // attach_*_pqc_signature escape hatch on their own schedule.
        let cold_path_inputs = self.steward_pqc_signer.clone().map(|signer| {
            (
                signer,
                record.record.key_id.clone(),
                record.record.registration_envelope.clone(),
                record.record.scrub_signature_classical.clone(),
            )
        });

        py.detach(|| {
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
                if let Some((signer, key_id, envelope, classical_sig_b64)) = cold_path_inputs {
                    let backend = backend.clone();
                    tokio::spawn(async move {
                        match cold_path_pqc_sign(&*signer, &envelope, &classical_sig_b64).await {
                            Ok((pubkey_b64, pqc_sig_b64)) => {
                                if let Err(e) = backend
                                    .attach_key_pqc_signature(&key_id, &pubkey_b64, &pqc_sig_b64)
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
        })
    }

    /// Federation directory: lookup a public key by `key_id`.
    /// Returns the JSON-encoded `KeyRecord` string, or `None`.
    fn lookup_public_key(&self, py: Python<'_>, key_id: &str) -> PyResult<Option<String>> {
        let backend = self.backend.clone();
        let runtime = self.runtime.clone();
        let key_id = key_id.to_owned();
        py.detach(|| {
            runtime.block_on(async move {
                let opt =
                    <PostgresBackend as crate::federation::FederationDirectory>::lookup_public_key(
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
        })
    }

    /// Federation directory: lookup all public keys for an identity_ref.
    /// Returns a JSON array string of `KeyRecord` objects.
    fn lookup_keys_for_identity(&self, py: Python<'_>, identity_ref: &str) -> PyResult<String> {
        let backend = self.backend.clone();
        let runtime = self.runtime.clone();
        let identity_ref = identity_ref.to_owned();
        py.detach(|| {
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
        })
    }

    /// Federation directory: write an attestation.
    fn put_attestation(&self, py: Python<'_>, signed_attestation_json: &str) -> PyResult<()> {
        let backend = self.backend.clone();
        let runtime = self.runtime.clone();
        let att: crate::federation::SignedAttestation =
            serde_json::from_str(signed_attestation_json).map_err(|e| {
                PyValueError::new_err(format!("SignedAttestation JSON decode: {e}"))
            })?;

        // v0.3.1 — cold-path PQC fill-in (CIRISPersist#10).
        let cold_path_inputs = self.steward_pqc_signer.clone().map(|signer| {
            (
                signer,
                att.attestation.attestation_id.clone(),
                att.attestation.attestation_envelope.clone(),
                att.attestation.scrub_signature_classical.clone(),
            )
        });

        py.detach(|| {
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
                        match cold_path_pqc_sign(&*signer, &envelope, &classical_sig_b64).await {
                            Ok((_pubkey_b64, pqc_sig_b64)) => {
                                // Attestations don't carry their own pubkey
                                // (they reference scrub_key_id's federation_keys
                                // pubkey for verification); only the PQC
                                // signature attaches.
                                if let Err(e) = backend
                                    .attach_attestation_pqc_signature(&attestation_id, &pqc_sig_b64)
                                    .await
                                {
                                    tracing::warn!(
                                        attestation_id = attestation_id.as_str(),
                                        error = %e,
                                        "cold-path PQC attach_attestation_pqc_signature failed; \
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
        })
    }

    /// Federation directory: list attestations targeting `attested_key_id`.
    fn list_attestations_for(&self, py: Python<'_>, attested_key_id: &str) -> PyResult<String> {
        let backend = self.backend.clone();
        let runtime = self.runtime.clone();
        let attested_key_id = attested_key_id.to_owned();
        py.detach(|| {
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
        })
    }

    /// Federation directory: list attestations issued by `attesting_key_id`.
    fn list_attestations_by(&self, py: Python<'_>, attesting_key_id: &str) -> PyResult<String> {
        let backend = self.backend.clone();
        let runtime = self.runtime.clone();
        let attesting_key_id = attesting_key_id.to_owned();
        py.detach(|| {
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
        })
    }

    /// Federation directory: write a revocation.
    fn put_revocation(&self, py: Python<'_>, signed_revocation_json: &str) -> PyResult<()> {
        let backend = self.backend.clone();
        let runtime = self.runtime.clone();
        let rev: crate::federation::SignedRevocation = serde_json::from_str(signed_revocation_json)
            .map_err(|e| PyValueError::new_err(format!("SignedRevocation JSON decode: {e}")))?;

        // v0.3.1 — cold-path PQC fill-in (CIRISPersist#10).
        let cold_path_inputs = self.steward_pqc_signer.clone().map(|signer| {
            (
                signer,
                rev.revocation.revocation_id.clone(),
                rev.revocation.revocation_envelope.clone(),
                rev.revocation.scrub_signature_classical.clone(),
            )
        });

        py.detach(|| {
            runtime.block_on(async move {
                use crate::federation::FederationDirectory;
                backend
                    .put_revocation(rev)
                    .await
                    .map_err(federation_err_to_py)?;
                if let Some((signer, revocation_id, envelope, classical_sig_b64)) = cold_path_inputs
                {
                    let backend = backend.clone();
                    tokio::spawn(async move {
                        match cold_path_pqc_sign(&*signer, &envelope, &classical_sig_b64).await {
                            Ok((_pubkey_b64, pqc_sig_b64)) => {
                                if let Err(e) = backend
                                    .attach_revocation_pqc_signature(&revocation_id, &pqc_sig_b64)
                                    .await
                                {
                                    tracing::warn!(
                                        revocation_id = revocation_id.as_str(),
                                        error = %e,
                                        "cold-path PQC attach_revocation_pqc_signature failed; \
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
        })
    }

    /// Federation directory: list revocations targeting `revoked_key_id`.
    fn revocations_for(&self, py: Python<'_>, revoked_key_id: &str) -> PyResult<String> {
        let backend = self.backend.clone();
        let runtime = self.runtime.clone();
        let revoked_key_id = revoked_key_id.to_owned();
        py.detach(|| {
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
        let backend = self.backend.clone();
        let runtime = self.runtime.clone();
        let key_id = key_id.to_owned();
        let mldsa_pk = pubkey_ml_dsa_65_base64.to_owned();
        let pqc_sig = scrub_signature_pqc.to_owned();
        py.detach(|| {
            runtime.block_on(async move {
                use crate::federation::FederationDirectory;
                backend
                    .attach_key_pqc_signature(&key_id, &mldsa_pk, &pqc_sig)
                    .await
                    .map_err(federation_err_to_py)
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
        let backend = self.backend.clone();
        let runtime = self.runtime.clone();
        let attestation_id = attestation_id.to_owned();
        let pqc_sig = scrub_signature_pqc.to_owned();
        py.detach(|| {
            runtime.block_on(async move {
                use crate::federation::FederationDirectory;
                backend
                    .attach_attestation_pqc_signature(&attestation_id, &pqc_sig)
                    .await
                    .map_err(federation_err_to_py)
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
        let backend = self.backend.clone();
        let runtime = self.runtime.clone();
        let revocation_id = revocation_id.to_owned();
        let pqc_sig = scrub_signature_pqc.to_owned();
        py.detach(|| {
            runtime.block_on(async move {
                use crate::federation::FederationDirectory;
                backend
                    .attach_revocation_pqc_signature(&revocation_id, &pqc_sig)
                    .await
                    .map_err(federation_err_to_py)
            })
        })
    }
}

/// Bridge `federation::Error` → `PyErr` at the FFI boundary.
/// Mission constraint (THREAT_MODEL.md AV-15): structured detail
/// goes to tracing; the Python exception carries the stable kind
/// token. Lens HTTP layer maps token → status code.
fn federation_err_to_py(e: crate::federation::Error) -> PyErr {
    let kind = e.kind();
    tracing::warn!(error = %e, kind = kind, "federation error");
    match e {
        // Caller-fault → ValueError (4xx).
        crate::federation::Error::InvalidArgument(_)
        | crate::federation::Error::SignatureInvalid(_) => PyValueError::new_err(kind),
        // Conflict → ValueError too; lens-side maps to 409.
        crate::federation::Error::Conflict(_) => PyValueError::new_err(kind),
        // Rate-limit → RuntimeError; lens maps to 429.
        crate::federation::Error::RateLimited { .. } => PyRuntimeError::new_err(kind),
        // Server-fault → RuntimeError (5xx).
        crate::federation::Error::Backend(_) => PyRuntimeError::new_err(kind),
    }
}

/// v0.3.1 — Cold-path PQC sign helper for the auto-fire flow after
/// federation writes (CIRISPersist#10). Computes the bound-signature
/// input (canonical_envelope_bytes || classical_sig_bytes), invokes
/// the steward's ML-DSA-65 signer, and returns base64-encoded
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
fn acquire_bootstrap_lock() -> std::io::Result<std::fs::File> {
    use fs4::fs_std::FileExt;
    let path = bootstrap_lock_path();
    if let Some(parent) = path.parent() {
        // Best-effort create_dir_all; if the parent already exists
        // (the common case once CIRIS_DATA_DIR is mounted) this is
        // a no-op. Failures here propagate to the caller.
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    file.lock_exclusive()?;
    tracing::debug!(
        lock_path = %path.display(),
        "ciris-persist: bootstrap flock acquired"
    );
    Ok(file)
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
        // Path exists; lock is held.
        assert!(dir.path().join(".persist-bootstrap.lock").exists());
        // Drop releases the lock; subsequent acquire from this
        // process succeeds. (Same-process flock semantics on Linux:
        // a process holds at most one flock per file regardless of
        // FD count, so re-acquiring is a no-op; on macOS it's the
        // same. Cross-process contention requires an integration
        // test which we don't do here.)
        drop(f1);
        let f2 = acquire_bootstrap_lock().expect("second acquire");
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
