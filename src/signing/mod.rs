//! Local identity signing — Rust-public surface (v0.4.2,
//! CIRISPersist#17).
//!
//! CIRISLensCore (rlib path, never PyO3) needs to sign detection
//! events via persist's local identity per its mission lock-in:
//! "uses `persist.local_sign()` exclusively." Pre-v0.4.2 the only
//! signing surface was the PyO3 `Engine.local_sign` method;
//! Rust callers had no way to compose against persist's signing
//! without going through Python.
//!
//! [`LocalSigner`] lifts the construction + sign primitives to a
//! Rust-public struct. PyO3 `Engine.local_sign` /
//! `local_pqc_sign` are now thin wrappers — one implementation,
//! both surfaces (CIRISPersist#7 single-source-of-truth pattern).
//!
//! # Construction
//!
//! Same shape as PyO3 Engine's local init:
//!
//! ```ignore
//! use ciris_persist::signing::{LocalSigner, LocalSignerConfig};
//!
//! let signer = LocalSigner::from_config(&LocalSignerConfig {
//!     key_id: "lens-steward".into(),
//!     key_path: "/run/secrets/lens-steward.seed".into(),
//!     pqc_key_id: Some("lens-steward-pqc".into()),
//!     pqc_key_path: Some("/run/secrets/lens-steward.mldsa.seed".into()),
//! })?;
//!
//! // Hot-path Ed25519 sign.
//! let sig: [u8; 64] = signer.sign_ed25519(canonical_bytes)?;
//!
//! // Cold-path ML-DSA-65 sign (3309 bytes; FIPS 204 final).
//! let pqc_sig: Vec<u8> = signer.sign_ml_dsa_65(canonical_bytes).await?;
//!
//! // Hybrid (Ed25519 + ML-DSA-65 over canonical || classical_sig)
//! // matching CIRISVerify's HybridSignature spec.
//! let hybrid = signer.sign_hybrid(canonical_bytes).await?;
//! ```
//!
//! # Both-or-neither PQC config
//!
//! `pqc_key_id` and `pqc_key_path` are paired: configuring one
//! without the other returns
//! [`LocalSignerError::PqcConfigInconsistent`]. When neither is
//! configured, the signer is Ed25519-only —
//! [`LocalSigner::sign_ml_dsa_65`] and
//! [`LocalSigner::sign_hybrid`] return
//! [`LocalSignerError::PqcNotConfigured`].
//!
//! # Seed-management discipline
//!
//! Same as PyO3 Engine: 32-byte raw seed files at the configured
//! paths. Seed bytes never enter the calling process address space
//! after [`LocalSigner::from_config`] (Ed25519 reads the seed
//! once into a `SigningKey`; ML-DSA-65 hands the path to
//! `MlDsa65SoftwareSigner::from_seed_file` which holds the keyring
//! reference, never returning the seed to the caller).

use std::path::PathBuf;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::{
    ClassicalAlgorithm, HybridSignature, PqcAlgorithm, SignatureMode, TaggedClassicalSignature,
    TaggedPqcSignature, CRYPTO_KIND_CIRIS_V1,
};
use ciris_keyring::{MlDsa65SoftwareSigner, PqcSigner};
use ed25519_dalek::{Signer as _, SigningKey};

/// Configuration for [`LocalSigner::from_config`]. Matches the
/// PyO3 Engine constructor's local-* parameter shape.
#[derive(Debug, Clone)]
pub struct LocalSignerConfig {
    /// Local identity key_id (e.g. `"lens-steward"`,
    /// `"persist-steward"`). Used as the `key_id` of the local
    /// `federation_keys` row and as the `scrub_key_id` for federation
    /// rows the deployment publishes.
    pub key_id: String,
    /// Filesystem path to the 32-byte raw Ed25519 seed for the
    /// local identity. Must be readable by the calling process
    /// and chmod 600 (OS handles the permission check on read).
    pub key_path: PathBuf,
    /// Optional ML-DSA-65 PQC local identity. Both-or-neither
    /// with `pqc_key_path`.
    pub pqc_key_id: Option<String>,
    /// Filesystem path to the 32-byte raw ML-DSA-65 seed.
    /// Both-or-neither with `pqc_key_id`.
    pub pqc_key_path: Option<PathBuf>,
}

/// Errors from [`LocalSigner`] construction + signing.
#[derive(Debug, thiserror::Error)]
pub enum LocalSignerError {
    /// `key_path` could not be read (file missing, wrong
    /// permissions, etc.).
    #[error("seed read ({path}): {source}")]
    SeedRead {
        /// The path that failed to read.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// Seed file existed but was the wrong length. Ed25519 requires
    /// exactly 32 raw bytes.
    #[error("seed wrong length: got {got} bytes from {path}, expected 32")]
    SeedLength {
        /// Path of the seed file.
        path: String,
        /// Observed length.
        got: usize,
    },

    /// Caller passed `pqc_key_id` without `pqc_key_path` or vice
    /// versa.
    #[error("pqc_key_id and pqc_key_path must both be provided or both omitted")]
    PqcConfigInconsistent,

    /// ML-DSA-65 seed file load failed (path missing, wrong
    /// length, parse error). Wraps the underlying keyring error
    /// as a string so it crosses module boundaries.
    #[error("ML-DSA-65 local seed load ({path}): {detail}")]
    PqcSeedLoad {
        /// Path of the ML-DSA-65 seed file.
        path: String,
        /// Underlying keyring error message.
        detail: String,
    },

    /// `sign_ml_dsa_65` or `sign_hybrid` called when the signer
    /// was constructed without PQC config.
    #[error("PQC local not configured (set pqc_key_id + pqc_key_path)")]
    PqcNotConfigured,

    /// Underlying ML-DSA-65 sign / public_key call failed.
    #[error("PQC sign: {0}")]
    PqcSign(String),
}

/// Local identity signer — Rust-public surface for federation
/// peers (CIRISLensCore, CIRISEdge, registry, partner sites)
/// that need to sign as the deployment's local identity.
///
/// Constructed once at deployment startup; held in an `Arc` and
/// shared across worker tasks. All sign methods take `&self`
/// (signing key isn't mutated).
pub struct LocalSigner {
    signing_key: SigningKey,
    key_id: String,
    pqc_signer: Option<Arc<dyn PqcSigner>>,
    pqc_key_id: Option<String>,
}

impl std::fmt::Debug for LocalSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't expose signing_key in Debug. Public key only.
        f.debug_struct("LocalSigner")
            .field("key_id", &self.key_id)
            .field("public_key_b64", &self.public_key_b64())
            .field("pqc_key_id", &self.pqc_key_id)
            .field("pqc_configured", &self.pqc_signer.is_some())
            .finish()
    }
}

impl LocalSigner {
    /// Load local identity from filesystem seeds.
    ///
    /// Mirrors PyO3 `Engine::__init__`'s local-* wiring exactly:
    /// reads the 32-byte raw Ed25519 seed; if `pqc_key_id` +
    /// `pqc_key_path` are configured, also loads the ML-DSA-65
    /// signer via `MlDsa65SoftwareSigner::from_seed_file`.
    ///
    /// Logs a `tracing::info` line with the local pubkey on
    /// success — same observability shape PyO3 Engine uses for
    /// "ciris-persist: local identity loaded".
    pub fn from_config(cfg: &LocalSignerConfig) -> Result<Self, LocalSignerError> {
        // Pair-validate PQC config first; cheaper than reading the
        // Ed25519 seed only to find the PQC config inconsistent.
        match (&cfg.pqc_key_id, &cfg.pqc_key_path) {
            (None, None) | (Some(_), Some(_)) => {}
            _ => return Err(LocalSignerError::PqcConfigInconsistent),
        }

        let path_str = cfg.key_path.to_string_lossy().into_owned();
        let seed = std::fs::read(&cfg.key_path).map_err(|e| LocalSignerError::SeedRead {
            path: path_str.clone(),
            source: e,
        })?;
        if seed.len() != 32 {
            return Err(LocalSignerError::SeedLength {
                path: path_str,
                got: seed.len(),
            });
        }
        let arr: [u8; 32] = seed.as_slice().try_into().expect("length-checked");
        let signing_key = SigningKey::from_bytes(&arr);

        let (pqc_key_id_out, pqc_signer) = match (&cfg.pqc_key_id, &cfg.pqc_key_path) {
            (Some(id), Some(path)) => {
                let path_str = path.to_string_lossy().into_owned();
                let signer = MlDsa65SoftwareSigner::from_seed_file(path, id).map_err(|e| {
                    LocalSignerError::PqcSeedLoad {
                        path: path_str.clone(),
                        detail: format!("{e}"),
                    }
                })?;
                tracing::info!(
                    local_pqc_key_id = id.as_str(),
                    seed_path = path_str.as_str(),
                    "ciris-persist: PQC local identity loaded (ML-DSA-65, software)"
                );
                let arc: Arc<dyn PqcSigner> = Arc::new(signer);
                (Some(id.clone()), Some(arc))
            }
            _ => (None, None),
        };

        let pubkey_b64 = B64.encode(signing_key.verifying_key().to_bytes());
        tracing::info!(
            local_key_id = cfg.key_id.as_str(),
            local_pubkey_b64 = %pubkey_b64,
            "ciris-persist: local identity loaded"
        );

        Ok(Self {
            signing_key,
            key_id: cfg.key_id.clone(),
            pqc_signer,
            pqc_key_id: pqc_key_id_out,
        })
    }

    /// Construct a [`LocalSigner`] from already-loaded primitives.
    /// For test fixtures and in-process key-management scenarios
    /// where the seed isn't on disk; production code should use
    /// [`Self::from_config`].
    pub fn from_parts(
        signing_key: SigningKey,
        key_id: String,
        pqc_signer: Option<Arc<dyn PqcSigner>>,
        pqc_key_id: Option<String>,
    ) -> Self {
        Self {
            signing_key,
            key_id,
            pqc_signer,
            pqc_key_id,
        }
    }

    /// Ed25519 sign canonical bytes. Returns the 64-byte signature.
    /// Hot-path; no async. Mirrors PyO3 `engine.local_sign(message)`.
    pub fn sign_ed25519(&self, message: &[u8]) -> Result<[u8; 64], LocalSignerError> {
        Ok(self.signing_key.sign(message).to_bytes())
    }

    /// ML-DSA-65 sign canonical bytes. Returns the 3309-byte
    /// signature (FIPS 204 final). Async because the underlying
    /// `PqcSigner` trait is async — HW post-quantum signers may
    /// require async I/O when they land.
    ///
    /// Returns [`LocalSignerError::PqcNotConfigured`] if the signer
    /// was constructed without PQC config.
    pub async fn sign_ml_dsa_65(&self, message: &[u8]) -> Result<Vec<u8>, LocalSignerError> {
        let signer = self
            .pqc_signer
            .as_ref()
            .ok_or(LocalSignerError::PqcNotConfigured)?;
        signer
            .sign(message)
            .await
            .map_err(|e| LocalSignerError::PqcSign(format!("{e}")))
    }

    /// Hybrid sign canonical bytes — Ed25519 over `message`, then
    /// ML-DSA-65 over `(message || classical_sig)` (the bound
    /// signature pattern that prevents stripping attacks). Returns
    /// the canonical [`HybridSignature`] shape persist already uses
    /// for federation rows.
    ///
    /// Lens-core detection events are federation evidence and want
    /// hybrid sigs at v0.1.0 to match the posture edge envelopes
    /// ship with. This is the convenience composition of
    /// `sign_ed25519` + `sign_ml_dsa_65` + bound-payload assembly.
    ///
    /// Returns [`LocalSignerError::PqcNotConfigured`] if the signer
    /// was constructed without PQC config.
    pub async fn sign_hybrid(&self, message: &[u8]) -> Result<HybridSignature, LocalSignerError> {
        let signer = self
            .pqc_signer
            .as_ref()
            .ok_or(LocalSignerError::PqcNotConfigured)?;

        let classical_sig = self.signing_key.sign(message).to_bytes();
        let mut bound = Vec::with_capacity(message.len() + classical_sig.len());
        bound.extend_from_slice(message);
        bound.extend_from_slice(&classical_sig);

        let pqc_sig = signer
            .sign(&bound)
            .await
            .map_err(|e| LocalSignerError::PqcSign(format!("{e}")))?;
        let pqc_pk = signer
            .public_key()
            .await
            .map_err(|e| LocalSignerError::PqcSign(format!("{e}")))?;

        Ok(HybridSignature {
            crypto_kind: CRYPTO_KIND_CIRIS_V1,
            classical: TaggedClassicalSignature {
                algorithm: ClassicalAlgorithm::Ed25519,
                signature: classical_sig.to_vec(),
                public_key: self.signing_key.verifying_key().to_bytes().to_vec(),
            },
            pqc: TaggedPqcSignature {
                algorithm: PqcAlgorithm::MlDsa65,
                signature: pqc_sig,
                public_key: pqc_pk,
            },
            mode: SignatureMode::HybridRequired,
        })
    }

    /// Local identity key_id.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// PQC local identity key_id (when configured).
    pub fn pqc_key_id(&self) -> Option<&str> {
        self.pqc_key_id.as_deref()
    }

    /// Local Ed25519 public key, base64 standard alphabet (44
    /// chars). Suitable for publishing to the registry / federation
    /// directory as `pubkey_ed25519_base64`.
    pub fn public_key_b64(&self) -> String {
        B64.encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Local ML-DSA-65 public key, base64 standard alphabet
    /// (~2604 chars; 1952 raw bytes). Async because `PqcSigner`'s
    /// public_key path is async (HW signers may dispatch).
    /// Returns `None` when PQC isn't configured.
    pub async fn pqc_public_key_b64(&self) -> Result<Option<String>, LocalSignerError> {
        let Some(signer) = self.pqc_signer.as_ref() else {
            return Ok(None);
        };
        let pk = signer
            .public_key()
            .await
            .map_err(|e| LocalSignerError::PqcSign(format!("{e}")))?;
        Ok(Some(B64.encode(&pk)))
    }

    /// Internal accessor for PyO3 wrapper — exposes the underlying
    /// `Arc<dyn PqcSigner>` so `Engine.local_pqc_sign` and the
    /// cold-path PQC fill-in can call it without re-implementing
    /// the seed loading. Wired by the PyO3 Engine refactor in a
    /// follow-up release; lives `pub(crate)` for now.
    #[allow(dead_code)]
    pub(crate) fn pqc_signer_arc(&self) -> Option<Arc<dyn PqcSigner>> {
        self.pqc_signer.clone()
    }

    /// Internal accessor for PyO3 wrapper. Same forward-wiring note
    /// as `pqc_signer_arc`.
    #[allow(dead_code)]
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

/// v1.11.0 (CIRISPersist#89) — adapts an [`Arc<LocalSigner>`] to the
/// [`ciris_keyring::HardwareSigner`] trait so it can drive
/// [`IngestPipeline`](crate::ingest::IngestPipeline)'s scrub-signing
/// step.
///
/// # Why an adapter
///
/// `IngestPipeline.signer` is typed `&dyn HardwareSigner` (the
/// production deployment passes a hardware-backed signer from
/// `ciris_keyring::get_platform_signer`). The Rust-side
/// [`Engine`](crate::Engine) composes an `Arc<LocalSigner>` instead —
/// a software Ed25519 identity loaded from a seed file. `LocalSigner`
/// is NOT a `HardwareSigner`, so [`Engine::receive_and_persist`]
/// wraps it in this adapter.
///
/// # Sign-only
///
/// `IngestPipeline` calls exactly one `HardwareSigner` method during
/// ingest — `sign` (the per-component scrub-envelope signature, step
/// 3.5). This adapter implements `sign` / `public_key` /
/// `current_alias` / `algorithm` / `hardware_type` /
/// `storage_descriptor` honestly. The key-management methods
/// (`generate_key`, `key_exists`, `delete_key`, `attestation`,
/// `attestation_with_nonce`) are not on the ingest path; they return
/// [`KeyringError::NotSupported`] rather than panicking — a
/// `LocalSigner` is constructed from an already-loaded seed and has
/// no key-lifecycle surface of its own.
pub struct LocalSignerHardwareAdapter {
    inner: Arc<LocalSigner>,
}

impl LocalSignerHardwareAdapter {
    /// Wrap an `Arc<LocalSigner>` in the `HardwareSigner` adapter.
    pub fn new(inner: Arc<LocalSigner>) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl ciris_keyring::HardwareSigner for LocalSignerHardwareAdapter {
    fn algorithm(&self) -> ciris_keyring::ClassicalAlgorithm {
        // LocalSigner's hot-path signature is Ed25519.
        ciris_keyring::ClassicalAlgorithm::Ed25519
    }

    fn hardware_type(&self) -> ciris_keyring::HardwareType {
        // A LocalSigner is a software identity loaded from a seed
        // file — no HSM binding.
        ciris_keyring::HardwareType::SoftwareOnly
    }

    async fn public_key(&self) -> Result<Vec<u8>, ciris_keyring::KeyringError> {
        Ok(self.inner.signing_key().verifying_key().to_bytes().to_vec())
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, ciris_keyring::KeyringError> {
        // The only HardwareSigner method IngestPipeline exercises.
        self.inner
            .sign_ed25519(data)
            .map(|sig| sig.to_vec())
            .map_err(|e| ciris_keyring::KeyringError::SigningFailed {
                reason: format!("local-signer adapter: {e}"),
            })
    }

    async fn attestation(
        &self,
    ) -> Result<ciris_keyring::PlatformAttestation, ciris_keyring::KeyringError> {
        Err(ciris_keyring::KeyringError::NotSupported {
            operation: "attestation (not supported by the local-signer adapter)".to_string(),
        })
    }

    async fn generate_key(
        &self,
        _config: &ciris_keyring::KeyGenConfig,
    ) -> Result<(), ciris_keyring::KeyringError> {
        Err(ciris_keyring::KeyringError::NotSupported {
            operation: "generate_key (not supported by the local-signer adapter)".to_string(),
        })
    }

    async fn key_exists(&self, _alias: &str) -> Result<bool, ciris_keyring::KeyringError> {
        Err(ciris_keyring::KeyringError::NotSupported {
            operation: "key_exists (not supported by the local-signer adapter)".to_string(),
        })
    }

    async fn delete_key(&self, _alias: &str) -> Result<(), ciris_keyring::KeyringError> {
        Err(ciris_keyring::KeyringError::NotSupported {
            operation: "delete_key (not supported by the local-signer adapter)".to_string(),
        })
    }

    fn current_alias(&self) -> &str {
        self.inner.key_id()
    }

    fn storage_descriptor(&self) -> ciris_keyring::StorageDescriptor {
        // LocalSigner holds the Ed25519 SigningKey in process memory
        // after `from_config` reads the seed once; it keeps no
        // on-disk file of its own (the seed path is owned by the
        // construction config, not the live signer). InMemory is the
        // honest descriptor — same as `Ed25519SoftwareSigner`.
        ciris_keyring::StorageDescriptor::InMemory
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_seed(seed: &[u8; 32]) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(seed).expect("write seed");
        f.flush().expect("flush");
        f
    }

    #[test]
    fn from_config_loads_ed25519_seed() {
        let seed = [0x42u8; 32];
        let f = write_seed(&seed);
        let signer = LocalSigner::from_config(&LocalSignerConfig {
            key_id: "test-steward".into(),
            key_path: f.path().to_path_buf(),
            pqc_key_id: None,
            pqc_key_path: None,
        })
        .expect("load");
        assert_eq!(signer.key_id(), "test-steward");
        assert!(signer.pqc_key_id().is_none());
        // Round-trip a sign + verify.
        let sig = signer.sign_ed25519(b"hello").expect("sign");
        assert_eq!(sig.len(), 64);
        let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        use ed25519_dalek::Verifier;
        vk.verify(b"hello", &ed25519_dalek::Signature::from_bytes(&sig))
            .expect("verify");
    }

    #[test]
    fn from_config_rejects_wrong_seed_length() {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(&[0x42u8; 31]).unwrap();
        f.flush().unwrap();
        let err = LocalSigner::from_config(&LocalSignerConfig {
            key_id: "test".into(),
            key_path: f.path().to_path_buf(),
            pqc_key_id: None,
            pqc_key_path: None,
        })
        .unwrap_err();
        assert!(
            matches!(err, LocalSignerError::SeedLength { got: 31, .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn from_config_rejects_pqc_config_inconsistent() {
        let f = write_seed(&[0x42u8; 32]);
        let err = LocalSigner::from_config(&LocalSignerConfig {
            key_id: "test".into(),
            key_path: f.path().to_path_buf(),
            pqc_key_id: Some("pqc".into()),
            pqc_key_path: None,
        })
        .unwrap_err();
        assert!(matches!(err, LocalSignerError::PqcConfigInconsistent));
    }

    #[test]
    fn sign_ml_dsa_65_without_pqc_config_returns_typed_error() {
        let f = write_seed(&[0x42u8; 32]);
        let signer = LocalSigner::from_config(&LocalSignerConfig {
            key_id: "test".into(),
            key_path: f.path().to_path_buf(),
            pqc_key_id: None,
            pqc_key_path: None,
        })
        .expect("load");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(async { signer.sign_ml_dsa_65(b"hello").await })
            .unwrap_err();
        assert!(matches!(err, LocalSignerError::PqcNotConfigured));
    }

    /// v1.11.0 (CIRISPersist#89) — the `HardwareSigner` adapter's
    /// `sign` delegates to `LocalSigner`'s Ed25519 sign, and the
    /// metadata methods report the software-signer truth.
    #[tokio::test]
    async fn hardware_adapter_sign_delegates_to_local_signer() {
        use ciris_keyring::{ClassicalAlgorithm, HardwareSigner, HardwareType, StorageDescriptor};
        use ed25519_dalek::{SigningKey, Verifier as _};

        let seed = [0x33u8; 32];
        let signer = Arc::new(LocalSigner::from_parts(
            SigningKey::from_bytes(&seed),
            "adapter-key".into(),
            None,
            None,
        ));
        let adapter = LocalSignerHardwareAdapter::new(signer.clone());

        // Metadata reflects a software Ed25519 identity.
        assert_eq!(adapter.algorithm(), ClassicalAlgorithm::Ed25519);
        assert_eq!(adapter.hardware_type(), HardwareType::SoftwareOnly);
        assert_eq!(adapter.current_alias(), "adapter-key");
        assert!(matches!(
            adapter.storage_descriptor(),
            StorageDescriptor::InMemory
        ));

        // sign() produces a 64-byte Ed25519 signature that verifies
        // against the LocalSigner's public key.
        let msg = b"adapter-sign-roundtrip";
        let sig = adapter.sign(msg).await.expect("adapter sign");
        assert_eq!(sig.len(), 64);
        let pk = adapter.public_key().await.expect("adapter public_key");
        let vk = SigningKey::from_bytes(&seed).verifying_key();
        assert_eq!(pk, vk.to_bytes().to_vec());
        let sig_arr: [u8; 64] = sig.as_slice().try_into().unwrap();
        vk.verify(msg, &ed25519_dalek::Signature::from_bytes(&sig_arr))
            .expect("adapter signature verifies");
    }

    /// v1.11.0 (CIRISPersist#89) — the adapter's key-lifecycle methods
    /// are off the ingest path and return a clear `NotSupported`
    /// error rather than panicking.
    #[tokio::test]
    async fn hardware_adapter_lifecycle_methods_return_not_supported() {
        use ciris_keyring::{HardwareSigner, KeyringError};
        use ed25519_dalek::SigningKey;

        let signer = Arc::new(LocalSigner::from_parts(
            SigningKey::from_bytes(&[0x44u8; 32]),
            "adapter-key".into(),
            None,
            None,
        ));
        let adapter = LocalSignerHardwareAdapter::new(signer);

        assert!(matches!(
            adapter.key_exists("adapter-key").await,
            Err(KeyringError::NotSupported { .. })
        ));
        assert!(matches!(
            adapter.delete_key("adapter-key").await,
            Err(KeyringError::NotSupported { .. })
        ));
        assert!(matches!(
            adapter.attestation().await,
            Err(KeyringError::NotSupported { .. })
        ));
        // attestation_with_nonce defaults to attestation() — also
        // surfaces NotSupported rather than panicking.
        assert!(matches!(
            adapter.attestation_with_nonce(Some(b"nonce")).await,
            Err(KeyringError::NotSupported { .. })
        ));
    }
}
