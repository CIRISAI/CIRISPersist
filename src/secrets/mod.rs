//! Federated SecretsService — encrypted secret store with audit
//! trail (v0.6.1+, CIRISPersist#19).
//!
//! Persist becomes the federation-stable host for the encrypted
//! secrets store that CIRISAgent's `SecretsServiceProtocol` absorbs.
//! "Secrets are on us."
//!
//! # Mission alignment (FSD `POST_INGEST_FILTER_PIPELINE.md` §7)
//!
//! The pipeline's encrypt-and-store stage (v0.6.2) writes via this
//! module's `SecretsService` trait. Agents delegate full
//! SecretsServiceProtocol CRUD to persist (`Engine.secrets()`) so
//! every secret in the federation is encrypted under one substrate-
//! managed master key, with one auditable access log, and one
//! key-rotation surface.
//!
//! # Crypto invariant (FSD §7.5a — crypto-through-ciris-crypto)
//!
//! Every crypto operation routes through [`crate::secrets::crypto`],
//! which is the **sole** import site of `ciris_crypto::*`. Persist
//! takes ZERO direct primitive deps (no `aes_gcm` / `pbkdf2` /
//! `hkdf` / `hmac` crates in our Cargo.toml). The boundary is
//! auditable in one file.
//!
//! # Scope per release
//!
//! - **v0.6.1-α1** (this commit): module skeleton + V010 migration +
//!   feature scaffolding + [`SecretsError`]. Trait + impls land in
//!   subsequent alphas.
//! - **v0.6.1-α2**: federation-stable wire types ([`SecretReference`],
//!   [`SecretRecallResult`], etc.).
//! - **v0.6.1-α3**: 18-method [`SecretsService`] trait.
//! - **v0.6.1-α4**: `crypto.rs` facade (ciris-crypto wrappers).
//! - **v0.6.1-α5**: `PostgresSecretsBackend` impl.
//! - **v0.6.1-α6**: `Engine.secrets()` + PyO3 wraps.
//! - **v0.6.1-α7**: HTTP API behind `secrets-server` feature.
//!
//! # Feature gates
//!
//! - `secrets` — base feature. Activates the trait + postgres impl
//!   plus crypto facade. Implies `postgres` + ciris-crypto's aes-gcm
//!   / kdf / hmac / random features.
//! - `secrets-server` — HTTP API endpoints. Requires `server`.
//!
//! Hardware-key migration (`migrate_to_hardware_key`) is **active**
//! as of v1.10.0 (CIRISPersist#87) — no separate feature gate. It
//! derives the secrets master key from a hardware-sealed seed via
//! [`ciris_verify_core::derive_symmetric_key`] (CIRISVerify v2.5.0+);
//! see [`hardware`]. On a host with no TPM / Keystore / Secure
//! Enclave it returns [`SecretsError::HardwareKeyUnavailable`] and
//! the caller stays on the software master key.

#[cfg(feature = "secrets")]
pub mod crypto;

#[cfg(feature = "secrets")]
pub(crate) mod hardware;

#[cfg(feature = "secrets")]
pub(crate) mod key_cache;

#[cfg(all(feature = "secrets", feature = "postgres"))]
pub mod postgres;

#[cfg(feature = "secrets")]
pub mod service;

#[cfg(all(feature = "secrets", feature = "sqlite"))]
pub mod sqlite;

#[cfg(feature = "secrets")]
pub mod types;

#[cfg(any(feature = "secrets-server", feature = "secrets-client"))]
pub mod wire;

#[cfg(feature = "secrets-client")]
pub mod client;

#[cfg(feature = "secrets")]
pub use service::SecretsService;

/// v1.10.1 (CIRISPersist#88 review, perf H2) — `reencrypt_all` row
/// batch size. The CPU-bound decrypt/derive/encrypt (PBKDF2 is
/// ~100 ms per secret) runs with no transaction open; only a chunk's
/// `UPDATE` batch holds a write transaction, so the lock is released
/// between chunks rather than held across the whole secrets table.
/// 64 keeps each locked window short while amortizing transaction
/// overhead.
#[cfg(feature = "secrets")]
pub(crate) const REENCRYPT_CHUNK_SIZE: usize = 64;

#[cfg(feature = "secrets-client")]
pub use client::FederatedSecretsClient;

#[cfg(feature = "secrets")]
pub use types::{
    AccessLogEntry, AccessOp, DecapsulationContext, DetectedSecret, EncryptedSecretRecord,
    FilterConfig, FilterUpdateRequest, FilterUpdateResult, MasterKeyRef, RotationResult,
    SecretRecallResult, SecretRecord, SecretReference, SecretsListFilter, SecretsServiceStats,
};

/// SecretsService-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens for HTTP / PyO3
/// sanitization. Verbose `Display` messages go to tracing only.
#[derive(Debug, thiserror::Error)]
pub enum SecretsError {
    /// Caller passed invalid arguments (empty key, malformed
    /// ciphertext, wrong base64 shape, etc.).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Authorization layer rejected the operation (accessor not
    /// permitted for the requested action_type on the secret).
    #[error("not authorized: {0}")]
    NotAuthorized(String),

    /// Secret wasn't found in the store. Surfaced for `recall_secret`
    /// and `forget_secret` on unknown UUIDs. Caller chooses whether
    /// to treat as a 404 or a no-op.
    #[error("not found: {0}")]
    NotFound(String),

    /// Crypto operation failed (decrypt auth-tag mismatch, KDF
    /// failure, etc.). Implies either ciphertext corruption or a
    /// master-key mismatch — investigate via the access log.
    #[error("crypto: {0}")]
    Crypto(String),

    /// Backend-level error (DB connection, JSONB serialization).
    /// String-typed because each backend has its own error tree.
    #[error("backend: {0}")]
    Backend(String),

    /// `migrate_to_hardware_key` could not reach hardware-backed
    /// secure storage — the host has no TPM / Keystore / Secure
    /// Enclave (or it is unusable), so there is no hardware root to
    /// derive the master key from. Expected on a no-hardware host;
    /// the caller keeps the software master key.
    #[error("hardware key path unavailable: {0}")]
    HardwareKeyUnavailable(String),

    /// Master-key rotation conflict (concurrent rotation, or the
    /// supplied new key is the same as the active key).
    #[error("rotation conflict: {0}")]
    RotationConflict(String),

    /// Internal serialization / type-conversion bug. Indicates a
    /// persist bug; operators should file an issue.
    #[error("internal: {0}")]
    Internal(String),
}

impl SecretsError {
    /// Stable string-token for telemetry / structured logging.
    /// Mirrors the kind() convention from
    /// `crate::pipeline::Error` / `crate::read::Error`.
    pub fn kind(&self) -> &'static str {
        match self {
            SecretsError::InvalidArgument(_) => "secrets_invalid_argument",
            SecretsError::NotAuthorized(_) => "secrets_not_authorized",
            SecretsError::NotFound(_) => "secrets_not_found",
            SecretsError::Crypto(_) => "secrets_crypto",
            SecretsError::Backend(_) => "secrets_backend",
            SecretsError::HardwareKeyUnavailable(_) => "secrets_hw_unavailable",
            SecretsError::RotationConflict(_) => "secrets_rotation_conflict",
            SecretsError::Internal(_) => "secrets_internal",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kind_tokens_stable() {
        assert_eq!(
            SecretsError::InvalidArgument("x".into()).kind(),
            "secrets_invalid_argument"
        );
        assert_eq!(
            SecretsError::NotAuthorized("x".into()).kind(),
            "secrets_not_authorized"
        );
        assert_eq!(
            SecretsError::NotFound("x".into()).kind(),
            "secrets_not_found"
        );
        assert_eq!(SecretsError::Crypto("x".into()).kind(), "secrets_crypto");
        assert_eq!(SecretsError::Backend("x".into()).kind(), "secrets_backend");
        assert_eq!(
            SecretsError::HardwareKeyUnavailable("x".into()).kind(),
            "secrets_hw_unavailable"
        );
        assert_eq!(
            SecretsError::RotationConflict("x".into()).kind(),
            "secrets_rotation_conflict"
        );
        assert_eq!(
            SecretsError::Internal("x".into()).kind(),
            "secrets_internal"
        );
    }
}
