//! `SecretsService` trait — the 18-method federation surface
//! (v0.6.1+, CIRISPersist#19; FSD `POST_INGEST_FILTER_PIPELINE.md` §7.1).
//!
//! Method-by-method this is everything `CIRISAgent`'s
//! `SecretsServiceProtocol` provides; persist becomes the
//! federation-stable substrate for the entire surface. Agents
//! delegate via `Engine.secrets()` (v0.6.1-α6).
//!
//! # Async trait pattern
//!
//! Persist uses `impl Future<...> + Send` GATs (Rust 1.75+) rather
//! than `#[async_trait]` (same convention as `crate::read::ReadEngine`
//! and `crate::derived::DerivedSchema`). One concrete impl ships in
//! v0.6.1-α5 (`PostgresSecretsBackend`); other backends (memory /
//! sqlite) return `NotImplemented` per the existing trait-method
//! convention if/when they're added.

use std::future::Future;

use super::types::{
    AccessLogEntry, DecapsulationContext, FilterConfig, FilterUpdateRequest, FilterUpdateResult,
    MasterKeyRef, RotationResult, SecretRecallResult, SecretReference, SecretsListFilter,
    SecretsServiceStats,
};
use super::SecretsError;

/// Federated SecretsService — 18 methods covering CRUD, detection,
/// decapsulation, direct crypto, filter config, audit, and key
/// rotation. Implements the full `CIRISAgent SecretsServiceProtocol`
/// surface so agents can delegate every secrets operation to persist.
///
/// # Audit invariant
///
/// **Every method MUST write a row to `cirislens_secrets.access_log`**
/// before returning (including on failure). The audit trail is the
/// load-bearing accountability surface; missing rows are a
/// correctness bug, not a perf optimization. The PG impl handles
/// this in a single transaction per call.
///
/// # AV-15 (HTTP/PyO3 sanitization)
///
/// `SecretsError::kind()` is the stable wire-side token. Verbose
/// `Display` messages stay in tracing only.
pub trait SecretsService: Send + Sync {
    // ── CRUD (matches CIRISAgent SecretsServiceProtocol §3.1 #3, #4, #7, #9, #10) ──

    /// Store a manually-keyed secret. Caller provides `key`; persist
    /// generates a per-secret salt + nonce, derives the per-secret
    /// encryption key from the active master key via PBKDF2-HMAC-
    /// SHA-256, encrypts under AES-256-GCM, and persists.
    ///
    /// `accessor` is recorded in `access_log.accessor` for audit.
    fn store_secret(
        &self,
        key: String,
        value: String,
        accessor: String,
    ) -> impl Future<Output = Result<(), SecretsError>> + Send;

    /// Retrieve a secret by manual key. Decrypts and returns
    /// plaintext. Audited.
    fn retrieve_secret(
        &self,
        key: &str,
        accessor: String,
    ) -> impl Future<Output = Result<Option<String>, SecretsError>> + Send;

    /// Recall a detected secret by UUID — the path
    /// `EncryptAndStore` creates. `decrypt=false` returns
    /// metadata only (no `access_log.operation = 'recall'`
    /// audit-decrypt entry).
    fn recall_secret(
        &self,
        uuid: &str,
        purpose: String,
        accessor: String,
        decrypt: bool,
    ) -> impl Future<Output = Result<Option<SecretRecallResult>, SecretsError>> + Send;

    /// Metadata-only listing. Filtered by [`SecretsListFilter`];
    /// `limit` bounds the page size (typical 100..1000). NO
    /// ciphertext leaves persist via this method.
    fn list_stored_secrets(
        &self,
        limit: usize,
        filter: SecretsListFilter,
    ) -> impl Future<Output = Result<Vec<SecretReference>, SecretsError>> + Send;

    /// Audited delete. Returns `true` if the secret existed,
    /// `false` if it was already absent.
    fn forget_secret(
        &self,
        uuid: &str,
        accessor: String,
    ) -> impl Future<Output = Result<bool, SecretsError>> + Send;

    // ── Detection + decapsulation (matches §3.1 #5, #6) ──

    /// Run the configured filter catalog against `text`, encrypt-
    /// and-store every detected secret, return the filtered text
    /// (with `{SECRET:uuid:description}` placeholders) + the list
    /// of created [`SecretReference`]s.
    ///
    /// This is the edge-side `EncryptAndStore` stage's primary
    /// entry point (FSD §5.2 default pipeline composition).
    fn process_incoming_text(
        &self,
        text: &str,
        source_message_id: &str,
        accessor: String,
    ) -> impl Future<Output = Result<(String, Vec<SecretReference>), SecretsError>> + Send;

    /// Walk `action_params`, replacing every `{SECRET:uuid:...}`
    /// placeholder with the cleartext IFF the secret's
    /// `auto_decapsulate_for_actions` whitelist includes
    /// `ctx.action_type`. Audits each decapsulation.
    fn decapsulate_secrets_in_parameters(
        &self,
        action_type: &str,
        action_params: serde_json::Value,
        ctx: DecapsulationContext,
    ) -> impl Future<Output = Result<serde_json::Value, SecretsError>> + Send;

    // ── Direct crypto (matches §3.1 #1, #2) ──

    /// Direct AES-256-GCM encrypt under the active master key (no
    /// row stored). Returns `base64(salt || nonce || ciphertext)`
    /// for caller-managed transport.
    ///
    /// Caller bears decryption responsibility — persist's recall
    /// path doesn't service the returned blob.
    fn encrypt(&self, plaintext: &str)
        -> impl Future<Output = Result<String, SecretsError>> + Send;

    /// Direct decrypt of caller-managed ciphertext (the inverse of
    /// [`SecretsService::encrypt`]).
    fn decrypt(
        &self,
        ciphertext: &str,
    ) -> impl Future<Output = Result<String, SecretsError>> + Send;

    // ── Filter config CRUD (matches §3.1 #8, #11) ──

    /// Read the current filter pattern catalog.
    fn get_filter_config(&self) -> impl Future<Output = Result<FilterConfig, SecretsError>> + Send;

    /// Write a new filter pattern catalog. Bumps the row's
    /// monotonic `version`.
    fn update_filter_config(
        &self,
        updates: FilterUpdateRequest,
        accessor: String,
    ) -> impl Future<Output = Result<FilterUpdateResult, SecretsError>> + Send;

    // ── Audit + observability (matches §3.1 #12, #13 + #15) ──

    /// Service-wide stats — total secrets, active filters,
    /// encryption health, rotation history.
    fn get_service_stats(
        &self,
    ) -> impl Future<Output = Result<SecretsServiceStats, SecretsError>> + Send;

    /// Liveness probe. Confirms the crypto facade + active master
    /// key + db connection are all reachable.
    fn is_healthy(&self) -> impl Future<Output = Result<bool, SecretsError>> + Send;

    /// Query the access log. `secret_uuid=Some(_)` narrows to one
    /// secret's history; `None` returns the global tail.
    fn get_access_logs(
        &self,
        secret_uuid: Option<&str>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<AccessLogEntry>, SecretsError>> + Send;

    // ── Key rotation + hardware key (matches §3.1 #14 + #16, #17, #18) ──

    /// Re-encrypt every stored secret under a new master key.
    /// Atomic (single transaction in postgres; backup-and-replace
    /// in sqlite). Audits as one `operation = 'reencrypt'` row per
    /// secret + one `operation = 'rotate'` row for the rotation
    /// event itself.
    fn reencrypt_all(
        &self,
        new_master_key_ref: MasterKeyRef,
        accessor: String,
    ) -> impl Future<Output = Result<RotationResult, SecretsError>> + Send;

    /// Rotate to a freshly generated master key (or use the
    /// supplied `new_master`). Returns the new key reference.
    /// Calls [`SecretsService::reencrypt_all`] internally as part
    /// of the rotation.
    fn rotate_master_key(
        &self,
        new_master: Option<Vec<u8>>,
        accessor: String,
    ) -> impl Future<Output = Result<MasterKeyRef, SecretsError>> + Send;

    /// Health check on the encryption path: round-trip
    /// `encrypt → decrypt` with a known plaintext under the active
    /// master key. Returns `true` on success.
    fn test_encryption(&self) -> impl Future<Output = Result<bool, SecretsError>> + Send;

    /// Migrate the master key from software file to CIRISVerify
    /// TPM/Keystore. Re-encrypts every secret as part of the
    /// migration.
    ///
    /// v0.6.1: returns [`SecretsError::HardwareKeyUnavailable`]
    /// (waiting on `ciris-keyring/symmetric-derivation` feature
    /// upstream). The method is in the trait surface so consumers
    /// can write against the contract today.
    fn migrate_to_hardware_key(
        &self,
        accessor: String,
    ) -> impl Future<Output = Result<MasterKeyRef, SecretsError>> + Send;
}
