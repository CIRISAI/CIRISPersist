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
    AccessLogEntry, DecapsulationContext, DetectedSecret, FilterConfig, FilterUpdateRequest,
    FilterUpdateResult, MasterKeyRef, RotationResult, SecretRecallResult, SecretReference,
    SecretsListFilter, SecretsServiceStats,
};
use super::SecretsError;
use crate::pipeline::classify::Sensitivity;
use crate::ClaimResult;

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
    ) -> impl Future<Output = Result<(String, Vec<SecretReference>), SecretsError>> + Send {
        // v1.5.7 (CIRISPersist#57) — Default impl composes the
        // existing primitives `get_filter_config` + `try_claim_secret`
        // so both PG and SQLite backends inherit it automatically.
        //
        // Pattern catalog shape (filter_config.config_value):
        //
        //   { "patterns": [
        //       { "pattern_id":              "api_key",
        //         "regex":                   "...",
        //         "description":             "...",
        //         "sensitivity":             "high",
        //         "auto_decapsulate_for_actions": ["..."] },
        //       ...
        //     ],
        //     "version":                     1
        //   }
        //
        // Each match → try_claim_secret (race-safe content-hmac dedup
        // per v1.0.0). Filtered text uses the
        // `{SECRET:<uuid>:<description>}` placeholder format the
        // decapsulation path matches on. source_message_id is
        // currently observability-only (not threaded into the
        // SecretRecord row); v1.6.x can extend the SecretReference
        // shape to carry it if needed.
        async move {
            #[derive(serde::Deserialize)]
            struct CatalogPattern {
                #[serde(default)]
                #[allow(dead_code)]
                pattern_id: Option<String>,
                regex: String,
                description: String,
                #[serde(default = "default_sensitivity")]
                sensitivity: Sensitivity,
                #[serde(default)]
                auto_decapsulate_for_actions: Vec<String>,
            }
            fn default_sensitivity() -> Sensitivity {
                Sensitivity::High
            }

            tracing::debug!(source_message_id, "process_incoming_text begin");

            let filter = self.get_filter_config().await?;
            let patterns_value = filter
                .config_value
                .get("patterns")
                .cloned()
                .unwrap_or(serde_json::Value::Array(Vec::new()));
            let patterns: Vec<CatalogPattern> =
                serde_json::from_value(patterns_value).map_err(|e| {
                    SecretsError::Internal(format!(
                        "filter config patterns decode (config_id={}): {e}",
                        filter.config_id
                    ))
                })?;

            let mut filtered = text.to_owned();
            let mut refs: Vec<SecretReference> = Vec::new();
            for pat in patterns {
                let re = regex::Regex::new(&pat.regex).map_err(|e| {
                    SecretsError::Internal(format!(
                        "filter pattern regex compile (description={:?}): {e}",
                        pat.description
                    ))
                })?;
                // Collect matched substrings up-front so we don't mutate
                // `filtered` while iterating. Pattern emits the FIRST
                // match per unique plaintext; try_claim_secret's hmac
                // dedup handles repeats inside the same text.
                let mut matched_plaintexts: Vec<String> = Vec::new();
                for m in re.find_iter(&filtered) {
                    let s = m.as_str().to_owned();
                    if !matched_plaintexts.iter().any(|x| x == &s) {
                        matched_plaintexts.push(s);
                    }
                }
                for plaintext in matched_plaintexts {
                    let claim = self
                        .try_claim_secret(
                            &plaintext,
                            &pat.description,
                            pat.sensitivity,
                            pat.auto_decapsulate_for_actions.clone(),
                            accessor.clone(),
                        )
                        .await?;
                    let secret_ref = match claim {
                        ClaimResult::Stored(r) | ClaimResult::AlreadyClaimed(r) => r,
                    };
                    let placeholder =
                        format!("{{SECRET:{}:{}}}", secret_ref.uuid, secret_ref.description);
                    filtered = filtered.replace(&plaintext, &placeholder);
                    refs.push(secret_ref);
                }
            }
            tracing::debug!(
                source_message_id,
                detected_count = refs.len(),
                "process_incoming_text done"
            );
            Ok((filtered, refs))
        }
    }

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

    // ── Atomic-claim (v1.0.0, CIRISAgent#756 concern #2) ──────────────

    /// Atomic-claim variant of [`SecretsService::store_secret`]
    /// (v1.0.0; CIRISAgent#756 concern #2). Race-safe write
    /// semantics for N concurrent workers processing the same
    /// envelope.
    ///
    /// Computes
    /// `content_hmac = HMAC-SHA256(active_master_key, plaintext)`,
    /// attempts an INSERT with the hmac as the unique key. On
    /// conflict (another caller already stored this plaintext under
    /// the same master key), returns
    /// [`ClaimResult::AlreadyClaimed`] with the existing row's
    /// [`SecretReference`]. On clean insert, returns
    /// [`ClaimResult::Stored`].
    ///
    /// Implementations MUST be atomic — two concurrent callers
    /// running the same plaintext through the INSERT race end up
    /// with one row, not two. PG backend uses
    /// `INSERT … ON CONFLICT (content_hmac) DO NOTHING RETURNING …`;
    /// SQLite uses `INSERT OR IGNORE …` plus a follow-up SELECT on
    /// conflict.
    ///
    /// # Master-key rotation
    ///
    /// The HMAC is computed under whichever master key is active at
    /// the time of the call. After rotation, the same plaintext
    /// produces a different HMAC and would re-claim. This is
    /// intentional: rotation is the boundary where dedup state
    /// resets.
    ///
    /// # Default impl
    ///
    /// Returns [`SecretsError::Internal`] — backends without the
    /// V017 content_hmac column (legacy in-memory shims) opt into
    /// the surface explicitly.
    fn try_claim_secret(
        &self,
        plaintext: &str,
        description: &str,
        sensitivity: Sensitivity,
        auto_decapsulate_for_actions: Vec<String>,
        accessor: String,
    ) -> impl Future<Output = Result<ClaimResult<SecretReference>, SecretsError>> + Send {
        let _ = (
            plaintext,
            description,
            sensitivity,
            auto_decapsulate_for_actions,
            accessor,
        );
        async {
            Err(SecretsError::Internal(
                "try_claim_secret not implemented for this backend".into(),
            ))
        }
    }

    // ── Caller-supplied detected-secret store (v1.5.24, CIRISPersist#66) ──

    /// Store an agent-detected secret with a **caller-supplied
    /// UUID** + full metadata bundle.
    ///
    /// Distinct from [`Self::try_claim_secret`] (persist generates
    /// the UUID, accepts a subset of metadata) and
    /// [`Self::store_secret`] (manually-keyed, no detection
    /// metadata). The agent owns the UUID + assigns rich detection
    /// context (`context_hint`, `source_message_id`,
    /// `detected_pattern`, `auto_decapsulate_for_actions`,
    /// `manual_access_only`) — persist stores it verbatim.
    ///
    /// # Race-safety + idempotency
    ///
    /// Returns [`ClaimResult::Stored`] on clean insert,
    /// [`ClaimResult::AlreadyClaimed`] when the row already exists
    /// (either same plaintext under a different caller UUID via the
    /// V017 `content_hmac` UNIQUE index, OR same UUID re-supplied
    /// idempotently). Both arms return the **canonical**
    /// [`SecretReference`] — caller reconciles to that UUID.
    ///
    /// # UUID collision with a *different* plaintext
    ///
    /// If the caller's `secret_uuid` is already in use for a
    /// different `content_hmac`, returns `InvalidArgument` —
    /// the agent has a UUID-allocation bug.
    ///
    /// # Default impl
    ///
    /// Returns [`SecretsError::Internal`] — backends opt in
    /// explicitly (PG + SQLite ship the impl in v1.5.24).
    fn store_detected_secret(
        &self,
        payload: DetectedSecret,
        accessor: String,
    ) -> impl Future<Output = Result<ClaimResult<SecretReference>, SecretsError>> + Send {
        let _ = (payload, accessor);
        async {
            Err(SecretsError::Internal(
                "store_detected_secret not implemented for this backend".into(),
            ))
        }
    }
}
