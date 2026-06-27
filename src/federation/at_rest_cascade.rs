//! v4.14.0 (CIRISPersist#152, CEG 0.18 §10.1.4) — the self/family
//! at-rest DEK cascade: encrypt-at-rest + per-recipient `key_grant`
//! delivery for the [`CryptoTier::InvisibleEncrypted`] tier.
//!
//! # What this module owns
//!
//! - The **at-rest ciphertext envelope** format (the format/version
//!   marker that makes a ciphertext body distinguishable from a
//!   plaintext one on read) — [`AtRestEnvelope`].
//! - The **persist content master key** ([`content_master_key`]) — how
//!   persist retains the per-write DEK so it can serve
//!   `get_blob_for_viewer` in the default tier (OQ-4). Hardware-rooted
//!   HKDF over the secrets-store sealed seed under a distinct context,
//!   with a software fallback honest about being software.
//! - The **self-retention wrap** ([`wrap_dek_for_persist`] /
//!   [`unwrap_dek_for_persist`]) — AES-256-GCM of the DEK under the
//!   content master key.
//!
//! # What this module does NOT own
//!
//! - Recipient enumeration (`list_identity_occurrences_active` /
//!   `list_families_for_member_active`) — the [`FederationDirectory`].
//! - The v2 recipient wrap (`wrap_dek_for_recipient_v2`) — `ciris_crypto`.
//! - Grant-row persistence — the [`BlobStorage`] at-rest grant methods.
//! - Orchestration (enumerate → encrypt → wrap → record) — the
//!   [`Engine`](crate::Engine) cascade method, which is the only place
//!   that holds both the directory and the blob surface.
//!
//! All crypto routes through `ciris_crypto` (MISSION §1.4); persist
//! never rolls its own. This module mirrors `src/secrets/crypto.rs`
//! discipline — the secrets-store at-rest precedent.
//!
//! [`CryptoTier::InvisibleEncrypted`]: crate::federation::types::cohort_scope::CryptoTier::InvisibleEncrypted
//! [`FederationDirectory`]: crate::federation::FederationDirectory
//! [`BlobStorage`]: crate::federation::blobs::BlobStorage

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

/// AES-256 key length (bytes). Mirrors `secrets::crypto::KEY_LEN`.
pub const DEK_LEN: usize = 32;

/// AES-GCM nonce length (bytes). Mirrors `secrets::crypto::NONCE_LEN`.
pub const NONCE_LEN: usize = 12;

/// Magic prefix of an [`AtRestEnvelope`]. A plaintext blob body that
/// happens to begin with these bytes is vanishingly rare, and the
/// authoritative ciphertext discriminator is the
/// `federation_blob_key_grants` row anyway — this marker is the
/// on-disk self-description so a body is decodable without external
/// state. 8 bytes: `b"CRBLOB\x01\x00"` (CIRIS blob, format 1, reserved 0).
pub const AT_REST_ENVELOPE_MAGIC: [u8; 8] = *b"CRBLOB\x01\x00";

/// The reserved `recipient_key_id` for persist's own content-master
/// self-retention grant row. Never a real federation key_id (the `__`
/// sentinel shape is not a valid key).
pub const PERSIST_SELF_RECIPIENT: &str = "__persist_self__";

/// `wrap_algorithm` string for the persist self-retention row
/// (AES-256-GCM of the DEK under the content master key). Distinct from
/// the recipient v2 wrap string ([`WRAP_ALGORITHM_V2`]).
pub const WRAP_ALGORITHM_CONTENT_MASTER: &str = "aes256_gcm_content_master";

/// `wrap_algorithm` DB/wire string for a recipient v2 grant — the
/// CEG §10.5.3 / §5.6.8.4 pinned payload string (underscored), matching
/// `cirisnode::media_sharing::WrapAlgorithm::X25519MlKem768Aes256GcmHkdfSha256`.
/// (NOTE: distinct from `ciris_crypto::key_grant::KEY_GRANT_ALGORITHM_V2`,
/// which is the hyphenated crypto-internal label inside the wrap envelope.)
pub const WRAP_ALGORITHM_V2: &str = "x25519_mlkem768_aes256_gcm_hkdf_sha256";

/// HKDF `context` (info string) for the content-at-rest master key.
/// **Stable wire constant** — changing it re-derives a different master
/// and orphans every at-rest blob encrypted under the old one. Distinct
/// from `secrets-store-master-v1` so content keys and secret-store keys
/// are domain-separated (ENCRYPTED_AT_REST.md §4.3).
pub const CONTENT_MASTER_CONTEXT: &str = "content-at-rest-master-v1";

/// Error from the at-rest cascade crypto helpers.
#[derive(Debug, thiserror::Error)]
pub enum AtRestError {
    /// A `ciris_crypto` primitive failed (RNG, AES-GCM, HKDF).
    #[error("at-rest crypto: {0}")]
    Crypto(String),
    /// The stored body is not a well-formed [`AtRestEnvelope`] (bad
    /// magic, truncated).
    #[error("at-rest envelope decode: {0}")]
    Decode(String),
    /// A key/nonce/DEK had the wrong length.
    #[error("at-rest invalid length: {0}")]
    InvalidLength(String),
}

/// The self-describing at-rest ciphertext envelope.
///
/// Wire layout (the bytes stored as the `federation_blobs` inline body,
/// and the bytes the at-rest SHA-256 is computed over):
///
/// ```text
/// magic[8] ‖ nonce[12] ‖ aes256_gcm_ciphertext_and_tag[..]
/// ```
///
/// The AES-256-GCM ciphertext (with its appended 16-byte tag, per
/// `ciris_crypto::aes_gcm::encrypt`) covers the *plaintext* blob body
/// under the per-write DEK and `nonce`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtRestEnvelope {
    /// The GCM nonce the body was sealed under (12 bytes).
    pub nonce: [u8; NONCE_LEN],
    /// `ciphertext ‖ tag` from `ciris_crypto::aes_gcm::encrypt`.
    pub ciphertext: Vec<u8>,
}

impl AtRestEnvelope {
    /// Encode to the on-disk byte layout (`magic ‖ nonce ‖ ciphertext`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(AT_REST_ENVELOPE_MAGIC.len() + NONCE_LEN + self.ciphertext.len());
        out.extend_from_slice(&AT_REST_ENVELOPE_MAGIC);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse the on-disk byte layout. Returns [`AtRestError::Decode`] on
    /// a bad magic or a truncated header.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AtRestError> {
        let header = AT_REST_ENVELOPE_MAGIC.len() + NONCE_LEN;
        if bytes.len() < header {
            return Err(AtRestError::Decode(format!(
                "body is {} bytes, shorter than the {header}-byte envelope header",
                bytes.len()
            )));
        }
        if bytes[..AT_REST_ENVELOPE_MAGIC.len()] != AT_REST_ENVELOPE_MAGIC {
            return Err(AtRestError::Decode(
                "body does not carry the at-rest envelope magic prefix".into(),
            ));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[AT_REST_ENVELOPE_MAGIC.len()..header]);
        Ok(Self {
            nonce,
            ciphertext: bytes[header..].to_vec(),
        })
    }

    /// True iff `bytes` begins with the at-rest envelope magic — a cheap
    /// on-read discriminator for "is this body encrypted-at-rest?".
    pub fn has_magic(bytes: &[u8]) -> bool {
        bytes.len() >= AT_REST_ENVELOPE_MAGIC.len()
            && bytes[..AT_REST_ENVELOPE_MAGIC.len()] == AT_REST_ENVELOPE_MAGIC
    }
}

/// Generate a fresh 32-byte per-write DEK via `ciris_crypto::random`.
pub fn fresh_dek() -> Result<[u8; DEK_LEN], AtRestError> {
    let v = ciris_crypto::random::bytes(DEK_LEN)
        .map_err(|e| AtRestError::Crypto(format!("random: {e}")))?;
    let mut dek = [0u8; DEK_LEN];
    if v.len() != DEK_LEN {
        return Err(AtRestError::Crypto(format!(
            "random returned {} bytes",
            v.len()
        )));
    }
    dek.copy_from_slice(&v);
    Ok(dek)
}

/// AES-256-GCM-encrypt `plaintext` under `dek` with a fresh random
/// nonce, returning the self-describing [`AtRestEnvelope`].
pub fn seal(dek: &[u8; DEK_LEN], plaintext: &[u8]) -> Result<AtRestEnvelope, AtRestError> {
    let nv = ciris_crypto::random::bytes(NONCE_LEN)
        .map_err(|e| AtRestError::Crypto(format!("random nonce: {e}")))?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nv);
    let ciphertext = ciris_crypto::aes_gcm::encrypt(dek, &nonce, plaintext)
        .map_err(|e| AtRestError::Crypto(format!("aes-gcm seal: {e}")))?;
    Ok(AtRestEnvelope { nonce, ciphertext })
}

/// AES-256-GCM-decrypt an [`AtRestEnvelope`] under `dek`, returning the
/// plaintext blob body. GCM auth-tag failure is an
/// [`AtRestError::Crypto`].
pub fn open(dek: &[u8; DEK_LEN], envelope: &AtRestEnvelope) -> Result<Vec<u8>, AtRestError> {
    ciris_crypto::aes_gcm::decrypt(dek, &envelope.nonce, &envelope.ciphertext)
        .map_err(|e| AtRestError::Crypto(format!("aes-gcm open: {e}")))
}

/// Wrap `dek` under the persist content master key for self-retention.
///
/// Returns base64 of `nonce(12) ‖ aes256_gcm(content_master, dek)` — the
/// `wrapped_dek` column value for the `__persist_self__` grant row. This
/// is how persist recovers the DEK to serve `get_blob_for_viewer` in the
/// default tier without storing the DEK plaintext (OQ-4).
pub fn wrap_dek_for_persist(
    content_master: &[u8; DEK_LEN],
    dek: &[u8; DEK_LEN],
) -> Result<String, AtRestError> {
    let nv = ciris_crypto::random::bytes(NONCE_LEN)
        .map_err(|e| AtRestError::Crypto(format!("random nonce: {e}")))?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nv);
    let ct = ciris_crypto::aes_gcm::encrypt(content_master, &nonce, dek)
        .map_err(|e| AtRestError::Crypto(format!("aes-gcm wrap dek: {e}")))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(B64.encode(out))
}

/// Reverse [`wrap_dek_for_persist`]: recover the DEK from the
/// `__persist_self__` grant's base64 `wrapped_dek` using the content
/// master key.
pub fn unwrap_dek_for_persist(
    content_master: &[u8; DEK_LEN],
    wrapped_dek_b64: &str,
) -> Result<[u8; DEK_LEN], AtRestError> {
    let raw = B64
        .decode(wrapped_dek_b64)
        .map_err(|e| AtRestError::Decode(format!("self-wrap base64: {e}")))?;
    if raw.len() < NONCE_LEN {
        return Err(AtRestError::Decode(format!(
            "self-wrap is {} bytes, shorter than the {NONCE_LEN}-byte nonce",
            raw.len()
        )));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&raw[..NONCE_LEN]);
    let pt = ciris_crypto::aes_gcm::decrypt(content_master, &nonce, &raw[NONCE_LEN..])
        .map_err(|e| AtRestError::Crypto(format!("aes-gcm unwrap dek: {e}")))?;
    if pt.len() != DEK_LEN {
        return Err(AtRestError::InvalidLength(format!(
            "unwrapped DEK is {} bytes, expected {DEK_LEN}",
            pt.len()
        )));
    }
    let mut dek = [0u8; DEK_LEN];
    dek.copy_from_slice(&pt);
    Ok(dek)
}

/// A v2 recipient wrap result, ready to record as a grant row.
#[derive(Debug, Clone)]
pub struct RecipientWrap {
    /// The recipient's occurrence federation key_id.
    pub recipient_key_id: String,
    /// The `KeyGrantWrapV2` JSON envelope (the `wrapped_dek` column).
    pub wrapped_dek_json: String,
}

/// Wrap `dek` to one recipient's content-encryption pubkeys via
/// `wrap_algorithm: v2` (`ciris_crypto::key_grant::wrap_dek_for_recipient_v2`).
///
/// `x25519_base64` (32-byte raw) and `ml_kem_768_base64` (1184-byte raw)
/// are the recipient's [`EncryptionPubkeys`](crate::federation::types::EncryptionPubkeys).
/// Returns the `KeyGrantWrapV2` JSON envelope — the exact shape
/// `wheel_key_grant::wrap_dek_for_recipient_v2_json` produces, so the
/// PyO3 unwrap surface round-trips it.
pub fn wrap_dek_v2(
    x25519_base64: &str,
    ml_kem_768_base64: &str,
    dek: &[u8; DEK_LEN],
) -> Result<String, AtRestError> {
    let x_pub_v = B64
        .decode(x25519_base64)
        .map_err(|e| AtRestError::Decode(format!("recipient x25519 base64: {e}")))?;
    let x_pub: [u8; 32] = x_pub_v.try_into().map_err(|v: Vec<u8>| {
        AtRestError::InvalidLength(format!("x25519 pubkey is {} bytes, expected 32", v.len()))
    })?;
    let ml_kem_pub = B64
        .decode(ml_kem_768_base64)
        .map_err(|e| AtRestError::Decode(format!("recipient ml-kem base64: {e}")))?;

    let wrap = ciris_crypto::key_grant::wrap_dek_for_recipient_v2(&x_pub, &ml_kem_pub, dek)
        .map_err(|e| AtRestError::Crypto(format!("key_grant v2 wrap: {e}")))?;

    let envelope = serde_json::json!({
        "algorithm": ciris_crypto::key_grant::KEY_GRANT_ALGORITHM_V2,
        "ephemeral_x25519_public_key_b64": B64.encode(wrap.ephemeral_x25519_public_key),
        "ml_kem_ciphertext_b64": B64.encode(&wrap.ml_kem_ciphertext),
        "nonce_b64": B64.encode(wrap.nonce),
        "ciphertext_b64": B64.encode(&wrap.ciphertext),
    });
    serde_json::to_string(&envelope)
        .map_err(|e| AtRestError::Crypto(format!("v2 envelope encode: {e}")))
}

/// The recipient-resolution + DEK-wrap + grant-record orchestration for
/// the [`CryptoTier::InvisibleEncrypted`] tier. Generic over a backend
/// that is **both** a [`FederationDirectory`] (recipient enumeration)
/// and a [`BlobStorage`] (ciphertext + grant persistence) — i.e. the
/// concrete `PostgresBackend` / `SqliteBackend`. The [`Engine`] calls
/// this on the matched backend arm.
///
/// [`CryptoTier::InvisibleEncrypted`]: crate::federation::types::cohort_scope::CryptoTier::InvisibleEncrypted
/// [`FederationDirectory`]: crate::federation::FederationDirectory
/// [`BlobStorage`]: crate::federation::blobs::BlobStorage
/// [`Engine`]: crate::Engine
pub mod orchestrate {
    use super::*;
    use crate::federation::blobs::{BlobBody, BlobError, BlobStorage};
    use crate::federation::types::cohort_scope::{CryptoTier, FAMILY, SELF};
    use crate::federation::types::EncryptionPubkeys;
    use crate::federation::FederationDirectory;
    use sha2::{Digest, Sha256};

    /// Outcome of an [`encrypt_and_cascade`] write.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CascadeResult {
        /// The at-rest content address (SHA-256 of the stored ciphertext
        /// envelope) — the handle a later
        /// [`get_blob_for_viewer`](read_for_viewer) read targets.
        pub at_rest_sha256: [u8; 32],
        /// Recipient occurrence key_ids that received a v2 grant.
        pub granted: Vec<String>,
        /// Active recipient occurrence key_ids **fail-secure excluded**
        /// because they carried no valid `encryption_pubkeys` (§10.1.4).
        /// They get NO grant — the content stays unreachable to them
        /// until they register keys; never a plaintext fallback.
        pub excluded: Vec<String>,
    }

    fn map_dir_err(e: crate::federation::Error) -> BlobError {
        BlobError::Backend(format!("at-rest cascade directory: {e}"))
    }

    fn map_at_rest_err(e: AtRestError) -> BlobError {
        BlobError::Backend(format!("at-rest cascade crypto: {e}"))
    }

    /// Valid-now wrap target? A recipient is excluded unless its
    /// occurrence carries BOTH encryption-pubkey halves. (Validity by
    /// `valid_until` is already applied by the `*_active` enumeration +
    /// `resolve_encryption_keys`.)
    fn usable_keys(keys: &Option<EncryptionPubkeys>) -> Option<&EncryptionPubkeys> {
        keys.as_ref()
            .filter(|k| !k.x25519_base64.is_empty() && !k.ml_kem_768_base64.is_empty())
    }

    /// Resolve the active recipient occurrences for a self/family write,
    /// as `(occurrence_key_id, encryption_pubkeys?)` pairs.
    ///
    /// - `self`: `list_identity_occurrences_active(owner_or_family_key_id)`.
    /// - `family`: every active occurrence of every current member
    ///   identity in the named family roster.
    async fn resolve_recipients<B>(
        backend: &B,
        cohort_scope: &str,
        owner_or_family_key_id: &str,
    ) -> Result<Vec<(String, Option<EncryptionPubkeys>)>, BlobError>
    where
        B: FederationDirectory + Sync,
    {
        match cohort_scope {
            SELF => {
                let occ = backend
                    .list_identity_occurrences_active(owner_or_family_key_id)
                    .await
                    .map_err(map_dir_err)?;
                Ok(occ
                    .into_iter()
                    .map(|o| (o.occurrence_key_id, o.encryption_pubkeys))
                    .collect())
            }
            FAMILY => {
                let family = backend
                    .lookup_family(owner_or_family_key_id)
                    .await
                    .map_err(map_dir_err)?
                    .ok_or_else(|| {
                        BlobError::InvalidArgument(format!(
                            "cohort_scope:family write names unknown family_key_id {owner_or_family_key_id:?}"
                        ))
                    })?;
                // Producer-side stop-wrapping (CIRISPersist#161 Ask 4,
                // CEG §11.7.1): a member removed via V067 is dropped from
                // the fan-out BEFORE we wrap — future writes simply exclude
                // them (forward secrecy under the per-write fresh DEK). The
                // `family.members` roster is the full admit history; compose
                // it with the family-membership revocation table so an
                // effective removal stops earning grants. (The per-member
                // `list_identity_occurrences_active` further drops revoked
                // *occurrences*; this drops revoked *memberships*.)
                let revs = backend
                    .list_family_membership_revocations_for(owner_or_family_key_id)
                    .await
                    .map_err(map_dir_err)?;
                let now = chrono::Utc::now();
                let removed: std::collections::HashSet<&str> = revs
                    .iter()
                    .filter(|r| r.effective_at <= now)
                    .map(|r| r.removed_identity_key_id.as_str())
                    .collect();
                let mut out = Vec::new();
                for member in &family.members {
                    if removed.contains(member.key_id.as_str()) {
                        continue;
                    }
                    let occ = backend
                        .list_identity_occurrences_active(&member.key_id)
                        .await
                        .map_err(map_dir_err)?;
                    for o in occ {
                        out.push((o.occurrence_key_id, o.encryption_pubkeys));
                    }
                }
                Ok(out)
            }
            other => Err(BlobError::InvalidArgument(format!(
                "encrypt_and_cascade is only for self/family, got cohort_scope {other:?}"
            ))),
        }
    }

    /// Encrypt `plaintext` at rest under a fresh per-write DEK, store the
    /// ciphertext envelope, wrap the DEK to every active recipient
    /// (fail-secure excluding those without valid `encryption_pubkeys`),
    /// and record persist's own content-master self-retention grant.
    ///
    /// `owner_or_family_key_id` is the identity key (self) or the
    /// family_key_id (family). Returns the [`CascadeResult`] (the at-rest
    /// SHA + the granted/excluded split).
    ///
    /// Precondition: `cohort_scope` resolves to
    /// [`CryptoTier::InvisibleEncrypted`] (the caller's dispatch already
    /// checked); other scopes are rejected with
    /// [`BlobError::InvalidArgument`].
    pub async fn encrypt_and_cascade<B>(
        backend: &B,
        cohort_scope: &str,
        owner_or_family_key_id: &str,
        plaintext: &[u8],
        media_type: Option<&str>,
    ) -> Result<CascadeResult, BlobError>
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        debug_assert_eq!(
            crate::federation::types::cohort_scope::crypto_tier(cohort_scope, None),
            CryptoTier::InvisibleEncrypted
        );

        // 1. Fresh per-write DEK + seal the body into a self-describing
        //    ciphertext envelope (the format/version marker).
        let dek = fresh_dek().map_err(map_at_rest_err)?;
        let envelope = seal(&dek, plaintext).map_err(map_at_rest_err)?;
        let envelope_bytes = envelope.to_bytes();
        let at_rest_sha256: [u8; 32] = Sha256::digest(&envelope_bytes).into();

        // 2. Store the ciphertext, structurally invisible (no holds_bytes;
        //    suppresses_holds_bytes is true for self/family).
        backend
            .store_blob_local(
                &at_rest_sha256,
                BlobBody::Inline(envelope_bytes),
                media_type,
            )
            .await?;

        // 3. persist self-retention: wrap the DEK under the content master
        //    so get_blob_for_viewer can recover it in the default tier.
        let content_master = backend.load_or_init_content_master().await?;
        let self_wrap = wrap_dek_for_persist(&content_master, &dek).map_err(map_at_rest_err)?;
        backend
            .put_at_rest_grant(
                &at_rest_sha256,
                PERSIST_SELF_RECIPIENT,
                WRAP_ALGORITHM_CONTENT_MASTER,
                &self_wrap,
                cohort_scope,
            )
            .await?;

        // 4. Recipient cascade — wrap the DEK to each active recipient
        //    whose occurrence carries valid encryption_pubkeys; fail-
        //    secure exclude the rest (no plaintext / v1 fallback).
        let recipients = resolve_recipients(backend, cohort_scope, owner_or_family_key_id).await?;
        let v2_algo = WRAP_ALGORITHM_V2;
        let mut granted = Vec::new();
        let mut excluded = Vec::new();
        for (occ_key_id, keys) in recipients {
            match usable_keys(&keys) {
                Some(k) => {
                    let wrapped = wrap_dek_v2(&k.x25519_base64, &k.ml_kem_768_base64, &dek)
                        .map_err(map_at_rest_err)?;
                    backend
                        .put_at_rest_grant(
                            &at_rest_sha256,
                            &occ_key_id,
                            v2_algo,
                            &wrapped,
                            cohort_scope,
                        )
                        .await?;
                    granted.push(occ_key_id);
                }
                None => excluded.push(occ_key_id),
            }
        }

        Ok(CascadeResult {
            at_rest_sha256,
            granted,
            excluded,
        })
    }

    /// One newcomer's wrap target for the [`rekey_for_newcomers`] walk:
    /// an occurrence key plus its (maybe-absent) content-encryption keys.
    #[derive(Debug, Clone)]
    pub struct Newcomer {
        /// The newcomer occurrence's federation key_id.
        pub occurrence_key_id: String,
        /// Its content-encryption pubkeys, or `None` (⇒ fail-secure
        /// excluded — no grant, never a plaintext fallback).
        pub encryption_pubkeys: Option<EncryptionPubkeys>,
    }

    /// Outcome of a [`rekey_for_newcomers`] retroactive-ADD walk.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct RekeyResult {
        /// Distinct at-rest blobs in the cohort-visibility set (the blobs
        /// the existing cohort already holds grants on, in this scope).
        pub blobs_scanned: usize,
        /// `(newcomer_occurrence_key_id, grants_added)` — the count of NEW
        /// grant rows written for each newcomer (re-running is idempotent:
        /// a grant already present is a no-op and not counted).
        pub granted: Vec<(String, usize)>,
        /// Newcomer occurrence key_ids **fail-secure excluded** for lacking
        /// valid `encryption_pubkeys`. They receive NO grant on ANY blob
        /// in the set; the caller emits `hard_case:recipient_excluded`.
        pub excluded: Vec<String>,
    }

    /// The **retroactive key-grant ADD re-wrap** (CIRISPersist#161 Ask 2/4,
    /// CEG §11.7.1 / §10.1.4) — the membership-change keystone.
    ///
    /// When a new occurrence/member is admitted into a cohort, the existing
    /// at-rest blobs in that cohort scope must become reachable to the
    /// newcomer. For each blob the existing cohort (`existing_recipients`)
    /// already holds grants on in `cohort_scope`, this:
    ///
    /// 1. recovers the per-write DEK via persist's `__persist_self__`
    ///    content-master self-retention grant
    ///    ([`unwrap_dek_for_persist`] over [`load_or_init_content_master`]);
    /// 2. `wrap_dek_v2`s it to each newcomer's `encryption_pubkeys`; and
    /// 3. `put_at_rest_grant`s the wrap.
    ///
    /// **Idempotent**: a newcomer already holding a grant for a blob is
    /// skipped (the underlying `put_at_rest_grant` is `ON CONFLICT DO
    /// NOTHING`, and the walk pre-checks the recipient set to avoid the
    /// re-unwrap), so re-running adds nothing. **Fail-secure**: a newcomer
    /// without valid `encryption_pubkeys` is recorded in
    /// [`RekeyResult::excluded`] and granted nothing — never a plaintext
    /// fallback.
    ///
    /// This composes over [`at_rest_cascade`](crate::federation::at_rest_cascade)
    /// — it reinvents no crypto. It does NOT touch existing grants of
    /// removed members (forward secrecy is automatic: the per-write fresh
    /// DEK means future writes simply exclude them; see the module + V070
    /// "never rewritten on remove" note). Retroactive *revoke* of past
    /// grants is intentionally out of scope (V067 models removal as an
    /// append-only revocation that the `*_active` read composes against; it
    /// does not delete at-rest grant rows, and CEG §11.7.1 Option-A relies
    /// on forward secrecy rather than retroactive key destruction).
    pub async fn rekey_for_newcomers<B>(
        backend: &B,
        cohort_scope: &str,
        existing_recipients: &[String],
        newcomers: &[Newcomer],
    ) -> Result<RekeyResult, BlobError>
    where
        B: BlobStorage + Sync,
    {
        if cohort_scope != SELF && cohort_scope != FAMILY {
            return Err(BlobError::InvalidArgument(format!(
                "rekey_for_newcomers is only for self/family, got cohort_scope {cohort_scope:?}"
            )));
        }

        // Split newcomers into wrap-able (keyed) and fail-secure-excluded.
        let mut keyed: Vec<(String, EncryptionPubkeys)> = Vec::new();
        let mut excluded: Vec<String> = Vec::new();
        for nc in newcomers {
            match usable_keys(&nc.encryption_pubkeys) {
                Some(k) => keyed.push((nc.occurrence_key_id.clone(), k.clone())),
                None => excluded.push(nc.occurrence_key_id.clone()),
            }
        }

        // The cohort-visibility set: blobs the existing cohort already
        // holds grants on, in this scope. Empty existing-recipient set ⇒
        // nothing to inherit (a brand-new cohort has no prior blobs).
        let blobs = if existing_recipients.is_empty() {
            Vec::new()
        } else {
            backend
                .list_at_rest_blobs_for_recipients(existing_recipients, cohort_scope)
                .await?
        };

        let mut granted: Vec<(String, usize)> = keyed.iter().map(|(k, _)| (k.clone(), 0)).collect();
        if keyed.is_empty() || blobs.is_empty() {
            return Ok(RekeyResult {
                blobs_scanned: blobs.len(),
                granted,
                excluded,
            });
        }

        let content_master = backend.load_or_init_content_master().await?;

        for sha in &blobs {
            // Which keyed newcomers still need a grant on this blob?
            let already: std::collections::HashSet<String> = backend
                .list_at_rest_grant_recipients(sha)
                .await?
                .into_iter()
                .collect();
            let needs: Vec<usize> = keyed
                .iter()
                .enumerate()
                .filter(|(_, (k, _))| !already.contains(k))
                .map(|(i, _)| i)
                .collect();
            if needs.is_empty() {
                continue; // every newcomer already granted on this blob.
            }

            // Recover the DEK once per blob via persist's self-retention
            // grant; a blob with no self-retention row is corrupt cascade
            // state (every encrypt_and_cascade writes one) — surface it.
            let self_grant = backend
                .get_at_rest_grant(sha, PERSIST_SELF_RECIPIENT)
                .await?
                .ok_or_else(|| {
                    BlobError::Backend(format!(
                        "rekey: at-rest blob {} in the cohort-visibility set has no persist \
                         self-retention row (corrupt cascade state)",
                        hex::encode(sha)
                    ))
                })?;
            let dek =
                unwrap_dek_for_persist(&content_master, &self_grant.1).map_err(map_at_rest_err)?;

            // #304 — wrap-once-to-the-identity: CIRISServer 0.5.56+ DERIVES a
            // user's content-KEM keypair (x25519 + ML-KEM-768) from the FedID
            // Ed25519 seed (CIRISVerify#151 / verify v8.3.0), so every
            // occurrence of one identity presents the IDENTICAL enc pubkey. The
            // wrap is recipient-determined by those pubkeys, so encap ONCE per
            // distinct pubkey pair and reuse the wrap for every occurrence that
            // shares it — any holder of the shared (derived) private key opens
            // it. This collapses N redundant ML-KEM-768 encaps to one per
            // derived identity; the grant rows stay per-occurrence (the reader
            // resolves by occurrence_key_id, unchanged). Non-derived (distinct)
            // pubkeys are unaffected — one wrap each, as before.
            let mut wrap_cache: std::collections::HashMap<(String, String), String> =
                std::collections::HashMap::new();
            for i in needs {
                let (occ_key_id, keys) = &keyed[i];
                let cache_key = (keys.x25519_base64.clone(), keys.ml_kem_768_base64.clone());
                let wrapped = match wrap_cache.get(&cache_key) {
                    Some(w) => w.clone(),
                    None => {
                        let w = wrap_dek_v2(&keys.x25519_base64, &keys.ml_kem_768_base64, &dek)
                            .map_err(map_at_rest_err)?;
                        wrap_cache.insert(cache_key, w.clone());
                        w
                    }
                };
                backend
                    .put_at_rest_grant(sha, occ_key_id, WRAP_ALGORITHM_V2, &wrapped, cohort_scope)
                    .await?;
                granted[i].1 += 1;
            }
        }

        Ok(RekeyResult {
            blobs_scanned: blobs.len(),
            granted,
            excluded,
        })
    }

    /// Emit the membership-change `hard_case:*` observability events for a
    /// completed [`rekey_for_newcomers`] walk (CIRISPersist#161 Ask 3/4):
    /// one [`FAMILY_MEMBERSHIP_CHANGE`](crate::federation::hard_case::kind::FAMILY_MEMBERSHIP_CHANGE)
    /// per newcomer (the observed roster delta), and one
    /// [`RECIPIENT_EXCLUDED`](crate::federation::hard_case::kind::RECIPIENT_EXCLUDED)
    /// per fail-secure-excluded keyless newcomer. Idempotent on the
    /// deterministic `event_id`s — re-running the walk at the same logical
    /// instant re-emits nothing.
    ///
    /// `target_key_id` is the family_key_id (family add) or the identity
    /// key (self add). The events are recorded through the
    /// [`record_hard_case`](FederationDirectory::record_hard_case) surface.
    async fn emit_membership_hard_cases<B>(
        backend: &B,
        cohort_scope: &str,
        target_key_id: &str,
        result: &RekeyResult,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), BlobError>
    where
        B: FederationDirectory + Sync,
    {
        use crate::federation::hard_case;
        // One membership-change event per newcomer (granted or excluded) —
        // the roster delta persist observed.
        let all_newcomers = result
            .granted
            .iter()
            .map(|(k, _)| k.as_str())
            .chain(result.excluded.iter().map(|k| k.as_str()));
        for member in all_newcomers {
            let granted_count = result
                .granted
                .iter()
                .find(|(k, _)| k == member)
                .map(|(_, n)| *n);
            backend
                .record_hard_case(hard_case::HardCaseEvent {
                    event_id: hard_case::membership_change_event_id(
                        target_key_id,
                        member,
                        observed_at,
                    ),
                    kind: hard_case::kind::FAMILY_MEMBERSHIP_CHANGE.to_string(),
                    target_key_id: Some(target_key_id.to_string()),
                    subject_key_id: Some(member.to_string()),
                    detail: serde_json::json!({
                        // CEG §7.7 canonical payload (1.0-RC5): direction +
                        // subject + cohort + effective instant. The add path
                        // is `change_kind: "added"` (the removal path emits
                        // `"removed"` from `put_*_membership_revocation`).
                        "change_kind": hard_case::change_kind::ADDED,
                        "subject_key_id": member,
                        "cohort_key_id": target_key_id,
                        "effective_at": observed_at.to_rfc3339(),
                        // Diagnostic fields persist has always carried.
                        "cohort_scope": cohort_scope,
                        "blobs_scanned": result.blobs_scanned,
                        "grants_added": granted_count,
                        "excluded": granted_count.is_none(),
                    }),
                    emitted_at: observed_at,
                })
                .await
                .map_err(|e| BlobError::Backend(format!("emit membership_change: {e}")))?;
        }
        // One recipient-excluded event per fail-secure exclusion.
        for excluded in &result.excluded {
            backend
                .record_hard_case(hard_case::HardCaseEvent {
                    event_id: hard_case::recipient_excluded_event_id(
                        cohort_scope,
                        excluded,
                        observed_at,
                    ),
                    kind: hard_case::kind::RECIPIENT_EXCLUDED.to_string(),
                    target_key_id: Some(target_key_id.to_string()),
                    subject_key_id: Some(excluded.clone()),
                    detail: serde_json::json!({
                        "cohort_scope": cohort_scope,
                        "blobs_scanned": result.blobs_scanned,
                        "reason": "no_valid_encryption_pubkeys",
                    }),
                    emitted_at: observed_at,
                })
                .await
                .map_err(|e| BlobError::Backend(format!("emit recipient_excluded: {e}")))?;
        }
        Ok(())
    }

    /// Membership-change driver for a **family** member-add (CEG §11.7.1 /
    /// §10.1.4, CIRISPersist#161 Ask 2/4) — the integration entry the
    /// [`Engine`](crate::Engine) dispatches.
    ///
    /// Resolves the newcomer member identity's active occurrences (the
    /// wrap targets) and the existing cohort recipients (every *other*
    /// active member identity's active occurrences), runs
    /// [`rekey_for_newcomers`] over the family-scope visibility set, and
    /// emits the membership `hard_case:*` events. Idempotent + fail-secure
    /// throughout. Returns the [`RekeyResult`].
    ///
    /// A keyless newcomer occurrence is excluded (no grant) and surfaced as
    /// `hard_case:recipient_excluded`; the family roster itself is the
    /// caller's responsibility (this runs *after* `put_family` admits the
    /// member — the roster already names them).
    pub async fn rekey_family_member_add<B>(
        backend: &B,
        family_key_id: &str,
        new_member_identity_key_id: &str,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<RekeyResult, BlobError>
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        let family = backend
            .lookup_family(family_key_id)
            .await
            .map_err(map_dir_err)?
            .ok_or_else(|| {
                BlobError::InvalidArgument(format!(
                    "rekey_family_member_add names unknown family_key_id {family_key_id:?}"
                ))
            })?;

        // Forward-path half (v6.2.0, #161 A4/A5): put the newcomer on the
        // roster so `resolve_recipients` includes them in FUTURE family
        // writes. Idempotent — re-running the driver, or admitting an
        // already-rostered member, is a no-op here. The re-key below is the
        // backward-path half (grant the newcomer PAST family blobs). Order
        // matters only for crash-consistency: roster-grow first means a
        // crash between the two leaves a rostered member missing some past
        // grants (recoverable by re-running the driver — re-key is
        // idempotent), never a re-keyed member absent from the roster.
        backend
            .add_family_member(
                family_key_id,
                crate::federation::types::FamilyMember {
                    key_id: new_member_identity_key_id.to_string(),
                    joined_at: observed_at,
                    role: None,
                },
            )
            .await
            .map_err(map_dir_err)?;

        // Newcomers = the new member identity's active occurrences.
        let newcomers: Vec<Newcomer> = backend
            .list_identity_occurrences_active(new_member_identity_key_id)
            .await
            .map_err(map_dir_err)?
            .into_iter()
            .map(|o| Newcomer {
                occurrence_key_id: o.occurrence_key_id,
                encryption_pubkeys: o.encryption_pubkeys,
            })
            .collect();

        // Existing cohort = every OTHER current member's active occurrences.
        let mut existing: Vec<String> = Vec::new();
        for m in &family.members {
            if m.key_id == new_member_identity_key_id {
                continue;
            }
            let occ = backend
                .list_identity_occurrences_active(&m.key_id)
                .await
                .map_err(map_dir_err)?;
            existing.extend(occ.into_iter().map(|o| o.occurrence_key_id));
        }

        let result = rekey_for_newcomers(backend, FAMILY, &existing, &newcomers).await?;
        emit_membership_hard_cases(backend, FAMILY, family_key_id, &result, observed_at).await?;
        Ok(result)
    }

    /// Membership-change driver for a **self** occurrence-add (CEG §11.7.1
    /// / §10.1.4) — a person admitting a new device-occurrence into their
    /// self-collective.
    ///
    /// Newcomers = the named new occurrence(s); existing cohort = the
    /// identity's *other* active occurrences. Runs the self-scope re-key +
    /// emits the membership events. Mirror of [`rekey_family_member_add`].
    pub async fn rekey_self_occurrence_add<B>(
        backend: &B,
        identity_key_id: &str,
        new_occurrence_key_ids: &[String],
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<RekeyResult, BlobError>
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        let active = backend
            .list_identity_occurrences_active(identity_key_id)
            .await
            .map_err(map_dir_err)?;
        let newset: std::collections::HashSet<&str> =
            new_occurrence_key_ids.iter().map(String::as_str).collect();

        let mut newcomers: Vec<Newcomer> = Vec::new();
        let mut existing: Vec<String> = Vec::new();
        for o in active {
            if newset.contains(o.occurrence_key_id.as_str()) {
                newcomers.push(Newcomer {
                    occurrence_key_id: o.occurrence_key_id,
                    encryption_pubkeys: o.encryption_pubkeys,
                });
            } else {
                existing.push(o.occurrence_key_id);
            }
        }

        let result = rekey_for_newcomers(backend, SELF, &existing, &newcomers).await?;
        emit_membership_hard_cases(backend, SELF, identity_key_id, &result, observed_at).await?;
        Ok(result)
    }

    /// #249 Cut G4 (§7) — forward-secrecy re-key on **community** member
    /// REMOVAL: the symmetric of [`rekey_family_member_add`]. Records the
    /// community membership revocation (forward-only; the active fold drops the
    /// member), then **bumps the community DEK epoch** (CC 4.4.3.2.2) so the
    /// next [`encrypt_and_cascade_community`](crate::federation::community_dek::encrypt_and_cascade_community)
    /// mints a FRESH DEK wrapped only to the REMAINING members — the removed
    /// member's keys can never unwrap content sealed after this point. Emits the
    /// [`membership_removed_event`](crate::federation::hard_case::membership_removed_event)
    /// (§9). Returns the new epoch.
    ///
    /// **Community-only by construction.** `self`/`family` use a *fresh-per-write*
    /// DEK ([`CryptoTier::InvisibleEncrypted`](crate::federation::types::cohort_scope::CryptoTier)):
    /// every write's wrap set is the active roster at write time, so a removed
    /// member is excluded from all FUTURE writes **inherently** — there is no
    /// shared epoch to bump (forward secrecy holds without a re-key). Only the
    /// community tier shares one DEK per `(community, epoch)` and therefore must
    /// rotate on removal.
    pub async fn rekey_community_member_revoke<B>(
        backend: &B,
        community_key_id: &str,
        removed_identity_key_id: &str,
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, BlobError>
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        use crate::federation::hard_case;
        // 1. Record the removal (append-only; the roster-minus-effective-
        //    revocations fold stops counting the member from `effective_at`).
        backend
            .put_community_membership_revocation(
                crate::federation::types::SignedCommunityMembershipRevocation {
                    community_membership_revocation:
                        crate::federation::types::CommunityMembershipRevocation {
                            community_key_id: community_key_id.to_string(),
                            removed_identity_key_id: removed_identity_key_id.to_string(),
                            removed_at: observed_at,
                            effective_at: observed_at,
                            reason: None,
                            witness_set: Vec::new(),
                            persist_row_hash: String::new(),
                        },
                },
            )
            .await
            .map_err(map_dir_err)?;
        // 2. Forward secrecy: bump the epoch. The next community cascade mints a
        //    fresh DEK and wraps it only to the remaining members (the wrap
        //    fan-out reads the active roster, which now excludes this member).
        let new_epoch = backend.community_dek_bump_epoch(community_key_id).await?;
        // 3. §9 — emit the membership-removed change event (consumers reconcile
        //    via list_hard_case_events instead of polling).
        backend
            .record_hard_case(hard_case::membership_removed_event(
                hard_case::kind::COMMUNITY_MEMBERSHIP_CHANGE,
                community_key_id,
                removed_identity_key_id,
                observed_at,
            ))
            .await
            .map_err(|e| BlobError::Backend(format!("emit membership_removed: {e}")))?;
        Ok(new_epoch)
    }

    /// The default-tier read: recover the plaintext blob body for a
    /// granted viewer. Persist unwraps the DEK (via its content-master
    /// self-retention grant), AES-GCM-decrypts, and returns the bytes.
    ///
    /// - [`BlobError::NotHeld`] if the at-rest bytes are absent.
    /// - [`BlobError::NotGranted`] if the viewer holds no grant (a
    ///   non-recipient, a revoked recipient, or a recipient that was
    ///   fail-secure excluded at write time).
    pub async fn read_for_viewer<B>(
        backend: &B,
        at_rest_sha256: &[u8; 32],
        viewer_key_id: &str,
    ) -> Result<Vec<u8>, BlobError>
    where
        B: BlobStorage + Sync,
    {
        // 1. The viewer's grant must exist (fail-secure gate). The
        //    grant's wrapped DEK shape is irrelevant to the default tier
        //    (persist decrypts via its own self-retention row); the
        //    viewer grant is the *authorization* predicate. A viewer with
        //    no grant is NotGranted even if the bytes are present.
        let viewer_grant = backend
            .get_at_rest_grant(at_rest_sha256, viewer_key_id)
            .await?;
        if viewer_grant.is_none() {
            return Err(BlobError::NotGranted {
                sha256_hex: hex::encode(at_rest_sha256),
                viewer_key_id: viewer_key_id.to_string(),
            });
        }

        // 2. The bytes must be held.
        let body = backend.get_blob(at_rest_sha256).await?;
        let envelope_bytes = match body {
            Some(BlobBody::Inline(b)) => b,
            Some(_) => {
                return Err(BlobError::InvalidArgument(
                    "at-rest blob is not an inline ciphertext envelope".into(),
                ))
            }
            None => {
                return Err(BlobError::NotHeld {
                    sha256_hex: hex::encode(at_rest_sha256),
                })
            }
        };
        let envelope = AtRestEnvelope::from_bytes(&envelope_bytes).map_err(map_at_rest_err)?;

        // 3. Recover the DEK via persist's content-master self-retention.
        let self_grant = backend
            .get_at_rest_grant(at_rest_sha256, PERSIST_SELF_RECIPIENT)
            .await?
            .ok_or_else(|| {
                BlobError::Backend(format!(
                    "at-rest blob {} has a viewer grant but no persist self-retention row \
                     (corrupt cascade state)",
                    hex::encode(at_rest_sha256)
                ))
            })?;
        let content_master = backend.load_or_init_content_master().await?;
        let dek =
            unwrap_dek_for_persist(&content_master, &self_grant.1).map_err(map_at_rest_err)?;

        // 4. Decrypt + return plaintext.
        open(&dek, &envelope).map_err(map_at_rest_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trips_through_bytes() {
        let env = AtRestEnvelope {
            nonce: [0x11; NONCE_LEN],
            ciphertext: vec![1, 2, 3, 4, 5],
        };
        let bytes = env.to_bytes();
        assert!(AtRestEnvelope::has_magic(&bytes));
        let back = AtRestEnvelope::from_bytes(&bytes).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn plaintext_body_is_not_mistaken_for_an_envelope() {
        let plain = b"a perfectly ordinary plaintext note about the cat";
        assert!(!AtRestEnvelope::has_magic(plain));
        let err = AtRestEnvelope::from_bytes(plain).unwrap_err();
        assert!(matches!(err, AtRestError::Decode(_)));
    }

    #[test]
    fn from_bytes_rejects_truncated_header() {
        let err = AtRestEnvelope::from_bytes(&AT_REST_ENVELOPE_MAGIC[..4]).unwrap_err();
        assert!(matches!(err, AtRestError::Decode(_)));
    }

    #[test]
    fn seal_open_round_trip_recovers_plaintext() {
        let dek = fresh_dek().unwrap();
        let pt = b"family photo bytes";
        let env = seal(&dek, pt).unwrap();
        // The sealed envelope must NOT equal the plaintext.
        assert_ne!(env.to_bytes(), pt.to_vec());
        let back = open(&dek, &env).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn open_rejects_wrong_dek() {
        let dek = fresh_dek().unwrap();
        let env = seal(&dek, b"secret").unwrap();
        let wrong = [0x99u8; DEK_LEN];
        assert!(matches!(open(&wrong, &env), Err(AtRestError::Crypto(_))));
    }

    #[test]
    fn persist_self_wrap_round_trip() {
        let master = [0x42u8; DEK_LEN];
        let dek = fresh_dek().unwrap();
        let wrapped = wrap_dek_for_persist(&master, &dek).unwrap();
        let back = unwrap_dek_for_persist(&master, &wrapped).unwrap();
        assert_eq!(back, dek);
    }

    #[test]
    fn persist_self_unwrap_rejects_wrong_master() {
        let master = [0x42u8; DEK_LEN];
        let dek = fresh_dek().unwrap();
        let wrapped = wrap_dek_for_persist(&master, &dek).unwrap();
        let wrong = [0x43u8; DEK_LEN];
        assert!(matches!(
            unwrap_dek_for_persist(&wrong, &wrapped),
            Err(AtRestError::Crypto(_))
        ));
    }

    #[test]
    fn recipient_v2_wrap_round_trips_via_ciris_crypto() {
        use ciris_crypto::x25519;
        let x_priv: [u8; 32] = [0x42; 32];
        let x_pub = x25519::public_from_secret(&x_priv);
        let (ml_priv, ml_pub) = ciris_crypto::ml_kem::generate_keypair().unwrap();
        let dek = fresh_dek().unwrap();

        let json = wrap_dek_v2(&B64.encode(x_pub), &B64.encode(&ml_pub), &dek).unwrap();
        assert!(json.contains("x25519-mlkem768-aes256-gcm-hkdf-sha256"));

        // Recover via the wheel_key_grant unwrap surface shape.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let eph: [u8; 32] = B64
            .decode(v["ephemeral_x25519_public_key_b64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let ml_ct = B64
            .decode(v["ml_kem_ciphertext_b64"].as_str().unwrap())
            .unwrap();
        let nonce: [u8; 12] = B64
            .decode(v["nonce_b64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let ct = B64.decode(v["ciphertext_b64"].as_str().unwrap()).unwrap();
        let wrap = ciris_crypto::key_grant::KeyGrantWrapV2 {
            ephemeral_x25519_public_key: eph,
            ml_kem_ciphertext: ml_ct,
            nonce,
            ciphertext: ct,
        };
        let back =
            ciris_crypto::key_grant::unwrap_dek_v2(&x_priv, &ml_priv, &ml_pub, &wrap).unwrap();
        assert_eq!(back, dek);
    }
}
