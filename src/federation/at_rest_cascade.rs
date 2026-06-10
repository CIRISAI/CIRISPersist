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
                let mut out = Vec::new();
                for member in &family.members {
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
