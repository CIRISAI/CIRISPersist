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
///
/// v25.1.0 (CIRISPersist#582, CC 5.1 / CIRISVerify#234) — this string and
/// `ciris_crypto::key_grant::KEY_GRANT_ALGORITHM_V2` are now **the same
/// identifier**. They were not: verify's constant carried the hyphenated
/// spelling until v11.1.0, when CC 5.1 (class rule CC 3.3.2) ratified the
/// snake_case form as *the single wire identifier* and demoted the hyphenated
/// one to a non-conformant alias that MUST be rejected and MUST NOT be
/// normalized before comparison. Persist's column string was already
/// conformant; the convergence is verify's constant moving to meet it. See
/// [`crate::maintenance::vocabulary`] for how already-stored non-conformant
/// values are retired (superseded, never rewritten).
pub const WRAP_ALGORITHM_V2: &str = "x25519_mlkem768_aes256_gcm_hkdf_sha256";

/// HKDF `context` (info string) for the content-at-rest master key.
/// **Stable wire constant** — changing it re-derives a different master
/// and orphans every at-rest blob encrypted under the old one. Distinct
/// from `secrets-store-master-v1` so content keys and secret-store keys
/// are domain-separated (BLOB_ENCRYPTION_AT_REST.md §4.3).
pub const CONTENT_MASTER_CONTEXT: &str = "content-at-rest-master-v1";

/// v43.0.0 (`FSD/BLOB_ENCRYPTION_AT_REST.md` §10.2) — **where the
/// content-at-rest master comes from.**
///
/// [`content_master_key`] returns this rather than a bare key so the
/// caller cannot lose the provenance on the way to
/// `federation_content_master.key_kind`. A software master recorded as
/// hardware would be a lie the schema is specifically shaped to prevent
/// (`master_key_b64` is "present iff `key_kind='software'`").
#[derive(Debug)]
pub enum ContentMasterSource {
    /// HKDF-derived from the platform's hardware-sealed seed under
    /// [`CONTENT_MASTER_CONTEXT`]. **Deterministic** — re-derived on every
    /// call from the same seed, so nothing is stored and there is no key
    /// material in the database at all.
    Hardware {
        /// The 32-byte derived master. `Zeroizing` — scrubbed on drop.
        key: zeroize::Zeroizing<[u8; 32]>,
        /// Provenance for `federation_content_master.descriptor`.
        descriptor: String,
    },
    /// No hardware-backed secure storage is reachable. The caller
    /// generates and persists a software master and MUST record it as
    /// `key_kind='software'` with `reason` in the descriptor.
    ///
    /// This is a clean, expected outcome on a no-TPM host — not an error.
    /// It is a distinct variant rather than a silent fallback so that
    /// "we are on software" is a decision the caller makes explicitly.
    SoftwareFallback {
        /// Why hardware was unavailable, verbatim, for the descriptor.
        reason: String,
    },
}

/// v43.0.0 (§10.2) — **resolve the content-at-rest master key.**
///
/// This is the function `at_rest_cascade`'s module header has always
/// pointed at and which, until now, did not exist: the header described
/// "hardware-rooted HKDF over the secrets-store sealed seed under a
/// distinct context, with a software fallback honest about being
/// software", [`CONTENT_MASTER_CONTEXT`] was defined with **zero call
/// sites**, and the backends generated a random software key instead. So
/// the fallback was not a fallback — it was the only path, reached by
/// default rather than by decision, while the doc asserted otherwise.
///
/// # The derivation
///
/// Same hardware-sealed seed as the secrets store, different HKDF
/// `info` — per §4.3, "no new master-key root". CIRISVerify owns the KDF
/// (`ciris_verify_core::derive_symmetric_key`); persist never implements
/// it (MISSION §1.4).
///
/// # Why the persisted row still wins
///
/// A node that already has a `key_kind='software'` row keeps using it
/// even once hardware becomes available. Re-deriving would orphan every
/// blob sealed under the software master **and** the sealed content-KEM
/// private halves, which are themselves sealed under this key. The same
/// rule the content-KEM identity already states: the stable persisted
/// material always wins. Migrating software → hardware is a re-wrap
/// operation, not a re-derivation, and is out of scope here.
///
/// **Synchronous / blocking** (TPM + filesystem I/O) — call from
/// `spawn_blocking`.
#[must_use]
pub fn content_master_key(create_seed_if_absent: bool) -> ContentMasterSource {
    #[cfg(feature = "secrets")]
    {
        match crate::secrets::hardware::derive_hardware_content_master_key(create_seed_if_absent) {
            // `derive_hardware_master_for_context` already asserts the length,
            // but this is the boundary where a wrong length would become a
            // silent truncation, so it is re-checked rather than assumed.
            Ok((master, descriptor)) => match <[u8; 32]>::try_from(master.as_slice()) {
                Ok(key) => ContentMasterSource::Hardware {
                    key: zeroize::Zeroizing::new(key),
                    descriptor,
                },
                Err(_) => ContentMasterSource::SoftwareFallback {
                    reason: format!(
                        "verify derived a {}-byte content master, expected 32",
                        master.len()
                    ),
                },
            },
            Err(e) => ContentMasterSource::SoftwareFallback {
                reason: format!("hardware content master unavailable: {e}"),
            },
        }
    }
    #[cfg(not(feature = "secrets"))]
    {
        let _ = create_seed_if_absent;
        ContentMasterSource::SoftwareFallback {
            reason: "built without the `secrets` feature — no hardware-sealed \
                     seed is reachable, so no hardware-rooted content master \
                     can be derived"
                .to_owned(),
        }
    }
}

/// v43.0.0 (§11.8) — the hardware-derived content master, resolved ONCE per
/// process on the blocking pool and cached. The derivation is deterministic
/// for a host (same seed, same context), so a process-global cache is
/// correct; the first implementation re-ran TPM + filesystem I/O inline on
/// a tokio worker for EVERY encrypted read and write.
///
/// Only the HARDWARE arm is cached: a software master lives in the database
/// row and is read there.
pub async fn hardware_content_master_cached() -> Option<[u8; 32]> {
    static CACHE: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    if let Some(v) = CACHE.get() {
        return Some(*v);
    }
    // Re-derivation of a master in use: NEVER mint a seed (§11.7).
    let derived = tokio::task::spawn_blocking(|| match content_master_key(false) {
        ContentMasterSource::Hardware { key, .. } => Some(*key),
        ContentMasterSource::SoftwareFallback { .. } => None,
    })
    .await
    .ok()
    .flatten();
    remember_only_success(&CACHE, derived)
}

/// §11.8 / I29 — **the cache remembers only success.** A transient TPM or
/// filesystem failure (or a failed join) yields `None` for THIS call and
/// leaves the cache empty, so the next call derives again. The second
/// rebuild cached whatever the first derivation returned — `None` included —
/// so one bad moment at boot made the corpus unavailable until restart.
fn remember_only_success(
    cache: &'static std::sync::OnceLock<[u8; 32]>,
    derived: Option<[u8; 32]>,
) -> Option<[u8; 32]> {
    let key = derived?;
    Some(*cache.get_or_init(|| key))
}

/// v43.0.0 (§11.8) — [`resolve_persisted_content_master`] with the hardware
/// arm served from [`hardware_content_master_cached`]: ONE TPM + filesystem
/// derivation per process instead of one per encrypted read and write. The
/// backends call THIS; the sync resolver below is the software arm and the
/// error vocabulary. (Ultrareview of `30fde79`: the cache existed with zero
/// callers, so the perf fix its docstring described was not applied.)
pub async fn resolve_persisted_content_master_cached(
    key_kind: &str,
    stored_b64: Option<&str>,
) -> Result<[u8; 32], AtRestError> {
    if key_kind == "hardware" {
        return hardware_content_master_cached().await.ok_or_else(|| {
            AtRestError::Crypto(
                "content master is recorded hardware-rooted but the hardware-sealed seed \
                 cannot be reached on this host — refusing to re-mint over a corpus sealed \
                 under it (BLOB_ENCRYPTION_AT_REST.md §11.7)"
                    .to_owned(),
            )
        });
    }
    resolve_persisted_content_master(key_kind, stored_b64)
}

/// v43.0.0 (§10.2) — turn a persisted `federation_content_master` row into
/// the 32-byte master, re-deriving when the row says hardware.
///
/// Shared by both SQL backends so the hardware/software decision cannot
/// drift between them — the `#596` class (three axes silently ignored by
/// one backend) is exactly what a per-backend copy of this would invite.
///
/// The row is the authority on WHICH root, never this function: a
/// `software` row carries its key and is used verbatim; a `hardware` row
/// carries no key and is re-derived from the sealed seed. That asymmetry
/// is the schema's own (`master_key_b64` is "present iff
/// `key_kind='software'`").
///
/// # Errors
///
/// A `hardware` row whose seed is no longer reachable is a HARD error, not
/// a fallback. Silently minting a fresh software master there would leave
/// every blob sealed under the old root undecryptable while reporting
/// success — the failure mode this returns an error to avoid.
pub fn resolve_persisted_content_master(
    key_kind: &str,
    master_key_b64: Option<&str>,
) -> Result<[u8; 32], AtRestError> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    match (key_kind, master_key_b64) {
        ("software", Some(b64)) => {
            let raw = B64
                .decode(b64)
                .map_err(|e| AtRestError::Crypto(format!("content-master b64: {e}")))?;
            <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| {
                AtRestError::Crypto(format!(
                    "content master is {} bytes, expected 32",
                    raw.len()
                ))
            })
        }
        ("hardware", _) => match content_master_key(false) {
            ContentMasterSource::Hardware { key, .. } => Ok(*key),
            ContentMasterSource::SoftwareFallback { reason } => Err(AtRestError::Crypto(format!(
                "content master is recorded hardware-rooted but the hardware-sealed seed \
                 is unreachable ({reason}); everything sealed under it — including the \
                 content-KEM private halves — cannot be decrypted without it. Refusing to \
                 mint a replacement, which would report success over an unreadable corpus"
            ))),
        },
        ("software", None) => Err(AtRestError::Crypto(
            "content master row says software but carries no key bytes".to_owned(),
        )),
        (other, _) => Err(AtRestError::Crypto(format!(
            "content master row has unknown key_kind {other:?}"
        ))),
    }
}

/// v43.0.0 (`FSD/BLOB_ENCRYPTION_AT_REST.md` §10.8) — **is this body
/// sealed?**, answered from the bytes rather than from the caller's word.
///
/// A sealed body starts with [`AT_REST_ENVELOPE_MAGIC`]. That is the whole
/// test for an inline body, and it is a test persist can actually perform.
///
/// # Why the other two variants are refusals, not passes
///
/// `External` — persist deliberately never dereferences the URI
/// ([`BlobBody::External`]'s own contract). It therefore cannot see the
/// bytes, cannot know whether they are sealed, and must not assert a
/// property it has no way to check. `ChunkDag` — the chunks are separate
/// rows; THIS function sees only the manifest, so per-chunk sealing is not
/// verifiable from a body alone.
///
/// In both cases the honest answer is "cannot verify", and in an encrypted
/// cohort **cannot-verify is a refusal**. Accepting them would make the
/// gate a report: it would pass, nothing would be red, and the plaintext
/// would be on disk in a cohort whose whole confidentiality story is that
/// it is not.
///
/// #832 (`BLOB_ENCRYPTION_AT_REST.md` §12.3) — a DAG IS verifiable, by a
/// different door: `chunk_dag_cascade::orchestrate::seal_stream_scoped`
/// checks the chunk ROWS (each chunk row records the tier it was stored at)
/// and refuses a DAG whose chunks are not all at its tier. This body-only
/// verdict stays a refusal precisely so nobody routes a DAG through a door
/// that cannot look at the rows.
#[must_use]
pub fn body_is_sealed(body: &crate::federation::blobs::BlobBody) -> BodySealState {
    use crate::federation::blobs::BlobBody;
    match body {
        BlobBody::Inline(bytes) => {
            if bytes.len() >= AT_REST_ENVELOPE_MAGIC.len()
                && bytes[..AT_REST_ENVELOPE_MAGIC.len()] == AT_REST_ENVELOPE_MAGIC
            {
                BodySealState::Sealed
            } else {
                BodySealState::Plaintext
            }
        }
        BlobBody::External(_) => BodySealState::Unverifiable {
            why: "an External body is a URI persist never dereferences, so its bytes \
                  cannot be inspected here",
        },
        BlobBody::ChunkDag(_) => BodySealState::Unverifiable {
            why: "a ChunkDag's chunks are separate rows; this door sees only the \
                  manifest, so per-chunk sealing cannot be verified here",
        },
    }
}

/// v43.0.0 (`BLOB_ENCRYPTION_AT_REST.md` §11.2) — **the tier a write at
/// `cohort_scope` lands on, resolved from the DIRECTORY.**
///
/// For `community` / `affiliations` the tier depends on the community
/// record and its authority: an AUTHORIZED `cohort_subkind: infrastructure`
/// community is Commons-tier plaintext (CC 4.4.3.2.1, normative), a
/// merely-labeled one is not (SecReview F2). That is why `community_key_id`
/// is required for those scopes and why the caller's own opinion of the
/// tier is never consulted — the first implementation called
/// `crypto_tier(scope, None)`, dropping the one axis a caller must not be
/// allowed to assert, and made infra content unstorable by any route.
pub async fn resolve_write_tier<D>(
    dir: &D,
    cohort_scope: &str,
    community_key_id: Option<&str>,
) -> Result<crate::federation::types::cohort_scope::CryptoTier, crate::federation::BlobError>
where
    D: crate::federation::FederationDirectory + ?Sized + Sync,
{
    use crate::federation::types::cohort_scope::{self as cs, CryptoTier};
    if !cs::is_valid(cohort_scope) {
        return Err(crate::federation::BlobError::InvalidArgument(format!(
            "cohort_scope {cohort_scope:?} is not in the closed set \
             {{self, family, community, affiliations, species, biosphere, federation}}"
        )));
    }
    if cohort_scope != cs::COMMUNITY && cohort_scope != cs::AFFILIATIONS {
        return Ok(cs::crypto_tier(cohort_scope, None));
    }
    let Some(comm) = community_key_id else {
        return Err(crate::federation::BlobError::InvalidArgument(format!(
            "cohort_scope {cohort_scope:?} requires community_key_id: the tier of community \
             content is a property of the community record, not of the label"
        )));
    };
    let community = dir
        .lookup_community(comm)
        .await
        .map_err(|e| {
            crate::federation::BlobError::Backend(format!(
                "resolve_write_tier: lookup_community: {e}"
            ))
        })?
        .ok_or_else(|| {
            crate::federation::BlobError::InvalidArgument(format!(
                "unknown community_key_id {comm:?}"
            ))
        })?;
    let infra =
        crate::federation::admission::is_authorized_infrastructure_community(dir, &community)
            .await
            .map_err(|e| {
                crate::federation::BlobError::Backend(format!(
                    "resolve_write_tier: infra check: {e}"
                ))
            })?;
    Ok(if infra {
        CryptoTier::Plaintext
    } else {
        cs::crypto_tier(cohort_scope, None)
    })
}

/// The three answers [`body_is_sealed`] can give. `Unverifiable` is
/// deliberately distinct from `Plaintext`: they refuse for different
/// reasons and a reader of the error deserves to know which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodySealState {
    /// Carries [`AT_REST_ENVELOPE_MAGIC`].
    Sealed,
    /// Inline bytes with no envelope magic — demonstrably not sealed.
    Plaintext,
    /// Persist cannot see the bytes from this door.
    Unverifiable {
        /// Why, for the refusal message.
        why: &'static str,
    },
}

/// v43.0.0 (§10.8) — **the write-door gate: an encrypted cohort never
/// accepts an unsealed body.**
///
/// `self` / `family` / `community` / `affiliations` resolve to an encrypted
/// [`CryptoTier`](crate::federation::types::cohort_scope::CryptoTier); the
/// commons tiers resolve to `Plaintext` and are unaffected.
///
/// # Why this is a gate and not a convention
///
/// Fountaining a plaintext shard cannot be undone. No later rotation
/// recalls it, and the tombstone plane cannot un-see it — §10.8. The
/// window between "wrote plaintext" and "noticed" is unbounded, and the
/// damage is already distributed by then. So the refusal has to be at the
/// door, before the bytes exist anywhere.
///
/// # Errors
///
/// [`BlobError::InvalidArgument`] naming the cohort, its tier, and which
/// of the two reasons applies.
pub fn check_body_sealed_for_cohort(
    cohort_scope: &str,
    body: &crate::federation::blobs::BlobBody,
) -> Result<(), crate::federation::BlobError> {
    use crate::federation::types::cohort_scope::{crypto_tier, CryptoTier};
    let tier = crypto_tier(cohort_scope, None);
    if matches!(tier, CryptoTier::Plaintext) {
        return Ok(());
    }
    match body_is_sealed(body) {
        BodySealState::Sealed => Ok(()),
        BodySealState::Plaintext => Err(crate::federation::BlobError::InvalidArgument(format!(
            "cohort_scope {cohort_scope:?} resolves to {tier:?}, which is encrypted at rest, \
             but the body carries no at-rest envelope magic — it is plaintext. Seal it first \
             (the cascade for this tier), then store: a plaintext shard that reaches a peer \
             cannot be recalled by any later rotation (BLOB_ENCRYPTION_AT_REST.md §10.8)"
        ))),
        BodySealState::Unverifiable { why } => {
            Err(crate::federation::BlobError::InvalidArgument(format!(
                "cohort_scope {cohort_scope:?} resolves to {tier:?}, which is encrypted at \
                 rest, and persist cannot verify this body is sealed: {why}. Refusing rather \
                 than asserting a property it cannot check"
            )))
        }
    }
}

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
///
/// #831 — a seal made with associated data ([`seal_aad`]) has the SAME
/// layout: the data is authenticated by the tag and is not on disk. Nothing
/// in the envelope says whether data was bound; the reader either presents
/// it or the open fails.
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

/// The AES-256-GCM authentication tag appended to every envelope's
/// ciphertext (`ciris_crypto::aes_gcm::encrypt` returns `ct ‖ tag`).
pub const AES_GCM_TAG_LEN: usize = 16;

/// #832 (`BLOB_ENCRYPTION_AT_REST.md` §12.1) — bytes an [`AtRestEnvelope`]
/// adds over its plaintext: `magic[8] ‖ nonce[12] ‖ … ‖ tag[16]`. The one
/// constant the chunk floor uses to refuse a chunk row whose declared
/// plaintext size contradicts its stored body (§12.3).
pub const AT_REST_ENVELOPE_OVERHEAD: usize =
    AT_REST_ENVELOPE_MAGIC.len() + NONCE_LEN + AES_GCM_TAG_LEN;

/// The plaintext length an envelope of `stored_len` bytes carries, or
/// `None` if `stored_len` is shorter than the envelope overhead (not an
/// envelope at all).
#[must_use]
pub fn sealed_plaintext_len(stored_len: u64) -> Option<u64> {
    stored_len.checked_sub(AT_REST_ENVELOPE_OVERHEAD as u64)
}

/// AES-256-GCM-encrypt `plaintext` under `dek` with a fresh random
/// nonce, returning the self-describing [`AtRestEnvelope`].
///
/// `aad` — caller-supplied associated data (#831, §11.2 (7)), folded into
/// the GCM tag by [`seal_aad`] and never stored: the envelope opens only for
/// a reader presenting the same bytes to [`open`]. `None` is the AAD-empty
/// seal, byte-identical to every row sealed before #831. I40 pins the
/// binding. Crypto routes through `ciris_crypto` only — this must NOT reach
/// for `ring` directly.
pub fn seal(
    dek: &[u8; DEK_LEN],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<AtRestEnvelope, AtRestError> {
    seal_aad(dek, aad, plaintext)
}

/// AES-256-GCM-decrypt an [`AtRestEnvelope`] under `dek`, returning the
/// plaintext blob body. GCM auth-tag failure is an
/// [`AtRestError::Crypto`].
///
/// `aad` — the associated data the envelope was sealed under (#831); the
/// same bytes or the open fails. `None` for a seal made without any.
pub fn open(
    dek: &[u8; DEK_LEN],
    envelope: &AtRestEnvelope,
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, AtRestError> {
    open_aad(dek, aad, envelope)
}

/// §11.2 (7) / §11.3 (5) / I40 — **associated data at a plaintext tier is
/// refused, never dropped.** One check for every seal and open door
/// (whole-blob, chunk write, stream seal, range read): a caller that passes
/// data against a row that is not sealed would otherwise believe in a
/// binding that does not exist — the hazard the parameter exists to
/// prevent. (Ultrareview of v44: the chunk doors had skipped it.)
pub(crate) fn refuse_aad_at_plaintext(
    sha256: &[u8; 32],
    aad: Option<&[u8]>,
) -> Result<(), crate::federation::BlobError> {
    if aad.is_some() {
        return Err(crate::federation::BlobError::InvalidArgument(format!(
            "blob {} is at the plaintext tier; associated data has nothing to bind to — a \
             plaintext row is not sealed",
            hex::encode(sha256)
        )));
    }
    Ok(())
}

/// [`seal`] with **associated data** (#831, `BLOB_ENCRYPTION_AT_REST.md`
/// §11.2 (7)).
///
/// When `aad` is present it is folded into the AES-256-GCM tag through
/// `ciris_crypto::aes_gcm::encrypt_aad`, so the envelope opens only for a
/// reader presenting the same bytes to [`open_aad`]. The data is NOT part of
/// the envelope and is never stored — that is the point: the caller binds
/// the ciphertext to something it holds elsewhere (a referencing row's
/// author and signed instant), and a ciphertext lifted onto another row
/// does not open there. `None` is exactly [`seal`]: the on-disk format is
/// unchanged and an AAD-less seal stays byte-compatible with every existing
/// row. (`Some(b"")` is equivalent to `None` — the verify crate pins
/// `encrypt_aad(.., b"", ..)` byte-identical to `encrypt`.)
pub fn seal_aad(
    dek: &[u8; DEK_LEN],
    aad: Option<&[u8]>,
    plaintext: &[u8],
) -> Result<AtRestEnvelope, AtRestError> {
    let nv = ciris_crypto::random::bytes(NONCE_LEN)
        .map_err(|e| AtRestError::Crypto(format!("random nonce: {e}")))?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nv);
    let Some(aad) = aad else {
        // No associated data: the AAD-empty primitive, byte-identical to
        // `encrypt_aad(.., b"", ..)` (pinned by the verify crate).
        let ciphertext = ciris_crypto::aes_gcm::encrypt(dek, &nonce, plaintext)
            .map_err(|e| AtRestError::Crypto(format!("aes-gcm seal: {e}")))?;
        return Ok(AtRestEnvelope { nonce, ciphertext });
    };
    let ciphertext = ciris_crypto::aes_gcm::encrypt_aad(dek, &nonce, aad, plaintext)
        .map_err(|e| AtRestError::Crypto(format!("aes-gcm seal under associated data: {e}")))?;
    Ok(AtRestEnvelope { nonce, ciphertext })
}

/// [`open`] with **associated data** (#831, §11.3 (5)): the reader's `aad`
/// must be the bytes the seal was bound to, or the tag does not verify.
/// `None` is exactly [`open`] — which is also why a seal bound to data does
/// not open for a reader presenting none, and an AAD-less seal does not open
/// for a reader presenting some: the two entry points refuse each other's
/// ciphertext by construction (asserted in the verify crate).
///
/// A wrong AAD is indistinguishable from a tampered body, and this does not
/// try to distinguish them: the [`AtRestError::Crypto`] says the bytes did
/// not belong to the row they arrived on, and names neither the data nor
/// what it bound.
pub fn open_aad(
    dek: &[u8; DEK_LEN],
    aad: Option<&[u8]>,
    envelope: &AtRestEnvelope,
) -> Result<Vec<u8>, AtRestError> {
    let Some(aad) = aad else {
        return ciris_crypto::aes_gcm::decrypt(dek, &envelope.nonce, &envelope.ciphertext)
            .map_err(|e| AtRestError::Crypto(format!("aes-gcm open: {e}")));
    };
    ciris_crypto::aes_gcm::decrypt_aad(dek, &envelope.nonce, aad, &envelope.ciphertext).map_err(
        |e| {
            AtRestError::Crypto(format!(
                "aes-gcm open under associated data refused ({e}): the viewer was authorized, \
                 but the bytes did not belong to the row they arrived on — the body was altered, \
                 or it was not sealed under the data this reader presented"
            ))
        },
    )
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
///
/// # The `"algorithm"` label and CC 5.1 (CIRISPersist#582)
///
/// This envelope's `"algorithm"` field is the ONE place persist writes
/// `ciris_crypto::key_grant::KEY_GRANT_ALGORITHM_V2` into durable bytes: the
/// envelope is stored verbatim as `federation_blob_key_grants.wrapped_dek`
/// (and the community-DEK member-grant column). Verify's v11.1.0 re-spelling
/// therefore means grants written before that pin carry the hyphenated,
/// now-non-conformant form at rest.
///
/// Those rows are **not** in scope for
/// [`crate::maintenance::vocabulary`]'s supersede sweep, and deliberately so:
/// they are unsigned substrate state, not attestations, so there is no
/// signature to desync and no `supersedes` chain to hang a retirement on — and
/// the label is descriptive metadata about an AEAD ciphertext that persist's
/// own unwrap path never reads (`unwrap_dek_v2_json` consumes only the four
/// `*_b64` fields). Re-labelling a stored wrap would change bytes nobody
/// verifies to satisfy a rule nobody applies here.
///
/// A CONSUMER that does compare the stored label must use verify's sanctioned
/// `key_grant_algorithm_v2_accepts(candidate, accept_legacy_hyphenated =
/// true)` while draining pre-v11.1.0 wraps — the escape hatch CC 5.1 supplies
/// for exactly this — and MUST NOT normalize the separator, which would make
/// the two identifiers compare equal and defeat the rule. The permanent fix on
/// that plane is a re-wrap (a fresh DEK cascade), not a relabel.
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
    ///
    /// `aad` (#831) is bound into the seal through [`seal_aad`] and never
    /// stored; a reader must present the same bytes to
    /// [`read_any_for_viewer`].
    pub async fn encrypt_and_cascade<B>(
        backend: &B,
        cohort_scope: &str,
        owner_or_family_key_id: &str,
        plaintext: &[u8],
        media_type: Option<&str>,
        aad: Option<&[u8]>,
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
        let envelope = seal(&dek, plaintext, aad).map_err(map_at_rest_err)?;
        let envelope_bytes = envelope.to_bytes();
        let at_rest_sha256: [u8; 32] = Sha256::digest(&envelope_bytes).into();

        // 2. Store the ciphertext, structurally invisible (no holds_bytes;
        //    suppresses_holds_bytes is true for self/family).
        backend
            .store_blob_local(
                &at_rest_sha256,
                BlobBody::Inline(envelope_bytes),
                media_type,
                cohort_scope,
                crate::federation::StorageFloor::resolved(
                    crate::federation::types::cohort_scope::CryptoTier::InvisibleEncrypted,
                ),
            )
            .await?;

        // 3 + 4. Self-retention + recipient fan-out (shared with the chunk
        //        cascade, §12.3: a chunk row gets exactly these grants).
        let (granted, excluded) = grant_dek_to_cohort(
            backend,
            &at_rest_sha256,
            cohort_scope,
            owner_or_family_key_id,
            &dek,
        )
        .await?;

        Ok(CascadeResult {
            at_rest_sha256,
            granted,
            excluded,
        })
    }

    /// The grant half of the self/family cascade: persist's content-master
    /// self-retention wrap for `at_rest_sha256`, then a v2 wrap of `dek` to
    /// every active recipient occurrence whose keys are usable, fail-secure
    /// excluding the rest. Returns `(granted, excluded)`.
    ///
    /// #832 (§12.3) — factored out so a sealed CHUNK row and a sealed
    /// MANIFEST row receive precisely the grants a whole blob does, from the
    /// same code. Crate-private: the caller must already have stored the
    /// row through the floor under the `InvisibleEncrypted` tier.
    pub(crate) async fn grant_dek_to_cohort<B>(
        backend: &B,
        at_rest_sha256: &[u8; 32],
        cohort_scope: &str,
        owner_or_family_key_id: &str,
        dek: &[u8; DEK_LEN],
    ) -> Result<(Vec<String>, Vec<String>), BlobError>
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        // persist self-retention: wrap the DEK under the content master so
        // the read door can recover it in the default tier.
        let content_master = backend.load_or_init_content_master().await?;
        let self_wrap = wrap_dek_for_persist(&content_master, dek).map_err(map_at_rest_err)?;
        backend
            .put_at_rest_grant(
                at_rest_sha256,
                PERSIST_SELF_RECIPIENT,
                WRAP_ALGORITHM_CONTENT_MASTER,
                &self_wrap,
                cohort_scope,
            )
            .await?;

        // Recipient cascade — wrap the DEK to each active recipient whose
        // occurrence carries valid encryption_pubkeys; fail-secure exclude
        // the rest (no plaintext / v1 fallback).
        let recipients = resolve_recipients(backend, cohort_scope, owner_or_family_key_id).await?;
        let v2_algo = WRAP_ALGORITHM_V2;
        let mut granted = Vec::new();
        let mut excluded = Vec::new();
        for (occ_key_id, keys) in recipients {
            match usable_keys(&keys) {
                Some(k) => {
                    let wrapped = wrap_dek_v2(&k.x25519_base64, &k.ml_kem_768_base64, dek)
                        .map_err(map_at_rest_err)?;
                    backend
                        .put_at_rest_grant(
                            at_rest_sha256,
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
        Ok((granted, excluded))
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
    /// caller's responsibility (this runs *after* the roster admits the
    /// member — the roster already names them).
    ///
    /// # v31.0.0 (CIRISPersist#654) — the doc above is TRUE again
    ///
    /// It was written for the original contract and then quietly falsified in
    /// v6.2.0, when this driver started calling `add_family_member` itself. That
    /// call was the whole of #654's exploit surface: this driver holds NO key
    /// material — that is its point — so it could not produce, and cannot relay,
    /// an authority signature over a roster it grows with a `joined_at` it mints
    /// itself. Growing a roster from inside a key-less cascade orchestrator is
    /// not a thing that can be made safe; it is a thing that has to stop.
    ///
    /// So the roster grow moved back OUT, to the caller, which reaches it
    /// through the now-gated
    /// [`add_family_member`](crate::federation::FederationDirectory::add_family_member)
    /// / [`supersede_family`](crate::federation::FederationDirectory::supersede_family)
    /// with a real signature, and this driver REFUSES a newcomer the roster
    /// does not already name.
    ///
    /// The membership test is the **revocation-folded ACTIVE** roster, not the
    /// raw `members[]`. Under the old shape a removed member could be handed
    /// back every past family blob simply by re-running the driver — it would
    /// re-add them to the roster and then re-key them — which is a
    /// forward-secrecy hole in the one direction forward secrecy is supposed to
    /// be automatic for the family tier.
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

        // v31.0.0 (CIRISPersist#654) — THE ROSTER PRECONDITION, replacing the
        // v6.2.0 unauthenticated `add_family_member` call this driver used to
        // make. The newcomer must already be an ACTIVE member; see the doc
        // comment for why a key-less cascade orchestrator must not be the thing
        // that grows a roster, and why the test is the revocation-folded roster
        // rather than the raw one.
        let active = backend
            .active_family_members(family_key_id)
            .await
            .map_err(map_dir_err)?;
        if !active
            .iter()
            .any(|m| m.key_id == new_member_identity_key_id)
        {
            return Err(BlobError::InvalidArgument(format!(
                "rekey_family_member_add: {new_member_identity_key_id:?} is not an active member \
                 of family {family_key_id:?}. The roster grow is the caller's, through the signed \
                 add_family_member / supersede_family door — this driver holds no key material and \
                 cannot authorize a membership change (CIRISPersist#654). Re-keying a member the \
                 roster does not name would also hand every past family blob to someone whose \
                 membership was revoked."
            )));
        }

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
    ///
    /// v21.0.0 (CIRISPersist#502 E4) — `authority_key_id` /
    /// `scrub_signature_classical` / `scrub_signature_pqc` are the caller's
    /// authority signature over the removal; `put_community_membership_revocation`
    /// hybrid-Strict-verifies them before any write (including the epoch bump
    /// below) — closing the exact hole this function's own doc names: an
    /// unauthenticated caller of this cascade could otherwise force a DEK
    /// rotation (forward-secrecy DoS) with no proof of authority at all.
    #[allow(clippy::too_many_arguments)]
    pub async fn rekey_community_member_revoke<B>(
        backend: &B,
        community_key_id: &str,
        removed_identity_key_id: &str,
        observed_at: chrono::DateTime<chrono::Utc>,
        authority_key_id: &str,
        scrub_signature_classical: &str,
        scrub_signature_pqc: Option<&str>,
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
                    authority_key_id: authority_key_id.to_string(),
                    scrub_signature_classical: scrub_signature_classical.to_string(),
                    scrub_signature_pqc: scrub_signature_pqc.map(str::to_string),
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
    /// #833 (§11.5, I31) — **the refusal for a sha with no row**, shared by
    /// every read door (whole-blob, range, and a DAG's covering chunk —
    /// ultrareview of v44 found the range door saying "never ours" where the
    /// whole-blob door says "swept"). Swept, or never ours? The epoch binding
    /// — which the retention sweep KEEPS, stamped — knows; but it is told only
    /// to a viewer who could have read the blob. So: AUTHORIZE FIRST, on the
    /// binding's (community, epoch), the same order as a live community blob
    /// (§11.3). A stranger gets `NotGranted`, naming neither (I4b). Returns
    /// `Ok(err)`: the refusal to hand back, or a backend error while deciding.
    pub(crate) async fn refuse_missing_row<B>(
        backend: &B,
        at_rest_sha256: &[u8; 32],
        viewer_key_id: &str,
    ) -> Result<BlobError, BlobError>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let not_held = BlobError::NotHeld {
            sha256_hex: hex::encode(at_rest_sha256),
        };
        let Some(binding) = backend.community_dek_blob_binding(at_rest_sha256).await? else {
            return Ok(not_held);
        };
        if !crate::federation::community_dek::orchestrate::may_learn_epoch_fate(
            backend,
            &binding.community_key_id,
            binding.epoch,
            viewer_key_id,
        )
        .await?
        {
            return Ok(BlobError::NotGranted {
                sha256_hex: hex::encode(at_rest_sha256),
                viewer_key_id: viewer_key_id.to_owned(),
            });
        }
        Ok(match binding.evicted_at {
            Some(evicted_at) => BlobError::Evicted {
                sha256_hex: hex::encode(at_rest_sha256),
                community_key_id: binding.community_key_id,
                epoch: binding.epoch,
                evicted_at,
            },
            // A live binding with no row is the state I19 forbids:
            // reported as absent, never as swept.
            None => not_held,
        })
    }

    /// v43.0.0 (`FSD/BLOB_ENCRYPTION_AT_REST.md` §10) — **read any blob as a
    /// viewer, without the caller knowing how it was stored.**
    ///
    /// This is the door a server or an agent should use. It takes a content
    /// address and a viewer, and returns plaintext. The caller does **not**
    /// need to know the cohort, whether the blob is encrypted, which DEK
    /// sealed it, which epoch it belongs to, or whether a grant exists — the
    /// substrate knows all of that and answers the only question the caller
    /// actually has: *give me the bytes, as me.*
    ///
    /// MISSION §1.4's "substrate absorbs complexity" applied to reads. A
    /// consumer that has to branch on cohort before reading is a consumer
    /// that will eventually branch WRONG — and the wrong branch on this
    /// surface is either a failed read or, worse, a caller reaching for the
    /// raw-bytes accessor and getting ciphertext it then treats as content.
    ///
    /// # How the path is determined — from the data, never from the caller
    ///
    /// 1. **Community binding present?** (`community_dek_blob_epoch`) → the
    ///    community path, authorized by the viewer's grant on the blob's own
    ///    epoch.
    /// 2. **Stored bytes carry [`AT_REST_ENVELOPE_MAGIC`]?** → the
    ///    self/family path, authorized by the viewer's at-rest grant.
    /// 3. **Otherwise** → a commons/plaintext blob; the bytes are returned
    ///    as stored.
    ///
    /// The three cases are mutually exclusive and exhaustive by
    /// construction: a sealed blob is either community-bound or it is not,
    /// and an unsealed blob carries no magic. There is no fallthrough where
    /// ciphertext could be returned as though it were content.
    ///
    /// # Errors
    ///
    /// Propagated from the path taken — [`BlobError::NotHeld`] if absent,
    /// [`BlobError::NotGranted`] if the viewer holds no grant, the
    /// destroyed-epoch refusal if the key material is gone, and
    /// [`BlobError::Evicted`] (#833, I31) if the retention sweep deleted the
    /// local copy — told only to a viewer the binding authorizes. Each says
    /// which of those it is; none of them is silently an empty read.
    ///
    /// `aad` (#831, §11.3 (5)) — the associated data the seal was bound to,
    /// if any. The same bytes, or the open fails AFTER authorization as a
    /// crypto-class [`BlobError::Backend`], never `NotGranted`: the viewer
    /// was authorized; the bytes did not belong to the row they arrived on.
    /// A non-grantee presenting the right data is still `NotGranted` and
    /// learns nothing. `Some(aad)` against a plaintext row is refused
    /// (`InvalidArgument`), as at the write door.
    pub async fn read_any_for_viewer<B>(
        backend: &B,
        at_rest_sha256: &[u8; 32],
        viewer_key_id: &str,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, BlobError>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::types::cohort_scope::CryptoTier;
        let not_held = || BlobError::NotHeld {
            sha256_hex: hex::encode(at_rest_sha256),
        };

        // 1. The ROW says what this is. (§11.1) The tier is the one the
        //    WRITE DOOR RESOLVED and recorded — never re-derived here from
        //    the scope, which would drop the directory axis (the infra
        //    carve-out) the door applied (I15).

        // 1. The ROW says what this is. (§11.1) The tier is the one the
        //    WRITE DOOR RESOLVED and recorded — never re-derived here from
        //    the scope, which would drop the directory axis (the infra
        //    carve-out) the door applied (I15). #832: the HEAD, so the
        //    dispatch below also knows whether this row is a chunk DAG —
        //    from a column, not from bytes.
        let Some(head) = backend.blob_head(at_rest_sha256).await? else {
            return Err(refuse_missing_row(backend, at_rest_sha256, viewer_key_id).await?);
        };
        let tier = head.crypto_tier;

        // 2. AUTHORIZE BY TIER, BEFORE TOUCHING THE BODY. (§11.3) The
        //    decision lives above the dispatch so a new tier cannot skip it.
        //    A refusal names only the sha and the viewer.
        authorize_viewer_by_tier(backend, at_rest_sha256, tier, viewer_key_id).await?;
        // §11.3 (5) / I40 — associated data presented against a row that was
        // never sealed: refused, as at the write door (after authorization,
        // so a stranger learns nothing from the refusal class).
        if tier == CryptoTier::Plaintext && aad.is_some() {
            return Err(BlobError::InvalidArgument(format!(
                "blob {} is recorded at the plaintext tier; associated data has nothing \
                 to bind to — a plaintext row is not sealed",
                hex::encode(at_rest_sha256)
            )));
        }

        // #832 (§12.4 / I35) — a chunk DAG is its CONTENT, concatenated, under
        // the whole-read cap; a sealed one opens the manifest and every chunk
        // under this viewer's authorization. The row's storage_kind decides,
        // never the bytes.
        if head.storage_kind == "chunk_dag" {
            return crate::federation::chunk_dag_cascade::orchestrate::read_dag_for_viewer_authorized(
                backend,
                at_rest_sha256,
                &head,
                viewer_key_id,
                None,
                aad,
            )
            .await;
        }

        // 3. Now — and only now — the body, once. An encrypted tier whose
        //    body does not parse as an envelope is corruption, never a
        //    plaintext return. (§11.3)
        let body = backend
            .get_blob(at_rest_sha256)
            .await?
            .ok_or_else(not_held)?;
        let bytes = match body {
            BlobBody::Inline(b) => b,
            BlobBody::External(_) => {
                return Err(BlobError::InvalidArgument(format!(
                    "blob {} is an External reference; persist does not dereference it — \
                     use get_blob to obtain the ref",
                    hex::encode(at_rest_sha256)
                )))
            }
            BlobBody::ChunkDag(_) => {
                return Err(BlobError::Backend(format!(
                    "blob {} read back as a chunk DAG but its row head did not say so",
                    hex::encode(at_rest_sha256)
                )))
            }
        };
        match tier {
            CryptoTier::Plaintext => Ok(bytes),
            CryptoTier::InvisibleEncrypted => {
                let envelope = AtRestEnvelope::from_bytes(&bytes).map_err(|e| {
                    BlobError::Backend(format!(
                        "blob {} is recorded at tier {tier:?} but its body is not an at-rest \
                         envelope ({e}) — corruption, not plaintext",
                        hex::encode(at_rest_sha256)
                    ))
                })?;
                read_for_viewer_sealed(backend, at_rest_sha256, &envelope, aad).await
            }
            CryptoTier::CommunityDek => {
                let envelope = AtRestEnvelope::from_bytes(&bytes).map_err(|e| {
                    BlobError::Backend(format!(
                        "blob {} is recorded at tier {tier:?} but its body is not an at-rest \
                         envelope ({e}) — corruption, not plaintext",
                        hex::encode(at_rest_sha256)
                    ))
                })?;
                crate::federation::community_dek::orchestrate::read_for_community_viewer_sealed(
                    backend,
                    at_rest_sha256,
                    viewer_key_id,
                    &envelope,
                    aad,
                )
                .await
            }
        }
    }

    /// §11.3 step 2 — **authorize `viewer_key_id` on a row by its recorded
    /// tier, before any body is touched.** Shared by the whole read, the
    /// range read (#832) and the per-chunk checks, so one predicate decides
    /// every read. A refusal names only the sha and the viewer (I4).
    pub(crate) async fn authorize_viewer_by_tier<B>(
        backend: &B,
        at_rest_sha256: &[u8; 32],
        tier: crate::federation::types::cohort_scope::CryptoTier,
        viewer_key_id: &str,
    ) -> Result<(), BlobError>
    where
        B: BlobStorage + Sync,
    {
        use crate::federation::types::cohort_scope::CryptoTier;
        let not_granted = || BlobError::NotGranted {
            sha256_hex: hex::encode(at_rest_sha256),
            viewer_key_id: viewer_key_id.to_owned(),
        };
        match tier {
            // Commons is public by construction. NOTE: on a relaying node the
            // row is commons-tier and the bytes it holds may be another
            // cohort's ciphertext — returned as held, which is the transfer
            // model (§10.6): a relay carries what it cannot read.
            CryptoTier::Plaintext => Ok(()),
            CryptoTier::InvisibleEncrypted => {
                if backend
                    .get_at_rest_grant(at_rest_sha256, viewer_key_id)
                    .await?
                    .is_none()
                {
                    return Err(not_granted());
                }
                Ok(())
            }
            CryptoTier::CommunityDek => {
                let Some((community, epoch)) =
                    backend.community_dek_blob_epoch(at_rest_sha256).await?
                else {
                    // A community-tier row with no binding is corruption,
                    // not a public blob.
                    return Err(BlobError::Backend(format!(
                        "blob {} is recorded at tier {tier:?} but carries no community-DEK binding",
                        hex::encode(at_rest_sha256)
                    )));
                };
                if !backend
                    .community_dek_has_member_grant(&community, epoch, viewer_key_id)
                    .await?
                {
                    return Err(not_granted());
                }
                Ok(())
            }
        }
    }

    /// v43.0.0 (`BLOB_ENCRYPTION_AT_REST.md` §11.2) — **THE write door**, as
    /// a free function so the Engine and the PyO3 surface share one body
    /// rather than two copies that can drift.
    ///
    /// Store `plaintext` at `cohort_scope`. The tier is resolved from the
    /// DIRECTORY ([`resolve_write_tier`](super::resolve_write_tier)); the
    /// caller never supplies it and never supplies sealed bytes:
    /// - **Plaintext** (commons, or an AUTHORIZED infrastructure community —
    ///   CC 4.4.3.2.1) → stored as given, `holds_bytes` announced, row
    ///   records the scope;
    /// - **InvisibleEncrypted** (`self` / `family`) → the self/family cascade:
    ///   fresh DEK, wrapped to every active occurrence, no `holds_bytes`. The
    ///   owner (self) or family key rides in `community_key_id`'s slot;
    /// - **CommunityDek** → the community cascade under the current epoch
    ///   DEK, wrapped to every active member, AND `holds_bytes` announced for
    ///   the SEALED bytes — community content federates with cleartext
    ///   provenance, and the cascade alone never emitted the announcement it
    ///   documented as the caller's job.
    ///
    /// There is no other consumer-reachable write that accepts an encrypted
    /// cohort. The commons doors record `federation` by construction and
    /// cannot be pointed at a private cohort. That is what makes §11.10 I1
    /// true rather than checked.
    ///
    /// `aad` (#831, §11.2 (7)) — caller-supplied associated data, bound into
    /// the seal at both encrypted tiers and NEVER stored; the reader presents
    /// the same bytes to [`read_any_for_viewer`] or the open fails. What it
    /// binds is whatever the caller holds beside the blob — a chat row's
    /// author, signed instant and epoch — so a ciphertext lifted onto another
    /// row does not open there. `Some(aad)` at a plaintext tier is refused
    /// (`InvalidArgument`): nothing to bind it to, and dropping it would leave
    /// the caller believing in a binding that does not exist.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_blob_scoped<B>(
        backend: &B,
        signer: &dyn ciris_keyring::HardwareSigner,
        cohort_scope: &str,
        community_key_id: Option<&str>,
        plaintext: &[u8],
        media_type: Option<&str>,
        aad: Option<&[u8]>,
    ) -> Result<crate::federation::PutBlobScopedResult, BlobError>
    where
        B: BlobStorage + crate::federation::FederationDirectory + Sync,
    {
        use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community_scoped;
        use crate::federation::types::cohort_scope::CryptoTier;
        use crate::federation::PutBlobScopedResult;
        use sha2::Digest as _;

        let now = chrono::Utc::now();
        // §11.2 (6) / I23 — the attesting key id has exactly one correct
        // value per signer; derive it, never accept it.
        let signer_key_id = crate::signing::federation_key_id_of(signer)
            .await
            .map_err(|e| BlobError::Backend(format!("put_blob_scoped: signer key id: {e}")))?;
        let signer_key_id = signer_key_id.as_str();
        let tier = super::resolve_write_tier(backend, cohort_scope, community_key_id).await?;
        match tier {
            CryptoTier::Plaintext => {
                // §11.2 (7) / I40 — nothing here is sealed, so nothing can
                // be bound. Refuse rather than drop: a caller that supplied
                // data believes in a binding, and must not be left believing.
                if aad.is_some() {
                    return Err(BlobError::InvalidArgument(format!(
                        "cohort_scope {cohort_scope:?} resolves to the plaintext tier; associated \
                         data has nothing to bind to — a plaintext row is not sealed"
                    )));
                }
                let sha: [u8; 32] = sha2::Sha256::digest(plaintext).into();
                backend
                    .put_blob_signing_at(
                        cohort_scope,
                        crate::federation::StorageFloor::resolved(CryptoTier::Plaintext),
                        &sha,
                        BlobBody::Inline(plaintext.to_vec()),
                        media_type,
                        signer_key_id,
                        signer,
                        now,
                        uuid::Uuid::new_v4(),
                    )
                    .await?;
                Ok(PutBlobScopedResult {
                    at_rest_sha256: sha,
                    tier,
                    epoch: None,
                    granted: Vec::new(),
                    excluded: Vec::new(),
                })
            }
            CryptoTier::InvisibleEncrypted => {
                let owner = community_key_id.ok_or_else(|| {
                    BlobError::InvalidArgument(format!(
                        "cohort_scope {cohort_scope:?} requires the owner (self) or family key id \
                         in the community_key_id argument"
                    ))
                })?;
                // §11.2 (5) / I21 — the matcher sees the PLAINTEXT, before sealing.
                let plain_sha: [u8; 32] = sha2::Sha256::digest(plaintext).into();
                backend.screen_inline_body(&plain_sha, plaintext).await?;
                let r =
                    encrypt_and_cascade(backend, cohort_scope, owner, plaintext, media_type, aad)
                        .await?;
                Ok(PutBlobScopedResult {
                    at_rest_sha256: r.at_rest_sha256,
                    tier,
                    epoch: None,
                    granted: r.granted,
                    excluded: r.excluded,
                })
            }
            CryptoTier::CommunityDek => {
                let comm = community_key_id.ok_or_else(|| {
                    BlobError::InvalidArgument("community_key_id required".into())
                })?;
                // §11.2 (5) / I21 — screened as plaintext, once; the announce below
                // carries a sealed-tier token so the floor does not screen the envelope.
                let plain_sha: [u8; 32] = sha2::Sha256::digest(plaintext).into();
                backend.screen_inline_body(&plain_sha, plaintext).await?;
                let r = encrypt_and_cascade_community_scoped(
                    backend,
                    cohort_scope,
                    comm,
                    plaintext,
                    media_type,
                    aad,
                )
                .await?;
                // ANNOUNCE the sealed bytes: community content federates with
                // cleartext provenance.
                let Some(BlobBody::Inline(sealed)) = backend.get_blob(&r.at_rest_sha256).await?
                else {
                    return Err(BlobError::Backend(
                        "community cascade stored no inline body".into(),
                    ));
                };
                backend
                    .put_blob_signing_at(
                        cohort_scope,
                        crate::federation::StorageFloor::resolved(CryptoTier::CommunityDek),
                        &r.at_rest_sha256,
                        BlobBody::Inline(sealed),
                        media_type,
                        signer_key_id,
                        signer,
                        now,
                        uuid::Uuid::new_v4(),
                    )
                    .await?;
                Ok(PutBlobScopedResult {
                    at_rest_sha256: r.at_rest_sha256,
                    tier,
                    epoch: Some(r.epoch),
                    granted: r.granted,
                    excluded: r.excluded,
                })
            }
        }
    }

    /// The decrypt half of [`read_for_viewer`], for a caller that has ALREADY
    /// authorized the viewer and parsed the envelope (the §11.3 read door).
    /// Recovers the DEK through persist's self-retention row.
    pub async fn read_for_viewer_sealed<B>(
        backend: &B,
        at_rest_sha256: &[u8; 32],
        envelope: &AtRestEnvelope,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, BlobError>
    where
        B: BlobStorage + Sync,
    {
        let self_grant = backend
            .get_at_rest_grant(at_rest_sha256, PERSIST_SELF_RECIPIENT)
            .await?
            .ok_or_else(|| {
                BlobError::Backend(format!(
                    "at-rest blob {} has no persist self-retention grant",
                    hex::encode(at_rest_sha256)
                ))
            })?;
        let content_master = backend.load_or_init_content_master().await?;
        let dek =
            unwrap_dek_for_persist(&content_master, &self_grant.1).map_err(map_at_rest_err)?;
        open(&dek, envelope, aad).map_err(map_at_rest_err)
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

        // 4. Decrypt + return plaintext. (#831 — this legacy door carries no AAD.)
        open(&dek, &envelope, None).map_err(map_at_rest_err)
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
        let env = seal(&dek, pt, None).unwrap();
        // The sealed envelope must NOT equal the plaintext.
        assert_ne!(env.to_bytes(), pt.to_vec());
        let back = open(&dek, &env, None).unwrap();
        assert_eq!(back, pt);
        assert_eq!(
            env.to_bytes().len(),
            pt.len() + AT_REST_ENVELOPE_OVERHEAD,
            "the overhead constant IS the envelope's overhead"
        );
        assert_eq!(
            sealed_plaintext_len(env.to_bytes().len() as u64),
            Some(pt.len() as u64)
        );
        assert_eq!(
            sealed_plaintext_len(AT_REST_ENVELOPE_OVERHEAD as u64 - 1),
            None
        );
    }

    #[test]
    fn open_rejects_wrong_dek() {
        let dek = fresh_dek().unwrap();
        let env = seal(&dek, b"secret", None).unwrap();
        let wrong = [0x99u8; DEK_LEN];
        assert!(matches!(
            open(&wrong, &env, None),
            Err(AtRestError::Crypto(_))
        ));
    }

    /// #831 — the twins bind the data and refuse across entry points.
    #[test]
    fn seal_aad_binds_the_data_and_refuses_across_entry_points() {
        let dek = fresh_dek().unwrap();
        let pt = b"alice's message";
        let row_a: &[u8] = b"alice\n2026-09-09T00:00:00.000Z\n1";
        let row_m: &[u8] = b"mallory\n2026-09-09T00:00:01.000Z\n1";
        let env = seal_aad(&dek, Some(row_a), pt).unwrap();
        assert_ne!(env.to_bytes(), pt.to_vec());
        assert!(
            !env.to_bytes().windows(row_a.len()).any(|w| w == row_a),
            "the data is bound, not stored"
        );
        assert_eq!(open_aad(&dek, Some(row_a), &env).unwrap(), pt);
        assert!(matches!(
            open_aad(&dek, Some(row_m), &env),
            Err(AtRestError::Crypto(_))
        ));
        assert!(matches!(
            open_aad(&dek, None, &env),
            Err(AtRestError::Crypto(_))
        ));
        assert!(matches!(
            open(&dek, &env, None),
            Err(AtRestError::Crypto(_))
        ));
        let msg = open_aad(&dek, Some(row_m), &env).unwrap_err().to_string();
        assert!(msg.contains("did not belong to the row"), "{msg}");
        assert!(!msg.contains("alice") && !msg.contains("mallory"), "{msg}");

        // `None` is exactly seal/open; data against an AAD-less seal refuses.
        let plain = seal_aad(&dek, None, pt).unwrap();
        assert_eq!(open(&dek, &plain, None).unwrap(), pt);
        assert_eq!(open_aad(&dek, None, &plain).unwrap(), pt);
        assert!(matches!(
            open_aad(&dek, Some(row_a), &plain),
            Err(AtRestError::Crypto(_))
        ));
        // `Some(b"")` ≡ `None` — verify pins encrypt_aad(.., b"", ..) ≡ encrypt.
        let empty = seal_aad(&dek, Some(b""), pt).unwrap();
        assert_eq!(open(&dek, &empty, None).unwrap(), pt);
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
        // v25.1.0 (#582, CC 5.1 / CIRISVerify#234) — assert against the
        // CONSTANT, not a spelling. The literal used to be pinned here, so the
        // v11.1.0 hyphenated→snake_case re-cut turned an unrelated crypto
        // round-trip test into a red. What this test owns is "the envelope
        // advertises the algorithm the wrap actually used"; which string that
        // is belongs to verify, and CC 5.1 is where it is ratified.
        assert!(json.contains(ciris_crypto::key_grant::KEY_GRANT_ALGORITHM_V2));
        assert!(
            !json.contains(ciris_crypto::key_grant::KEY_GRANT_ALGORITHM_V2_LEGACY_HYPHENATED),
            "the non-conformant hyphenated alias must never be EMITTED: {json}"
        );

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

#[cfg(test)]
mod content_master_root_tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;

    /// v43.0.0 (§10.2) — a `software` row is used verbatim.
    #[test]
    fn software_row_yields_its_own_bytes() {
        let key = [7u8; 32];
        let got = resolve_persisted_content_master("software", Some(&B64.encode(key)))
            .expect("software row resolves");
        assert_eq!(
            got, key,
            "the stored bytes ARE the master; nothing re-derives"
        );
    }

    /// The failure this function exists to make loud.
    ///
    /// A `hardware` row carries no key bytes, so it must re-derive. When the
    /// sealed seed is unreachable the ONLY safe answer is an error: minting a
    /// replacement would report success over a corpus that can no longer be
    /// decrypted — including the content-KEM private halves, which are
    /// themselves sealed under this key.
    ///
    /// Under `cfg(not(feature = "secrets"))` the derivation is structurally
    /// unavailable, so this is exactly the production shape of "seed gone".
    #[test]
    #[cfg(not(feature = "secrets"))]
    fn hardware_row_without_a_reachable_seed_is_a_hard_error_never_a_fallback() {
        let err = resolve_persisted_content_master("hardware", None)
            .expect_err("a hardware row with no reachable seed must NOT resolve");
        let msg = err.to_string();
        assert!(
            msg.contains("hardware-rooted") && msg.contains("unreachable"),
            "error must name the cause, got: {msg}"
        );
        assert!(
            msg.contains("Refusing to mint a replacement"),
            "error must say why it refuses rather than falling back, got: {msg}"
        );
    }

    /// Malformed rows fail rather than defaulting.
    #[test]
    fn malformed_rows_refuse() {
        assert!(resolve_persisted_content_master("software", None).is_err());
        assert!(resolve_persisted_content_master("nonsense", None).is_err());
        // wrong length
        assert!(
            resolve_persisted_content_master("software", Some(&B64.encode([1u8; 16]))).is_err()
        );
        // not base64
        assert!(resolve_persisted_content_master("software", Some("!!!not b64!!!")).is_err());
    }

    /// `ContentMasterSource` must never let a caller record a software master
    /// as hardware: the two carry different payloads by construction, so the
    /// mistake is not expressible rather than merely discouraged.
    #[test]
    fn the_source_variants_cannot_be_confused() {
        match content_master_key(true) {
            // On a host with no TPM (CI, dev) this is the expected arm.
            ContentMasterSource::SoftwareFallback { reason } => {
                assert!(!reason.is_empty(), "a software fallback must say WHY");
            }
            // On a hardware host, the key is present and there is nothing to
            // persist — the row records provenance only.
            ContentMasterSource::Hardware { key, descriptor } => {
                assert_eq!(key.len(), 32);
                assert!(
                    descriptor.contains("context="),
                    "descriptor must name the HKDF context it derived under, got: {descriptor}"
                );
            }
        }
    }
}

/// `FSD/BLOB_ENCRYPTION_AT_REST.md` §11.10 — **the blob-encryption invariants,
/// each falsifiable through a door a consumer holds.**
///
/// Written BEFORE the §11 rebuild and confirmed RED on `fd43e74` (the first
/// implementation, PR #827). Cross-backend by construction: one function per
/// invariant, called from every backend's test module, so a backend that
/// diverges cannot pass by carrying its own copy. Generic rather than `&dyn`
/// because [`BlobStorage`] returns `impl Future`.
///
/// The discipline these encode: **a mutation test proves the function
/// refuses; it says nothing about whether any shipping path calls it.** Every
/// exercise here therefore asserts through the read/write door itself, never
/// by calling a gate function directly.
#[cfg(any(test, feature = "test-anchor"))]
#[allow(dead_code)]
pub mod blob_invariants {
    use crate::federation::blobs::BlobBody;
    use crate::federation::{BlobError, BlobStorage, DekKeyState, FederationDirectory};

    fn sha(bytes: &[u8]) -> [u8; 32] {
        use sha2::Digest as _;
        sha2::Sha256::digest(bytes).into()
    }

    /// A registered node key + its signer, for doors that announce.
    ///
    /// Registers BOTH the alias and the signer's DERIVED key id: since
    /// v9.3.0 (#247) a `holds_bytes` row's `scrub_key_id` is the signer's
    /// derived federation key (`<label>-<fp>`), and the FK on it is what the
    /// first draft of this fixture tripped — an announce that fails at the
    /// FK is a fixture defect, not a door defect, and it would have read as
    /// "the door refuses commons writes" to anyone not looking closely.
    pub async fn node_signer<B>(
        backend: &B,
        key_id: &str,
    ) -> std::sync::Arc<crate::signing::LocalSigner>
    where
        B: FederationDirectory + Sync,
    {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::identity_type::USER;
        ts::register_hybrid_key_as(backend, key_id, key_id, USER).await;
        let signer = ts::local_signer(key_id);
        // The derived id, carrying the alias's real pubkeys (so the emitted
        // signature verifies against the registered key).
        let derived = signer.derived_key_id();
        ts::register_hybrid_key_as(backend, &derived, key_id, USER).await;
        signer
    }

    // ── I2 ───────────────────────────────────────────────────────────────
    /// **Reads dispatch on the ROW, never on the bytes.**
    ///
    /// A COMMONS blob whose bytes happen to begin with the at-rest envelope
    /// magic is still a commons blob: public, returned to anyone. The first
    /// implementation sniffed the magic and routed it down the sealed path,
    /// refusing a public document to every reader.
    pub async fn exercise_i2_reads_dispatch_on_the_row<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::{
            orchestrate::read_any_for_viewer, AT_REST_ENVELOPE_MAGIC,
        };
        let run = uuid::Uuid::new_v4().simple().to_string();
        let node = format!("{tag}-node-{run}");
        let signer = node_signer(backend, &node).await;
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer.clone());

        // A public document that begins with the magic bytes by coincidence.
        let mut body = AT_REST_ENVELOPE_MAGIC.to_vec();
        body.extend_from_slice(b"public doc that merely starts with the marker");
        let id = sha(&body);
        backend
            .put_blob_signing(
                &id,
                BlobBody::Inline(body.clone()),
                None,
                &node,
                &adapter,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .unwrap_or_else(|e| panic!("{tag} I2: a commons write must succeed: {e}"));

        let got = read_any_for_viewer(backend, &id, &format!("{tag}-stranger-{run}"), None)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "{tag} I2: a COMMONS blob is public, but the read door refused it — it \
                     decided the tier from the BYTES (the magic prefix) instead of from the \
                     row: {e}"
                )
            });
        assert_eq!(got, body, "{tag} I2: commons bytes returned verbatim");
    }

    // ── I3 ───────────────────────────────────────────────────────────────
    /// **There is no body-taking write at an encrypted cohort.**
    ///
    /// The substrate seals. A caller cannot hand persist bytes and assert
    /// "these are sealed" — not plaintext, not magic-plus-garbage, not even a
    /// genuine envelope. The first implementation accepted anything with an
    /// 8-byte prefix.
    pub async fn exercise_i3_no_body_taking_write_at_an_encrypted_cohort<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::AT_REST_ENVELOPE_MAGIC;
        use crate::federation::types::cohort_scope::{AFFILIATIONS, COMMUNITY, FAMILY, SELF};
        let run = uuid::Uuid::new_v4().simple().to_string();
        let node = format!("{tag}-node-{run}");
        let signer = node_signer(backend, &node).await;
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer.clone());

        // A real, non-infra community so the refusal is "encrypted tier",
        // not "unknown community".
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        crate::federation::community_dek::lifecycle_support::seed_community(
            backend,
            &comm,
            &[(&alice, &alice_occ)],
        )
        .await;
        let mut spoofed = AT_REST_ENVELOPE_MAGIC.to_vec();
        spoofed.extend_from_slice(b"board minutes in the clear");
        for scope in [SELF, FAMILY, COMMUNITY, AFFILIATIONS] {
            let id = sha(&spoofed);
            let comm_arg = (scope == COMMUNITY || scope == AFFILIATIONS).then_some(comm.as_str());
            let res = backend
                .put_blob_signing_scoped(
                    scope,
                    comm_arg,
                    &id,
                    BlobBody::Inline(spoofed.clone()),
                    None,
                    &node,
                    &adapter,
                    chrono::Utc::now(),
                    uuid::Uuid::new_v4(),
                )
                .await;
            assert!(
                res.is_err(),
                "{tag} I3 [{scope}]: a magic-prefixed plaintext body was ACCEPTED at an \
                 encrypted cohort — the gate tests a marker, not the envelope"
            );
            assert!(
                !backend.has_blob(&id).await.unwrap(),
                "{tag} I3 [{scope}]: refused bytes must not be on disk"
            );
        }
    }

    // ── I4a ──────────────────────────────────────────────────────────────
    /// **Every read door authorizes by tier BEFORE any dispatch.**
    ///
    /// A plaintext body sitting under a private cohort — however it got
    /// there — is never served to a stranger. The first implementation's
    /// cohort-agnostic read returned it: authorization lived inside two of
    /// three branches and the third had none.
    pub async fn exercise_i4a_read_door_authorizes_before_dispatch<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::read_any_for_viewer;
        let run = uuid::Uuid::new_v4().simple().to_string();
        // A private plaintext row, placed through the storage floor as a
        // bypass would leave it. The floor is a FIXTURE here; I14 pins that
        // production code never reaches it outside the cascades.
        let body = b"self journal entry, in the clear".to_vec();
        let id = sha(&body);
        super::blob_invariants_fixture::place_private_plaintext(backend, &id, body.clone()).await;

        let res = read_any_for_viewer(backend, &id, &format!("{tag}-stranger-{run}"), None).await;
        match res {
            Ok(bytes) if bytes == body => panic!(
                "{tag} I4a: the read door returned a PRIVATE plaintext blob to a stranger — \
                 authorization is per-branch, not per-door"
            ),
            Ok(_) => panic!("{tag} I4a: returned bytes to a stranger at all"),
            Err(BlobError::NotGranted { .. }) => {}
            Err(other) => panic!("{tag} I4a: expected NotGranted, got {other:?}"),
        }
    }

    // ── I4b ──────────────────────────────────────────────────────────────
    /// **A refusal names only the sha and the viewer.**
    ///
    /// A non-grantee asking about a community blob must not learn which
    /// community it belongs to, or which epoch. The first implementation
    /// checked epoch destruction BEFORE the grant and named both in the
    /// error. (The destroyed-with-binding state that exercise originally
    /// constructed is now unrepresentable — I6 made bind and destroy
    /// mutually exclusive by statement — so this asserts the property on a
    /// live blob, where the refusal path is the ordinary one.)
    pub async fn exercise_i4b_refusal_does_not_name_the_binding<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::read_any_for_viewer;
        use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        crate::federation::community_dek::lifecycle_support::seed_community(
            backend,
            &comm,
            &[(&alice, &alice_occ)],
        )
        .await;
        let sealed = encrypt_and_cascade_community(backend, &comm, b"minutes", None)
            .await
            .unwrap();

        let err = read_any_for_viewer(
            backend,
            &sealed.at_rest_sha256,
            &format!("{tag}-stranger-{run}"),
            None,
        )
        .await
        .expect_err("a stranger must be refused");
        assert!(
            matches!(err, BlobError::NotGranted { .. }),
            "{tag} I4b: expected NotGranted, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            !msg.contains(&comm) && !msg.contains("epoch"),
            "{tag} I4b: the refusal to a NON-GRANTEE disclosed the binding: {msg}"
        );
    }

    // ── I5 ───────────────────────────────────────────────────────────────
    /// **`destroyed` ⇒ zero persist key material for that epoch.**
    ///
    /// The self-retention wrap and every member grant are gone. A text column
    /// that says "destroyed" while the wraps survive is a read-door refusal,
    /// not destruction — the first implementation shipped exactly that.
    pub async fn exercise_i5_destroy_deletes_key_material<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::community_dek::orchestrate::{
            encrypt_and_cascade_community, set_key_state,
        };
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        crate::federation::community_dek::lifecycle_support::seed_community(
            backend,
            &comm,
            &[(&alice, &alice_occ)],
        )
        .await;
        let sealed = encrypt_and_cascade_community(backend, &comm, b"x", None)
            .await
            .unwrap();
        let epoch = sealed.epoch;
        assert!(
            backend
                .community_dek_get_self_retention(&comm, epoch)
                .await
                .unwrap()
                .is_some(),
            "{tag} I5: precondition — a self-retention wrap exists before destroy"
        );
        assert!(
            !backend
                .community_dek_member_grant_recipients(&comm, epoch)
                .await
                .unwrap()
                .is_empty(),
            "{tag} I5: precondition — member grants exist before destroy"
        );

        // I20 — destroy acts only on an epoch rotation has left behind.
        backend.community_dek_bump_epoch(&comm).await.unwrap();
        let sweeper = node_signer(backend, &format!("{tag}-sweeper-{run}")).await;
        backend
            .community_dek_evict_epoch_objects(&comm, epoch, &sweeper, chrono::Utc::now())
            .await
            .unwrap();
        set_key_state(backend, &comm, epoch, DekKeyState::Destroyed)
            .await
            .unwrap();

        assert!(
            backend
                .community_dek_get_self_retention(&comm, epoch)
                .await
                .unwrap()
                .is_none(),
            "{tag} I5: the self-retention wrap SURVIVED destroy — persist can still recover \
             the DEK, so 'destroyed' is a label, not destruction"
        );
        assert!(
            backend
                .community_dek_member_grant_recipients(&comm, epoch)
                .await
                .unwrap()
                .is_empty(),
            "{tag} I5: member grant rows SURVIVED destroy"
        );
    }

    // ── I6 ───────────────────────────────────────────────────────────────
    /// **Bind requires `enabled`; destroy requires zero bound; both atomic.**
    ///
    /// The falsifier is a blob bound to an epoch that is not enabled. The
    /// first implementation's bind was an unconditional INSERT, so an emission
    /// that read `enabled` and then lost a race with the sweep bound its blob
    /// to a destroyed epoch — permanently unreadable.
    pub async fn exercise_i6_bind_and_destroy_exclude_each_other<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::community_dek::orchestrate::{
            encrypt_and_cascade_community, set_key_state,
        };
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        crate::federation::community_dek::lifecycle_support::seed_community(
            backend,
            &comm,
            &[(&alice, &alice_occ)],
        )
        .await;
        let sealed = encrypt_and_cascade_community(backend, &comm, b"x", None)
            .await
            .unwrap();
        let epoch = sealed.epoch;

        // Destroy with content bound → refused (already pinned elsewhere; kept
        // so this exercise states BOTH halves of the exclusion).
        assert!(
            set_key_state(backend, &comm, epoch, DekKeyState::Destroyed)
                .await
                .is_err(),
            "{tag} I6: destroy with a bound object must refuse"
        );

        // Rotate (I20), empty + destroy, THEN try to bind a late arrival.
        backend.community_dek_bump_epoch(&comm).await.unwrap();
        let sweeper = node_signer(backend, &format!("{tag}-sweeper-{run}")).await;
        backend
            .community_dek_evict_epoch_objects(&comm, epoch, &sweeper, chrono::Utc::now())
            .await
            .unwrap();
        set_key_state(backend, &comm, epoch, DekKeyState::Destroyed)
            .await
            .unwrap();
        let late = sha(b"a blob sealed by a writer that read `enabled` a moment ago");
        let res = backend
            .community_dek_bind_blob_epoch(&late, &comm, epoch)
            .await;
        assert!(
            res.is_err(),
            "{tag} I6: a blob was BOUND to a destroyed epoch — bind is an unconditional \
             insert, so the check/seal/bind race strands content"
        );
        assert_eq!(
            backend
                .community_dek_epoch_object_count(&comm, epoch)
                .await
                .unwrap(),
            0,
            "{tag} I6: nothing may be bound to a destroyed epoch"
        );
    }

    // ── I9 ───────────────────────────────────────────────────────────────
    /// **Eviction of announced content emits `withdraws` before delete.**
    ///
    /// After the sweep evicts a community blob this node announced, this
    /// node is no longer a listed holder. The first implementation deleted
    /// bytes and binding with no signer and no withdraws, so peers kept
    /// routing to a node that answered `NotHeld`.
    pub async fn exercise_i9_eviction_retracts_announcement<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::community_dek::orchestrate::{
            encrypt_and_cascade_community, sweep_rotated_epochs,
        };
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        let node = format!("{tag}-node-{run}");
        crate::federation::community_dek::lifecycle_support::seed_community(
            backend,
            &comm,
            &[(&alice, &alice_occ)],
        )
        .await;
        let signer = node_signer(backend, &node).await;
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer.clone());

        let sealed = encrypt_and_cascade_community(backend, &comm, b"old", None)
            .await
            .unwrap();
        // Announce this node as a holder of the sealed bytes (community
        // content federates with cleartext provenance) — under the node's
        // DERIVED signing key, which is what the production door
        // (`orchestrate::put_blob_scoped`) announces under and what the sweep
        // looks up. An announcement under an arbitrary attesting key is that
        // key's holder's to retract; the sweep cannot sign for it.
        let node_derived = signer.derived_key_id();
        let Some(BlobBody::Inline(bytes)) = backend.get_blob(&sealed.at_rest_sha256).await.unwrap()
        else {
            panic!("{tag} I9: sealed blob is inline");
        };
        backend
            .put_blob_signing_at(
                crate::federation::types::cohort_scope::COMMUNITY,
                crate::federation::StorageFloor::resolved(
                    crate::federation::types::cohort_scope::CryptoTier::CommunityDek,
                ),
                &sealed.at_rest_sha256,
                BlobBody::Inline(bytes),
                None,
                &node_derived,
                &adapter,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .unwrap_or_else(|e| panic!("{tag} I9: announce holds_bytes: {e}"));
        assert!(
            backend
                .list_holders(&sealed.at_rest_sha256)
                .await
                .unwrap()
                .contains(&node_derived),
            "{tag} I9: precondition — this node is a listed holder"
        );

        // Rotate past it and authorize deletion, then sweep.
        backend.community_dek_bump_epoch(&comm).await.unwrap();
        backend
            .community_dek_set_retain_past_epochs(&comm, Some(0))
            .await
            .unwrap();
        let report = sweep_rotated_epochs(backend, &comm, &signer, chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(
            report.evicted_objects, 1,
            "{tag} I9: the old epoch's object is evicted"
        );

        let holders = backend.list_holders(&sealed.at_rest_sha256).await.unwrap();
        assert!(
            !holders.contains(&node_derived),
            "{tag} I9: this node STILL advertises holds_bytes for bytes it no longer holds — \
             eviction deleted without emitting withdraws: holders={holders:?}"
        );
    }

    // ── I10 ──────────────────────────────────────────────────────────────
    /// **A community blob's tier is resolved from the DIRECTORY, including
    /// the CC 4.4.3.2.1 infrastructure carve-out.**
    ///
    /// An AUTHORIZED infrastructure community stores plaintext and announces
    /// `holds_bytes`; a merely-labeled one does not get the carve-out. The
    /// first implementation passed `cohort_subkind = None` to the tier
    /// resolver, so infra content was refused at the write door AND by the
    /// cascade — unstorable by any route.
    pub async fn exercise_i10_infra_carveout_resolved_from_directory<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-infra-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        let node = format!("{tag}-node-{run}");
        crate::federation::community_dek::lifecycle_support::seed_community_with(
            backend,
            &comm,
            &[(&alice, &alice_occ)],
            crate::federation::types::identity_type::SUBSTRATE_PERSIST,
            Some(serde_json::json!({ "cohort_subkind": "infrastructure" })),
        )
        .await;
        let signer = node_signer(backend, &node).await;
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer.clone());

        let body = b"canonical governance root, plaintext by constitution".to_vec();
        let id = sha(&body);
        backend
            .put_blob_signing_scoped(
                crate::federation::types::cohort_scope::COMMUNITY,
                Some(&comm),
                &id,
                BlobBody::Inline(body.clone()),
                None,
                &node,
                &adapter,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "{tag} I10: an AUTHORIZED infrastructure community could not store its \
                     plaintext governance content — the carve-out was dropped at the door: {e}"
                )
            });
        assert!(
            backend.list_holders(&id).await.unwrap().contains(&node),
            "{tag} I10: commons-tier infra content announces holds_bytes"
        );
    }
    // ── I15 ──────────────────────────────────────────────────────────────
    /// **An authorized infrastructure community's write resolves `Plaintext`,
    /// STORES that tier, and reads back through the generic read door.**
    ///
    /// The first rebuild stored only the scope and had reads re-derive the
    /// tier from it — the exact `crypto_tier(scope, None)` call the write
    /// door is forbidden to make. So the infra row was written as plaintext,
    /// classified `CommunityDek` on read, and failed for lack of a binding it
    /// correctly did not have. (C2-1)
    pub async fn exercise_i15_infra_row_reads_back_as_plaintext<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::{
            put_blob_scoped, read_any_for_viewer,
        };
        use crate::federation::types::cohort_scope::CryptoTier;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-infra-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        let node = format!("{tag}-node-{run}");
        crate::federation::community_dek::lifecycle_support::seed_community_with(
            backend,
            &comm,
            &[(&alice, &alice_occ)],
            crate::federation::types::identity_type::SUBSTRATE_PERSIST,
            Some(serde_json::json!({ "cohort_subkind": "infrastructure" })),
        )
        .await;
        let signer = node_signer(backend, &node).await;
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer.clone());

        let body = b"governance root: plaintext by constitution, readable by anyone".to_vec();
        let res = put_blob_scoped(
            backend,
            &adapter,
            crate::federation::types::cohort_scope::COMMUNITY,
            Some(&comm),
            &body,
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I15: infra write through THE door: {e}"));
        assert_eq!(res.tier, CryptoTier::Plaintext, "{tag} I15: resolved tier");
        assert_eq!(
            backend.blob_crypto_tier(&res.at_rest_sha256).await.unwrap(),
            Some(CryptoTier::Plaintext),
            "{tag} I15: the ROW records the RESOLVED tier, not the label's tier"
        );

        let got = read_any_for_viewer(
            backend,
            &res.at_rest_sha256,
            &format!("{tag}-stranger"),
            None,
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "{tag} I15: content written through the infra carve-out is UNREADABLE \
                     through the generic read — the read re-derived the tier from the scope \
                     and discarded the write-time resolution: {e}"
            )
        });
        assert_eq!(got, body, "{tag} I15: plaintext round-trips");
    }

    // ── I17 ──────────────────────────────────────────────────────────────
    /// **Bind requires the CURRENT epoch, not merely an enabled one.**
    ///
    /// After a rotation the old epoch stays `enabled` until a background
    /// sweep disables it. An emission that read the old epoch before the
    /// bump must NOT be able to bind under it: the member the rotation
    /// removed keeps that epoch's wrap (AV-70) and would read content
    /// written after their removal. (C2-2)
    pub async fn exercise_i17_bind_requires_the_current_epoch<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        crate::federation::community_dek::lifecycle_support::seed_community(
            backend,
            &comm,
            &[(&alice, &alice_occ)],
        )
        .await;
        let sealed = encrypt_and_cascade_community(backend, &comm, b"before", None)
            .await
            .unwrap();
        let old = sealed.epoch;
        let new = backend.community_dek_bump_epoch(&comm).await.unwrap();
        assert!(new > old, "{tag} I17: precondition — rotated");
        assert_eq!(
            backend.community_dek_key_state(&comm, old).await.unwrap(),
            Some(DekKeyState::Enabled),
            "{tag} I17: precondition — the rotated-past epoch is STILL enabled (no sweep ran)"
        );

        let late = sha(b"sealed by a writer that read the old epoch a moment before the bump");
        let res = backend
            .community_dek_bind_blob_epoch(&late, &comm, old)
            .await;
        assert!(
            res.is_err(),
            "{tag} I17: a blob was BOUND to a rotated-past epoch — the removed member holds \
             that epoch's wrap and can read content written after their removal"
        );
        assert_eq!(
            backend
                .community_dek_epoch_object_count(&comm, old)
                .await
                .unwrap(),
            1,
            "{tag} I17: the pre-rotation binding is untouched"
        );
        let again = encrypt_and_cascade_community(backend, &comm, b"after", None)
            .await
            .unwrap();
        assert_eq!(
            again.epoch, new,
            "{tag} I17: the door seals under the current epoch"
        );

        // The attempt the door loops over, driven at the STALE epoch as the
        // racing writer would: refused, and the ciphertext row it stored is
        // gone again — no orphan, no public blob of unreadable bytes.
        use crate::federation::community_dek::orchestrate::{seal_store_bind_at, SealOutcome};
        match seal_store_bind_at(
            backend,
            crate::federation::types::cohort_scope::COMMUNITY,
            &comm,
            old,
            b"raced",
            None,
            None,
        )
        .await
        .unwrap()
        {
            SealOutcome::EpochMoved { at_rest_sha256 } => assert!(
                !backend.has_blob(&at_rest_sha256).await.unwrap(),
                "{tag} I17: a refused bind left its ciphertext row behind (orphan)"
            ),
            SealOutcome::Bound(r) => panic!(
                "{tag} I17: a writer holding the STALE epoch {old} bound a blob (epoch {})",
                r.epoch
            ),
        }
    }

    // ── I18 ──────────────────────────────────────────────────────────────
    /// **A withdraws failure aborts the eviction; retry never double-retracts.**
    ///
    /// The first rebuild swallowed the withdraws error and deleted anyway —
    /// "fail-honest" that was fail-silent: no withdraws, bytes gone,
    /// `list_holders` naming this node until TTL. (C2-3)
    ///
    /// Two halves. (a) An announcement this node ALREADY retracted is not
    /// retracted again by the sweep (retry after a partial failure is safe) —
    /// held by the directory's retraction fold at write (#502 E7), which is
    /// why the evict loop carries no second filter.
    /// (b) When the withdraws cannot be admitted, the bytes and the binding
    /// stay and the error propagates.
    // `emit_withdraws_attestation_helper` exists only with a backend feature;
    // the no-backend axis legs compile this module with `--all-targets`.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    pub async fn exercise_i18_withdraw_failure_aborts_eviction<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        let node = format!("{tag}-node-{run}");
        crate::federation::community_dek::lifecycle_support::seed_community(
            backend,
            &comm,
            &[(&alice, &alice_occ)],
        )
        .await;
        let signer = node_signer(backend, &node).await;
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer.clone());
        let node_derived = signer.derived_key_id();
        let prefix = crate::federation::HOLDS_BYTES_ATTESTATION_TYPE_PREFIX;
        async fn withdraws_by<D: FederationDirectory + Sync>(backend: &D, node: &str) -> usize {
            backend
                .list_attestations_by(node)
                .await
                .unwrap()
                .into_iter()
                .filter(|a| {
                    a.attestation_type == crate::federation::types::attestation_type::WITHDRAWS
                })
                .count()
        }

        // (a) announce, retract by hand, then sweep: exactly ONE withdraws.
        let sealed = encrypt_and_cascade_community(backend, &comm, b"old", None)
            .await
            .unwrap();
        let Some(BlobBody::Inline(bytes)) = backend.get_blob(&sealed.at_rest_sha256).await.unwrap()
        else {
            panic!("{tag} I18: sealed blob is inline");
        };
        backend
            .put_blob_signing_at(
                crate::federation::types::cohort_scope::COMMUNITY,
                crate::federation::StorageFloor::resolved(
                    crate::federation::types::cohort_scope::CryptoTier::CommunityDek,
                ),
                &sealed.at_rest_sha256,
                BlobBody::Inline(bytes),
                None,
                &node_derived,
                &adapter,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .unwrap();
        let prior = backend
            .list_attestations_by(&node_derived)
            .await
            .unwrap()
            .into_iter()
            .find(|a| a.attestation_type.starts_with(prefix))
            .expect("the announcement");
        crate::federation::blobs::emit_withdraws_attestation_helper(
            &prior,
            &node_derived,
            &signer,
            backend,
            chrono::Utc::now(),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I18: retract by hand: {e}"));
        assert_eq!(
            withdraws_by(backend, &node_derived).await,
            1,
            "{tag} I18: precondition"
        );

        backend.community_dek_bump_epoch(&comm).await.unwrap();
        backend
            .community_dek_set_retain_past_epochs(&comm, Some(0))
            .await
            .unwrap();
        let n = backend
            .community_dek_evict_epoch_objects(&comm, sealed.epoch, &signer, chrono::Utc::now())
            .await
            .unwrap_or_else(|e| panic!("{tag} I18(a): evict after a manual retraction: {e}"));
        assert_eq!(n, 1, "{tag} I18(a): evicted");
        assert_eq!(
            withdraws_by(backend, &node_derived).await,
            1,
            "{tag} I18(a): the sweep re-retracted an announcement this node had ALREADY \
             withdrawn — a retry after a partial failure double-retracts"
        );

        // (b) announce again under a NEW epoch; make the withdraws inadmissible
        //     by handing the sweep a `now` far outside the admission skew; the
        //     bytes and binding must survive and the error must surface.
        let sealed2 = encrypt_and_cascade_community(backend, &comm, b"newer", None)
            .await
            .unwrap();
        let Some(BlobBody::Inline(bytes2)) =
            backend.get_blob(&sealed2.at_rest_sha256).await.unwrap()
        else {
            panic!("{tag} I18: sealed blob is inline");
        };
        backend
            .put_blob_signing_at(
                crate::federation::types::cohort_scope::COMMUNITY,
                crate::federation::StorageFloor::resolved(
                    crate::federation::types::cohort_scope::CryptoTier::CommunityDek,
                ),
                &sealed2.at_rest_sha256,
                BlobBody::Inline(bytes2),
                None,
                &node_derived,
                &adapter,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
            .unwrap();
        backend.community_dek_bump_epoch(&comm).await.unwrap();
        let far_future = chrono::Utc::now() + chrono::Duration::days(3650);
        let res = backend
            .community_dek_evict_epoch_objects(&comm, sealed2.epoch, &signer, far_future)
            .await;
        assert!(
            res.is_err(),
            "{tag} I18(b): the withdraws could not be admitted and the eviction reported SUCCESS"
        );
        assert!(
            backend
                .get_blob(&sealed2.at_rest_sha256)
                .await
                .unwrap()
                .is_some(),
            "{tag} I18(b): the bytes were DELETED although the retraction failed — \
             list_holders will name this node for content it cannot serve"
        );
        assert_eq!(
            backend
                .community_dek_epoch_object_count(&comm, sealed2.epoch)
                .await
                .unwrap(),
            1,
            "{tag} I18(b): the binding survives a failed eviction"
        );
    }

    // ── I19 ──────────────────────────────────────────────────────────────
    /// **A blob's satellite rows die with it.** `delete_blob` removes the
    /// epoch binding and the at-rest grants transactionally, so a deleted
    /// blob can never hold an epoch's object count above zero. (C2-9)
    pub async fn exercise_i19_delete_blob_removes_satellites<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        crate::federation::community_dek::lifecycle_support::seed_community(
            backend,
            &comm,
            &[(&alice, &alice_occ)],
        )
        .await;
        let sealed = encrypt_and_cascade_community(backend, &comm, b"x", None)
            .await
            .unwrap();
        assert_eq!(
            backend
                .community_dek_epoch_object_count(&comm, sealed.epoch)
                .await
                .unwrap(),
            1
        );
        assert!(backend.delete_blob(&sealed.at_rest_sha256).await.unwrap());
        assert!(
            backend
                .community_dek_blob_epoch(&sealed.at_rest_sha256)
                .await
                .unwrap()
                .is_none(),
            "{tag} I19: the epoch binding OUTLIVED its blob"
        );
        assert_eq!(
            backend
                .community_dek_epoch_object_count(&comm, sealed.epoch)
                .await
                .unwrap(),
            0,
            "{tag} I19: a deleted blob holds the epoch's object count above zero — its DEK \
             can never be destroyed"
        );
        assert!(
            backend
                .get_at_rest_grant(&sealed.at_rest_sha256, super::PERSIST_SELF_RECIPIENT)
                .await
                .unwrap()
                .is_none(),
            "{tag} I19: an at-rest grant OUTLIVED its blob"
        );
    }

    // ── I20 ──────────────────────────────────────────────────────────────
    /// **The current epoch cannot be disabled or destroyed through the
    /// key-state door.** Rotation retires an epoch; the door only acts on
    /// epochs rotation has already left behind. (C2-8)
    pub async fn exercise_i20_the_primary_cannot_be_retired<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::community_dek::orchestrate::{
            encrypt_and_cascade_community, set_key_state,
        };
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        crate::federation::community_dek::lifecycle_support::seed_community(
            backend,
            &comm,
            &[(&alice, &alice_occ)],
        )
        .await;
        let sealed = encrypt_and_cascade_community(backend, &comm, b"x", None)
            .await
            .unwrap();
        let current = backend.community_dek_current_epoch(&comm).await.unwrap();
        assert_eq!(sealed.epoch, current);

        for to in [DekKeyState::Disabled, DekKeyState::Destroyed] {
            assert!(
                set_key_state(backend, &comm, current, to).await.is_err(),
                "{tag} I20: the door let the CURRENT epoch be moved to {to:?} — the pointer \
                 keeps naming it and every later write fails in ensure_epoch_dek"
            );
            // The backend's own conditional statement refuses too — the door's
            // check is a friendlier message, not the guard.
            let _ = backend
                .community_dek_set_key_state(&comm, current, to)
                .await;
            assert_eq!(
                backend
                    .community_dek_key_state(&comm, current)
                    .await
                    .unwrap(),
                Some(DekKeyState::Enabled),
                "{tag} I20: the backend statement moved the CURRENT epoch to {to:?}"
            );
        }
        // Still writable.
        encrypt_and_cascade_community(backend, &comm, b"still fine", None)
            .await
            .unwrap_or_else(|e| panic!("{tag} I20: the community is wedged: {e}"));
    }

    // ── I21 ──────────────────────────────────────────────────────────────
    /// A matcher double that records every body it is shown.
    pub struct RecordingMatcher {
        /// Every body `check` was shown, in order.
        pub seen: std::sync::Mutex<Vec<Vec<u8>>>,
        /// Report a match (policy: refuse) for every body.
        pub refuse: bool,
    }

    #[async_trait::async_trait]
    impl crate::federation::PerceptualHashMatcher for RecordingMatcher {
        async fn check(
            &self,
            _sha256: &[u8; 32],
            body: &[u8],
        ) -> Result<crate::federation::HashMatchResult, crate::federation::HashMatchError> {
            self.seen.lock().unwrap().push(body.to_vec());
            Ok(if self.refuse {
                crate::federation::HashMatchResult::Match {
                    database: crate::federation::HashDatabaseId("i21".into()),
                    score: 0.99,
                    threshold: 0.5,
                }
            } else {
                crate::federation::HashMatchResult::NoMatch
            })
        }
        fn databases(&self) -> &[crate::federation::HashDatabaseId] {
            &[]
        }
        fn on_match_policy(&self) -> crate::federation::OnMatchPolicy {
            crate::federation::OnMatchPolicy::Refuse
        }
    }

    /// **The matcher screens the PLAINTEXT, once, before sealing, on every
    /// tier.** The caller installs `matcher` on the backend first. (C2-6)
    pub async fn exercise_i21_matcher_screens_plaintext_before_sealing<B>(
        backend: &B,
        tag: &str,
        matcher: &RecordingMatcher,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::put_blob_scoped;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        let node = format!("{tag}-node-{run}");
        crate::federation::community_dek::lifecycle_support::seed_community(
            backend,
            &comm,
            &[(&alice, &alice_occ)],
        )
        .await;
        let signer = node_signer(backend, &node).await;
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer.clone());

        let plaintext = format!("{tag} an image the matcher must see AS IS {run}").into_bytes();
        matcher.seen.lock().unwrap().clear();
        put_blob_scoped(
            backend,
            &adapter,
            crate::federation::types::cohort_scope::COMMUNITY,
            Some(&comm),
            &plaintext,
            None,
            None,
        )
        .await
        .unwrap();
        let seen = matcher.seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![plaintext.clone()],
            "{tag} I21 (community): the matcher must be shown the PLAINTEXT exactly once — \
             not the ciphertext, not twice, not never; it saw {} body(ies)",
            seen.len()
        );

        matcher.seen.lock().unwrap().clear();
        put_blob_scoped(
            backend,
            &adapter,
            crate::federation::types::cohort_scope::FEDERATION,
            None,
            &plaintext,
            None,
            None,
        )
        .await
        .unwrap();
        let seen = matcher.seen.lock().unwrap().clone();
        assert_eq!(
            seen,
            vec![plaintext.clone()],
            "{tag} I21 (commons): screened exactly once; saw {} body(ies)",
            seen.len()
        );
    }

    /// The refusing half of I21: a refused plaintext leaves NOTHING behind —
    /// no ciphertext row, no binding — because the screen ran before the
    /// cascade, not after it.
    pub async fn exercise_i21b_a_refused_plaintext_is_never_sealed<B>(
        backend: &B,
        tag: &str,
        matcher: &RecordingMatcher,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::put_blob_scoped;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        let node = format!("{tag}-node-{run}");
        crate::federation::community_dek::lifecycle_support::seed_community(
            backend,
            &comm,
            &[(&alice, &alice_occ)],
        )
        .await;
        let signer = node_signer(backend, &node).await;
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer.clone());
        assert!(matcher.refuse, "{tag} I21b: fixture — a refusing matcher");
        let epoch = backend.community_dek_current_epoch(&comm).await.unwrap();
        let res = put_blob_scoped(
            backend,
            &adapter,
            crate::federation::types::cohort_scope::COMMUNITY,
            Some(&comm),
            b"known-bad",
            None,
            None,
        )
        .await;
        assert!(
            matches!(res, Err(BlobError::HashMatchedKnownBad { .. })),
            "{tag} I21b: a matcher hit must refuse the write: {res:?}"
        );
        assert_eq!(
            backend
                .community_dek_epoch_object_count(&comm, epoch)
                .await
                .unwrap(),
            0,
            "{tag} I21b: the cascade PERSISTED the content before the screen refused it"
        );
    }

    // ── I23 ──────────────────────────────────────────────────────────────
    /// **The write door derives the attesting key id from its signer.** An
    /// announcement is under the signer's DERIVED federation key — the one
    /// the sweep searches under — never an alias a surface happened to hold.
    /// (C2-5)
    pub async fn exercise_i23_the_door_announces_under_the_signers_derived_key<B>(
        backend: &B,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::put_blob_scoped;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let node = format!("{tag}-node-{run}");
        let signer = node_signer(backend, &node).await;
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer.clone());
        let derived = signer.derived_key_id();
        assert_ne!(
            derived, node,
            "{tag} I23: fixture — alias and derived id differ"
        );

        let body = format!("{tag} commons {run}").into_bytes();
        let res = put_blob_scoped(
            backend,
            &adapter,
            crate::federation::types::cohort_scope::FEDERATION,
            None,
            &body,
            None,
            None,
        )
        .await
        .unwrap();
        let holders = backend.list_holders(&res.at_rest_sha256).await.unwrap();
        assert!(
            holders.contains(&derived) && !holders.contains(&node),
            "{tag} I23: the announcement must be under the signer's DERIVED key {derived:?} \
             (what the sweep retracts under), never the alias {node:?}: holders={holders:?}"
        );
    }
    // ── I24 ──────────────────────────────────────────────────────────────
    /// **The row records the cohort the write NAMED.** `affiliations` and
    /// `community` share a cascade and a tier; an `affiliations` write must
    /// not land as `community` on the row §11.1 calls the authority.
    /// (Ultrareview of `30fde79`.)
    pub async fn exercise_i24_the_row_records_the_named_cohort<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::put_blob_scoped;
        use crate::federation::types::cohort_scope::{CryptoTier, AFFILIATIONS};
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        let node = format!("{tag}-node-{run}");
        crate::federation::community_dek::lifecycle_support::seed_community(
            backend,
            &comm,
            &[(&alice, &alice_occ)],
        )
        .await;
        let signer = node_signer(backend, &node).await;
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer.clone());
        let res = put_blob_scoped(
            backend,
            &adapter,
            AFFILIATIONS,
            Some(&comm),
            b"affil",
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(res.tier, CryptoTier::CommunityDek);
        assert_eq!(
            backend
                .blob_cohort_scope(&res.at_rest_sha256)
                .await
                .unwrap()
                .as_deref(),
            Some(AFFILIATIONS),
            "{tag} I24: an affiliations write was recorded as some other cohort"
        );
    }
    // ── I25 ──────────────────────────────────────────────────────────────
    /// **The floor refuses a self-contradicting row.** `self`/`family` at
    /// `plaintext`, or commons at a sealed tier, is refused by the floor
    /// itself — so even an in-crate caller holding a token cannot record the
    /// row §11.1 says is unrepresentable.
    pub async fn exercise_i25_the_floor_refuses_a_contradictory_row<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::types::cohort_scope::{CryptoTier, FAMILY, FEDERATION, SELF};
        use crate::federation::StorageFloor;
        for (scope, tier) in [
            (SELF, CryptoTier::Plaintext),
            (FAMILY, CryptoTier::Plaintext),
            (FEDERATION, CryptoTier::InvisibleEncrypted),
            (FEDERATION, CryptoTier::CommunityDek),
        ] {
            let body = format!("{tag} {scope} {tier:?}").into_bytes();
            let id = sha(&body);
            let res = backend
                .store_blob_local(
                    &id,
                    BlobBody::Inline(body),
                    None,
                    scope,
                    StorageFloor::resolved(tier),
                )
                .await;
            assert!(
                matches!(res, Err(BlobError::InvalidArgument(_))),
                "{tag} I25 [{scope} @ {tier:?}]: the floor recorded a self-contradicting row: {res:?}"
            );
            assert!(
                !backend.has_blob(&id).await.unwrap(),
                "{tag} I25: nothing stored"
            );
        }
    }
    // ── I28 ──────────────────────────────────────────────────────────────
    /// **An announcement never stores.** If a rotation and a retention sweep
    /// evict a community blob between the cascade's bind and the door's
    /// announcement, the announcement must refuse (`NotHeld`) — not re-insert
    /// a ciphertext row with no binding and return success. (C3-2)
    pub async fn exercise_i28_announce_refuses_an_evicted_row<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
        use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY};
        use crate::federation::StorageFloor;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        let node = format!("{tag}-node-{run}");
        crate::federation::community_dek::lifecycle_support::seed_community(
            backend,
            &comm,
            &[(&alice, &alice_occ)],
        )
        .await;
        let signer = node_signer(backend, &node).await;
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer.clone());
        let node_derived = signer.derived_key_id();

        // The cascade half of the door: sealed, stored, bound.
        let sealed = encrypt_and_cascade_community(backend, &comm, b"raced", None)
            .await
            .unwrap();
        let Some(BlobBody::Inline(bytes)) = backend.get_blob(&sealed.at_rest_sha256).await.unwrap()
        else {
            panic!("{tag} I28: sealed blob is inline");
        };
        // A rotation + retention sweep evicts it before the door announces.
        backend.community_dek_bump_epoch(&comm).await.unwrap();
        backend
            .community_dek_set_retain_past_epochs(&comm, Some(0))
            .await
            .unwrap();
        let sweeper = node_signer(backend, &format!("{tag}-sweeper-{run}")).await;
        let n = backend
            .community_dek_evict_epoch_objects(&comm, sealed.epoch, &sweeper, chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(n, 1, "{tag} I28: precondition — evicted");
        assert!(!backend.has_blob(&sealed.at_rest_sha256).await.unwrap());

        // The announce half of the door, arriving late.
        let res = backend
            .put_blob_signing_at(
                COMMUNITY,
                StorageFloor::resolved(CryptoTier::CommunityDek),
                &sealed.at_rest_sha256,
                BlobBody::Inline(bytes),
                None,
                &node_derived,
                &adapter,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await;
        assert!(
            matches!(res, Err(BlobError::NotHeld { .. })),
            "{tag} I28: announcing an EVICTED community blob must refuse NotHeld, got {res:?}"
        );
        assert!(
            !backend.has_blob(&sealed.at_rest_sha256).await.unwrap(),
            "{tag} I28: the announcement RE-INSERTED the ciphertext row — without its \
             binding, a row read_blob_as reports as corrupt"
        );
        assert!(
            !backend
                .list_holders(&sealed.at_rest_sha256)
                .await
                .unwrap()
                .contains(&node_derived),
            "{tag} I28: no holder claim for bytes this node does not hold"
        );
    }

    // ── I31 ──────────────────────────────────────────────────────────────
    /// **Eviction is a fact a reader is told; deletion is not.** (#833)
    ///
    /// The retention sweep keeps the epoch binding and stamps `evicted_at`;
    /// the object count ignores evicted bindings so destroy still succeeds;
    /// an AUTHORIZED viewer reading the evicted sha gets
    /// `Evicted{community, epoch, evicted_at}`, a stranger gets `NotGranted`
    /// (naming neither community nor epoch — I4b), an unknown sha gets
    /// `NotHeld`. Both authorization legs are exercised: the epoch grant
    /// (a REMOVED member, who keeps the old epoch's grant by AV-70, before
    /// the epoch is destroyed) and the current roster (a member after the
    /// production sweep has destroyed the epoch and erased its grants).
    pub async fn exercise_i31_eviction_is_a_fact_a_reader_is_told<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::read_any_for_viewer;
        use crate::federation::community_dek::lifecycle_support::{revoke_member, seed_community};
        use crate::federation::community_dek::orchestrate::{
            encrypt_and_cascade_community, read_for_community_viewer, sweep_rotated_epochs,
        };
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        let bob = format!("{tag}-bob-{run}");
        let bob_occ = format!("{tag}-bob-occ-{run}");
        let stranger = format!("{tag}-stranger-{run}");
        seed_community(backend, &comm, &[(&alice, &alice_occ), (&bob, &bob_occ)]).await;
        let sweeper = node_signer(backend, &format!("{tag}-sweeper-{run}")).await;

        let sealed = encrypt_and_cascade_community(backend, &comm, b"minutes", None)
            .await
            .unwrap();
        let e0 = sealed.epoch;
        let at_rest = sealed.at_rest_sha256;

        // Rotation-on-removal: bob is out; e0 is rotated past. Bob KEEPS his
        // grant on e0 (AV-70, forward-only) until the epoch is destroyed.
        revoke_member(backend, &comm, &bob).await;
        assert!(
            backend.community_dek_current_epoch(&comm).await.unwrap() > e0,
            "{tag} I31: precondition — the revocation rotated the epoch"
        );
        assert!(
            backend
                .community_dek_has_member_grant(&comm, e0, &bob_occ)
                .await
                .unwrap(),
            "{tag} I31: precondition — the removed member still holds the e0 grant (AV-70)"
        );

        // ── Phase A: evict WITHOUT destroying (the sweep's first half, alone)
        //    so the epoch-grant leg of the authorization is the one that
        //    decides.
        let t_evict = chrono::Utc::now();
        let n = backend
            .community_dek_evict_epoch_objects(&comm, e0, &sweeper, t_evict)
            .await
            .unwrap();
        assert_eq!(n, 1, "{tag} I31: one object evicted");
        assert!(
            !backend.has_blob(&at_rest).await.unwrap(),
            "{tag} I31: the bytes are gone"
        );
        assert_eq!(
            backend.community_dek_blob_epoch(&at_rest).await.unwrap(),
            Some((comm.clone(), e0)),
            "{tag} I31: the sweep DELETED the binding — a later read cannot tell swept from \
             never-ours"
        );
        assert_eq!(
            backend
                .community_dek_epoch_object_count(&comm, e0)
                .await
                .unwrap(),
            0,
            "{tag} I31: an evicted binding is COUNTED as a live object — destroy is blocked \
             forever"
        );
        let again = backend
            .community_dek_evict_epoch_objects(&comm, e0, &sweeper, chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(
            again, 0,
            "{tag} I31: a second eviction of the same epoch re-processed already-evicted \
             bindings (the stamp must be written once)"
        );

        // The RANGE read door tells the authorized viewer the same fact —
        // "swept", not "never ours" (ultrareview of v44).
        let ranged = crate::federation::chunk_dag_cascade::orchestrate::read_any_range_for_viewer(
            backend, &at_rest, &bob_occ, 0, 0, None,
        )
        .await;
        assert!(
            matches!(&ranged, Err(BlobError::Evicted { epoch, .. }) if *epoch == e0),
            "{tag} I31: the range door reported an EVICTED sha as {ranged:?} to an authorized \
             viewer — 'never ours' where the whole-blob door says Evicted"
        );

        // The removed member holds the e0 grant and is NOT on the roster:
        // authorized by the grant leg alone.
        let bob_res = read_any_for_viewer(backend, &at_rest, &bob_occ, None).await;
        match &bob_res {
            Err(BlobError::Evicted {
                community_key_id,
                epoch,
                evicted_at,
                sha256_hex,
            }) => {
                assert_eq!(community_key_id, &comm, "{tag} I31: names the community");
                assert_eq!(*epoch, e0, "{tag} I31: names the epoch");
                assert_eq!(
                    sha256_hex,
                    &hex::encode(at_rest),
                    "{tag} I31: names the sha"
                );
                let skew = (*evicted_at - t_evict).num_milliseconds().abs();
                assert!(
                    skew < 1_000,
                    "{tag} I31: evicted_at {evicted_at} is not the instant the sweep was \
                     given ({t_evict})"
                );
            }
            other => panic!(
                "{tag} I31: a REMOVED member who still holds the epoch grant must be told the \
                 blob was evicted (grant leg); got {other:?}"
            ),
        }

        // ── Phase B: the production sweep — evicts (nothing left) and
        //    DESTROYS e0, erasing every e0 grant (I5). From here the roster
        //    leg is the only one that can authorize a member.
        let report = sweep_rotated_epochs(backend, &comm, &sweeper, chrono::Utc::now())
            .await
            .unwrap();
        assert!(
            report.destroyed.contains(&e0),
            "{tag} I31: destroy after the sweep must still succeed — the object count must \
             ignore evicted bindings; report {report:?}"
        );
        assert_eq!(
            backend.community_dek_key_state(&comm, e0).await.unwrap(),
            Some(DekKeyState::Destroyed)
        );
        assert!(
            !backend
                .community_dek_has_member_grant(&comm, e0, &alice_occ)
                .await
                .unwrap(),
            "{tag} I31: precondition — destroy erased the epoch's grants (I5)"
        );

        // A current member: authorized by the roster leg.
        let alice_res = read_any_for_viewer(backend, &at_rest, &alice_occ, None).await;
        match &alice_res {
            Err(BlobError::Evicted {
                community_key_id,
                epoch,
                ..
            }) => {
                assert_eq!(community_key_id, &comm);
                assert_eq!(*epoch, e0);
            }
            other => panic!(
                "{tag} I31: a CURRENT member reading a swept sha after the production sweep \
                 (epoch destroyed, grants gone) must be told it was evicted, not that it was \
                 never ours; got {other:?}"
            ),
        }

        // A stranger: refused, and the refusal names neither community nor
        // epoch (I4b) — the same class a stranger gets on a live blob.
        let err = read_any_for_viewer(backend, &at_rest, &stranger, None)
            .await
            .expect_err("a stranger must be refused");
        assert!(
            matches!(err, BlobError::NotGranted { .. }),
            "{tag} I31: a stranger must get NotGranted, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            !msg.contains(&comm) && !msg.contains("epoch"),
            "{tag} I31: the refusal to a STRANGER disclosed the binding: {msg}"
        );

        // The DIRECT community door (`Engine::read_blob_for_community_viewer`
        // and its PyO3 binding — a production surface) gives the same two
        // answers: the door is not the only way through.
        let direct = read_for_community_viewer(backend, &at_rest, &alice_occ).await;
        assert!(
            matches!(&direct, Err(BlobError::Evicted { epoch, .. }) if *epoch == e0),
            "{tag} I31: the direct community door must tell a member the blob was evicted \
             (it authorized by an epoch grant the destroy erased?); got {direct:?}"
        );
        let err = read_for_community_viewer(backend, &at_rest, &stranger)
            .await
            .expect_err("a stranger must be refused at the direct door too");
        assert!(
            matches!(err, BlobError::NotGranted { .. }),
            "{tag} I31: the direct community door must refuse a stranger NotGranted, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            !msg.contains(&comm) && !msg.contains("epoch"),
            "{tag} I31: the direct door's refusal to a STRANGER disclosed the binding: {msg}"
        );

        // The removed member, now that destroy erased the e0 grant: not a
        // grantee, not on the roster ⇒ NotGranted.
        let err = read_any_for_viewer(backend, &at_rest, &bob_occ, None)
            .await
            .expect_err("a removed member with no surviving grant must be refused");
        assert!(
            matches!(err, BlobError::NotGranted { .. }),
            "{tag} I31: a removed member whose grants the destroy erased must get NotGranted, \
             got {err:?}"
        );

        // A sha that was never ours: NotHeld, to a member and to a stranger.
        let random = sha(format!("{tag}-never-ours-{run}").as_bytes());
        for viewer in [&alice_occ, &stranger] {
            let err = read_any_for_viewer(backend, &random, viewer, None)
                .await
                .expect_err("an unknown sha must be refused");
            assert!(
                matches!(err, BlobError::NotHeld { .. }),
                "{tag} I31: an unknown sha must be NotHeld for {viewer}, got {err:?}"
            );
        }
    }

    // ── I40 ──────────────────────────────────────────────────────────────
    /// **Caller-supplied associated data is bound into the seal, never
    /// stored.** (#831, from #830 — the chat migration's lifted-ciphertext
    /// substitution.)
    ///
    /// Under a per-epoch community DEK a ciphertext lifted from Alice's
    /// message row onto Mallory's own validly-signed row opens for every
    /// member: the blob is addressed by sha and authorized by membership, and
    /// neither knows which row asked. A row-side commitment to `(sha, author,
    /// asserted_at)` does not close that — Mallory signs a self-consistent
    /// tuple. Only the seal can refuse it: the writer folds the row's data
    /// into the GCM tag, the reader presents the same data, and the data is
    /// never on disk. Both encrypted tiers; the plaintext tier refuses the
    /// data rather than dropping it.
    pub async fn exercise_i40_associated_data_binds_the_seal<B>(backend: &B, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::{
            put_blob_scoped, read_any_for_viewer,
        };
        use crate::federation::community_dek::lifecycle_support::{seed_community, seed_member};
        use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY, FEDERATION, SELF};
        let run = uuid::Uuid::new_v4().simple().to_string();
        let node = format!("{tag}-node-{run}");
        let signer = node_signer(backend, &node).await;
        let adapter = crate::signing::LocalSignerHardwareAdapter::new(signer.clone());
        let stranger = format!("{tag}-stranger-{run}");

        // What a chat row supplies: author ‖ signed instant ‖ epoch. Alice's
        // row, and the row Mallory signs after lifting Alice's sha onto it.
        let alice_row = format!("{tag}-alice-{run}\n2026-09-09T00:00:00.000Z\n1");
        let mallory_row = format!("{tag}-mallory-{run}\n2026-09-09T00:00:01.000Z\n1");
        let a: &[u8] = alice_row.as_bytes();
        let a_prime: &[u8] = mallory_row.as_bytes();

        // self/family: an owner with one keyed occurrence.
        let owner = format!("{tag}-owner-{run}");
        let owner_occ = format!("{tag}-owner-occ-{run}");
        seed_member(backend, &owner, &owner_occ).await;
        // community: alice as a member.
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let alice_occ = format!("{tag}-alice-occ-{run}");
        seed_community(backend, &comm, &[(&alice, &alice_occ)]).await;

        for (scope, key, viewer, tier) in [
            (
                SELF,
                owner.as_str(),
                owner_occ.as_str(),
                CryptoTier::InvisibleEncrypted,
            ),
            (
                COMMUNITY,
                comm.as_str(),
                alice_occ.as_str(),
                CryptoTier::CommunityDek,
            ),
        ] {
            let body = format!("message body sealed at {scope}").into_bytes();
            let put = put_blob_scoped(backend, &adapter, scope, Some(key), &body, None, Some(a))
                .await
                .unwrap_or_else(|e| panic!("{tag} I40: seal at {scope} with associated data: {e}"));
            assert_eq!(
                put.tier, tier,
                "{tag} I40: precondition — {scope} resolved sealed"
            );
            let id = put.at_rest_sha256;

            // The data is a binding, not a column: not in the stored body.
            let Some(BlobBody::Inline(stored)) = backend.get_blob(&id).await.unwrap() else {
                panic!("{tag} I40: the sealed {scope} row is inline");
            };
            assert!(
                !stored.windows(a.len()).any(|w| w == a),
                "{tag} I40: the associated data is STORED in the {scope} body"
            );

            // Alice's row opens it.
            let got = read_any_for_viewer(backend, &id, viewer, Some(a))
                .await
                .unwrap_or_else(|e| {
                    panic!("{tag} I40: open at {scope} under the sealing data: {e}")
                });
            assert_eq!(
                got, body,
                "{tag} I40: {scope} plaintext under the sealing data"
            );

            // Mallory's row does not — after authorization, as a crypto-class
            // refusal, naming neither row nor binding.
            let err = read_any_for_viewer(backend, &id, viewer, Some(a_prime))
                .await
                .expect_err(&format!(
                    "{tag} I40: the {scope} ciphertext OPENED under another row's data — lifted \
                     onto Mallory's row, Alice's message reads as Mallory's"
                ));
            assert!(
                matches!(err, BlobError::Backend(_)),
                "{tag} I40: a mismatch after authorization is a crypto-class error (the viewer \
                 was authorized; the bytes did not belong to the row), got {err:?}"
            );
            let msg = err.to_string();
            assert!(
                !msg.contains(&alice_row) && !msg.contains(&mallory_row) && !msg.contains(&comm),
                "{tag} I40: the refusal named the data or the binding: {msg}"
            );

            // No data at all does not open it either: the seal demands what
            // bound it.
            let err = read_any_for_viewer(backend, &id, viewer, None)
                .await
                .expect_err(&format!(
                "{tag} I40: the {scope} ciphertext opened with NO data — the binding was dropped"
            ));
            assert!(
                matches!(err, BlobError::Backend(_)),
                "{tag} I40: an absent binding is the same crypto-class refusal, got {err:?}"
            );

            // A stranger presenting the right data is still refused FIRST, by
            // authorization, and learns nothing about the seal.
            let err = read_any_for_viewer(backend, &id, &stranger, Some(a))
                .await
                .expect_err(&format!("{tag} I40: a stranger read a {scope} blob"));
            assert!(
                matches!(err, BlobError::NotGranted { .. }),
                "{tag} I40: authorization comes before the open — a stranger with the right \
                 data is NotGranted, got {err:?}"
            );

            // A seal WITHOUT data at the same tier is the v43 row: it opens
            // without data, and presenting data against it is refused — the
            // two entry points do not open each other's ciphertext.
            let unbound =
                put_blob_scoped(backend, &adapter, scope, Some(key), b"unbound", None, None)
                    .await
                    .unwrap_or_else(|e| panic!("{tag} I40: an AAD-less seal at {scope}: {e}"));
            assert_eq!(
                read_any_for_viewer(backend, &unbound.at_rest_sha256, viewer, None)
                    .await
                    .unwrap_or_else(|e| panic!("{tag} I40: AAD-less open at {scope}: {e}")),
                b"unbound",
                "{tag} I40: an AAD-less seal stays readable without data"
            );
            assert!(
                matches!(
                    read_any_for_viewer(backend, &unbound.at_rest_sha256, viewer, Some(a)).await,
                    Err(BlobError::Backend(_))
                ),
                "{tag} I40: data presented against an AAD-less seal must refuse — a reader that \
                 believes in a binding that does not exist is told so"
            );
        }

        // The plaintext tier: nothing to bind to. Refused, not dropped; and
        // nothing stored.
        let body = b"public doc with a binding nobody could hold".to_vec();
        let id = sha(&body);
        let res = put_blob_scoped(backend, &adapter, FEDERATION, None, &body, None, Some(a)).await;
        assert!(
            matches!(res, Err(BlobError::InvalidArgument(_))),
            "{tag} I40: associated data at a PLAINTEXT tier must be refused, not silently \
             dropped, got {res:?}"
        );
        assert!(
            !backend.has_blob(&id).await.unwrap(),
            "{tag} I40: the refused commons write stored the row anyway"
        );
        put_blob_scoped(backend, &adapter, FEDERATION, None, &body, None, None)
            .await
            .unwrap_or_else(|e| panic!("{tag} I40: the commons write without data: {e}"));
        let res = read_any_for_viewer(backend, &id, &stranger, Some(a)).await;
        assert!(
            matches!(res, Err(BlobError::InvalidArgument(_))),
            "{tag} I40: data presented against a PLAINTEXT row must be refused at the read door \
             as at the write door, got {res:?}"
        );
        assert_eq!(
            read_any_for_viewer(backend, &id, &stranger, None)
                .await
                .unwrap(),
            body,
            "{tag} I40: the commons row is still public without data"
        );

        // Every seal/open door, not only the whole-blob ones: the chunk
        // write, the stream seal and the range read at a PLAINTEXT tier
        // refuse data rather than dropping it (ultrareview of v44).
        use crate::federation::chunk_dag_cascade::orchestrate::{
            put_blob_chunk_scoped, read_any_range_for_viewer, seal_stream_scoped,
        };
        let stream = format!("{tag}-i40-stream-{run}");
        let res =
            put_blob_chunk_scoped(backend, FEDERATION, None, &stream, 0, b"seg", 0, Some(a)).await;
        assert!(
            matches!(res, Err(BlobError::InvalidArgument(_))),
            "{tag} I40: a commons CHUNK write accepted associated data it cannot bind: {res:?}"
        );
        put_blob_chunk_scoped(backend, FEDERATION, None, &stream, 0, b"seg", 0, None)
            .await
            .unwrap_or_else(|e| panic!("{tag} I40: commons chunk without data: {e}"));
        let res =
            seal_stream_scoped(backend, &adapter, FEDERATION, None, &stream, None, Some(a)).await;
        assert!(
            matches!(res, Err(BlobError::InvalidArgument(_))),
            "{tag} I40: a commons STREAM seal accepted associated data it cannot bind: {res:?}"
        );
        let sealed = seal_stream_scoped(backend, &adapter, FEDERATION, None, &stream, None, None)
            .await
            .unwrap_or_else(|e| panic!("{tag} I40: commons seal without data: {e}"));
        let res =
            read_any_range_for_viewer(backend, &sealed.manifest_sha256, &stranger, 0, 2, Some(a))
                .await;
        assert!(
            matches!(res, Err(BlobError::InvalidArgument(_))),
            "{tag} I40: the RANGE read of a plaintext DAG accepted associated data: {res:?}"
        );
        assert_eq!(
            read_any_range_for_viewer(backend, &sealed.manifest_sha256, &stranger, 0, 2, None)
                .await
                .unwrap(),
            b"seg".to_vec(),
            "{tag} I40: the commons DAG is still public without data"
        );
    }
}

/// Fixture-only access to the storage floor for [`blob_invariants`].
#[cfg(any(test, feature = "test-anchor"))]
#[allow(dead_code)]
pub mod blob_invariants_fixture {
    use crate::federation::blobs::BlobBody;
    use crate::federation::BlobStorage;

    /// Place a plaintext body under a PRIVATE cohort, as a bypass would.
    /// The row is recorded at the tier the cohort REQUIRES (the floor refuses
    /// a `self`/`family` row at `plaintext` — I25), so what this plants is a
    /// row that claims sealed and carries clear bytes — the I4a probe: the
    /// read door must refuse a stranger BEFORE it looks at those bytes.
    pub async fn place_private_plaintext<B: BlobStorage + Sync>(
        backend: &B,
        sha: &[u8; 32],
        body: Vec<u8>,
    ) {
        backend
            .store_blob_local(
                sha,
                BlobBody::Inline(body),
                None,
                crate::federation::types::cohort_scope::SELF,
                crate::federation::StorageFloor::resolved(
                    crate::federation::types::cohort_scope::CryptoTier::InvisibleEncrypted,
                ),
            )
            .await
            .expect("floor write");
    }
}

#[cfg(test)]
mod cache_policy_tests {
    use super::remember_only_success;

    /// I29 — a failed derivation is not remembered; the next one is.
    #[test]
    fn i29_the_cache_remembers_only_success() {
        static CACHE: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
        assert_eq!(remember_only_success(&CACHE, None), None);
        assert!(
            CACHE.get().is_none(),
            "I29: a transient failure was CACHED — the corpus stays unavailable until restart"
        );
        assert_eq!(
            remember_only_success(&CACHE, Some([7u8; 32])),
            Some([7u8; 32])
        );
        // Once derived, a later failure cannot evict the good value either.
        assert_eq!(remember_only_success(&CACHE, None), None);
        assert_eq!(CACHE.get(), Some(&[7u8; 32]));
    }
}
