//! v5.4.0 (CIRISPersist#198, CEG 1.0 §5.6.8.8.2) — the versioned
//! [`LocalIdentityAggregate`]: a single-call snapshot of the local
//! node's federation hybrid identity across its **three distinct
//! keypair roles**.
//!
//! # The three roles (§5.6.8.8.2, NORMATIVE)
//!
//! | Role | Keys | Source | v1 |
//! |---|---|---|---|
//! | Signing | Ed25519 + ML-DSA-65 | persist's local signer (held) | populated |
//! | RET-transport | X25519 + Ed25519 (classical) | edge (`transport_identity_pubkeys()`) | **None — seam for #199** |
//! | Content-KEM | X25519 + ML-KEM-768 | persist mints + seals | populated |
//!
//! §5.6.8.8.2 is normative: *"three distinct keypairs; deriving the
//! content-KEM x25519 from either of the others is a conformance
//! violation."* The content-KEM keypair is therefore **freshly
//! generated** ([`crate::federation::blobs::BlobStorage::load_or_init_content_kem_identity`])
//! — never an Edwards→Montgomery conversion of the Ed25519 signing key,
//! never the Reticulum transport x25519. This is the discipline the
//! older #198 sketch (which derived x25519 from Ed25519) was superseded
//! by once the three-role model settled.
//!
//! # Crypto-agility
//!
//! [`LocalIdentityAggregate::aggregate_version`] is `1` here. A future
//! ML-KEM-1024 content-KEM (or any role-key algorithm change) bumps it
//! to `2` so consumers can gate on the version before interpreting the
//! pubkey fields.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The current [`LocalIdentityAggregate::aggregate_version`]. Bumped
/// when a role's key algorithm changes (e.g. ML-KEM-1024 → `2`).
pub const LOCAL_IDENTITY_AGGREGATE_VERSION: u32 = 1;

/// A single-call snapshot of the local node's federation hybrid
/// identity, spanning the three §5.6.8.8.2 keypair roles.
///
/// JSON-serialized over the PyO3 boundary by
/// [`crate::Engine::local_identity_aggregate`]. All pubkeys are base64
/// (standard alphabet) of the raw key bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalIdentityAggregate {
    /// Schema version — `1` (= [`LOCAL_IDENTITY_AGGREGATE_VERSION`]).
    /// Crypto-agility headroom: a future role-key algorithm change bumps
    /// this so consumers gate before interpreting the pubkey fields.
    pub aggregate_version: u32,

    /// The signing identity's stable `key_id` (the configured
    /// `local_key_id`). Always present — the signing role is required.
    pub key_id: String,
    /// The signing identity's PQC `key_id` (`local_pqc_key_id`), when a
    /// PQC signer is configured.
    pub pqc_key_id: Option<String>,

    // ── Signing role (Ed25519 + ML-DSA-65) — persist's local signer ──
    /// Ed25519 signing pubkey, base64 (32 raw bytes). Always present.
    pub ed25519_pubkey_b64: String,
    /// ML-DSA-65 signing pubkey, base64 (1952 raw bytes; FIPS 204), when
    /// a PQC signer is configured.
    pub ml_dsa_65_pubkey_b64: Option<String>,

    // ── RET-transport role (X25519 + Ed25519 classical) — edge ───────
    /// Reticulum transport X25519 pubkey, base64 (32 raw bytes).
    /// **`None` in v1** — populated from edge once #199 is wired.
    pub reticulum_x25519_pubkey_b64: Option<String>,
    /// Reticulum transport Ed25519 pubkey, base64 (32 raw bytes).
    /// **`None` in v1** — populated from edge once #199 is wired.
    pub reticulum_ed25519_pubkey_b64: Option<String>,

    // ── Content-KEM role (X25519 + ML-KEM-768) — persist mints+seals ─
    /// Content-KEM X25519 pubkey, base64 (32 raw bytes). A **freshly
    /// minted** key, independent of the signing key (§5.6.8.8.2).
    pub content_x25519_pubkey_b64: Option<String>,
    /// Content-KEM ML-KEM-768 pubkey, base64 (1184 raw bytes; FIPS 203).
    pub content_ml_kem_768_pubkey_b64: Option<String>,

    /// Canonical `did:key:` form. **`None` in v1** — deferred (no base58
    /// dependency is pulled for this cut).
    pub did_key: Option<String>,

    /// Stable identity hash: SHA-256 hex over the **present** role
    /// pubkeys, role-labeled + length-prefixed (collision-safe — see
    /// [`identity_hash`]). A stable addressing primitive.
    pub identity_hash: String,

    /// When this snapshot was produced (unix epoch milliseconds).
    pub evaluated_at_unix_ms: i64,
}

/// Compute the collision-safe identity hash over the **present** role
/// pubkeys, in a fixed role order, each entry role-labeled and
/// length-prefixed (the digest style of
/// [`crate::ceg::aggregates::scoring::scoring_factors_cache_key`]).
///
/// Absent fields contribute a `0` presence byte (so "x25519 absent"
/// never collides with "x25519 = empty string"); present fields
/// contribute a `1` byte, then the u64-LE byte length, then the base64
/// bytes. Role labels are NUL-terminated domain separators so the
/// boundary between two adjacent fields can't be shifted to forge a
/// match. The version is folded in first — a v2 aggregate over the same
/// keys hashes differently.
fn identity_hash(
    aggregate_version: u32,
    ed25519_pubkey_b64: &str,
    ml_dsa_65_pubkey_b64: Option<&str>,
    reticulum_x25519_pubkey_b64: Option<&str>,
    reticulum_ed25519_pubkey_b64: Option<&str>,
    content_x25519_pubkey_b64: Option<&str>,
    content_ml_kem_768_pubkey_b64: Option<&str>,
) -> String {
    let mut h = Sha256::new();
    h.update(b"LocalIdentityAggregate:v1.0\0");
    h.update(aggregate_version.to_le_bytes());

    let mut field = |label: &[u8], value: Option<&str>| {
        h.update(label);
        match value {
            Some(v) => {
                h.update([1u8]);
                h.update((v.len() as u64).to_le_bytes());
                h.update(v.as_bytes());
            }
            None => h.update([0u8]),
        }
    };

    // Ed25519 signing is always present; route it through the same
    // present-path encoding for a uniform layout.
    field(b"sign.ed25519\0", Some(ed25519_pubkey_b64));
    field(b"sign.ml_dsa_65\0", ml_dsa_65_pubkey_b64);
    field(b"ret.x25519\0", reticulum_x25519_pubkey_b64);
    field(b"ret.ed25519\0", reticulum_ed25519_pubkey_b64);
    field(b"kem.x25519\0", content_x25519_pubkey_b64);
    field(b"kem.ml_kem_768\0", content_ml_kem_768_pubkey_b64);

    hex::encode(h.finalize())
}

impl LocalIdentityAggregate {
    /// Assemble the aggregate from its resolved role inputs, computing
    /// [`Self::identity_hash`] over the present pubkeys and stamping
    /// `aggregate_version = 1` + `evaluated_at_unix_ms = now`.
    ///
    /// The signing Ed25519 pubkey is required (the signing role is
    /// mandatory). RET-transport is `None` in v1. Content-KEM pubkeys are
    /// the freshly-minted halves from
    /// [`load_or_init_content_kem_identity`](crate::federation::blobs::BlobStorage::load_or_init_content_kem_identity).
    #[allow(clippy::too_many_arguments)]
    pub fn assemble(
        key_id: String,
        pqc_key_id: Option<String>,
        ed25519_pubkey_b64: String,
        ml_dsa_65_pubkey_b64: Option<String>,
        reticulum_x25519_pubkey_b64: Option<String>,
        reticulum_ed25519_pubkey_b64: Option<String>,
        content_x25519_pubkey_b64: Option<String>,
        content_ml_kem_768_pubkey_b64: Option<String>,
        evaluated_at_unix_ms: i64,
    ) -> Self {
        let identity_hash = identity_hash(
            LOCAL_IDENTITY_AGGREGATE_VERSION,
            &ed25519_pubkey_b64,
            ml_dsa_65_pubkey_b64.as_deref(),
            reticulum_x25519_pubkey_b64.as_deref(),
            reticulum_ed25519_pubkey_b64.as_deref(),
            content_x25519_pubkey_b64.as_deref(),
            content_ml_kem_768_pubkey_b64.as_deref(),
        );
        Self {
            aggregate_version: LOCAL_IDENTITY_AGGREGATE_VERSION,
            key_id,
            pqc_key_id,
            ed25519_pubkey_b64,
            ml_dsa_65_pubkey_b64,
            reticulum_x25519_pubkey_b64,
            reticulum_ed25519_pubkey_b64,
            content_x25519_pubkey_b64,
            content_ml_kem_768_pubkey_b64,
            did_key: None,
            identity_hash,
            evaluated_at_unix_ms,
        }
    }
}

/// The freshly-minted content-KEM identity returned by
/// [`load_or_init_content_kem_identity`](crate::federation::blobs::BlobStorage::load_or_init_content_kem_identity)
/// — the two **public** halves, stable across calls/reboots.
///
/// This is the same shape an [`IdentityOccurrence`] registers as a wrap
/// target ([`EncryptionPubkeys`]), but for the local node's own
/// identity. The private halves stay sealed in the backend; v1 only
/// surfaces the pubkeys (for the aggregate).
///
/// [`IdentityOccurrence`]: crate::federation::types::IdentityOccurrence
/// [`EncryptionPubkeys`]: crate::federation::types::EncryptionPubkeys
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentKemIdentity {
    /// Content-KEM X25519 pubkey, base64 (32 raw bytes).
    pub x25519_pubkey_b64: String,
    /// Content-KEM ML-KEM-768 pubkey, base64 (1184 raw bytes).
    pub ml_kem_768_pubkey_b64: String,
}

/// Mint a fresh content-KEM keypair pair (X25519 + ML-KEM-768) via
/// `ciris_crypto`, returning `(x25519_priv[32], x25519_pub[32],
/// ml_kem_priv, ml_kem_pub)`. The x25519 keypair is generated
/// **independently** (its own CSPRNG draw) — never derived from a
/// signing key (§5.6.8.8.2). The backend `load_or_init_*` impls call
/// this on the first-write path and seal the two privates under the
/// content master before persisting.
#[allow(clippy::type_complexity)]
pub fn mint_content_kem_keypair(
) -> Result<([u8; 32], [u8; 32], Vec<u8>, Vec<u8>), crate::federation::BlobError> {
    let (x_priv, x_pub) = ciris_crypto::x25519::generate_ephemeral_keypair().map_err(|e| {
        crate::federation::BlobError::Backend(format!("content-kem x25519 keygen: {e}"))
    })?;
    let (ml_priv, ml_pub) = ciris_crypto::ml_kem::generate_keypair().map_err(|e| {
        crate::federation::BlobError::Backend(format!("content-kem ml-kem keygen: {e}"))
    })?;
    Ok((x_priv, x_pub, ml_priv, ml_pub))
}

/// Seal a content-KEM private half under the content master, mirroring
/// the self/family DEK self-retention wrap
/// ([`crate::federation::at_rest_cascade::wrap_dek_for_persist`]):
/// base64 of `nonce(12) ‖ aes256_gcm(content_master, sk)`. Generic over
/// the secret length (x25519 = 32, ML-KEM-768 private = 64).
pub fn seal_content_kem_private(
    content_master: &[u8; 32],
    private_key: &[u8],
) -> Result<String, crate::federation::BlobError> {
    use crate::federation::at_rest_cascade::NONCE_LEN;
    let nv = ciris_crypto::random::bytes(NONCE_LEN).map_err(|e| {
        crate::federation::BlobError::Backend(format!("content-kem seal nonce: {e}"))
    })?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nv);
    let ct = ciris_crypto::aes_gcm::encrypt(content_master, &nonce, private_key)
        .map_err(|e| crate::federation::BlobError::Backend(format!("content-kem seal: {e}")))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(B64.encode(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_content_kem_keypair_is_independent_and_well_sized() {
        let (x_priv, x_pub, ml_priv, ml_pub) = mint_content_kem_keypair().unwrap();
        assert_eq!(x_pub.len(), 32);
        assert_eq!(ml_pub.len(), ciris_crypto::ml_kem::ML_KEM_768_PUBKEY_LEN);
        // Two independent draws differ (the public x25519 is not its own
        // private, and a second mint differs from the first).
        assert_ne!(x_pub.to_vec(), x_priv.to_vec());
        let (_, x_pub2, _, _) = mint_content_kem_keypair().unwrap();
        assert_ne!(x_pub.to_vec(), x_pub2.to_vec());
        assert!(!ml_priv.is_empty());
    }

    #[test]
    fn seal_content_kem_private_round_trips_via_wrap_discipline() {
        use crate::federation::at_rest_cascade::{unwrap_dek_for_persist, DEK_LEN};
        let master = [0x42u8; 32];
        // A 32-byte secret round-trips through the persist self-wrap pair
        // (the seal uses the identical AES-GCM construction).
        let secret = [0x07u8; DEK_LEN];
        let sealed = seal_content_kem_private(&master, &secret).unwrap();
        let back = unwrap_dek_for_persist(&master, &sealed).unwrap();
        assert_eq!(back, secret);
    }

    #[test]
    fn assemble_v1_shape_signing_and_kem_present_ret_none() {
        let agg = LocalIdentityAggregate::assemble(
            "lens-steward".into(),
            Some("lens-steward-mldsa".into()),
            "ZWQyNXNpZ24=".into(),
            Some("bWxkc2E2NQ==".into()),
            None,
            None,
            Some("a2VteDI1NTE5".into()),
            Some("a2VtbWxrZW0=".into()),
            1_700_000_000_000,
        );
        assert_eq!(agg.aggregate_version, 1);
        assert!(agg.reticulum_x25519_pubkey_b64.is_none());
        assert!(agg.reticulum_ed25519_pubkey_b64.is_none());
        assert!(agg.content_x25519_pubkey_b64.is_some());
        assert!(agg.did_key.is_none());
        assert_eq!(agg.identity_hash.len(), 64); // sha256 hex
    }

    #[test]
    fn identity_hash_changes_when_a_present_field_changes() {
        let base = LocalIdentityAggregate::assemble(
            "k".into(),
            None,
            "AAAA".into(),
            None,
            None,
            None,
            Some("BBBB".into()),
            Some("CCCC".into()),
            0,
        );
        let changed = LocalIdentityAggregate::assemble(
            "k".into(),
            None,
            "AAAA".into(),
            None,
            None,
            None,
            Some("BBBB".into()),
            Some("DDDD".into()), // ml-kem pubkey differs
            0,
        );
        assert_ne!(base.identity_hash, changed.identity_hash);
    }

    #[test]
    fn identity_hash_absent_vs_empty_do_not_collide() {
        let absent = LocalIdentityAggregate::assemble(
            "k".into(),
            None,
            "AAAA".into(),
            None,
            None,
            None,
            None,
            None,
            0,
        );
        let empty = LocalIdentityAggregate::assemble(
            "k".into(),
            None,
            "AAAA".into(),
            None,
            None,
            None,
            Some(String::new()),
            None,
            0,
        );
        assert_ne!(absent.identity_hash, empty.identity_hash);
    }

    #[test]
    fn aggregate_round_trips_through_serde_json() {
        let agg = LocalIdentityAggregate::assemble(
            "lens-steward".into(),
            Some("lens-steward-mldsa".into()),
            "ZWQyNXNpZ24=".into(),
            Some("bWxkc2E2NQ==".into()),
            None,
            None,
            Some("a2VteDI1NTE5".into()),
            Some("a2VtbWxrZW0=".into()),
            1_700_000_000_000,
        );
        let json = serde_json::to_string(&agg).unwrap();
        let back: LocalIdentityAggregate = serde_json::from_str(&json).unwrap();
        assert_eq!(agg, back);
    }
}
