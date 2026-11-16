//! v62.0.0 (slice D, CIRISVerify 23 composite cut; CC rc20 "nothing carries,
//! clean mesh") — **a transparency head's or witness cosignature's
//! signature: the composite, and only the composite.**
//!
//! CIRISVerify 23 changed [`SignedTreeHead::signature`] and
//! [`WitnessSignature::signature`] to raw bytes: the CC 2.6.1.7 composite
//! ML-DSA-65-Ed25519 (3373 bytes, `mldsaSig || ed25519Sig`). A v62 node starts
//! at its edition-2 genesis and reads ONLY edition-2 objects (rc20 0c9e17c):
//!
//! - every head and cosignature it WRITES is a composite ([`sign_sth`]);
//! - a head or cosignature arriving in the EARLIER (bound-hybrid
//!   `HybridSignature`) form is refused at the door by name
//!   ([`SthFormRefusal::EarlierForm`], `sth_signature_earlier_form`), never
//!   verified;
//! - an earlier-form head this node's own store holds from before the
//!   upgrade is refused by name on read, never served
//!   (`TODO(archive-ruling)`: the operator ruling on the pre-v62 store, kept
//!   as an archive and never read, is open).
//!
//! The three logs ride this one module: the audit log (`audit::merkle_store`,
//! persist-signed), the trust-grant receipts (the same tree), and the
//! per-stream logs (`stream_sth`, producer-signed).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::composite::{CompositePublicKey, SIGNATURE_LEN};
use ciris_verify_core::transparency::{SignedTreeHead, WitnessSignature};

/// The stable token of an earlier-form refusal.
pub const STH_SIGNATURE_EARLIER_FORM: &str = "sth_signature_earlier_form";
/// The stable token of a refusal of bytes in no form at all.
pub const STH_SIGNATURE_UNRECOGNIZED: &str = "sth_signature_unrecognized";

/// Why signature bytes are not a composite.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SthFormRefusal {
    /// The earlier (CC 8.11.12 bound-hybrid) form: a pre-v62 object. A v62
    /// node reads only edition-2 objects (CC rc20, "nothing carries").
    #[error(
        "sth_signature_earlier_form: a bound-hybrid (pre-edition-2) signature; a v62 node \
         reads only CC 2.6.1.7 composites (nothing carries into the edition)"
    )]
    EarlierForm,
    /// Not a composite and not the earlier form either.
    #[error("sth_signature_unrecognized: {len} bytes are not a {SIGNATURE_LEN}-byte composite")]
    Unrecognized {
        /// The length of the bytes refused.
        len: usize,
    },
}

impl SthFormRefusal {
    /// The stable token.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            Self::EarlierForm => STH_SIGNATURE_EARLIER_FORM,
            Self::Unrecognized { .. } => STH_SIGNATURE_UNRECOGNIZED,
        }
    }
}

/// The composite in `sig`, or the named refusal. The earlier form is the
/// `HybridSignature` JSON object every pre-v62 `signature_blob` holds; it is
/// recognised only to be refused by name.
///
/// # Errors
/// [`SthFormRefusal`].
pub fn classify(sig: &[u8]) -> Result<&[u8], SthFormRefusal> {
    if sig.len() == SIGNATURE_LEN {
        return Ok(sig);
    }
    if sig.first() == Some(&b'{')
        && serde_json::from_slice::<ciris_crypto::HybridSignature>(sig).is_ok()
    {
        return Err(SthFormRefusal::EarlierForm);
    }
    Err(SthFormRefusal::Unrecognized { len: sig.len() })
}

/// Sign transparency-head (or cosignature) `bytes`: the composite, through
/// [`LocalSigner::sign_composite`](crate::signing::LocalSigner::sign_composite)
/// (the keyring's FIPS 204 context-sign plus `composite::assemble_composite`).
///
/// # Errors
/// The signer's error; [`LocalSignerError::CompositeUnavailable`](crate::signing::LocalSignerError::CompositeUnavailable)
/// from a PQC signer without context-sign.
pub async fn sign_sth(
    signer: &crate::signing::LocalSigner,
    bytes: &[u8],
) -> Result<Vec<u8>, crate::signing::LocalSignerError> {
    signer.sign_composite(bytes).await
}

/// Why a signature did not verify.
#[derive(Debug, thiserror::Error)]
pub enum FormVerifyError {
    /// Not a composite (earlier form or unrecognized), refused by name.
    #[error(transparent)]
    Form(#[from] SthFormRefusal),
    /// The pinned keys cannot form a composite key (no ML-DSA-65 key, a key
    /// that does not decode).
    #[error("signature_key_unusable: {0}")]
    Key(String),
    /// The composite does not verify.
    #[error("signature_invalid: {0}")]
    Invalid(String),
}

/// The pinned keys a signature verifies under: a federation key's two halves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedKeys {
    /// Ed25519, 32 bytes, base64.
    pub ed25519_base64: String,
    /// ML-DSA-65, 1952 bytes, base64. `None` verifies nothing.
    pub ml_dsa_65_base64: Option<String>,
}

impl PinnedKeys {
    /// From a `federation_keys` row.
    #[must_use]
    pub fn of(rec: &super::types::KeyRecord) -> Self {
        Self {
            ed25519_base64: rec.pubkey_ed25519_base64.clone(),
            ml_dsa_65_base64: rec.pubkey_ml_dsa_65_base64.clone(),
        }
    }

    /// The 1984-byte composite key `mldsaPK || ed25519PK`.
    ///
    /// # Errors
    /// [`FormVerifyError::Key`] when a half is missing or does not decode.
    pub fn composite(&self) -> Result<CompositePublicKey, FormVerifyError> {
        let key = |m: String| FormVerifyError::Key(m);
        let pqc = self
            .ml_dsa_65_base64
            .as_deref()
            .ok_or_else(|| key("no ML-DSA-65 key is pinned".into()))?;
        let pqc = B64
            .decode(pqc)
            .map_err(|e| key(format!("ML-DSA-65 key base64: {e}")))?;
        let ed = B64
            .decode(&self.ed25519_base64)
            .map_err(|e| key(format!("Ed25519 key base64: {e}")))?;
        CompositePublicKey::from_halves(&pqc, &ed).map_err(|e| key(format!("{e}")))
    }
}

/// Verify `sig`, a signature over `sth`'s signing bytes (the operator's own,
/// or a witness cosignature: both cover [`SignedTreeHead::signing_bytes_of`]),
/// under the PINNED composite key. The earlier form is refused by name.
///
/// # Errors
/// [`FormVerifyError`].
pub fn verify_sth_signature(
    sth: &SignedTreeHead,
    sig: &[u8],
    pinned: &PinnedKeys,
) -> Result<(), FormVerifyError> {
    let c = classify(sig)?;
    pinned
        .composite()?
        .verify(&sth.signing_bytes_of(), c)
        .map_err(|e| FormVerifyError::Invalid(e.to_string()))
}

/// Resolve `key_id` in `directory` and [`verify_sth_signature`].
///
/// # Errors
/// [`FormVerifyError::Key`] for an unknown key or a directory fault (fail
/// closed); otherwise as [`verify_sth_signature`].
pub async fn verify_sth_signature_via_directory<F>(
    directory: &F,
    sth: &SignedTreeHead,
    key_id: &str,
    sig: &[u8],
) -> Result<(), FormVerifyError>
where
    F: super::FederationDirectory + ?Sized,
{
    // The form first: an earlier-form object is refused by name before any
    // key is looked up.
    classify(sig)?;
    let rec = directory
        .lookup_public_key(key_id)
        .await
        .map_err(|e| FormVerifyError::Key(format!("key {key_id:?}: directory: {e}")))?
        .ok_or_else(|| FormVerifyError::Key(format!("key {key_id:?} is not registered")))?;
    verify_sth_signature(sth, sig, &PinnedKeys::of(&rec))
}

/// A witness this verifier trusts, with its pinned keys (the persist
/// counterpart of Verify's `TrustedWitness`, resolved from `federation_keys`
/// halves).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedWitness {
    /// The witness id (matches `WitnessSignature::witness_id`).
    pub witness_id: String,
    /// Its pinned keys.
    pub keys: PinnedKeys,
}

/// Count the DISTINCT trusted witnesses that validly cosigned `sth`, each
/// cosignature verified under the witness's PINNED composite key (CEG 0.2
/// §10.3.1, Verify's `count_valid_witnesses` rules):
///
/// 1. a repeated `witness_id` counts once;
/// 2. an untrusted witness, or one whose pinned key does not decode, does not
///    count;
/// 3. the cosignature's consistency proof must chain to `(tree_size,
///    root_hash)`;
/// 4. the composite verifies over `signing_bytes_of()` under the pinned key
///    (an earlier-form cosignature never counts).
#[must_use]
pub fn count_valid_witnesses(sth: &SignedTreeHead, trusted: &[PinnedWitness]) -> usize {
    let mut counted: Vec<&str> = Vec::new();
    for ws in &sth.witness_signatures {
        if counted.contains(&ws.witness_id.as_str()) {
            continue;
        }
        let Some(tw) = trusted.iter().find(|t| t.witness_id == ws.witness_id) else {
            continue;
        };
        if ws
            .consistency_proof
            .verify(sth.tree_size, &sth.root_hash)
            .is_err()
        {
            continue;
        }
        if verify_sth_signature(sth, &ws.signature, &tw.keys).is_ok() {
            counted.push(&ws.witness_id);
        }
    }
    counted.len()
}

/// Whether `quorum` distinct trusted witnesses validly cosigned `sth`.
#[must_use]
pub fn witness_quorum_met(sth: &SignedTreeHead, trusted: &[PinnedWitness], quorum: usize) -> bool {
    count_valid_witnesses(sth, trusted) >= quorum
}

/// Why a head's JSON was refused.
#[derive(Debug, thiserror::Error)]
pub enum SthJsonError {
    /// A signature in the wrong form.
    #[error(transparent)]
    Form(#[from] SthFormRefusal),
    /// Not a head.
    #[error("sth json: {0}")]
    Json(serde_json::Error),
}

fn carries_an_object_signature(value: &serde_json::Value) -> bool {
    value
        .get("signature")
        .is_some_and(serde_json::Value::is_object)
}

/// Parse a [`SignedTreeHead`] from JSON. A head carrying its signature (or a
/// witness's) as the v22 `HybridSignature` OBJECT is the earlier form and is
/// refused by name rather than as a serde type error.
///
/// # Errors
/// [`SthJsonError`].
pub fn sth_from_json(value: serde_json::Value) -> Result<SignedTreeHead, SthJsonError> {
    let earlier = carries_an_object_signature(&value)
        || value
            .get("witness_signatures")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|ws| ws.iter().any(carries_an_object_signature));
    if earlier {
        return Err(SthJsonError::Form(SthFormRefusal::EarlierForm));
    }
    let sth: SignedTreeHead = serde_json::from_value(value).map_err(SthJsonError::Json)?;
    classify(&sth.signature)?;
    for ws in &sth.witness_signatures {
        classify(&ws.signature)?;
    }
    Ok(sth)
}

/// Parse a stored witness list. A pre-v62 row (each signature the
/// `HybridSignature` object) is the earlier form: refused by name.
/// `TODO(archive-ruling)`: the pre-v62 store is to be kept as an archive and
/// never read (operator ruling open); until then its rows refuse here.
///
/// # Errors
/// [`SthJsonError`].
pub fn witnesses_from_json(raw: &str) -> Result<Vec<WitnessSignature>, SthJsonError> {
    let value: serde_json::Value = serde_json::from_str(raw).map_err(SthJsonError::Json)?;
    if value
        .as_array()
        .is_some_and(|ws| ws.iter().any(carries_an_object_signature))
    {
        return Err(SthJsonError::Form(SthFormRefusal::EarlierForm));
    }
    let ws: Vec<WitnessSignature> = serde_json::from_value(value).map_err(SthJsonError::Json)?;
    for w in &ws {
        classify(&w.signature)?;
    }
    Ok(ws)
}

/// The `merkle_sth_log.signer_key_id` column for a head: a composite carries
/// no key of its own, so the column is empty (the verifier pins the signer;
/// the column was never an authority).
#[must_use]
pub fn signer_column(_sig: &[u8]) -> String {
    String::new()
}

/// Test support: composite test keys, and the earlier form persist refuses.
#[cfg(any(test, feature = "test-anchor"))]
pub mod test_support {
    use ciris_crypto::composite::CompositeSigningKey;

    /// A composite key from the seeds a bound-hybrid test signer uses
    /// (`MlDsa65Signer::from_seed(mldsa)`, `Ed25519Signer::from_seed(ed)`):
    /// the same two public keys, so a key record registered from that signer
    /// verifies it.
    #[must_use]
    pub fn composite(mldsa_seed: [u8; 32], ed_seed: [u8; 32]) -> CompositeSigningKey {
        CompositeSigningKey::from_seeds(&mldsa_seed, &ed_seed)
    }

    /// A composite cosignature over `sth` (Verify's `cosign`: the
    /// consistency proof is checked first).
    ///
    /// # Errors
    /// The consistency proof's refusal or the signer's.
    pub fn cosign(
        sth: &ciris_verify_core::transparency::SignedTreeHead,
        witness_id: impl Into<String>,
        signer: &CompositeSigningKey,
        consistency_proof: ciris_verify_core::transparency::WitnessConsistencyProof,
    ) -> Result<
        ciris_verify_core::transparency::WitnessSignature,
        ciris_verify_core::transparency::TransparencyError,
    > {
        sth.cosign(witness_id, signer, consistency_proof)
    }

    /// An earlier-form (v61, bound-hybrid JSON) signature over `bytes`, as
    /// the stored bytes a pre-v62 row holds: what the v62 door refuses by
    /// name.
    ///
    /// # Panics
    /// On a signer fault (test-only).
    #[must_use]
    pub fn earlier_bytes(mldsa_seed: [u8; 32], ed_seed: [u8; 32], bytes: &[u8]) -> Vec<u8> {
        let ed = ciris_crypto::Ed25519Signer::from_seed(&ed_seed).expect("ed25519 seed");
        let ml = ciris_crypto::MlDsa65Signer::from_seed(&mldsa_seed).expect("ml-dsa seed");
        let h = ciris_crypto::HybridSigner::new(ed, ml)
            .expect("hybrid signer")
            .sign(bytes)
            .expect("bound-hybrid sign");
        serde_json::to_vec(&h).expect("earlier-form encode")
    }
}
