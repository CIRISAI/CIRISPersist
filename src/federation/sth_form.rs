//! v62.0.0 (slice D, CIRISVerify 23 composite cut) — **the signature FORM of
//! a transparency head or witness cosignature, read by form and signed by
//! ceremony state.**
//!
//! CIRISVerify 23.0.0 changed [`SignedTreeHead::signature`] and
//! [`WitnessSignature::signature`] from a bound-hybrid
//! [`HybridSignature`](ciris_crypto::HybridSignature) to raw bytes, and its own
//! readers expect the CC 2.6.1.7 composite ML-DSA-65-Ed25519 (3373 bytes). CC
//! rc20 keeps the EARLIER form valid: a head or cosignature signed under it
//! still verifies (CC 8.11, the bound-hybrid form at CC 8.11.12), and a node
//! WRITES the earlier form until it holds the edition-2 ceremony row (CC
//! ruling D4). So persist carries both forms in the one byte field:
//!
//! - **earlier form** — the bound-hybrid `HybridSignature` as its JSON bytes,
//!   exactly the bytes persist's `signature_blob` columns already hold (v61
//!   and earlier). A v61 row reads back unchanged;
//! - **composite form** — the 3373-byte `mldsaSig || ed25519Sig`.
//!
//! [`classify`] decides the form from the bytes alone (never from a date or a
//! build flag); every verifier dispatches on it. [`sign_sth`] picks the form
//! to WRITE from the node's [`CeremonyState`]: earlier before the ceremony row
//! is held, composite after. The composite branch needs the keyring's FIPS 204
//! context-sign (CIRISVerify 23.1.3, `PqcSigner::sign_with_context`); a
//! signer without it refuses by name
//! ([`LocalSignerError::CompositeUnavailable`](crate::signing::LocalSignerError)).
//!
//! The three logs ride this one module: the audit log (`audit::merkle_store`,
//! persist-signed), the trust-grant receipts (the same tree), and the
//! per-stream logs (`stream_sth`, producer-signed).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::composite::{CompositePublicKey, SIGNATURE_LEN};
use ciris_crypto::HybridSignature;
use ciris_verify_core::transparency::{SignedTreeHead, WitnessSignature};

/// The two signature forms a head or cosignature may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureForm {
    /// CC 8.11.12: the bound-hybrid `HybridSignature`, as JSON bytes.
    Earlier,
    /// CC 2.6.1.7: the 3373-byte composite.
    Composite,
}

/// A classified signature.
#[derive(Debug, Clone)]
pub enum FormedSignature<'a> {
    /// The earlier form, parsed.
    Earlier(Box<HybridSignature>),
    /// The composite form, as given.
    Composite(&'a [u8]),
}

/// The bytes are neither form: a refusal, never absence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "signature_form_unrecognized: {len} bytes are neither an earlier-form (CC 8.11.12) \
     bound-hybrid signature nor a {SIGNATURE_LEN}-byte composite (CC 2.6.1.7)"
)]
pub struct UnrecognizedForm {
    /// The length of the bytes that classified as neither.
    pub len: usize,
}

/// Classify signature bytes by FORM. A composite is binary of exactly
/// [`SIGNATURE_LEN`] bytes; the earlier form is a JSON object that parses as a
/// `HybridSignature`. The two cannot collide: JSON text of that length that
/// parsed would be the earlier form, and composite bytes are not JSON.
///
/// # Errors
/// [`UnrecognizedForm`] when the bytes are neither.
pub fn classify(sig: &[u8]) -> Result<FormedSignature<'_>, UnrecognizedForm> {
    if sig.first() == Some(&b'{') {
        if let Ok(h) = serde_json::from_slice::<HybridSignature>(sig) {
            return Ok(FormedSignature::Earlier(Box::new(h)));
        }
    }
    if sig.len() == SIGNATURE_LEN {
        return Ok(FormedSignature::Composite(sig));
    }
    Err(UnrecognizedForm { len: sig.len() })
}

/// The form of `sig`, if it has one.
#[must_use]
pub fn form_of(sig: &[u8]) -> Option<SignatureForm> {
    match classify(sig) {
        Ok(FormedSignature::Earlier(_)) => Some(SignatureForm::Earlier),
        Ok(FormedSignature::Composite(_)) => Some(SignatureForm::Composite),
        Err(_) => None,
    }
}

/// The earlier-form bytes of a bound-hybrid signature: its JSON, the encoding
/// persist's `signature_blob` columns have always held.
///
/// # Errors
/// A serde fault (never expected for a `HybridSignature`).
pub fn earlier_form_bytes(sig: &HybridSignature) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(sig)
}

/// The `merkle_sth_log.signer_key_id` column for a head signature: for the
/// earlier form, the hex of the Ed25519 key the signature carries (what every
/// pre-v62 row holds); a composite carries no key, so the column is empty
/// (the verifier pins the signer; the column was never an authority).
#[must_use]
pub fn signer_column(sig: &[u8]) -> String {
    match classify(sig) {
        Ok(FormedSignature::Earlier(h)) => hex::encode(&h.classical.public_key),
        _ => String::new(),
    }
}

/// Does this node hold the edition-2 ceremony row (CC ruling D4)?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyState {
    /// No ceremony row is held: write the earlier form.
    NotHeld,
    /// The ceremony row is held: write the composite.
    Held,
}

impl CeremonyState {
    /// The form a node in this state writes.
    #[must_use]
    pub fn writes(self) -> SignatureForm {
        match self {
            Self::NotHeld => SignatureForm::Earlier,
            Self::Held => SignatureForm::Composite,
        }
    }
}

/// The node's ceremony state. **No edition-2 ceremony row exists yet**: its
/// kind is defined by the edition-2 ceremony set CIRISVerify ships in 23.x
/// (genesis bundle and revocation snapshot payloads, trust root on edition 2,
/// the cutover proof), and persist's edition-2 slice admits it. Until that
/// row kind exists no node can hold it, so every node is
/// [`CeremonyState::NotHeld`] and writes the earlier form, as CC D4 rules.
/// The one place the answer is read; the ceremony slice replaces this body
/// with the directory read.
#[must_use]
pub fn ceremony_state() -> CeremonyState {
    CeremonyState::NotHeld
}

/// Sign transparency-head (or cosignature) `bytes` in the form `ceremony`
/// writes. Earlier form: `LocalSigner::sign_hybrid`, as JSON bytes. Composite:
/// `LocalSigner::sign_composite`.
///
/// # Errors
/// The signer's error; [`LocalSignerError::CompositeUnavailable`](crate::signing::LocalSignerError::CompositeUnavailable)
/// from a signer without a context-sign.
pub async fn sign_sth(
    signer: &crate::signing::LocalSigner,
    bytes: &[u8],
    ceremony: CeremonyState,
) -> Result<Vec<u8>, crate::signing::LocalSignerError> {
    match ceremony.writes() {
        SignatureForm::Earlier => {
            let sig = signer.sign_hybrid(bytes).await?;
            earlier_form_bytes(&sig).map_err(|e| {
                crate::signing::LocalSignerError::PqcSign(format!("earlier-form encode: {e}"))
            })
        }
        SignatureForm::Composite => signer.sign_composite(bytes).await,
    }
}

/// Why a signature did not verify.
#[derive(Debug, thiserror::Error)]
pub enum FormVerifyError {
    /// The bytes are neither form.
    #[error(transparent)]
    Unrecognized(#[from] UnrecognizedForm),
    /// The pinned keys cannot verify this form (no ML-DSA-65 key, a key that
    /// does not decode).
    #[error("signature_key_unusable: {0}")]
    Key(String),
    /// The signature does not verify.
    #[error("signature_invalid ({form:?}): {detail}")]
    Invalid {
        /// The form that was checked.
        form: SignatureForm,
        /// What failed.
        detail: String,
    },
}

/// The pinned keys a signature verifies under: a federation key's two halves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedKeys {
    /// Ed25519, 32 bytes, base64.
    pub ed25519_base64: String,
    /// ML-DSA-65, 1952 bytes, base64. `None` verifies neither form (both
    /// forms need the PQC half under Strict).
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

    /// The two halves, decoded: `(ed25519, ml_dsa_65)`.
    ///
    /// # Errors
    /// [`FormVerifyError::Key`] when a half is missing or not base64.
    pub fn decoded(&self) -> Result<(Vec<u8>, Vec<u8>), FormVerifyError> {
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
        Ok((ed, pqc))
    }

    /// The 1984-byte composite key `mldsaPK || ed25519PK`.
    ///
    /// # Errors
    /// [`FormVerifyError::Key`] when a half is missing or does not decode.
    pub fn composite(&self) -> Result<CompositePublicKey, FormVerifyError> {
        let (ed, pqc) = self.decoded()?;
        CompositePublicKey::from_halves(&pqc, &ed).map_err(|e| FormVerifyError::Key(format!("{e}")))
    }
}

/// Verify `sig`, a signature over `sth`'s signing bytes (the operator's own,
/// or a witness cosignature: both cover [`SignedTreeHead::signing_bytes_of`]),
/// under `pinned`, dispatched by FORM:
///
/// - earlier (CC 8.11.12): CIRISVerify's `earlier_form::EarlierSignedTreeHead`
///   over the same head fields, whose `verify` requires the keys the
///   signature carries to BE the pinned ones and then the bound hybrid;
/// - composite (CC 2.6.1.7): under the pinned composite key.
///
/// Keys come from the caller's pinned state, never from the signature.
///
/// # Errors
/// [`FormVerifyError`] naming the form and the failure.
pub fn verify_sth_signature(
    sth: &SignedTreeHead,
    sig: &[u8],
    pinned: &PinnedKeys,
) -> Result<SignatureForm, FormVerifyError> {
    match classify(sig)? {
        FormedSignature::Earlier(h) => {
            let (ed, pqc) = pinned.decoded()?;
            let earlier = ciris_verify_core::earlier_form::EarlierSignedTreeHead {
                log_id: sth.log_id.clone(),
                tree_size: sth.tree_size,
                root_hash: sth.root_hash,
                timestamp: sth.timestamp,
                signature: *h,
                witness_signatures: Vec::new(),
            };
            if earlier.verify(&ed, &pqc) {
                Ok(SignatureForm::Earlier)
            } else {
                Err(FormVerifyError::Invalid {
                    form: SignatureForm::Earlier,
                    detail: "the bound-hybrid signature does not verify under the pinned keys \
                             (CC 8.11.12)"
                        .into(),
                })
            }
        }
        FormedSignature::Composite(c) => {
            pinned
                .composite()?
                .verify(&sth.signing_bytes_of(), c)
                .map_err(|e| FormVerifyError::Invalid {
                    form: SignatureForm::Composite,
                    detail: e.to_string(),
                })?;
            Ok(SignatureForm::Composite)
        }
    }
}

/// Resolve `key_id` in `directory` and [`verify_sth_signature`].
///
/// # Errors
/// [`FormVerifyError::Key`] for an unknown key; otherwise as
/// [`verify_sth_signature`]. A directory fault is a `Key` refusal (fail
/// closed).
pub async fn verify_sth_signature_via_directory<F>(
    directory: &F,
    sth: &SignedTreeHead,
    key_id: &str,
    sig: &[u8],
) -> Result<SignatureForm, FormVerifyError>
where
    F: super::FederationDirectory + ?Sized,
{
    let rec = directory
        .lookup_public_key(key_id)
        .await
        .map_err(|e| FormVerifyError::Key(format!("key {key_id:?}: directory: {e}")))?
        .ok_or_else(|| FormVerifyError::Key(format!("key {key_id:?} is not registered")))?;
    verify_sth_signature(sth, sig, &PinnedKeys::of(&rec))
}

/// A witness this verifier trusts, with its pinned keys (the persist
/// counterpart of Verify's `TrustedWitness`, which pins only a composite key
/// and so cannot count an earlier-form cosignature).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedWitness {
    /// The witness id (matches `WitnessSignature::witness_id`).
    pub witness_id: String,
    /// Its pinned keys.
    pub keys: PinnedKeys,
}

/// Count the DISTINCT trusted witnesses that validly cosigned `sth`, each
/// cosignature verified by its form under the witness's PINNED keys
/// (CEG 0.2 §10.3.1, Verify's `count_valid_witnesses` rules):
///
/// 1. a repeated `witness_id` counts once;
/// 2. an untrusted witness, or one whose pinned key does not decode, does not
///    count;
/// 3. the cosignature's consistency proof must chain to `(tree_size,
///    root_hash)`;
/// 4. the signature verifies over `signing_bytes_of()` under the pinned keys.
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

/// Rewrite a JSON value of a [`SignedTreeHead`] (or a list of
/// [`WitnessSignature`]s) so an EARLIER-form signature, carried as the v22
/// `HybridSignature` object, becomes the base64 of its JSON bytes, the shape
/// Verify 23's serde reads. Composite signatures (already base64 strings) are
/// left alone. Walks `signature` on the head and on each witness.
pub fn normalize_signature_json(value: &mut serde_json::Value) {
    fn fix(sig: &mut serde_json::Value) {
        if sig.is_object() {
            if let Ok(bytes) = serde_json::to_vec(sig) {
                *sig = serde_json::Value::String(B64.encode(bytes));
            }
        }
    }
    match value {
        serde_json::Value::Array(ws) => {
            for w in ws {
                if let Some(sig) = w.get_mut("signature") {
                    fix(sig);
                }
            }
        }
        serde_json::Value::Object(o) => {
            if let Some(sig) = o.get_mut("signature") {
                fix(sig);
            }
            if let Some(ws) = o.get_mut("witness_signatures") {
                normalize_signature_json(ws);
            }
        }
        _ => {}
    }
}

/// Parse a [`SignedTreeHead`] from JSON in either form (see
/// [`normalize_signature_json`]).
///
/// # Errors
/// The serde error.
pub fn sth_from_json(mut value: serde_json::Value) -> Result<SignedTreeHead, serde_json::Error> {
    normalize_signature_json(&mut value);
    serde_json::from_value(value)
}

/// Parse a stored witness list in either form.
///
/// # Errors
/// The serde error.
pub fn witnesses_from_json(raw: &str) -> Result<Vec<WitnessSignature>, serde_json::Error> {
    let mut value: serde_json::Value = serde_json::from_str(raw)?;
    normalize_signature_json(&mut value);
    serde_json::from_value(value)
}

/// Test support: earlier-form cosignatures and heads from a bound-hybrid
/// test signer (the producer side of the CC 8.11.12 form, which Verify 23
/// does not ship and production never writes after the ceremony row).
#[cfg(any(test, feature = "test-anchor"))]
pub mod test_support {
    use ciris_crypto::{Ed25519Signer, HybridSigner, MlDsa65Signer};
    use ciris_verify_core::transparency::{
        SignedTreeHead, TransparencyError, WitnessConsistencyProof, WitnessSignature,
    };

    /// The earlier-form signature `sth` carries, parsed (panics on a
    /// composite: test-only).
    #[must_use]
    pub fn earlier_of(sig: &[u8]) -> ciris_crypto::HybridSignature {
        serde_json::from_slice(sig).expect("an earlier-form signature")
    }

    /// `sth` with its earlier-form signature edited by `f` and re-encoded.
    #[must_use]
    pub fn edit_earlier(
        sth: &SignedTreeHead,
        f: impl FnOnce(&mut ciris_crypto::HybridSignature),
    ) -> SignedTreeHead {
        let mut h = earlier_of(&sth.signature);
        f(&mut h);
        let mut out = sth.clone();
        out.signature = super::earlier_form_bytes(&h).expect("earlier-form encode");
        out
    }

    /// The bound-hybrid test signer the stores' tests use.
    pub type EarlierSigner = HybridSigner<Ed25519Signer, MlDsa65Signer>;

    /// An earlier-form signature over `bytes`, as the stored bytes.
    ///
    /// # Panics
    /// On a signer fault (test-only).
    #[must_use]
    pub fn earlier_sign(signer: &EarlierSigner, bytes: &[u8]) -> Vec<u8> {
        super::earlier_form_bytes(&signer.sign(bytes).expect("bound-hybrid sign"))
            .expect("earlier-form encode")
    }

    /// An earlier-form witness cosignature over `sth`, after checking the
    /// consistency proof as Verify's `cosign` does.
    ///
    /// # Errors
    /// The consistency proof's refusal.
    pub fn earlier_cosign(
        sth: &SignedTreeHead,
        witness_id: impl Into<String>,
        signer: &EarlierSigner,
        consistency_proof: WitnessConsistencyProof,
    ) -> Result<WitnessSignature, TransparencyError> {
        consistency_proof.verify(sth.tree_size, &sth.root_hash)?;
        Ok(WitnessSignature {
            witness_id: witness_id.into(),
            signature: earlier_sign(signer, &sth.signing_bytes_of()),
            consistency_proof,
        })
    }
}
