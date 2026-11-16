//! v62.0.0 (slice D, CIRISVerify 23 composite cut) — **a §19 substrate
//! object's signature, verified by FORM.**
//!
//! CIRISVerify 23.0.0 moved the §19 verifiers (`verify_witness`,
//! `verify_aggregation_meta`, `verify_storage_budget_v1`,
//! `verify_corpus_want_v1`) to the CC 2.6.1.7 composite (`(sig,
//! composite_pubkey)` through `substrate::verify_composite`) and removed the
//! bound-hybrid verifier. CC rc20 keeps the EARLIER form valid: an object
//! signed under it still verifies (CC 8.11, the bound-hybrid form at CC
//! 8.11.12: Ed25519 over the preimage, ML-DSA-65 over `preimage ‖
//! ed25519_sig`, both mandatory). So persist dispatches on the form the
//! caller presents:
//!
//! - [`Sig19::Composite`]: Verify's own composite verifier;
//! - [`Sig19::Earlier`]: Verify's `earlier_form::verify_bound_hybrid`
//!   (CIRISVerify 23.1.2, verify-only), over the SAME preimage
//!   (`canonical_preimage()` / `signing_preimage()`, unchanged by the cut).
//!
//! The structural checks each Verify function makes besides the signature
//! (namespace guard, leaf recompute, `validate()`) are run by the callers for
//! the earlier form, in Verify's order. [`sign_sig19`] writes the form the
//! node's ceremony state names (CC D4).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

pub use crate::federation::sth_form::SignatureForm;

/// A §19 signature in one of its two forms (raw bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sig19 {
    /// CC 8.11.12: the bound-hybrid pair. `mldsa65: None` is the §19.0 hard
    /// cut (refused, never classical-only).
    Earlier {
        /// Ed25519 over the preimage.
        ed25519: Vec<u8>,
        /// ML-DSA-65 over `preimage ‖ ed25519`.
        mldsa65: Option<Vec<u8>>,
    },
    /// CC 2.6.1.7: the 3373-byte composite.
    Composite(Vec<u8>),
}

/// Why a §19 signature was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Sig19Error {
    /// A field is not base64, or the JSON form is not one of the two.
    #[error("sig19_malformed: {0}")]
    Malformed(String),
    /// Earlier form: the ML-DSA-65 half is missing (the §19.0 hard cut).
    #[error("sig19_hybrid_required: the earlier-form signature carries no ML-DSA-65 half")]
    HybridRequired,
    /// Earlier form: the bound-hybrid pair does not verify (CC 8.11.12;
    /// which half is not said).
    #[error("sig19_earlier_invalid")]
    EarlierInvalid,
    /// A key or signature has the wrong length or does not decode.
    #[error("sig19_malformed_key_or_signature")]
    MalformedKeyOrSignature,
    /// Composite: the signature does not verify (which half is not said).
    #[error("sig19_composite_invalid")]
    CompositeInvalid,
}

impl Sig19 {
    /// The form.
    #[must_use]
    pub fn form(&self) -> SignatureForm {
        match self {
            Self::Earlier { .. } => SignatureForm::Earlier,
            Self::Composite(_) => SignatureForm::Composite,
        }
    }

    /// The earlier form from its two base64 halves (an empty or absent
    /// ML-DSA-65 half is kept as `None`, refused at verify).
    ///
    /// # Errors
    /// [`Sig19Error::Malformed`] on bad base64.
    pub fn earlier_b64(ed25519_b64: &str, mldsa65_b64: Option<&str>) -> Result<Self, Sig19Error> {
        let ed25519 = B64
            .decode(ed25519_b64)
            .map_err(|e| Sig19Error::Malformed(format!("ed25519 sig base64: {e}")))?;
        let mldsa65 = match mldsa65_b64 {
            Some(s) if !s.is_empty() => Some(
                B64.decode(s)
                    .map_err(|e| Sig19Error::Malformed(format!("ml_dsa_65 sig base64: {e}")))?,
            ),
            _ => None,
        };
        Ok(Self::Earlier { ed25519, mldsa65 })
    }

    /// The composite from base64.
    ///
    /// # Errors
    /// [`Sig19Error::Malformed`] on bad base64.
    pub fn composite_b64(b64: &str) -> Result<Self, Sig19Error> {
        B64.decode(b64)
            .map(Self::Composite)
            .map_err(|e| Sig19Error::Malformed(format!("composite sig base64: {e}")))
    }

    /// Parse the one-argument wire form a caller passes: a base64 string is
    /// the composite; a JSON object `{"ed25519": <b64>, "ml_dsa_65": <b64>}`
    /// is the earlier form.
    ///
    /// # Errors
    /// [`Sig19Error::Malformed`] for anything else.
    pub fn from_wire(signature: &str) -> Result<Self, Sig19Error> {
        let t = signature.trim();
        if t.starts_with('{') {
            let v: serde_json::Value = serde_json::from_str(t)
                .map_err(|e| Sig19Error::Malformed(format!("earlier-form signature JSON: {e}")))?;
            let ed = v.get("ed25519").and_then(|x| x.as_str()).ok_or_else(|| {
                Sig19Error::Malformed(
                    "an earlier-form signature is {\"ed25519\": <b64>, \"ml_dsa_65\": <b64>}"
                        .into(),
                )
            })?;
            return Self::earlier_b64(ed, v.get("ml_dsa_65").and_then(|x| x.as_str()));
        }
        Self::composite_b64(t)
    }
}

/// The earlier-form (CC 8.11.12) verifier: CIRISVerify's
/// `earlier_form::verify_bound_hybrid` (verify-only, no producer). Ed25519
/// over `preimage`, ML-DSA-65 over `preimage ‖ ed25519_sig`, both against the
/// caller-pinned keys; a missing ML-DSA-65 half is refused. Verify's error
/// does not say which half failed.
///
/// # Errors
/// [`Sig19Error::MalformedKeyOrSignature`] / [`Sig19Error::EarlierInvalid`].
pub fn verify_bound_hybrid(
    preimage: &[u8],
    ed25519_sig: &[u8],
    mldsa65_sig: Option<&[u8]>,
    ed25519_pubkey: &[u8],
    mldsa65_pubkey: &[u8],
) -> Result<(), Sig19Error> {
    use ciris_verify_core::substrate::HolonomicError;
    ciris_verify_core::earlier_form::verify_bound_hybrid(
        preimage,
        ed25519_sig,
        mldsa65_sig,
        ed25519_pubkey,
        mldsa65_pubkey,
    )
    .map_err(|e| match e {
        HolonomicError::MalformedKeyOrSignature => Sig19Error::MalformedKeyOrSignature,
        _ => Sig19Error::EarlierInvalid,
    })
}

/// Sign `preimage` in the form `ceremony` writes (CC D4): the earlier
/// bound-hybrid pair before the edition-2 ceremony row
/// (`LocalSigner::sign_hybrid`: Ed25519 over the preimage, ML-DSA-65 over
/// `preimage ‖ ed25519_sig`), the composite after
/// (`LocalSigner::sign_composite`).
///
/// # Errors
/// The signer's error.
pub async fn sign_sig19(
    signer: &crate::signing::LocalSigner,
    preimage: &[u8],
    ceremony: crate::federation::sth_form::CeremonyState,
) -> Result<Sig19, crate::signing::LocalSignerError> {
    match ceremony.writes() {
        SignatureForm::Earlier => {
            let h = signer.sign_hybrid(preimage).await?;
            Ok(Sig19::Earlier {
                ed25519: h.classical.signature,
                mldsa65: Some(h.pqc.signature),
            })
        }
        SignatureForm::Composite => signer.sign_composite(preimage).await.map(Sig19::Composite),
    }
}

/// The composite key `mldsaPK ‖ ed25519PK` of a pinned pair.
#[must_use]
pub fn composite_pubkey(ed25519_pubkey: &[u8], mldsa65_pubkey: &[u8]) -> Vec<u8> {
    let mut pk = Vec::with_capacity(mldsa65_pubkey.len() + ed25519_pubkey.len());
    pk.extend_from_slice(mldsa65_pubkey);
    pk.extend_from_slice(ed25519_pubkey);
    pk
}

/// Verify `sig` over `preimage` under the pinned pair, by FORM.
///
/// # Errors
/// [`Sig19Error`] naming the failure.
pub fn verify_sig19(
    preimage: &[u8],
    sig: &Sig19,
    ed25519_pubkey: &[u8],
    mldsa65_pubkey: &[u8],
) -> Result<SignatureForm, Sig19Error> {
    match sig {
        Sig19::Earlier { ed25519, mldsa65 } => {
            verify_bound_hybrid(
                preimage,
                ed25519,
                mldsa65.as_deref(),
                ed25519_pubkey,
                mldsa65_pubkey,
            )?;
            Ok(SignatureForm::Earlier)
        }
        Sig19::Composite(c) => {
            use ciris_verify_core::substrate::HolonomicError;
            ciris_verify_core::substrate::verify_composite(
                preimage,
                c,
                &composite_pubkey(ed25519_pubkey, mldsa65_pubkey),
            )
            .map_err(|e| match e {
                HolonomicError::MalformedKeyOrSignature => Sig19Error::MalformedKeyOrSignature,
                _ => Sig19Error::CompositeInvalid,
            })?;
            Ok(SignatureForm::Composite)
        }
    }
}
