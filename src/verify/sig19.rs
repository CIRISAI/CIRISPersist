//! v62.0.0 (slice D, CIRISVerify 23 composite cut; CC rc20 "nothing
//! carries") — **a §19 substrate object's signature: the composite only.**
//!
//! CIRISVerify 23 moved the §19 verifiers (`verify_witness`,
//! `verify_aggregation_meta`, `verify_storage_budget_v1`,
//! `verify_corpus_want_v1`) to the CC 2.6.1.7 composite (`(sig,
//! composite_pubkey)` through `substrate::verify_composite`). A v62 node
//! reads only edition-2 objects: a §19 object arriving with the EARLIER
//! bound-hybrid pair (an Ed25519 half plus an ML-DSA-65 half over `preimage ‖
//! ed25519_sig`) is refused at the door by name
//! ([`Sig19Error::EarlierForm`], `sig19_earlier_form`), never verified. The
//! forward builders sign the composite ([`sign_sig19`]).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

/// The stable token of an earlier-form §19 refusal.
pub const SIG19_EARLIER_FORM: &str = "sig19_earlier_form";

/// A §19 composite signature (3373 bytes, `mldsaSig ‖ ed25519Sig`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sig19(pub Vec<u8>);

/// Why a §19 signature was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Sig19Error {
    /// The earlier (CC 8.11.12) bound-hybrid pair: a pre-v62 object.
    #[error(
        "sig19_earlier_form: a bound-hybrid (pre-edition-2) §19 signature; a v62 node reads \
         only CC 2.6.1.7 composites (nothing carries into the edition)"
    )]
    EarlierForm,
    /// A field is not base64, or the wire form is not a composite.
    #[error("sig19_malformed: {0}")]
    Malformed(String),
    /// A key or signature has the wrong length or does not decode.
    #[error("sig19_malformed_key_or_signature")]
    MalformedKeyOrSignature,
    /// The composite does not verify (which half is not said).
    #[error("sig19_composite_invalid")]
    CompositeInvalid,
    /// v62.0.0 (F0-cp5b; CC 6.1.3) — a lone Ed25519 or ML-DSA-65 half where
    /// the object's ONE composite belongs, refused by name before any key is
    /// read. The message leads with `verify_component_signature`.
    #[error("{0}")]
    ComponentSignature(String),
}

impl Sig19 {
    /// The composite from base64.
    ///
    /// # Errors
    /// [`Sig19Error::Malformed`] on bad base64.
    pub fn composite_b64(b64: &str) -> Result<Self, Sig19Error> {
        let raw = B64
            .decode(b64)
            .map_err(|e| Sig19Error::Malformed(format!("composite sig base64: {e}")))?;
        // v62.0.0 (F0-cp5b; CC 6.1.3) — the one composite shape check shared
        // with the directory verifier: a lone half is refused by name.
        use crate::federation::edition2::composite_verify::{
            require_composite_length, CompositeVerifyError,
        };
        require_composite_length(raw.len()).map_err(|e| match e {
            CompositeVerifyError::ComponentSignature { .. } => {
                Sig19Error::ComponentSignature(e.to_string())
            }
            other => Sig19Error::Malformed(other.to_string()),
        })?;
        Ok(Self(raw))
    }

    /// Parse the one-argument wire form a caller passes: a base64 composite.
    /// A JSON object (the earlier `{"ed25519": …, "ml_dsa_65": …}` pair) is
    /// refused by name.
    ///
    /// # Errors
    /// [`Sig19Error::EarlierForm`] / [`Sig19Error::Malformed`].
    pub fn from_wire(signature: &str) -> Result<Self, Sig19Error> {
        let t = signature.trim();
        if t.starts_with('{') {
            return Err(Sig19Error::EarlierForm);
        }
        Self::composite_b64(t)
    }

    /// From a wire's three base64 signature fields (the two earlier halves
    /// and the composite): any earlier half present is the earlier form,
    /// refused by name; otherwise the composite.
    ///
    /// # Errors
    /// [`Sig19Error::EarlierForm`] / [`Sig19Error::Malformed`].
    pub fn from_wire_fields(
        ed25519_b64: &str,
        mldsa65_b64: &str,
        composite_b64: &str,
    ) -> Result<Self, Sig19Error> {
        if !ed25519_b64.is_empty() || !mldsa65_b64.is_empty() {
            return Err(Sig19Error::EarlierForm);
        }
        if composite_b64.is_empty() {
            return Err(Sig19Error::Malformed("no composite signature".into()));
        }
        Self::composite_b64(composite_b64)
    }
}

/// Sign `preimage` with the node's signer: the composite
/// (`LocalSigner::sign_composite`).
///
/// # Errors
/// The signer's error.
pub async fn sign_sig19(
    signer: &crate::signing::LocalSigner,
    preimage: &[u8],
) -> Result<Sig19, crate::signing::LocalSignerError> {
    signer.sign_composite(preimage).await.map(Sig19)
}

/// The composite key `mldsaPK ‖ ed25519PK` of a pinned pair.
#[must_use]
pub fn composite_pubkey(ed25519_pubkey: &[u8], mldsa65_pubkey: &[u8]) -> Vec<u8> {
    let mut pk = Vec::with_capacity(mldsa65_pubkey.len() + ed25519_pubkey.len());
    pk.extend_from_slice(mldsa65_pubkey);
    pk.extend_from_slice(ed25519_pubkey);
    pk
}

/// Verify `sig` over `preimage` under the pinned pair's composite key.
///
/// # Errors
/// [`Sig19Error`] naming the failure.
pub fn verify_sig19(
    preimage: &[u8],
    sig: &Sig19,
    ed25519_pubkey: &[u8],
    mldsa65_pubkey: &[u8],
) -> Result<(), Sig19Error> {
    use ciris_verify_core::substrate::HolonomicError;
    ciris_verify_core::substrate::verify_composite(
        preimage,
        &sig.0,
        &composite_pubkey(ed25519_pubkey, mldsa65_pubkey),
    )
    .map_err(|e| match e {
        HolonomicError::MalformedKeyOrSignature => Sig19Error::MalformedKeyOrSignature,
        _ => Sig19Error::CompositeInvalid,
    })
}
