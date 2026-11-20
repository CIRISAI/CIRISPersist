//! v62.0.0 (F0-cp6b; CC 6.1.3, CC 1.13.4) — **the calibration bundle's
//! signature check**, one function both backends' PyO3 arms call.
//!
//! A calibration bundle is signed by a RATCHET steward and verified here
//! through the directory: its bytes cross nodes, so it is ONE composite
//! (v62.0.0, F0-cp7: composite only). The bundle's two
//! signature fields carry the composite's halves as the composite lays them
//! out (`ml_dsa_65_sig ‖ ed25519_sig` IS the composite, 3309 + 64 bytes), the
//! same split `derived::detection_row` stores; `signing_key_id` is the
//! steward's edition-2 identity-ref. A lone half is refused by name
//! (`verify_component_signature`); the earlier bound-hybrid pair has the same
//! two-field shape and is refused by the composite verify
//! (`verify_composite_invalid`).

use crate::federation::edition2::composite_verify::{
    now_ms, verify_composite_via_directory, CompositeVerifyError,
};
use crate::federation::FederationDirectory;

use super::types::CalibrationBundle;

/// Why a calibration bundle's signature was refused: the composite check's
/// refusal, its token leading the message.
#[derive(Debug)]
pub enum CalibrationSignatureError {
    /// The composite check refused.
    Composite(CompositeVerifyError),
}

impl std::fmt::Display for CalibrationSignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Composite(e) => write!(f, "{e}"),
        }
    }
}

/// Verify `bundle`'s ONE composite over its `canonical_bytes` under the
/// steward's live edition-2 key. v62.0.0 (F0-cp7): the plane crosses nodes,
/// so it is composite only; the earlier own-form (bound-hybrid) branch and the
/// plane's entry in the substrate predicate are deleted with the bound-hybrid
/// verify family.
///
/// # Errors
/// [`CalibrationSignatureError`].
pub async fn verify_calibration_bundle<F>(
    dir: &F,
    bundle: &CalibrationBundle,
) -> Result<(), CalibrationSignatureError>
where
    F: FederationDirectory + ?Sized,
{
    let mut composite = Vec::with_capacity(bundle.ml_dsa_65_sig.len() + bundle.ed25519_sig.len());
    composite.extend_from_slice(&bundle.ml_dsa_65_sig);
    composite.extend_from_slice(&bundle.ed25519_sig);
    verify_composite_via_directory(
        dir,
        &bundle.canonical_bytes,
        &bundle.signing_key_id,
        &composite,
        now_ms(),
    )
    .await
    .map(|_| ())
    .map_err(CalibrationSignatureError::Composite)
}
