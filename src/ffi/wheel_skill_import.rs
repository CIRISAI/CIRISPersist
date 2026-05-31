//! v3.8.0 — PyO3 surface for CIRISVerify v4.7.0's
//! `SkillImportManifest` verification.
//!
//! Verify ships `_wheel_skill_import.py` grafting onto its CIRISVerify
//! class. Persist's parallel surface exposes `verify_skill_import_manifest_json`
//! so Python users of `ciris-persist` get the method natively (Eric's
//! "if it ain't on the FFI/Python interface, it doesn't exist" rule).
//!
//! This is the consumer-side check for the CIRISNodeCore skill-import
//! pipeline (CIRISAgent fold-in surface) — a Python caller hands the
//! raw manifest bytes + the trusted-steward pubkey and gets back
//! either a typed verification report or a typed integrity error.
//!
//! # Wiring (orchestrator handles)
//!
//! - `Cargo.toml`: no extra feature; `verify_skill_import_manifest`
//!   is in the base `ciris_verify_core` surface.
//! - `src/ffi/mod.rs`: `#[cfg(feature = "pyo3")] pub mod wheel_skill_import;`
//! - `src/ffi/pyo3.rs`: add a thin `#[pymethods]` on `PyEngine`
//!   delegating to `verify_skill_import_manifest_json`.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_verify_core::security::function_integrity::StewardPublicKey;
use ciris_verify_core::skill_import::verify_skill_import_manifest;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

const ED25519_KEY_LEN: usize = 32;
const ML_DSA_65_PUBKEY_LEN: usize = 1952;

/// Verify a `SkillImportManifest` against a trusted steward pubkey pair.
///
/// Inputs (all base64):
/// - `manifest_bytes_b64` — the raw manifest bytes (canonical JSON;
///   same bytes the steward signed)
/// - `steward_ed25519_pub_b64` — 32 bytes Ed25519 public key
/// - `steward_ml_dsa_65_pub_b64` — 1952 bytes ML-DSA-65 public key
///
/// Returns JSON on success:
/// ```json
/// {
///   "valid": true,
///   "source": "<source-type>",
///   "skill_manifest_sha256": "<hex64>",
///   "signer_identity": "<key_id>",
///   "import_timestamp": "<rfc3339>"
/// }
/// ```
///
/// Raises `PyRuntimeError` with the structured reason on signature /
/// canonicalization / integrity failure (no oracle leak — opaque
/// IntegrityError is the AEAD-discipline default).
pub fn verify_skill_import_manifest_json(
    manifest_bytes_b64: &str,
    steward_ed25519_pub_b64: &str,
    steward_ml_dsa_65_pub_b64: &str,
) -> PyResult<String> {
    let manifest_bytes = B64
        .decode(manifest_bytes_b64)
        .map_err(|e| PyValueError::new_err(format!("manifest_bytes_b64 decode: {e}")))?;

    // Steward pubkey is &'static — we leak the boxed bytes. Skill-import
    // manifests verify infrequently (operator-imports a new skill once);
    // the leak per call is bounded ~2KiB.
    let ed25519_bytes = B64
        .decode(steward_ed25519_pub_b64)
        .map_err(|e| PyValueError::new_err(format!("steward_ed25519_pub_b64 decode: {e}")))?;
    if ed25519_bytes.len() != ED25519_KEY_LEN {
        return Err(PyValueError::new_err(format!(
            "steward_ed25519_pub_b64 must be 32 bytes, got {}",
            ed25519_bytes.len()
        )));
    }
    let ml_dsa_65_bytes = B64
        .decode(steward_ml_dsa_65_pub_b64)
        .map_err(|e| PyValueError::new_err(format!("steward_ml_dsa_65_pub_b64 decode: {e}")))?;
    if ml_dsa_65_bytes.len() != ML_DSA_65_PUBKEY_LEN {
        return Err(PyValueError::new_err(format!(
            "steward_ml_dsa_65_pub_b64 must be {ML_DSA_65_PUBKEY_LEN} bytes, got {}",
            ml_dsa_65_bytes.len()
        )));
    }
    let ed_array: [u8; ED25519_KEY_LEN] = ed25519_bytes.try_into().expect("checked length above");
    let ed25519_static: &'static [u8; ED25519_KEY_LEN] = Box::leak(Box::new(ed_array));
    let ml_dsa_65_static: &'static [u8] = Box::leak(ml_dsa_65_bytes.into_boxed_slice());

    let trusted = StewardPublicKey {
        ed25519: ed25519_static,
        ml_dsa_65: ml_dsa_65_static,
    };

    let manifest = verify_skill_import_manifest(&manifest_bytes, &trusted)
        .map_err(|e| PyRuntimeError::new_err(format!("skill_import verify failed: {e}")))?;

    let source = manifest
        .source_type()
        .map_err(|e| PyRuntimeError::new_err(format!("source_type: {e}")))?;
    let result = serde_json::json!({
        "valid": true,
        "source": format!("{:?}", source),
        "skill_manifest_sha256": manifest.skill_manifest_sha256,
        "signer_identity": manifest.signer_identity,
        "import_timestamp": manifest.import_timestamp,
    });
    serde_json::to_string(&result)
        .map_err(|e| PyRuntimeError::new_err(format!("result encode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // PyErr message content isn't introspectable from `cargo test`
    // without a Python interpreter in PyO3 0.28+. These tests just
    // assert the unhappy paths are errors; detailed message-text
    // checks happen at the Python-pytest layer.
    #[test]
    fn rejects_invalid_b64_inputs() {
        let _err = verify_skill_import_manifest_json("!!!", "AAAA", "AAAA").unwrap_err();
    }

    #[test]
    fn rejects_wrong_length_ed25519_pubkey() {
        let too_short = B64.encode([0u8; 16]);
        let valid_mldsa = B64.encode(vec![0u8; ML_DSA_65_PUBKEY_LEN]);
        let manifest = B64.encode(b"{}");
        let _err =
            verify_skill_import_manifest_json(&manifest, &too_short, &valid_mldsa).unwrap_err();
    }
}
