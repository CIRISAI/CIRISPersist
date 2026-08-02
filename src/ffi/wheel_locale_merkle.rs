//! v3.8.0 — PyO3 surface for CIRISVerify v4.7.0's per-locale Merkle
//! root + inclusion-proof primitives (RFC 6962-shape, per CIRISRegistry
//! FSD-002 v1.4.3 §3.2.1.2).
//!
//! Verify ships `_wheel_locale_merkle.py` grafting onto its CIRISVerify
//! class. Persist's parallel surface exposes
//! `verify_locale_inclusion_json` and `locale_merkle_root_json` so
//! Python users of `ciris-persist` can verify per-locale build-manifest
//! inclusion natively (Eric's "if it ain't on the FFI/Python interface,
//! it doesn't exist" rule).
//!
//! Composes with the v3.6.x build-manifest pipeline + the CEG §10.3
//! transparency-log discipline.

use ciris_verify_core::locale_merkle::{verify_locale_inclusion, LocaleInclusionProof, LocaleLeaf};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

/// Compute the per-locale leaf-hash for a `LocaleLeaf`-shape JSON
/// envelope. Returns the 32-byte SHA-256 as hex.
///
/// JSON shape (matching `ciris_verify_core::locale_merkle::LocaleLeaf`):
///
/// ```json
/// {
///   "target": "ios-mobile-bundle",
///   "lang_code": "en",
///   "files_root": "abcd...",
///   "build_id": "01HXY...",
///   "signer_identity": "registry-steward-us"
/// }
/// ```
pub fn locale_leaf_hash_hex(leaf_json: &str) -> PyResult<String> {
    let leaf: LocaleLeaf = serde_json::from_str(leaf_json)
        .map_err(|e| PyValueError::new_err(format!("LocaleLeaf decode: {e}")))?;
    // v25.0.0 (CIRISPersist#577 / CIRISVerify v11.0.0) — `leaf_hash` became
    // FALLIBLE. CC 3.1.2.1 v2 moves the preimage from line-oriented
    // `key=value\n` concatenation to `sha256(JCS({…}))`, and JCS
    // canonicalization can fail — so the error is surfaced to the caller
    // rather than unwrapped. v1's form carried attacker-influenceable free
    // text with no newline guard (verify's AV-50), which is the injection
    // class v2 closes; a panic here would trade that for a different one.
    let hash = leaf
        .leaf_hash()
        .map_err(|e| PyValueError::new_err(format!("LocaleLeaf leaf_hash: {e}")))?;
    Ok(hex::encode(hash))
}

/// Verify a `LocaleInclusionProof` against the expected per-target
/// Merkle root. Returns JSON: `{"valid": true}` on success;
/// raises `PyRuntimeError` with the structured reason on failure.
///
/// Inputs:
/// - `leaf_json`: the `LocaleLeaf` the consumer is verifying inclusion of
/// - `proof_json`: the proof returned by Registry's per-locale GET endpoint
/// - `expected_root_hex`: 64-char hex of the parent Merkle root
pub fn verify_locale_inclusion_json(
    leaf_json: &str,
    proof_json: &str,
    expected_root_hex: &str,
) -> PyResult<String> {
    let leaf: LocaleLeaf = serde_json::from_str(leaf_json)
        .map_err(|e| PyValueError::new_err(format!("LocaleLeaf decode: {e}")))?;
    let proof: LocaleInclusionProof = serde_json::from_str(proof_json)
        .map_err(|e| PyValueError::new_err(format!("LocaleInclusionProof decode: {e}")))?;
    let expected_root = decode_hex32(expected_root_hex, "expected_root_hex")?;

    verify_locale_inclusion(&leaf, &proof, &expected_root)
        .map_err(|e| PyRuntimeError::new_err(format!("locale_inclusion verify failed: {e}")))?;

    serde_json::to_string(&serde_json::json!({
        "valid": true,
        "lang_code": leaf.lang_code,
        "target": leaf.target,
    }))
    .map_err(|e| PyRuntimeError::new_err(format!("result encode: {e}")))
}

/// Convenience: compute the RFC 6962-style Merkle root over a list
/// of leaf JSON envelopes. Returns the 32-byte root as hex.
///
/// `leaves_json`: a JSON array of `LocaleLeaf` objects.
pub fn locale_merkle_root_hex(leaves_json: &str) -> PyResult<String> {
    let leaves: Vec<LocaleLeaf> = serde_json::from_str(leaves_json)
        .map_err(|e| PyValueError::new_err(format!("leaves array decode: {e}")))?;
    if leaves.is_empty() {
        return Err(PyValueError::new_err(
            "leaves array must be non-empty (§3.2.1.2 forbids empty trees)",
        ));
    }
    // v25.0.0 (CIRISPersist#577) — collect into a Result so ONE malformed
    // leaf fails the whole root rather than silently contributing a wrong
    // hash: a Merkle root computed over a partially-canonicalized set is a
    // root nobody can reproduce.
    let leaf_hashes: Vec<[u8; 32]> = leaves
        .iter()
        .map(ciris_verify_core::locale_merkle::LocaleLeaf::leaf_hash)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| PyValueError::new_err(format!("LocaleLeaf leaf_hash: {e}")))?;
    let root = ciris_verify_core::locale_merkle::merkle_root(&leaf_hashes)
        .map_err(|e| PyRuntimeError::new_err(format!("merkle_root: {e}")))?;
    Ok(hex::encode(root))
}

fn decode_hex32(s: &str, label: &'static str) -> PyResult<[u8; 32]> {
    let s = s.strip_prefix("sha256:").unwrap_or(s);
    let bytes =
        hex::decode(s).map_err(|e| PyValueError::new_err(format!("{label} hex decode: {e}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        PyValueError::new_err(format!(
            "{label} must be 32 bytes (64 hex chars), got {}",
            v.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_leaf() -> LocaleLeaf {
        LocaleLeaf {
            target: "ios-mobile-bundle".to_string(),
            lang_code: "en".to_string(),
            files_root: hex::encode([0x42u8; 32]),
            build_id: "01HXY-test-build-id".to_string(),
            signer_identity: "registry-steward-us".to_string(),
        }
    }

    #[test]
    fn leaf_hash_matches_native_computation() {
        let leaf = sample_leaf();
        let want = hex::encode(leaf.leaf_hash().expect("v2 canonicalization"));
        let leaf_json = serde_json::to_string(&leaf).unwrap();
        let got = locale_leaf_hash_hex(&leaf_json).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn merkle_root_single_leaf_matches_leaf_hash() {
        let leaf = sample_leaf();
        let leaves_json = format!("[{}]", serde_json::to_string(&leaf).unwrap());
        let root_hex = locale_merkle_root_hex(&leaves_json).unwrap();
        // RFC 6962: single-leaf tree's root IS the leaf hash.
        assert_eq!(
            root_hex,
            hex::encode(leaf.leaf_hash().expect("v2 canonicalization"))
        );
    }

    // PyErr message content isn't introspectable from `cargo test`
    // without a Python interpreter in PyO3 0.28+. Detailed message
    // text is checked at the Python-pytest layer.
    #[test]
    fn empty_leaves_rejected() {
        let _err = locale_merkle_root_hex("[]").unwrap_err();
    }
}
