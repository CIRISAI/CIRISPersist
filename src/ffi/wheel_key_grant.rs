//! PyO3 surface for the `key_grant` DEK wrap/unwrap primitive — **v2
//! (X25519 + ML-KEM-768 hybrid) only**.
//!
//! Verify ships its own Python sidecar (`_wheel_key_grant.py` grafts
//! onto its `CIRISVerify` class). This file is persist's parallel
//! surface — PyEngine exposes `wrap_dek_for_recipient_v2_b64` /
//! `unwrap_dek_v2_b64` so Python users of `ciris-persist` get the
//! methods natively (Eric's "if it ain't on the FFI/Python interface,
//! it doesn't exist" discipline; CIRISVerify#50).
//!
//! # The classical v1 pair is GONE (v35.0.0, CIRISPersist#715)
//!
//! v34.0.0 (#704) removed the classical v1 wrap from admission —
//! `WrapAlgorithm` variant, wire token, parse arm — yet this file kept
//! minting it: `wrap_dek_for_recipient_b64` emitted
//! `algorithm: "x25519-aes256-gcm-hkdf-sha256"`, a token
//! `extract_key_grant_payload` refuses BY NAME
//! (`RETIRED_WRAP_ALGORITHM_WIRE_TOKENS`). A consumer following the
//! wheel's own surface wrapped a DEK the substrate's gate then refused,
//! and a classical-only X25519 wrap of a long-lived DEK is a
//! harvest-now-decrypt-later hole (CC 5.1) — the fleet directive is that
//! classical-only paths do not exist to be chosen.
//!
//! Removed, not replaced: the v2 wrap needs the recipient's ML-KEM-768
//! public key, which the v1 signature `(recipient_x25519_pub, dek)`
//! cannot express — and the v2 pair has been on this wheel since Cut
//! C3b. A stale caller gets an `AttributeError` naming the method, the
//! same disposition v34 gave `cirisnode_list_key_grants_for_stream_epoch_json`.
//! Anyone draining pre-v34 v1-wrapped material does it against
//! `ciris-crypto`'s still-exported v1 primitives (`unwrap_dek`,
//! `KEY_GRANT_ALGORITHM_V1`) or CIRISVerify's own wheel sidecar, which
//! retains the pair — a deliberate off-substrate door: persist's
//! admission chose refusal-without-migration for stored v1 grants at
//! v34, and its wheel does not reopen that decision.
//!
//! # Wiring
//!
//! - `Cargo.toml`: `ciris-crypto/key-grant` feature.
//! - `src/ffi/mod.rs`: `#[cfg(feature = "_pyffi")] pub mod wheel_key_grant;`
//! - `src/ffi/pyo3.rs`: two thin `#[pymethods]` on `PyEngine`
//!   delegating to `wrap_dek_for_recipient_v2_json` / `unwrap_dek_v2_json`.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::key_grant::{
    key_grant_algorithm_v2_accepts, unwrap_dek_v2, wrap_dek_for_recipient_v2, KeyGrantWrapV2,
    KEY_GRANT_ALGORITHM_V2, KEY_GRANT_ALGORITHM_V2_LEGACY_HYPHENATED,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

const X25519_KEY_LEN: usize = 32;
const DEK_LEN: usize = 32;

/// v4.x (CIRISPersist#142 Cut C3b, CEG §10.5.3) — wrap a 32-byte DEK for
/// a recipient under **`wrap_algorithm: v2`** (X25519 + ML-KEM-768 hybrid,
/// FIPS 203 — the PQC-at-rest wrap mandated for streaming epoch DEKs).
/// Delegates to `ciris-crypto`'s `wrap_dek_for_recipient_v2` (v4.10.0).
/// Returns a JSON string:
///
/// The `algorithm` field carries `ciris_crypto::key_grant::KEY_GRANT_ALGORITHM_V2`
/// verbatim — the snake_case identifier CC 5.1 ratified as *the single wire
/// identifier* (CIRISVerify#234, adopted at v25.1.0). The hyphenated form this
/// doc block used to show is a non-conformant alias.
///
/// ```json
/// {
///   "algorithm": "x25519_mlkem768_aes256_gcm_hkdf_sha256",
///   "ephemeral_x25519_public_key_b64": "...",
///   "ml_kem_ciphertext_b64": "...",
///   "nonce_b64": "...",
///   "ciphertext_b64": "..."
/// }
/// ```
///
/// `recipient_ml_kem_pub_b64` is the recipient's ML-KEM-768 public key
/// (1184 bytes); a wrong length surfaces as a runtime error from the
/// crypto layer. Other inputs are base64 (persist's `_b64` idiom).
pub fn wrap_dek_for_recipient_v2_json(
    recipient_x25519_pub_b64: &str,
    recipient_ml_kem_pub_b64: &str,
    dek_b64: &str,
) -> PyResult<String> {
    let recipient_x_pub =
        decode_fixed_b64::<X25519_KEY_LEN>(recipient_x25519_pub_b64, "recipient_x25519_pub_b64")?;
    let recipient_ml_kem_pub = B64
        .decode(recipient_ml_kem_pub_b64)
        .map_err(|e| PyValueError::new_err(format!("recipient_ml_kem_pub_b64 decode: {e}")))?;
    let dek = decode_fixed_b64::<DEK_LEN>(dek_b64, "dek_b64")?;

    let wrap = wrap_dek_for_recipient_v2(&recipient_x_pub, &recipient_ml_kem_pub, &dek)
        .map_err(|e| PyRuntimeError::new_err(format!("key_grant v2 wrap: {e}")))?;

    let envelope = serde_json::json!({
        "algorithm": KEY_GRANT_ALGORITHM_V2,
        "ephemeral_x25519_public_key_b64": B64.encode(wrap.ephemeral_x25519_public_key),
        "ml_kem_ciphertext_b64": B64.encode(&wrap.ml_kem_ciphertext),
        "nonce_b64": B64.encode(wrap.nonce),
        "ciphertext_b64": B64.encode(&wrap.ciphertext),
    });
    serde_json::to_string(&envelope)
        .map_err(|e| PyRuntimeError::new_err(format!("key_grant v2 envelope encode: {e}")))
}

/// v4.x (CIRISPersist#142 Cut C3b) — unwrap a `KeyGrantWrapV2`-shaped
/// JSON envelope (the shape [`wrap_dek_for_recipient_v2_json`] produces)
/// using the recipient's X25519 private key + ML-KEM-768 private/public
/// keys. Returns the 32-byte DEK as base64.
///
/// v35.0.0 (#715) — the envelope's `algorithm` field is REQUIRED and
/// validated through `key_grant_algorithm_v2_accepts(token, false)`, the
/// only sanctioned comparison for the identifier. This unwrap used to
/// ignore the field entirely, which quietly accepted the retired CC
/// 1.0-rc2 hyphenated spelling — and any other label — on a surface
/// whose admission-door counterpart refuses retired spellings BY NAME
/// and never normalizes. The refusal here mirrors that door: the
/// hyphenated legacy gets its disposition and the exact token to send.
pub fn unwrap_dek_v2_json(
    recipient_x25519_priv_b64: &str,
    recipient_ml_kem_priv_b64: &str,
    recipient_ml_kem_pub_b64: &str,
    wrap_json: &str,
) -> PyResult<String> {
    let recipient_x_priv =
        decode_fixed_b64::<X25519_KEY_LEN>(recipient_x25519_priv_b64, "recipient_x25519_priv_b64")?;
    let recipient_ml_kem_priv = B64
        .decode(recipient_ml_kem_priv_b64)
        .map_err(|e| PyValueError::new_err(format!("recipient_ml_kem_priv_b64 decode: {e}")))?;
    let recipient_ml_kem_pub = B64
        .decode(recipient_ml_kem_pub_b64)
        .map_err(|e| PyValueError::new_err(format!("recipient_ml_kem_pub_b64 decode: {e}")))?;

    let envelope: serde_json::Value = serde_json::from_str(wrap_json)
        .map_err(|e| PyValueError::new_err(format!("wrap_json decode: {e}")))?;

    let algorithm = envelope
        .get("algorithm")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PyValueError::new_err("wrap_json: missing algorithm"))?;
    if !key_grant_algorithm_v2_accepts(algorithm, false) {
        return Err(if algorithm == KEY_GRANT_ALGORITHM_V2_LEGACY_HYPHENATED {
            PyValueError::new_err(format!(
                "wrap_json: algorithm `{algorithm}` is the CC 1.0-rc2 hyphenated \
                 spelling of the v2 hybrid wrap; CC 5.1 (CIRISVerify#234) ratified \
                 `{KEY_GRANT_ALGORITHM_V2}` as the single wire identifier and nothing \
                 accepts both spellings — respell and resubmit"
            ))
        } else {
            PyValueError::new_err(format!(
                "wrap_json: algorithm `{algorithm}` is not the v2 hybrid wrap \
                 identifier `{KEY_GRANT_ALGORITHM_V2}` — this surface unwraps v2 \
                 envelopes only (the classical v1 wrap was removed in v34.0.0, \
                 CIRISPersist#704)"
            ))
        });
    }

    let ephemeral_b64 = envelope
        .get("ephemeral_x25519_public_key_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PyValueError::new_err("wrap_json: missing ephemeral_x25519_public_key_b64")
        })?;
    let ml_kem_ct_b64 = envelope
        .get("ml_kem_ciphertext_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PyValueError::new_err("wrap_json: missing ml_kem_ciphertext_b64"))?;
    let nonce_b64 = envelope
        .get("nonce_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PyValueError::new_err("wrap_json: missing nonce_b64"))?;
    let ciphertext_b64 = envelope
        .get("ciphertext_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PyValueError::new_err("wrap_json: missing ciphertext_b64"))?;

    let ephemeral_x25519_public_key =
        decode_fixed_b64::<X25519_KEY_LEN>(ephemeral_b64, "ephemeral_x25519_public_key_b64")?;
    let ml_kem_ciphertext = B64
        .decode(ml_kem_ct_b64)
        .map_err(|e| PyValueError::new_err(format!("ml_kem_ciphertext_b64 decode: {e}")))?;
    let nonce_vec = B64
        .decode(nonce_b64)
        .map_err(|e| PyValueError::new_err(format!("nonce_b64 decode: {e}")))?;
    let nonce: [u8; 12] = nonce_vec.try_into().map_err(|v: Vec<u8>| {
        PyValueError::new_err(format!("nonce must be 12 bytes, got {}", v.len()))
    })?;
    let ciphertext = B64
        .decode(ciphertext_b64)
        .map_err(|e| PyValueError::new_err(format!("ciphertext_b64 decode: {e}")))?;

    let wrap = KeyGrantWrapV2 {
        ephemeral_x25519_public_key,
        ml_kem_ciphertext,
        nonce,
        ciphertext,
    };
    let dek = unwrap_dek_v2(
        &recipient_x_priv,
        &recipient_ml_kem_priv,
        &recipient_ml_kem_pub,
        &wrap,
    )
    .map_err(|e| PyRuntimeError::new_err(format!("key_grant v2 unwrap: {e}")))?;
    Ok(B64.encode(dek))
}

fn decode_fixed_b64<const N: usize>(s: &str, label: &'static str) -> PyResult<[u8; N]> {
    let bytes = B64
        .decode(s)
        .map_err(|e| PyValueError::new_err(format!("{label} b64 decode: {e}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        PyValueError::new_err(format!("{label} must be {N} bytes, got {}", v.len()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::x25519;

    fn v2_wrap_fixture() -> (String, [u8; 32], Vec<u8>, Vec<u8>, [u8; 32]) {
        let recipient_x_priv: [u8; 32] = [0x42; 32];
        let recipient_x_pub = x25519::public_from_secret(&recipient_x_priv);
        // ML-KEM-768 half — generate_keypair() returns (private, public).
        let (ml_kem_priv, ml_kem_pub) =
            ciris_crypto::ml_kem::generate_keypair().expect("ml-kem keypair");
        let dek: [u8; 32] = [0xCC; 32];
        let wrap_json = wrap_dek_for_recipient_v2_json(
            &B64.encode(recipient_x_pub),
            &B64.encode(&ml_kem_pub),
            &B64.encode(dek),
        )
        .expect("v2 wrap succeeds");
        (wrap_json, recipient_x_priv, ml_kem_priv, ml_kem_pub, dek)
    }

    #[test]
    fn wrap_unwrap_v2_round_trip_recovers_dek() {
        let (wrap_json, recipient_x_priv, ml_kem_priv, ml_kem_pub, dek) = v2_wrap_fixture();
        // The envelope advertises the v2 algorithm string. Assert against the
        // CONSTANT, never a spelling (v25.1.0 / #582, CC 5.1): the identifier
        // is verify's to ratify, and pinning the literal here is what turns a
        // vocabulary tightening into an unrelated red.
        assert!(
            wrap_json.contains(KEY_GRANT_ALGORITHM_V2),
            "v2 envelope names the v2 algorithm: {wrap_json}"
        );

        let unwrapped_b64 = unwrap_dek_v2_json(
            &B64.encode(recipient_x_priv),
            &B64.encode(&ml_kem_priv),
            &B64.encode(&ml_kem_pub),
            &wrap_json,
        )
        .expect("v2 unwrap succeeds");
        let unwrapped = B64.decode(&unwrapped_b64).unwrap();
        assert_eq!(unwrapped, dek, "DEK survives the v2 hybrid round-trip");
    }

    /// v35.0.0 (#715) — the mint-refused-by-your-own-gate witness. The token
    /// the wheel mints must be the token `extract_key_grant_payload` — the
    /// REAL admission door every `put_key_grant` passes through — admits as
    /// `wrap_algorithm`. Wired through the minted ENVELOPE, not through the
    /// constant both sides import: a wheel that drifted to any other spelling
    /// (the hyphenated rc2 legacy is refused BY NAME at that door) reds this
    /// test even though its own round-trip stays green.
    #[test]
    #[cfg(feature = "cirisnode")]
    fn wheel_minted_algorithm_round_trips_the_admission_door() {
        let (wrap_json, ..) = v2_wrap_fixture();
        let envelope: serde_json::Value = serde_json::from_str(&wrap_json).unwrap();
        let minted_algorithm = envelope
            .get("algorithm")
            .and_then(|v| v.as_str())
            .expect("wheel envelope names its algorithm")
            .to_owned();

        let sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let payload = serde_json::json!({
            "recipient_key_id": "recipient-1",
            "content_sha256": sha,
            "wrapped_dek_base64": B64.encode([0u8; 48]),
            "wrap_algorithm": minted_algorithm,
            "ratchet_version": 1,
            "key_validity_window": {
                "not_before": "2026-05-29T00:00:00Z",
                "not_after": "2027-05-29T00:00:00Z",
            },
            "scope": "single_content",
            "scope_id": sha,
            "rotation_chain": [],
        });
        let admitted = crate::cirisnode::extract_key_grant_payload(
            crate::cirisnode::KEY_GRANT_SUBJECT_KIND,
            &payload,
        )
        .expect("a grant naming the wheel-minted algorithm is admitted")
        .expect("subject_kind key_grant decodes to a grant");
        assert_eq!(
            admitted.wrap_algorithm.as_str(),
            minted_algorithm,
            "the admitted wrap_algorithm is the one the wheel minted"
        );
    }

    #[test]
    fn unwrap_v2_rejects_wrong_x25519_key() {
        let (wrap_json, _, ml_kem_priv, ml_kem_pub, _) = v2_wrap_fixture();
        // A different X25519 private key must fail the hybrid unwrap
        // (AEAD tag mismatch — opaque WrapUnverified).
        let wrong_x_priv: [u8; 32] = [0x99; 32];
        let _err = unwrap_dek_v2_json(
            &B64.encode(wrong_x_priv),
            &B64.encode(&ml_kem_priv),
            &B64.encode(&ml_kem_pub),
            &wrap_json,
        )
        .unwrap_err();
    }

    /// v35.0.0 (#715) — the retired hyphenated rc2 spelling is refused, never
    /// folded onto the live token. Structural fields are all valid — the
    /// label alone is the defect, so a pass here can only come from the
    /// algorithm check.
    #[test]
    fn unwrap_v2_refuses_the_legacy_hyphenated_spelling() {
        let (wrap_json, recipient_x_priv, ml_kem_priv, ml_kem_pub, _) = v2_wrap_fixture();
        let mut envelope: serde_json::Value = serde_json::from_str(&wrap_json).unwrap();
        envelope["algorithm"] =
            serde_json::Value::String(KEY_GRANT_ALGORITHM_V2_LEGACY_HYPHENATED.into());
        let _err = unwrap_dek_v2_json(
            &B64.encode(recipient_x_priv),
            &B64.encode(&ml_kem_priv),
            &B64.encode(&ml_kem_pub),
            &serde_json::to_string(&envelope).unwrap(),
        )
        .unwrap_err();
    }

    /// v35.0.0 (#715) — an envelope with NO algorithm label is not the shape
    /// [`wrap_dek_for_recipient_v2_json`] produces and is refused, not
    /// unwrapped on faith.
    #[test]
    fn unwrap_v2_refuses_a_missing_algorithm() {
        let (wrap_json, recipient_x_priv, ml_kem_priv, ml_kem_pub, _) = v2_wrap_fixture();
        let mut envelope: serde_json::Value = serde_json::from_str(&wrap_json).unwrap();
        envelope.as_object_mut().unwrap().remove("algorithm");
        let _err = unwrap_dek_v2_json(
            &B64.encode(recipient_x_priv),
            &B64.encode(&ml_kem_priv),
            &B64.encode(&ml_kem_pub),
            &serde_json::to_string(&envelope).unwrap(),
        )
        .unwrap_err();
    }

    #[test]
    fn wrap_v2_rejects_short_recipient_x25519_pub() {
        // PyErr message content isn't introspectable from cargo test
        // without a Python interpreter in PyO3 0.28+. The wrap path's
        // contract here is just "non-32-byte input is an error" —
        // unwrap_err() captures that. Detailed message text is checked
        // at the Python-pytest layer.
        let too_short = B64.encode([0u8; 16]);
        let (_, ml_kem_pub) = ciris_crypto::ml_kem::generate_keypair().expect("ml-kem keypair");
        let dek = B64.encode([0u8; 32]);
        let _err =
            wrap_dek_for_recipient_v2_json(&too_short, &B64.encode(&ml_kem_pub), &dek).unwrap_err();
    }
}
