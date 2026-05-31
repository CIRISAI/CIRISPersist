//! v3.8.0 — PyO3 surface for CIRISVerify v4.7.0's `key_grant` HPKE-shape
//! DEK wrap/unwrap primitive.
//!
//! Verify ships its own Python sidecar (`_wheel_key_grant.py` grafts
//! onto its `CIRISVerify` class). This file is persist's parallel
//! surface — PyEngine exposes `wrap_dek_for_recipient_b64` /
//! `unwrap_dek_b64` so Python users of `ciris-persist` get the
//! methods natively (Eric's "if it ain't on the FFI/Python interface,
//! it doesn't exist" discipline; CIRISVerify#50).
//!
//! Composes with `subject_kind: key_grant` substrate work
//! (CIRISPersist#134) — the same x25519-aes256-gcm-hkdf-sha256
//! shape used in CEG 0.3 §5.6.8.4 `key_grant` payloads.
//!
//! # Wiring (already done by the orchestrator)
//!
//! - `Cargo.toml`: enable `ciris-crypto/key-grant` feature.
//! - `src/ffi/mod.rs`: `#[cfg(feature = "pyo3")] pub mod wheel_key_grant;`
//! - `src/ffi/pyo3.rs`: add two thin `#[pymethods]` on `PyEngine`
//!   delegating to `wrap_dek_for_recipient_json` / `unwrap_dek_json`.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::key_grant::{unwrap_dek, wrap_dek_for_recipient, KeyGrantWrap};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

const X25519_KEY_LEN: usize = 32;
const DEK_LEN: usize = 32;

/// Wrap a 32-byte DEK for an X25519 recipient. Returns a JSON string:
///
/// ```json
/// {
///   "algorithm": "x25519-aes256-gcm-hkdf-sha256",
///   "ephemeral_public_key_b64": "...",
///   "nonce_b64": "...",
///   "ciphertext_b64": "..."
/// }
/// ```
///
/// Inputs are base64 (consistent with persist's `_b64` PyO3 idiom).
pub fn wrap_dek_for_recipient_json(
    recipient_x25519_pub_b64: &str,
    dek_b64: &str,
) -> PyResult<String> {
    let recipient_pub =
        decode_fixed_b64::<X25519_KEY_LEN>(recipient_x25519_pub_b64, "recipient_x25519_pub_b64")?;
    let dek = decode_fixed_b64::<DEK_LEN>(dek_b64, "dek_b64")?;

    let wrap = wrap_dek_for_recipient(&recipient_pub, &dek)
        .map_err(|e| PyRuntimeError::new_err(format!("key_grant wrap: {e}")))?;

    let envelope = serde_json::json!({
        "algorithm": "x25519-aes256-gcm-hkdf-sha256",
        "ephemeral_public_key_b64": B64.encode(wrap.ephemeral_public_key),
        "nonce_b64": B64.encode(wrap.nonce),
        "ciphertext_b64": B64.encode(&wrap.ciphertext),
    });
    serde_json::to_string(&envelope)
        .map_err(|e| PyRuntimeError::new_err(format!("key_grant envelope encode: {e}")))
}

/// Unwrap a `KeyGrantWrap`-shaped JSON envelope using the recipient's
/// X25519 private key. Returns the 32-byte DEK as base64.
///
/// `wrap_json` accepts the shape produced by
/// [`wrap_dek_for_recipient_json`] — exact key names + base64 fields.
pub fn unwrap_dek_json(recipient_x25519_priv_b64: &str, wrap_json: &str) -> PyResult<String> {
    let recipient_priv =
        decode_fixed_b64::<X25519_KEY_LEN>(recipient_x25519_priv_b64, "recipient_x25519_priv_b64")?;

    let envelope: serde_json::Value = serde_json::from_str(wrap_json)
        .map_err(|e| PyValueError::new_err(format!("wrap_json decode: {e}")))?;

    let ephemeral_b64 = envelope
        .get("ephemeral_public_key_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PyValueError::new_err("wrap_json: missing ephemeral_public_key_b64"))?;
    let nonce_b64 = envelope
        .get("nonce_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PyValueError::new_err("wrap_json: missing nonce_b64"))?;
    let ciphertext_b64 = envelope
        .get("ciphertext_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PyValueError::new_err("wrap_json: missing ciphertext_b64"))?;

    let ephemeral_public_key =
        decode_fixed_b64::<X25519_KEY_LEN>(ephemeral_b64, "ephemeral_public_key_b64")?;
    let nonce_vec = B64
        .decode(nonce_b64)
        .map_err(|e| PyValueError::new_err(format!("nonce_b64 decode: {e}")))?;
    let nonce: [u8; 12] = nonce_vec.try_into().map_err(|v: Vec<u8>| {
        PyValueError::new_err(format!("nonce must be 12 bytes, got {}", v.len()))
    })?;
    let ciphertext = B64
        .decode(ciphertext_b64)
        .map_err(|e| PyValueError::new_err(format!("ciphertext_b64 decode: {e}")))?;

    let wrap = KeyGrantWrap {
        ephemeral_public_key,
        nonce,
        ciphertext,
    };
    let dek = unwrap_dek(&recipient_priv, &wrap)
        .map_err(|e| PyRuntimeError::new_err(format!("key_grant unwrap: {e}")))?;
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

    #[test]
    fn wrap_unwrap_round_trip_recovers_dek() {
        let recipient_priv: [u8; 32] = [0x42; 32];
        let recipient_pub = x25519::public_from_secret(&recipient_priv);
        let dek: [u8; 32] = [0xAA; 32];

        let wrap_json = wrap_dek_for_recipient_json(&B64.encode(recipient_pub), &B64.encode(dek))
            .expect("wrap succeeds");
        let unwrapped_b64 =
            unwrap_dek_json(&B64.encode(recipient_priv), &wrap_json).expect("unwrap succeeds");
        let unwrapped = B64.decode(&unwrapped_b64).unwrap();
        assert_eq!(unwrapped, dek, "DEK survives round-trip");
    }

    #[test]
    fn wrap_rejects_short_recipient_pub() {
        // PyErr message content isn't introspectable from cargo test
        // without a Python interpreter in PyO3 0.28+. The wrap path's
        // contract here is just "non-32-byte input is an error" —
        // unwrap_err() captures that. Detailed message text is checked
        // at the Python-pytest layer.
        let too_short = B64.encode([0u8; 16]);
        let dek = B64.encode([0u8; 32]);
        let _err = wrap_dek_for_recipient_json(&too_short, &dek).unwrap_err();
    }
}
