//! v3.8.0 (CIRISPersist follow-up to CIRISVerify v4.7.0 / CIRISVerify#50) —
//! PyO3 surface for verify v4.7.0's hybrid X25519 + ML-KEM-768 KEX.
//!
//! CIRISVerify v4.7.0 shipped a Python sidecar
//! (`ciris_verify/_wheel_hybrid_kex.py`) that grafts four KEX methods
//! onto the verify wheel's `CIRISVerify` class. Per Eric's discipline —
//! "if it ain't on the FFI/Python interface, it doesn't exist" —
//! persist exposes a PARALLEL surface so callers who hold a
//! `ciris_persist.PyEngine` get the same post-quantum-ready handshake
//! primitive natively, without having to reach across into the verify
//! wheel.
//!
//! The Rust core (`ciris_crypto::hybrid_kex`) is stateless — pure
//! functions taking recipient public-key material and producing an
//! ephemeral `HybridHandshakeMsg` plus a 32-byte session key. Persist
//! exposes them as free functions (not methods on a `#[pyclass]`)
//! because there's no per-instance state to maintain.
//!
//! # Wire shape
//!
//! Algorithm: `hybrid-x25519-mlkem768-hkdf-sha256-v1`. Hybrid mode runs
//! X25519 ECDH in series with ML-KEM-768 encapsulation under one
//! HKDF-SHA256 binding — an attacker must break BOTH primitives to
//! recover the session key. See
//! `src/ciris-crypto/src/hybrid_kex.rs` (verify v4.7.0) for the full
//! protocol description.
//!
//! # Field-encoding convention
//!
//! Persist's existing PyO3 surface uses base64 for raw key/signature
//! bytes crossing the FFI boundary (see `public_key_b64()` /
//! `local_sign_b64` in `pyo3.rs`). This module follows that convention:
//! callers pass base64-encoded keys and receive a JSON envelope with
//! base64-encoded keys / ciphertexts / session-key fields.
//!
//! This differs from verify's wheel-side wire shape (which uses
//! JSON `list[int]` for byte arrays). The persist surface is the
//! one persist consumers (lens-core, the agent's bundled Python) will
//! call directly, so it reads consistently with the rest of `PyEngine`.
//!
//! # Wiring (orchestrator task — NOT done in this file)
//!
//! After this file lands the integrator MUST do three things:
//!
//! 1. **Cargo.toml** — enable the `hybrid-kex` feature on the
//!    `ciris-crypto` dep. Either fold it into persist's existing
//!    `pyo3` feature (mirrors how `aes-gcm` / `kdf` / `hmac` are
//!    folded into `secrets`):
//!
//!    ```toml
//!    pyo3 = ["dep:pyo3", "postgres", "ciris-crypto/hybrid-kex"]
//!    ```
//!
//!    Or add it as a standalone `hybrid-kex` feature that `pyo3`
//!    depends on (preferred if other non-Python consumers may want
//!    the KEX too — e.g. the C-ABI shell in Phase 2):
//!
//!    ```toml
//!    hybrid-kex = ["ciris-crypto/hybrid-kex"]
//!    pyo3       = ["dep:pyo3", "postgres", "hybrid-kex"]
//!    ```
//!
//! 2. **`src/ffi/mod.rs`** — add the module declaration, gated to the
//!    same feature set as the rest of the PyO3 surface:
//!
//!    ```ignore
//!    #[cfg(feature = "pyo3")]
//!    pub mod wheel_hybrid_kex;
//!    ```
//!
//! 3. **`src/ffi/pyo3.rs`** — graft four thin methods onto `PyEngine`
//!    inside the existing `#[pymethods] impl PyEngine` block. Each
//!    delegates to a free function in this module:
//!
//!    ```ignore
//!    /// Initiate side: hybrid X25519 + ML-KEM-768 KEX.
//!    /// See `ciris_verify._wheel_hybrid_kex.initiate_hybrid_kex` for
//!    /// the parallel verify-wheel surface.
//!    fn initiate_hybrid_kex_b64(
//!        &self,
//!        recipient_x25519_pub_b64: &str,
//!        recipient_mlkem768_pub_b64: &str,
//!    ) -> PyResult<String> {
//!        crate::ffi::wheel_hybrid_kex::initiate_hybrid_kex_json(
//!            recipient_x25519_pub_b64,
//!            recipient_mlkem768_pub_b64,
//!        )
//!    }
//!
//!    /// Respond side: derive the matching 32-byte session key.
//!    fn respond_hybrid_kex_b64(
//!        &self,
//!        recipient_x25519_priv_b64: &str,
//!        recipient_mlkem768_priv_b64: &str,
//!        recipient_mlkem768_pub_b64: &str,
//!        handshake_msg_json: &str,
//!    ) -> PyResult<String> {
//!        crate::ffi::wheel_hybrid_kex::respond_hybrid_kex_json(
//!            recipient_x25519_priv_b64,
//!            recipient_mlkem768_priv_b64,
//!            recipient_mlkem768_pub_b64,
//!            handshake_msg_json,
//!        )
//!    }
//!
//!    /// Initiate side: classical X25519-only KEX fallback.
//!    fn initiate_classical_kex_b64(
//!        &self,
//!        recipient_x25519_pub_b64: &str,
//!    ) -> PyResult<String> {
//!        crate::ffi::wheel_hybrid_kex::initiate_classical_kex_json(
//!            recipient_x25519_pub_b64,
//!        )
//!    }
//!
//!    /// Respond side: classical X25519-only KEX fallback.
//!    fn respond_classical_kex_b64(
//!        &self,
//!        recipient_x25519_priv_b64: &str,
//!        handshake_msg_json: &str,
//!    ) -> PyResult<String> {
//!        crate::ffi::wheel_hybrid_kex::respond_classical_kex_json(
//!            recipient_x25519_priv_b64,
//!            handshake_msg_json,
//!        )
//!    }
//!    ```
//!
//! Python callers then get:
//!
//! ```python
//! import base64, json
//! from ciris_persist import PyEngine
//! eng = PyEngine(...)
//! out = json.loads(eng.initiate_hybrid_kex_b64(
//!     recipient_x_pub_b64, recipient_mlkem_pub_b64,
//! ))
//! send_to_peer = {
//!     "algorithm":             out["algorithm"],
//!     "x25519_ephemeral_pub":  out["x25519_ephemeral_pub_b64"],
//!     "mlkem768_ciphertext":   out["mlkem768_ciphertext_b64"],
//! }
//! session_key = base64.b64decode(out["session_key_b64"])  # SECRET — keep local
//! ```

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

use ciris_crypto::hybrid_kex::{
    initiate_classical, initiate_hybrid, respond_classical, respond_hybrid_with_public,
    ClassicalHandshakeMsg, HybridHandshakeMsg, KEX_ALGORITHM_CLASSICAL_V1, KEX_ALGORITHM_HYBRID_V1,
};

// =============================================================================
// Wire-format types — base64-encoded mirrors of the verify Rust types
// =============================================================================

/// Initiate-side return envelope for the hybrid KEX. All byte fields
/// are base64 (standard alphabet, padded) — matching persist's
/// `*_b64` PyO3 convention.
///
/// The `session_key_b64` field is SECRET — callers must keep it local
/// and not transmit it. Send only `algorithm` +
/// `x25519_ephemeral_pub_b64` + `mlkem768_ciphertext_b64` to the peer.
#[derive(Debug, Serialize, Deserialize)]
struct HybridInitiateOutB64 {
    algorithm: String,
    x25519_ephemeral_pub_b64: String,
    mlkem768_ciphertext_b64: String,
    session_key_b64: String,
}

/// Respond-side return envelope.
#[derive(Debug, Serialize, Deserialize)]
struct RespondOutB64 {
    session_key_b64: String,
}

/// Wire shape for the handshake message the initiator sends to the
/// responder. Mirrors `ciris_crypto::hybrid_kex::HybridHandshakeMsg`
/// but with base64 fields so it round-trips through persist's
/// b64-encoded FFI surface.
#[derive(Debug, Serialize, Deserialize)]
struct HybridHandshakeMsgB64 {
    algorithm: String,
    x25519_ephemeral_pub_b64: String,
    mlkem768_ciphertext_b64: String,
}

/// Classical-fallback initiate-side return envelope.
#[derive(Debug, Serialize, Deserialize)]
struct ClassicalInitiateOutB64 {
    algorithm: String,
    x25519_ephemeral_pub_b64: String,
    session_key_b64: String,
}

/// Classical-fallback handshake message wire shape.
#[derive(Debug, Serialize, Deserialize)]
struct ClassicalHandshakeMsgB64 {
    algorithm: String,
    x25519_ephemeral_pub_b64: String,
}

// =============================================================================
// Input validation helpers
// =============================================================================

/// Decode + length-check a base64 X25519 key (32 bytes exact).
fn decode_x25519_key(field: &str, b64: &str) -> PyResult<[u8; 32]> {
    let bytes = B64
        .decode(b64)
        .map_err(|e| PyValueError::new_err(format!("{field}: base64 decode failed: {e}")))?;
    if bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "{field}: X25519 key MUST be 32 bytes (got {})",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Decode a base64 byte string (no length constraint — used for
/// ML-KEM keys/ciphertexts which have FIPS-203 specified lengths but
/// we let the ciris-crypto layer enforce them so we don't
/// hard-code the constants here).
fn decode_b64(field: &str, b64: &str) -> PyResult<Vec<u8>> {
    B64.decode(b64)
        .map_err(|e| PyValueError::new_err(format!("{field}: base64 decode failed: {e}")))
}

// =============================================================================
// Free functions — these are what PyEngine methods delegate to
// =============================================================================

/// Initiate side: hybrid X25519 + ML-KEM-768 KEX (CIRISVerify#47/#50).
///
/// Generates an ephemeral X25519 keypair, ECDHs against the recipient's
/// long-term X25519 public key, encapsulates a fresh ML-KEM-768 shared
/// secret against the recipient's long-term ML-KEM-768 public key, and
/// HKDF-binds everything into a 32-byte session key. The result is
/// harvest-now-decrypt-later resistant — an attacker must break BOTH
/// X25519 AND ML-KEM-768 to recover the session key.
///
/// # Returns
///
/// JSON string carrying `{algorithm, x25519_ephemeral_pub_b64,
/// mlkem768_ciphertext_b64, session_key_b64}`. The `session_key_b64`
/// field is SECRET — keep it local; the other three go to the peer.
///
/// # Errors
///
/// - `PyValueError` if `recipient_x25519_pub_b64` does not decode to
///   exactly 32 bytes, or any input fails base64 decoding.
/// - `PyRuntimeError` wrapping a `KexError` if the underlying crypto
///   primitives fail (in practice: ML-KEM keypair length mismatch).
pub fn initiate_hybrid_kex_json(
    recipient_x25519_pub_b64: &str,
    recipient_mlkem768_pub_b64: &str,
) -> PyResult<String> {
    let x_pub = decode_x25519_key("recipient_x25519_pub_b64", recipient_x25519_pub_b64)?;
    let mlkem_pub = decode_b64("recipient_mlkem768_pub_b64", recipient_mlkem768_pub_b64)?;

    let (msg, session_key) = initiate_hybrid(&x_pub, &mlkem_pub)
        .map_err(|e| PyRuntimeError::new_err(format!("hybrid_kex initiate failed: {e}")))?;

    let out = HybridInitiateOutB64 {
        algorithm: msg.algorithm,
        x25519_ephemeral_pub_b64: B64.encode(msg.x25519_ephemeral_pub),
        mlkem768_ciphertext_b64: B64.encode(&msg.mlkem768_ciphertext),
        session_key_b64: B64.encode(session_key),
    };
    serde_json::to_string(&out)
        .map_err(|e| PyRuntimeError::new_err(format!("hybrid_kex JSON encode failed: {e}")))
}

/// Respond side: derive the matching 32-byte session key from the
/// initiator's handshake message.
///
/// The session key matches what the initiator derived iff the message
/// was untampered AND the recipient keys are correct. Per the v4.6.0
/// opaque-failure discipline, wrong-key / tampered-ciphertext cases
/// produce a *different* (but still successfully returned) session
/// key — the AEAD layer above this KEX detects the mismatch as a tag
/// failure. Only algorithm-identifier mismatches surface as a typed
/// `PyRuntimeError`.
///
/// # Arguments
///
/// - `recipient_x25519_priv_b64`: recipient's long-term X25519 private
///   key, base64-encoded (32 bytes when decoded).
/// - `recipient_mlkem768_priv_b64`: recipient's long-term ML-KEM-768
///   private key, base64-encoded.
/// - `recipient_mlkem768_pub_b64`: recipient's long-term ML-KEM-768
///   public key, base64-encoded (needed for HKDF salt binding).
/// - `handshake_msg_json`: JSON-encoded `HybridHandshakeMsgB64` from
///   the initiator — `{algorithm, x25519_ephemeral_pub_b64,
///   mlkem768_ciphertext_b64}`.
///
/// # Returns
///
/// JSON string `{"session_key_b64": "..."}`.
pub fn respond_hybrid_kex_json(
    recipient_x25519_priv_b64: &str,
    recipient_mlkem768_priv_b64: &str,
    recipient_mlkem768_pub_b64: &str,
    handshake_msg_json: &str,
) -> PyResult<String> {
    let x_priv = decode_x25519_key("recipient_x25519_priv_b64", recipient_x25519_priv_b64)?;
    let mlkem_priv = decode_b64("recipient_mlkem768_priv_b64", recipient_mlkem768_priv_b64)?;
    let mlkem_pub = decode_b64("recipient_mlkem768_pub_b64", recipient_mlkem768_pub_b64)?;

    let parsed: HybridHandshakeMsgB64 = serde_json::from_str(handshake_msg_json)
        .map_err(|e| PyValueError::new_err(format!("handshake_msg_json parse failed: {e}")))?;

    // Decode the message's inner fields and rebuild the verify-side
    // wire type. We don't validate algorithm here; the verify layer
    // enforces it via `KexError::AlgorithmMismatch`.
    let eph_pub = decode_x25519_key("x25519_ephemeral_pub_b64", &parsed.x25519_ephemeral_pub_b64)?;
    let mlkem_ct = decode_b64("mlkem768_ciphertext_b64", &parsed.mlkem768_ciphertext_b64)?;

    let msg = HybridHandshakeMsg {
        algorithm: parsed.algorithm,
        x25519_ephemeral_pub: eph_pub,
        mlkem768_ciphertext: mlkem_ct,
    };

    let session_key = respond_hybrid_with_public(&x_priv, &mlkem_priv, &mlkem_pub, &msg)
        .map_err(|e| PyRuntimeError::new_err(format!("hybrid_kex respond failed: {e}")))?;

    let out = RespondOutB64 {
        session_key_b64: B64.encode(session_key),
    };
    serde_json::to_string(&out)
        .map_err(|e| PyRuntimeError::new_err(format!("hybrid_kex JSON encode failed: {e}")))
}

/// Initiate side: classical X25519-only KEX fallback.
///
/// Used when a peer doesn't advertise ML-KEM-768 support. Identical
/// shape to [`initiate_hybrid_kex_json`] minus the ML-KEM-768
/// ciphertext.
pub fn initiate_classical_kex_json(recipient_x25519_pub_b64: &str) -> PyResult<String> {
    let x_pub = decode_x25519_key("recipient_x25519_pub_b64", recipient_x25519_pub_b64)?;

    let (msg, session_key) = initiate_classical(&x_pub)
        .map_err(|e| PyRuntimeError::new_err(format!("classical_kex initiate failed: {e}")))?;

    let out = ClassicalInitiateOutB64 {
        algorithm: msg.algorithm,
        x25519_ephemeral_pub_b64: B64.encode(msg.x25519_ephemeral_pub),
        session_key_b64: B64.encode(session_key),
    };
    serde_json::to_string(&out)
        .map_err(|e| PyRuntimeError::new_err(format!("classical_kex JSON encode failed: {e}")))
}

/// Respond side: classical X25519-only KEX fallback.
pub fn respond_classical_kex_json(
    recipient_x25519_priv_b64: &str,
    handshake_msg_json: &str,
) -> PyResult<String> {
    let x_priv = decode_x25519_key("recipient_x25519_priv_b64", recipient_x25519_priv_b64)?;

    let parsed: ClassicalHandshakeMsgB64 = serde_json::from_str(handshake_msg_json)
        .map_err(|e| PyValueError::new_err(format!("handshake_msg_json parse failed: {e}")))?;
    let eph_pub = decode_x25519_key("x25519_ephemeral_pub_b64", &parsed.x25519_ephemeral_pub_b64)?;

    let msg = ClassicalHandshakeMsg {
        algorithm: parsed.algorithm,
        x25519_ephemeral_pub: eph_pub,
    };

    let session_key = respond_classical(&x_priv, &msg)
        .map_err(|e| PyRuntimeError::new_err(format!("classical_kex respond failed: {e}")))?;

    let out = RespondOutB64 {
        session_key_b64: B64.encode(session_key),
    };
    serde_json::to_string(&out)
        .map_err(|e| PyRuntimeError::new_err(format!("classical_kex JSON encode failed: {e}")))
}

// =============================================================================
// Constants exposed for callers that want to assert algorithm IDs
// without parsing a JSON envelope.
// =============================================================================

/// Wire constant — hybrid mode algorithm identifier. Mirrors
/// `ciris_crypto::hybrid_kex::KEX_ALGORITHM_HYBRID_V1`.
pub const ALGORITHM_HYBRID_V1: &str = KEX_ALGORITHM_HYBRID_V1;

/// Wire constant — classical fallback algorithm identifier. Mirrors
/// `ciris_crypto::hybrid_kex::KEX_ALGORITHM_CLASSICAL_V1`.
pub const ALGORITHM_CLASSICAL_V1: &str = KEX_ALGORITHM_CLASSICAL_V1;

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::{ml_kem, x25519};
    use serde_json::Value;

    /// Helper — generate a fresh recipient hybrid keypair set
    /// (X25519 + ML-KEM-768) using the verify crate's own public
    /// generators. Returns (x_priv, x_pub, mlkem_priv, mlkem_pub),
    /// all in base64.
    fn fresh_recipient_b64() -> (String, String, String, String) {
        let (x_sk, x_pk) = x25519::generate_ephemeral_keypair().expect("x25519 keypair");
        let (mlkem_sk, mlkem_pk) = ml_kem::generate_keypair().expect("ml-kem keypair");
        (
            B64.encode(x_sk),
            B64.encode(x_pk),
            B64.encode(&mlkem_sk),
            B64.encode(&mlkem_pk),
        )
    }

    /// Headline correctness — hybrid initiate -> respond yields the
    /// SAME 32-byte session key on both sides.
    #[test]
    fn hybrid_round_trip_yields_matching_session_keys() {
        let (rx_x_priv_b64, rx_x_pub_b64, rx_mlkem_priv_b64, rx_mlkem_pub_b64) =
            fresh_recipient_b64();

        let init_json = initiate_hybrid_kex_json(&rx_x_pub_b64, &rx_mlkem_pub_b64)
            .expect("initiate_hybrid_kex_json");
        let init: Value = serde_json::from_str(&init_json).unwrap();

        // Algorithm sanity-check.
        assert_eq!(init["algorithm"], ALGORITHM_HYBRID_V1);

        // The initiator's session key — secret to this side.
        let initiator_session_key = init["session_key_b64"].as_str().unwrap().to_string();

        // Build the wire message (everything the peer needs).
        let handshake_msg = serde_json::json!({
            "algorithm": init["algorithm"],
            "x25519_ephemeral_pub_b64": init["x25519_ephemeral_pub_b64"],
            "mlkem768_ciphertext_b64": init["mlkem768_ciphertext_b64"],
        })
        .to_string();

        // Responder derives.
        let resp_json = respond_hybrid_kex_json(
            &rx_x_priv_b64,
            &rx_mlkem_priv_b64,
            &rx_mlkem_pub_b64,
            &handshake_msg,
        )
        .expect("respond_hybrid_kex_json");
        let resp: Value = serde_json::from_str(&resp_json).unwrap();

        let responder_session_key = resp["session_key_b64"].as_str().unwrap();
        assert_eq!(
            initiator_session_key, responder_session_key,
            "hybrid KEX round-trip MUST yield matching session keys"
        );

        // 32 bytes (b64-decoded) — sanity that we got a real key.
        let raw = B64.decode(responder_session_key).unwrap();
        assert_eq!(raw.len(), 32);
    }

    /// Fresh handshakes against the same recipient produce DISTINCT
    /// session keys — ephemeral X25519 + fresh ML-KEM encapsulation
    /// each call.
    #[test]
    fn hybrid_fresh_handshakes_produce_distinct_session_keys() {
        let (_, rx_x_pub_b64, _, rx_mlkem_pub_b64) = fresh_recipient_b64();
        let a: Value = serde_json::from_str(
            &initiate_hybrid_kex_json(&rx_x_pub_b64, &rx_mlkem_pub_b64).unwrap(),
        )
        .unwrap();
        let b: Value = serde_json::from_str(
            &initiate_hybrid_kex_json(&rx_x_pub_b64, &rx_mlkem_pub_b64).unwrap(),
        )
        .unwrap();
        assert_ne!(a["session_key_b64"], b["session_key_b64"]);
    }

    /// Classical-fallback round-trip parity test.
    #[test]
    fn classical_round_trip_yields_matching_session_keys() {
        let (rx_x_priv_b64, rx_x_pub_b64, _, _) = fresh_recipient_b64();

        let init_json =
            initiate_classical_kex_json(&rx_x_pub_b64).expect("initiate_classical_kex_json");
        let init: Value = serde_json::from_str(&init_json).unwrap();
        assert_eq!(init["algorithm"], ALGORITHM_CLASSICAL_V1);
        let initiator_key = init["session_key_b64"].as_str().unwrap().to_string();

        let handshake_msg = serde_json::json!({
            "algorithm": init["algorithm"],
            "x25519_ephemeral_pub_b64": init["x25519_ephemeral_pub_b64"],
        })
        .to_string();

        let resp_json = respond_classical_kex_json(&rx_x_priv_b64, &handshake_msg)
            .expect("respond_classical_kex_json");
        let resp: Value = serde_json::from_str(&resp_json).unwrap();
        assert_eq!(initiator_key, resp["session_key_b64"]);
    }

    // PyErr message content isn't introspectable from `cargo test`
    // without a Python interpreter in PyO3 0.28+. These tests just
    // assert the unhappy paths are errors; detailed message-text
    // checks happen at the Python-pytest layer.

    /// Wrong-length X25519 key surfaces as PyValueError.
    #[test]
    fn wrong_x25519_key_length_rejected_with_value_error() {
        let bad_x_pub_b64 = B64.encode([0u8; 16]);
        let (_, _, _, rx_mlkem_pub_b64) = fresh_recipient_b64();
        let _err = initiate_hybrid_kex_json(&bad_x_pub_b64, &rx_mlkem_pub_b64).unwrap_err();
    }

    /// Non-base64 input surfaces as PyValueError.
    #[test]
    fn non_base64_input_rejected_with_value_error() {
        let (_, _, _, rx_mlkem_pub_b64) = fresh_recipient_b64();
        let _err = initiate_hybrid_kex_json("!!!not-base64!!!", &rx_mlkem_pub_b64).unwrap_err();
    }

    /// Algorithm-identifier mismatch surfaces as PyRuntimeError
    /// (defense against silent downgrade).
    #[test]
    fn hybrid_wrong_algorithm_identifier_rejected_with_runtime_error() {
        let (rx_x_priv_b64, rx_x_pub_b64, rx_mlkem_priv_b64, rx_mlkem_pub_b64) =
            fresh_recipient_b64();
        let init: Value = serde_json::from_str(
            &initiate_hybrid_kex_json(&rx_x_pub_b64, &rx_mlkem_pub_b64).unwrap(),
        )
        .unwrap();

        // Hand the responder a message tagged with the classical algo —
        // verify rejects with `KexError::AlgorithmMismatch`.
        let bad_msg = serde_json::json!({
            "algorithm": ALGORITHM_CLASSICAL_V1,
            "x25519_ephemeral_pub_b64": init["x25519_ephemeral_pub_b64"],
            "mlkem768_ciphertext_b64": init["mlkem768_ciphertext_b64"],
        })
        .to_string();

        let _err = respond_hybrid_kex_json(
            &rx_x_priv_b64,
            &rx_mlkem_priv_b64,
            &rx_mlkem_pub_b64,
            &bad_msg,
        )
        .unwrap_err();
    }

    /// Wrong recipient keys -> diverged session key (NOT an error per
    /// the opaque-failure discipline — the AEAD layer above this KEX
    /// catches it).
    #[test]
    fn hybrid_wrong_recipient_keys_yield_diverged_session() {
        let (rx_x_priv_b64, rx_x_pub_b64, rx_mlkem_priv_b64, rx_mlkem_pub_b64) =
            fresh_recipient_b64();
        let (wrong_x_priv_b64, _, wrong_mlkem_priv_b64, wrong_mlkem_pub_b64) =
            fresh_recipient_b64();

        let init: Value = serde_json::from_str(
            &initiate_hybrid_kex_json(&rx_x_pub_b64, &rx_mlkem_pub_b64).unwrap(),
        )
        .unwrap();
        let initiator_key = init["session_key_b64"].as_str().unwrap().to_string();

        let handshake_msg = serde_json::json!({
            "algorithm": init["algorithm"],
            "x25519_ephemeral_pub_b64": init["x25519_ephemeral_pub_b64"],
            "mlkem768_ciphertext_b64": init["mlkem768_ciphertext_b64"],
        })
        .to_string();

        // Legit recipient -> matching key.
        let legit_resp: Value = serde_json::from_str(
            &respond_hybrid_kex_json(
                &rx_x_priv_b64,
                &rx_mlkem_priv_b64,
                &rx_mlkem_pub_b64,
                &handshake_msg,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(initiator_key, legit_resp["session_key_b64"]);

        // Wrong recipient -> diverged key (NOT an error).
        let wrong_resp: Value = serde_json::from_str(
            &respond_hybrid_kex_json(
                &wrong_x_priv_b64,
                &wrong_mlkem_priv_b64,
                &wrong_mlkem_pub_b64,
                &handshake_msg,
            )
            .unwrap(),
        )
        .unwrap();
        assert_ne!(initiator_key, wrong_resp["session_key_b64"]);
    }

    /// Algorithm-identifier wire constants are stable. Re-asserting
    /// here gives persist its own lock on the wire shape — any future
    /// rotation MUST land in lockstep with verify.
    #[test]
    fn algorithm_identifiers_are_stable_wire_constants() {
        assert_eq!(ALGORITHM_HYBRID_V1, "hybrid-x25519-mlkem768-hkdf-sha256-v1");
        assert_eq!(ALGORITHM_CLASSICAL_V1, "classical-x25519-hkdf-sha256-v1");
    }
}
