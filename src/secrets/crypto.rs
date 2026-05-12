//! Crypto facade — the ONLY import site of `ciris_crypto::*` in
//! persist (FSD `POST_INGEST_FILTER_PIPELINE.md` §7.5a).
//!
//! Every crypto operation in `src/secrets/` routes through this
//! file. The rest of the secrets module imports from
//! `crate::secrets::crypto`; persist takes ZERO direct primitive
//! deps on `aes_gcm` / `pbkdf2` / `hkdf` / `hmac` / `rand` crates.
//! The boundary is auditable in one file.
//!
//! # Operations exposed
//!
//! - [`random_bytes`] — `n` cryptographically-random bytes from the
//!   OS-RNG via `ciris_crypto::random::bytes`.
//! - [`derive_secret_key`] — PBKDF2-HMAC-SHA-256 master + salt →
//!   per-secret key. Routes to `ciris_crypto::kdf::pbkdf2_hmac_sha256`.
//! - [`encrypt`] / [`decrypt`] — AES-256-GCM via
//!   `ciris_crypto::aes_gcm::{encrypt,decrypt}`. Caller supplies
//!   key + nonce; this facade owns nonce-generation policy for the
//!   `store_secret` path (12 random bytes per the GCM spec).
//! - [`hmac_sha256`] — auth tag computation for non-AES paths
//!   (filter-config integrity, audit-log row hash). Routes to
//!   `ciris_crypto::hmac::sha256`.
//!
//! # PBKDF2 iteration count
//!
//! 600,000 iterations per OWASP 2023 recommendation for PBKDF2-
//! HMAC-SHA-256. Hard-coded here (no env override) so deployments
//! can't accidentally weaken the KDF. The cost is bounded —
//! master-key derivation runs ONCE at SecretsService init, not on
//! every encrypt.

use super::SecretsError;

/// PBKDF2 iteration count. OWASP 2023 for PBKDF2-HMAC-SHA-256.
const PBKDF2_ITERS: u32 = 600_000;

/// AES-256 key length (bytes).
pub const KEY_LEN: usize = 32;

/// AES-GCM nonce length (bytes).
pub const NONCE_LEN: usize = 12;

/// PBKDF2 salt length (bytes). 32 bytes is well above NIST minimum.
pub const SALT_LEN: usize = 32;

/// Generate `n` cryptographically-random bytes from the OS-RNG.
///
/// Implementation: `ciris_crypto::random::bytes(n)`. Returns
/// [`SecretsError::Crypto`] on RNG failure (vanishingly rare; OS-
/// level entropy starvation).
pub fn random_bytes(n: usize) -> Result<Vec<u8>, SecretsError> {
    ciris_crypto::random::bytes(n).map_err(|e| SecretsError::Crypto(format!("random: {e}")))
}

/// Generate a fresh AES-GCM nonce (12 bytes).
pub fn random_nonce() -> Result<[u8; NONCE_LEN], SecretsError> {
    let v = random_bytes(NONCE_LEN)?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&v);
    Ok(nonce)
}

/// Generate a fresh per-secret salt (32 bytes).
pub fn random_salt() -> Result<[u8; SALT_LEN], SecretsError> {
    let v = random_bytes(SALT_LEN)?;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&v);
    Ok(salt)
}

/// Generate a fresh 32-byte master key (used by `rotate_master_key`).
pub fn random_master_key() -> Result<[u8; KEY_LEN], SecretsError> {
    let v = random_bytes(KEY_LEN)?;
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&v);
    Ok(key)
}

/// Derive a per-secret AES-256 key from `(master_key, salt)` via
/// PBKDF2-HMAC-SHA-256 (600k iters, OWASP 2023).
pub fn derive_secret_key(master_key: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], SecretsError> {
    if master_key.len() != KEY_LEN {
        return Err(SecretsError::InvalidArgument(format!(
            "master_key must be {KEY_LEN} bytes (got {})",
            master_key.len()
        )));
    }
    if salt.len() != SALT_LEN {
        return Err(SecretsError::InvalidArgument(format!(
            "salt must be {SALT_LEN} bytes (got {})",
            salt.len()
        )));
    }
    let derived = ciris_crypto::kdf::pbkdf2_hmac_sha256(master_key, salt, PBKDF2_ITERS, KEY_LEN)
        .map_err(|e| SecretsError::Crypto(format!("pbkdf2: {e}")))?;
    let mut key = [0u8; KEY_LEN];
    if derived.len() != KEY_LEN {
        return Err(SecretsError::Crypto(format!(
            "pbkdf2 returned {} bytes; expected {KEY_LEN}",
            derived.len()
        )));
    }
    key.copy_from_slice(&derived);
    Ok(key)
}

/// AES-256-GCM encrypt. `key` is exactly 32 bytes; `nonce` is
/// exactly 12 bytes. Returns `ciphertext || auth_tag` per the GCM
/// spec (`ciris_crypto::aes_gcm::encrypt` packs the tag onto the
/// returned vec).
pub fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SecretsError> {
    if key.len() != KEY_LEN {
        return Err(SecretsError::InvalidArgument(format!(
            "key must be {KEY_LEN} bytes (got {})",
            key.len()
        )));
    }
    if nonce.len() != NONCE_LEN {
        return Err(SecretsError::InvalidArgument(format!(
            "nonce must be {NONCE_LEN} bytes (got {})",
            nonce.len()
        )));
    }
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(key);
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(nonce);
    ciris_crypto::aes_gcm::encrypt(&k, &n, plaintext)
        .map_err(|e| SecretsError::Crypto(format!("aes-gcm encrypt: {e}")))
}

/// AES-256-GCM decrypt. Reverses [`encrypt`]. Returns the plaintext
/// or [`SecretsError::Crypto`] on auth-tag mismatch.
pub fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, SecretsError> {
    if key.len() != KEY_LEN {
        return Err(SecretsError::InvalidArgument(format!(
            "key must be {KEY_LEN} bytes (got {})",
            key.len()
        )));
    }
    if nonce.len() != NONCE_LEN {
        return Err(SecretsError::InvalidArgument(format!(
            "nonce must be {NONCE_LEN} bytes (got {})",
            nonce.len()
        )));
    }
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(key);
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(nonce);
    ciris_crypto::aes_gcm::decrypt(&k, &n, ciphertext)
        .map_err(|e| SecretsError::Crypto(format!("aes-gcm decrypt: {e}")))
}

/// HMAC-SHA-256 auth tag computation. Used by filter-config row
/// integrity + audit-log row hashing.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    ciris_crypto::hmac::sha256(key, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_length() {
        let v = random_bytes(64).unwrap();
        assert_eq!(v.len(), 64);
    }

    #[test]
    fn random_nonce_salt_master_key_shapes() {
        assert_eq!(random_nonce().unwrap().len(), NONCE_LEN);
        assert_eq!(random_salt().unwrap().len(), SALT_LEN);
        assert_eq!(random_master_key().unwrap().len(), KEY_LEN);
    }

    #[test]
    fn derive_secret_key_deterministic() {
        let master = [0x42u8; KEY_LEN];
        let salt = [0xaau8; SALT_LEN];
        let k1 = derive_secret_key(&master, &salt).unwrap();
        let k2 = derive_secret_key(&master, &salt).unwrap();
        assert_eq!(k1, k2, "same (master, salt) → same key");
    }

    #[test]
    fn derive_secret_key_diverges_on_salt() {
        let master = [0x42u8; KEY_LEN];
        let salt_a = [0xaau8; SALT_LEN];
        let salt_b = [0xbbu8; SALT_LEN];
        let k_a = derive_secret_key(&master, &salt_a).unwrap();
        let k_b = derive_secret_key(&master, &salt_b).unwrap();
        assert_ne!(k_a, k_b);
    }

    #[test]
    fn derive_secret_key_rejects_wrong_lengths() {
        let res = derive_secret_key(&[0u8; 16], &[0u8; SALT_LEN]);
        assert!(matches!(res, Err(SecretsError::InvalidArgument(_))));
        let res = derive_secret_key(&[0u8; KEY_LEN], &[0u8; 8]);
        assert!(matches!(res, Err(SecretsError::InvalidArgument(_))));
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = [0x11u8; KEY_LEN];
        let nonce = [0x22u8; NONCE_LEN];
        let plaintext = b"hello, federation";
        let ct = encrypt(&key, &nonce, plaintext).unwrap();
        let pt = decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let key = [0x11u8; KEY_LEN];
        let nonce = [0x22u8; NONCE_LEN];
        let mut ct = encrypt(&key, &nonce, b"hello").unwrap();
        ct[0] ^= 0x01; // flip a bit
        let res = decrypt(&key, &nonce, &ct);
        assert!(
            matches!(res, Err(SecretsError::Crypto(_))),
            "tampered ciphertext must be rejected"
        );
    }

    #[test]
    fn decrypt_rejects_wrong_nonce() {
        let key = [0x11u8; KEY_LEN];
        let nonce = [0x22u8; NONCE_LEN];
        let wrong_nonce = [0x33u8; NONCE_LEN];
        let ct = encrypt(&key, &nonce, b"hello").unwrap();
        let res = decrypt(&key, &wrong_nonce, &ct);
        assert!(matches!(res, Err(SecretsError::Crypto(_))));
    }

    #[test]
    fn hmac_sha256_deterministic_and_diverges_on_input() {
        let k = [0u8; 32];
        let h1 = hmac_sha256(&k, b"alpha");
        let h2 = hmac_sha256(&k, b"alpha");
        let h3 = hmac_sha256(&k, b"beta");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }
}
