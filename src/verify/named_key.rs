//! v62.0.0 (slice D) — **the named-key derivation, available to a node.**
//!
//! `ciris_verify_core::derive_symmetric_key` (the HKDF over a stored
//! named-key seed that keys persist's secrets master and the MLS-state store)
//! sits in Verify 23's `host` tier with the rest of `keys`. A node build has
//! no `host`, and the derivation is pure, so persist carries it here, byte
//! for byte (the same salt, hash, info and length), through ciris-crypto's
//! HKDF. I1859 pins it equal to Verify's on a host build.
//!
//! ```text
//! PRK = HKDF-Extract(salt = "CIRIS-named-key-derive-v1", IKM = seed)
//! key = HKDF-Expand(PRK, info = context, L = 32)
//! ```

use zeroize::Zeroizing;

/// Verify's `NAMED_KEY_DERIVE_SALT`. **Stable wire constant.**
const NAMED_KEY_DERIVE_SALT: &[u8] = b"CIRIS-named-key-derive-v1";

/// Length of a derived symmetric key (256-bit).
pub const DERIVED_KEY_LEN: usize = 32;

/// Why a derivation produced no key.
#[derive(Debug, thiserror::Error)]
pub enum NamedKeyError {
    /// The seed for the key id could not be loaded.
    #[error("named key seed load: {0}")]
    Load(#[from] ciris_keyring::KeyringError),
    /// HKDF refused (unreachable for 32 bytes; mapped, never unwrapped).
    #[error("named key HKDF: {0}")]
    Hkdf(String),
}

/// Derive the 32-byte key for `context` from the seed `storage` holds under
/// `key_id`. The same `(seed, context)` always yields the same key.
///
/// # Errors
/// [`NamedKeyError`] on a load or HKDF fault.
pub fn derive_symmetric_key(
    storage: &dyn ciris_keyring::SecureBlobStorage,
    key_id: &str,
    context: &str,
) -> Result<Vec<u8>, NamedKeyError> {
    let seed = Zeroizing::new(storage.load(key_id)?);
    ciris_crypto::kdf::hkdf_sha256(
        &seed,
        NAMED_KEY_DERIVE_SALT,
        context.as_bytes(),
        DERIVED_KEY_LEN,
    )
    .map_err(|e| NamedKeyError::Hkdf(e.to_string()))
}

#[cfg(all(test, feature = "host"))]
mod tests {
    /// I1859 — persist's derivation is Verify's, byte for byte.
    #[test]
    fn i1859_the_named_key_derivation_is_verifys() {
        struct One(Vec<u8>);
        impl ciris_keyring::SecureBlobStorage for One {
            fn store(&self, _: &str, _: &[u8]) -> Result<(), ciris_keyring::KeyringError> {
                Ok(())
            }
            fn load(&self, _: &str) -> Result<Vec<u8>, ciris_keyring::KeyringError> {
                Ok(self.0.clone())
            }
            fn exists(&self, _: &str) -> bool {
                true
            }
            fn delete(&self, _: &str) -> Result<(), ciris_keyring::KeyringError> {
                Ok(())
            }
            fn list_keys(&self) -> Result<Vec<String>, ciris_keyring::KeyringError> {
                Ok(vec!["k".into()])
            }
            fn is_hardware_backed(&self) -> bool {
                false
            }
            fn diagnostics(&self) -> String {
                "I1859 one-seed".into()
            }
        }
        for (seed, ctx) in [
            (vec![0u8; 32], "secrets-store-master-v1"),
            ((0u8..64).collect::<Vec<u8>>(), "mls-state-at-rest-v1"),
            (vec![0xA5; 32], ""),
        ] {
            let s = One(seed);
            assert_eq!(
                super::derive_symmetric_key(&s, "k", ctx).unwrap(),
                ciris_verify_core::derive_symmetric_key(&s, "k", ctx).unwrap(),
                "I1859: {ctx:?}"
            );
        }
    }
}
