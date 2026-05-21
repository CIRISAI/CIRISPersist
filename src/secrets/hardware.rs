//! Hardware-rooted secrets master-key derivation (CIRISPersist#87).
//!
//! `migrate_to_hardware_key` re-encrypts the secrets store under a
//! master key derived from a **hardware-sealed seed**. The derivation
//! is CIRISVerify's — persist calls
//! [`ciris_verify_core::derive_symmetric_key`] and never rolls its own
//! crypto. (v2.4.0 trapped that function behind the C-ABI
//! `ciris-verify-ffi` crate; CIRISVerify#25 / v2.5.0 promoted it into
//! the `ciris-verify-core` rlib precisely so persist could call it.)
//!
//! ## Derivation chain
//!
//! ```text
//! random 32B seed ──store──▶ SecureBlobStorage (TPM / Keystore /
//!                                                Secure Enclave)
//!         │
//!         └─ HKDF-SHA256(salt = "CIRIS-named-key-derive-v1",
//!                        info = "secrets-store-master-v1")  ◀── verify
//!                        │
//!                        ▼
//!              32-byte secrets master key  (never itself stored)
//! ```
//!
//! The seed is sealed by the platform secure storage; the master key
//! is HKDF-derived from it on demand and held only in the in-process
//! key cache. A change of [`SECRETS_MASTER_CONTEXT`] re-derives a
//! different master and orphans every encrypted secret — it is a
//! stable wire constant.

use ciris_keyring::create_platform_storage;

use super::crypto;
use super::SecretsError;

/// Blob-storage alias for persist's secure storage.
const SECRETS_STORAGE_ALIAS: &str = "ciris-persist-secrets";

/// Key id of the hardware-sealed seed the secrets master is derived
/// from. The seed is 32 random bytes sealed by the platform
/// `SecureBlobStorage`; the master key is HKDF-derived from it, so
/// the master itself is never written to storage.
const SECRETS_SEED_KEY_ID: &str = "cirislens-secrets-seed";

/// HKDF `context` (info string) for the secrets-master derivation.
/// **Stable wire constant** — changing it re-derives a different
/// master key and orphans every secret encrypted under the old one.
const SECRETS_MASTER_CONTEXT: &str = "secrets-store-master-v1";

/// Resolve the directory the platform secure storage keeps its
/// wrapped-blob envelopes in. Mirrors persist's `CIRIS_DATA_DIR`
/// convention (the same env var the keyring bootstrap lock honours).
fn secrets_storage_dir() -> std::path::PathBuf {
    match std::env::var("CIRIS_DATA_DIR") {
        Ok(d) if !d.is_empty() => std::path::PathBuf::from(d).join("keyring"),
        _ => std::path::PathBuf::from("/tmp/ciris-persist-keyring"),
    }
}

/// Derive the hardware-rooted secrets master key.
///
/// Returns the 32-byte master key plus a descriptor string for
/// `master_key_meta.descriptor`. **Synchronous / blocking** (TPM +
/// filesystem I/O) — call it from `spawn_blocking`.
///
/// Fails with [`SecretsError::HardwareKeyUnavailable`] when the
/// platform has no hardware-backed secure storage. The caller (the
/// agent) treats that as "stay on the software master key" — it is a
/// clean, expected outcome on a no-TPM host, not an error to surface.
pub(crate) fn derive_hardware_master_key() -> Result<(Vec<u8>, String), SecretsError> {
    let storage =
        create_platform_storage(SECRETS_STORAGE_ALIAS, secrets_storage_dir()).map_err(|e| {
            SecretsError::HardwareKeyUnavailable(format!("secure storage init failed: {e}"))
        })?;

    // No TPM / Keystore / Secure Enclave → no hardware migration.
    // create_platform_storage would have fallen back to software file
    // storage; deriving a "hardware" master from that is dishonest, so
    // refuse and let the caller keep the software master key.
    if !storage.is_hardware_backed() {
        return Err(SecretsError::HardwareKeyUnavailable(
            "no hardware-backed secure storage on this platform \
             (no TPM / Keystore / Secure Enclave) — keeping the software master key"
                .into(),
        ));
    }

    // Ensure the hardware-sealed seed exists. The first migration on a
    // host generates + seals it; later calls re-derive the same master
    // from the same seed (idempotent).
    if !storage.exists(SECRETS_SEED_KEY_ID) {
        let seed = crypto::random_bytes(crypto::KEY_LEN)?;
        storage
            .store(SECRETS_SEED_KEY_ID, &seed)
            .map_err(|e| SecretsError::HardwareKeyUnavailable(format!("seal secrets seed: {e}")))?;
    }

    // CIRISVerify owns the derivation (HKDF-SHA256 over the sealed
    // seed). Persist never implements the KDF itself.
    let master = ciris_verify_core::derive_symmetric_key(
        storage.as_ref(),
        SECRETS_SEED_KEY_ID,
        SECRETS_MASTER_CONTEXT,
    )
    .map_err(|e| {
        SecretsError::HardwareKeyUnavailable(format!("verify derive_symmetric_key failed: {e}"))
    })?;

    if master.len() != crypto::KEY_LEN {
        return Err(SecretsError::Crypto(format!(
            "verify derived a {}-byte key; expected {}",
            master.len(),
            crypto::KEY_LEN
        )));
    }

    let descriptor = format!(
        "hardware-blob-storage seed={SECRETS_SEED_KEY_ID} context={SECRETS_MASTER_CONTEXT}"
    );
    Ok((master, descriptor))
}
