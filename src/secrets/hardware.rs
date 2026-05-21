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
use zeroize::Zeroizing;

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
/// wrapped-blob envelopes in, under persist's `CIRIS_DATA_DIR`.
///
/// v1.10.1 (CIRISPersist#87 review M2) — refuses when `CIRIS_DATA_DIR`
/// is unset rather than silently falling back to a world-writable,
/// predictable `/tmp` path. On a TPM host the seed blob is sealed
/// (confidentiality holds), but a `/tmp` fallback is squattable — a
/// local user pre-creating the path as a symlink, or with hostile
/// permissions, is an integrity / availability vector. A deployment
/// that wants hardware-backed secrets must point `CIRIS_DATA_DIR` at
/// a process-private directory.
fn secrets_storage_dir() -> Result<std::path::PathBuf, SecretsError> {
    match std::env::var("CIRIS_DATA_DIR") {
        Ok(d) if !d.is_empty() => Ok(std::path::PathBuf::from(d).join("keyring")),
        _ => Err(SecretsError::HardwareKeyUnavailable(
            "CIRIS_DATA_DIR is not set — refusing to place hardware-key storage \
             under a world-writable /tmp path; set CIRIS_DATA_DIR to a \
             process-private directory to enable hardware-backed secrets"
                .into(),
        )),
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
    let storage_dir = secrets_storage_dir()?;
    let storage = create_platform_storage(SECRETS_STORAGE_ALIAS, storage_dir).map_err(|e| {
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
        // v1.10.1 (#87 review H2) — `Zeroizing` scrubs the raw seed on
        // drop. The seed is the hardware root: leaking it compromises
        // every key ever derived from it.
        let seed = Zeroizing::new(crypto::random_bytes(crypto::KEY_LEN)?);
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
