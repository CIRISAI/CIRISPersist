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
    // The secrets store's first migration legitimately CREATES the seed.
    derive_hardware_master_for_context(SECRETS_MASTER_CONTEXT, true)
}

/// v43.0.0 (BLOB_ENCRYPTION_AT_REST.md §10.2) — the **content-at-rest**
/// master, derived from the SAME hardware-sealed seed under a DISTINCT
/// HKDF context.
///
/// §4.3 is explicit that content encryption "introduces no new master-key
/// root; it reuses this one, under a distinct HKDF context string." The
/// domain separation is the context and nothing else: same seed, same
/// `derive_symmetric_key`, different `info`. Two roots would mean two
/// things to seal, two things to rotate and two ways to lose the corpus.
///
/// [`crate::federation::at_rest_cascade::CONTENT_MASTER_CONTEXT`] is the
/// wire constant; it lives beside the cascade that consumes it, and
/// `the_content_context_is_domain_separated` pins that the two contexts
/// can never collide.
pub(crate) fn derive_hardware_content_master_key(
    create_seed_if_absent: bool,
) -> Result<(Vec<u8>, String), SecretsError> {
    derive_hardware_master_for_context(
        crate::federation::at_rest_cascade::CONTENT_MASTER_CONTEXT,
        create_seed_if_absent,
    )
}

/// The shared body: seal-if-absent, then HKDF under `context`.
/// `create_seed_if_absent` — v43.0.0 (`BLOB_ENCRYPTION_AT_REST.md` §11.7).
/// The FIRST derivation on a host may seal a fresh seed. A derivation that
/// exists to RE-DERIVE a master already in use must not: if the keyring
/// directory is gone (new container volume, a restore without the data
/// dir, a remounted path) while the TPM is still present, minting a new
/// seed silently yields a DIFFERENT master — every prior blob and every
/// sealed content-KEM private half then fails to unwrap with an opaque AEAD
/// error while new writes succeed under the new root. The first
/// implementation claimed to refuse this and did the opposite.
fn derive_hardware_master_for_context(
    context: &str,
    create_seed_if_absent: bool,
) -> Result<(Vec<u8>, String), SecretsError> {
    let storage_dir = secrets_storage_dir()?;
    let storage = create_platform_storage(SECRETS_STORAGE_ALIAS, storage_dir).map_err(|e| {
        SecretsError::HardwareKeyUnavailable(format!("secure storage init failed: {e}"))
    })?;
    derive_with_storage(storage.as_ref(), context, create_seed_if_absent)
}

/// The derivation proper, over an already-opened storage. Split out so the
/// seed policy (§11.7) is testable against a double — the branch is
/// unreachable on a host with no TPM, which is every CI runner.
fn derive_with_storage(
    storage: &dyn ciris_keyring::SecureBlobStorage,
    context: &str,
    create_seed_if_absent: bool,
) -> Result<(Vec<u8>, String), SecretsError> {
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
        if !create_seed_if_absent {
            return Err(SecretsError::HardwareKeyUnavailable(format!(
                "the hardware-sealed seed {SECRETS_SEED_KEY_ID:?} is ABSENT and this derivation \
                 (context={context}) is a re-derivation of a master already in use. Refusing to \
                 mint a replacement: it would be a different key, and everything sealed under \
                 the old one — including the content-KEM private halves — would become \
                 undecryptable while new writes succeeded. Restore the keyring directory."
            )));
        }
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
    let master = ciris_verify_core::derive_symmetric_key(storage, SECRETS_SEED_KEY_ID, context)
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

    let descriptor = format!("hardware-blob-storage seed={SECRETS_SEED_KEY_ID} context={context}");
    Ok((master, descriptor))
}

#[cfg(test)]
mod context_domain_separation_tests {
    /// v43.0.0 (§10.2 / §4.3) — the secrets master and the content master
    /// derive from the SAME hardware-sealed seed and are separated by the
    /// HKDF context alone. If the two contexts ever collided, the secrets
    /// store and the blob corpus would share one key: a compromise of either
    /// would be a compromise of both, and neither could be rotated
    /// independently.
    ///
    /// Both are documented "stable wire constants" — changing one orphans
    /// everything encrypted under it — so this also pins that a careless
    /// rename cannot silently merge them.
    #[test]
    fn the_content_context_is_domain_separated() {
        let secrets = super::SECRETS_MASTER_CONTEXT;
        let content = crate::federation::at_rest_cascade::CONTENT_MASTER_CONTEXT;
        assert_ne!(
            secrets, content,
            "secrets and content masters derive from ONE seed; the context is the \
             only thing separating them"
        );
        assert!(!secrets.is_empty() && !content.is_empty());
    }
}

#[cfg(test)]
mod seed_policy_tests {
    //! §11.10 I11 — **a hardware root never re-mints.** The branch under test
    //! is unreachable on a host without a TPM (every CI runner), so it is
    //! driven through a storage double that reports hardware-backed.

    use ciris_keyring::SecureBlobStorage as _;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct FakeHardwareStorage {
        blobs: Mutex<HashMap<String, Vec<u8>>>,
    }
    impl FakeHardwareStorage {
        fn empty() -> Self {
            Self {
                blobs: Mutex::new(HashMap::new()),
            }
        }
    }
    impl ciris_keyring::SecureBlobStorage for FakeHardwareStorage {
        fn store(&self, key_id: &str, data: &[u8]) -> Result<(), ciris_keyring::KeyringError> {
            self.blobs
                .lock()
                .unwrap()
                .insert(key_id.to_owned(), data.to_vec());
            Ok(())
        }
        fn load(&self, key_id: &str) -> Result<Vec<u8>, ciris_keyring::KeyringError> {
            self.blobs
                .lock()
                .unwrap()
                .get(key_id)
                .cloned()
                .ok_or(ciris_keyring::KeyringError::NoPlatformSupport)
        }
        fn exists(&self, key_id: &str) -> bool {
            self.blobs.lock().unwrap().contains_key(key_id)
        }
        fn delete(&self, key_id: &str) -> Result<(), ciris_keyring::KeyringError> {
            self.blobs.lock().unwrap().remove(key_id);
            Ok(())
        }
        fn list_keys(&self) -> Result<Vec<String>, ciris_keyring::KeyringError> {
            Ok(self.blobs.lock().unwrap().keys().cloned().collect())
        }
        fn is_hardware_backed(&self) -> bool {
            true
        }
        fn diagnostics(&self) -> String {
            "fake hardware storage (test double)".into()
        }
    }

    /// The falsifier for I11: a re-derivation over an ABSENT seed must
    /// refuse, not mint. The first implementation minted — a lost keyring
    /// directory silently produced a different master, every prior blob
    /// failed to unwrap with an opaque AEAD error, and new writes succeeded.
    #[test]
    fn i11_a_re_derivation_over_an_absent_seed_refuses_rather_than_minting() {
        let storage = FakeHardwareStorage::empty();
        let err = super::derive_with_storage(&storage, "content-at-rest-master-v1", false)
            .expect_err("re-derivation over an absent seed must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("ABSENT") && msg.contains("Refusing to mint"),
            "the refusal must name the cause and the consequence, got: {msg}"
        );
        assert!(
            !storage.exists(super::SECRETS_SEED_KEY_ID),
            "refusing must not have minted a seed as a side effect"
        );
    }

    /// The legitimate first derivation seals a seed, and every later
    /// re-derivation (create=false) reproduces the SAME master — which is
    /// the property that makes the process-global cache correct (§11.8).
    #[test]
    fn a_first_derivation_seals_and_re_derivations_are_stable() {
        let storage = FakeHardwareStorage::empty();
        let (first, _) = super::derive_with_storage(&storage, "content-at-rest-master-v1", true)
            .expect("first derivation may create the seed");
        assert!(storage.exists(super::SECRETS_SEED_KEY_ID));
        let (again, _) = super::derive_with_storage(&storage, "content-at-rest-master-v1", false)
            .expect("re-derivation over a present seed");
        assert_eq!(first, again, "same seed + same context ⇒ same master");
        // Domain separation is the context alone (§10.2).
        let (other, _) = super::derive_with_storage(&storage, "secrets-store-master-v1", false)
            .expect("a different context derives");
        assert_ne!(
            first, other,
            "a different context must derive a different master"
        );
    }
}
