//! Process-global software master-key cache (v0.9.3 refactor;
//! extracted from `secrets::postgres` so the SQLite backend can
//! share the same in-memory key store).
//!
//! v0.6.1 software-mode master keys live here for the lifetime of
//! the process; rotation inserts the new key alongside the old.
//! When the `secrets-hw` track lands (per FSD §7.5b), TPM/Keystore-
//! backed lookups replace this cache for production deployments —
//! the cache stays as the fallback for software-mode sovereign
//! deployments.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use super::SecretsError;

fn cache() -> &'static Mutex<HashMap<String, Vec<u8>>> {
    static CELL: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Look up the raw master-key bytes for `key_ref`. Returns `None` if
/// the key isn't cached (caller falls back to the persisted row's
/// descriptor or rejects with `SecretsError::Crypto` per active path).
pub(crate) fn software_keys_get(key_ref: &str) -> Option<Vec<u8>> {
    cache().lock().ok()?.get(key_ref).cloned()
}

/// Insert raw master-key bytes for `key_ref`. Used by
/// `rotate_master_key` after generating new bytes; also by tests +
/// the bootstrap path that materializes an in-memory software key
/// when no persisted master exists.
pub(crate) fn software_keys_put(key_ref: String, bytes: Vec<u8>) -> Result<(), SecretsError> {
    let mut g = cache()
        .lock()
        .map_err(|_| SecretsError::Internal("software_keys mutex poisoned".into()))?;
    g.insert(key_ref, bytes);
    Ok(())
}
