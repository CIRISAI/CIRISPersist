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

use zeroize::Zeroizing;

use super::SecretsError;

// v1.10.1 (CIRISPersist#87 review H2) — cache values are
// `Zeroizing<Vec<u8>>`: a master key sits here for the whole process
// lifetime, so when a rotation evicts it (or the process maps drop)
// the bytes are scrubbed rather than left in freed heap. The public
// API stays `Vec<u8>` — the transient copy a caller pulls out is
// used for one encrypt/decrypt then dropped.
fn cache() -> &'static Mutex<HashMap<String, Zeroizing<Vec<u8>>>> {
    static CELL: OnceLock<Mutex<HashMap<String, Zeroizing<Vec<u8>>>>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Look up the raw master-key bytes for `key_ref`. Returns `None` if
/// the key isn't cached (caller falls back to the persisted row's
/// descriptor or rejects with `SecretsError::Crypto` per active path).
pub(crate) fn software_keys_get(key_ref: &str) -> Option<Vec<u8>> {
    cache().lock().ok()?.get(key_ref).map(|z| z.to_vec())
}

/// Insert raw master-key bytes for `key_ref`. Used by
/// `rotate_master_key` after generating new bytes; also by tests +
/// the bootstrap path that materializes an in-memory software key
/// when no persisted master exists.
pub(crate) fn software_keys_put(key_ref: String, bytes: Vec<u8>) -> Result<(), SecretsError> {
    let mut g = cache()
        .lock()
        .map_err(|_| SecretsError::Internal("software_keys mutex poisoned".into()))?;
    // The passed-in `bytes` allocation is moved into `Zeroizing`, so
    // the caller's buffer is the one that gets scrubbed on eviction.
    g.insert(key_ref, Zeroizing::new(bytes));
    Ok(())
}

/// Drop the cached bytes for `key_ref` (scrubbing them via
/// `Zeroizing`). v2.0 concurrency hardening: `rotate_master_key`
/// caches the new key bytes *before* committing so the row is never
/// visible without its bytes; if that commit then loses a concurrent
/// first-use bootstrap race the staged row is rolled back, and this
/// evicts the now-orphaned bytes rather than leaking them for the
/// process lifetime. Idempotent — a missing key is a no-op.
pub(crate) fn software_keys_remove(key_ref: &str) {
    if let Ok(mut g) = cache().lock() {
        g.remove(key_ref);
    }
}
