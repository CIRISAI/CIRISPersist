//! v62.0.0 (F0-cp8) — **test audit entries sealed the one way an entry is
//! signed**: ONE composite over the entry's preimage
//! ([`super::verify::entry_signing_preimage`]) under a fixture key's
//! identity-ref, its `key:record` put on the directory the audit backend
//! reads ([`put_actor`]).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use super::types::AuditEntry;
use super::verify::{compute_entry_hash, entry_signing_preimage, truncate_to_micros};
use crate::federation::edition2::fixture_switch as e2;
use crate::federation::FederationDirectory;

/// Put `seed`'s `key:record` (a `user` key: no window, so every instant is
/// covered) on `dir`; returns its identity-ref, the `actor_id` [`seal`]
/// writes.
pub(crate) async fn put_actor<D: FederationDirectory + ?Sized>(dir: &D, seed: &str) -> String {
    e2::put_key(dir, seed, &["user"]).await
}

/// `seed`'s identity-ref, whether or not its record is put.
pub(crate) fn actor(seed: &str) -> String {
    e2::kid(seed)
}

/// Seal `entry` as `seed`: `actor_id` its identity-ref, `recorded_at` at µs,
/// `entry_hash` computed, `signature` the base64 composite over the preimage.
///
/// # Panics
/// A malformed `prev_hash`.
pub(crate) fn seal(seed: &str, mut entry: AuditEntry) -> AuditEntry {
    entry.actor_id = e2::kid(seed);
    entry.recorded_at = truncate_to_micros(entry.recorded_at);
    entry.signature = String::new();
    entry.entry_hash = compute_entry_hash(&entry).expect("entry hash").to_vec();
    let preimage = entry_signing_preimage(&entry).expect("entry preimage");
    let sig = e2::signing_key(seed)
        .sign(&preimage)
        .expect("composite sign");
    entry.signature = B64.encode(sig);
    entry
}
