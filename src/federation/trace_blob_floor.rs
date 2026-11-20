//! v62.0.0 (wave P7; I14) — **the trace blob's floor**: the one production
//! caller of the storage floor (`BlobStorage::store_blob_local`) outside the
//! sealing cascades, for a `trace:complete:v1` row's blob.
//!
//! I14 forbids a door that can place bytes under a cohort without sealing
//! them: the first scoped write door called the floor directly for
//! `self` / `family` and stored plaintext under a private cohort. A trace
//! blob cannot do that here, by construction:
//!
//! - the bytes are stored EXACTLY as the row names them (the row's
//!   `manifest.content_hash` / `evidence_refs` bind them; persist never
//!   re-encodes a trace blob, the CC "manifest form only" ruling);
//! - a sealed at-rest envelope (option A: the PRODUCER sealed it through the
//!   self/family cascade, `Engine::seal_trace` → `put_blob_scoped`) is
//!   recorded at the `InvisibleEncrypted` floor, and anything else at the
//!   `Plaintext` floor;
//! - [`StorageFloor::check_scope`] runs before the write and refuses the
//!   contradiction: a plaintext `self` / `family` blob, or a sealed commons
//!   one, is refused, never stored.
//!
//! It is listed beside the cascades in I14's Rust gate
//! (`blob_surface_gates::i14_the_storage_floor_has_no_door`) and in
//! `rules/i14-storage-floor.yml`'s `ignores`. Nothing else in this file may
//! call the floor.

use crate::federation::types::cohort_scope::CryptoTier;
use crate::federation::{BlobBody, BlobStorage, FederationDirectory, StorageFloor};
use crate::store::Error as StoreError;

/// **Store a trace blob** on the blob plane, shared by the sqlite and
/// postgres `Backend::store_trace_blob` overrides: the bytes as received,
/// `Inline`, under their SHA-256 (hash-on-write; the holding claim is the
/// claim emitter's, not this door's). The floor is chosen from the bytes (a
/// sealed envelope or not) and checked against `cohort_scope` before the
/// write. Then every trace row held on this blob re-folds
/// ([`crate::ingest::refold_trace_blob`]).
///
/// # Errors
/// The floor's refusal or the blob plane's error, as [`StoreError::Backend`].
pub(crate) async fn store_trace_blob_on<T>(
    store: &T,
    sha256: &[u8; 32],
    blob: Vec<u8>,
    cohort_scope: &str,
    group_key_id: Option<&str>,
    author_key_id: &str,
) -> Result<(), StoreError>
where
    T: BlobStorage + FederationDirectory + Sync,
{
    let tier = if crate::ingest::is_sealed_trace_blob(&blob) {
        CryptoTier::InvisibleEncrypted
    } else {
        CryptoTier::Plaintext
    };
    let floor = StorageFloor::resolved(tier);
    floor
        .check_scope(cohort_scope)
        .map_err(|e| StoreError::Backend(format!("trace blob floor: {e}")))?;
    store
        .store_blob_local(
            sha256,
            BlobBody::Inline(blob),
            Some(crate::ingest::TRACE_BLOB_MEDIA_TYPE),
            cohort_scope,
            floor,
            Some(author_key_id),
            group_key_id,
        )
        .await
        .map_err(|e| StoreError::Backend(format!("trace blob store: {e}")))?;
    crate::ingest::refold_trace_blob(store, sha256).await;
    Ok(())
}
