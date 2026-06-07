//! Streaming-chunk content sealing — per-chunk AES-256-GCM with the
//! CEG 0.10 §10.5.2 **STREAM nonce** (CIRISPersist#142 Cut C2).
//!
//! # Why a STREAM nonce (not whole-object GCM)
//!
//! Whole-object AES-GCM must buffer the entire blob to validate the
//! single tag → incompatible with seek (FSD §5). Each chunk is sealed
//! independently with a distinct nonce so random access works and a
//! torn/truncated stream is *detected*, not coerced (MISSION §1.6).
//!
//! # The nonce (CEG §10.5.2 — V2 lock)
//!
//! ```text
//! nonce[12] = prefix[7] ‖ counter_be[4] ‖ last_flag[1]
//! ```
//! - `prefix[7]` = `HKDF-SHA256(epoch_dek; info = "ciris-stream-nonce/v1"
//!   ‖ stream_id ‖ epoch)[0..7]` — derived, never transmitted; per-`
//!   (stream_id, epoch)` unique; recomputable by any holder of the epoch
//!   DEK.
//! - `counter_be[4]` = the 32-bit big-endian chunk index within the
//!   epoch. The Rust type (`u32`) bounds it; the *caller* (Cut C3) MUST
//!   force an epoch roll before the counter would exceed `u32::MAX`
//!   (CEG `MAX_CHUNKS_PER_EPOCH` operational cap) — within one epoch the
//!   counter is strictly monotonic and never wraps.
//! - `last_flag[1]` = `0x01` on the final chunk of an epoch, `0x00`
//!   otherwise → truncation + append resistance (the final chunk gets a
//!   distinct nonce, so an adversary can't drop it or append past it).
//!
//! # Nonce-reuse safety (the catastrophic GCM case)
//!
//! A `(key, nonce)` pair must never repeat. Within an epoch the DEK is
//! fixed and the counter is strictly monotonic (the `u32` type + the
//! caller's roll-before-wrap), so nonces never repeat. Across epochs the
//! DEK changes (Cut C3), so a reset counter lives in a different
//! keyspace — `(dek_e, n)` and `(dek_{e+1}, n)` are distinct pairs;
//! cross-epoch counter reset is free.
//!
//! # ⚠️ CEG §10.5.2 interop gap (FLAGGED for CEG clarification)
//!
//! CEG writes the HKDF info as `… ‖ stream_id ‖ epoch` but does **not**
//! pin the byte-encoding of `epoch` (it pins `counter_be` as big-endian
//! but is silent on the info's `epoch`). Because **consumers recompute
//! this nonce to open chunks** (zero-trust-of-host), persist and every
//! producer/consumer must agree byte-for-byte. This module uses
//! `epoch.to_be_bytes()` (consistent with `counter_be`) via the single
//! [`encode_nonce_info`] constant. If CEG later pins a different
//! encoding, change that one function — the round-trip tests pin the
//! current behavior. **This must be ratified in CEG before cross-impl
//! streaming interop is relied on.**
//!
//! # Crypto routing (MISSION §1.4)
//!
//! AES-256-GCM and HKDF route through the `secrets::crypto` facade — the
//! sole symmetric-crypto site. This module imports NO `ciris_crypto::*`
//! directly; it never rolls its own crypto.

use crate::secrets::crypto;
use crate::secrets::SecretsError;

/// Length of the derived nonce prefix, in bytes (CEG §10.5.2).
pub const PREFIX_LEN: usize = 7;
/// Length of the big-endian chunk counter, in bytes.
pub const COUNTER_LEN: usize = 4;
/// Length of the last-chunk flag, in bytes.
pub const FLAG_LEN: usize = 1;
/// AES-GCM nonce length (12 bytes = `PREFIX_LEN + COUNTER_LEN + FLAG_LEN`).
pub const NONCE_LEN: usize = PREFIX_LEN + COUNTER_LEN + FLAG_LEN;
/// Epoch-DEK length (AES-256 key).
pub const DEK_LEN: usize = 32;

/// Domain-separation tag for the nonce-prefix HKDF (CEG §10.5.2).
const STREAM_NONCE_INFO_TAG: &[u8] = b"ciris-stream-nonce/v1";
/// Final-chunk-of-epoch flag byte.
const LAST_FLAG: u8 = 0x01;
/// Non-final-chunk flag byte.
const NOT_LAST_FLAG: u8 = 0x00;

/// Sealing/opening failure.
#[derive(Debug, thiserror::Error)]
pub enum StreamSealError {
    /// Nonce derivation (HKDF) or the AEAD seal/open failed.
    #[error("stream seal crypto: {0}")]
    Crypto(#[from] SecretsError),
    /// The epoch DEK was not exactly [`DEK_LEN`] bytes.
    #[error("epoch DEK must be {DEK_LEN} bytes (got {0})")]
    BadDekLength(usize),
}

/// Build the HKDF `info` for the nonce prefix: `tag ‖ stream_id ‖
/// epoch_be8`. **The sole place the CEG §10.5.2 info encoding lives** —
/// see the module-level interop-gap note. The variable-length
/// `stream_id` sits between the fixed tag and the fixed 8-byte epoch
/// suffix; distinct `(stream_id, epoch)` pairs yield distinct `info`
/// (a longer stream_id changes the total length, an equal-length one
/// changes the bytes), so distinct prefixes.
fn encode_nonce_info(stream_id: &str, epoch: u64) -> Vec<u8> {
    let sid = stream_id.as_bytes();
    let mut info = Vec::with_capacity(STREAM_NONCE_INFO_TAG.len() + sid.len() + 8);
    info.extend_from_slice(STREAM_NONCE_INFO_TAG);
    info.extend_from_slice(sid);
    info.extend_from_slice(&epoch.to_be_bytes());
    info
}

/// Derive the 12-byte STREAM nonce for a chunk (CEG §10.5.2).
///
/// `prefix = HKDF-SHA256(epoch_dek; info)[0..7]`; nonce = `prefix ‖
/// counter.to_be_bytes() ‖ last_flag`.
pub fn stream_nonce(
    epoch_dek: &[u8; DEK_LEN],
    stream_id: &str,
    epoch: u64,
    counter: u32,
    last: bool,
) -> Result<[u8; NONCE_LEN], StreamSealError> {
    let info = encode_nonce_info(stream_id, epoch);
    // Empty salt → RFC 5869 default; the DEK is the IKM, the domain tag
    // + stream + epoch are the info.
    let prefix = crypto::hkdf_sha256(epoch_dek, &[], &info, PREFIX_LEN)?;

    let mut nonce = [0u8; NONCE_LEN];
    nonce[..PREFIX_LEN].copy_from_slice(&prefix);
    nonce[PREFIX_LEN..PREFIX_LEN + COUNTER_LEN].copy_from_slice(&counter.to_be_bytes());
    nonce[NONCE_LEN - FLAG_LEN] = if last { LAST_FLAG } else { NOT_LAST_FLAG };
    Ok(nonce)
}

/// Seal one chunk: AES-256-GCM encrypt `plaintext` under `epoch_dek`
/// with the STREAM nonce for `(stream_id, epoch, counter, last)`. The
/// returned ciphertext carries the 16-byte GCM tag (the facade packs it
/// on). The nonce is NOT stored — it is recomputed on open.
pub fn seal_chunk(
    epoch_dek: &[u8; DEK_LEN],
    stream_id: &str,
    epoch: u64,
    counter: u32,
    last: bool,
    plaintext: &[u8],
) -> Result<Vec<u8>, StreamSealError> {
    let nonce = stream_nonce(epoch_dek, stream_id, epoch, counter, last)?;
    Ok(crypto::encrypt(epoch_dek, &nonce, plaintext)?)
}

/// Open one chunk: reverse [`seal_chunk`]. The nonce is recomputed from
/// `(stream_id, epoch, counter, last)`; a wrong DEK / stream / epoch /
/// counter / flag, or any ciphertext tamper, fails the GCM auth tag and
/// returns [`StreamSealError::Crypto`] (fail-honest — never a coerced
/// plaintext).
pub fn open_chunk(
    epoch_dek: &[u8; DEK_LEN],
    stream_id: &str,
    epoch: u64,
    counter: u32,
    last: bool,
    ciphertext: &[u8],
) -> Result<Vec<u8>, StreamSealError> {
    let nonce = stream_nonce(epoch_dek, stream_id, epoch, counter, last)?;
    Ok(crypto::decrypt(epoch_dek, &nonce, ciphertext)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEK_A: [u8; 32] = [0x11; 32];
    const DEK_B: [u8; 32] = [0x22; 32];

    #[test]
    fn round_trips() {
        let pt = b"the quick brown fox jumps over the lazy dog";
        let ct = seal_chunk(&DEK_A, "stream-1", 0, 0, false, pt).unwrap();
        assert_ne!(&ct[..pt.len().min(ct.len())], &pt[..pt.len().min(ct.len())]);
        let back = open_chunk(&DEK_A, "stream-1", 0, 0, false, &ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn nonce_is_deterministic() {
        let a = stream_nonce(&DEK_A, "s", 3, 7, true).unwrap();
        let b = stream_nonce(&DEK_A, "s", 3, 7, true).unwrap();
        assert_eq!(a, b);
        // layout: counter_be in bytes 7..11, flag in byte 11.
        assert_eq!(
            &a[PREFIX_LEN..PREFIX_LEN + COUNTER_LEN],
            &7u32.to_be_bytes()
        );
        assert_eq!(a[NONCE_LEN - 1], LAST_FLAG);
    }

    #[test]
    fn nonces_differ_across_counters() {
        let n0 = stream_nonce(&DEK_A, "s", 0, 0, false).unwrap();
        let n1 = stream_nonce(&DEK_A, "s", 0, 1, false).unwrap();
        assert_ne!(n0, n1, "monotone counter must change the nonce");
    }

    #[test]
    fn last_flag_changes_the_nonce() {
        let not_last = stream_nonce(&DEK_A, "s", 0, 5, false).unwrap();
        let last = stream_nonce(&DEK_A, "s", 0, 5, true).unwrap();
        assert_ne!(not_last, last, "truncation/append resistance");
        // only the final byte differs.
        assert_eq!(not_last[..NONCE_LEN - 1], last[..NONCE_LEN - 1]);
    }

    #[test]
    fn cross_epoch_counter_reset_is_nonce_safe() {
        // Same counter, different epoch → different prefix → different
        // nonce, so a reset counter at the next epoch never reuses a
        // (key, nonce) pair even though the DEK also changes.
        let e0 = stream_nonce(&DEK_A, "s", 0, 0, false).unwrap();
        let e1 = stream_nonce(&DEK_A, "s", 1, 0, false).unwrap();
        assert_ne!(e0, e1, "epoch must change the derived prefix");
    }

    #[test]
    fn different_stream_id_changes_the_prefix() {
        let a = stream_nonce(&DEK_A, "stream-a", 0, 0, false).unwrap();
        let b = stream_nonce(&DEK_A, "stream-b", 0, 0, false).unwrap();
        assert_ne!(a[..PREFIX_LEN], b[..PREFIX_LEN]);
    }

    #[test]
    fn tamper_is_rejected() {
        let mut ct = seal_chunk(&DEK_A, "s", 0, 0, false, b"secret payload").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01; // flip a tag bit
        assert!(open_chunk(&DEK_A, "s", 0, 0, false, &ct).is_err());
    }

    #[test]
    fn wrong_context_fails_to_open() {
        let ct = seal_chunk(&DEK_A, "s", 0, 5, false, b"payload").unwrap();
        // wrong DEK
        assert!(open_chunk(&DEK_B, "s", 0, 5, false, &ct).is_err());
        // wrong stream
        assert!(open_chunk(&DEK_A, "other", 0, 5, false, &ct).is_err());
        // wrong epoch
        assert!(open_chunk(&DEK_A, "s", 1, 5, false, &ct).is_err());
        // wrong counter
        assert!(open_chunk(&DEK_A, "s", 0, 6, false, &ct).is_err());
        // wrong last-flag
        assert!(open_chunk(&DEK_A, "s", 0, 5, true, &ct).is_err());
        // right context still opens
        assert_eq!(
            open_chunk(&DEK_A, "s", 0, 5, false, &ct).unwrap(),
            b"payload"
        );
    }

    #[test]
    fn empty_plaintext_seals_to_a_tag_only() {
        let ct = seal_chunk(&DEK_A, "s", 0, 0, true, b"").unwrap();
        assert_eq!(ct.len(), 16, "GCM tag only");
        assert_eq!(open_chunk(&DEK_A, "s", 0, 0, true, &ct).unwrap(), b"");
    }
}
