//! Streaming-chunk content sealing — per-chunk AES-256-GCM with the
//! CC 5.3.3.1 **STREAM nonce** (CIRISPersist#142 Cut C2, #969, #992).
//!
//! # Why a STREAM nonce (not whole-object GCM)
//!
//! Whole-object AES-GCM must buffer the entire blob to validate the
//! single tag → incompatible with seek (FSD §5). Each chunk is sealed
//! independently with a distinct nonce so random access works and a
//! torn/truncated stream is *detected*, not coerced (MISSION §1.6).
//!
//! # The nonce (CC 5.3.3.1)
//!
//! ```text
//! nonce[12] = prefix[7] ‖ counter_be[4] ‖ last_flag[1]
//! prefix    = HKDF-SHA256(ikm = epoch_dek, salt = ∅,
//!                         info = "ciris-stream-nonce/v1" ‖ utf8(stream_id) ‖ u64_be(epoch))[0..7]
//! ```
//!
//! Derived, never transmitted: every holder of the epoch DEK recomputes it
//! to open a chunk. `counter` is the chunk's index within the epoch (a
//! `u32`; the chunk cascade rolls the epoch before it would wrap, and
//! reserves the epoch's last slot for its terminator); `last_flag` is
//! `0x01` on the epoch's terminator, giving truncation and append
//! resistance.
//!
//! **v54.0.0 (CIRISPersist#992): the derivation is verify's.**
//! [`stream_nonce`] and [`parse_nonce`] are `ciris_crypto::stream_seal`
//! (CIRISVerify v20, #303/#304), the ONE implementation persist, edge and
//! verify call — it is also the A/V inner seal (CIRISConstitution#140), so
//! live and stored chunks share one nonce. Verify's derivation is
//! infallible, so the `StreamSealError::Kdf` arm is gone. The I311
//! witness below (an independent HKDF over the info encoding) and verify's
//! own golden vectors (pinned here as I560) hold the two crates together.
//!
//! # Nonce-reuse safety (the catastrophic GCM case)
//!
//! A `(key, nonce)` pair must never repeat. Within an epoch the DEK is
//! fixed and the counter is strictly monotonic (single sender, the floor's
//! counter check), so nonces never repeat. Across epochs the DEK changes,
//! so a reset counter lives in a different keyspace.
//!
//! # The stored-chunk construction (v54.0.0, #992)
//!
//! A STORED stream chunk is `AES-256-GCM(epoch_dek, stream_nonce(…),
//! aad = chunk_aad(caller_aad, stream_id, storage_seq))` in the at-rest
//! envelope layout. [`seal_stream_chunk`] / [`open_stream_chunk`] are that
//! construction, public, and the store's own append and read doors call
//! these same two functions — so the AAD has ONE construction and a chunk a
//! producer seals here opens through the store, and vice versa. The pre-v54
//! public `seal_chunk` / `open_chunk` sealed with NO associated data, a
//! different construction no stored chunk used; they are removed (clean
//! break): nothing should seal a stream chunk without its position.

use crate::federation::at_rest_cascade::{AtRestEnvelope, AtRestError};
use crate::federation::StreamKeySlot;

/// Length of the derived nonce prefix, in bytes (CC 5.3.3.1).
pub const PREFIX_LEN: usize = ciris_crypto::stream_seal::STREAM_NONCE_PREFIX_LEN;
/// Length of the big-endian chunk counter, in bytes.
pub const COUNTER_LEN: usize = 4;
/// Length of the last-chunk flag, in bytes.
pub const FLAG_LEN: usize = 1;
/// AES-GCM nonce length (12 bytes = `PREFIX_LEN + COUNTER_LEN + FLAG_LEN`).
pub const NONCE_LEN: usize = ciris_crypto::stream_seal::STREAM_NONCE_LEN;
/// Epoch-DEK length (AES-256 key).
pub const DEK_LEN: usize = ciris_crypto::stream_seal::EPOCH_DEK_LEN;

/// Derive the 12-byte STREAM nonce for a chunk (CC 5.3.3.1) —
/// `ciris_crypto::stream_seal::stream_nonce`, delegated (#992). Infallible.
pub use ciris_crypto::stream_seal::stream_nonce;

/// v53.0.0 (CIRISPersist#969) — read `(counter, last)` back out of a stored
/// STREAM nonce; `ciris_crypto::stream_seal::parse_stream_nonce` (#992).
/// `None` when the flag byte is neither `0x00` nor `0x01` (no STREAM nonce
/// has it). The prefix is NOT checked here: the caller recomputes the whole
/// nonce with [`stream_nonce`] and compares, which is what binds the prefix
/// to the epoch DEK, the stream and the epoch.
#[must_use]
pub fn parse_nonce(nonce: &[u8; NONCE_LEN]) -> Option<(u32, bool)> {
    ciris_crypto::stream_seal::parse_stream_nonce(nonce)
}

/// Why a stream chunk did not seal or open.
#[derive(Debug, thiserror::Error)]
pub enum StreamSealError {
    /// The stored nonce's flag byte is neither STREAM flag: no STREAM
    /// nonce has it.
    #[error("the envelope's nonce flag byte is not a STREAM flag (CC 5.3.3.1)")]
    NotAStreamNonce,
    /// The stored nonce is well-formed but is not
    /// `stream_nonce(dek, stream_id, epoch, counter, last)`: its prefix does
    /// not belong to this DEK, stream and epoch. Refused before the open.
    #[error("the envelope's nonce is not the STREAM nonce of its stream, epoch and DEK")]
    NotThisStreamsNonce,
    /// The AEAD seal failed.
    #[error("stream chunk seal: {0}")]
    Seal(AtRestError),
    /// The AEAD open failed under the position-bound AAD — a wrong DEK,
    /// `caller_aad` or `storage_seq`, or tampered bytes. Carries the
    /// at-rest error so a door can keep its typed crypto-class refusal.
    #[error("stream chunk did not open: {0}")]
    DidNotOpen(AtRestError),
}

/// v54.0.0 (CIRISPersist#992) — seal one STORED stream chunk: AES-256-GCM
/// under `epoch_dek` with the STREAM nonce `(stream_id, epoch, counter,
/// last)` and the position-bound AAD
/// [`chunk_aad`](crate::federation::chunk_dag_cascade::chunk_aad)`(caller_aad,
/// stream_id, storage_seq)`. The store's append door calls this function;
/// an envelope sealed here is byte-for-byte the store's construction.
///
/// `counter` is the STREAM counter (the chunk's index within its epoch);
/// `storage_seq` is the chunk's position in the stream (a terminator's is
/// `terminator_seq(epoch)`). The two are different numbers.
///
/// # Errors
/// [`StreamSealError::Seal`] if the AEAD refuses.
#[allow(clippy::too_many_arguments)]
pub fn seal_stream_chunk(
    epoch_dek: &[u8; DEK_LEN],
    stream_id: &str,
    epoch: u64,
    counter: u32,
    last: bool,
    caller_aad: Option<&[u8]>,
    storage_seq: u64,
    plaintext: &[u8],
) -> Result<AtRestEnvelope, StreamSealError> {
    let nonce = stream_nonce(epoch_dek, stream_id, epoch, counter, last);
    let aad = crate::federation::chunk_dag_cascade::chunk_aad(caller_aad, stream_id, storage_seq);
    crate::federation::at_rest_cascade::seal_aad_at_nonce(epoch_dek, nonce, &aad, plaintext)
        .map_err(StreamSealError::Seal)
}

/// v54.0.0 (CIRISPersist#992) — open one STORED stream chunk, the reverse
/// of [`seal_stream_chunk`]: read `(counter, last)` from the envelope's
/// nonce, require the nonce to BE `stream_nonce(epoch_dek, stream_id,
/// epoch, counter, last)` (fail closed before the open), then open under
/// `chunk_aad(caller_aad, stream_id, storage_seq)`. Returns the plaintext
/// and the chunk's slot. The store's read door calls this function.
///
/// # Errors
/// [`StreamSealError::NotAStreamNonce`] / [`StreamSealError::NotThisStreamsNonce`]
/// for a nonce that is not this stream epoch's; [`StreamSealError::DidNotOpen`]
/// when the GCM tag fails (wrong DEK, `caller_aad` or `storage_seq`, or
/// tampered bytes) — fail-honest, never a coerced plaintext.
pub fn open_stream_chunk(
    epoch_dek: &[u8; DEK_LEN],
    stream_id: &str,
    epoch: u64,
    caller_aad: Option<&[u8]>,
    storage_seq: u64,
    envelope: &AtRestEnvelope,
) -> Result<(Vec<u8>, StreamKeySlot), StreamSealError> {
    let (counter, last) = parse_nonce(&envelope.nonce).ok_or(StreamSealError::NotAStreamNonce)?;
    if stream_nonce(epoch_dek, stream_id, epoch, counter, last) != envelope.nonce {
        return Err(StreamSealError::NotThisStreamsNonce);
    }
    let aad = crate::federation::chunk_dag_cascade::chunk_aad(caller_aad, stream_id, storage_seq);
    let plain = crate::federation::at_rest_cascade::open_aad(epoch_dek, Some(&aad), envelope)
        .map_err(StreamSealError::DidNotOpen)?;
    Ok((plain, StreamKeySlot { counter, last }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEK_A: [u8; 32] = [0x11; 32];
    const DEK_B: [u8; 32] = [0x22; 32];

    fn slot(counter: u32, last: bool) -> StreamKeySlot {
        StreamKeySlot { counter, last }
    }

    #[test]
    fn round_trips() {
        let pt = b"the quick brown fox jumps over the lazy dog";
        let env = seal_stream_chunk(&DEK_A, "stream-1", 0, 0, false, Some(b"row"), 0, pt).unwrap();
        assert_ne!(&env.ciphertext[..pt.len()], &pt[..]);
        let (back, s) = open_stream_chunk(&DEK_A, "stream-1", 0, Some(b"row"), 0, &env).unwrap();
        assert_eq!(back, pt);
        assert_eq!(s, slot(0, false));
    }

    #[test]
    fn nonce_is_deterministic() {
        let a = stream_nonce(&DEK_A, "s", 3, 7, true);
        let b = stream_nonce(&DEK_A, "s", 3, 7, true);
        assert_eq!(a, b);
        // layout: counter_be in bytes 7..11, flag in byte 11.
        assert_eq!(
            &a[PREFIX_LEN..PREFIX_LEN + COUNTER_LEN],
            &7u32.to_be_bytes()
        );
        assert_eq!(a[NONCE_LEN - 1], 0x01);
    }

    #[test]
    fn nonces_differ_across_counters() {
        let n0 = stream_nonce(&DEK_A, "s", 0, 0, false);
        let n1 = stream_nonce(&DEK_A, "s", 0, 1, false);
        assert_ne!(n0, n1, "monotone counter must change the nonce");
    }

    #[test]
    fn last_flag_changes_the_nonce() {
        let not_last = stream_nonce(&DEK_A, "s", 0, 5, false);
        let last = stream_nonce(&DEK_A, "s", 0, 5, true);
        assert_ne!(not_last, last, "truncation/append resistance");
        // only the final byte differs.
        assert_eq!(not_last[..NONCE_LEN - 1], last[..NONCE_LEN - 1]);
    }

    #[test]
    fn cross_epoch_counter_reset_is_nonce_safe() {
        let e0 = stream_nonce(&DEK_A, "s", 0, 0, false);
        let e1 = stream_nonce(&DEK_A, "s", 1, 0, false);
        assert_ne!(e0, e1, "epoch must change the derived prefix");
    }

    #[test]
    fn different_stream_id_changes_the_prefix() {
        let a = stream_nonce(&DEK_A, "stream-a", 0, 0, false);
        let b = stream_nonce(&DEK_A, "stream-b", 0, 0, false);
        assert_ne!(a[..PREFIX_LEN], b[..PREFIX_LEN]);
    }

    #[test]
    fn tamper_is_rejected() {
        let mut env =
            seal_stream_chunk(&DEK_A, "s", 0, 0, false, None, 0, b"secret payload").unwrap();
        let last = env.ciphertext.len() - 1;
        env.ciphertext[last] ^= 0x01; // flip a tag bit
        assert!(matches!(
            open_stream_chunk(&DEK_A, "s", 0, None, 0, &env),
            Err(StreamSealError::DidNotOpen(_))
        ));
    }

    /// I561 (#992) — every input of the stored construction is bound: the
    /// DEK, stream and epoch through the nonce recompute (refused BEFORE the
    /// open), the caller's AAD and the storage position through the GCM tag.
    #[test]
    fn i561_wrong_context_fails_to_open() {
        let env = seal_stream_chunk(&DEK_A, "s", 0, 5, false, Some(b"row"), 9, b"payload").unwrap();
        // wrong DEK / stream / epoch: the nonce is not this stream epoch's.
        for (dek, sid, epoch) in [(&DEK_B, "s", 0), (&DEK_A, "other", 0), (&DEK_A, "s", 1)] {
            assert!(
                matches!(
                    open_stream_chunk(dek, sid, epoch, Some(b"row"), 9, &env),
                    Err(StreamSealError::NotThisStreamsNonce)
                ),
                "{sid} epoch {epoch}"
            );
        }
        // wrong storage_seq / caller_aad (and a missing one): the tag fails.
        for (aad, seq) in [(Some(&b"row"[..]), 10), (Some(&b"other"[..]), 9), (None, 9)] {
            assert!(
                matches!(
                    open_stream_chunk(&DEK_A, "s", 0, aad, seq, &env),
                    Err(StreamSealError::DidNotOpen(_))
                ),
                "aad {aad:?} seq {seq}"
            );
        }
        // a nonce flag byte no STREAM nonce carries.
        let mut bad = env.clone();
        bad.nonce[NONCE_LEN - 1] = 0x02;
        assert!(matches!(
            open_stream_chunk(&DEK_A, "s", 0, Some(b"row"), 9, &bad),
            Err(StreamSealError::NotAStreamNonce)
        ));
        // right context still opens, and reports the slot it was sealed at.
        assert_eq!(
            open_stream_chunk(&DEK_A, "s", 0, Some(b"row"), 9, &env).unwrap(),
            (b"payload".to_vec(), slot(5, false))
        );
    }

    #[test]
    fn empty_plaintext_seals_to_a_tag_only() {
        let env = seal_stream_chunk(&DEK_A, "s", 0, 0, true, None, 0, b"").unwrap();
        assert_eq!(env.ciphertext.len(), 16, "GCM tag only");
        let (plain, s) = open_stream_chunk(&DEK_A, "s", 0, None, 0, &env).unwrap();
        assert_eq!(plain, b"");
        assert_eq!(s, slot(0, true));
    }

    /// #969 — the parse is the inverse of the layout, and a flag byte no
    /// STREAM nonce carries is refused.
    #[test]
    fn parse_nonce_reads_counter_and_flag() {
        let n = stream_nonce(&DEK_A, "s", 3, 0x0102_0304, true);
        assert_eq!(parse_nonce(&n), Some((0x0102_0304, true)));
        let n = stream_nonce(&DEK_A, "s", 3, 9, false);
        assert_eq!(parse_nonce(&n), Some((9, false)));
        let mut bad = n;
        bad[NONCE_LEN - 1] = 0x02;
        assert_eq!(parse_nonce(&bad), None);
    }

    /// I311 (#969) — the CC 5.3.3.1 vector: `info = "ciris-stream-nonce/v1"
    /// ‖ stream_id_utf8 ‖ epoch_be8`, prefix = HKDF-SHA256(dek; info)[0..7].
    /// Computed here from the definition with an independent HKDF call, so a
    /// change to the info encoding (epoch little-endian, a separator, a
    /// different tag) is a red. Unchanged by #992: it is now the witness
    /// that verify's derivation is the one persist v53 stored under.
    #[test]
    fn i311_the_prefix_is_the_cc_5_3_3_1_derivation() {
        let mut info = b"ciris-stream-nonce/v1".to_vec();
        info.extend_from_slice("cam-1".as_bytes());
        info.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 7]);
        let prefix = ciris_crypto::kdf::hkdf_sha256(&DEK_A, &[], &info, 7).unwrap();
        let n = stream_nonce(&DEK_A, "cam-1", 7, 0x0000_0102, false);
        assert_eq!(&n[..7], prefix.as_slice());
        assert_eq!(&n[7..11], &[0, 0, 1, 2]);
        assert_eq!(n[11], 0x00);
    }

    /// I560 (#992) — verify's published CC 5.3.3.1 golden vectors
    /// (CIRISVerify v20 `ciris_crypto::stream_seal`, derived there with a
    /// from-scratch Python RFC 5869 HKDF), pinned here as bytes. With I311
    /// they hold persist's stored nonces and verify's derivation together:
    /// a later verify that changed the derivation would fail here at the
    /// re-pin, before any stored chunk stopped opening.
    #[test]
    fn i560_verify_golden_vectors() {
        const DEK: [u8; 32] = [0x42; 32];
        let cases: [(&str, u64, u32, bool, &str); 5] = [
            ("cam-1", 7, 0x102, false, "334c5b834c1ddd0000010200"),
            ("cam-1", 7, 0x102, true, "334c5b834c1ddd0000010201"),
            ("cam-1", 8, 0x102, false, "58b01d9376176b0000010200"),
            ("", 0, 0, false, "4dee044e7c7b010000000000"),
            (
                "stream-\u{e9}",
                u64::MAX,
                u32::MAX,
                true,
                "1b86de86e1bfc4ffffffff01",
            ),
        ];
        for (sid, epoch, ctr, last, want) in cases {
            let n = stream_nonce(&DEK, sid, epoch, ctr, last);
            assert_eq!(
                hex::encode(n),
                want,
                "{sid:?} epoch={epoch} ctr={ctr} last={last}"
            );
            assert_eq!(parse_nonce(&n), Some((ctr, last)));
        }
        // The same vectors through persist's own HKDF framing (v53's
        // derivation, `kdf::hkdf_sha256(dek, &[], info, 7)`): the prefix of
        // every case.
        for (sid, epoch, _, _, want) in cases {
            let mut info = b"ciris-stream-nonce/v1".to_vec();
            info.extend_from_slice(sid.as_bytes());
            info.extend_from_slice(&epoch.to_be_bytes());
            let p = ciris_crypto::kdf::hkdf_sha256(&DEK, &[], &info, 7).unwrap();
            assert_eq!(hex::encode(&p), want[..14], "{sid:?} epoch={epoch}");
        }
    }
}
