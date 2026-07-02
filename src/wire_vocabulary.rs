//! CC 0.7 wire-vocabulary — CIRISPersist's Tier-2 range-steward surface.
//!
//! The federation wire vocabulary is a hash-pinned constitutional artifact
//! (`CIRISConstitution/manifests/WIRE_VOCABULARY.md` v1.0.1, artifact
//! steward CIRISRegistry). It is **two-tier** (RFC 8126 registration-policy
//! vocabulary):
//!
//! - **Tier 1** — the closed `MessageType` set carrying the ethical
//!   primitives (attestations, votes, key registration, …). Adding one is a
//!   CC §4.5.1 amendment. CIRISEdge owns this; persist does not.
//! - **Tier 2** — three opaque channels (`OpaqueRequest` / `OpaqueResponse`
//!   / `OpaqueEvent`) carrying a `kind: u32` from a per-repo reserved range
//!   (§3.1). Edge treats the payload as opaque bytes; the *range steward*
//!   owns the inner schema, canonicalization, and convenience surface (§3.3)
//!   and documents `kind → semantics` in a `WIRE_VOCABULARY_KINDS.md`.
//!
//! §3.1 assigns CIRISPersist the range [`PERSIST_KIND_RANGE`]
//! (`0x0005_0000..=0x0005_FFFF`, "persist-tier telemetry"). This module is
//! persist's §3.3 range-steward surface: the ratified [`TRACE_BATCH_KIND`],
//! the shared payload canonicalization ([`trace_batch_payload_bytes`] /
//! [`BatchEnvelope::from_json`]), and the pinned [`WIRE_VOCABULARY_HASH`].
//! The human-readable allocation table lives in `WIRE_VOCABULARY_KINDS.md`
//! at the repo root.
//!
//! **Dependency direction (why there is no `send_trace_batch` here).** §3.3's
//! worked example — `CIRISAgent::send_inline_text(text)` as a thin wrapper
//! over `edge.send_opaque_event(kind, app_canonicalize(text))` — works
//! because CIRISAgent sits *above* CIRISEdge. CIRISPersist sits *below* edge
//! (edge links persist, not the reverse), so a `send_trace_batch(edge, …)`
//! wrapper cannot live here without inverting the dependency. Persist instead
//! exports the ratified `kind` + the schema + the canonicalization helper —
//! the single shared definition — and the emitter tier (CIRISAgent#904) and
//! receiver tier (CIRISServer/lens-core) compose it with edge's *generic*
//! `send_opaque_event` / `subscribe_opaque`.

use crate::schema::BatchEnvelope;

/// The CC 0.7 wire-vocabulary hash — SHA-256 of the canonical bytes of
/// `WIRE_VOCABULARY.md` v1.0.1 (§4). Every ratifying repo pins this identical
/// value; a mismatch at cohabitation is a substrate-tier build failure, not a
/// warning. Byte-identical to `CIRISEdge::WIRE_VOCABULARY_HASH` (CIRISEdge#241)
/// and the artifact-steward copy in CIRISRegistry.
///
/// sha256 = c6bd6aa44111b226a6f204801b1afaa7153fb43296652c1f7cbc23228ac9346c
pub const WIRE_VOCABULARY_HASH: [u8; 32] = [
    0xc6, 0xbd, 0x6a, 0xa4, 0x41, 0x11, 0xb2, 0x26, 0xa6, 0xf2, 0x04, 0x80, 0x1b, 0x1a, 0xfa, 0xa7,
    0x15, 0x3f, 0xb4, 0x32, 0x96, 0x65, 0x2c, 0x1f, 0x7c, 0xbc, 0x23, 0x22, 0x8a, 0xc9, 0x34, 0x6c,
];

/// CIRISPersist's reserved Tier-2 `kind` range (§3.1): the 16-bit sub-range
/// `0x0005_0000..=0x0005_FFFF`, "persist-tier telemetry". Every persist-owned
/// `kind` MUST fall inside this range; [`is_persist_kind`] enforces it.
pub const PERSIST_KIND_RANGE: std::ops::RangeInclusive<u32> = 0x0005_0000..=0x0005_FFFF;

/// Ratified `kind` for the **accord trace-events batch** (the §3.3 migrant of
/// the retired `MessageType::AccordEventsBatch`). Carried as an
/// `OpaqueEvent { kind: TRACE_BATCH_KIND, payload }` where `payload` is the
/// canonical JSON bytes of a [`BatchEnvelope`] — exactly the bytes the HTTP
/// ingest path posts and `Engine::receive_and_persist` consumes.
///
/// - Produce the payload with [`trace_batch_payload_bytes`].
/// - Verify-before-persist on receive with [`BatchEnvelope::from_json`]
///   (all schema-version / trace-level / required-field / depth gates fire
///   there; hash-chain verify + scrub + persist run inside lens/persist —
///   edge is agnostic).
///
/// Consumers pin THIS constant rather than a local literal: CIRISServer's
/// lens-core relay repins its provisional `ACCORD_EVENTS_KIND` here, and
/// CIRISAgent#904 (emitter) shares the same definition.
pub const TRACE_BATCH_KIND: u32 = 0x0005_0001;

/// `true` iff `kind` falls in persist's reserved Tier-2 range (§3.1). A peer
/// that receives a persist-range `kind` it does not implement returns
/// `OpaqueResponse { status: 501 }` (never a silent drop) — that dispatch is
/// edge's, but the range membership test is persist's to define.
#[must_use]
pub fn is_persist_kind(kind: u32) -> bool {
    PERSIST_KIND_RANGE.contains(&kind)
}

/// Produce the opaque-event **payload bytes** for a trace-events batch: the
/// canonical JSON serialization of `envelope`. This is the range steward's
/// half of the §3.3 shared definition — the emitter feeds the result to
/// edge's generic `send_opaque_event([`TRACE_BATCH_KIND`], bytes)`, and the
/// receiver round-trips them back through [`BatchEnvelope::from_json`].
///
/// The bytes are `serde_json` of the typed [`BatchEnvelope`] (no
/// `serde_json::Value` anywhere in the type — MISSION.md §3 anti-pattern #1),
/// so they parse losslessly on the receive side. Errors are surfaced rather
/// than panicking so a caller never emits a half-serialized batch.
pub fn trace_batch_payload_bytes(envelope: &BatchEnvelope) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the CC 0.7 wire-vocabulary hash to its hex source of truth
    /// (§4). A drift here is a coordinated wire-break signal, not a bug
    /// fix — and it must stay byte-identical to every other ratifying
    /// repo's pin (CIRISEdge, CIRISRegistry artifact copy).
    #[test]
    fn wire_vocabulary_hash_pinned() {
        const HEX: &str = "c6bd6aa44111b226a6f204801b1afaa7153fb43296652c1f7cbc23228ac9346c";
        let mut expected = [0u8; 32];
        for (i, byte) in expected.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&HEX[i * 2..i * 2 + 2], 16).unwrap();
        }
        assert_eq!(WIRE_VOCABULARY_HASH, expected);
    }

    /// The ratified trace-batch kind sits inside persist's reserved
    /// §3.1 range (and the range endpoints behave).
    #[test]
    fn trace_batch_kind_is_in_persist_range() {
        assert_eq!(TRACE_BATCH_KIND, 0x0005_0001);
        assert!(is_persist_kind(TRACE_BATCH_KIND));
        assert!(is_persist_kind(0x0005_0000));
        assert!(is_persist_kind(0x0005_FFFF));
        assert!(!is_persist_kind(0x0004_FFFF));
        assert!(!is_persist_kind(0x0006_0000));
    }

    /// The §3.3 shared definition round-trips: payload bytes produced by
    /// the steward helper parse back through the verify-on-receive gate
    /// to an equal envelope.
    #[test]
    fn payload_bytes_round_trip_through_from_json() {
        let bytes = serde_json::json!({
            "events": [{
                "event_type": "complete_trace",
                "trace_level": "generic",
                "trace": {
                    "trace_id": "trace-th_std_abc-20260430001553",
                    "thought_id": "th_std_abc",
                    "task_id": "ACCEPT_INCOMPLETENESS_xyz",
                    "agent_id_hash": "deadbeef",
                    "started_at": "2026-04-30T00:15:53.123456+00:00",
                    "completed_at": "2026-04-30T00:16:12.789012+00:00",
                    "trace_level": "generic",
                    "trace_schema_version": "2.7.0",
                    "components": [],
                    "signature": "AAAA",
                    "signature_key_id": "ciris-agent-key:dead"
                }
            }],
            "batch_timestamp": "2026-04-30T00:16:13.000000+00:00",
            "consent_timestamp": "2026-04-30T00:00:00.000000+00:00",
            "trace_level": "generic",
            "trace_schema_version": "2.7.0"
        });
        let envelope =
            BatchEnvelope::from_json(&serde_json::to_vec(&bytes).unwrap()).expect("seed parses");

        let payload = trace_batch_payload_bytes(&envelope).expect("serialize payload");
        let round_tripped = BatchEnvelope::from_json(&payload).expect("payload re-parses");
        assert_eq!(envelope, round_tripped, "steward payload must round-trip");
    }
}
