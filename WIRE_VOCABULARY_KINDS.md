# CIRISPersist Wire Vocabulary — Tier-2 `kind` allocations

**Range steward:** CIRISPersist
**Reserved range (§3.1):** `0x0005_0000..=0x0005_FFFF` — "persist-tier telemetry"
**Wire authority:** `CIRISConstitution/manifests/WIRE_VOCABULARY.md` v1.0.1
(artifact steward CIRISRegistry), CC 0.7.
**Pinned vocabulary hash (§4):** `c6bd6aa44111b226a6f204801b1afaa7153fb43296652c1f7cbc23228ac9346c`
— exported as `ciris_persist::WIRE_VOCABULARY_HASH`, byte-identical to
`CIRISEdge::WIRE_VOCABULARY_HASH` (CIRISEdge#241) and the artifact-steward copy.

---

## What this document is

The CC 0.7 wire vocabulary is **two-tier** (RFC 8126 registration policy).
Tier 1 is the closed `MessageType` set carrying the ethical primitives, owned
by CIRISEdge and amended only through CC §4.5.1. Tier 2 is three opaque
channels — `OpaqueRequest` / `OpaqueResponse` / `OpaqueEvent` — each carrying a
`kind: u32` drawn from a per-repo reserved range. Edge treats the `payload` as
opaque bytes and enforces only the outer envelope signature + the global body
caps; **the range steward owns the inner schema, its canonicalization, and the
convenience surface** (§3.3), documented here.

§3.1 assigns CIRISPersist the range above. This file is the authoritative
`kind → semantics` table for it. Edge does not know or enforce what a persist
`kind` means; a peer that receives a persist-range `kind` it does not implement
returns `OpaqueResponse { status: 501 }` — never a silent drop.

Allocating a new `kind` inside this range is a steward action (RFC 8126 Private
Use): no CC amendment, just an entry below + the matching constant in
`src/wire_vocabulary.rs`.

---

## Allocations

| `kind` | Name | Channel | Payload | Status |
|---|---|---|---|---|
| `0x0005_0001` | accord trace-events batch | `OpaqueEvent` | canonical JSON of `ciris_persist::schema::BatchEnvelope` | **Ratified** (v11.9.0) |
| `0x0005_0002..=0x0005_00FF` | — | — | reserved for future persist telemetry | Unallocated |
| DSAR (`0x0005_0100..=0x0005_01FF`) | data-subject access/erasure | — | — | **Reserved, not allocated** (see below) |
| `0x0005_0200..=0x0005_FFFF` | — | — | unallocated | — |

### `0x0005_0001` — accord trace-events batch

The §3.3 migrant of the retired `MessageType::AccordEventsBatch`.

- **Channel:** `OpaqueEvent { kind: 0x0005_0001, payload }` — Durable,
  fire-and-forget (no ack). Trace/telemetry: hash-chain verify + scrub +
  persist happen inside lens/persist; edge is agnostic.
- **Payload:** the canonical JSON bytes of a `BatchEnvelope` — exactly the
  bytes the HTTP ingest path posts and `Engine::receive_and_persist` consumes.
  No `serde_json::Value` anywhere in the type (MISSION.md §3 anti-pattern #1);
  every field is typed, so the bytes parse losslessly.
- **Schema owner:** `ciris_persist::schema::BatchEnvelope` (this repo,
  `src/schema/envelope.rs`).
- **Canonicalization (produce):** `ciris_persist::trace_batch_payload_bytes(&BatchEnvelope)`.
- **Verify-before-persist (receive):** `BatchEnvelope::from_json(&payload)` —
  all schema-version / trace-level / required-field / `MAX_DATA_DEPTH` gates
  fire there and return typed errors before anything is persisted.
- **Constant:** `ciris_persist::TRACE_BATCH_KIND`.
- **Body cap:** the global `MAX_BODY_BYTES` (8 MiB, §3.2); no smaller per-kind
  sub-cap declared.

**Consumers:**
- *Receiver* — CIRISServer / lens-core relay repins its provisional
  `ACCORD_EVENTS_KIND = 0x0005_0001` onto `ciris_persist::TRACE_BATCH_KIND`.
- *Emitter* — CIRISAgent#904 (pending) produces the payload via
  `trace_batch_payload_bytes` and sends it over edge's generic
  `send_opaque_event(TRACE_BATCH_KIND, bytes)`.

### DSAR — reserved, **not** allocated

The §3.1 range scope names "trace batches, **DSAR**", but §3.3 resolves that
`DSARRequest` / `DSARResponse` **stay Tier-1** and do not migrate:
data-subject access/erasure is rights-bearing (consent-weight, adjacent to
`Withdraws`) **and** rides Durable + requires-ack — the erasure-completion
receipt the three opaque channels cannot express (§3 delivery-expressiveness
limit). No DSAR `kind` is allocated here. The sub-range is held reserved so
that, should a durable ack-bearing opaque channel ever be added and DSAR be
revisited, its allocation lands in a stable place.

---

## Why persist exposes no `send_trace_batch` wrapper

§3.3's worked example — `CIRISAgent::send_inline_text(text)` wrapping
`edge.send_opaque_event(kind, app_canonicalize(text))` — works because
CIRISAgent sits *above* CIRISEdge. **CIRISPersist sits below edge** (edge links
persist; the reverse would be a dependency cycle), so a `send_trace_batch(edge,
…)` wrapper cannot live in this repo. Persist therefore owns and exports the
*shared definition* — the ratified `kind`, the `BatchEnvelope` schema, and the
`trace_batch_payload_bytes` / `from_json` canonicalization pair — and the
emitter/receiver tiers (which depend on both persist and edge) compose it with
edge's generic `send_opaque_event` / `subscribe_opaque`. "App owns meaning" is
honored on the wire and in the stewardship graph; the only thing that never
exists is a transport-tier typed struct for this migrant.
