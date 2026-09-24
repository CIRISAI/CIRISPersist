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

## Replicated `EnvelopeKind`s — the sixteenth kind, `KeyGrant` (v44.3.0, #848)

Distinct from the Tier-2 `kind: u32` range above: the **replicated wire
kinds** are the closed `EnvelopeKind` set persist owns as the APPLY authority
(`src/federation/replication_policy.rs`, pinned by `REPLICATION_POLICY_HASH`;
CIRISEdge's `replication::protocol::EnvelopeKind` mirrors the names in order,
CIRISServer pins the hash). Fifteen kinds shipped through v44.2.1; v44.3.0
**appends** the sixteenth — never inserts, the order is hashed:

| # | `EnvelopeKind` | carries | signer | binding | projections |
|---|---|---|---|---|---|
| 16 | `KeyGrant` | one CC 3 `key_grant` **set**: every recipient wrap for one identity | `RegisteredSigner` | `SelfOwn` | `[KeyGrants]` |

- **Wire shape.** A `SignedKeyGrantSet` is an attestation row whose
  `attestation_type` is `key_grant:epoch:v1` (epoch axis: identity
  `(community_key_id, minter_key_id, epoch)`, signed by the MINTER's
  occurrence key) or `key_grant:content:v1` (content axis: identity
  `(at_rest_sha256, cohort_scope, owner_key_id)`, signed by the blob's
  AUTHOR), and whose envelope carries `{"kind":"key_grant", "axis", …identity…,
  "wraps":[{"recipient_occurrence_key_id","wrap_algorithm","wrapped_dek"}]}`
  — CC 3's vocabulary, canonicalised and hybrid-signed like every other
  attestation. It rides the attestation cursor (`list_attestations_since`);
  a receiver routes it by `attestation_type` to `apply_replicated_key_grant`.
- **Admission** (`key_grant::admit_replicated_key_grant`): the signer is
  resolved from the admitting node's own directory; epoch axis — the signer
  is the set's `minter_key_id` AND an active member of the community at
  `asserted_at` per the replicated roster fold; content axis — the signer is
  the blob row's `author_key_id` when the row is present (accepted before the
  row arrives: order independence); every wrap is v2. Anything else is a
  typed `federation_key_grant_refused`.
- **Projection** `KeyGrants`: every wrap, in one transaction, as a UNION
  (`ON CONFLICT DO NOTHING`). Grants are never retracted (CC 3: "cannot
  retroactively un-share"); forward secrecy is by rotation. There is no
  withdraw for this kind.
- **Plane.** `Plane::KeyGrant { axis }` projects `SelfOwn` at self / family
  (the content axis) and `Cohort` everywhere else (the epoch axis); never
  `Global`. Tombstone ceiling: the row max, `Cohort` — unreachable, since the
  kind has no withdraw.
- **Pins moved:** `REPLICATION_POLICY_HASH`
  `3af30bcc…23bbef` → `c1082c12db13b6d0f2240b910da2c0008a85b363df4f9b9b73a013ab28cb389d`;
  `CONSENT_GRAMMAR_HASH` (its `kind_transferability` covers the kind list;
  `KeyGrant` is `StructuralPlane`)
  `b66870da…290d69f` → `79c74e4d4d04aeb624a7139d705d4882c25f32f6654e5bf017e2f5b99eec38ac`.

`FSD/BLOB_REPLICATION.md` Part II (§11–§19) is the design.

## Replicated `EnvelopeKind`s — the seventeenth kind, `CommunityMembershipWidening` (v48.0.0, #860)

Sixteen kinds shipped through v47.4.0; v48.0.0 **appends** the seventeenth
after `KeyGrant` — never inserts, the order is hashed:

| # | `EnvelopeKind` | carries | signer | binding | projections |
|---|---|---|---|---|---|
| 17 | `CommunityMembershipWidening` | one row of `federation_community_membership_widenings`: `(community_key_id, member_key_id, effective_at)` + `joined_at`, `role` — the addition plane, the mirror of `CommunityMembershipRevocation` | `RegisteredSigner` | `OwnerOf` | `[]` (E4: the row IS the projection) |

- **Wire shape.** A `SignedCommunityMembershipWidening` is the widening row
  plus the room authority's hybrid scrub over its canonical (JCS) envelope
  with `persist_row_hash` stripped — the same signing shape as the
  revocation. It rides `list_signed_community_membership_widenings_since`
  (pair cursor; resume id = the three-part compound of the PK).
- **Admission** (`tier_ingest::verify_community_membership_widening_admission`):
  unknown room → `InvalidArgument` first; the signer must be in the room's
  authority set at `effective_at`; future-dated rows are refused
  (`community_dek::reject_future_dated_community_widening`).
- **Fold.** `active_roster_at(record, widenings, revocations, as_of)`: the
  latest event per member wins; a removal wins a tie. Every read-time gate
  goes through `effective_roster` / `is_active_community_member`. The DEK
  epoch does NOT rotate on a widening.
- **Pins moved:** `REPLICATION_POLICY_HASH`
  `c1082c12…389d` → `9d62d3a86f7a0ab955969256a10c8160da73a390953ba3c87167a2da96828a19`;
  `CONSENT_GRAMMAR_HASH` (`CommunityMembershipWidening` is `StructuralPlane`)
  `ed2b0f2c…482` → `07a677bbcdff236e2018f0786e8d9b0d0ef6b5b7cc2b871d41459e26ff8864a9`.

`FSD/ROOM_ROSTER_PLANES.md` is the design.

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
