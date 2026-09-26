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

## Replicated `EnvelopeKind`s — the eighteenth kind, `FamilyMembershipWidening` (v49.0.0, #910)

Seventeen kinds shipped through v48.0.0; v49.0.0 **appends** the eighteenth
after `CommunityMembershipWidening` — never inserts, the order is hashed:

| # | `EnvelopeKind` | carries | signer | binding | projections |
|---|---|---|---|---|---|
| 18 | `FamilyMembershipWidening` | one row of `federation_family_membership_widenings`: `(family_key_id, member_key_id, effective_at)` + `joined_at`, `role`, `cosignatures` — the family addition plane, the twin of `CommunityMembershipWidening` | `RegisteredSigner` | `OwnerOf` | `[]` (E4: the row IS the projection) |

- **Wire shape.** A `SignedFamilyMembershipWidening` is the widening row plus
  the primary signer's hybrid scrub over its canonical (JCS) envelope with
  `persist_row_hash` stripped, and any `cosignatures` over the same envelope
  (omitted when empty). It rides `list_signed_family_membership_widenings_since`
  (pair cursor; resume id = the three-part compound of the PK).
- **Admission** (`tier_ingest::verify_family_membership_widening_admission`,
  then `check_family_roster_authority`): the primary and every co-signature
  verify; a future-dated row is refused
  (`reject_future_dated_family_widening`); the signer set must meet the
  family's own `consensus_protocol` at `effective_at` (the same
  `roster_event_standing` rooms use; a family has no moderation plane); the
  family must exist and the member must be a registered key; idempotent on the
  three-part PK.
- **Fold.** `authorized_family_roster_at`: the record's members, then the
  family widening and revocation planes by `effective_at` (a removal wins a
  tie), applying only events with standing. `active_family_members`,
  `list_families_for_member_active`, the admission readers, the at-rest family
  fan-out and `verify_membership_quorum`'s prior roster all read it.
  `add_family_member` is the local door onto the plane; no door rewrites a
  family record to grow it.
- **The family revocation key** gains `effective_at` (V154): a re-added
  member can be removed again; the since-read's resume id and the wire-index
  record key are the three-part compound.
- **Pins moved:** `REPLICATION_POLICY_HASH`
  `9d62d3a8…8a19` → `7d0e97b45c83b4ef4f0cc49a2c75f2064b2f9bd090ee2b89264ab2c8da084bae`;
  `CONSENT_GRAMMAR_HASH` (`FamilyMembershipWidening` is `StructuralPlane`)
  `07a677bb…64a9` → `62de16961aa7e631d999611b30bdcf9dc42c683e9e69a0c142b710609f9e133c`.

`FSD/ROOM_ROSTER_AUTHORITY.md` §10 is the design.

## Replicated `EnvelopeKind`s — the nineteenth kind, `CommunityMembershipListing` (v49.0.0, #912)

Eighteen kinds through the #910 slice; v49.0.0 **appends** the nineteenth
after `FamilyMembershipWidening` — never inserts, the order is hashed:

| # | `EnvelopeKind` | carries | signer | binding | projections |
|---|---|---|---|---|---|
| 19 | `CommunityMembershipListing` | one row of `federation_community_membership_listings`: `(community_key_id, member_key_id, effective_at)` + `listed` (`"public"` or absent) — one member's CC 2 public-listing choice in one room | `RegisteredSigner` | `SelfOwn` | `[]` (the row IS the projection) |

- **Wire shape.** A `SignedCommunityMembershipListing` is the listing row plus
  the signer's hybrid scrub over its canonical (JCS) envelope with
  `persist_row_hash` stripped. `listed` is omitted when absent (CC 2 spells a
  private roster as the member absent). No co-signatures. It rides
  `list_signed_community_membership_listings_since` (pair cursor; resume id =
  the three-part compound of the PK).
- **Admission** (`listing::check_community_membership_listing`, every
  backend): the signature verifies; the signer IS the member, else
  `Error::MembershipListingRefused` `envelope_listed_not_self_asserted` (the
  clause that makes the field an opt-in and not a power); `listed` is `public`
  or absent, else `envelope_listed_bad_value`; no future-dating; the room exists
  (a family id is `envelope_listed_scope_invalid`, an unknown id the FK's
  `InvalidArgument`); idempotent on the PK. Membership is NOT checked at the
  door — rows arrive out of order.
- **Fold.** `listed_members` / `listing::listed_community_members_at`: the
  room's active members by `authorized_community_roster_at` whose latest
  listing at or before the instant is `public`. Forward-only: clearing is a
  later row with `listed` absent; nothing is rewritten. The only roster view a
  non-member may be served (the host gates the endpoint).
- **Vocabulary.** `listed` joined `universal_paths` (`paths::LISTED`):
  `ENVELOPE_VOCABULARY_SHA256`
  `4d7054a6…589b` → `a6a84cc9d5f4d6bd6295cfc78b42bce35145d2bb9ff14391bfe32ab027116a6a`.
  `history_on_join` is NOT adopted in v49.0.0 (a recorded decision; see the
  re-pin log in `envelope.rs`).
- **Pins moved:** `REPLICATION_POLICY_HASH`
  `7d0e97b4…4bae` → `5501d6b9621e0af400ed89c0c803515b33c084676be5cd5182c3629277d9714a`;
  `CONSENT_GRAMMAR_HASH` (`CommunityMembershipListing` is `StructuralPlane`)
  `62de1696…133c` → `8230589131945c4b4db3c2e7ca2187e6c02543cd8f084b0f8862eb951d2c82ac`;
  both directory-capsule wire digests (one op, one result appended — growth,
  `DIRECTORY_ABI_VERSION` stays 5).

`FSD/ROOM_ROSTER_AUTHORITY.md` §11 is the design.

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
