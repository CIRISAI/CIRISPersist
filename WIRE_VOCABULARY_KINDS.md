# CIRISPersist Wire Vocabulary — `kind` allocations

**Range steward:** CIRISPersist
**Reserved range (§3.1):** `0x0005_0000..=0x0005_FFFF` — "persist-tier telemetry"
**Wire authority:** `CIRISConstitution/manifests/WIRE_VOCABULARY.md` v1.0.1
(artifact steward CIRISRegistry), CC 0.7.
**Pinned vocabulary hash (§4):** `c6bd6aa44111b226a6f204801b1afaa7153fb43296652c1f7cbc23228ac9346c`
— exported as `ciris_persist::WIRE_VOCABULARY_HASH`, byte-identical to
`CIRISEdge::WIRE_VOCABULARY_HASH` (CIRISEdge#241) and the artifact-steward copy.

This file covers two separate vocabularies persist owns:

1. the **Tier-2 `kind: u32` allocations** in persist's reserved range (the
   human-readable table behind `src/wire_vocabulary.rs`), and
2. the **replicated `EnvelopeKind` set** persist owns as the APPLY authority
   (`src/federation/replication_policy.rs`).

---

## Part 1 — Tier-2 `kind` allocations

The CC 0.7 wire vocabulary is **two-tier** (RFC 8126 registration policy).
Tier 1 is the closed `MessageType` set carrying the ethical primitives, owned
by CIRISEdge and amended only through CC §4.5.1. Tier 2 is three opaque
channels — `OpaqueRequest` / `OpaqueResponse` / `OpaqueEvent` — each carrying a
`kind: u32` drawn from a per-repo reserved range. Edge treats the `payload` as
opaque bytes and enforces only the outer envelope signature and the global body
caps; **the range steward owns the inner schema, its canonicalization, and the
convenience surface** (§3.3), documented here.

§3.1 assigns CIRISPersist the range above. This table is the authoritative
`kind → semantics` map for it. Edge does not know or enforce what a persist
`kind` means; a peer that receives a persist-range `kind` it does not implement
returns `OpaqueResponse { status: 501 }` — never a silent drop.

Allocating a new `kind` inside this range is a steward action (RFC 8126 Private
Use): no CC amendment, just an entry below and the matching constant in
`src/wire_vocabulary.rs`.

### Allocations

| `kind` | Name | Channel | Payload | Status |
|---|---|---|---|---|
| `0x0005_0001` | accord trace-events batch | `OpaqueEvent` | canonical JSON of `ciris_persist::schema::BatchEnvelope` | **Ratified** |
| `0x0005_0002..=0x0005_00FF` | — | — | reserved for future persist telemetry | Unallocated |
| DSAR (`0x0005_0100..=0x0005_01FF`) | data-subject access/erasure | — | — | **Reserved, not allocated** (see below) |
| `0x0005_0200..=0x0005_FFFF` | — | — | unallocated | — |

### `0x0005_0001` — accord trace-events batch

The §3.3 migrant of the retired Tier-1 `MessageType::AccordEventsBatch`.

- **Channel:** `OpaqueEvent { kind: 0x0005_0001, payload }` — Durable,
  fire-and-forget (no ack). Hash-chain verify, scrub and persist happen inside
  lens/persist; edge is agnostic.
- **Payload:** the canonical JSON bytes of a `BatchEnvelope` — exactly the
  bytes the HTTP ingest path posts and `Engine::receive_and_persist` consumes.
  No `serde_json::Value` anywhere in the type (MISSION.md §6 anti-pattern #6);
  every field is typed, so the bytes parse losslessly.
- **Schema owner:** `ciris_persist::schema::BatchEnvelope` (`src/schema/envelope.rs`).
- **Canonicalization (produce):** `ciris_persist::trace_batch_payload_bytes(&BatchEnvelope)`.
- **Verify-before-persist (receive):** `BatchEnvelope::from_json(&payload)` —
  all schema-version / trace-level / required-field / `MAX_DATA_DEPTH` gates
  fire there and return typed errors before anything is persisted.
- **Constant:** `ciris_persist::TRACE_BATCH_KIND`.
- **Body cap:** the global `MAX_BODY_BYTES` (8 MiB, §3.2); no smaller per-kind
  sub-cap.

**Consumers:**
- *Receiver* — the CIRISServer / lens-core relay subscribes on
  `ciris_persist::TRACE_BATCH_KIND`.
- *Emitter* — CIRISAgent (CIRISAgent#904) produces the payload via
  `trace_batch_payload_bytes` and sends it over edge's generic
  `send_opaque_event(TRACE_BATCH_KIND, bytes)`.

### DSAR — reserved, **not** allocated

The §3.1 range scope names "trace batches, **DSAR**", but §3.3 resolves that
`DSARRequest` / `DSARResponse` **stay Tier-1**: data-subject access/erasure is
rights-bearing (consent-weight, adjacent to `Withdraws`) **and** rides Durable +
requires-ack — the erasure-completion receipt the three opaque channels cannot
express (§3 delivery-expressiveness limit). No DSAR `kind` is allocated here.
The sub-range is held so that, should a durable ack-bearing opaque channel ever
exist and DSAR be revisited, its allocation has a stable place.

### Why persist exposes no `send_trace_batch` wrapper

§3.3's worked example — `CIRISAgent::send_inline_text(text)` wrapping
`edge.send_opaque_event(kind, app_canonicalize(text))` — works because
CIRISAgent sits *above* CIRISEdge. **CIRISPersist sits below edge** (edge links
persist; the reverse would be a dependency cycle), so a `send_trace_batch(edge,
…)` wrapper cannot live in this repo. Persist owns and exports the *shared
definition* — the ratified `kind`, the `BatchEnvelope` schema, and the
`trace_batch_payload_bytes` / `from_json` canonicalization pair — and the
emitter/receiver tiers (which depend on both persist and edge) compose it with
edge's generic `send_opaque_event` / `subscribe_opaque`. "App owns meaning"
holds on the wire and in the stewardship graph; there is no transport-tier
typed struct for this migrant.

---

## Part 2 — Replicated `EnvelopeKind`s

The **replicated wire kinds** are a closed, ordered set persist owns as the
APPLY authority (`src/federation/replication_policy.rs`, `EnvelopeKind::ALL`).
CIRISEdge's `replication::protocol::EnvelopeKind` mirrors the names in order,
and CIRISServer pins the hash. The order is hashed, so a new kind is always
**appended**, never inserted, and a retired kind keeps its position.

**Pins:**
- `REPLICATION_POLICY_HASH` = `1860451cf166879431dadf433422f6fdb43a911b5c889b0f55ca491262393869`
  (covers every kind's `KindPolicy`: signer, binding, projections, tier, audience).
- `CONSENT_GRAMMAR_HASH` = `4d473eac6f2bfde1a78b01e9a2ac8442fc9adb5207c7adeb51d509215b79e843`
  (its `kind_transferability` covers the kind list).

### The nineteen kinds, in hashed order

| # | `EnvelopeKind` | Table / carrier | Framed carriage |
|---|---|---|---|
| 1 | `Key` | `federation_keys` | retired — travels as its row (an `Attestation`) |
| 2 | `Attestation` | `federation_attestations` — the whole claim namespace rides here | live |
| 3 | `Revocation` | `federation_revocations` | retired — travels as its row |
| 4 | `IdentityOccurrence` | `federation_identity_occurrences` | retired — travels as its row |
| 5 | `Family` | `federation_families` | live |
| 6 | `Community` | `federation_communities` | live |
| 7 | `IdentityOccurrenceRevocation` | `federation_identity_occurrence_revocations` | retired — travels as its row |
| 8 | `FamilyMembershipRevocation` | `federation_family_membership_revocations` | live |
| 9 | `CommunityMembershipRevocation` | `federation_community_membership_revocations` (insert rotates the DEK epoch) | live |
| 10 | `LocationProof` | `federation_location_proofs` | live |
| 11 | `Organization` | — | retired (CC 3.3.9): an organisation is an affiliation's community record |
| 12 | `OrgMembership` | — | retired (CC 3.3.9): a member is a `membership:{stage}` seat plus a hierarchy edge |
| 13 | `PartnerRecord` | — | retired (CC 3.3.9): a partner is a `licensure:{community_key_id}:v1` row on the `Attestation` kind |
| 14 | `TransportDestination` | `federation_transport_destinations` | live |
| 15 | `AccordQuorumEvidence` | `accord_proposal` + its `accord_participation` set, as one bundle | live |
| 16 | `KeyGrant` | `key_grant:*` rows (see below) | live |
| 17 | `CommunityMembershipWidening` | `federation_community_membership_widenings` | live |
| 18 | `FamilyMembershipWidening` | `federation_family_membership_widenings` | live |
| 19 | `CommunityMembershipListing` | `federation_community_membership_listings` | live |

An inbound framed object of a retired kind (`RETIRED_FRAMED`) is refused with
`federation_envelope_kind_retired`, whose detail names the kind in snake_case.

### Who a kind is served to (CIRISEdge#761, CIRISPersist#963)

Every `KindPolicy` carries an `audience` (`ServeAudience`):

- `cohort` — `Attestation`, `KeyGrant`: decided per row, per peer
  (`replication_audience::may_receive`).
- `membership_plane` — `Family`, `Community` and the five membership planes
  (`may_receive_group_plane`): public groups to every peer; a private group's
  to members' nodes, live invitees' nodes and the named member's nodes.
- `public` — every other kind.

### 16 — `KeyGrant` (#848, #989, CC 3.3.2)

A key grant is one `scores` row per recipient. The `KeyGrant` kind is the
plane these rows project into.

- **Wire shape.** A `SignedKeyGrantRow` (`{"attestation": {…}}`, the
  `SignedAttestation` shape) is a `scores` row with envelope `dimension`
  `key_grant:content:v1` / `key_grant:epoch:v1` / `key_grant:stream:v1`,
  `attesting_key_id` the sealer (the minter on the epoch axis, a key that
  speaks for the owner on the content and stream axes), `attested_key_id` the
  RECIPIENT occurrence, `score` 1.0, no subject, no expiry, at the content's
  own `cohort_scope` (`community` on the epoch axis). Envelope members, each
  present only on the axis that uses it: `axis`, `at_rest_sha256`,
  `owner_key_id`, `community_key_id`, `minter_key_id`, `epoch`, `stream_id`,
  `wrap_algorithm` (v2 only), `wrapped_dek`; plus the CC 2 target
  (`family_key_id` on a family row, `community_id` on a community row and on
  every epoch row). The digest is a member, never an `evidence_refs` citation.
- **Admission** (`key_grant::check_key_grant_row_admission`, asked of every
  federation-tier row on every backend): the shape, a v2 wrap, self-signed, the
  sealer rule, and the recipient rule (an occurrence the one audience rule
  lets hold the cohort's key). A `withdraws` / `recants` naming a key-grant row
  is refused.
- **Projection.** Both typed attestation doors (`apply_replicated_attestation`,
  `put_attestation_synced`) project the row's wrap into the grant tables as a
  union keyed by the row's identity `(dimension, attester, attested, axis
  identity)`; CC 2's latest-wins over `(attester, dimension, attested)` does
  not apply. `apply_replicated_key_grant` is the door that reports the
  projection. Grants are never retracted (CC 3: "cannot retroactively
  un-share"); forward secrecy is by rotation.
- **Plane.** `Plane::KeyGrant { axis }` projects `SelfOwn` at self / family
  (the content axis) and `Cohort` everywhere else; never `Global`.
- **Delivery.** A row reaches its recipient's node when the cohort's audience
  contains that node, and no other node.
- **Retired set carrier.** The earlier carrier — one signed SET of every
  recipient wrap for one identity, typed `key_grant:{axis}:v1` — is retired
  (CC 2.4 closes the row-type slot at the five structural types). The
  row-type gate refuses a set row `attestation_type_unregistered` at the plane
  doors, the key-grant door answers `set_retired`, and held sets are not
  served (`registry::RETIRED_CARRIER_STEMS`); each node re-emits its own wraps
  as rows (V192 marks every axis dirty).

`FSD/BLOB_REPLICATION.md` Part II (§11–§19) is the design.

### 17 — `CommunityMembershipWidening` (#860)

| signer | binding | projections |
|---|---|---|
| `RegisteredSigner` | `OwnerOf` | `[]` (E4: the row IS the projection) |

One row of `federation_community_membership_widenings`:
`(community_key_id, member_key_id, effective_at)` + `joined_at`, `role` — the
addition plane, the mirror of `CommunityMembershipRevocation`.

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

`FSD/ROOM_ROSTER_PLANES.md` is the design.

### 18 — `FamilyMembershipWidening` (#910)

| signer | binding | projections |
|---|---|---|
| `RegisteredSigner` | `OwnerOf` | `[]` (E4: the row IS the projection) |

One row of `federation_family_membership_widenings`:
`(family_key_id, member_key_id, effective_at)` + `joined_at`, `role`,
`cosignatures` — the family addition plane, the twin of
`CommunityMembershipWidening`.

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
- **The family revocation key** includes `effective_at` (V154): a re-added
  member can be removed again; the since-read's resume id and the wire-index
  record key are the three-part compound.

`FSD/ROOM_ROSTER_AUTHORITY.md` §10 is the design.

### 19 — `CommunityMembershipListing` (#912)

| signer | binding | projections |
|---|---|---|
| `RegisteredSigner` | `SelfOwn` | `[]` (the row IS the projection) |

One row of `federation_community_membership_listings`:
`(community_key_id, member_key_id, effective_at)` + `listed` (`"public"` or
absent) — one member's CC 2 public-listing choice in one room.

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
- **Vocabulary.** `listed` is a `universal_paths` member (`paths::LISTED`),
  covered by `ENVELOPE_VOCABULARY_SHA256`. `history_on_join` is not adopted
  (see the pin notes in `src/federation/envelope.rs`).

`FSD/ROOM_ROSTER_AUTHORITY.md` §11 is the design.
