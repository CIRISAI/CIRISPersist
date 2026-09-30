# FSD — Membership acceptance: nobody joins without their own signed consent

**Issue:** CIRISPersist#955 · **Normative source:** CIRISConstitution#133 (CC 4.4.3.2.3 admit predicate and its family twin) · **Target:** v52.0.0 (MAJOR) · **Adopter contract:** accepted by CIRISServer as posted in #955 issuecomment-5903472278 (Server mirror: `FSD/MEMBERSHIP_INVITES.md` @8bd5e522).

**Rulings (maintainer, 2026-09-30):**
- Nobody joins a family or community without their own signed acceptance. This holds under every `consensus_protocol`, `founder_only` included.
- Founding-roster members consent by SIGNING the founding record (its authority or a co-signer); anyone listed who did not sign joins only by proposal and acceptance (§9 Q1).
- A supersede never adds a member; every addition rides the widening planes (§9 Q2).
- Reverse quorum is not a membership protocol; its refusal on rosters stays.

---

## 1. The hole

Membership grows through four entry points:
- the widening planes (`put_family_membership_widening`, `put_community_membership_widening`, and the local `add_member` → `add_{family,community}_member`, which write a widening row);
- a roster-growing supersede (`supersede_{family,community}_with_quorum`, and replicated `put_family` / `apply_replicated_community` through `group_amendment::route_occupied_*`);
- the founding record (the first insert of `put_family` / `put_community` / `apply_replicated_community`).

Each asks the EXISTING members' standing under `consensus_protocol` (`check_{family,community}_roster_authority`, `verify_membership_quorum`). None asks the member being added. The only newcomer-signed input anywhere is `geographic`'s `location_proof`.

## 2. Three claim dimensions on the attestation plane

No new `EnvelopeKind`. The attestation plane carries every claim family, and a new kind is a hashed-vocabulary append plus a re-pin for every adopter. The rows ride `list_attestations_since` like every claim.

| dimension (the envelope's `dimension`; `attestation_type` = `scores`) | attester (`signer_acts_for` applies) | `cohort_scope` / target | envelope members (REQUIRED unless noted) |
|---|---|---|---|
| `membership:proposal:v1` | the inviter (§4) | `family` or `community`; target = the group (`family_key_id` / `community_key_id`) | `group_kind` ∈ {`family`, `community`}; the group id in its target member; `role` (nullable); `subject_key_ids = [K]` (exactly one) |
| `membership:acceptance:v1` | K's person key | the proposal's group target | `references_attestation_id` (the proposal); `proposal_hash` = the proposal's `original_content_hash`; the group id; `role` = the role offered |
| `membership:decline:v1` | K's person key | the proposal's group target | `references_attestation_id`; `proposal_hash`; the group id |

**Proposal row rules:**
- `expires_at` is REQUIRED, `> asserted_at`, and `≤ asserted_at + 30 days` (`MEMBERSHIP_PROPOSAL_MAX_TTL_SECS = 2 592 000`).
- K is named in `subject_key_ids`, NOT in `attested_key_id`: AV-84 makes a targeted row's `attested_key_id` its own producer.
- A proposal for a K who is already active in the group at `asserted_at` is not an error. It simply has nothing to admit.

The dimension family is governed by persist. It is registered through CIRISConstitution#133. Until the re-vendor lands it is a declared exception (`UNREGISTERED_GATED_FAMILIES`), never a staged family: a staged family refuses at federation tier and would stop delivery.

## 3. Two narrow arms

### 3.1 Read: the proposal reaches its subject
A `membership:proposal:v1` row is readable by a caller whose self-collective (`admission.self_key_ids`) contains an entry of the row's `subject_key_ids`.
- The Rust gate `CallerScope::admits` and the SQL twin `cohort_scope_sql_predicate_full` move together. The SQL twin is an `EXISTS` over the V106 `attestation_subjects` projection, keyed on the row's `attestation_id` and gated on `attestation_type = 'membership:proposal:v1'`.
- Only the proposal dimension gets this arm; nothing else in the room becomes visible to a non-member.
- The serve cursor (`list_attestations_since`) is unchanged: it already serves every federation-tier row. Routing a proposal to K's node is the transport's job (Edge), keyed on `subject_key_ids`.

### 3.2 Write: K's reply at a group K is not in
AV-45 (`check_write_cohort_scope_for`) refuses a non-member's row at a group target. An acceptance or decline is admitted there iff:
- its signer resolves (`signer_acts_for`) to the proposal's `subject_key_ids[0]`;
- the referenced proposal is held on this node;
- group id, `proposal_hash` and (acceptance) `role` agree with it.

A reply whose proposal is not held here refuses RETRYABLE: `membership_proposal_unresolved`, the #797 shape. A reply that disagrees refuses TERMINAL: `membership_acceptance_mismatch`. Every other non-member row still refuses as today.

**Replies conflict.** The door refuses the second reply (acceptance after decline, decline after acceptance) by the same K to the same proposal: `membership_reply_conflict`. A node that holds both, because they replicated in different orders, treats the proposal as dead (§5).

## 4. Who proposes; where the quorum lives
- `founder_only`: the proposer is an active founder (role `founder`).
- Any other protocol: any active member at the proposal's `asserted_at`.
- **The consensus quorum stays on the growth record** (the widening's primary signer and cosigners, or the supersede's `quorum_signatures`), judged exactly as today by `check_*_roster_authority` / `verify_membership_quorum`. The proposal carries no quorum: it is an invitation; the group's decision is the growth. One quorum check, not two.
- Consequence: under a quorum protocol K can accept and still not be admitted. Server shows this as "accepted, awaiting the group".

## 5. The gate: every growth, every protocol, put AND apply
For each identity K that a growth ADDS — not active in the group's authorized roster immediately before the growth's instant — the door requires:

1. an admitted `membership:acceptance:v1` by K referencing a proposal P for the same group (and, for a widening, the same `role`);
2. no admitted `membership:decline:v1` by K of P, and no `withdraws` of P by its proposer;
3. `acceptance.asserted_at ≤ P.expires_at`;
4. the growth's own signed instant `≤ P.expires_at`.

Expiry is judged on the instants the parties signed, never on a receiver's clock. Every node gives the same verdict for the same rows ([[feedback-a-signer-chosen-instant-is-not-an-axis-for-readmission]]: the instants are the consenting parties' own).

A role change for an already-active member is not a growth and needs no acceptance.

**Refusals** (one new `Error::MembershipAcceptanceRefused { group_key_id, member_key_id, rule }`, Python `ValueError` as the sibling `RosterAuthorityUnauthorized`, message `"<kind>: <rule>"`; CC surface `hard_case:community_consensus_protocol_violation:{C}`):

| rule | class |
|---|---|
| `membership_acceptance_unresolved` | RETRYABLE (no acceptance held yet; rows arrive out of order) |
| `membership_proposal_unresolved` | RETRYABLE (the acceptance's proposal not held) |
| `membership_declined` | terminal |
| `membership_proposal_expired` | terminal (includes a withdrawn proposal) |
| `membership_acceptance_mismatch` | terminal (group / hash / role) |
| `membership_reply_conflict` | terminal (both replies held) |
| `membership_founding_member_unsigned` | terminal (Q1) |
| `membership_supersede_cannot_add` | terminal (Q2) |

**Doors:**

| entry | local put | replication apply |
|---|---|---|
| widening (family, community) | `put_*_membership_widening` via `add_*_member` | the same door; the gate lives in `check_{family,community}_roster_authority`, which both reach |
| supersede | `supersede_*_signed` (`group_amendment.rs`) | `route_occupied_*` (`group_amendment.rs`) |
| founding record | `put_family` / `put_community` first insert (memory, sqlite, postgres) | `put_family` (replicated) / `apply_replicated_community` Insert route |

**Founding record (Q1):** every listed member signed the record — its authority or a `cosignatures[]` entry, compared as identities — else `membership_founding_member_unsigned`. `SignedFamily` gains `cosignatures` (V162, persisted and served like a community row's V158 column).

**Supersede (Q2):** a supersede's roster may keep, re-list or drop members but never add one (`membership_supersede_cannot_add`), on the local door and the replicated amendment. One exception: a trust-root-grade community's founders' amendment (#926 HIGH-3 — founder seats move only through the record) may seat a key that SIGNED that version; signing is consent (Q1) and there is no proposal whose expiry could be judged.

## 6. Decline, withdrawal, leave
- A decline is terminal for its proposal; a new invitation is a new proposal.
- The proposer may withdraw a proposal with the ordinary `withdraws`; a withdrawn proposal is treated as expired.
- A growth already admitted is never re-judged. A member leaves only by their own forward-only `withdraws`, unchanged.
- Rows stored before v52 are not re-judged.

## 7. Delivery (both directions)
- **Proposal → K's node:** the transport routes by `subject_key_ids`. K's node applies it through `apply_replicated_attestation`, whose AV-45 gate asks whether the proposer is a member of the group. So K's node must hold the group's record and roster planes to admit the proposal (§9 Q4).
- **Reply → the group:** the reply is placed at the group target and routes like any room row. §3.2 admits it at members' nodes.

## 8. Witnesses (I210–I219; every backend unless noted)

| id | property |
|---|---|
| I210 | K (and K's other device) reads the proposal through `list_attestations`; a non-subject non-member does not. The Rust gate equals the SQL twin on sqlite and postgres. |
| I211 | K's acceptance at the group target is admitted; a stranger's reply is refused; a reply before its proposal is `membership_proposal_unresolved` (retryable) and admits on retry. |
| I212 | A widening adding K with no acceptance is refused `membership_acceptance_unresolved` on the local door AND the replicated door; with an acceptance it is admitted and the fold shows K. A role change of an active member needs none. |
| I213 | Decline is terminal (a later growth is refused); the opposite reply to the same proposal is `membership_reply_conflict` in either order; a second invitation, accepted, admits. |
| I214 | Expiry on signed instants: an acceptance after `expires_at`, and a growth `effective_at` after it, are each refused. The proposal door refuses a missing or non-positive TTL, or one over 30 days. |
| I215 | A group, hash or role mismatch is `membership_acceptance_mismatch`. |
| I216 | Founding: a record whose listed members all signed is admitted (family and community); an unsigned listed member is `membership_founding_member_unsigned`; the family's co-signatures are persisted and served (V162). |
| I217 | A supersede adding K is `membership_supersede_cannot_add`; a rename-only supersede is admitted. |
| I218 | Under a quorum protocol, an accepted K with an under-signed widening is refused `roster_authority_*` ("accepted, awaiting the group"), then admitted at quorum. |
| I219 | Two nodes, end to end through the planes: the proposal on A is applied and read on K's node B; K accepts on B; A applies the acceptance; A's widening is admitted and B applies it. |

## 9. Resolved (operator rulings of 2026-09-30, and persist's calls)

- **Q1 — founding (operator):** a founding member is admitted iff it signed the founding record (authority or co-signer). Signing is consent. `SignedFamily.cosignatures` + V162.
- **Q2 — supersede (operator):** a supersede may not add members; additions ride the widening planes, which carry the signed instant expiry is judged on. Trust-root founders' amendments keep their record-only founder seats for keys that signed the version (§5).
- **Q3 — namespace (persist):** `membership:` is admitted through `UNREGISTERED_GATED_FAMILIES` (and recorded in `PERSIST_AUTHORED_GATED_UNCATALOGUED_FAMILIES`) until CIRISConstitution#133 registers the three rows; the re-vendor deletes both lines (the tests fail until it does). Not a staged family: that would refuse at federation tier and stop delivery.
- **Q4 — K's node (persist):** a proposal whose group this node does NOT hold is stored without the roster check (the subject-apply arm) and is readable there only by its subject; the proposer's standing is judged where the roster lives, when the growth arrives. A reply is admitted wherever its proposal is held — it never needs the group's roster.

## 10. Decisions the build forced

- **Rows are `scores` claims.** The three dimensions ride the envelope's `dimension` (like every claim family); a proposer retracts with the ordinary `withdraws`.
- **The reply is attested to K.** `attested_key_id` = the invitee, signed by K or a key acting for K (AV-84 admits a device signing about its own identity), so `list_attestations_for(K)` finds K's replies.
- **AV-84's one exception:** a proposal names exactly one invitee in `subject_key_ids`.
- **The no-moderator federation gate (CC 4.5.4) does not judge membership rows.** They are part of admission, like the roster rows that gate never judged; refusing them would leave an unmoderated room unable ever to invite the moderator it lacks.
- **Engine doors:** `Engine::propose_membership(scope, group, invitee, role, expires_at)` and `Engine::reply_to_membership_proposal(proposal_id, accept)`.
