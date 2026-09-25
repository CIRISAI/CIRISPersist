# FSD — A roster change needs standing; admission reads the same roster

**Issues:** CIRISPersist#907, CIRISPersist#908 (both filed against v48.0.0 `59283e3e` while CIRISServer scoped community roster CRUD).
**Release:** v49.0.0 (MAJOR). Roster rows gain co-signatures, `AdmitSpec` gains a field, a new typed refusal, a new directory read, and roster changes that a single signature used to carry are now refused unless the room's `consensus_protocol` is met. First built as a v48.1.0 minor with single-signer standing; checked against the CC and ruled by the operator (2026-09-24): **full CC now, as a MAJOR** — see §2.
**Predecessor:** `FSD/ROOM_ROSTER_PLANES.md` (v48.0.0, #860).

## 0. Understanding, and what already exists

**The CC, read for this document** (CIRISConstitution `constitution/`, 2026-09-24):
- **CC 4.4.3.2.3** `community-admission` — a membership change is admitted by `evaluate_consensus_protocol(protocol, current, proposed.signatures)` over the **current** community, then any subkind predicate (geographic: a live `location_proof` inside the constraint). Refusal emits `hard_case:community_consensus_protocol_violation`.
- **CC 4.4.3.4.2** `admission-membership` (family; community mirrors it) — the protocol arms: `founder_only` any founder signature; `unanimous` every current member; `majority` more than half; `quorum:M/N` at least `M`, **absolute** (4.4.3.4.2.1); `weighted:{rubric}` / `custom:{id}` operator-defined. An insufficient change is held pending (operator window) or rejected; persist has no pending state, so it rejects.
- **CC 4.4.3.2.4.1(a)** — resolution is deterministic and evaluated as of the resolver's `now`; `cohort_subkind: infrastructure` evaluates the protocol over **founders only**.
- **CC 4.2 (accord halt reach)** — a delegation is measured as **live at the act's `asserted_at`**, the precedent for judging a moderator's standing at the change's instant.
- **CC 2.4.1** `withdraws-isn't-retroactive`, applied as forward-only removal in **CC 4.4.3.2.2** and **CC 4.5.12.1**; epochs are the key-rotation axis (a removal rotates; `history_on_join: from_join` reads the current epoch forward). A change stands in the epoch it was admitted in.
- The CC names **no leave rule** and **no moderator arm** in admission.

**Sibling documents** (searched across CIRISServer, CIRISEdge, CIRISAgent, CIRISConformance, CIRISRegistry, CIRISVerify, CIRISConstitution):
- **CIRISServer `FSD/ROSTER_AND_DRIVE_CRUD.md`** (2026-09-24, the 0.5.216 contract that filed #907–#909) — **agrees** with this document: a change is authorized when the signer set satisfies `consensus_protocol`; `founder_only` is the default for new households and rooms, so the common case is one founder signature; stronger protocols use a two-phase **envelope → cosign → assemble** flow; **leaving is always your own act**; a room may be widened by a founder or "an appointed roster-duty holder via `delegates_to`". It **adds** a rule persist does not enforce: the last founder may not leave a room or family that still has other members (`community.last_founder`, a server refusal). It cites `verify_membership_quorum` as the protocol check; that function checks a **strict majority whatever the protocol**, which is §7's recorded gap. Co-signed widening and revocation rows (§3) are what the server's assemble step now produces.
- **CIRISServer `FSD/ROSTERED_GROUP_KEY_OPS.md`** (2026-06-21) — the accord catalogue: a family is `consensus_protocol` + entrenchment, a community is `consensus_protocol` + moderation; the accord's `verify_quorum_policy` requires `M` distinct founder co-signatures with strict majority. Same co-signing idea on a different plane.
- **CIRISEdge `FSD/GROUP_CONTENT_ON_BLOBS.md`** — "widening" there means widening a **content row's audience** (`widen_audience`), not a roster. Same word, different plane; this document always says *membership widening*.
- **CIRISServer `FSD/MESH_GOVERNANCE_AND_ADMIN_OPS.md`** — moderation, takedown and reverse quorum on content; nothing on roster standing.
- **Persist** `FSD/ROOM_ROSTER_PLANES.md` (v48.0.0, #860) is the predecessor; `FSD/SELF_FAMILY_DEK_CASCADE.md` and `FSD/V4_0_DATA_ACCESS_SURFACE.md` mention `consensus_protocol` only as a record field.

**Open, for the operator:**
1. **Last founder.** Should persist refuse a self-leave that removes the last active founder while other members remain (the server's rule)? Without it, a `founder_only` room can be left with no one able to change it. Proposed: yes, as `roster_last_founder` (substantive), since it is a property of the roster and every host would otherwise re-implement it.
2. **`supersede_*_with_quorum`** checks strict majority whatever the protocol. Proposed: route it through the same protocol evaluator in a follow-up.

## 1. The two defects

### 1.1 #907 — admission reads the record, not the roster
v48 made the widening plane the only way a room grows, and routed every read-time gate it listed through the one fold. The caller-admission path was not on the list:

- `list_communities_for_member_active` takes candidates from `list_communities_for_member` — containment in the RECORD's `members` on all three backends — and drops a room if ANY revocation naming the member is effective. No widening is a candidate; no later event can undo a removal.
- `active_community_key_ids_for` (the write-scope reader behind `build_caller_admission`) folds correctly but starts from the same record-only candidates.
- `groups_of(Community | Affiliations, …)` rides the first.

So a widened member is refused by every §4.3 gate while the wrap set holds the room key for them, and a removed-then-re-added member is refused forever.

### 1.2 #908 — a roster row needs only a valid signature
`verify_community_membership_widening_admission` and `…_revocation_admission` verify the hybrid signature under `authority_key_id` and stop. `SignerBinding::OwnerOf` on the policy row is referenced nowhere outside the policy table: a label, not a gate. Any registered key can widen itself into any room (and the minter wraps the room key to it at the next seal) or remove any member (and rotate the epoch). **v48.0.0's `WIRE_VOCABULARY_KINDS.md` claimed the widening door checks the room's authority set. It did not; that sentence was false when shipped and is corrected here.**

## 2. Standing is the room's consensus protocol (CC 4.4.3.2.3)

CC 4.4.3.2.3 (community) and 4.4.3.4.2 (family, the rule it mirrors) admit a membership change — an addition **or** a removal — by evaluating the room's **current** `consensus_protocol` over the change's **signatures**, against the roster at the change's time:

| `consensus_protocol` | admitted iff, over the room's active members at `t` |
|---|---|
| `founder_only` | some signer is an active member with role `founder` |
| `unanimous` | every active member signed (the roster is non-empty) |
| `majority` | more than half of the active members signed |
| `quorum:M/N` | at least `M` active members signed — `M` absolute, `N` documentary (CC 4.4.3.4.2.1) |
| `weighted:{rubric}`, `custom:{id}` | **refused** `roster_consensus_unevaluable`: an operator rubric persist cannot evaluate |

For `cohort_subkind: infrastructure` the protocol is evaluated over the **founders** only (CC 4.4.3.2.4.1(a)). A change is judged **once, at its own instant**: the roster, the founders and the protocol arms are read from the authorized state at `effective_at`. Delegations are judged the same way (a delegation's liveness is measured at the act's `asserted_at`, CC 4.2), and a later retraction does not reach back (CC 2.4.1 `withdraws-isn't-retroactive`). In the operator's framing: **a change belongs to the epoch it was admitted in.**

**Operator rulings beyond the CC text:**
- **Leaving needs no one's permission.** A revocation signed by the member it removes is admitted on that signature alone. The CC names no leave rule; this is persist's reading of its silence, a consent floor.
- **Named moderators keep standing, judged at the change's instant.** A signer reached from an active, steward-bound founder by a live `moderate`-scoped `delegates_to` chain **as of `effective_at`** admits the change alone. Retracting the delegation later does not undo changes made while it was live.
- **Dropped:** the room's own key and the room record's signer have no standing (neither is a CC admission path). Producers that signed removals as the room key — the #757 chat rooms, E4-era code — must now gather member signatures.

A stored row with **no recorded signer** (a revocation admitted before V110 stored one) counts: it was admitted under the rules of its day, and dropping it would readmit a removed member.

## 3. Co-signed rows, and one authorized fold

**Wire.** `SignedCommunityMembershipWidening` and `SignedCommunityMembershipRevocation` gain `cosignatures: Vec<RosterCosignature { authority_key_id, scrub_signature_classical, scrub_signature_pqc }>` (`#[serde(default, skip_serializing_if = "Vec::is_empty")]`, so a single-signed row's bytes and content hash are unchanged). Every co-signature is a hybrid scrub over the **same** `signing_envelope()` as the primary, verified at the door; a duplicate signer or a co-signer equal to the primary is refused (`InvalidArgument`). `AdmitSpec` gains the same field, so `add_community_member` can carry a quorum. V153 adds a `cosignatures` column (`'[]'` default) to both tables; the signed since-reads serve it; memory mirrors it.

**Fold.** `authorized_community_roster_at` replays the room's history in the v48 order (record members first — counted from the record, never their `joined_at` — then dated events by `effective_at`, a removal last at a tie, then member key) and **applies an event only if its signer set meets §2 in the state built so far.** An unapplied event is inert: stored, served, never counted. Every node replays the same stored history the same way, so nodes that received rows in different orders agree — which a door alone cannot guarantee. The pure core (`authorized_roster_state_at` over prepared `RosterEvent`s) is public; the async helper prepares each event's signer set and its moderator reach at the event's instant. `active_roster_at` stays the unsigned fold.

**Read.** `community_roster_signers(community_key_id)` returns every stored event's `(member, effective_at)` with its primary signer (`None` for a legacy row) and co-signers. Trait default `Unsupported` (every fold over an implementor without it fails secure); sqlite, postgres and memory implement it; the capsule proxy keeps the default like its per-room siblings, and a capsule consumer folds from the signed since-reads, which carry every signer.

**Walk.** The moderation walk (`scoped_delegation_reach`) gains an optional instant. Unset, it behaves exactly as before for every existing caller. Set to `t`, an edge counts only if it was asserted at or before `t` and not expired at `t`, and a retraction counts only if it was asserted at or before `t`. One walk, two readings — never a second walk that could drift.

## 4. The doors

`put_community_membership_widening` / `put_community_membership_revocation` (sqlite, postgres, memory) verify the primary and every co-signature, then evaluate §2 against the authorized state at the row's `effective_at`, before any write — before a revocation rotates the epoch. `add_community_member` inherits it through the widening door. A refusal is `Error::RosterAuthorityUnauthorized { community_key_id, offered_authority_key_id, rule }` (kind `federation_roster_authority_unauthorized`; Python raises the type `LocationAuthorityUnauthorized` does):

- `roster_authority_not_established` — **retryable**: the protocol is not met and at least one signer has no event in the room yet. Rows arrive out of order; persist has no deferral queue (the #734 property), so the caller re-submits.
- `roster_consensus_insufficient` — **substantive**: every signer is known and the protocol is not met.
- `roster_consensus_unevaluable` — **substantive**: `weighted:` / `custom:` protocol.

## 5. #907 — admission reads the fold

- `list_communities_for_member` (all backends) returns rooms the member appears in on the record **or in a widening**: containment in the room's history, still raw (a removed member is still listed). Its doc says so.
- `list_communities_for_member_active` and `active_community_key_ids_for` keep a candidate iff `is_active_community_member(…)` by the authorized fold. The hand-rolled "any revocation wins" spelling is deleted.
- Families have no widening plane and a two-part revocation key, so a removed family member cannot be re-added at all; `list_families_for_member_active` is unchanged and the gap is recorded on #907.

## 6. Invariants

- **I170 — admission is the roster.** memory, sqlite, postgres: a member widened by the founder of a `founder_only` room is admitted by every admission reader (`build_caller_admission`, `list_communities_for_member_active`, `groups_of`); removed, refused; re-added, admitted again. Control: before the widening, not admitted.
- **I171 — standing is the protocol.** One arm per protocol, each with its refusal and its admission: `founder_only` (a plain member refused `roster_consensus_insufficient`, a founder admitted); `majority` of three (one signature refused, two admitted via a co-signature); `unanimous` (all but one refused, all admitted); `quorum:2/5` (one refused, two admitted); `custom:x` (refused `roster_consensus_unevaluable`); `infrastructure` subkind (a majority of plain members refused, the founders admitted). A stranger refused `roster_authority_not_established`. A member leaving admitted alone. The room's own key and the record signer, alone, refused. A refused revocation stores no row (the rotation shares its transaction).
- **I172 — the fold judges the history, not the arrival.** Two nodes receive the same rows in opposite orders; after both arrive their rosters agree.
- **I173 — a legacy revocation still counts** (fold and store halves).
- **I175 — a moderator's change belongs to its instant.** Founder alice appoints mo (`moderate`); mo widens hank at `t1`; alice withdraws the appointment at `t2`. hank stays on the roster; a widening by mo dated after `t2` is refused. Control: a widening by mo dated before the appointment is refused.
- **I176 — co-signatures are verified.** A co-signature over a different envelope, a duplicate co-signer, and a co-signer equal to the primary are each refused; the stored row serves its co-signatures byte-exact on the since-read.

## 7. Not in scope
- `supersede_community_with_quorum` checks a strict majority regardless of the room's protocol (a separate CC gap on the record-rewrite path); recorded on #908.
- A family widening plane (§5).

## 8. Bundled: #909 and the verify re-pin

**#909 — `list_attestations` ignored `AttestationFilter::lifecycle`.** `Live` is the documented serde default and means "hide rows retracted by a still-hiding composer" (`supersedes` / `withdraws` / `recants` from the same attester). `list_scores` applied it on all three backends; `list_attestations` took the filter and dropped the axis on sqlite and postgres (memory does not implement the read), so every drive listing that reads through `Engine::list_attestations` showed withdrawn and replaced files. The same predicate now runs in both queries. Replication reads the since-cursor, not this read, so nothing that replicates changes. **I174** (sqlite, postgres): one live row, one withdrawn, one superseded pair; `Live` shows live + head, and each `Include*` view and `All` add back exactly their class.

**CIRISVerify v16.1.0 → v16.2.1.** v16.2.0 added a golden vector and corrected a doc claim; v16.2.1 makes every `SecureBlobStorage` report an absent key as `KeyNotFound` (CIRISVerify#288/#289). Persist decides seed absence with `exists()`, never from `load`'s error, so production is unaffected; the `FakeHardwareStorage` test double answered `NoPlatformSupport` and now honours the contract it stands in for. Seven Cargo pins and the wheel's `ciris-verify>=16.2.1,<17` move together.

## 9. How the design got here

The first build (v48.1.0, single-signer standing) passed its witnesses; the full lanes then found that keyed rooms sign removals as the room key, and a check against the CC showed the whole single-signer model was weaker than CC 4.4.3.2.3 for every protocol but `founder_only`. The operator chose full CC as v49.0.0 and ruled on the three extensions (§2). Families remain signature-only — the same shape as #908, out of scope, recorded on the issue.
