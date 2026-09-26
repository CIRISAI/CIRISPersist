# FSD — A roster change needs standing; admission reads the same roster

**Issues:** CIRISPersist#907, CIRISPersist#908, CIRISPersist#909, CIRISPersist#910 (#907/#908 filed against v48.0.0 `59283e3e` while CIRISServer scoped community roster CRUD).
**Release:** v49.0.0 (MAJOR). Roster rows gain co-signatures, `AdmitSpec` gains a field, a new typed refusal, a new directory read, and roster changes that a single signature used to carry are now refused unless the room's `consensus_protocol` is met. First built as a v49.0.0 minor with single-signer standing; checked against the CC and ruled by the operator (2026-09-24): **full CC now, as a MAJOR** — see §2.
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

**Decentralized moderation, as the CC builds it** (read for this document):
- **Two layers (CC 4.5.5).** *Open labeling*: anyone files a `scores` row against anything; readers compose hide / blur / down-rank filters as consumer policy. *Authoritative action*: a takedown, a moderation event, an appeal ruling requires a delegated duty (`moderate`, `takedown`, `review`, `slash`), exercised as-self or through a `delegates_to` chain whose every edge bears the scope, which attenuates and never expands, is depth ≤ 5, is revocable at any link, and roots in a steward-bound human. The principal is discovered by walking the chain, never read from a payload field — *takedown isn't a coup*.
- **No unmoderated space (CC 4.5.4).** A community federates only while ≥ 1 live `moderate` holder exists. A moderator is an **appointment** — `delegates_to(authority → K, scope ⊇ {moderate}, community_id: C)` with the root in C's authority set (founders, or keys C's `consensus_protocol` authorizes) and steward-bound. Lapse ⇒ merit auto-promotion (highest `moderation_track_record`) ⇒ else 48 h recovery ⇒ else fail-secure.
- **Presence is authority (CC 4.5.13, generalising the accord live quorum of CC 4.2.6).** A moderator or community steward acts by a single signature; on their absence within 48 h a live-majority of whoever shows up decides; a harm report defaults to removal; keeping and viewing are signed acts. *Past actions validly decided by the then-live set stand* (CC 4.2.6) — the non-retroactivity this document's fold implements.
- **Persist's reverse quorum (#574, v24.3.0; #591 escalation)** is the commons brake on that pattern: an action lands on arrival; any one member may object; `m` in-window objectors reverse it; dismissing an objection needs ≥ a strict majority. **Forward quorum** — evaluating `consensus_protocol` — was always the missing half (CIRISServer `MESH_GOVERNANCE_AND_ADMIN_OPS.md`: "consensus_protocol is a stored label", CIRISServer#111). This document builds it, in persist.

**The constraint that shapes every answer.** The roster fold runs on every node, so **every evaluator must be a pure function of replicated, signed state**. A host-registered callback would let two nodes fold the same rows to different rosters. Operator rubrics and custom predicates are therefore **declared data in the signed room record** (`policy_blob`), evaluated by persist's one evaluator — never plugged-in code.

**Resolved (2026-09-24, operator: "all of them implemented now and usable, with persist providing DRY evaluators"):**
1. **All forms are evaluated**, by one module (`federation::consensus`) that every path calls — roster rows, `verify_membership_quorum` / `supersede_*_with_quorum`, and the family doors. See §2.1.
2. **Last founder.** Persist refuses a change that leaves a room or family with other active members and **no active founder** (`roster_last_founder`, substantive) — the CC 4.5.4 "never a vacuum" rule applied to governance, and the Server's `last_founder` rule moved to where every host gets it. Removing the last member entirely is allowed (the room dissolves).
3. **`supersede_*_with_quorum`** evaluates the room's own protocol through the same module instead of a fixed strict majority.
4. **Trust-root charters keep their #557 floor** (strict majority of the node's own roster, applied on top of the evaluator's answer) — deliberate hardening for roots, now layered over the one evaluator rather than a second reading of the vocabulary.
5. **Families** use the same evaluator on their membership-revocation door and `add_family_member` — the #908 shape closed on both planes.

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
| `weighted:{rubric}` | Σ weight(signer) ≥ threshold, with `rubric` resolved from the room record's `policy_blob.rubrics.{rubric}` = `{ "weights": {key_or_role → w}, "default_weight": w, "threshold": x }`; the CC's own worked case (`weights` all 1, `threshold = ceil(roster/2)`) is the built-in rubric `uniform_half`. An undeclared rubric ⇒ `roster_consensus_unevaluable` |
| `custom:{id}` | the room record's `policy_blob.custom.{id}` — a declared expression over the primitives: `{"any_of": [...]}`, `{"all_of": [...]}`, `{"founder": {}}`, `{"quorum": M}`, `{"majority": {}}`, `{"unanimous": {}}`, `{"role": {"name": r, "min": M}}`, `{"weighted": "rubric"}`. Role-based and multi-stage protocols (the CC's examples) compose from these. An undeclared id or an unknown node ⇒ `roster_consensus_unevaluable` |
| `reverse_quorum:M/N:{window}[+escalate:…]` | **act-unless-objected, classified by direction** (the accord-ops invariant: *1-of-N to protect, m-of-n to undo, never a 1-of-N capability grant*): a **removal** (protective — it withdraws the room key going forward) lands on any one active member's signature and is **reversed** — the member counts again — if `M` distinct active members file in-window objections through the #574 fold; an **addition** (a capability grant — it wraps the room key) needs the #574 dismissal threshold forward (`M` floored at a strict majority). The `+escalate:` steward tier applies to the objection fold unchanged |

For `cohort_subkind: infrastructure` the protocol is evaluated over the **founders** only (CC 4.4.3.2.4.1(a)). `quorum:M/N` reads `M` as absolute (CC 4.4.3.4.2.1 is normative over the older vocabulary table's "n is the current roster size").

### 2.1 One evaluator

`federation::consensus::evaluate(protocol, subkind, policy_blob, roster_at_t, signers, direction) -> Verdict { Admit | Insufficient { needed, have } | Unevaluable(reason) }` is pure and total over the vocabulary. Every caller passes the roster it already folded; none re-reads the protocol string. `required_signatures(protocol, roster)` exposes the count for callers that tally elsewhere (the trust-root charter, which then applies its #557 floor). A change is judged **once, at its own instant**: the roster, the founders and the protocol arms are read from the authorized state at `effective_at`. Delegations are judged the same way (a delegation's liveness is measured at the act's `asserted_at`, CC 4.2), and a later retraction does not reach back (CC 2.4.1 `withdraws-isn't-retroactive`). In the operator's framing: **a change belongs to the epoch it was admitted in.**

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
- `roster_consensus_unevaluable` — **substantive**: a `weighted:` rubric or `custom:` id the room record does not declare, or a malformed declaration.
- `roster_last_founder` — **substantive**: the change would leave other active members and no active founder.

## 5. #907 — admission reads the fold

- `list_communities_for_member` (all backends) returns rooms the member appears in on the record **or in a widening**: containment in the room's history, still raw (a removed member is still listed). Its doc says so.
- `list_communities_for_member_active` and `active_community_key_ids_for` keep a candidate iff `is_active_community_member(…)` by the authorized fold. The hand-rolled "any revocation wins" spelling is deleted.
- ~~Families have no widening plane and a two-part revocation key, so a removed family member cannot be re-added at all; `list_families_for_member_active` is unchanged and the gap is recorded on #907.~~ Closed by §10 (#910): families have the plane, the three-part key, and `list_families_for_member_active` reads `authorized_family_roster_at`.

## 6. Invariants

- **I170 — admission is the roster.** memory, sqlite, postgres: a member widened by the founder of a `founder_only` room is admitted by every admission reader (`build_caller_admission`, `list_communities_for_member_active`, `groups_of`); removed, refused; re-added, admitted again. Control: before the widening, not admitted.
- **I171 — standing is the protocol.** One arm per protocol, each with its refusal and its admission: `founder_only` (a plain member refused `roster_consensus_insufficient`, a founder admitted); `majority` of three (one signature refused, two admitted via a co-signature); `unanimous` (all but one refused, all admitted); `quorum:2/5` (one refused, two admitted); `custom:x` (refused `roster_consensus_unevaluable`); `infrastructure` subkind (a majority of plain members refused, the founders admitted). A stranger refused `roster_authority_not_established`. A member leaving admitted alone. The room's own key and the record signer, alone, refused. A refused revocation stores no row (the rotation shares its transaction).
- **I172 — the fold judges the history, not the arrival.** Two nodes receive the same rows in opposite orders; after both arrive their rosters agree.
- **I173 — a legacy revocation still counts** (fold and store halves).
- **I175 / I175b — a moderator's change belongs to its instant, and an appointment to its epoch.** Founder alice appoints mo (`moderate`); mo widens hank at `t1`; alice withdraws the appointment at `t2`. hank stays on the roster; a widening by mo dated after `t2` is refused. Control: a widening by mo dated before the appointment is refused.
- **I176 — co-signatures are verified.** A co-signature over a different envelope, a duplicate co-signer, and a co-signer equal to the primary are each refused; the stored row serves its co-signatures byte-exact on the since-read.

### 6.1 Mutation round (v49.0.0; lane = every roster / moderation / reverse-quorum / consensus / family / supersede / amendment / #909 test, sqlite + postgres under `pg_test_db.sh`; each mutant reverted before the next)

| # | Mutant | Verdict | Killed by |
|---|--------|---------|-----------|
| M1 | legacy (signer-less) rows no longer count | KILLED | i173_fold i173_postgres i173_sqlite |
| M2 | a member leaving needs the protocol | KILLED | active_community_members_subtracts_effective_revocation active_community_members_subtracts_effective_revocation_sqlite forged_community_membership_revocation_wrong_signer_rejected_502e4 i179 i180 i77_owned_node_minter_admitted_by_principal_postgres |
| M3 | named moderators have no standing | KILLED | moderator_change_belongs_to_its_instant_memory moderator_change_belongs_to_its_instant_postgres moderator_change_belongs_to_its_instant_sqlite |
| M4 | a moderator root need not be an active founder | SURVIVED round 1 — the RULE was wrong (a founder's departure lapsed their appointments); replaced per the 2026-09-25 ruling, see M4b/M4c | — |
| M5 | retryable/substantive classification collapsed | KILLED | i171 i179 |
| M6 | last-founder rule dropped | KILLED | i179 i180 |
| M7 | last-founder demotion arm dropped | KILLED | i180 |
| M8 | the fold applies every event | KILLED | i172 |
| M9 | the fold ignores reverse-quorum reversals | KILLED | reverse_quorum_roster_removal_memory reverse_quorum_roster_removal_postgres reverse_quorum_roster_removal_sqlite |
| M10 | the door judges a row WITH itself | KILLED | add_community_member_grows_roster_idempotent_sqlite |
| M11 | moderator standing judged NOW, not at the change | KILLED | moderator_change_belongs_to_its_instant_memory moderator_change_belongs_to_its_instant_postgres moderator_change_belongs_to_its_instant_sqlite |
| M12 | majority admits exactly half | KILLED | i172 i179 infrastructure_counts_founders_only quorum_supersede_protocol_decides_memory quorum_supersede_protocol_decides_postgres quorum_supersede_protocol_decides_sqlite |
| M13 | unanimous admits all-but-one | KILLED | every_arm_admits_and_refuses i171 i179 quorum_supersede_protocol_decides_memory quorum_supersede_protocol_decides_postgres quorum_supersede_protocol_decides_sqlite |
| M14 | quorum needs M-1 | KILLED | every_arm_admits_and_refuses i171 |
| M15 | founder_only admits any member | KILLED | every_arm_admits_and_refuses i171 i179 i182 quorum_supersede_protocol_decides_memory quorum_supersede_protocol_decides_postgres |
| M16 | infrastructure counts everyone | KILLED (unit-level only — see limits) | infrastructure_counts_founders_only |
| M17 | reverse_quorum addition at 1-of-N | KILLED | quorum_supersede_protocol_decides_memory quorum_supersede_protocol_decides_postgres quorum_supersede_protocol_decides_sqlite reverse_quorum_protects_cheaply_and_grants_expensively reverse_quorum_roster_removal_memory reverse_quorum_roster_removal_postgres |
| M18 | no eligible signer still evaluates | SURVIVED round 1 → KILLED round 2 (witness added) | reverse_quorum_roster_removal_memory reverse_quorum_roster_removal_postgres reverse_quorum_roster_removal_sqlite |
| M19 | weighted threshold off by one weight | SURVIVED round 1 → KILLED round 2 (witness added) | i182 weighted_uniform_half_and_declared |
| M20 | a protocol-only rewrite is a protective Remove | KILLED | quorum_supersede_protocol_decides_memory quorum_supersede_protocol_decides_postgres quorum_supersede_protocol_decides_sqlite |
| M21 | sqlite list_attestations ignores lifecycle (#909) | KILLED | sqlite_list_attestations_lifecycle_i174_909 |
| M22 | postgres list_attestations ignores lifecycle (#909) | KILLED | pg_list_attestations_lifecycle_i174_909 |
| M4b | the epoch filter dropped (any appointment counts) | KILLED | an_appointment_belongs_to_its_epoch_memory an_appointment_belongs_to_its_epoch_postgres an_appointment_belongs_to_its_epoch_sqlite |
| M4c | the root must still be an active founder at t (the old rule) | KILLED | an_appointment_belongs_to_its_epoch_memory an_appointment_belongs_to_its_epoch_postgres an_appointment_belongs_to_its_epoch_sqlite |

**24 mutants, 24 killed** after two rounds. Round 1 left two survivors, and they meant different things. **M18** was a missing witness: under `reverse_quorum` a removal admits on any signer, so the only thing stopping a stranger's removal is the "no eligible signer admits nothing" guard — I181 now tries it. **M4** was a wrong RULE: the draft required a moderator's appointing founder to still be an active founder at the change's instant, so a founder's departure silently lapsed every appointment they made — a removal acting like a slash. The operator's ruling (2026-09-25): **no ending is retroactive** — removal, `withdraws`, `recants` and slashing all leave past decisions intact, and the recourse is re-adjudication; an appointment belongs to the epoch it was issued in (the root must have held authority when appointing, and need not hold it later). M4b and M4c pin both halves (I175b).

**Limits, stated.** M16 (the `infrastructure` subkind counts founders only) and M19's first kill are unit-level (`consensus::tests`); M19 now also dies on I182. An infrastructure-labelled room needs an authorized infrastructure key to be stored (SecReview F2), so no backend leg reaches that arm through a door — the arm is enforced, its reachability is unwitnessed. The mixed-change `Remove` pass in `verify_membership_quorum` is an EQUIVALENT mutant today (the evaluator reads direction only for `reverse_quorum`, where a removal always admits) and is documented in the code rather than witnessed.

## 7. Not in scope
- `supersede_community_with_quorum` checks a strict majority regardless of the room's protocol (a separate CC gap on the record-rewrite path); recorded on #908.
- ~~A family widening plane (§5).~~ In scope since §10 (#910).

## 8. Bundled: #909 and the verify re-pin

**#909 — `list_attestations` ignored `AttestationFilter::lifecycle`.** `Live` is the documented serde default and means "hide rows retracted by a still-hiding composer" (`supersedes` / `withdraws` / `recants` from the same attester). `list_scores` applied it on all three backends; `list_attestations` took the filter and dropped the axis on sqlite and postgres (memory does not implement the read), so every drive listing that reads through `Engine::list_attestations` showed withdrawn and replaced files. The same predicate now runs in both queries. Replication reads the since-cursor, not this read, so nothing that replicates changes. **I174** (sqlite, postgres): one live row, one withdrawn, one superseded pair; `Live` shows live + head, and each `Include*` view and `All` add back exactly their class.

**CIRISVerify v16.1.0 → v16.2.1.** v16.2.0 added a golden vector and corrected a doc claim; v16.2.1 makes every `SecureBlobStorage` report an absent key as `KeyNotFound` (CIRISVerify#288/#289). Persist decides seed absence with `exists()`, never from `load`'s error, so production is unaffected; the `FakeHardwareStorage` test double answered `NoPlatformSupport` and now honours the contract it stands in for. Seven Cargo pins and the wheel's `ciris-verify>=16.2.1,<17` move together.

## 9. How the design got here

The first build (v49.0.0, single-signer standing) passed its witnesses; the full lanes then found that keyed rooms sign removals as the room key, and a check against the CC showed the whole single-signer model was weaker than CC 4.4.3.2.3 for every protocol but `founder_only`. The operator chose full CC as v49.0.0 and ruled on the three extensions (§2). Families remain signature-only — the same shape as #908, out of scope, recorded on the issue.

## 10. #910 — families get the room treatment, and a group amendment replicates

**Filed 2026-09-25 by CIRISServer** (household CRUD on v48.0.0 / edge v31.0.0); **folded into v49.0.0 by the operator** so adopters re-pin once. Verified on the tree: a supersede UPDATEs the group row and appends `federation_group_versions`, but never re-indexes the wire record; the replicated `put_family` is a plain INSERT (a peer keeps its first copy) and `put_community` refuses a differing record under an occupied id (#758). So every record-level change — family growth, role changes, `consensus_protocol` amendments, renames — reaches no peer, **on both group kinds**. Rooms only looked fine because v48 moved their growth onto the widening plane.

1. **A family widening plane** — the #860 design applied to families: `federation_family_membership_widenings` (same shape and three-part key as the community table, co-signatures included), `EnvelopeKind::FamilyMembershipWidening` **appended as the 18th kind**, doors / per-group read / signed since-read on sqlite, postgres, memory, the capsule, the double and the connection model; `add_family_member` becomes the local door onto it (the record is never rewritten to grow). `REPLICATION_POLICY_HASH` and `CONSENT_GRAMMAR_HASH` re-pin.
2. **Re-admission** — the family revocation key gains `effective_at` (a table rebuild, as V151 did for rooms); an exact retry stays the #861 no-op.
3. **One fold at every family gate** — the same authorized replay (§3) and evaluator (§2) as rooms, over the family's own protocol; `active_family_members`, `list_families_for_member_active`, the admission readers and `verify_membership_quorum`'s prior roster all read it.
4. **Role changes ride the plane, for both kinds.** A widening that names an active member with a different role is a role change, judged by the protocol like any other change; the same role stays the idempotent no-op. Membership and role then never need a record rewrite.
5. **A group amendment replicates.** What is left on the record — name, `consensus_protocol`, `policy_blob`, entrenchment — changes by `supersede_*_with_quorum`. The signed group record gains an optional `supersede_proof { prior_persist_row_hash, change_envelope, quorum_signatures }`; supersede re-indexes the wire record; a replicated put of a differing record under an occupied id is applied **only** when the proof names the receiving node's own stored `persist_row_hash` and passes `verify_membership_quorum` against the receiving node's own prior roster (authority re-derived from its own verified state). Anything else keeps the #758 refusal. Entrenched families still refuse amendments.

**Invariants.** I177 — family widening converges across two nodes (the I164 shape) and a removed family member is re-admitted (#910.1). I178 — a family role change and a `consensus_protocol` amendment each reach a peer; a forged or stale proof (wrong prior hash, insufficient quorum) is refused and the peer keeps its record. I179 — family standing is the family's protocol (I171's arms on the family plane), and `verify_membership_quorum`'s prior roster is the fold, not the raw record (#910.2).

**Built (§10 items 1–4, #910.1–#910.3).** V154 (both dialects) adds `federation_family_membership_widenings` and rebuilds the family revocation table on `(family_key_id, removed_identity_key_id, effective_at)`. `EnvelopeKind::FamilyMembershipWidening` is the 18th kind, APPENDED (`REPLICATION_POLICY_HASH` `9d62d3a8…` → `7d0e97b4…`, `CONSENT_GRAMMAR_HASH` `07a677bb…` → `62de1696…`, both capsule digests re-pinned as growth). The family doors (`put_family_membership_widening`, `put_family_membership_revocation`) verify the primary and every co-signature and ask `check_family_roster_authority`, which runs the ONE standing function (`roster_event_standing`) over the family's own protocol — the community fold was generalized (`prepare_roster_events`, `check_roster_authority_over`) rather than copied; a family has no moderation plane. `family_roster_signers` returns the same `CommunityRosterSigners` shape (one shape of plane, one shape of signers). `add_family_member` is a trait default onto the plane; no backend rewrites a family record to grow it any more (`authorize_family_growth` is gone; `supersede_family*` is untouched). `active_family_members`, `list_families_for_member_active`, `group_prior_envelope` (so `verify_membership_quorum`'s prior roster) and the at-rest family fan-out read `authorized_family_roster_at`. Witnesses: I177 and I179 (`src/federation/family_roster_invariants.rs`, memory / sqlite / postgres). Item 5 (a group amendment replicates) and I178 are a separate slice.

**Built (§10 item 5, #910.5).** `SignedFamily` / `SignedCommunity` carry an optional `supersede_proof: GroupSupersedeProof { prior_persist_row_hash, change_envelope, quorum_signatures }` — omitted on the wire when absent (every existing record keeps its bytes and content hash) and outside `signing_envelope()` (the scrub signs the record; the proof authorizes the transition). V155 (both dialects) adds a nullable `supersede_proof` column to `federation_families` and `federation_communities`. `supersede_*_with_quorum` attaches the proof (the prior hash is the row it replaces); a plain `supersede_*` drops any caller-supplied proof (nothing verified it). Every backend's `supersede_group_row` checks, inside the transaction that replaces the row (postgres reads it `FOR UPDATE`), that a proof names the version it replaces, writes the proof (or NULL), and re-indexes the wire record. The replicated `put_family` / `put_community` route an occupied id through ONE decision (`group_amendment::route_occupied_{family,community}`): identical content is the no-op; a differing record without a proof is refused (`Conflict` — the #758 verdict verbatim for communities, the same shape for families, which used to keep their first copy on SQL and overwrite on memory); a proof naming a prior hash this node does not hold is refused as STALE (`Conflict`, retryable); otherwise the envelope must describe the record (`assert_change_envelope_matches`, plus a family's entrenchment: an entrenched family stays entrenched, and the record's flag is the one the quorum signed) and `verify_membership_quorum` must admit it against this node's own prior roster and protocol — then it is applied as a supersede (version bump + history row carrying the quorum). A first copy of an amended version is stored with its proof, so the next peer can apply it. A replicated amendment is recorded under the `community` history discriminator even when the origin superseded it as `affiliations` (the live row is shared; the receiver cannot tell). Witness: I178 (`src/federation/group_amendment_invariants.rs`, memory / sqlite / postgres, both kinds).

## 12. Bundled from the backlog pass: CIRISVerify v17, #913, #911, #915

**CIRISVerify v16.2.1 → v17.0.0.** Seven Cargo pins and the wheel's `ciris-verify>=17.0.0,<18` move together. v17 makes `ciris_crypto::Ed25519Verifier`'s `ClassicalVerifier::verify` strict (CIRISVerify#292's supersede fix and #293's Android challenge policy ride the same tag).

**#913 — one Ed25519 rule, stated.** Persist held two: the trace floor called `verify_strict`, while the hybrid federation-row floor called the trait's permissive `verify`. With a small-order `A`, the pair `(R = identity, s = 0)` verifies against any message. `HybridPolicy::Strict`'s ML-DSA-65 half contained it, so the only exposure was a path admitting on the classical half alone. v17 makes the trait method strict, but a strictness inherited through a dependency is not a rule anyone chose. `verify/hybrid.rs` now calls `verify_strict` by name, as `verify/ed25519.rs` does. **Operators holding federation rows from producers other than verify's own:** re-verify once. A row that stops verifying under strict was never produced by an honest signer.

**#911 — the durable MLS-state store has persist's one root.** `encrypted_kv::XChaChaKvStore` is where openmls's `StorageProvider` cold state lives (CEWP §7.8). Every host opened it with `open_in_memory(room_id)`: a public id as the passphrase, harmless in memory and no encryption on disk. A restarted device then lost its group state (CIRISServer#630). The fix:
- `XChaChaKvStore::open_mls_state(path)` derives the store's key from the SAME hardware-sealed seed as the secrets master and the content-at-rest master, through CIRISVerify's `derive_symmetric_key`, under a third context, `MLS_STATE_CONTEXT = "mls-state-at-rest-v1"`. There is one root to seal and rotate (BLOB_ENCRYPTION_AT_REST §4.3).
- Only the first open of a store that holds no verifier row may seal a seed. A store in use re-derives and never mints (§11.7). Otherwise a lost keyring with the TPM present would yield a different key, and the state would be unreadable while new writes went on.
- **Degraded posture, named:** with no hardware seed (no TPM / Keystore / Secure Enclave, a build without `secrets`, `CIRIS_DATA_DIR` unset, or a missing seed under a store in use), the answer is `KVError::HardwareCustodyUnavailable`. Nothing opens, and no derived or public passphrase stands in. The host chooses between in-memory state and `open(path, passphrase)` with an operator-supplied passphrase.
- The CIRISEdge half (the `StorageProvider` over this store, rejoin after restart) is CIRISEdge#676.
- **I184:** the seed policy (first open may seal, a reopen never mints, state survives the reopen); a different key refused by the verifier, never re-initialised; no seed refuses and leaves nothing behind; the production opener answers only by its two names. `every_hardware_context_is_domain_separated` pins the three contexts pairwise distinct. `the_mls_state_key_is_a_third_stable_key_from_the_one_seed` covers the derivation over the hardware double.

**#915 — Android custody attested at key generation (CIRISServer#339, CC 4.2.2.1).**
- **The arm.** `AttestationEvidence::AndroidGenerationCustody` is a closed body: leaf hex, intermediate chain hex, and `challenge_policy: "generation_only"`, the only legal value. It is walked through verify's `verify_android_key_attestation_with_challenge_policy` under `AndroidChallengePolicy::GenerationOnly`, against each anchor in `HardwareAttestationPolicy::android_root_ders`. The default anchors are verify's baked 2022 Google Hardware Attestation Root and Key Attestation CA1, fingerprint-checked by verify. An anchor that fails its check is dropped, and an empty set refuses.
- **What is enforced.** The chain, and anti-lift: `expected_pubkey` is the record's own Ed25519 key.
- **What is given up.** Per-enrollment binding. That is sound on an admission path because the record is signed by the key it attests, so a replayer without the private key gains nothing. The stored body says so.
- **The class.** It is the key's measured security level: StrongBox is `AndroidStrongbox`, TEE is `AndroidKeystore`, software is `SoftwareOnly`. The class meets `accepted_hardware_types` like every other class.
- **Where the walk runs.** `check_structure` / `check` now take the record's raw Ed25519 key (`record_ed25519`, public). Every door passes it: registration, the replicated door, the genesis bundle's install check, and the trust-root holder leg, which reports a walked Android holder as `layer_b: Some(true)`. An Android body with no key is refused, never admitted unwalked.
- **Unchanged.** The YubiKey `GenerationCustody` arm.
- **Not covered.** Google's revocation list, which needs network I/O, as verify states.
- **I185:** the measured class; anti-lift; a foreign root (the baked default and a second mock CA); an empty anchor set; the software floor; no key; the closed body; and on every backend, the registration door (genuine admitted, lifted refused, nothing stored), the replicated door, and the trust-root leg. The chains come from a mock Google CA (rcgen over the record's bare public key) and are inert against the baked anchors.

**Mutation round (#911 / #915; the I184/I185/I154–I158 lane plus the real-custody binary, sqlite + postgres under `pg_test_db.sh`): 10 of 10 killed.**

| # | Mutant | Killed by |
|---|---|---|
| N1 | a reopened MLS store may mint a seed | `i184_the_first_open_may_seal_a_reopen_never_mints` |
| N2 | no hardware custody surfaces as a crypto fault | `i184_the_production_opener_answers_by_name` |
| N3 | the MLS context collides with the secrets context | `every_hardware_context_is_domain_separated`, `the_mls_state_key_is_a_third_stable_key_from_the_one_seed` |
| N4 | the measured Android class skips the accepted-types floor | `i185_a_software_held_key_meets_the_software_floor` |
| N5 | StrongBox measured as the TEE class | `i185_a_genuine_chain_admits_at_the_measured_class` |
| N6 | the Android arm reports no class | the measured-class witness, `i185_doors` ×3 |
| N7 | a missing record key is walked as a zero key | `i185_no_key_to_bind_refuses_rather_than_admitting_unwalked` |
| N8 | the non-accord door passes no record key | `i185_doors` (memory, sqlite, postgres) |
| N9 | the trust-root leg reports an Android holder as unwalked | `i185_doors` (memory, sqlite, postgres) |
| N10 | the default Android anchor set is empty | `i185_a_chain_rooted_outside_the_anchors_is_refused`, `i185_the_default_anchor_set_is_googles_two_roots` |

The one derivation no CI runner reaches, `derive_hardware_mls_state_key` over a real TPM, is covered by the seed-policy tests over the hardware double; it passes its context constant straight through.

**Out of v49 by the operator's scope choice:** #914 (disclosure-set replication, which waits on a ruling about the consent edge it rides) and the roster-book read for CIRISServer#650.
