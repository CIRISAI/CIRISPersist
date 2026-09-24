# FSD — A roster change needs standing; admission reads the same roster

**Issues:** CIRISPersist#907, CIRISPersist#908 (both filed against v48.0.0 `59283e3e` while CIRISServer scoped community roster CRUD).
**Release:** v48.1.0 (MINOR: one new typed refusal, one new directory read with a default body, one new public fold; nothing existing changes shape. Precedent for a typed refusal in a minor: v31.1.0, v12.5.0, v11.5.0).
**Predecessor:** `FSD/ROOM_ROSTER_PLANES.md` (v48.0.0, #860).

## 1. The two defects

### 1.1 #907 — admission reads the record, not the roster
v48 made the widening plane the only way a room grows, and routed every read-time gate it listed through the one fold. The caller-admission path was not on the list:

- `list_communities_for_member_active` takes candidates from `list_communities_for_member` — containment in the RECORD's `members` on all three backends — and drops a room if ANY revocation naming the member is effective. No widening is a candidate; no later event can undo a removal.
- `active_community_key_ids_for` (the write-scope reader behind `build_caller_admission`) folds correctly but starts from the same record-only candidates.
- `groups_of(Community | Affiliations, …)` rides the first.

So a widened member is refused by every §4.3 gate while the wrap set holds the room key for them, and a removed-then-re-added member is refused forever.

### 1.2 #908 — a roster row needs only a valid signature
`verify_community_membership_widening_admission` and `…_revocation_admission` verify the hybrid signature under `authority_key_id` and stop. `SignerBinding::OwnerOf` on the policy row is referenced nowhere outside the policy table: a label, not a gate. Any registered key can widen itself into any room (and the minter wraps the room key to it at the next seal) or remove any member (and rotate the epoch). **v48.0.0's `WIRE_VOCABULARY_KINDS.md` claimed the widening door checks the room's authority set. It did not; that sentence was false when shipped and is corrected here.**

## 2. Standing

A signer `s` has **standing** for a roster event at instant `t` in room `C` iff, against the room's authorized roster immediately before the event (§3):

1. `s` is the room's **record signer** (the `authority_key_id` stored with `C`'s row — the key that founded it) and `s` is not currently removed from `C`; or
2. `s` is an active member of `C` whose role is `founder`; or
3. `C.consensus_protocol` is not `founder_only` and `s` is an active member of `C` (the existing `community_authority_set_for` rule: the whole roster governs an open room); or
4. `s` is a **named moderator** of `C` for duty `moderate` — reached by a live `moderate`-scoped `delegates_to` chain from a steward-bound root in rules 1–2; or
5. the event is a **revocation** and `s` is the removed member (leaving a room needs no one's permission).

Rules 1–3 and 5 are evaluated **at `t`** by the replay. Rule 4 is **read-time state**: the delegation walk evaluates liveness now (it has no instant parameter). Consequence, stated because it is a product decision: retracting a moderator's delegation withdraws the roster changes that moderator signed, until a signer with standing re-signs them. Founders and the record signer are unaffected.

A stored row whose signer was never recorded (a revocation admitted before V110 stored `authority_key_id`) **counts**: it was admitted under the rules of its day, and dropping it would readmit a removed member.

## 3. One authorized fold

`authorized_roster_at(record, signers, founder_only, moderators, widenings, revocations, as_of)` replaces the unsigned `active_roster_at` at every directory read (`active_community_members`, the DEK wrap set, the key-grant walk, the local door). It replays events in the v48 order — record members first (counted from the record, never their `joined_at`), then dated events by `effective_at`, removal last at a tie, then member key for a total order — and **applies an event only if its signer has standing (§2) in the state built so far**. An unauthorized event is inert: stored, served, and never counted.

This is what makes the rule convergent. A door alone cannot be: node A admits bob's widening of carol before bob's own removal arrives; node B saw the removal first and refuses it. The fold on both nodes replays the same authorized history and agrees. `active_roster_at` stays exported and unchanged (the pure, unsigned fold; its doc now says so).

New directory read, one per room: `community_roster_signers(community_key_id) -> CommunityRosterSigners { record_authority_key_id, widening_signers, revocation_signers }` (each signer keyed by `(member_key_id, effective_at)`). Implemented on sqlite, postgres and memory; classified in the connection model and parity; delegated by the directory double. Its trait default returns `Unsupported`, so an out-of-tree implementor keeps compiling and every fold over it fails secure. The FFI capsule proxy keeps the default, exactly like its per-room siblings (`list_community_membership_revocations_for` / `…_widenings_for` are `Unsupported` there already): a capsule consumer folds from the signed since-reads, which carry every signer, and must apply §2 in its own fold. No capsule wire change; `DIRECTORY_ABI_VERSION` stays 5.

## 4. The doors

`put_community_membership_widening` and `put_community_membership_revocation` (sqlite, postgres, memory) evaluate §2 after the signature and before any write — before a revocation rotates the epoch — against the authorized roster at the row's `effective_at`. `add_community_member` inherits it through the widening door. A refusal is the new typed `Error::RosterAuthorityUnauthorized { community_key_id, offered_authority_key_id, rule }` (kind `federation_roster_authority_unauthorized`; Python raises the same type `LocationAuthorityUnauthorized` does). Rule tokens:

- `roster_authority_not_established` — **retryable**: the signer has no event in the room at all. Rows arrive out of order; the event that gives the signer standing may not be here yet. Persist has no deferral queue (the #734 property), so the caller re-submits.
- `roster_authority_removed` — **substantive**: the signer's latest event at `t` is a removal.
- `roster_authority_insufficient` — **substantive**: the signer is an active member, but the room is `founder_only` and the signer is neither a founder nor a named moderator.

The fold (§3) re-checks everything the door checked, so a row a door admitted on incomplete state is still judged by the full history.

## 5. #907 — admission reads the fold

- `list_communities_for_member` (all backends) returns rooms the member appears in on the record **or in a widening**: containment in the room's history, still raw (a removed member is still listed). Its doc says so.
- `list_communities_for_member_active` and `active_community_key_ids_for` keep a candidate iff `is_active_community_member(…)` by the authorized fold. The hand-rolled "any revocation wins" spelling is deleted.
- Families have no widening plane and a two-part revocation key, so a removed family member cannot be re-added at all; `list_families_for_member_active` is unchanged and the gap is recorded on #907.

## 6. Invariants

- **I170 — admission is the roster.** On memory, sqlite, postgres: a member widened by the founder is admitted (`build_caller_admission` names the room; `groups_of(Community)` and `list_communities_for_member_active` list it); removed, refused; re-added after the removal, admitted again. The control: before the widening, not admitted.
- **I171 — a stranger cannot move the roster.** A registered key with no event in the room signs a widening of itself: refused `roster_authority_not_established`, no row, fold unchanged. A removed member signs a widening: `roster_authority_removed`. In a `founder_only` room a plain member signs a widening: `roster_authority_insufficient`. A stranger's revocation of a member: refused, and the epoch does NOT rotate. Admitted: the record signer, a founder, a named moderator, a plain member in an open room, and a member revoking itself.
- **I172 — the fold judges the history, not the arrival.** An open room; bob (a plain member) widens carol at `t2`; bob was removed at `t1 < t2`. Node A receives the widening before the removal (door admits — bob had standing in A's state); node B receives the removal first (door refuses `roster_authority_removed`). After both arrive, A's fold and B's fold agree: carol is out.
- **I173 — a legacy revocation still counts.** A revocation stored with no recorded signer (the pre-V110 shape, written below the door) removes its member.

Mutants planned: the door's standing check skipped (I171); the revocation door checking only the widening (I171 epoch arm); the fold ignoring standing (I172); the fold ignoring the record signer / founders / moderators / self-leave, one at a time (I171 admitted legs through the fold); legacy `None` signers dropped (I173); `list_communities_for_member` without widenings (I170); `_active` back to "any revocation wins" (I170 re-add leg).

## 7. Not in scope
- A quorum `membership_policy` for roster changes (#908 mentions one; no such policy field exists on `Community`, and inventing one is a grammar change).
- A family widening plane (§5).
- An instant-aware delegation walk (§2 rule 4).
