# FSD — a room's roster converges both ways (CIRISPersist#860)

**Release:** v48.0.0 (MAJOR: the community-revocation PK and its since-cursor resume id gain `effective_at`; `add_community_member`'s signed preimage becomes the widening row, not the grown record; a 17th replication kind; V151 re-points two shipped FKs).
**Ask (CIRISEdge, from #608/#613, verified on v44.6.0):** two findings with one root — *the community record is not a principal*, so the doors that mutate a roster after creation either cannot write (the revocation FK) or cannot replicate (a grown record is a fork at every peer). Every pair room edge has ever made is in this state; it shows now because a pair never widens or revokes. CIRISServer#594's revoke/invite routes are blocked on both.

## 1. What is true today

- `federation_community_membership_revocations.community_key_id REFERENCES federation_keys(key_id)` (V067, both backends; V141 rebuilt sqlite's shape unchanged). `federation_communities.community_key_id` is a bare `TEXT PRIMARY KEY`; `put_community` never requires a key; `identity_type::ALL` has no `community`. A room is admitted, replicated, sealed under — and its first revocation fails the FK. persist's own fixtures register the room id as a `user` key first (I63 and siblings), which is why it never surfaced. **The family twin has the same FK** (`family_key_id REFERENCES federation_keys`), and a family is keyless by doctrine (`reference_constitutional_family_is_keyless`): the accord's own family could not revoke a holder through this door either.
- Widening: `add_community_member(community_key_id, member, spec)` grows the roster **in place** — `UPDATE federation_communities SET members, persist_row_hash, authority_key_id, scrub_*` — and the `version` column never moves; `Community` carries no version on the wire. The grown record is served by `list_signed_communities_since` as the same id with a new hash; every peer's `put_community` is INSERT-or-`Conflict`, and edge classifies that `Conflict` as `CommunityRosterFork`. `supersede_community` (Cut G2 versions + `federation_group_versions`) exists but neither the local grow nor the replication path uses it, and the wire record could not say which version it is.
- Removal converges because it is an **append plane**: a signed row per event, served by a pair-cursor since-read, admitted by signature + the E4 `RegisteredSigner`/`OwnerOf` policy, folded at read time by `active_community_members` (`removed_key_ids_at(effective_at ≤ now)`) — and, per #848 §15, an admitted removal rotates the DEK epoch in the same transaction. The revocation PK is `(community_key_id, removed_identity_key_id)`; #861 made a repeat a no-op on it.
- Nine production readers take the raw `community.members` (`location.rs:162`, `key_grant.rs:945/957`, `admission.rs:11858/11962/12425/12479`, `community_dek.rs:348`, `mod.rs:4444`); today revocations already do not reach some of them — after this cut a raw read is a wrong read.

## 2. The rule

**A room's roster is the fold of its record plus two append planes — widenings and revocations — ordered by effective instant; every door admits every well-formed signed row regardless of arrival order, and the fold decides.** A room is a keyless identifier, like a family: the planes reference the group table, never `federation_keys`.

## 3. The structure

### 3.1 V151 — the group planes reference the group (finding 1)
Both membership-revocation tables re-point their group FK: `family_key_id → federation_families(family_key_id)`, `community_key_id → federation_communities(community_key_id)`. sqlite: table rebuild (no self-FK — the `_new`+`RENAME` shape is safe here); postgres: `DROP CONSTRAINT`/`ADD CONSTRAINT`. The community table's PK becomes `(community_key_id, removed_identity_key_id, effective_at)` (§3.3); the family PK is unchanged (families have no widening plane in this cut; `supersede_family` is their grow). The migration-checksum manifest pins V151's bytes.

### 3.2 The widening plane (finding 2)
```
federation_community_membership_widenings (
  community_key_id   REFERENCES federation_communities,
  member_key_id      REFERENCES federation_keys,
  joined_at, effective_at, role (nullable),
  persist_row_hash, authority_key_id, scrub_signature_classical, scrub_signature_pqc, admitted_at,
  PRIMARY KEY (community_key_id, member_key_id, effective_at))
```
`types::CommunityMembershipWidening { community_key_id, member_key_id, joined_at, effective_at, role, persist_row_hash }` with `signing_envelope()` (the record minus `persist_row_hash` — the revocation's discipline), `SignedCommunityMembershipWidening { widening, authority_key_id, scrub_* }`, `ServedCommunityMembershipWidening { widening, admitted_at }`. Admission = `verify_community_membership_widening_admission` (the exact mirror of the revocation's: the hybrid signature under `authority_key_id` over the canonical envelope) + the room must exist (the FK says so; memory mirrors it) + the member must be a registered, steward-bound key (`check_community_membership_steward_binding` applied to the one member, as `put_community` applies it to the roster) + `reject_future_dated` as the revocation does. **A widening does not rotate the DEK epoch**: the member is wrapped into the current epoch by the minter at its next seal — the wrap set is the fold (§3.4). Retroactive access to earlier epochs is a product decision the minter makes by re-wrapping; persist does not grant it.

Doors: `FederationDirectory::put_community_membership_widening`, `list_community_membership_widenings_for`, `list_signed_community_membership_widenings_since(since, limit)` (pair-cursor; resume id = compound of the PK, as the revocation's), on sqlite / postgres / memory; `Unsupported` across the FFI capsule; classified in the connection model, parity `CALL_CLASSES`, the directory double. `EnvelopeKind::CommunityMembershipWidening` — the 17th kind — with the E4 policy `(RegisteredSigner, OwnerOf, NotApplicable)`, and the namespace manifest.

`add_community_member(community_key_id, member, spec)` **keeps its name and becomes the local door onto the plane**: it builds `CommunityMembershipWidening { member.key_id, member.joined_at, effective_at: member.joined_at, member.role }`, verifies `spec` over the **widening's** envelope, inserts, and returns `Ok(true)` (or `Ok(false)` on the byte-identical row). The record is not touched. An edge-built `AdmitSpec` signed over the grown record no longer verifies — that is the break, and the reason this is v48.

### 3.3 The revocation PK gains `effective_at`
Because a member can be re-added, a member can be removed twice. `(community_key_id, removed_identity_key_id, effective_at)`: an exact retry is still `ON CONFLICT DO NOTHING` (the #861 rule — one rotation per removal); a removal at another instant is another event, admitted, and rotates (a re-removal after a re-add is a real removal). The since-read's resume id becomes the three-part compound. Order-independence: the door never consults the fold to decide admission (a replica that receives revocation₂ before widening₂ must still store it).

### 3.4 One fold
`active_community_members(community_key_id)` = for each key id that appears in the record's `members`, a widening, or a revocation: take the latest event with `effective_at ≤ now` among {record membership at `joined_at`, widenings at `effective_at`, revocations at `effective_at`}; the member is active iff that event is an add. Ties at the same instant: a revocation wins over a widening (removal is the safer read). The nine raw readers (§1) go through the fold — `is_active_community_member(directory, community_key_id, key_id)` for the single-member gates (`key_grant`, `admission` ×4, `location`) and the fold for the wrap set (`community_dek.rs:348`) and the projection (`mod.rs:4444`). Memory's `add_community_member` and `supersede`-time roster checks likewise.

### 3.5 Not changed
`put_community` stays INSERT-or-`Conflict`: a record with the same id and different content IS a fork; growth rides the plane. `supersede_community` stays the operator door for renames/protocol changes. Family rosters keep their current doors.

## 4. Invariants (RED first; sqlite + postgres + memory through one `&dyn FederationDirectory`; two directories where convergence is claimed)

- **I163 — a keyless room can revoke.** `put_community` a room whose id is registered as no key; `put_community_membership_revocation` admits (today: FK failure on sqlite/postgres). The family twin: `seed_test_family` with an unregistered family id; `put_family_membership_revocation` admits. The fold drops the member; the DEK epoch advanced exactly once.
- **I164 — a widening converges.** Node A: room `{alice, bob}` founded by alice; alice widens `carol` through `add_community_member` (spec over the widening envelope). Node B holds the original record (replicated). The widening row served by A's `list_signed_community_membership_widenings_since` is applied on B through `put_community_membership_widening`: admitted, no `Conflict`, B's fold = `{alice, bob, carol}` = A's; the community RECORD on both nodes is byte-identical to the original (no fork, no version move). A spec signed over the grown record (edge's current shape) is refused with the signature reason.
- **I165 — order does not matter.** The events `widen carol (t1)`, `revoke carol (t2)`, `widen carol (t3)`, `revoke carol (t4)` applied on three directories in three different orders (chronological, reversed, revocations-first) yield the same fold at `now = t4+ε` (carol absent) and at `now = t3+ε` (carol present); every row admitted on every directory; the repeat of `revoke (t2)` is a no-op with no second rotation, while `revoke (t4)` rotates — epoch advanced exactly twice across the sequence.
- **I166 — a raw roster read is a wrong read.** After a widening, `location`/`key_grant`/the four `admission` gates/the DEK wrap set/the projection see `carol` (through the fold); after her revocation they do not; a mutant that reads `community.members` in any of them is caught by the widened-then-revoked member.
- **I167 — the since-read resumes across the three-part id.** Two revocations of the same member at different instants are served as two rows and a cursor placed between them resumes at the second.

Mutants planned: the FK re-point reverted (I163); `add_community_member` back to mutating the record (I164: fork on B); the fold ignoring widenings / ignoring the later revocation / tie broken toward the widening (I165); each raw reader left raw (I166 ×9); the repeat-revocation no-op dropped (I165: three rotations); the resume id without `effective_at` (I167).

## 5. Verification
(§5.1 mutation table recorded at build time.)

## 6. Not in scope
- A `community` identity type (a room is not a person, and not a key — the FK re-point is the answer edge preferred).
- A widening plane for families (their grow is `supersede_family` under the family quorum).
- Retroactive epoch grants to a re-added member (the minter's re-wrap decision).
- Edge's `widen_community` and Server's #594 routes; CIRISEdge's `a_room_that_is_not_a_registered_key_cannot_revoke_yet` goes red on adoption — that is their signal.
