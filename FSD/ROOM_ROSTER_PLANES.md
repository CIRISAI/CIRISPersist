# FSD — a room's roster converges both ways (CIRISPersist#860)

**Surface:** the group planes reference the group table (V151); the community widening plane, `EnvelopeKind::CommunityMembershipWidening` (the 17th replication kind); the revocation key includes `effective_at`; one roster fold. Standing for a roster change — who may sign it — is `FSD/ROOM_ROSTER_AUTHORITY.md`.
**Origin:** CIRISEdge (#608/#613): *the community record is not a principal*, so a door that mutates a roster after creation must neither require a key for the room nor rewrite the record.

## 1. Background

- A room is a keyless identifier. `federation_communities.community_key_id` is a bare `TEXT PRIMARY KEY`; `put_community` never requires a key; `identity_type::ALL` has no `community`. A family is keyless too (a constitutional family has no key). So a plane that references `federation_keys(key_id)` for the group would make the first revocation of a keyless room or family fail its FK.
- A grown record is a fork. `put_community` is INSERT-or-`Conflict` at every peer, and edge classifies that `Conflict` as `CommunityRosterFork`. Growth that rewrote the record in place would never replicate. So growth rides an append plane.
- Removal converges because it is an **append plane**: a signed row per event, served by a pair-cursor since-read, admitted by signature and standing, folded at read time — and, per #848 §15, an admitted removal rotates the DEK epoch in the same transaction. #861 makes an exact repeat a no-op.
- Production readers that took the raw `community.members` (`location.rs`, `key_grant.rs`, four `admission.rs` gates, `community_dek.rs`'s wrap set, the `mod.rs` projection) read the fold instead (§3.4); a raw read is a wrong read.

## 2. The rule

**A room's roster is the fold of its record plus two append planes — widenings and revocations — ordered by effective instant; every door admits every well-formed signed row regardless of arrival order, and the fold decides.** A room is a keyless identifier, like a family: the planes reference the group table, never `federation_keys`.

## 3. The structure

### 3.1 V151 — the group planes reference the group
Both membership-revocation tables re-point their group FK: `family_key_id → federation_families(family_key_id)`, `community_key_id → federation_communities(community_key_id)`. sqlite: table rebuild (no self-FK — the `_new`+`RENAME` shape is safe here); postgres: `DROP CONSTRAINT`/`ADD CONSTRAINT`. The community table's PK is `(community_key_id, removed_identity_key_id, effective_at)` (§3.3). Families have the same widening plane and three-part key (V154, `FSD/ROOM_ROSTER_AUTHORITY.md` §10). The migration-checksum manifest pins V151's bytes.

### 3.2 The widening plane
```
federation_community_membership_widenings (
  community_key_id   REFERENCES federation_communities,
  member_key_id      REFERENCES federation_keys,
  joined_at, effective_at, role (nullable),
  persist_row_hash, authority_key_id, scrub_signature_classical, scrub_signature_pqc, admitted_at,
  PRIMARY KEY (community_key_id, member_key_id, effective_at))
```
`types::CommunityMembershipWidening { community_key_id, member_key_id, joined_at, effective_at, role, persist_row_hash }` with `signing_envelope()` (the record minus `persist_row_hash` — the revocation's discipline), `SignedCommunityMembershipWidening { widening, authority_key_id, scrub_* }`, `ServedCommunityMembershipWidening { widening, admitted_at }`. Admission = `verify_community_membership_widening_admission` (the exact mirror of the revocation's: the hybrid signature under `authority_key_id` over the canonical envelope) + the room must exist (the FK says so) + the member must be a registered, steward-bound key (`check_community_membership_steward_binding` applied to the one member, as `put_community` applies it to the roster) + `reject_future_dated` as the revocation does + the signer set's standing under the room's `consensus_protocol` (`FSD/ROOM_ROSTER_AUTHORITY.md` §2–§4). **A widening does not rotate the DEK epoch**: the member is wrapped into the current epoch by the minter at its next seal — the wrap set is the fold (§3.4). Retroactive access to earlier epochs is a product decision the minter makes by re-wrapping; persist does not grant it.

Doors: `FederationDirectory::put_community_membership_widening`, `list_community_membership_widenings_for`, `list_signed_community_membership_widenings_since(since, limit)` (pair-cursor; resume id = compound of the PK, as the revocation's), on sqlite / postgres; `Unsupported` across the FFI capsule; classified in the connection model, parity `CALL_CLASSES`, the directory double. `EnvelopeKind::CommunityMembershipWidening` — the 17th kind — with the E4 policy `(RegisteredSigner, OwnerOf, NotApplicable)`, and the namespace manifest.

`add_community_member(community_key_id, member, spec)` **is the local door onto the plane**: it builds `CommunityMembershipWidening { member.key_id, member.joined_at, effective_at: member.joined_at, member.role }`, verifies `spec` over the **widening's** envelope, inserts, and returns `Ok(true)` — or `Ok(false)` with nothing written when the member is already active at `effective_at` by the fold (a re-add with a fresh `joined_at` is not a second event; the fold is identical with or without the row) or on the byte-identical row. The local door may consult the fold — it is the node's own authority; the replicated door never does. The record is not touched. An `AdmitSpec` signed over a grown record does not verify.

### 3.3 The revocation PK includes `effective_at`
Because a member can be re-added, a member can be removed twice. `(community_key_id, removed_identity_key_id, effective_at)`: an exact retry is `ON CONFLICT DO NOTHING` (the #861 rule — one rotation per removal); a removal at another instant is another event, admitted, and rotates (a re-removal after a re-add is a real removal). The since-read's resume id is the three-part compound. Order-independence: the door never consults the fold to decide admission (a replica that receives revocation₂ before widening₂ must still store it).

### 3.4 One fold
`active_community_members(community_key_id)` = for each key id that appears in the record's `members`, a widening, or a revocation: take the latest event with `effective_at ≤ now` among {record membership — counted FROM THE RECORD, before every dated event, never from its signer-chosen `joined_at` (a peer that seeds the room from a skewed clock must not refuse a legitimate earlier mint; I77 pins this), widenings at `effective_at`, revocations at `effective_at`}; the member is active iff that event is an add. Ties at the same instant: a revocation wins over a widening (removal is the safer read). The readers (§1) go through the fold — `is_active_community_member(directory, community_key_id, key_id)` for the single-member gates (`key_grant`, `admission` ×4, `location`) and the fold for the wrap set (`community_dek.rs`) and the projection (`mod.rs`). `FSD/ROOM_ROSTER_AUTHORITY.md` §3 adds standing: an event is applied only if its signer set meets the protocol in the state built so far.

### 3.5 What stays on the record
`put_community` is INSERT-or-`Conflict`: a record with the same id and different content is a fork unless it carries a quorum-verified amendment proof (`FSD/ROOM_ROSTER_AUTHORITY.md` §10 item 5); growth rides the plane. `supersede_community` is the door for renames and protocol changes.

## 4. Invariants (sqlite + postgres through one `&dyn FederationDirectory`; two directories where convergence is claimed)

- **I163 — a keyless room can revoke.** `put_community` a room whose id is registered as no key; `put_community_membership_revocation` admits. The family twin: `seed_test_family` with an unregistered family id; `put_family_membership_revocation` admits. The fold drops the member; the DEK epoch advanced exactly once.
- **I164 — a widening converges.** Node A: room `{alice, bob}` founded by alice; alice widens `carol` through `add_community_member` (spec over the widening envelope). Node B holds the original record (replicated). The widening row served by A's `list_signed_community_membership_widenings_since` is applied on B through `put_community_membership_widening`: admitted, no `Conflict`, B's fold = `{alice, bob, carol}` = A's; the community RECORD on both nodes is byte-identical to the original (no fork, no version move). A spec signed over the grown record is refused with the signature reason.
- **I165 — order does not matter.** The events `widen carol (t1)`, `revoke carol (t2)`, `widen carol (t3)`, `revoke carol (t4)` applied on three directories in three different orders (chronological, reversed, revocations-first) yield the same fold at `now = t4+ε` (carol absent) and at `now = t3+ε` (carol present); every row admitted on every directory; the repeat of `revoke (t2)` is a no-op with no second rotation, while `revoke (t4)` rotates — epoch advanced exactly twice across the sequence.
- **I166 — a raw roster read is a wrong read.** After a widening, `location`/`key_grant`/the four `admission` gates/the DEK wrap set/the projection see `carol` (through the fold); after her revocation they do not; a mutant that reads `community.members` in any of them is caught by the widened-then-revoked member.
- **I167 — the since-read resumes across the three-part id.** Two revocations of the same member at different instants are served as two rows and a cursor placed between them resumes at the second.

Mutants: the FK re-point reverted (I163); `add_community_member` back to mutating the record (I164: fork on B); the fold ignoring widenings / ignoring the later revocation / tie broken toward the widening (I165); each raw reader left raw (I166 ×9); the repeat-revocation no-op dropped (I165: three rotations); the resume id without `effective_at` (I167).

## 5. Verification

### 5.1 Mutation table (lane = I163–I169 + the #861 repeat witness, sqlite + postgres; each mutant reverted before the next)

| # | Mutant | Verdict | Killed by |
|---|--------|---------|-----------|
| M1 | fold ignores widenings | KILLED | postgres_dyn::i164 postgres_dyn::i165 postgres_dyn::i166 sqlite_dyn::i164 sqlite_dyn::i165 sqlite_dyn::i166 |
| M2 | fold tie: the widening wins | KILLED | postgres_dyn::i165 sqlite_dyn::i165 |
| M3 | fold ignores as_of | KILLED | postgres_dyn::i165 sqlite_dyn::i165 |
| M4 | add_community_member reports every put as new | KILLED | postgres_dyn::i164 sqlite_dyn::i164 |
| M6 | effective_roster reads the record raw | KILLED | postgres_dyn::i166 sqlite_dyn::i166 |
| M7 | the predicate drops the steward arm | KILLED | postgres::i169 run::i168_the_sweep_promotes_an_owned_agents_rows sqlite::i169 |
| M8 | the loader drops the by-for union | KILLED | postgres::i169 run::i168_the_sweep_promotes_an_owned_agents_rows sqlite::i169 |
| M9 | the predicate ignores for_key_id | KILLED | postgres::i169 sqlite::i169 |
| M12 | the widening admission gate is bypassed | KILLED | postgres_dyn::i164 sqlite_dyn::i164 |
| M13 | the crossing accepts any grant as covering the sender | KILLED | postgres::i169 sqlite::i169 |
| M14 | revocation materialize ignores the instant | KILLED | postgres_dyn::i167 sqlite_dyn::i167 |
| M15 | widening materialize returns nothing | KILLED | postgres_dyn::i167 sqlite_dyn::i167 |

M11 is the FK migration itself, not a code mutant; I163 covers it. M9 (the predicate ignoring `for_key_id`) is killed only because I169 asks the read and the predicate directly and drives the crossing's negative arm: on the loader path the read filters by machine and the predicate checks the same field, so each would hide the other.

## 6. Not in scope
- A `community` identity type (a room is not a person, and not a key; the planes reference the group table).
- Retroactive epoch grants to a re-added member (the minter's re-wrap decision).
- Edge's `widen_community` and Server's #594 routes.
