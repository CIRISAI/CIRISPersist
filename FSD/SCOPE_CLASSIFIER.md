# FSD — one scope classifier (CIRISPersist#897, #796, #797)

**Release:** v47.0.0 (MAJOR: `Audience::Affiliations` gains its room; `ScopeRefusalReason` gains an arm).
**Rulings:** edge on #897 (room-gated, grounded in CC 4.4.3.2.1 / 4.4.3.2.8); operator: v47.0.0 carries #796 and #797.

## 1. The class

#893 and #897 are the same defect from opposite directions: **for one `cohort_scope`, persist's gates asked different questions.** #893 failed closed (a room could not read its own rows) and was reported within a day. #897 fails open (any caller, unauthenticated included, reads `affiliations`), which nothing reports.

The cause is structural. `cohort_scope` is a closed vocabulary held as `&str` constants, so every gate re-spells its own classification with `==`, `matches!` or a `_` arm. The compiler cannot see the spellings, and nothing compares them. The census at `4abe256d`:

| site | `affiliations` | question asked |
|---|---|---|
| `types::cohort_scope::crypto_tier` | CommunityDek | room |
| `at_rest_cascade::resolve_write_tier` | refuses without `community_key_id` | room |
| `replication/hold.rs` (×4) | room | room |
| `namespace::projection_for` | `Projection::Cohort` | room |
| `blobs.rs` content tier | encrypted | room |
| **AV-45** `check_write_cohort_scope` (`admission.rs:1453`) | `Ok(())`, any writer | **broad** |
| **AV-45** `check_write_cohort_scope_for::needs_admission` (`mod.rs:4655`) | no admission read | **broad** |
| **AV-45** trace ingest (`ingest.rs:780`) | no admission read | **broad** |
| **AV-84** `check_cohort_standing_resolved` (`admission.rs:2220`) | skipped | **broad** |
| **AV-84** `check_promotion_cohort_standing` (`admission.rs:2353`) | skipped | **broad** |
| `check_targeted_cohort_requires_federation_tier` (`admission.rs:12033`) | skipped | **broad** |
| §4.3 read gate (`scope/sql.rs` `BROAD_TIERS`, `scope/caller.rs` `BROAD`) | anyone | **broad** |
| `crossing::Audience::Affiliations` | unit variant, no room | **broad** |

Edge's table named four of the eight broad spellings. The other four came out of the inventory. Sorting the table this way makes the pattern plain: every site that decides at-rest *storage* says "room", and every site that decides *admission* says "broad". The storage tier refuses to store a room-less `affiliations` row, and AV-45 admits one.

**#796** is the same class inside one function. `crypto_tier` ends in `_ => Plaintext`, so a scope added to the closed set without an arm is stored in plaintext. The conformance gate that claims to catch this (`check_cohort_scope_processor_is_total`) asserts only that `crypto_tier` does not panic. With a `_` arm it cannot panic for any input, so the gate cannot fail.

## 2. The rule

CC 4.4.3.2.1 puts `affiliations` in the **Community** tier: encrypted under the community DEK and readable by community members. CC 4.4.3.2.8: an affiliation "shares the CommunityDek crypto tier and all the community machinery", and its `compartments[]` are "membership ⊆ roster". A public affiliation record is **promoted to a commons row** (`disclosure_posture: transparency-seeking`). It is never read through the `affiliations` scope.

For every gate, therefore, `affiliations` is answered exactly as `community` is: *is the caller or writer in the room this row names?* The roster is the community record's roster (`community_key_ids`).

## 3. The structure: classify once

```rust
pub mod cohort_scope {
    /// The closed vocabulary as a type. `ALL`, `is_valid`, and every
    /// classifier derive from it.
    pub enum Scope { SelfOnly, Family, Community, Affiliations, Species, Biosphere, Federation }

    /// What a placement at this scope claims. ONE exhaustive match; every
    /// gate reads this and none re-spells it.
    pub enum Placement {
        /// The caller's self-collective (v46.3.1).
        SelfCollective,
        /// One named cohort: the row names its target, the writer must be in
        /// it, a reader must be in it.
        Targeted(TargetPlane),
        /// No roster: anyone.
        Commons,
    }
    pub enum TargetPlane { Family, Room }   // Room = the community roster

    impl Scope {
        pub fn parse(s: &str) -> Option<Scope>;
        pub fn as_str(self) -> &'static str;
        pub fn placement(self) -> Placement;          // exhaustive, no `_`
        pub fn crypto_tier(self, subkind: Option<&str>) -> CryptoTier; // exhaustive, no `_`
    }
}
```

Every site in §1's table switches from `==`/`matches!` on strings to `Scope::parse(..)?.placement()`. An unknown string is a **distinct, named** outcome at each site. It is never a `_` that happens to mean "commons".

- **`crypto_tier(&str, ..)`** keeps its signature for its callers and delegates. An unparseable scope stays `Plaintext` on an **explicit** `None` arm, documented as "a corrupt column, not a scope" (#796's "if a runtime wildcard is still wanted, make it a distinct arm that says so").
- **AV-45** (`check_write_cohort_scope`): `Targeted(Family)` → `family_key_ids`; `Targeted(Room)` → `community_key_ids`; `Commons` → `Ok`; `SelfCollective` → `Ok`. The three enforcement sites share one `needs_admission = placement is Targeted`.
- **AV-84** and the federation-tier floor: `is_targeted()`.
- **Read gate:** `BROAD_TIERS` becomes `Scope::ALL.filter(Commons)`. The targeted arms iterate `Targeted(Room)` scopes, so `affiliations` joins `community` on V150's `cohort_target`. The SQL twin renders `cohort_scope IN ('community','affiliations') AND cohort_target = ANY($n)`.
- **`Audience::Affiliations { community_key_id }`**: `from_cohort_scope` refuses a room-less `affiliations` with the same `need(..)` as `community`; `cohort_target` and `cohort_target_member` (`"community_key_id"`) follow.

The hold path, `namespace`, `at_rest_cascade` and `blobs.rs` already answer "room" and are moved onto the classifier in the same cut, so there is one spelling left, not two.

## 4. #797: a membership the resolver cannot answer yet

`check_write_cohort_scope_for` resolves membership for the ONE claimed target. `contains_or_absent` maps "that cohort's roster is unknown here" (`Err(InvalidArgument)`) to `Ok(false)`, which refuses as `NoCommunityMembership` / `NoFamilyMembership`, exactly as a genuine non-member is refused. The code comment already calls this "the transient-correct answer for a row arriving ahead of its roster (CIRISEdge#522)". The refusal is correct; its *name* is wrong, and callers log and act on the name. The consent sweep counts both outcomes as `skipped`.

New arm: **`ScopeRefusalReason::MembershipUnresolved { plane }`**, kind `scope_membership_unresolved`. It is produced only where the roster for the claimed target **does not exist in this directory**. Both still refuse the write (fail-secure is unchanged); the caller learns which one it got.

- Terminal (`NoFamilyMembership` / `NoCommunityMembership`): the roster exists and the writer's principal is not an active member.
- Transient (`MembershipUnresolved`): no roster for that target, so nothing can yet answer.

Backend errors still propagate as errors. They are not refusals.

`sweep_widen` gains a report counter, `awaiting_roster`, beside `awaiting_actor`, so the background walk stops logging "not a member" for a room it has not received yet.

## 5. Invariants

- **I145 — one row, every gate** (edge's witness, sqlite + postgres + memory). One `affiliations` row placed in affiliation A. Callers: a member of A; a member of only B, where B is shared with the producer (the #893 trap); unauthenticated. Asked of **write** (AV-45 via the put door), **widen** (`Audience::from_cohort_scope` + `describe`), **hold** (the send set), and **read** (`list_scores` then `list_attestations`). The four admitted sets are asserted **equal to each other** and to `{A's member}`. A gate that drifts goes red against its siblings, not only against a constant.
- **I146 — the classifier is total and pinned.** Every `Scope` maps to an **expected** `(Placement, CryptoTier)` in a literal table, and the table's length equals `Scope::ALL`. This replaces the does-not-panic loop in `check_cohort_scope_processor_is_total`.
- **I147 — unresolved is not "not a member".** A write naming a room this directory has never seen refuses with `MembershipUnresolved`; the same write after the roster lands, by a non-member, refuses `NoCommunityMembership`; by a member, lands.
- The #893 legs (I144), the #888 self legs, and the V141 rebuild witness stay green.

**Mutants planned:** `affiliations` back to `Commons` in `placement()` (I145 red at every gate at once, which is the point); one gate reverting to a local `FAMILY || COMMUNITY` spelling (I145 red on that gate alone, with the answer-sets unequal); `crypto_tier` regaining a `_` arm (I146 red: a new variant no longer fails the build; see §6); `MembershipUnresolved` collapsed into `NoCommunityMembership` (I147 red); the room-less `affiliations` audience admitted (I145 widen leg red).

## 6. Measuring the build-error claim

"Adding a scope is a build error" is a claim about the compiler, and a mutant that fails to compile is the *pass* condition. The round adds an eighth `Scope` variant with no arms and records **DID-NOT-COMPILE** as the expected verdict. Any other verdict means an arm somewhere still has a `_`.

## 7. Migration and census

A stored `affiliations` row with no room becomes read-refused after this cut. That is correct: hold never sent it, and it was readable only through this bug. Census, run on a real node **before the v47.0.0 tag** (edge records it as a pre-tag gate in `FSD/CONTENT_TRANSFER.md` §4.1 on CIRISEdge#658):

```sql
SELECT count(*) FROM federation_attestations
 WHERE cohort_scope = 'affiliations' AND cohort_target IS NULL;
```

No production producer is known in edge, server or agent. No persist migration is needed: V150's partial index already covers `affiliations`.

## 8. Not in scope

- `Cohort` (`federation/cohort.rs`, the reverse-quorum group type): a separate four-value vocabulary with no gate role.
- The consent grammar. The audience vocabulary is unchanged, and the room already rides the grant's cohort-target alias (`sweep_widen` passes it), so `CONSENT_GRAMMAR_HASH` does not move.
- Edge's serve arm. That belongs to edge, which is closing it fail-closed in v30.1.0.
