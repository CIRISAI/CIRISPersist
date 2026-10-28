# FSD — one scope classifier (CIRISPersist#897, #796, #797)

**Status:** Implemented. `cohort_scope::Scope` in `src/federation/types.rs`; witnesses in `src/federation/scope_classifier_invariants.rs`. Grounded in CC 4.4.3.2.1 and CC 4.4.3.2.8.

## 1. The class

`cohort_scope` is a closed vocabulary. If each gate classifies it on its own — re-spelling the classification with `==`, `matches!` or a `_` arm over `&str` constants — the compiler cannot see the spellings and nothing compares them, so **for one `cohort_scope`, different gates ask different questions.** That fails in both directions: closed (#893: a room cannot read its own rows), and open (#897: any caller, unauthenticated included, reads `affiliations`). A fail-open gate is the dangerous one, because nothing reports it.

The split runs along one line. Every site that decides at-rest *storage* (`crypto_tier`, `at_rest_cascade::resolve_write_tier`, the replication hold path, `namespace::projection_for`, the `blobs.rs` content tier) treats `affiliations` as a room. A site that decides *admission* or *read* by its own spelling — the AV-45 write gates (`check_write_cohort_scope`, `check_write_cohort_scope_for`, trace ingest), the AV-84 standing checks, the federation-tier floor for targeted cohorts, the §4.3 read gate and `crossing::Audience::Affiliations` — can treat it as broad. Then the storage tier refuses to store a room-less `affiliations` row while the admission gate admits one.

**#796** is the same class inside one function: a classifier ending in `_ => Plaintext` stores any scope added to the closed set without an arm in plaintext. A conformance gate that only asserts "does not panic" cannot catch it, because with a `_` arm nothing can panic.

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
        /// The caller's self-collective.
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

Every gate named in §1 asks `Scope::parse(..)?.placement()` instead of comparing strings. An unknown string is a **distinct, named** outcome at each site. It is never a `_` that happens to mean "commons".

- **`crypto_tier(&str, ..)`** keeps its string signature for its callers and delegates. An unparseable scope stays `Plaintext` on an **explicit** `None` arm, documented as "a corrupt column, not a scope" (#796's "if a runtime wildcard is still wanted, make it a distinct arm that says so").
- **AV-45** (`check_write_cohort_scope`): `Targeted(Family)` → `family_key_ids`; `Targeted(Room)` → `community_key_ids`; `Commons` → `Ok`; `SelfCollective` → `Ok`. The three enforcement sites share one `needs_admission = placement is Targeted`.
- **AV-84** and the federation-tier floor: `is_targeted()`.
- **Read gate:** the broad set is `cohort_scope::commons()`, derived from the classifier. The SQL twin renders **one arm per roster**, `cohort_scope IN ('community','affiliations') AND cohort_target = ANY($n)`, so the reader's community set is bound once (the `scope_bind` parameter-count test pins the binding). A single-scope roster (`family`) renders `= 'family'`.
- **`Audience::Affiliations { community_key_id }`**: `from_cohort_scope` refuses a room-less `affiliations` with the same `need(..)` as `community`; `cohort_target` and `cohort_target_member` (`"community_key_id"`) follow.

The hold path, `at_rest_cascade` and `blobs.rs` read the same classifier, so there is one spelling. `namespace::projection_for` does **not**: it classifies a different axis (per-plane projection: `SelfOwn` / `Cohort` / `Global`), its tables already group `affiliations` with `community`, and its fallback arm fails *narrow* (`Cohort`), not open.

## 4. #797: a membership the resolver cannot answer yet

`check_write_cohort_scope_for` resolves membership for the ONE claimed target. A row can arrive ahead of its roster (CIRISEdge#522). Refusing it is correct, but refusing it under the same name as a genuine non-member is not: callers log and act on the name, and a terminal name for a transient condition stops a retry that would succeed.

So the refusal has its own arm: **`ScopeRefusalReason::MembershipUnresolved`**, kind `scope_membership_unresolved`. (A unit variant: the scope is already logged beside it, so carrying the plane would repeat it.) It is produced only where the roster for the claimed target **does not exist in this directory**. Both still refuse the write (fail-secure is unchanged); the caller learns which one it got.

- Terminal (`NoFamilyMembership` / `NoCommunityMembership`): the roster exists and the writer's principal is not an active member.
- Transient (`MembershipUnresolved`): no roster for that target, so nothing can yet answer.

Backend errors still propagate as errors. They are not refusals.

It is produced at both write doors. The attestation put door looks the roster up before resolving membership. The trace-ingest door looks it up **only on the refusal path**, so an admitted batch pays nothing. The reason reaches Python as `"<kind>: <reason>"` (the `rate_limited` shape); the exception type and the leading token are unchanged.

`sweep_widen` reports `awaiting_roster` beside `awaiting_actor`, so the background walk does not log "not a member" for a room it has not received yet.

## 5. Invariants

- **I145 — one row, every gate** (sqlite + postgres; the Rust read twin runs on in-memory sqlite). One `affiliations` row placed in affiliation A. Callers: a member of A; a member of only B, where B is shared with the producer (the #893 trap); unauthenticated. Asked of **write** (AV-45 via the put door), **widen** (`Audience::from_cohort_scope` + `describe`), **hold** (the send set), and **read** (`list_scores` then `list_attestations`). The four admitted sets are asserted **equal to each other** and to `{A's member}`. A gate that drifts goes red against its siblings, not only against a constant.
- **I146 — the classifier is total and pinned.** Every `Scope` maps to an **expected** `(Placement, CryptoTier)` in a literal table, and the table's length equals `Scope::ALL`. `check_cohort_scope_processor_is_total` asserts this table, not merely that classification does not panic.
- **I147 — unresolved is not "not a member".** A write naming a room this directory has never seen refuses with `MembershipUnresolved`; the same write after the roster lands, by a non-member, refuses `NoCommunityMembership`; by a member, lands.
- The #893 legs (I144), the #888 self legs, and the V141 rebuild witness stay green.

### 5.1 Mutation round: 11 / 11

Run under `scripts/pg_test_db.sh`. M9's pass condition is DID-NOT-COMPILE (§6).

| # | Mutant | Verdict |
|---|--------|---------|
| M1 | the classifier puts `affiliations` back in the Commons | KILLED: I145 + I147 (all backends), the conformance gate |
| M2 | the attestation put door re-spells "targeted" locally as `FAMILY \|\| COMMUNITY` | KILLED: I145, I147 (all backends) |
| M3 | the SQL twin's room arm drops `affiliations` | KILLED: I145 sqlite + postgres (the two read doors disagree) |
| M4 | the Rust twin reads `affiliations` as broad | KILLED: I145 (Rust read twin) |
| M5 | the put door's unresolved refusal collapses into `NoCommunityMembership` | KILLED: I147 (all backends), the sweep's `awaiting_roster` test |
| M6 | the trace door's unresolved refusal collapses | KILLED: `write_gate_unresolved_roster_is_retryable_797` |
| M7 | a room-less `affiliations` audience is admitted at the widen door | KILLED: I145 (all backends) |
| M8 | `crypto_tier` stores `affiliations` in plaintext | KILLED: the conformance gate (the #796 class, now catchable) |
| M9 | a new `Scope` variant with no classification | **DID-NOT-COMPILE** (the pass condition) |
| M10′ | the hold path sends `affiliations` to everyone | KILLED: I145 (all backends) |
| M11 | the Python message drops the reason | KILLED: `write_scope_refused_message_carries_the_reason_797` |

M10′ is written as valid Rust; a mutant that does not compile for an unrelated reason measures the mutant, not the witness.

## 6. Measuring the build-error claim

"Adding a scope is a build error" is a claim about the compiler, and a mutant that fails to compile is the *pass* condition. The round adds an eighth `Scope` variant with no arms and records **DID-NOT-COMPILE** as the expected verdict. Any other verdict means an arm somewhere still has a `_`.

## 7. Migration and census

**Limit:** a stored `affiliations` row with no room is read-refused. That is correct: hold never sends it, and a room-less `affiliations` row is not a valid placement. To find any such rows on a node:

```sql
SELECT count(*) FROM federation_attestations
 WHERE cohort_scope = 'affiliations' AND cohort_target IS NULL;
```

CIRISEdge records this census as a release gate in its `FSD/CONTENT_TRANSFER.md` §4.1 (CIRISEdge#658). No persist migration is needed: V150's partial index covers `affiliations`.

## 8. Not in scope

- `Cohort` (`federation/cohort.rs`, the reverse-quorum group type): a separate four-value vocabulary with no gate role.
- The consent grammar. The audience vocabulary is unchanged, and the room already rides the grant's cohort-target alias (`sweep_widen` passes it), so `CONSENT_GRAMMAR_HASH` does not move.
- CIRISEdge's serve arm, which belongs to CIRISEdge.
