# FSD — the targeted cohorts are readable by their own members

**Cut:** v46.5.0 (CIRISPersist#893). **Ruling:** edge, on the issue, 2026-09-23 — option (1), with (2) refused outright.
**Normative anchors:** CEG §8.1.13.3 (the `cohort_scope` read gate), AV-84 / CIRISPersist#592 (a targeted placement is a producer self-declaration), CC 5.2 (the audience of a room is its members).

## 1. The contradiction

Two rules, each correct alone, and unsatisfiable together on the attestation plane:

- **AV-84 (write).** A `community` / `family` row MUST name its own **producer** in `attested_key_id`; naming the room is refused at the put, promote and re-scope doors.
- **§4.3 (read).** A row is admitted iff its **target** is in the caller's admitted set — and the target column passed on `federation_attestations` is `attested_key_id`.

`attested_key_id` is the producer; `community_key_ids` holds room keys; the intersection is empty by construction. **No member can read their own room's rows through this door.** Every `community` and `family` attestation persist has ever admitted is invisible to every reader, including the room.

It survived because `federation_attestations` has **no target column** — `cohort_target_id` is a `trace_events` column (V060), and the trace plane's gate is passed it, so `trace_events_cohort_scope_round_trips_sqlite` passes and covers a different plane. No test read a targeted-cohort *attestation* back. A gate whose failing case has no witness.

## 2. The rule (stated once)

**The gate asks the ROW's room, never the producer's rooms.** That predicate is already shipped twice in this stack and both spellings key on the row:

```rust
// persist, the hold path — federation/replication/hold.rs
cs::COMMUNITY | cs::AFFILIATIONS => community_key_id.is_some_and(|c| member_communities.contains(c))
// edge, the serve path — replication/bridge.rs (CC 5.2 audience gate, v19.0.0)
Audience::Community { community_key_id } => peer_in_cohort(peer, |c| c.communities.contains(community_key_id))
```

§4.3 is the one asking a different question. This cut makes it ask theirs.

**Refused: "admit iff the caller shares a room with the producer."** It is not a cheaper version of the rule, it is a different one, and it is **transitive**: Alice is in R1 with Bob and R2 without him; Alice writes a row placed in R2; Bob reads it because he shares *a* room with Alice. Room membership would become transitive through producers, and the local read door would contradict the hold path and edge's serve gate at once — a row unservable to a peer over the wire and readable by that same party locally. Worse than today's symmetric failure, and it will not ship even as an interim (edge's ruling; their counterexample).

## 3. The target is per ARM, not per query

The gate passes one target column to all arms today. It cannot simply be swapped, because the `self` arm does not have an envelope target: a `self` row names no room, and v46.3.1's self arm compares `attested_key_id` against the caller's `self_key_ids` by principal (#888). So:

| arm | target |
|---|---|
| `self` | `attested_key_id` — principal equality against `self_key_ids`, unchanged |
| `family` / `community` | the ROW's cohort target, from the signed envelope |
| broad tiers | no target; admitted unconditionally, unchanged |

## 4. Surface

| symbol | change |
|---|---|
| `federation_attestations.cohort_target` | NEW generated column over the signed envelope, `COALESCE` across `COHORT_TARGET_ENVELOPE_FIELDS` in canonical order (sqlite `VIRTUAL`, postgres `STORED`) — the V106 `dimension` precedent. Indexed for the targeted arms |
| `CallerScope::admits(cohort_scope, target, cohort_target, dimension)` | takes the row's cohort target beside its attested key; `self` reads the first, `family`/`community` the second |
| `cohort_scope_sql_predicate*` | takes a `cohort_target_col` beside `target_col`, and binds the targeted arms against it. `None` means *the target column already IS the room* — which is the **trace** plane (`trace_events.cohort_target_id`, V060), where these arms were always correct. Only the attestation plane needed a second column. A door that forgets it keeps the pre-#893 behaviour, which refuses rather than leaks |

The stored value cannot drift from the fact the write gate admitted: `envelope_cohort_target` refuses a split-brain row (two populated aliases disagreeing, PR #759 review) at the put door, so every stored row has agreeing aliases and the column's `COALESCE` is total over them.

No wire change, no vocabulary change. One migration, generated columns only — no backfill, no rewrite. MINOR.

## 5. Invariants

- **I144** (sqlite, postgres; memory through the scores door) — **a room reads its own rows.**
  1. A member of room R reads back a correctly-shaped `community` row placed in R (producer-attested per AV-84, room in the envelope) — **admitted**.
  2. A caller who shares a **different** room with that same producer, and is **not** in R, reads the same row — **refused**. *This is the leg that kills the rejected option; under it the row would be admitted.*
  3. The same row and caller under the pre-fix predicate — refused for the **wrong reason** — so leg 1 cannot pass vacuously. Today everything is refused, which is exactly how the hole survived.
  4. `family` takes the same shape with `family_key_id` as the target (#887's canonical member).
  5. `self` is unchanged: the #888 legs (a claimed node reads its own rows; the sensitive-leaf and revoked-occurrence arms) stay green.

### 5.1 Mutation round — 8 / 8 killed

Run under `scripts/pg_test_db.sh` so no postgres leg can pass in 0.00 s by
returning early without a DSN.

| # | Mutant | Verdict |
|---|--------|---------|
| M1 | the targeted arms point back at the PRODUCER (`attested_key_id`) — the pre-#893 predicate | KILLED — `i144` sqlite + postgres |
| M2 | the targeted arms drop the room-MEMBERSHIP test and admit any row that names a room | KILLED — `i144` sqlite + postgres |
| M3-sqlite | the generated column reads only the FIRST alias (`community_id`) | KILLED — `i144` sqlite |
| M3-postgres | same, postgres | KILLED — `i144` postgres |
| M4 | the `self` arm keys on the generated room column too | KILLED — `i141`, `i121`–`i124` (the #888 legs) on both backends |
| M5 | the Rust twin asks the PRODUCER's rooms | **survived round one** → KILLED — `memory::i144`, `targeted_arm_tests` |
| M6 | a targeted row that names NO room is admitted (fail OPEN) | **survived round one** → KILLED — `targeted_arm_tests` |
| M7 | the scores plane drops the row's room before the gate sees it | KILLED — `memory::i144` |

Both survivors were gaps in the WITNESS, not holes in the fix:

- **M5** survived because the memory leg of I144 returned early on "no
  relational read substrate" — it ran in 0.00 s and measured nothing, the
  same class as a postgres leg without a DSN. The memory backend has no
  `list_attestations` substrate, but it *does* serve `list_scores`, and that
  door folds through `CallerScope::admits` — the Rust twin this cut changes.
  I144 now folds through the scores plane FIRST, on all three backends, and
  only then through `list_attestations`. M7 was added to pin that new plane.
- **M6** survived because no leg built a room-less targeted row — and the
  write gate refuses one outright (there is nothing to check membership
  against). So I144 asserts the REFUSAL at the door, and the read-side
  fail-closed arm is witnessed on the twin itself (`targeted_arm_tests`),
  where it belongs: it is a property of the gate, not of what persist
  happens to store today.

## 6. Not in scope

- The trace plane, which has its own `cohort_target_id` column and whose gate already reads it — it passes `None` for the new parameter and its SQL is byte-identical to before (the three `scope::sql` shape tests assert exactly that, unchanged).
- `list_attestations_since`, the ungated replication cursor.
- `affiliations` (CIRISPersist#897). The read gate treats it as a BROAD tier — admitted to any caller — while `replication/hold.rs` gates it on room membership exactly like `community`. Same class as this issue (two gates, one scope, different questions), opposite direction: it fails open. Which one moves is a visibility ruling, not part of this repair; V150's partial index already covers `affiliations` so either answer needs no new migration.
- A gap-free filtered listing (`admitted_at`-ordered) — raised with edge on their PR #657; a third door if a consumer needs it.
