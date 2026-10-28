# FSD — the targeted cohorts are readable by their own members

**Status:** Implemented (CIRISPersist#893). Gate in `src/scope/caller.rs` and `src/scope/sql.rs`; column in `V150__cohort_target_generated_column.sql`; witness I144 in `src/ceg/list/drive_query_invariants.rs`.
**Normative anchors:** CEG §8.1.13.3 (the `cohort_scope` read gate), AV-84 / CIRISPersist#592 (a targeted placement is a producer self-declaration), CC 5.2 (the audience of a room is its members).

## 1. The constraint

Two rules meet on the attestation plane:

- **AV-84 (write).** A `community` / `family` row MUST name its own **producer** in `attested_key_id`; naming the room is refused at the put, promote and re-scope doors.
- **§4.3 (read).** A row is admitted iff its **target** is in the caller's admitted set.

If the read gate took `attested_key_id` as the target, the two would be unsatisfiable together: `attested_key_id` is the producer, `community_key_ids` holds room keys, and the intersection is empty by construction — no member could read their own room's rows. So the targeted arms read the row's room from the signed envelope, through the generated column `federation_attestations.cohort_target` (§4).

The trace plane does not have this problem: `trace_events` carries its room in `cohort_target_id` (V060), and its gate reads that column. A witness on the trace plane says nothing about the attestation plane, which is why I144 reads a targeted-cohort *attestation* back.

## 2. The rule (stated once)

**The gate asks the ROW's room, never the producer's rooms.** The hold path and CIRISEdge's serve path ask the same question, both keyed on the row:

```rust
// persist, the hold path — federation/replication/hold.rs
cs::COMMUNITY | cs::AFFILIATIONS => community_key_id.is_some_and(|c| member_communities.contains(c))
// CIRISEdge, the serve path — replication/bridge.rs (CC 5.2 audience gate)
Audience::Community { community_key_id } => peer_in_cohort(peer, |c| c.communities.contains(community_key_id))
```

The §4.3 read gate asks it too, so local read, hold and serve agree.

**Refused: "admit iff the caller shares a room with the producer."** It is not a cheaper version of the rule, it is a different one, and it is **transitive**: Alice is in R1 with Bob and R2 without him; Alice writes a row placed in R2; Bob reads it because he shares *a* room with Alice. Room membership would become transitive through producers, and the local read door would contradict the hold path and CIRISEdge's serve gate at once — a row unservable to a peer over the wire and readable by that same party locally.

## 3. The target is per ARM, not per query

One target column cannot serve all arms, because the `self` arm has no envelope target: a `self` row names no room, and the self arm compares `attested_key_id` against the caller's `self_key_ids` by principal (#888). So:

| arm | target |
|---|---|
| `self` | `attested_key_id` — principal equality against `self_key_ids` |
| `family` / `community` / `affiliations` | the ROW's cohort target, from the signed envelope |
| broad tiers | no target; admitted unconditionally |

## 4. Surface

| symbol | role |
|---|---|
| `federation_attestations.cohort_target` | generated column over the signed envelope, `COALESCE` across `COHORT_TARGET_ENVELOPE_FIELDS` in canonical order (sqlite `VIRTUAL`, postgres `STORED`; V150, after the V106 `dimension` precedent). Indexed for the targeted arms |
| `CallerScope::admits(cohort_scope, target, cohort_target, dimension)` | takes the row's cohort target beside its attested key; `self` reads the first, the targeted arms the second |
| `cohort_scope_sql_predicate*` | takes a `cohort_target_col` beside `target_col`, and binds the targeted arms against it. `None` means *the target column already IS the room* — the **trace** plane (`trace_events.cohort_target_id`, V060). A door that omits it falls back to the producer column, which refuses rather than leaks |

The stored value cannot drift from the fact the write gate admitted: `envelope_cohort_target` refuses a split-brain row (two populated aliases disagreeing) at the put door, so every stored row has agreeing aliases and the column's `COALESCE` is total over them.

No wire or vocabulary consequence. The column is generated, so it needs no backfill or rewrite.

## 5. Invariants

- **I144** (sqlite, postgres; through the scores door and `list_attestations`) — **a room reads its own rows.**
  1. A member of room R reads back a correctly-shaped `community` row placed in R (producer-attested per AV-84, room in the envelope) — **admitted**.
  2. A caller who shares a **different** room with that same producer, and is **not** in R, reads the same row — **refused**. *This is the leg that kills the rejected option; under it the row would be admitted.*
  3. The same row and caller under the producer-keyed predicate — refused for the **wrong reason** — so leg 1 cannot pass vacuously (a gate that refuses everything would pass legs 2 and 4 alone).
  4. `family` takes the same shape with `family_key_id` as the target (#887's canonical member).
  5. `self` is unchanged: the #888 legs (a claimed node reads its own rows; the sensitive-leaf and revoked-occurrence arms) stay green.

### 5.1 Mutation round — 8 / 8 killed

Run under `scripts/pg_test_db.sh` so no postgres leg can pass in 0.00 s by
returning early without a DSN.

| # | Mutant | Verdict |
|---|--------|---------|
| M1 | the targeted arms point back at the PRODUCER (`attested_key_id`) | KILLED — `i144` sqlite + postgres |
| M2 | the targeted arms drop the room-MEMBERSHIP test and admit any row that names a room | KILLED — `i144` sqlite + postgres |
| M3-sqlite | the generated column reads only the FIRST alias (`community_id`) | KILLED — `i144` sqlite |
| M3-postgres | same, postgres | KILLED — `i144` postgres |
| M4 | the `self` arm keys on the generated room column too | KILLED — `i141`, `i121`–`i124` (the #888 legs) on both backends |
| M5 | the Rust twin asks the PRODUCER's rooms | KILLED — `i144` (scores door), `targeted_arm_tests` |
| M6 | a targeted row that names NO room is admitted (fail OPEN) | KILLED — `targeted_arm_tests` |
| M7 | the scores plane drops the row's room before the gate sees it | KILLED — `i144` (scores door) |

Two witness-shape rules follow from M5 and M6:

- **The Rust twin is witnessed through a door that uses it.** `list_scores`
  folds through `CallerScope::admits`, so I144 reads through the scores
  plane FIRST and only then through `list_attestations`; M7 pins that plane.
  A leg that returns early measures nothing — the same class as a postgres
  leg without a DSN.
- **Fail-closed on a room-less targeted row is a property of the gate.** The
  write gate refuses such a row outright, so no stored row can exercise the
  read-side arm. I144 asserts the REFUSAL at the door, and the read-side arm
  is witnessed on the twin itself (`targeted_arm_tests`).

## 6. Not in scope

- The trace plane, which has its own `cohort_target_id` column and whose gate reads it — it passes `None` for `cohort_target_col` (the three `scope::sql` shape tests pin its SQL).
- `list_attestations_since`, the ungated replication cursor.
- `affiliations` placement (CIRISPersist#897): a room scope like `community`, classified once for every gate in `FSD/SCOPE_CLASSIFIER.md`.
- **Not implemented:** a gap-free filtered listing (`admitted_at`-ordered), raised on CIRISEdge PR #657; a third door if a consumer needs it.
