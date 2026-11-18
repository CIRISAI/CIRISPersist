# P5b: the node-local touch claim write

Base: `v62-syn0` @ 8f33957f. Worktree `/home/emoore/CIRISPersist-wp-P5b`, branch `v62-p-P5b`. Patch: `P5b.patch`; API: `P5b.api.md`. Invariants used: I3114–I3117 (P5 used I3110–I3113). Nothing was built, so every claim is BELIEVED. Claims marked "read-checked" were checked by reading the source.

## Why

RULINGS: "a touch claim is node-local". `CC_FAMILYMAP_ANSWER.md`: "NODE-LOCAL fold (CC 2.4.1 'node-local derived state'); witness_touch and n_of_m forms have no basis: GONE".

Before this patch the only write was the hybrid-signed `put_touch_claim(&SignedTouchClaim)`. F0's `scripts/earlier_form_doors.tsv` classes it `refuses`, so at CP2 no node could record a floor at all (E2's finding).

## What changed, file by file

- **`src/federation/mod.rs`** (trait), two NEW methods. Both have an `Err(Error::Unsupported { method })` default, so the generator delegates them as leaves (found, not listed). The table's grammar is in P5b.api.md.
  - **`put_touch_claim_local(target_key_id, target_kind, fresh_as_of, cohort_scope) -> Result<TouchApplyOutcome, Error>`**: the write.
  - **`freshness_floor(target_key_id, target_kind) -> Result<Option<types::FreshnessFloor>, Error>`**: the read. It returns the fields the fold reads (target, kind, `fresh_as_of`, `cohort_scope`), whichever write set them.
  - The `lookup_freshness_floor` doc now says it is the earlier form's read and skips node-local rows. Plus a 4-line test-module declaration (`touch_local_invariants`).
- **`src/federation/types.rs`**: NEW `FreshnessFloor` (Debug, Clone, PartialEq, Eq, Serialize, Deserialize) and NEW `NODE_LOCAL_TOUCH_FORM = "node_local"`.
- **`src/federation/admission.rs`**: NEW `check_touch_fresh_as_of_skew(fresh_as_of, now, max_skew)`. `verify_touch_claim_admission` delegates to it. The message prefix changed from "signed touch_claim:" to "touch_claim:"; no test matches the old prefix (grep, read-checked).
- **`src/federation/evidence_admit.rs`**:
  - NEW `PlannedLocalTouch<'a>` and NEW `EvidenceStore::store_planned_touch_claim_local`.
  - NEW shared plan `put_touch_claim_local_planned`, which runs, in order:
    1. a non-empty target and kind (`InvalidArgument`);
    2. `check_cohort_scope` (`CohortScopeRejected`);
    3. the skew guard at the door's one clock read (`host::clock::now()`, `DEFAULT_MAX_TOUCH_SKEW`);
    4. the merge.
  - The plan has NO `refuse_earlier_form`: the write takes no object.
- **`src/store/sqlite.rs`, `src/store/postgres.rs`**:
  - the trait door is a one-call delegation to the plan;
  - `freshness_floor` reads the table directly, through new parsers `sqlite_row_to_freshness_floor` / `pg_row_to_freshness_floor`;
  - `store_planned_touch_claim_local` uses the signed door's exact SQL merge (`ON CONFLICT … DO UPDATE … WHERE excluded.fresh_as_of > stored`). sqlite keeps the same `to_rfc3339` text spelling;
  - `lookup_freshness_floor` gains `AND signer_form <> 'node_local'`.
- **No schema change.** V300 must reproduce edition 1's `freshness_floor` DDL byte for byte (`edition_baseline.rs` I1950), and V300's checksum is pinned (`evidence/migration_checksums.tsv`). So the NOT NULL signed columns stay. A node-local row is `signer_form = 'node_local'`, `attesting_key_id` = `dir.node_key_id()` (provenance only, or empty), `signed_envelope = '{}'`, `signature = ''`. It claims no signature, and the signed read skips it. When F removes the signed door, edition 3 can drop the four columns.
- **`src/federation/ownership_reclaim.rs`**:
  - the PRODUCTION consumer (the abandonment fold, step 7) reads `freshness_floor`, not `lookup_freshness_floor`;
  - the one PRODUCER (the reclaim ceremony's seizure arm, `test_support`) uses `put_touch_claim_local(owner2, OWNERSHIP_FRESHNESS_TARGET_KIND, now−5 min truncated to substrate resolution, self)`;
  - the now-unused `self_touch` fixture and its `SignerForm` / `SignedTouchClaim` imports are removed.
  - There is no other producer in production (grep: pyo3, engine and server have none). The test producers in `freshness.rs` (E2's bodies) and `attester_key_unknown_invariants.rs` (it witnesses the signed door's `AttesterKeyUnknown`) stay with the signed door.
- **`src/federation/directory_double.rs`**: regenerated (`python3 scripts/gen_directory_double.py`; `--check` OK, 143 delegations).
- **`src/store/parity.rs`**:
  - `CALL_CLASSES` gains `put_touch_claim_local_planned` (Plan), `store_planned_touch_claim_local` (Plumbing) and `check_touch_fresh_as_of_skew` (Gate);
  - `SHARED_PLANS` 74→75 and `SHARED_DOORS` 81→82, one row each.
  - **Merge note:** other patches that add rows to these fixed-length arrays (F0 edits around them) need the counts re-summed at synthesis.
- **`src/store/sqlite_conn_model.rs`**: `store_planned_touch_claim_local` (Write) and `freshness_floor` (Read).

## F0's door table: NO row added (a deliberate departure from the brief)

`scripts/earlier_form_doors.py` (F0.patch) inventories a trait method only when its parameters name an OBJECT type (`Signed*`, `serde_json::Value`, …) or a `*json*` parameter. A row naming a door the inventory does not find is red: "STALE row …: the inventory finds no such door". `put_touch_claim_local` takes `&str` and `DateTime<Utc>`, so it is not inventoried. An `exempt` row for it would turn F0's gate red. The gate's own rule already covers the case: a write that takes no object is not a door of this table. If the lead still wants the row, F0's inventory needs a hand-listed exemption mechanism first.

## Tests (`src/federation/touch_local_invariants.rs`; sqlite AND postgres runners)

- **I3114** monotonic max: first → `Advanced`; older and equal → `NotFresher`, and the floor is unchanged; newer → `Advanced`.
- **I3115** future skew: `now + 10 min` → `InvalidArgument` ("ahead of now"), nothing written; `now + 1 min` → `Advanced`.
- **I3116** cohort scope: `""`, `public`, `everyone`, `SELF` → `CohortScopeRejected { cohort_scope }`, nothing written. Each of the seven closed values is stored and read back as `FreshnessFloor { .., cohort_scope }`.
- **I3117** the local row is the floor: `freshness_floor` sees it; `lookup_freshness_floor` returns `Ok(None)` (it skips the row, it does not fail to decode it); an empty target or kind → `InvalidArgument`.
- All instants are whole seconds, so sqlite text and pg µs round-trip exactly.
- The reclaim ceremony (`exercise_reclaim_ceremony`, held by E2) now exercises the fold over a node-local floor.
- Mutations (not run): flip the SQL `>` → I3114 reds; drop the skew guard → I3115 reds; drop the scope check → I3116 reds; drop the signed read's filter → I3117 reds.

## Refusal tokens introduced

None. The refusals reuse `InvalidArgument` and `CohortScopeRejected` (`federation_cohort_scope_rejected`).

## Compile risks

1. `async_trait` default bodies with `chrono::DateTime<chrono::Utc>` parameters in the trait (mod.rs) and in the generated double; `freshness::` resolves through the double's `use super::*` (read-checked: one existing `freshness::` use).
2. pg params: `&planned.target_key_id` (`&&str`), `&crate::federation::types::NODE_LOCAL_TOUCH_FORM` (`&&'static str`), `&planned.node_key_id` (`&String`), `&planned.fresh_as_of` (`&DateTime<Utc>`). These are the same ToSql kinds the signed executor binds.
3. The parity scan counts (`SHARED_PLANS`/`SHARED_DOORS` array lengths) if another patch also edits them; and `every_backend_runs_the_same_gates_in_the_same_order` over `freshness_floor` (it has the same shape as `lookup_freshness_floor`, which passes today).

## Not done / for others

- **E2:** the remaining held `freshness.rs` bodies can move to `put_touch_claim_local` / `freshness_floor`, or die with the signed door. `run_forged_signature_rejection` is moot for the node-local write.
- **F:** remove `put_touch_claim`, `lookup_freshness_floor`, `SignedTouchClaim`, `SignerForm`, `verify_signed_touch_claim` and `verify_touch_claim_admission` together. `check_touch_fresh_as_of_skew` and the read and write here remain.
- No Python surface: there was none for touch claims.
- No CHANGELOG or evidence rows (R0).
