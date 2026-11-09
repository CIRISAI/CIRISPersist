# Adversarial Review Checklist: Federation Trust and Admission

**Issue:** CIRISPersist#1229. **As of:** 61.1.0 (unreleased), base `04e5126f`.
**Audience:** an independent reviewer, and us. Each item names the
constitutional rule it checks (a CC section), the witnesses persist holds for
it, and what is stated but not measured.

An external static review (relayed by the steward, 2026-11-08) named the trust
and admission machinery as persist's most consequential surface and asked five
questions. This document maps those questions so an audit has a target. It
reports no new defect. "No external security review" is still true: everything
below is a claim backed by persist's own tests (see [README](../README.md),
[THREAT_MODEL.md](THREAT_MODEL.md)).

## How to read an item

- **Rule** is the CC section the code implements. The constitution is the
  authority, and the code is checked against it.
- **Witnesses** are tests that fail if the rule is broken. Each is named by its
  invariant number (`I…`) and test function, with its file and backends:
  `sqlite+pg` means one body run on both, `pure` means no backend, and
  `from-disk` means a gate that reads the source as text. The in-memory backend
  was retired in CIRISPersist#1002 (`src/store/parity.rs`), so no witness runs
  on it.
- **Shipped in** is the first release a witness exists in. `61.1.0` means it is
  integrated on this tree but not released. Production at 61.0.5 does not have
  it.
- **Gaps** are claims nothing measures. A gap is not a defect finding. It is
  where a reviewer should push.
- A postgres leg skips (and passes) when no test DSN is set, except
  `vote_by_person_invariants.rs`, which panics instead. A reviewer running the
  suite must set the DSN, or the `pg` half of every `sqlite+pg` witness proves
  nothing (see `docs/MUTATION_TESTING.md` for the runner's environment).

---

## 1. Can Sybil identities acquire legitimate trust?

**Rule.** Anyone may assert under their own key. Admission is trust or
consent, and a fold keys on whether the emitter resolves to an authority (CC
4.4.3.4.3, CC 4.4.3.8 "Who I trust"). A minted key has standing only through
rows that others sign about it. First contact during a Sybil flood is a stated
residual (CC 5.4.6).

**Witnesses.**

| witness | where | backends | what it proves |
|---|---|---|---|
| `exercise_family_trust_root` via `family_trust_root_works_on_{sqlite,postgres}_557` | `src/federation/operational.rs`; runners in `src/store/{sqlite,postgres}.rs` | sqlite+pg | A 1-of-3 charter is refused, one seat cannot re-root, and a family becomes a root only with a 2-of-3 charter, a grant, and this node's own edge |
| `exercise_trust_root` via `trust_root_helper_works_on_{sqlite,postgres}_536` | same | sqlite+pg | The trust-root verdict's walk |
| I437, I438 `i437_trust_root_valid_reads_a_superseded_edge`, `i438_trusted_roots_of_reads_a_superseded_edge` | `src/federation/rc7_accord_invariants.rs` | sqlite+pg | The edge leg of the trust-root verdict reads a superseded acceptance |
| I439 `i439_a_keyless_family_confers_at_its_quorum` | same | sqlite+pg | A keyless family confers only as it charters, at its quorum |
| `exercise_conferral_is_not_stewardship` via `conferral_is_not_stewardship_{sqlite,postgres}_87` | `src/federation/admission.rs`; `src/store/{sqlite,postgres}.rs` | sqlite+pg | A conferral is never counted as stewardship |
| I1361 `i1361_infra_relay_is_accord_conferred` | `src/federation/v601_asks_invariants.rs` | sqlite+pg | `infra:relay` is conferred only by a 2-of-3 holder co-scrub (CC 5.4.6 item 4). A scrub by a key outside the roster reads false |
| I190 (`i190_*` runners) | `src/federation/canonical_community_invariants.rs` | sqlite+pg | The canonical community admits at 2 of 3 and refuses 1 of 3. A founder the accord did not confer is refused. `trust:accepts` is the one-row un-trust |
| `a_withdrawn_trust_root_stops_projecting_global_685` | `tests/withdrawn_trust_root_685.rs` | sqlite (`test-anchor` builds only) | A withdrawn root stops projecting global standing |
| `promotion_cohort_standing_is_not_av45_592`, `every_authority_claim_declares_a_conferral_mode`, `a_deferred_conferral_mode_never_backs_a_membership_test_607` | `src/federation/admission.rs` | pure | Every authority claim states how it is conferred, and a deferred mode never backs a membership test |

**Gaps.**

- **No "Who I trust" fold by that name.** Nothing in `src/` is called
  `trust_set`. CC 4.4.3.8's trust-or-consent rule appears only as a comment
  (`src/federation/licensure.rs`). No witness states that "a fold keys on the
  emitter resolving to an authority" as one property across folds.
- **No witness for "a minted key has standing only through rows others sign
  about it"** as a general property, apart from the per-door refusals above.
- **No flood at scale.** First contact under a Sybil flood (CC 5.4.6) is a
  stated residual. It is unmeasured, and it is leviculum#100 territory.

## 2. Can quorum voting be manipulated?

**Rule.** One vote per person: an order-free fold over fedIDs (CC 4.5.13,
`CLM-vote-once-per-person`, CIRISPersist#1198). A policy row is five integers
inside the two-path corridor, with a count minimum. A removal under
`open:self_admit` takes two voices other than the member's own (CC 4.5.13). A
`unanimous` removal is every other member (CC 3.1.3.2, CIRISPersist#1192). The
base is the expected-active census (CC 6.1.9).

**Status.** #1198 is integrated into **61.1.0** and is not released. At
61.0.5, room votes still count by key, and the door refusals that depended on
arrival order (`NotACohortMember`, `DuplicateObjection`, `TargetActionUnknown`,
`ObjectionUnknown`, `DismissalQuorumShort`) still refuse.

**Witnesses.**

| witness | where | backends | what it proves |
|---|---|---|---|
| I1525 `i1525_two_devices_are_one_voice` | `src/federation/vote_by_person_invariants.rs` | sqlite+pg | Two devices of one self are one voice |
| I1526 `i1526_disagreement_is_no_voice`, I1527 `i1527_a_sibling_withdrawal_leaves_one`, I1536 `i1536_a_recant_leaves_the_other_row` | same | sqlite+pg | Rows that disagree are no voice until a retraction leaves one |
| I1528 `i1528_another_self_does_not_count`, I1529 `i1529_an_evicted_devices_vote_is_void`, I1535 `i1535_an_evicted_seat_stays_the_persons` | same | sqlite+pg | A key of another self does not count. An evicted device's vote is void |
| I1530 `i1530_a_membership_change_counts_persons`, `i1530b_the_floor_counts_persons`, `i1530c_a_held_event_stands_and_a_new_one_is_refused` (pure) | same | sqlite+pg, pure | The roster plane counts persons, and so does its floor |
| I1531 `i1531_no_order_changes_the_count`; `no_permutation_of_the_rows_changes_the_count` | same; `src/federation/reverse_quorum.rs` | sqlite+pg; pure | 720 orders of six rows fold to one answer |
| I1533 `i1533_the_count_reads_no_clock` | `vote_by_person_invariants.rs` | sqlite+pg | The count reads no clock |
| I1534 `i1534_a_ballot_before_its_occurrence`, `i1534b_either_arrival_order`; I1538 `i1538_a_row_waits_for_what_it_names`; I1539 `i1539_recusal_reads_the_held_target` | same | sqlite+pg | A row admitted before what it names counts once that arrives, in either order |
| I1537 `i1537_the_deadline_is_a_window`, `i1537b_the_tally_is_shared_the_tier_is_not`; I1540–I1542 | same | sqlite+pg | The steward deadline is this node's window (V213), and the backfill |
| I1532 `i1532_a_retraction_counts_persons` | `src/federation/group_plane_invariants.rs` | sqlite+pg | A cosigned `withdraws` of a roster event counts persons |
| `every_arm_admits_and_refuses`, `a_unanimous_removal_is_every_other_member`, `a_self_signed_admission_is_refused_by_every_other_protocol`, `open_self_admit_admits_the_joiner_and_floors_removal_at_two`, `reverse_quorum_protects_cheaply_and_grants_expensively`, `infrastructure_counts_founders_only`, `node_founder_seat_is_not_eligible` | `src/federation/consensus.rs` (`consensus::tests`) | pure | The evaluator, arm by arm |
| I1503 `i1503_removal_takes_two_voices` | `src/federation/open_admission_invariants.rs` | sqlite+pg | Under `open:self_admit` one voice is refused and two are admitted |
| I1505 `i1505_a_widening_is_reversible_under_reverse_quorum` | same | sqlite+pg | The count minimum: one objector never decides, even at m = 1 |
| I1500–I1502 | same | sqlite+pg | `founder_only` is refused above the family, `open:self_admit` is valid only on a public room, and a self-signed admission is valid only there |
| `quorum_path_every_roster_size`, `lone_path_every_roster_size_and_objection_count`, `one_key_roster_is_the_only_unilateral_door`, `the_corridor_refuses_each_pole_by_its_token`, `governance_policy_vectors_replay`, and the TLC trace replays `combined{1,2,3,4}_*`, `unilateral3_stolen_final_execute_is_refused` | `src/federation/two_path.rs` | pure | The two-path corridor, checked against the model's traces |
| I1303–I1306 (`i1303_every_two_path_row_of_the_vendored_table_is_in_its_corridor`, `i1305_a_row_outside_its_corridor_is_refused_by_its_token`, `i1306_an_unreadable_row_is_refused_not_guessed`) | `src/federation/governance_policy.rs` | pure | Every vendored policy row is in its corridor, and an unreadable one is refused |
| I1620 `i1620_a_retraction_names_its_member` (61.1.0, #1188) | `group_plane_invariants.rs` | sqlite+pg | A retraction names the member its row names: under `unanimous`, every OTHER member retracts a widening. Under `open:self_admit`, a record's withdrawal (dissolution) names no member and takes the two-voice floor |

**Gaps.**

- **The census base at scale** (CC 6.1.9) is unmeasured. It is v62 work.
- **#1192's unanimous removal** has only the pure evaluator test
  (`a_unanimous_removal_is_every_other_member`) and, from 61.1.0, I1620's
  retraction leg. No door witness removes a member under `unanimous`.
- **The TLA+ models are not in this tree.** `formal/two_path/TwoPath.tla`,
  `formal/self_roster/SelfRoster.tla` and the others are referenced by path
  (`src/federation/namespace/csd4_chain.json`, `governance_policy.json`). Only
  six TLC traces are vendored (`tests/fixtures/self_roster/*.json`), pinned by
  I1300/I1302 and replayed by `two_path.rs`. "The generated TLC instances per
  policy row" are not run here.
- **`prepare_roster_events` reads `Utc::now()`** (`src/federation/mod.rs`). This
  is the known LTS gap named on #1198, and it is fixed in v62. I1533 covers the
  vote count, not this read.

## 3. Can a compromised steward permanently capture authority?

**Rule.** Anyone may leave a root or found one (CC 1.13.2, CC 4.2). The halt is
bounded and public, and leaving escapes it. A steward's acts are rows under the
steward's own name. The scale gate hands amendment authority to governance (CC
4.5.1).

**Witnesses.**

| witness | where | backends | what it proves |
|---|---|---|---|
| I1130–I1143, I1307 (`i1133_the_thief_cannot_evict`, `i1134_an_evicted_keys_vote_is_void`, `i1137_a_second_device_acts_as_its_self`, `i1141_the_genesis_key_is_evictable`, `i1142_an_evicted_key_cannot_sign_into_its_old_window`, `i1139_two_nodes_land_alike`, `i1307_the_corridor_runs_at_admission`) | `src/federation/self_roster_invariants.rs` | sqlite+pg | The self-roster's two-path door: a thief cannot evict, an evicted key's vote is void, and the steward predicate admits a live roster key of the same self only (CC 3.3.6.3) |
| I450e–I450j, I509–I511 (`i450h_the_standing_roster_is_the_held_heads`) | `src/federation/accord_roster_invariants.rs` | sqlite+pg | An accord holder is added by a strict majority of the standing roster, and the cosigns of the holder being added do not count |
| I436 `i436_a_decision_carries_no_steward_signatures` | `src/federation/rc7_accord_invariants.rs` | sqlite+pg | An accord decision carries no steward signatures |
| I650 `i650_authorisation_is_the_roots_own_protocol` | `src/federation/steward_purge_invariants.rs` | sqlite+pg | A steward purge is authorised by the root's own protocol |
| `run_costeward_gate_matrix` via `costeward_gate_{sqlite,postgres}` | `src/federation/admission.rs` | sqlite+pg | The co-steward binding gates |
| I190 (`trust:accepts`) | `canonical_community_invariants.rs` | sqlite+pg | Un-trusting a root is one row |
| `exercise_family_trust_root` leg (e) | `operational.rs` | sqlite+pg | The family halt latch is reported but gates nothing (no I-number) |

**Gaps.**

- **No witness for leaving a root, or for founding one,** as an end-to-end act.
  The nearest is I190's one-row un-trust.
- **No witness bounds the halt's duration.** The halt models
  (`formal/accord_halt/AccordHalt{,Fuse}.tla`) are referenced and not vendored.
- **No "scale gate"** (CC 4.5.1) exists in code or tests under that name.
- **No witness that a steward's acts are rows under its own name** as one
  property.
- **`RootReach` (`Prop_NoBan`, `Untrust`) has no Rust code.** It appears only in
  the vendored `src/federation/namespace/csd4_chain.json`.
- **No live run of leaving a captured root.**

## 4. Does revocation propagate across disconnected nodes?

**Rule.** Admit every verifiable row and let the fold decide. A late revocation
is held, and it counts from the moment it is held, on every node alike (CC
4.5.13's state processor; #1198's rulings on the door refusals that depended
on arrival order). A retraction is judged by who signed it, not by when it
arrived (CC 2.4.1.1, CIRISPersist#1218).

**Witnesses.**

| witness | where | backends | what it proves |
|---|---|---|---|
| I1600 `i1600_only_the_producer_or_a_stamp_retires` | `src/federation/withdraws_order_roster_receipt_invariants.rs` | pure | Against the eight adverse classes and a cosigned act, a subject's `withdraws` retires nothing, in every permutation of the rows |
| I1601 `i1601_both_arrival_orders_agree` | same | sqlite+pg | Through the real door, in both arrival orders, four readers agree (the fold, the Live rule, the read-time re-derivation, the SQL Live listing) |
| I1603 `i1603_a_forged_stamp_is_never_kept`, I1604 `i1604_a_node_cannot_outrun_its_owner` | same | sqlite+pg | See section 6, #1218 H1 |
| I1531, I1534b, I1538 | `vote_by_person_invariants.rs` | sqlite+pg, pure | Vote rows in any order fold to one count |
| I1486 `i1486_rows_replicate` | `group_plane_invariants.rs` | sqlite+pg | A second node fed only the first node's rows folds the same record and roster, and its projections rebuild byte-equal |
| I1139 `i1139_two_nodes_land_alike` | `self_roster_invariants.rs` | sqlite+pg | Two nodes land the same self-roster |
| I165 `i165_order_does_not_matter` | `src/federation/room_roster_invariants.rs` | sqlite+pg | Room roster events admit in every order |
| I656 `i656_the_tombstone_replicates_re_verified`, I697 `i697_a_tombstone_never_reaches_the_accountability_record` | `steward_purge_invariants.rs` | sqlite+pg | A tombstone replicates and is re-verified. Replication order cannot purge the accountability record |
| `the_fold_is_invariant_under_every_permutation_of_the_roots` | `src/federation/mesh_config.rs` | pure | The mesh fold is the same in every order of its roots |
| I1623 `i1623_an_unstamped_withdraws_dissolves_nothing` (61.1.0, #1188) | `src/federation/affiliation_floor_invariants.rs` | sqlite+pg, two nodes | A stranger's `withdraws` of a room's record, held before the record arrived (so stored with no rule), dissolves nothing once the record lands |

**Gaps.**

- **No partition-and-remerge permutation test.** Persist owns one (the
  steward's comment on #1229): two nodes receive the same rows in different
  orders, including a late revocation, and fold to the same roster, standing
  and tally, on both backends. It does not exist yet. The order tests above are
  pure (I1531, I1600) or one node in two orders (I1534b, I1601). None joins two
  nodes with a late revocation.
- **The order dependence #1218 names is owned, not fixed.** An honest
  non-producer `withdraws` that arrived before its target retires nothing on
  that node, while a node that got the rows in order retires the target
  (fail-closed). The I1600–I1604 header states this, and v62's fold derives
  the entitlement.
- **No real partition on the canonical** has been run.

## 5. Do SQLite and PostgreSQL enforce identical authorization semantics?

**Rule.** No backend-only door: every door runs on both backends, and its
decisions live in one shared plan that a backend only executes
(CIRISPersist#934, `docs/FROM_DISK_GATES.md`).

**Witnesses.**

| witness | where | backends | what it proves |
|---|---|---|---|
| `every_backend_runs_the_same_gates_in_the_same_order`, `shared_doors_decide_nothing_in_a_backend`, `no_backend_door_reads_identical`, `every_propagated_call_in_a_door_is_classified`, `no_call_class_is_stale`, `no_declared_divergence_is_stale`, `every_declared_divergence_states_a_substantive_reason` | `src/store/parity.rs` | from-disk | Each backend runs the same gates in the same order. A shared door decides nothing in a backend. Every call is classified, and every divergence is declared with a reason. The tables are `SHARED_PLANS` (75), `SHARED_SELECTIONS` (8) and `SHARED_DOORS` (85) |
| `the_scan_is_not_vacuous`, `a_commented_out_gate_does_not_read_as_live` | same | from-disk | The scan can fail |
| `the_rust_text_counts_equal_the_ast_grep_expectations`, `every_absence_guard_expects_zero_and_keeps_its_text_twin`, `the_text_counter_ignores_comments_and_strings` | `src/ast_gate_parity.rs`, `rules/expected.json` | from-disk | The ast-grep rule counts match the text counts |
| `src/store/sqlite_conn_model.rs`, `src/store/schema_parity.rs`, `src/store/backend_suite.rs` | | from-disk / sqlite+pg | The connection classes, schema parity, and the shared backend suite |
| The two-backend runner in every `*_invariants.rs` | `src/federation/*_invariants.rs` | sqlite+pg | One body per witness, instantiated per backend |

**Gaps.**

- **The shared, identical and gateless counts are not asserted.** `door_report`
  (`parity.rs`, `#[ignore]`) prints them. The issue's "91 shared / 310
  gateless at v61" and the plan's snapshot (`docs/V61_TASK_PLAN.md`) are reports,
  not gates.
- **"Every witness runs on both backends" is a convention, not a gate.** No
  from-disk check refuses an `*_invariants.rs` body with one backend runner.
- **Not tested under adversarial inputs across backends.** The witness to add
  (persist's, per #1229): the mesh story trace replayed on sqlite and postgres,
  with a second node receiving the rows in another order and folding
  identically. It does not exist yet.

---

## 6. 61.1.0 additions

| addition | rule | witnesses | backends |
|---|---|---|---|
| **#1218 H1.** An unstamped non-producer `withdraws` retires nothing, and only this node's door stamps a rule | CC 2.4.1.1, CC 3.2 | I1600 (pure, every permutation); I1601 (both orders, four readers); I1603 `i1603_a_forged_stamp_is_never_kept`: a rule 1 or 5 offered through `put_attestation` or `apply_replicated_attestation`, in either order, is refused in order and held unstamped when early, and it stays unstamped once the target lands; I1604 `i1604_a_node_cannot_outrun_its_owner`: a node named as the subject of its own owner-binding cannot shed its owner by sending a `withdraws` first; I1623 (#1188): an unstamped `withdraws` of a room's record dissolves nothing; I1624 (#1188): a stranger's early `withdraws` retires no standing proposal | pure; sqlite+pg |
| **#1233.** Strict-only verification, and a hybrid tree head at store | CC 5.3.2.4.3.1; CC 5.3.1 | I1560/I1561 `i1560_i1561_python_verify_doors_accept_only_strict_{sqlite,postgres}` (`src/ffi/pyo3/hybrid_policy_1233_tests.rs`); I1562 `i1562_capsule_verify_hybrid_refuses_every_policy_but_strict` (`src/ffi/directory_capsule.rs`); I1563 `test_verify_hybrid_via_directory_accepts_only_strict_1233`, `test_verify_hybrid_refuses_before_any_decode_1233` (`tests/python/test_hybrid_policy_1233_surface.py`); I1564 `i1564_store_refuses_a_head_without_its_pqc_half`, I1565, I1566 `i1566_verify_refuses_a_head_without_its_pqc_half` (`src/audit/hybrid_head_1233_invariants.rs`; `require_hybrid_sth` in `src/audit/merkle_store.rs`); I1567 `i1567_audit_chain_proof_serves_a_stored_head_as_itself_{sqlite,postgres}`; I1568 `i1568_via_directory_refuses_every_policy_but_strict` (`src/verify/strict_api_1233_invariants.rs`) | sqlite+pg; I1566 pure; I1563 Python |
| **#1174.** Classifier-keyed gates: a `scores`-form row meets every gate its classic-form twin meets | CC 2.4; CC 3.1.9.4; CC 3.4.3; CC 3.1.5 | I1590 `i1590_the_family_is_the_dimension_on_scores_and_the_type_elsewhere`, I1595 `i1595_substrate_self_report_prefixes_are_the_tables`, I1596 `i1596_the_trace_gate_reads_the_family_in_either_form` (pure); I1591 `i1591_health_liveness_self_ban_in_both_forms`, I1592 `i1592_hard_case_emitter_rule_in_both_forms`, I1593 `i1593_substrate_self_report_attester_in_both_forms`, I1607 `i1607_a_peers_self_report_is_reported_not_refused`, I1594 `i1594_trace_summary_self_emission_in_both_forms` (`src/federation/scores_form_family_1174_invariants.rs`); the type-slot `capacity:*` carve-out in I1600 | pure; sqlite+pg |
| **H3.** A `hard_case` foreign occupant: this node's record lands under the emitter-bound id | CC 3.4.2 (the substrate emits `hard_case`); the 61.1 entry cites no section | I1605/I1606 `i1605_i1606_a_foreign_occupant_never_blocks_the_record` (`src/federation/hard_case_occupant_invariants.rs`): the record lands under the emitter-bound id, the peer's row is unchanged, and a re-record of its own event is a no-op | sqlite+pg |
| **#1238.** SQLite write transactions begin `IMMEDIATE` | no CC section (an availability property of a shared file) | I1660 `i1660_put_attestation_waits_out_a_held_write_lock`, `i1660_a_read_then_write_key_record_waits_out_a_held_write_lock` (real file); I1661 `every_sqlite_write_transaction_is_immediate_1238`, `the_deferred_begin_scanner_reads_calls_not_mentions_1238` (`src/store/sqlite_write_tx_1238_invariants.rs`); I1662 `i1662_a_backend_error_carries_its_detail_to_python_1238` (`src/ffi/pyo3.rs`); I1663 `no_read_door_closure_in_sqlite_rs_writes_1238` (`src/store/sqlite_conn_model.rs`) | sqlite; from-disk |
| **#1239.** `Engine.verify_trace` gives one verdict, ingest's | CC 5.3.2.4.3.1 | I1569 `i1569_verify_trace_gives_ingests_verdict_{sqlite,postgres}` (`src/ffi/pyo3/verify_trace_1239_tests.rs`): one corpus of traces, including one with no PQC half, gets the same verdict from the dry-run and from `receive_and_persist` | sqlite+pg |

**Gaps in the 61.1.0 additions.**

- **#1218:** the order dependence is owned by v62 (section 4).
- **#1238:** I1660 has no postgres twin. That follows from what it tests
  (SQLite's file lock).
- **#1239:** `tests/python/test_verify_trace_gil.py` exercises `verify_trace`
  but does not cite I1569 or #1239. The Python-surface witness is the PyO3
  test, not the pytest.
- **H3:** the v1 id derivation is unchanged, so a foreign occupant still holds
  the v1 id until an operator purges it (v62 moves every record to an
  emitter-bound id, CIRISPersist#1237).

## 7. How strong the witnesses are: #1188's survivors

A witness counts only if it fails when the line it guards is broken.
`cargo-mutants` checks this (`docs/MUTATION_TESTING.md`). The v61.0.0 run left
22 survivors in this surface (CIRISPersist#1188), and the nightly
`scope-s1-retire` was red four nights running on one of them. 61.1.0 adds a
witness for each, or an allow-list entry with the reason it is equivalent
(`scripts/mutants/allowed_survivors.txt`):

| site | witness |
|---|---|
| `check_cosigned_withdraws` `subject` (the nightly red) | I1620 |
| `community_dissolved_at` stamp test | I1623; the match guard is equivalent (a listed row's record is the listed community's, `check_canonical_group_row`) |
| `PlannedHead::{group_key_id, supersede_proof}` | I1622 (pure) |
| `live_standing_proposal` (6) | I1624 |
| `record_names_its_audience` family arm | I1625, and I1521 (which already carried a family record to a node that did not hold it, but the scope's filter did not select it) |
| `displaces` (3) | I1626 |
| `consensus_protocol::{founders_hold_authority, is_canonical_form}` (6) | I1621 (pure) |

## Summary of gaps

| # | gap | item |
|---|---|---|
| G1 | No "Who I trust" fold or `trust_set` by name, and no cross-fold witness that a fold keys on the emitter resolving to an authority | 1 |
| G2 | No general witness that a minted key's standing comes only from rows others sign | 1 |
| G3 | Sybil flood at first contact, at scale (CC 5.4.6 residual) | 1 |
| G4 | Census base at scale (CC 6.1.9) | 2 |
| G5 | No door witness for a `unanimous` removal (#1192) | 2 |
| G6 | TLA+ models and per-policy-row TLC instances not in this tree; six traces vendored | 2, 3 |
| G7 | `prepare_roster_events` reads `Utc::now()` (v62) | 2 |
| G8 | No witness for leaving or founding a root end to end, for a bounded halt, for a scale gate, or for "a steward's acts are rows under its own name" | 3 |
| G9 | `RootReach` (`Prop_NoBan`, `Untrust`) has no Rust code | 3 |
| G10 | No two-node partition-and-remerge test with a late revocation, on both backends | 4 |
| G11 | #1218's order dependence, owned by v62 | 4 |
| G12 | Parity counts (shared, identical, gateless) are reported, not asserted | 5 |
| G13 | "Every witness on both backends" is a convention, not a gate | 5 |
| G14 | No mesh story trace replayed on both backends with a second node in another order | 5 |
| G15 | `test_verify_trace_gil.py` does not cite I1569 | 6 |
