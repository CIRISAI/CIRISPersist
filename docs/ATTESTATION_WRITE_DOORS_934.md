# The attestation plane's write doors (CIRISPersist#934 step 1)

Inventory taken on branch `arch-934-one-door`, off v55.0.0 (`ca6bdf60`). The
scan is `store::parity` (#670/#681): run
`PARITY_DOOR_FILTER=<name> cargo test --lib store::parity::tests::door_report -- --ignored --nocapture`.

The verdicts the report prints:

- `shared`: every backend's door is a call into one shared plan.
- `identical xN (k gates)`: the decision is written N times, byte-equal by the scan.
- `declared`: a `DECLARED_DIVERGENCES` row pins one backend's shape.
- `gateless`: the scan sees no gate.

## Doors

| door | before (v55.0.0) | after | state |
|---|---|---|---|
| `put_attestation_with_origin` (under `put_attestation`, `put_attestation_authored`, and the replicated apply's fresh-id store) | identical x3 (59 gates) | shared: `plan:put_attestation_planned` | done (door 1) |
| `attach_attestation_pqc_signature` | gateless (its two refusals and the hash recompute were inline, written three times) | shared: `plan:attach_attestation_pqc_planned` | done (door 3) |
| `attestation_upsert_local` / `attestation_insert_local` | gateless (a scanner blind spot, see below); really identical x3 (17 gates) | shared: `plan:write_local_attestation_planned` | done (door 2); the occupied-id divergence ruled (I951) |
| `reseal_attestation_v31` | declared (memory re-asks `check_reseal_admission` under its lock) | unchanged | not attempted: needs #681's closure form |
| `purge_attestation_v31`, `purge_genesis_delegation_row_v31` | identical x3 (1 gate each) | unchanged | not attempted: steward-purge plane, 13 `CLM-purge-*` rows |
| `enter_mesh` (promotion) | declared; decision already `crossing::plan_enter_mesh` (v39) | unchanged | already planned |
| `put_holding_claim` | identical x2; decision already `holding_claim::prepare_announcement` | unchanged | already planned (memory holds no blobs) |
| `apply_replicated_attestation`, `put_attestation_synced` | `attestation_apply::apply_planned` (v50); a fresh id stores through door 1 | unchanged | already planned |

### Door 1: the gate sequence, identical on all three backends at v55.0.0

```
validate_subject_key_ids_at, check_genesis_attestation_reserved,
refuse_if_tombstoned_attestation, refuse_mock_trace_attestation,
check_write_authored, check_write_synced, check_write, check_write,
check_federation, check_envelope_size_admission, canonicalize_in_place,
check_content_hash_hex, check_delivery_mode_vocabulary,
check_consent_scope_tokens, check_media_source, check_instant_binding,
check_row_column_binding, admit_row_type, check_cohort_scope,
check_capacity_never_local, check_trace_dimension_admission,
validate_grant_admission, default.check, verify_consent_record_transit_ingest,
verify_federation_tier_ingest, check_attestation_write_scope,
check_attestation_tier_vocabulary, check_targeted_cohort_requires_federation_tier,
check_cohort_standing_resolved, validate_envelope_against_schema,
check_withdraws_admission, check_delegated_duty_scores_admission,
check_consent_for_key_admission, check_node_agency_admission,
check_user_target_steward_binding_admission, check_minor_owner_binding_not_announced,
check_delegation_cycle_admission, check_single_node_owner_admission,
check_trust_charter_admission, check_attach_freshness,
check_family_charter_admission, check_reserved_prefix_admission,
check_capacity_consent_admission, check_rendition_placement,
check_config_self_or_owner_admission, check_duty_admission,
check_config_renewal_supersedes, check_session_self_report_admission,
check_community_trust_grant_admission, check_custody_ack_admission,
check_holding_claim_scope, check_community_listing_admission,
check_dimension_case_rule, check_licensure_delegator_is_authority,
check_peer_deadmission, check_no_moderator_federate_apply,
check_attested_subject_admission, check_delegation_cycle_admission (under the
write lock), attestation_reput_verdict
```

### The local doors: the gate sequence, identical on all three backends

```
check_envelope_size_admission, check_consent_scope_tokens, check_media_source,
check_trace_dimension_admission, check_trust_charter_admission,
check_attach_freshness, check_local_tier_eligibility, check_cohort_scope,
verify_caller_signed_local_row, check_attested_subject_admission,
check_rendition_placement, default.check, local_row_instant,
check_genesis_attestation_reserved, stamp_local_row,
check_envelope_size_admission, check_instant_binding
```

Both doors delegate their whole body to a same-file helper
(`{memory,sqlite,pg}_write_local_attestation`) as the body's tail expression.
The v55 scanner counted only `?`-shaped propagation, so it reported both doors
`gateless` on all three backends. The scan now also counts a tail call to a
classified gate, delegating helper or plan, and the three helpers are
classified.

**The divergence, and the ruling (I951,
`federation::local_door_divergence_invariants`).** When the caller-chosen
`attestation_id` was already held, memory returned the id before the upsert's
replace-DELETE. sqlite and postgres ran that DELETE, then an
insert-if-absent, then re-projected and, for a `withdraws`, overwrote the
admission depth.

| case | memory before | sqlite, postgres before | all three now |
|---|---|---|---|
| upsert re-uses its own `(attester, dimension)` row's id | old row kept | replaced | replaced |
| upsert re-uses another dimension's row's id | Ok, nothing changed | Ok, the upsert's own row deleted, nothing stored | `LocalAttestationIdOccupied`, nothing changed |
| insert re-uses a held id | Ok, nothing written | Ok, nothing written | Ok, nothing written |

The lead ruled that an upsert replaces its own row and that any other holder
of the id is a typed refusal. `attestation_admit::local_occupied_id_verdict`
is the one clause.

## The CC conditions (CIRISConstitution review on #934, 2026-10-13)

**1. Two named instants, both inputs.** A plan takes
`PlanInstants { fold_at, received_at }` and reads no clock.

- `fold_at` is the row's signed instant, used for folds over other rows. The
  live door passes the row's `asserted_at`, and a replay of `V(rows, t)`
  passes `t`.
- `received_at` is the receiver's clock at the door, used for the receipt
  bounds.

#934 changes no behaviour, so each gate is wired to the instant it read
before. `store::parity`'s `PLAN_INSTANTS` derives this table from the plan
bodies and fails on any difference:

| plan | call | instant | before #934 | note |
|---|---|---|---|---|
| put | `check_instant_binding` | `received_at` | clock | receipt bound: future skew |
| put | `check_attach_freshness` | `received_at` | clock | receipt bound: CC 2.6.7 window W |
| put | `check_capacity_consent_admission` | `received_at` | clock | fold still at receipt: #1049 candidate |
| put | `check_delegation_cycle_admission` | `received_at` | clock | fold still at receipt: #1049 candidate |
| put | `check_trust_charter_admission` | `received_at` | clock | fold still at receipt: #1049 candidate |
| put | `check_peer_deadmission` | `received_at` | clock | fold still at receipt: #1049 candidate |
| put | `check_licensure_delegator_is_authority` | both | clock and `asserted_at` | judged at receipt and at the signed instant |
| put | `check_community_trust_grant_admission` | `fold_at` | `asserted_at` | owner bindings at the grant's instant (CC 3.3.1) |
| executor re-ask | `check_delegation_cycle_admission` | `received_at` | clock | the plan's instant, under the write lock |
| PQC completion | completion stamp | `received_at` | clock | `pqc_completed_at` |
| local | `check_trust_charter_admission`, `check_attach_freshness`, `local_row_instant`, `check_instant_binding` | `received_at` | clock | the local door mints its own instant |

Every other gate reads neither instant. It reads the row, or no time at all.
Gates that read the clock two or more calls deep are not yet audited one by
one.

I950 is the witness. One row is planned under different pairs and gets each
gate's verdict on memory, sqlite and postgres, covering the skew bound, the
cycle fold at receipt, and the owner fold at `fold_at`. Two mutations each
turn a leg red on all three backends: the skew bound given `fold_at`, and the
owner fold given `received_at`.

**2. No admission decision reads a projection.** These reads in the put plan
are not signed rows:

- the AV-76 per-peer quota and its cohort-affinity memo (node-local,
  receipt-time rate state);
- `settle_if_held`'s wire-index lookup (an accelerator; it settles only on a
  byte-identical held row);
- the blob store, read by `check_rendition_placement` and
  `check_holding_claim_scope`;
- the purge tombstones table, read by `refuse_if_tombstoned_attestation`.

The directory walks read the attestation rows and their subject projection.
None of these was re-derived in this step.

**3. Manifest rows move with the symbol.** No decision symbol was renamed or
moved. The gates kept their names and files, and gained only instant
parameters. `evidence_tsv.py check` matches all
225 rows.

**4. rc8's rules land once.** The extension point is `plan_put_attestation`. A
new admission rule is one call in its tier (pure gates in AV-76 tier 1,
directory walks in tier 4), given `fold_at` or `received_at` by name and
recorded in `PLAN_INSTANTS`. The local doors' point is
`plan_write_local_attestation`.
