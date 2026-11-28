# Delete list: where the build line decides a rule over rows itself

From a read-only audit on 2026-11-27 of the branch base. Sites were READ
unless marked (B) for believed. Sizes are believed, taken from function
spans. Line numbers are of the branch base and drift as soon as anything is
deleted: use the function names. Paths are under `src/federation/` unless
shown.

**What reaches the crate today** (kernel 0.2.2): the yes or no of a count
inside `consensus.rs::evaluate`; the owner seat (`kernel::owner`); "key
covered at t" (`kernel::key_end`); one trust-edge leg (`kernel::trust`).
Everything below is persist's own.

**Rough size:** 850 to 1,000 functions, 43 to 48 thousand non-test lines
(about half doc comments), plus their `*_invariants.rs` tests.

**Stays:** the fold scheduler in `edition2/fold.rs` (`hold`, `reads`, `Dep`,
`attempt`, `record`, `refold_*`, `run`, the store functions): it becomes the
store-and-ask-again loop. Codecs, stores as fetches, one-row door checks.

## 1. Roster replay and standing

- `mod.rs`: `removed_key_ids_at`, `active_roster_at`, `sort_roster_events`,
  `fold_roster` and wrappers (`authorized_roster_state_at`,
  `authorized_roster_spans_at`, `authorized_roster_high_water_at`,
  `authorized_roster_at`, `active_count`), `prepare_roster_events`,
  `community_roster_events`, `family_roster_events`,
  `authorized_family_roster_at`, `authorized_community_roster_at`,
  `read_community_roster`, `authorized_community_roster_spans_at`,
  `community_roster_high_water_at`, `effective_roster`,
  `is_active_community_member`, the `active_*` trait defaults,
  `add_community_member` / `add_family_member` no-op rule.
- `mod.rs`: `roster_event_standing`, `roster_event_verdict` (includes the
  last-founder rule), `check_roster_authority_over`,
  `check_community_roster_authority_verdict`,
  `check_family_roster_authority_verdict`, `founder_candidates`,
  `root_authority_intervals`, `subtract_intervals`, `moderator_roots_at`,
  `roster_reversal_stands`.
- `roster_head.rs`: `fold_disagreement`, `check_version_covers_fold`,
  `roster_lag`, `held_floor`, `admitted_at`, `answered_after`.
- About 25 callers read `authorized_community_roster_at`; each is listed
  under its own group below.

## 2. Counts

- `consensus.rs`: `eligible_seats`, `quorum_need`, `required_signatures(_at)`,
  `explain_refusal`, `evaluate_reference_over`, `evaluate_open_self_admit`,
  `OPEN_SELF_ADMIT_REMOVAL_FLOOR`.
- `mod.rs`: `verify_membership_quorum`, `group_prior_envelope`,
  `supersede_*_with_quorum`.
- `admission.rs`: `community_quorum_cosigned_at`, `community_quorum_at_head`,
  `roster_version_admits`, `appointment_stands_at`, `group_act_at`,
  `counted_group_of`, `counted_row_is_one_keys_act`,
  `check_counted_withdrawal`, `check_membership_keeps_counted`,
  `distinct_self_reporting_subjects` (B).
- `reverse_quorum.rs`: `count_distinct_roster_scrubs`,
  `count_distinct_voices`.
- `group_membership_change.rs`: `roster_from_envelope`,
  `quorum_threshold_from_envelope`, `validate_membership_change_structure`.
- `edition2/voices.rs`: `roster_voices`, `counted_roster_signers`,
  `row_voice_issuers`, `row_voices`, `primary_voice`, `floor_actor`.
- `tier_ingest.rs`: `verify_roster_cosignatures`.

## 3. Founders and the trust-root community

- `canonical_community.rs`: `founder_arm_at`, `check_founder(s)_eligible`,
  `founder_counts`, `conferred`, `resignations_of`, `resigned_within`,
  `withdrawal_instant`, `seated_since`, `founder_liveness`, `is_live`,
  `compute_standing`, `active_founders`, `verify_founders_link(_memo)`,
  `verify_chain(_memo)`, `verify_links_from`, `walk_from_held`, `held`,
  `holds_at`, stored and chain standing, `check_trust_root_roster_change`,
  `check_founding_margin`, `is_rebirth_over_stalled`,
  `accord_quorum_over_community`, `accord_quorum_at`,
  `count_over_trust_root` (B), `charter_in_force` (B),
  `live_charter_rows` (B), `witness_quorum_for` (B).
- `admission.rs`: `stored_founder_only_room`,
  `refuse_membership_event_under_founder_only`,
  `check_founder_only_escape`, the infrastructure founder checks
  (`check_infrastructure_founders_not_node`,
  `check_infrastructure_founder_count_unchanged`, conformance and degrade
  checks), the accord-holder roster and role checks (`accord_holder_roster`,
  `accord_threshold_now`, `verify_canonical_authority_over_roster`).

## 4. Invitation and acceptance

- `membership_acceptance.rs`: `check_growth_accepted`,
  `check_attestation_write_scope` (membership legs), `live_invitees_of`,
  `conflicts_with`, `opposite_reply_stands`, `reply_withdrawn`,
  `proposal_withdrawn`, `replies_of`, `replies_to`,
  `node_seated_without_acceptance`, `check_*founding_signers`,
  `check_supersede_adds_no_member`, `check_standing_proposal`,
  `check_proposer_under_founder_only`, `room_is_open`, the root-grant and
  officer acceptance readers.
- `public_room.rs`, `community_admit.rs`: the open self-admission door and
  its removal window.

## 5. Objections

- `reverse_quorum.rs`: `fold_reverse_quorum(_over)`, `escalate_objection`,
  `is_ballot_on`, `voices`, `tally`, `resolve_reverse_quorum_with`,
  `cohort_state`, `objections_against`, `vote_retractions`,
  `standing_votes`, the threshold functions, the dismissed / upheld /
  overruled builders and enums.

## 6. Two-path and holds

- `two_path.rs`: `decide`, `decide_all`, `decide_counts`, `resolve`,
  `check_corridor`.
- `cosign.rs`: `active_members_at`, `admit_row`, `execute_for`,
  `execute_due`, `window_secs`, `edition2_voices`, `act_retracted`,
  `held_equivalent`, `withdrawn_by_proposer`.
- `edition2/fold.rs`: `lapse_short_counted_rows`, `hold_window_secs`,
  `FinalPlane` / `is_final`, `final_hold_untriggered`, `never_retracts`,
  `held_primary`.

## 7. Persons and the self roster

- `key_person.rs`: all of `KeySelves`.
- `mod.rs`: `active_identit(y|ies)_for_occurrence`, `node_bearing_*`,
  `agreed_from_*`, `occurrence_agreed_*`, `community_node_bearing_seats`,
  `community_key_selves`, `family_key_selves`.
- `self_roster.rs`: `roster_now`, `is_roster_key_at`,
  `roster_assertion_live`, `acts_as_steward_at`, `genesis_evicted_*`,
  `self_of_at`, `answers_for`, `answer_rows`, `plan`, `standing`,
  `execute_for`, `execute_due`, `gate_edition2`, `roster_step`,
  `load_roster_graph`, `ancestors`, `roster_at_heads`, `roster_reading`,
  `void_for_reader`, `roster_at_head`, `current_head`,
  `check_roster_act_fresh`.
- `edition2/occurrence.rs`: `occurrence_seats_for`, the multi-row legs of
  `put_occurrence_voice`, `bind_xwing_keys_for`, `bind_relay_offer_for`,
  `own_voice_agreed_from`, proposer choice (`proposer_on_roster`,
  `lowest_voice_*`, `carried_of_bind`), `proposal_withdrawn`,
  `landing_statement`, `current_roster_heads`.
- `admission.rs`: `cohort_standing_core`, `check_cohort_standing_resolved`,
  `consenting_person` (B), `writer_principal` (B).

## 8. Heads

- `edition2/head_rule.rs`: `resolve`, `state_head`, `state_end_head`,
  `roster_head_row`, `owner_binding_row`, `delegation_row`,
  `roster_descends`, `require_end_head_current`.
- `edition2/group.rs`: `held_lineage`, `chosen_prev`, `load_chain`,
  `merge_reading`, `prev_head_digest`, `check_founding_uncontested`,
  `drop_merged_tips`, `forked_tip_members`, `check_membership_head`, the
  vouch transport (`Vouch`, `run_vouched`, `vouched_*`, `voices_of`,
  `supersede_proof`).
- `group_amendment.rs`: `prev_head_names_held` and the held-head verdict.
- `edition2/transport_rebind.rs`: `counted_holders`, `counting_voices`,
  `counts`, `rebind_counted`, `seeding_run`, `latest_counted_rebind`.

## 9. Trust root

- `edition2/trust_root_group.rs`: `holders_count(_at)`, `bundle_quorum_over`,
  `voices_before_successor`, `is_bundle_holder`, `bundle_holders`,
  `holders_in_force`, `holder_founder_counts_at`, `version_signers`.
- `edition2/genesis.rs` (persist side; the per-bundle reading is Verify's):
  `read_lineage`, `in_force_of`, `store_root_family`, `head_standing`,
  `tips`, `successor_instant`, `halt_roster`, `bundle_descends`,
  `named_bundle`, `bundle_head_in_force`, `held_voices`.
- `edition2/recovery_signer.rs`: all.
- `edition2/halt.rs` (persist side): `replay_fold`, `replayed_by`,
  `concluded_lifecycle`, `roster_in_force`, confirmed / active from
  `concluded_lifecycle`. The latch and fuse stay.
- `edition2/peer_rooting.rs`: `peer_rooting`, `root_arm`, `arm`,
  `attach_reading`.
- `trust_root.rs`: the multi-row body of `trust_root_valid`,
  `bundle_root_holders`, `chain_legs_of`, `direction_denied_ids`, the
  capability walk (`capability_roots_to_trusted_root*`, `conferred_for_act`,
  `live_conferral*`, `rotates_own_grant`, `owner_granted_scope`), the
  family charter quorum variants, transit eligibility
  (`resolve_transit_eligibility*`, `transit_eligibility_walk`),
  `tombstoned_ids`, the owner / acceptor readers (`governing_owner`,
  `acceptance_of`, `accepted_roots_of`, `bundle_root_accepted`,
  `trusted_roots_of`).
- `admission.rs`: `check_root_voice_signer`, `root_grant_reading`,
  `check_root_grant_counted`, `check_root_grant_withdrawal`,
  `root_grants_for`, `root_grant_of`.
- `precedence.rs`: `retired_ids` and its users.

## 10. Key plane

- `edition2/liveness.rs`: `judged`, `key_of_at_depth`, `possession_missing`,
  `co_statements_refused`, `rival_rotation`, `record_owner`,
  `is_accord_holder`, `honoured_at`, `in_effect`.
- `register.rs`: `fold_key_statement_standing`,
  `resolve_key_statement_standing`, `check_revocation_bound` (B).
- `admission.rs`: `check_revocation_authority`.
- `key_plane.rs`: `occurrence_withdrawal_of`, `occurrence_revoked_by`.
- `edition2/projection.rs`: `key_projection`, `projected_record`.
- `src/kernel/key_end.rs`: `within_record`, `end_rule`, the persist-side
  ordering around `key_live`.

## 11. Delegation and duties

- `admission.rs`: the delegation walk (`scoped_delegation_reach*`,
  `DelegationWalkLens`, `delegation_term_live_at`, `retracted_edge_ids`),
  licensure (`quorum_licence_reach`, `licensure_issuance_at`,
  `licence_roots_at`, `*_role_term_at`), steward and owner readers
  (`live_delegation_granter*`, `is_steward_bound`, `owner_*_in_force_at`,
  `agent_owner_*`, `may_act_through`, `nodes_owned_by`,
  `holds_grant_delegation`, `delegation_path_hops`), moderators
  (`is_named_moderator`, `moderators_of`, `appointed_moderators_of`,
  `moderation_reach_of*`, `check_moderation_admission`,
  `moderation_duty_roots`, `community_authority_set_for`), duties
  (`duty_holders_*`, `named_moderator_holders`, `first_duty_holder_voice`,
  `slash_act_decider`, `check_delegated_duty_scores_admission`,
  `duty_set_in_force` (B)), the withdraws rules
  (`check_withdraws_admission*`, `resolve_withdraws_admission_rule*`),
  `check_officer_appointment_counted`, the `admission:unit` count.
- `edition2/admission_unit.rs`, `edition2/receipts.rs` (`receipt_rule`,
  `trusted_services`): shut in v62 unless the crate answers them.
- `edition2/second_signer_voice.rs`: `held_rows_for`,
  `countersign_parties`; `edition2/door.rs`:
  `resolved_second_signer_roles`, `agent_owner`.

## 12. Affiliation

- `affiliation_config.rs`: `deciding_seats`, `check_one_voice_countersign`,
  `check_floor_act_withdrawal`, `standing_voices`, `floor_affiliation`.

## 13. Audience and wraps

- `replication_audience.rs`: the rule functions (`devices_of`,
  `owned_device_record`, `OwnerAllowLists`, `occurrence_may_hold_key`,
  `occurrence_may_hold_room_key`, `owner_nodes_receiving`,
  `audience_nodes`, `may_receive*`, `record_names_its_audience`).
- `key_grant.rs`: `recipient_may_hold_key`, `AudienceSnapshot`,
  `judged_by_emission_fold`, `is_active_member_at`, `may_issue_grant_for`,
  `check_sealer`, `stream_grant_row_instants`, `held_owner` re-judge.
- `community_dek.rs`: `active_member_occurrences`,
  `resolve_community_members`, `room_targets`, `seat_community_member`,
  `may_learn_epoch_fate`, the rotation rule in `ensure_epoch_dek_over`.
- `at_rest_cascade.rs`, `chunk_dag_cascade.rs`: `resolve_recipients`, the
  rekey paths, `member_holders`, `device_may_hold_room_key`,
  `stream_targets`, `stream_epoch_verdict`, `stream_grant_sealer`.
- `replication/hold.rs`: `audience_memberships`, `family_audience`,
  `is_audience(_of)`, `would_hold`.

## 14. Who is served

- `edition2/serve.rs`: `servable_to`, `servable_by_own_rule`,
  `this_node_is_rooted`, `rooted_for_serve`, `rooted_under`,
  `serve_standing`, `commons_servable`, `is_party_to_row`,
  `public_group_serves`.
- `edition2/group_serve.rs`: `servable_without_row`, `event_servable`,
  `cosign_servable`, `group_servable`, `served_to_floor_official`,
  `delivered_to_requester`, `carried_by_a_naming_row`.

## 15. Ownership

- `ownership_reclaim.rs`: all (shut in v62).
- `src/kernel/owner.rs`: the binding filters, synthesised withdraw rows and
  the rank table; `admission.rs::kernel_owner_selves` post-filters.

## 16. Purge, quarantine, age

- `steward_purge.rs`: `authorise_edition2_at`, `check_notice_window`
  (multi-row part), `check_counts`, `retraction_admissible`,
  `resolve_selection`, the tombstone standing and void rules.
- `quarantine.rs`: `fold_quarantine` and its readers.
- `age.rs`: the band fold and `duty_edge_void_for_minor` (waits on the
  crate; see the boundary in `PLAN.md`).
- `mesh_config.rs`: `fold_mesh_config`, `root_authorizes_author`,
  `root_quorum_reached` (shut in v62).

## 17. `src/kernel/` (persist's adapter)

About 1,100 of 2,000 lines: `consensus.rs` arm table, `ballot_rows`,
`admits_by_rows`, the short-circuits in `count_over`; `law.rs` `ARMS`;
`head.rs` `head_entries`; `trust.rs` and `owner.rs` rank tables;
`view.rs` `RowId::synthetic` / `of_label`; `differential.rs` whole.
Rewritten from the kernel's wire map.

## 18. Stores (sqlite and postgres)

Verdict-bearing state to remove: the live group row read as the head with
a persist-minted `version`; `federation_role_withdrawals`;
`consent_peer_set*` as a fold; the trust columns on `federation_keys`;
proposal `settled_at` / `outcome` columns; `federation_group_tips`;
`federation_withdraws_admission_depths`; `accord_active_halt` except the
latch. `federation_vote_windows.first_held_at` stays as the node's
first-held instant. `store/parity.rs` names the gates and is edited with
each deletion.

## 19. Placement chosen by constant

`hard_case.rs::hard_case_emit_input`; `key_plane.rs::minted_row`;
`key_grant.rs::emission_cohort_scope`; `group_plane.rs::plan_group_row`;
`community_dek.rs::emit_excluded_hard_cases`; `blobs.rs`
(`store_plaintext_local`, `put_blob_chunk`, `put_blob_signing`,
`emit_withdraws_attestation_helper`). Each takes its placement from the
family's row in the Constitution's placement table.

## Not built on the build line

Elections, duty seats, window rows, `regard:*`, the `officer` role,
`overseen_by`, the room node row's `refs.also.under` / `voice`,
`refs.further_prev` (B: the lane branches `wseat2`, `wroomkey6`, `wduty17`
may hold parts).
