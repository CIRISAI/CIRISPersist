# Host surface tied to rules that go

READ on the build line (`src/ffi/pyo3.rs`, `src/ffi/directory_capsule.rs`,
`src/engine.rs`). Line numbers are of the branch base. Nothing here is
decided: every removal, rename or new verb needs Eric, and no new method or
argument is added without him. The final list waits for the kernel's public
functions at the tag.

## Python methods

| Method | Line | Tied to |
|---|---|---|
| `cohort_add_member` | 23609 | roster growth under persist's standing rule |
| `cohort_revoke_member` | 23664 | removal; resignation; founder checks |
| `cohort_swap_member` | 23715 | both |
| `cohort_supersede_group`, `cohort_supersede_group_with_quorum` | 23778, 24024 | earlier-form supersede with cosign count |
| `cohort_group_at` | 23920 | group at a persist-minted version |
| `cohort_active_members_json`, `cohort_active_member_keys_json`, `active_community_members_json`, `active_family_members_json`, `list_families_for_member_active_json`, `list_communities_for_member_active_json` | 23430, 23474, 23312, 23355, 12482, 12527 | roster "as of now" |
| `add_moderator`, `remove_moderator` | 9202, 9264 | deletion already approved; replaced by the seat verbs |
| `moderators_of_json`, `is_named_moderator_json`, `check_no_moderator_federate_json` | 24128, 12667, 12741 | moderator standing |
| `resolve_reverse_quorum_json` | 3610 | objection fold, dismissals, steward tier |
| `self_roster_standing`, `execute_self_roster_due`, `self_roster_vote_envelope` | 24519, 24538, 24576 | device-roster proposals settled on the node clock |
| `purge_dry_run_json`, `purge_rows_json`, `purge_status_json`, `purge_finalize_json`, `apply_replicated_purge_json` | 13954 to 14079 | steward purge |
| `owner_of_json`, `steward_bindings_of_json`, `nodes_stewarded_by_json`, `steward_binding_chain_json`, `serve_seat_owner_announced` | 24840, 24183, 24914, 24954, 24879 | ownership and stewardship readings |
| `steward_bind`, `steward_bind_incapacity`, `grant_delegation`, `revoke_delegation` | 8860, 9145, 8810, 9236 | delegation rows (producers; likely stay, re-pointed) |
| `trust_root_verdict_json`, `delegates_to_graph`, `delegations_to_json` | 3224, 23263, 25217 | delegation chain readings |
| `federation_revoke_trust` | 16668 | trust column revoke |
| `signer_standing`, `amendment_standings_json`, `resolve_key_statement_standing_json`, `serve_standing_json` | 7265, 7416, 3306, 6610 | standing readings |
| `set_active_halt`, `get_active_halt_json`, `clear_active_halt` | 12126, 12151, 12173 | halt state |
| `seat_community_member_json`, `rekey_family_member_add_json` | 24429, 24327 | key grants driven by membership |

## Capsule ops

`AddCommunityMember`, `AddFamilyMember`,
`Put{Community,Family}Membership{Revocation,Widening}`, `SupersedeGroupRow`,
`ListGroupTips`, `TrustRootValid`, `CapabilityRootsToTrustedRoot`,
`BuildDelegationGraph`, `ReachableUnderScope`, `ResolveEncryptionKeys`,
`ResolveTransitEligibility`, `CommunitiesContaining`, `LookupRoleWithdrawal`,
`LookupCanonicalWithdrawal`, `ListCanonicalWithdrawals`,
`VoteWindowFirstHeld`, `Get/Set/ClearActiveHalt`,
`ListSettledSelfRosterProposals`, `ListSettledEdition2RosterProposals`,
`Edition2RosterProposal`, `KeyGrantHeldOwner`, `ListLiveConsentGrantsBy`,
`ServeStanding`, `PurgeTombstoned`, `PurgeTombstoneNotices`,
`WithdrawsAdmissionDepth`, `WithdrawsDelegationDepth`,
`ListOwnerBindingsSince`.

## Already approved (by the Constitution session in Eric's stead, reversible)

Nine seat verbs on Rust, Python and capsule; deletion of `add_moderator`
and `remove_moderator`. To be re-confirmed with Eric at resume.

## Not in code

`history_on_join` and `membership_public_to_private` have no behaviour on
the build line (a comment and a vocabulary entry).
