# From-disk gates

A from-disk gate is a test that reads source files while it runs (`std::fs::read_to_string` under `CARGO_MANIFEST_DIR`, or `include_str!` of a `.rs`/`.sql` file) and asserts something about their text: a call is made at every door, a name is never spelled, two dialects declare the same columns. CIRISPersist#1026 starts moving the countable ones to [ast-grep](https://ast-grep.github.io) rules, which match the syntax tree.

Two lessons drive the port:

- **From-disk counts must strip comments.** A commented-out call once passed a text count. Every text gate has to strip comments (and often string literals) by hand, and each does it differently. An ast-grep rule matching `call_expression` cannot match a comment or a string by construction.
- **Shared `CARGO_TARGET_DIR`: from-disk gates scan the main checkout.** A test binary built in one worktree and reused from another read the other tree's sources. `scripts/ast_gates.sh` scans `CARGO_MANIFEST_DIR` when it is set, else the toplevel of the checkout it is run from, refuses a root without `sgconfig.yml`, and prints the root it scanned. Every Rust from-disk gate reads `env!("CARGO_MANIFEST_DIR")` of the crate under test, never a fixed path.

## How the ported gates run

| piece | what it does |
|---|---|
| `sgconfig.yml`, `rules/*.yml` | One rule per ported count. Each rule names its files explicitly (no globs). Its file name is its id. |
| `rules/expected.json` | The exact per-file match count of every rule. A `0` is a claim too: the file must hold no match. |
| `scripts/ast_gates.sh` | Runs `ast-grep scan --json` (ast-grep 0.45.3, pinned, sha256-checked download into `~/.cache/ciris-ast-grep`, or `AST_GREP=`). It compares counts with `expected.json` in both directions: a rule without expectations, expectations without a rule, a rule file list that differs from its expected files, a missing file, or any differing count is red. Exit 0 green, 1 red, 2 usage or bad root, 3 tool unavailable. A certify fast gate (`astgates`) and a CI `lint` step. |
| `src/ast_gate_parity.rs` | Counts the same call sites by text, with comments and string contents blanked, and holds them equal to the same `expected.json`. The AST count and the text count therefore agree through one committed file. A call ast-grep cannot see, such as one inside a macro's token tree, shows up as a disagreement instead of a silently lower count. |

Each ported gate keeps its original Rust witness for one release (issue step 3). The Rust text scan is deleted once the AST rule has carried a release.

### Ported (v53.2.0)

| rule | original gate | counts | expected |
|---|---|---|---|
| `i110-check-consent-scope-tokens` | `consent_scope_invariants.rs::i110_one_matcher_every_door` (≥ 2/2/2/1) | calls of `check_consent_scope_tokens` in sqlite, postgres, memory, admission | 2/2/2/1 exactly |
| `i119-check-media-source` | `media_source_invariants.rs::i119_every_door_and_the_vocabulary` (≥ 2/2/2/1) | calls of `check_media_source`, same four files | 2/2/2/1 exactly |
| `i448-prev-head-check` | `lineage_head_invariants.rs::i448_every_backend_runs_the_prev_check_on_both_arms` (== 2 per backend) | calls of `check_prev_head_names_held` inside `fn supersede_group_row`, three backends | 2/2/2 |
| `scores-read-log` | `scores_read_audit.rs::all_six_scores_read_sites_log` (1 per site, 6 sites) | calls of `log_scores_read` inside `fn list_scores` / `fn resolve_scores`, three backends | 2/2/2 |
| `i26-cached-content-master` | `blob_surface_gates.rs::i26_backends_resolve_the_content_master_through_the_cache` (cached ≥ 1) | calls of `resolve_persisted_content_master_cached`, sqlite + postgres | 1/1 |
| `i26-uncached-content-master` | the same test (uncached == 0) | calls of `resolve_persisted_content_master`, sqlite + postgres | 0/0 |

The AST rules count exactly where several Rust gates assert a minimum (`>=`), so they are the stricter of the two. The Rust gates' other legs stay in Rust: I448's field checks, `scores-read-log`'s per-site variant name and its log-before-gate order, and I110's vocabulary-literal checks.

Mutation results (v53.2.0, 12 + 3): for each rule, a commented-out copy of the call (line and block comment) placed in the counted scope left both counts unchanged and green. Deleting the call (renaming it on disk) made both `ast_gates.sh` and the parity test red. For I26, turning the cached call into the uncached one made both rules red. Three more mutants were also red: an expected entry removed, a glob in a rule's `files:`, and `CARGO_MANIFEST_DIR` pointed at another checkout (refused, exit 2).

## Inventory (v53.2.0)

Classes:

- **AST-COUNT**: counts call sites, path mentions or definitions of a named item. A single ast-grep pattern counts it.
- **AST-STRUCT**: a structural property, such as "fn X's body calls Y before Z" or "every fn in a list calls W". AST-able with relational rules (`inside`, `has`, `precedes`), but larger than a count.
- **TEXTUAL**: asserts on SQL strings, migration bytes, doc prose, string-literal content or byte digests. These stay textual. ast-grep would only see an opaque string.
- **not a gate**: reads a JSON or SQL file as data.

| file | test | inv. | scans | asserts | class |
|---|---|---|---|---|---|
| ceg/list/drive_query_invariants.rs | i143_the_chunk_adopt_reaches_python | I143 | ffi/pyo3.rs, ffi_taxonomy.tsv | `fn adopt_sealed_chunk_json(` defined; tsv names it | AST-COUNT + TEXTUAL |
| federation/accord_roster_invariants.rs | i450i_genesis_runs_the_coverage_rule | I450i | genesis/ceremony_verify.rs | `check_family_record` calls `charter_commitments_cover(` and propagates | AST-STRUCT |
| federation/admission.rs | trust_plane_ops_are_classified_and_their_gates_resolve_721 | #721 | admission.rs, emit.rs | each TRUST_PLANE_OPS gate has a `fn` | AST-COUNT (def, data-driven) |
| federation/blob_surface_gates.rs | i8_every_lifecycle_op_is_reachable_from_engine_and_ffi | I8 | engine.rs, pyo3.rs | 17 symbols named in both | AST-COUNT |
| 〃 | i13_ffi_blob_bindings_route_errors_through_blob_err_to_py | I13 | pyo3.rs | a fn naming a cascade symbol also calls `blob_err_to_py` | AST-STRUCT |
| 〃 | **i26_backends_resolve_the_content_master_through_the_cache** | I26 | sqlite.rs, postgres.rs | cached ≥ 1, uncached == 0 | AST-COUNT — **ported** |
| 〃 | i30_python_sweep_report_carries_every_field | I30 | community_dek.rs, pyo3.rs | every SweepReport field as a JSON key literal | TEXTUAL |
| 〃 | i54_every_cascade_serializer_carries_the_roster_partition | I54 | pyo3.rs | 5 bodies carry 4 JSON key literals | TEXTUAL |
| 〃 | i14_the_storage_floor_has_no_door | I14 | all src | no floor-method calls outside an allowlist | AST-COUNT (== 0 outside allowlist) |
| 〃 | i36_the_transfer_path_never_decrypts | I36 | engine, sqlite, postgres | serve bodies call no decrypt | AST-STRUCT |
| 〃 | i45_the_adopt_path_never_decrypts | I45 | adopt_cascade, engine, backends | 21 bodies call no decrypt | AST-STRUCT |
| 〃 | i288_every_stream_chunk_delete_clears_its_counters | I288 | sqlite, postgres | fn with `DELETE FROM …stream_chunks` names the epoch-count table | TEXTUAL (SQL) |
| 〃 | i46_the_will_decision_has_one_home_and_every_accept_door_runs_it | I46 | adopt_cascade, engine, all src | 4 doors call `would_hold(`; one home | AST-STRUCT + AST-COUNT |
| 〃 | i48_would_hold_and_the_adopt_path_consult_no_serve_tier | I48 | hold, adopt_cascade, engine | 7 bodies never name the serve tier | AST-STRUCT |
| 〃 | i49_is_proxy_content_is_the_one_classification | I49 | engine, hold, all src | 3 bodies call `is_proxy_content(`; no rival | AST-STRUCT + AST-COUNT |
| 〃 | i90b_every_serve_door_routes_through_the_one_disposition | I90b | engine.rs | disposition check before `.get_blob(` | AST-STRUCT |
| 〃 | i53_no_privacy_overclaim_in_the_blob_and_replication_text | I53 | replication/**, FSD .md | no overclaim words | TEXTUAL |
| federation/canonical_community_invariants.rs | i190_f_ci_preflight_gates_the_bundle_quorum | I190(f) | ci.yml | CI runs the preflight | TEXTUAL |
| federation/capacity_consent_invariants.rs | i548e_one_fold_every_door | I548e | admission, engine, pyo3 | gate/Engine/PyO3 bodies call `capacity_consent_stance(` | AST-STRUCT |
| federation/chunk_dag_cascade.rs | the_whole_read_door_passes_the_cap_constant | I35 | chunk_dag_cascade.rs | body names `DAG_WHOLE_READ_CAP_BYTES` | AST-STRUCT |
| federation/claim_signing_invariants.rs | i89b_both_announcing_doors_route_to_the_shared_predicate | I89b–d | engine, pyo3 | doors call `check_announcing_signer(`; preflight follows | AST-STRUCT |
| federation/consent_by_humans_invariants.rs | i94b_i98_one_helper_one_rule_every_door | I94b, I98 | admission, consent_by_humans, pyo3, engine | 3 fns call `user_identity_anchors_of(`; one `combine_principal_stances` | AST-COUNT + AST-STRUCT |
| federation/consent_scope_invariants.rs | **i110_one_matcher_every_door** | I110 | consent_scope, consent, types, admission, backends | one `covers`; kind literals once; `check_consent_scope_tokens(` per door | AST-COUNT — **calls leg ported**; literal legs TEXTUAL |
| federation/durability_invariants.rs | i419_the_bytes_plane_has_no_publish_own_cell | I419 | namespace/mod.rs | FountainContent arm never yields `Projection::SelfOwn` | AST-STRUCT |
| federation/epoch_minter_invariants.rs | i130_one_derivation_for_every_minter_writer | I130 | 7 files | `epoch_minter::resolve(` etc. present/absent | AST-COUNT + AST-STRUCT |
| federation/family_rules.rs | pinned_sites_resolve_to_a_definition_in_source | #590 | all src | each enforced_at site has a `fn` | AST-STRUCT (def lookup) |
| 〃 | every_admission_shaped_prefix_literal_is_classified | — | all src | family-shaped string literals classified | TEXTUAL |
| federation/genesis/mod.rs | the_test_ceremony_seam_is_fenced_973 | #973 | genesis/mod.rs, test_ceremony.rs | 8 items `#[cfg(feature = "test-anchor")]`; call count == 3 | AST-STRUCT + AST-COUNT |
| 〃 | the_community_birth_lives_in_the_bundle | T5 | genesis/mod.rs | no `include_str!` of the community seed | AST-COUNT (== 0) |
| 〃 | no_src_code_mutates_the_anchor_environment_738 | #738 | all src | no `set_var`/`remove_var` of 4 anchor vars | AST-COUNT (== 0) |
| federation/held_settle_invariants.rs | i235_every_replicated_door_settles_first | I235 | backends | each door calls `settle_if_held(` first | AST-STRUCT |
| federation/holder_claim_index_invariants.rs | i114_every_attestation_insert_site_runs_the_index_hook | I114 | sqlite, postgres | fn with `INSERT INTO federation_attestations` calls the hook | TEXTUAL (SQL anchor) |
| federation/key_grant_invariants.rs | i59_key_grant_is_the_sixteenth_kind_with_the_stated_policy_row | I59 | WIRE_VOCABULARY_KINDS.md | doc names KeyGrant | TEXTUAL |
| 〃 | i67_no_production_delete_on_the_grant_tables_outside_destroy | I67 | sqlite, postgres, blobs | one `DELETE FROM …member_grants` | TEXTUAL (SQL) |
| 〃 | i69_every_python_write_door_emits_the_key_grant_set | I69 | pyo3.rs | 5 doors emit the key-grant set | AST-STRUCT |
| 〃 | i72_both_adopt_doors_project_pending_content_grants | I72 | adopt_cascade.rs | 2 doors call `project_pending_content_grants(` | AST-STRUCT |
| 〃 | i78_occurrence_plane_lists_signed_put_rows_only | I78 | sqlite, postgres | SQL has `attesting_key_id IS NOT NULL` | TEXTUAL (SQL) |
| 〃 | i66e_every_dek_plane_door_resolves_the_sentinel_first | I66e, I68 | engine.rs | 16 doors call `ensure_minter_sentinels_resolved()` | AST-STRUCT |
| federation/key_rebind_invariants.rs | i103_one_rule_every_door | I103 | register, backends, pyo3, engine | one `ReplicatedKeyPlan::Rebind` arm; mirrors delegate | AST-COUNT + AST-STRUCT |
| federation/lineage_head_invariants.rs | **i448_every_backend_runs_the_prev_check_on_both_arms** | I448 | backends | 2 `check_prev_head_names_held(` in `supersede_group_row` | AST-COUNT — **ported** |
| federation/load_bearing.rs | nothing_yields_anti_entropy_satisfied_today | #564 | all src | nothing constructs `AntiEntropy::Satisfied` | AST-COUNT (== 0) |
| federation/media_source_invariants.rs | **i119_every_door_and_the_vocabulary** | I119 | backends, admission, envelope | `check_media_source(` per door | AST-COUNT — **ported** |
| federation/mesh_config.rs | the_doc_counts_match_the_registry | #602 | mesh_config.rs | prose key count == `ALL.len()` | TEXTUAL |
| federation/namespace/supersets.rs | evidence_cc_impl_pointers_resolve | #519 | cc_impl.tsv + cited files | each path#symbol defined | AST-STRUCT (def lookup) |
| 〃 | evidence_cc_impl_rows_pin_the_current_crate_version | #577 | cc_impl.tsv | 172 rows pin the version | TEXTUAL |
| 〃 | verify_pin_major_matches_the_wheel_requires_dist | — | Cargo.toml, pyproject.toml | verify majors agree | TEXTUAL |
| 〃 | every_cited_processor_has_a_non_test_caller | #543 | all src | each cited fn has a non-test caller | AST-COUNT (≥ 1, data-driven) |
| 〃 | every_pointer_read_is_discriminator_guarded | — | all src | pointer reads guarded within ±30 lines | TEXTUAL (window, SQL) |
| 〃 | manifest_absence_claims_still_hold | #586 | all src | claimed-absent symbols undefined | AST-STRUCT (def lookup) |
| federation/occurrence_principal_invariants.rs | i125_no_unordered_limit_one | I125 | sqlite, postgres, hold | SQL has `ORDER BY … DESC` | TEXTUAL (SQL) + AST-STRUCT |
| federation/replication/admission.rs | every_quota_constant_is_derived | #583 | replication/admission.rs | each quota const documents its bound | TEXTUAL (doc) |
| federation/replication/mod.rs | the_retired_depth_knob_stays_retired | #748 | all src | no `recursion_depth` | AST-COUNT (== 0) |
| federation/roster_head_invariants.rs | i458_every_door_runs_its_consequence | I458 | 4 files | coverage check before `supersede_group_row(` | AST-STRUCT |
| federation/row_type_invariants.rs | i378_the_gate_is_wired_at_every_door | I378 | backends, admission, emit, row_type | `admit_row_type` right after binding | AST-STRUCT (+ TEXTUAL) |
| federation/scores_read_audit.rs | **all_six_scores_read_sites_log** | — | backends | one `log_scores_read(` per site, before the gate | AST-COUNT — **count ported**; order leg AST-STRUCT |
| 〃 | the_redaction_token_is_reserved_and_unwired | CC 3.4.5 | all src | no other file names the token | AST-COUNT (== 0) |
| federation/self_collective_invariants.rs | i140_the_doors_reach_python_and_no_claim_was_added | I140 | pyo3, types | 4 `fn …_json(` defined | AST-COUNT + TEXTUAL |
| federation/types.rs | every_closed_vocabulary_const_is_in_its_all_686 | #686 | types.rs | consts == their `ALL` arrays | AST-STRUCT |
| 〃 | every_delegation_scope_const_is_classified | — | all src | scope-like consts classified | AST-STRUCT |
| ffi/directory_capsule.rs | directory_op_wire_contract_is_pinned_682 | #682 | directory_capsule.rs | sha256 of two enum bodies pinned | TEXTUAL (digest) |
| ffi/pyo3.rs | no_sync_signing_verb_is_called_from_persists_own_tree | #620 | all src | no `call_method("local_sign")` | AST-COUNT (== 0, string arg) |
| 〃 | no_block_on_reaches_the_pyo3_boundary_holding_the_gil | #580 | pyo3.rs | every `block_on(` inside `py.detach` | AST-STRUCT |
| observe/tests.rs | i551_every_emitted_label_is_catalogued_… | I551 | all src | `observe::Door::X` mentions == catalogue | AST-COUNT (path set) |
| 〃 | i551_each_backend_records_under_its_own_label | I551 | backends | own `StoreBackend::` only | AST-COUNT |
| scope/sql.rs | every_attestation_door_composes_the_dimension_aware_predicate | #889 | sqlite, postgres | predicates composed near literals | TEXTUAL (window) |
| store/crypto_cardinality.rs | every_crypto_column_declares_its_natural_key_789; trace_events_no_longer_carries_per_event_crypto_789 | #789 | migrations | SQL markers | TEXTUAL (SQL) |
| store/migration_immutability.rs | shipped_migration_bytes_never_change, the_pinned_checksums_…, no_migration_after_v144_uses_subsec, the_bookworm_witness_…, the_subsec_modifier_appears_in_no_source_but_this_file, emit_migration_checksum_manifest | #840, #845 | migrations, scripts | bytes, checksums, SQL modifiers | TEXTUAL |
| store/parity.rs | every_propagated_call_in_a_door_is_classified, no_call_class_is_stale, every_backend_runs_the_same_gates_in_the_same_order, no_declared_divergence_is_stale, the_scan_is_not_vacuous | #670 | backends + 3 | per-door gate sequences | AST-STRUCT |
| 〃 | no_backend_source_uses_raw_strings | — | backends | no `r#"` | TEXTUAL |
| 〃 | no_backend_file_hand_rolls_the_seal | #643 | backends | `sign_envelope` only in one test fn | AST-COUNT (per fn) |
| store/postgres.rs | no_attestation_id_is_parsed_as_a_uuid | #622 | postgres.rs | no `Uuid::parse_str` of an attestation id | AST-COUNT (== 0, heuristic) |
| 〃 | every_postgres_test_goes_through_the_provisioner | — | all src | no direct env read of the PG URL | AST-COUNT (== 0) |
| store/schema_parity.rs | 5 DDL parity tests; the_insert_recognizer_…_758; a_column_one_dialect_omits_…_656 | #656, #758 | migrations, backends | DDL/INSERT agreement | TEXTUAL (SQL) |
| store/sqlite_conn_model.rs | 4 conn-class tests; no_production_line_in_sqlite_rs_locks_a_connection_directly | I4 | sqlite.rs | connection discipline per fn | AST-STRUCT; last one AST-COUNT |
| verify/canonical.rs | i295_one_serde_jcs_in_the_lock | I295 | Cargo.lock | one serde_jcs | TEXTUAL |
| observe/tests.rs | i552_… | I552 | telemetry/catalog.json | JSON vs catalogue | not a gate (data) |
| genesis/bundle.rs, genesis/mod.rs (3), mesh_config.rs, row_type_invariants.rs (I379), scores_read_audit.rs (#724), supersets.rs (SUPERSETS_JSON), store/memory.rs (#490), tests/trace_crypto_cardinality_migration.rs (2) | — | — | JSON fixtures / migrations | read as data | not a gate |

## Follow-up (not in v53.2.0)

- **Next AST-COUNT ports:** I14, the `== 0` guards (#738, #564, #748, CC 3.4.5, #620, #622, the PG provisioner gate), I551's path-mention set, I98's single definition, I103's single arm, I8's 17 symbols, `no_backend_file_hand_rolls_the_seal`, `no_production_line_in_sqlite_rs_locks_a_connection_directly`. Each needs a rule, an `expected.json` entry and a `PORTED` row in `src/ast_gate_parity.rs`.
- **AST-STRUCT gates** (I13, I36, I45, I46, I48, I49, I90b, I548e, I89b, I235, I458, I378, I66e, I69, I72, #580, the parity and sqlite_conn_model families) need relational rules (`inside`, `has`, `precedes`) and a way to express "every fn in this list". Port them after the counts.
- **Delete the Rust text scans** of the six ported gates in the release after v53.2.0, once the AST rules have carried a release (issue step 3). Keep `src/ast_gate_parity.rs` until then.
- **TEXTUAL gates stay textual.** SQL strings (supersets' pointer guard, I114, I288, I67, I78, I125, the schema-parity and migration families), doc prose (#583, #602, I53, I59), byte digests (#682) and lockfile checks (I295) are about text, not syntax.
