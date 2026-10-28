# v60.0.0 — task plan: the free migrations, the backend refactor, and one mutation discipline

v60.0.0 has shipped. This is the plan it was built from, kept because scope files, workflows
and source comments cite its sections. Two parts of it are standing rules: §3 (the mutation
discipline, now documented in [MUTATION_TESTING.md](MUTATION_TESTING.md)) and §6 (process
rules, which the v61 plan extends). The next release's plan is
[V61_TASK_PLAN.md](V61_TASK_PLAN.md).

v60 is the refactor cut. The planes with no external consumer yet move onto `scores` rows
first, because they are free to move now and would otherwise have to be consolidated by the
refactor. Organisations as affiliations (#1036) is in.

## 0. The target (CEWPOS)

CEWPOS states the end state the substrate converges on
([WHY.md](https://github.com/CIRISAI/CEWPOS/blob/main/WHY.md),
`CEWPOS_ATTESTATION_CALCULUS.md`): **signed attestations are the only state**; semantics are
the closed set of five structural operators (`scores` + `delegates_to` / `supersedes` /
`withdraws` / `recants`); the system grows by vocabulary, never by new primitives; the corpus
is append-only, signed, federated and content-addressed. For persist that means two debts, and
v60 pays both down:

1. **Typed state that is not a row.** Before v60, 13 of 18 replication kinds were typed objects
   with their own tables and wire framing; each is a second primitive.
2. **One trait written three times.** 250 `FederationDirectory` methods, most implemented once
   per backend across sqlite, postgres and an in-process memory backend. The defect class
   "green on memory, red on sqlite/postgres" was the most-recorded in the repo.

CEWPOS's CSD/4 catalogue (`CSD4_CATALOGUE_AND_MIGRATION_PLAN.md`) keys CSD-120, -123 and -126
(affiliations, partners, affiliation keys) on affiliation ROWS, not on the `organizations` /
`partner_records` tables, which is why #1036 item 4 is in this cut.

## 1. Baselines (v59.1.0)

| measure | value |
|---|---|
| backend files | 134,737 lines (sqlite 56,003 / postgres 53,130 / memory 25,604) |
| `FederationDirectory` methods | 250 (95 with a default body) |
| shared plans (`plan_*`) | 19 |
| replication kinds | 18 live; 4 retired framed (key plane) |
| witnesses | 664 distinct I-numbers; 88 `*_invariants.rs` files |
| scheduled mutation scopes | 3 (`scope-consent-gate`, `scope-observe` ×2 shards, `scope-observe-sites` weekly) |
| certify wall (1 lane) | 3253 s |
| last migration / witness | V201 / I1160 |

v60 numbering: migrations from **V202**, witnesses from **I1161**.

## 2. Order and ownership

One builder at a time, each slice on its own branch from the previous slice's head, integrated
onto `release-60.0.0`. Each slice's brief is self-contained.

| # | slice | tickets | kind |
|---|---|---|---|
| S0 | small fixes + the mutation discipline | #1112, #1109, #1111 | fixes |
| S1 | `cirisnode.*` silos onto `scores` | #988 item 1, #803, #854 | free migration |
| S2 | goals onto `goal:{scale}` | #988 item 4 | free migration (Edge drops 2 message types) |
| S3 | key-record write doors on one plan | #934 step 3 remainder | refactor |
| S4 | consent and sweep planes on one plan | #934 step 4 | refactor |
| S5 | retire `memory.rs` onto sqlite in-memory | #1002 (+ #679, #681, #691, #720, #722, #787) | refactor |
| S6 | organisations as affiliations | #1036 (all five items), #1049, #1062, #1048 | migration + feature |
| S6v | vendor CC v1.0-rc9 at the tag (CIRISConstitution#182) | registry re-vendor; the chain, governance-policy and vocabulary fixtures become runtime manifests; `check_corridor` at admission from the policy table | vendor |
| S7 | release: evidence, CHANGELOG, Edge adoption, chain | — | — |

Not in v60, by decision: #1004 (the workspace split; it needs the plan/execute line S3–S5
draw), #991 planes 2–3 (`group:roster:v1`, the membership rows, general `cosignatures[]`),
#1098 / #1100 / #1101 (CC conformance work on doors S4–S6 move; cheaper written once on the
shared plan), the retirement program (#1079–#1088). Downstream asks raised during the cut became
tickets; they are scheduled in [V61_TASK_PLAN.md](V61_TASK_PLAN.md).

## 3. The mutation discipline (S0, then every slice)

Every slice runs its mutation round through the repo's one gated matrix (`scripts/mutants.sh`,
`scripts/mutants/scope-*.txt`, `scripts/mutants_matrix.py`, `allowed_survivors.txt`), so the
results can be re-run and the scheduled matrix learns every new site.

1. **Every slice ships its mutation set as a scope file**, `scripts/mutants/scope-<slice>.txt`:
   a `tests:` filterset naming the slice's witnesses, and the files (for files over a few
   thousand lines, the functions) the slice touched. The matrix (`matrix.json`,
   `verdict.txt`, `unvalidated.txt`) is the handoff's mutation table, by path. No ad-hoc
   mutation scripts; `scripts/mutants.sh cargo-mutants <scope>` is the one runner, through
   `cargo_guard.sh`.
2. **A slice is green only when its scope's verdict is exit 0**: every mutant caught, or
   allow-listed with a tracking issue, and `unvalidated.txt` empty (a witness that kills
   nothing is a witness about a neighbouring gate). Exit 3 means shard it, not shrink it.
3. **The new scopes join the scheduled matrix** (`.github/workflows/mutants.yml`),
   budget-fitted and sharded; the weekly run takes the heavy ones.
4. **The PR gets a diff-scoped report**: `scripts/mutants_diff.sh <base>` runs in the
   `reports (non-gating)` workflow on every `release-*` PR, so "which changed line can be
   mutated with no test noticing" is answered for the whole diff, not only the chosen sites.
5. **One backend column fewer**: with the memory backend retired (S5), a mutant is tested on
   sqlite and postgres.

**S0 deliverables:** the seven `src/observe` survivors killed with witnesses (#1112, no
allow-list entries); the slice rule and scope-file template in `docs/MUTATION_TESTING.md`; the
`mutants_diff.sh` step on `release-*` PRs; and `scripts/mutants_scopes_check.py`, a from-disk
check that every `scope-*.txt` resolves, every `tests:` filter matches at least one test and
every allow-list line carries an issue (a certify fast gate beside `mutmatrix`, and CI).

## 3b. CSD/4 as the key for persist's testing, QA and mutation scopes

**The manifest** (CIRISClient `packaging/csd4/`, from CIRISServer#802's release assets,
sha-pinned in `tests/fixtures/csd4/PIN.md`):

- `topology_vocabulary.json`: 110 atoms, each `{plane, state_predicate, cc_ref,
  in_state_table, meaning}`. The vocabulary is the Constitution's
  (`manifests/topology_vocabulary.json`); the client holds a byte copy and a pin.
- `traces.json`: the twenty topologies T0–T19 from Server's `harness.native` model, each a list
  of steps `{id, atoms}` with `promises` and a `refused` map.
- `requirements.yaml`: per CSD, the topology it names and its tests as `{at: [atoms], probe:
  {node, path, status, expect}}`.

**What persist keys to.** The atoms, the trace steps and their refusal maps, which are
CC-owned and pinned, never a card's `shows:` tags (UI contracts). The chain back to the formal
models runs atom → `cc_ref` → CC claim id → persist evidence row → witness → mutation scope.
CC publishes that chain as data, `manifests/csd4_chain.json`: per atom, `states[]` with the
formal `model_ref`, `invariants[]`, `claims[]` with parsed evidence refs, and `refusal_tokens`
by section; `_meta.pins` carries the sha256 of the state table, the invariants, the
vocabulary, `claims.tsv` and `evidence_pins.tsv`. Persist vendors it as
`src/federation/namespace/csd4_chain.json`.

**Tasks.**

- **S0-csd:** the csd4 assets vendored byte-for-byte with their pin into
  `tests/fixtures/csd4/`, and `scripts/csd4_coverage.py`: a from-disk join of atoms
  (`cc_ref`) ⋈ CC `claims.tsv` ⋈ `evidence/cc_impl.tsv` ⋈ the `*_invariants.rs` witnesses
  and `scripts/mutants/scope-*.txt`, plus every `refused` token in `traces.json` ⋈ persist's
  `kind()` / reason tokens. It lists every atom and refusal token with no persist witness, no
  mutation scope or no token behind it. Report-only (`reports (non-gating)`, see
  [TOOLING.md](TOOLING.md)); it becomes a gate once CC's join data covers it.
- **S7-trace:** replay the substrate half of each T0–T19 step at persist's doors on sqlite and
  postgres, asserting each atom's `state_predicate` through persist's own reads and each
  step's `refused` tokens exactly. Each topology becomes one witness and one mutation scope
  named for the promise it protects (`scope-t<nn>-<name>.txt`).
- **Rule going forward:** a new door's witness names the atom(s) it realises in its doc
  comment; `csd4_coverage.py` reads them, so a door no atom reaches is visible, and an atom no
  door realises is a persist gap by name.

## 4. The slices

### S0 — small fixes (#1109, #1111) and #1112

- **#1109** `admission::nodes_owned_by` seeks candidates among the self's live roster keys
  (through `self_of_at`, the predicate `owner_of` uses), so a device joined by approval and
  announced with its roster key `<fedID>-<fp>` is placed. Witness I1161 on sqlite and
  postgres.
- **#1111** test-anchor seam on W_self: under `feature = "test-anchor"` AND the runtime
  override active (the existing fence and production tripwire), `CIRIS_TEST_W_SELF_SECS`
  replaces `W_SELF_SECS` in `self_roster::policy()`. A non-test-anchor build ignores it
  (from-disk check). Witness I1162.
- **#1112** as in §3.
- Mutation scope: `scope-s0-roster-seam.txt` and the fixed `scope-observe`.

### S1 — `cirisnode.*` onto `scores` (#988 item 1, #803, #854)

CC 3.1.9 registers each class as a dimension.

| table (V011/V012/V054) | becomes | fate of the table |
|---|---|---|
| `contributions` | the CC 2.1 Contribution itself: the `scores` row | dropped |
| `votes` | `vote:{contribution_id}` rows | dropped |
| `moderation_events` | `moderation:{allegation_type}` rows | dropped |
| `slashing_attestations` | `slashing:{outcome}` rows | dropped |
| `reconsideration_requests` / `_attestations` | `reconsideration:{grounds}` rows (the subject-standing rule applies) | dropped |
| `credits_ledger`, `expertise_ledger` | projections of `credits:…` / `expertise:…` rows, byte-equal rebuildable | kept as projections with `attestation_id` FK |
| `takedown_notice` | `takedown_notice:{basis}:v1` `scores` row (#803); `LegalBasis` spellings in CC's closed vocabulary (`dmca512`, `dsa_article16`), V202 rewriting the V054 CHECK and rows | — |
| `scheduled_takedown_actions`, `promotion_attestations` | local bookkeeping | unchanged |
| `federation_delivery_attestations` | local (a receipt) | unchanged |
| `key_grant` subject_kind | retired (duplicates the key-grant plane) | refused by name |

Every row carries hybrid PQC signatures; the Emit/Ingest subject gate is one gate on canonical
subject ids (#854); the `cirisnode` Python surface keeps its method names as thin wrappers that
plan rows; a typed cirisnode object offered on the wire is refused. Witnesses I1166–I1172;
`scope-s1-cirisnode.txt`.

### S2 — goals onto `goal:{scale}` (#988 item 4)

The declarer's signed `scores` row on `goal:{scale}` IS the Goal; `goal_id` is its
`attestation_id`; `MetaGoalAlignment` is an admission gate on the family; amendment is
`supersedes`, retirement `withdraws`, "never mine" `recants`; the `goals` table (V050) is a
projection (`attestation_id` FK, byte-equal rebuild). The admission tokens are CC 3.1.9.7's
(`goal_meta_alignment_malformed`, `goal_body_malformed`, `goal_typed_object_retired`).
Witnesses I1174–I1182; `scope-s2-goals.txt`.

### S3 — key-record write doors on one plan (#934 step 3, the remainder)

The key-record write doors (`put_public_key`, seed, scrub upgrade, canonical supersede, rebind
/ invalid-replace, reanchor, PQC completion, scrub rehydrate, peer removal) decide in one
function, `key_plane::plan_key_record_write(dir, input) -> Plan`; each backend keeps a
`KeyPlaneStore::store_planned_key_record` executor (SQL, row mapping, transaction only). Per
door: the parity scan reports it `shared`; the existing witnesses pass unchanged; a mutation of
the shared plan is red on every backend. Witnesses I1183–I1188; `scope-s3-key-plane.txt`.

### S4 — consent and sweep planes on one plan (#934 step 4)

The consent doors (`set_consent_role`, the consent-peer and live-grant lists,
`list_consent_revocations`, `grant_trust`, `key_grant_held_owner`, `project_key_grant_row`)
and the sweeps (`run_pqc_sweep`, `run_consent_sla_watch`, `stream_dek_evict_room_chunks`,
`prune_transport_destinations_not_seen_since`, the retention sweeps): writes are
`consent_admit::plan_*` plus thin executors; reads are one shared fold over a typed page read;
sweeps are one shared selection plus a per-backend delete. The family-scoped key-plane holdings
read (#1105) is one shared read plan. Witnesses I1192–I1201; `scope-s4-consent-sweep.txt`.

### S5 — retire `MemoryBackend` (#1002)

Tests run on `SqliteBackend::open_in_memory()` (one migrated template per test process,
cloned), `test_backend()` returns it, tests on a memory-only fault seam use
`FaultInjectingDirectory` over sqlite, and `src/store/memory.rs`, the memory arm of
`parity.rs`, the memory column of the #670 gate-sequence scan and the memory shard of every
`on_each_backend!` are deleted. Folded in: #679 (schema measured, not modelled), #681, #691
(parity reads from disk), #720 (`LifecycleView` as one plan-emitted predicate), #722 (the
cursor planes witnessed on the two real backends), #787 (the `DirectoryOp` proxy gate).
`scope-s5-memory-retire.txt`.

### S6 — organisations as affiliations (#1036, all items; #1049; #1062; #1048)

(1) `licensure:{community_key_id}` is a cosigned row whose `consensus_protocol` source is the
authority community, and the `license` chain roots at that quorum; (2) a licence is judged at
its signed `asserted_at` with the W past-freshness bound (`asserted_at_stale`); (3) audience:
no public default, re-emission to named readers; (4) `organization` / `org_membership` /
`partner_record` are affiliation rows with the `revision` anti-rollback and ±5 min skew bound,
`partner_record` the typed licence payload, and the three replication kinds retired; (5)
contest: a subject's `withdraws` against `licensure:*` / `revocation:*` is refused, and a
contest is `reconsideration:{grounds}`. #1062: an organisation's owner-binding names the
affiliation and is cosigned. #1048: `delegation_term_required`. Witnesses I1210–I1235;
`scope-s6-affiliations.txt`. Evidence: `CLM-authority-id-is-org-id`,
`CLM-licence-authority-quorum`, `CLM-licence-judged-at-issuance`, `CLM-licence-audience`,
`CLM-licence-contest`.

### S6v — vendor CC v1.0-rc9

Persist vendors tagged CC only: `scripts/check_vendored_cc.sh <tag>` must pass, the
`manifest_diff.py` report goes in the CHANGELOG for Edge, and every `VENDORED_*` pin and the
binds oracle are regenerated at the tag commit. rc9 adds `objection:{state}` with `proposal`
and `assent`; `transport:canonical_rebind:v1`; `identity:occurrence_revocation:v1`; the
refusal tokens `federation_set_semantics_unsorted` (sorted AND unique) and the
`federation_malformed_row` reasons `envelope_member_null`, `aggregate_source_duplicate`,
`key_id_fingerprint_mismatch`, `carrier_without_roster_quorum`; CC 4.5.13's
`governance_policy.json` (cancel_over, at_window, min_count) and `csd4_chain.json`. The
governance-policy, chain and csd4 fixtures become runtime manifests at the tag's bytes, and
`TwoPathPolicy::check_corridor` runs at admission against the vendored policy table. The 732
governance vectors and the self_roster traces re-run at the tag's pins. Witnesses I1300–I1311;
`scope-s6v-vendor.txt`.

### S7 — release

Evidence rows in the manifest only (`namespace_supersets.json` → `evidence_tsv.py write`),
`supersets.rs EXPECTED` honest, CHANGELOG `## [60.0.0]` with the Edge/Server adoption list
(retired kinds, Python signature changes, `DIRECTORY_ABI_VERSION`), the new mutation scopes
wired into `mutants.yml`, every cheap leg run before the chain (the five axes, pyo3, both
clippy, pyi; then deny, evidence, the directory double, the full lane including the
`test-anchor` and python legs), `--hold` for Edge's re-gate, then ship and finish; CC gets the
tag, sha and evidence path for the pin.

## 5. Acceptance for the cut

| measure | v59.1.0 | v60 target | v60.0.0 |
|---|---|---|---|
| backend lines | 134,737 | ≤ 105,000 | 105,198 |
| `memory.rs` | 25,604 | 0 | 0 |
| replication kinds live / typed | 18 / 13 | ≤ 13 / ≤ 7 | 12 / 11 |
| doors on a shared plan | 19 | ≥ 35 | 40 (+8 shared selections) |
| typed silo tables | 7 cirisnode + goals + 3 org | 2 projections (credits, expertise) + goals projection | as targeted |
| mutation scopes, all scheduled, all exit 0 | 3 | 3 + one per slice | 12 |
| CSD/4 coverage | none | `csd4_coverage.py` report in CI | report in CI |

The v60.0.0 column is the measurement at the release, from
[V61_TASK_PLAN.md](V61_TASK_PLAN.md) §0. The typed-kinds target moves to v61.

## 6. Process rules

- Every cargo / nextest / maturin call and every `git commit` goes through
  `scripts/cargo_guard.sh`; `CARGO_BUILD_JOBS=4`, `NEXTEST_TEST_THREADS=4`; at most two guarded
  builds at a time (`CARGO_GUARD_SLOTS=2`, 11 GB caps: the sqlite lane peaks at about 8.5 GB
  anonymous memory whatever the job count). Disk, not RAM, caps the worktree count: a warm
  target dir is about 44 GB.
- No `--no-verify`, no `--amend`; only the release lead pushes.
- A shipped migration is immutable as bytes; the evidence tsv is generated from the manifest.
- Each slice: cheap legs under `-D warnings`, the full lane INCLUDING `test-anchor` and python,
  its mutation scope at exit 0, the size report delta, then a handoff with every claim marked
  TESTED or BELIEVED.
- Nobody edits a slice's worktree while it has a build running or a diff staged.
- Downstream asks raised during a cut become tickets; Edge adapts once, to the release head.
