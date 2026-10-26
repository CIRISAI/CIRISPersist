# v60.0.0 — task plan: the free migrations, the backend refactor, and one mutation discipline

Operator direction (2026-10-21): v60 is the refactor cut, with the planes that have no
external consumer yet migrated onto `scores` rows first, because they are free to move
now and gone before the refactor has to consolidate their doors. #1036 (affiliations) is in.

## 0. The target (CEWPOS)

CEWPOS states the end state the substrate is converging on ([WHY.md](https://github.com/CIRISAI/CEWPOS/blob/main/WHY.md),
`CEWPOS_ATTESTATION_CALCULUS.md`): **signed attestations are the only state**; semantics are the
closed set of five structural operators (`scores` + `delegates_to` / `supersedes` / `withdraws` /
`recants`); the system grows by vocabulary, never by new primitives; the corpus is
append-only, signed, federated and content-addressed, and the substrate (`ciris-persist`,
`ciris-edge`, `ciris-verify`) is "settled and not in question". For persist that means two
debts, and v60 pays both down:

1. **Typed state that is not a row.** At v59.1.0, 13 of 18 replication kinds are still typed
   objects with their own tables and wire framing. Every one is a second primitive.
2. **One trait written three times.** 250 `FederationDirectory` methods; 95 have a shared body,
   19 doors run on a shared `plan_*`, the rest are implemented once per backend
   (`sqlite.rs` 56,003 lines, `postgres.rs` 53,130, `memory.rs` 25,604 = 134,737). The
   defect class "green on memory, red on sqlite/postgres" is the most-recorded in the repo.

The CSD/4 catalogue in CEWPOS (`CSD4_CATALOGUE_AND_MIGRATION_PLAN.md`) already keys CSD-120,
-123 and -126 (affiliations, partners, affiliation keys) on affiliation ROWS, not on the
`organizations` / `partner_records` tables, which is why #1036 item 4 is in this cut.

## 1. Baselines (v59.1.0, tag 32512f52)

| measure | value | how measured |
|---|---|---|
| backend files | 134,737 lines (sqlite 56,003 / postgres 53,130 / memory 25,604) | `wc -l` at the tag |
| of which test-only | sqlite ≈26.5k, postgres ≈52.0k, memory ≈13.5k | first `#[cfg(test)]` to EOF |
| all of `src/` | 672,986 lines | `wc -l` over `*.rs` |
| `FederationDirectory` methods | 250 (95 with a default body) | `awk` over the trait |
| shared plans (`plan_*`) | 19 | `git grep` |
| replication kinds | 18 live; 4 retired framed (key plane) | `replication_policy::EnvelopeKind` |
| witnesses | 664 distinct I-numbers; 88 `*_invariants.rs` files | `git grep` |
| nightly mutation scopes | 3 (`scope-consent-gate`, `scope-observe` ×2 shards, `scope-observe-sites` weekly) | `scripts/mutants/` |
| nightly mutants job | RED every day since 2026-10-14 (#1112: 7 unkilled in `src/observe`) | run 39595602108 |
| certify wall (1 lane) | 3253 s (v59.0.0) | `.release/59.0.0/certify.log` |
| last migration / witness | V201 / I1160 | — |

v60 numbering: migrations from **V202**, witnesses from **I1161**.

## 2. Order and ownership

One builder at a time (the memory budget), each slice its own branch from the previous
slice's head, integrated onto `release-60.0.0` by the lead. Briefs are self-contained: every
ruling a slice needs is in its section below, because a message to a busy agent lands after
its build.

| # | slice | tickets | kind | expected size |
|---|---|---|---|---|
| S0 | small fixes + the mutation discipline | #1112, #1109, #1111 | fixes | ½ day |
| S1 | `cirisnode.*` silos onto `scores` | #988 item 1, #803, #854 | free migration | 1 day |
| S2 | goals onto `goal:{scale}` | #988 item 4 | free migration (Edge drops 2 message types) | ½ day |
| S3 | key-record write doors on one plan | #934 step 3 remainder | refactor | ½ day |
| S4 | consent and sweep planes on one plan | #934 step 4 | refactor | 1 day |
| S5 | retire `memory.rs` onto sqlite in-memory | #1002 (+ folds #679, #681, #691, #720, #722, #787) | refactor, the only step that moves the total | 1–1½ days |
| S6 | organisations as affiliations | #1036 (all five items), #1049, #1062, #1048 | migration + feature | 2 days |
| S6v | vendor CC v1.0-rc9 at the tag (tagged 2026-10-21, CC main 5d50c6bb; CIRISConstitution#182) | registry re-vendor; the chain, governance-policy and vocabulary fixtures become runtime manifests; `check_corridor` at admission from the policy table | vendor | ½–1 day |
| S7 | release: evidence, CHANGELOG, Edge adoption, chain | — | — | ½ day |

Not in v60, by decision: #1004 (the workspace split; it needs the plan/execute line S3–S5
finish drawing), #991 planes 2–3 (`group:roster:v1`, the membership rows, general
`cosignatures[]`; Edge carries all of them live), #1098 / #1100 / #1101 (CC conformance work
on doors S4–S6 move; writing them once on the shared plan is cheaper), #1105 (lands with S4
as a side effect if the key-plane read moves; otherwise v61), the retirement program
(#1079–#1088, on Agent's sequencing). New downstream asks during v60 become tickets.

Tickets filed during v60 (2026-10-21), all after v60 unless noted: #1101 serve-seat live owner
check (steward: after v60); #1113 takedown reversal (CC 4.5.3 at rc10, per-holder window from
`executed_at`); #1114 three `malformed_row` reasons appended (rides S6v if that slice has room);
#1115 `observation:access_assumption:v1` family gate (CC#183 N1); #1116 occurrence build pin
`build_manifest_hash` + `build_manifest_ref` (CC#183 N4). CC rc10 carries the text for all of
them; their claims stay staged until built.

Steward rulings 2026-10-22 (CC, cirisconstitution-b8), none in v60, tickets to be filed by the
asking team: (1) RaptorQ is dropped as the durability mechanism; durability becomes per-item
target-holder replication of encrypted chunks. The fountain store surfaces stay for the A/V
codec path only; the `FountainHoldingClaim` "shelf length" role moves to a per-item holder
count over chunk holdings; expect a durable-mark member on the publish row (shape from Server)
and a real per-item holder listing where today only a symbol count is exposed. (2) New
`mesh_config` keys, relieve-never-expand, Edge the consumer: `shaping.rho`,
`shaping.window_secs`, `shaping.node_cap_bytes_per_s`, `onion.cap_factor`,
`onion.mix_mean_delay_ms` (Edge files the shapes); the four redundancy keys keep their meaning
over holders per item. (3) Role token `infra:relay` (steward-conferred, on owner-bound
bundle-rooted identities, seat-like in the onion cap; Edge files the ask) and identity_type
`rendezvous` (CC 3.1.4): no occurrence, no standing, key record travels inline, never admitted
to the key plane as an identity; refusal token `federation_rendezvous_key_not_an_identity`
(CC 3.1.4 `rendezvous:route:v1` row, rc10); a rendezvous node holding a mailbox MUST be a
serve seat (CC 5.4.6 item 6), so the mailbox surface rides on #1101's predicate. (4) Possession challenge (N6): weight rule is the interim;
the challenger is staged for the durability tier's first release.
Edge filed the asks the same day, all after v60: #1117 the accord M-of-N threshold (strict
majority over the standing roster) as a callable function; #1118 the five mesh_config keys
(and, per the steward, the two symbol-count redundancy keys retire while `target_holders` and
`min_viable_holders` stay); #1119 `delegation_scope::INFRA_RELAY`.
S2 tokens registered on CC rc10 at 3.1.9.7 "Admission of a Goal" (10-22): `goal_meta_alignment_malformed`,
`goal_body_malformed`, `goal_typed_object_retired`; scales self / cohort / federation; negative
self score = avoidance goal; amend / retire / disown = supersedes / withdraws / recants. Persist
pins them against CIRISConstitution#67 in `RULES_NOT_ON_THE_ROW` until the next CC re-pin
(S6v vendors the rc9 TAG, which predates them); repoint to CC 3.1.9.7 at that re-pin.
Steward ruling on CC rc10 (post agent 2.16.3, 10-22), after v60, persist files the ticket when
the agent's shape is final (claims staged on CIRISAgent#1316): CC 3.1.9.4 registers
`deferral:request:v1` (agent occurrence key, the cell as audience) and
`deferral:response:{approved|rejected}:v1` (the WA's own key seated in the live set at
asserted_at; subject = the agent; references_attestation_id → the request) as the dimensions
for what S1 just made `contribution:{subject_kind}:v1` rows with subject kinds
DeferralRequest / DeferralResponse, so those two subject kinds move onto their own families.
CC 3.1.5 adds `identity_amendment:v1` (agent occurrence key about its identity key; members
`amendment_digest` hex64 + `authorized_by` uuid, both CC 2.1 rows) with the admission rule:
refuse `identity_amendment_unauthorized` unless the cited response is admitted, approved,
about this agent and signed by a key seated as a WA at the response's asserted_at.
`wa_adjudication:{state}` closes to abandonment | seizure | successor.

Steward ruling 10-22, the CENSUS (after v60; persist settles row names + tokens with Edge, files
the ticket once settled): the holonomic view becomes the census; CC 6.2 removed; v1 is
SECRET-SHARED: each node splits each bucketed count (and each member its vote cell) into two
additive shares sent to two seats chosen by H(token‖period); each seat sums the shares it holds;
composite and tally = the sum of the two partials, published with the mass commitment over
per-period tokens; no seat sees a return or a vote; participation visible. Numbers: k = 10
owners per cell; a census-derived base falls at most 10 % per period, floor above the
small-community size = max(rooted-active roster, 50 % of the last stable composite); a
one-period fall over a third freezes the base and all narrowing reliefs. Expected-active (CC
4.5.13's base) = owners active in ≥1 of the last four periods, a member-only composite under the
community's MLS epoch key. Dominance gate refuses a composite/tally where one owner holds over
half the mass. Persist's door work: a share-sum store per seat per period (local, deleted after
the period), the partial-sum row, the composite row on AggregationMetaV1 v3 (verify inputs as
envelope members, dominance + multiplicity gates at federation admission), the expected-active
reader with its floor feeding `two_path::Base` (today StandingRoster only; `Base::count` is the
one site) and reverse_quorum, and the algorithm id + period a ballot binds to. Persist's
answer (sent to CC + Edge 10-23 01:30 UTC): the share rows need ONE new placement class
`addressed` (one recipient in for_key_id, audience {author, recipient}, never widened, expires
at period end; may_receive's refers-to arm + expires_at/reap already exist, the Placement
variant does not); recipient and aggregator must be serve seats (#1101 predicate); proposed
tokens census_return_recipient_not_seat / census_return_expired /
census_composite_signer_not_seat / census_composite_below_k; "cells sum to mass" needs a
signed mass_total member, a Merkle root cannot be summed; the objection tally stays an
identified count and does not ride the anonymising carrier (one COUNT path, two instruments).
SETTLED with Edge 10-23 (section 10 at CIRISEdge feat/onion-fsd 0f56b86): seven families
(`census:share|partial|composite:{class}:v1`, `census:expected_active:v1`,
`census:member:share|partial:v1`, `ballot:tally:{poll_id}:v1`), the `addressed` placement for
every share row (member shares addressed to a tally MEMBER of the room, never room-held), sums
mod the field prime, one composite per (class, period) by the share_index-0 seat, 19 tokens;
final list sent to CC to register; persist's door work is #1121 (after v60, depends on #1101).

## 3. The mutation discipline (S0, then every slice)

**Problem.** The repo has a centralized, gated mutation matrix (`scripts/mutants.sh`,
`scripts/mutants/scope-*.txt`, `scripts/mutants_matrix.py`, `allowed_survivors.txt`,
`docs/MUTATION_TESTING.md`), but every slice since v53 has run its mutation round as an
ad-hoc Python script outside the repo (`release53/*_mut*.py`, 20+ of them in v59 alone)
whose results survive only as a handoff table and a CHANGELOG line. Nobody can re-run them,
the nightly matrix never learns the new sites, and the nightly job itself has been red and
unread for a week (#1112).

**Rule for v60 (the "centralize/utilize" ask).**

1. **Every slice ships its mutation set as a scope file**, `scripts/mutants/scope-<slice>.txt`
   (grammar: `tests:` filterset naming the slice's witnesses; the files, and for files over
   a few thousand lines the functions, that the slice touched). The hand-written mutation
   list in the brief becomes the scope's `tests:` + sites; the matrix (`matrix.json`,
   `verdict.txt`, `unvalidated.txt`) is the handoff's mutation table, by path. No ad-hoc
   Python mutation scripts; `scripts/mutants.sh cargo-mutants <scope>` is the one runner,
   through `cargo_guard.sh`.
2. **A slice is green only when its scope's verdict is exit 0**: every mutant caught, or
   allow-listed with a tracking issue, and `unvalidated.txt` empty (a witness that kills
   nothing is a witness about a neighbouring gate). Exit 3 means shard it, not shrink it.
3. **The new scopes join the nightly matrix** (`.github/workflows/mutants.yml`), budget-fitted
   and sharded; the weekly run takes the heavy ones. S7 wires them.
4. **The PR gets a diff-scoped report**: `scripts/mutants_diff.sh <base>` runs in the
   `reports (non-gating)` workflow on every v60 PR, so "which changed line can be mutated
   with no test noticing" is answered for the whole diff, not only the sites someone chose.
5. **Retire the backend triplication of witnesses** in S5: a mutant is tested on sqlite and
   postgres; the memory column of the matrix goes with the memory backend.

**S0 deliverables.**
- #1112: kill the seven `src/observe` survivors with witnesses (`metrics_unit` brace-guard
  cases; a `count_read` witness that each timing-out mutant changes within the nextest
  `mutants` profile's 60 s). No allow-list entries. The nightly job goes green.
- `scripts/mutants/README.md` (or a section in `docs/MUTATION_TESTING.md`): the slice rule
  above, the scope-file template, and the brief sentence agents copy.
- `reports (non-gating)` workflow gains the `mutants_diff.sh` step on `release-*` PRs.
- A from-disk check, `scripts/mutants_scopes_check.py`: every `scope-*.txt` resolves
  (`mutants_matrix.py resolve`), every `tests:` filter matches at least one test, every
  allow-list line carries an issue. Added to certify's fast gates beside `mutmatrix`.


## 3b. CSD/4 as the key for persist's testing, QA and mutation scopes

**What the manifest is (read 2026-10-21, CIRISClient `packaging/csd4/`, vendored from
CIRISServer#802 release assets, sha-pinned in `PIN.md`):**

- `topology_vocabulary.json`: 110 atoms, each `{plane, state_predicate, cc_ref, in_state_table,
  meaning}`. The vocabulary is the CONSTITUTION's (`manifests/topology_vocabulary.json`,
  steward decision 2026-10-18); the client holds a byte copy and a pin.
- `traces.json`: the twenty topologies T0–T19 from Server's `harness.native` model, each a
  list of steps `{id, atoms}` with `promises` and a `refused` map.
- `requirements.yaml`: per CSD, the topology it names and its tests as `{at: [atoms],
  probe: {node, path, status, expect}}` (the `csd:tests` block in each card).

CEWPOS's catalogue (`CSD4_CATALOGUE_AND_MIGRATION_PLAN.md`) reports 101/101 active cards
green against it, 134 test instants, 74 checkpoints, and 77 rows "⏳ Upstream (stops at
rel[k]:…)": the relations the substrate or server cannot yet produce (agent 12, agent_bond 10,
invite 8, community_trust 6, scoped_file 4, key_grant 4, authority 4, guardian_bond 3,
holder 2, resign, lineage_head, evict_lone).

**Maturity, honestly.** The atom vocabulary and the traces are mature enough to key to:
they are CC-owned, pinned, and already drive 134 instants. The cards are not (CSD-095 is
`stage: sketched`; `shows:` tags are UI contracts). So persist keys to the ATOMS, the trace
steps and their refusal maps, never to a card's `shows:` tags, and the chain back to the
formal models runs atom → `cc_ref` → CC claim id → persist evidence row → witness → mutation
scope. CC delivered the chain as data the same day: `manifests/csd4_chain.json` at rc9 5fe1c0f
(`tools/build_csd4_chain.py`, CI-diffed): per atom, `states[]` with the formal `model_ref`,
`invariants[]`, `claims[]` with parsed evidence refs (1,035 point at CIRISPersist), and
`refusal_tokens` (69, by section, with a bold/after_refusal confidence); `_meta.pins` carries
the sha256 of STATE_TABLE.tsv (157 states), INVARIANTS.tsv (152 properties), the vocabulary,
claims.tsv and evidence_pins.tsv. The per-step refusal map and the relation owner map are
Server/CEWPOS data, not CC's. Persist vendors the chain as a test fixture until the v1.0-rc9
tag and joins on it directly.

**Tasks.**

- **S0-csd (in S0):** vendor the three csd4 assets byte-for-byte with their pin into
  `tests/fixtures/csd4/` (the self_roster traces and governance vectors precedent; runtime
  vendoring waits for the rc9 tag). `scripts/csd4_coverage.py`: a from-disk join of
  atoms (`cc_ref`) ⋈ CC `claims.tsv` (section) ⋈ `evidence/cc_impl.tsv` (persist symbols) ⋈
  the `*_invariants.rs` witnesses and `scripts/mutants/scope-*.txt` (by file/symbol), plus
  every `refused` token in `traces.json` ⋈ persist's `kind()` / reason tokens. Output: every
  atom and every refusal token with no persist witness, no mutation scope, or no token
  behind it; the "stops at rel[k]" list restricted to persist-owned relations. Report-only
  in v60 (`reports (non-gating)`), with the gap list posted on #934 as the v61 backlog;
  it becomes a certify gate once CC's join data lands.
- **S7-trace (in S7, or its own slice if S0-csd shows the shape is cheap):** replay the
  SUBSTRATE half of each T0–T19 step at persist's doors: drive the step's writes through
  the real admission doors on sqlite and postgres, assert each atom's `state_predicate`
  through persist's own state and fold reads (`node_state`, `trust_root_valid`,
  `self_roster_standing`, …), and assert the step's `refused` tokens are exactly what the
  doors emit. Each topology becomes one witness (I12xx) and one mutation scope keyed by
  topology (`scope-t<nn>-<name>.txt`), so a mutation scope is named for the user-facing
  promise it protects, not for a file.
- **Rule going forward:** a new door's witness names the atom(s) it realises in its doc
  comment; `csd4_coverage.py` reads them, so a door no atom reaches is visible (a
  candidate for the refactor to delete), and an atom no door realises is a persist gap by
  name.

## 4. The slices

### S0 — small fixes (#1109, #1111) and #1112

- **#1109** `admission::nodes_owned_by` seeks candidates only among `delegates_to` rows signed
  by the fedID's own key; a device joined by approval announces with its roster key
  `<fedID>-<fp>` and is never placed. Widen the candidate seek to the self's live roster keys
  through the predicate `owner_of` already uses (`self_of_at`). Witness I1161 on sqlite and
  postgres: a roster-key-announced node is returned by `nodes_owned_by(fedID)`; a key of
  another self is not; mutation: revert to own-key-only. Server deletes its
  `announced_nodes_of` workaround after.
- **#1111** test-anchor seam on W_self: under `feature = "test-anchor"` AND the runtime
  override active (the existing fence + production tripwire), `CIRIS_TEST_W_SELF_SECS` read
  once replaces `W_SELF_SECS` in `self_roster::policy()`. Node-clock semantics unchanged.
  Witness: with the env set a lone-path proposal lands after the short window; without the
  override the env has no effect; a non-test-anchor build ignores it (from-disk check).
- **#1112** as in §3.
- Mutation scope: `scope-s0-roster-seam.txt` (the two doors) + the fixed `scope-observe`.

### S1 — `cirisnode.*` onto `scores` (#988 item 1, #803, #854)

CC 3.1.9 registers each class as a dimension; nothing outside persist writes these tables
(checked 2026-10-21: NodeCore and Portal do not exist; Server's `qa_runner/modules/cirisnode_tests.py`
is the only caller and moves with the surface). Precedent: v18 `trace:complete:v1`, v57
`hard_case:{kind}:v1` / `detection:{detector}:v1` (`attestation_admit::plan_*_row`,
`silo_projection::check_projection_rebuild`).

| table (V011/V012/V054) | becomes | fate of the table |
|---|---|---|
| `contributions` | the CC 2.1 Contribution itself: the `scores` row | dropped |
| `votes` | `vote:{contribution_id}` rows | dropped |
| `moderation_events` | `moderation:{allegation_type}` rows | dropped |
| `slashing_attestations` | `slashing:{outcome}` rows | dropped |
| `reconsideration_requests` / `_attestations` | `reconsideration:{grounds}` rows (the v59 subject-standing rule applies) | dropped |
| `credits_ledger`, `expertise_ledger` | derived balances → PROJECTIONS of `credits:…` / `expertise:…` rows, byte-equal rebuildable | kept as projections with `attestation_id` FK |
| `takedown_notice` (a Contribution today) | `takedown_notice:{basis}:v1` `scores` row (#803); `LegalBasis` spellings move to CC's closed vocab (`dmca512`, `dsa_article16`): serde + V202 rewriting the V054 CHECK and rows + the readers in `steward_purge.rs` / `takedown_tombstone.rs` | the pinned-divergence test in `media_sharing.rs` is deleted |
| `scheduled_takedown_actions`, `promotion_attestations` | stay local bookkeeping | unchanged |
| `federation_delivery_attestations` | stays local (a receipt; the `delivery_receipt:{stream_id}` family is #984 row 17, not this cut) | unchanged |
| `key_grant` subject_kind | RETIRED (duplicates the key-grant plane) | refused by name |

Rulings: hybrid PQC signatures on every row (the Ed25519-only fallback ends); the Emit/Ingest
subject gate becomes ONE gate on canonical subject ids (#854); the `cirisnode` Python surface
keeps its method names as thin wrappers that plan rows, removes what has no row meaning, and
lists every signature change; one migration V202 (sqlite + postgres twins) drops/converts;
`RETIRED_FRAMED`-style refusal for any typed cirisnode object offered on the wire.
Witnesses I1162+: each class admits as a row and folds (credits/expertise balances byte-equal
before and after rebuild); a takedown notice as a row drives the existing takedown doors;
the retired subject_kind refused; `check_projection_rebuild` red while un-rehomed rows exist.
Mutation scope `scope-s1-cirisnode.txt`. Evidence: the CLM rows CC stages on #988 item 1 /
#803 (`CLM-takedown-notice-row` graduates here). Expected: backend −2k to −3k lines, 5 typed
tables gone.

### S2 — goals onto `goal:{scale}` (#988 item 4)

The declarer's signed `scores` row on `goal:{scale}` IS the Goal; `goal_id` = its
`attestation_id`; `MetaGoalAlignment` is an admission gate on the family; amendment =
`supersedes`, retirement = `withdraws`, "never mine" = `recants`; the `goals` table (V050)
becomes a projection (`attestation_id` FK, byte-equal rebuild). Edge retires its
`GoalDeclaration` / `GoalRetirement` message types (Edge adoption, once, at S7). Witnesses
I117x on both backends + mutations; `scope-s2-goals.txt`. Expected: −0.5k.

### S3 — key-record write doors on one plan (#934 step 3, the remainder)

v58 put the key plane on rows and `put_revocation` on `plan_put_revocation`; the key-record
WRITE doors (`put_public_key`, seed, scrub upgrade, canonical supersede, rebind /
invalid-replace, reanchor, PQC completion, scrub rehydrate, peer removal) still each write the
`federation_keys` row + its `key:record:v1` row per backend (`*_sync_key_record_row`). Move
the decision and the row-plan into `key_plane::plan_key_record_write(dir, input) -> Plan`;
each backend keeps a `KeyPlaneStore::store_planned_key_record` executor (SQL, row mapping,
transaction only). Acceptance per door (the #934 rule): the decision lives in one function;
the parity scan reports the door `shared`, not `identical ×3`; the existing witnesses pass
unchanged; a mutation of the shared plan is red on every backend. `scope-s3-key-plane.txt`.
Expected: backend −1k.

### S4 — consent and sweep planes on one plan (#934 step 4)

Doors (counted at v59.1.0, one impl per backend): `set_consent_role`, `list_consent_peers`,
`list_consent_peers_for`, `list_live_consent_grants_by/for`, `list_consent_revocations`,
`grant_trust`, `key_grant_held_owner`, `project_key_grant_row`, and the sweeps
(`run_pqc_sweep`, `run_consent_sla_watch`, `stream_dek_evict_room_chunks`,
`prune_transport_destinations_not_seen_since`, the retention sweeps). Writes become
`consent_admit::plan_*` + thin executors; reads become one shared fold over a typed page
read; sweeps become one shared selection + per-backend delete. The #1105 family-scoped
key-plane holdings read lands here as one shared read plan. Witnesses: the existing consent /
key-grant / sweep invariants unchanged; a mutation of each shared plan red on every backend;
`scope-s4-consent-sweep.txt`. Expected: backend −2k to −3k.

### S5 — retire `MemoryBackend` (#1002)

Steps as filed: (1) measure `SqliteBackend::open_in_memory()` with all migrations against
`MemoryBackend::new()`; if replay dominates, one migrated template per test process cloned
by `sqlite3_serialize/deserialize`; (2) `test_backend()` returning the sqlite in-memory
backend; migrate the ~450 constructions file by file, each commit green; (3) tests on a
memory-only fault seam move to `FaultInjectingDirectory` over sqlite; (4) delete
`src/store/memory.rs`, the memory arm of `parity.rs`, the memory column of the #670
gate-sequence scan, the memory shard of every `on_each_backend!`. Done when no
`MemoryBackend` symbol remains, the test count is unchanged apart from the memory-arm
duplicates, and certify's rest leg wall time before/after is posted on #1002. Folds: #679
(schema measured, not modelled: the sqlite/pg DDL replayer no longer needs a third dialect),
#681, #691 (parity reads from disk: fewer arms), #720 (`LifecycleView` as one plan-emitted
predicate), #722 (the cursor planes witnessed on the two real backends), #787 (the
`DirectoryOp` proxy gate). `scope-s5-memory-retire.txt` is the whole-matrix re-run of every
existing scope with the memory column gone. Expected: −25k lines; witnesses run on two
backends.

### S6 — organisations as affiliations (#1036, all items; #1049; #1062; #1048)

CC rc8 (#161/#162/#164), text on CC `rc8.1` (vendored). Items: (1) `licensure:{community_key_id}`
is a cosigned row whose `consensus_protocol` source is the authority community; the
`license` chain roots at that quorum; (2) judged at the signed `asserted_at` (the `as_of`
lens) with the W past-freshness bound now shipped (#1049's door: the key_grant / consent
grant chain judged at the row's instant with `asserted_at_stale`); (3) audience: no public
default, re-emission to named readers; (4) `organization` / `org_membership` /
`partner_record` → affiliation rows, `revision` anti-rollback and the ±5 min skew bound
ported, `partner_record` as the typed licence payload; the three replication kinds retire
(Edge drops them at S7); no Portal data exists to migrate; (5) contest: a subject's
`withdraws` against `licensure:*` / `revocation:*` refused (the v59-deferred carve-out
widening in `resolve_withdraws_admission_rule_at`), contest = `reconsideration:{grounds}`;
#1062 owner-binding for an organisation names the affiliation and is cosigned; #1048
`delegation_term_required` from its parked branch `v54.1-rc8-term-gate`, rebased.
Witnesses I12xx on both backends + mutations; `scope-s6-affiliations.txt`. Evidence:
`CLM-authority-id-is-org-id`, `CLM-licence-authority-quorum`, `CLM-licence-judged-at-issuance`,
`CLM-licence-audience`, `CLM-licence-contest`. Expected: 3 typed tables and 3 wire kinds gone.


### S6v — vendor CC v1.0-rc9 (tagged 2026-10-21)

Tag `v1.0-rc9` = CC main `5d50c6bb160ecbee99a66e1700597c029846e6b6` (tag object `a1c2bea5`).
Verified from the local CC checkout: the diff from aa5ae9c to the tag is `tools/_md2latex.py`
and the PDFs only; no manifest, registry, vector or Part byte changed, and the vendored
`tests/fixtures/csd4/csd4_chain.json` sha256 equals `git show v1.0-rc9:manifests/csd4_chain.json`
(b759e488…). S6v therefore vendors at 5d50c6bb and no longer waits on anything.

Persist vendors tagged CC only (v58's slice V is the template: `scripts/check_vendored_cc.sh
<tag>` must PASS; `manifest_diff.py` report in the CHANGELOG for Edge; every `VENDORED_*`
pin and the binds oracle regenerated at the tag commit). rc9 adds, at least: `objection:{state}`
with `proposal` and `assent`; `transport:canonical_rebind:v1`; `identity:occurrence_revocation:v1`;
the refusal tokens persist named (`federation_set_semantics_unsorted` sorted-AND-unique,
`federation_malformed_row` reasons `envelope_member_null`, `aggregate_source_duplicate`,
`key_id_fingerprint_mismatch`, `carrier_without_roster_quorum`); CC 4.5.13's
`governance_policy.json` (cancel_over, at_window, min_count) and `csd4_chain.json`. The
fixtures vendored in v59/S0 (`governance_policy.json` b7d2370d, `csd4_chain.json` 5fe1c0f,
the csd4 vocabulary/traces/requirements) move to runtime manifests at the tag's bytes, and
`TwoPathPolicy::check_corridor` runs at admission against the vendored policy table (the one
piece v59 left for the tag). The 732 governance vectors and the self_roster traces re-run
at the tag's pins. Witness the pins; mutation scope `scope-s6v-vendor.txt`.

### S7 — release

Evidence rows in the manifest only (`namespace_supersets.json` → `evidence_tsv.py write`),
`supersets.rs EXPECTED` honest, CHANGELOG `## [60.0.0]` per slice with the Edge/Server
adoption list (retired kinds, Python signature changes, DIRECTORY_ABI), the new mutation
scopes wired into `mutants.yml`, `release.sh --dry-run` cheap legs ALL run before the chain
(the five axes, pyo3, both clippy, pyi; then deny, evidence, double, the FULL lane including
the `test-anchor` and python legs), `--hold` for Edge's re-gate, then ship + finish; CC gets
the tag, sha and evidence path for the pin.

## 5. Acceptance for the cut (numbers to post in the PR)

| measure | v59.1.0 | v60 target |
|---|---|---|
| backend lines | 134,737 | ≤ 105,000 |
| `memory.rs` | 25,604 | 0 |
| replication kinds live / typed | 18 / 13 typed | ≤ 13 / ≤ 7 typed (cirisnode never had one; Organization, OrgMembership, PartnerRecord retired) |
| doors on a shared plan | 19 | ≥ 35 |
| typed silo tables | 7 cirisnode + goals + 3 org | 2 projections (credits, expertise) + goals projection; the rest dropped |
| mutation scopes | 3 | 3 + 7 (one per slice) + topology scopes from S7-trace, all in the nightly, all exit 0 |
| CSD/4 coverage | none | `csd4_coverage.py` report in CI: every atom/refusal token → witness + scope, or a named gap |
| nightly mutants job | red | green |
| ad-hoc mutation scripts | the v59 pattern | none; matrix paths in every handoff |
| certify wall | 3253 s | measured; expected lower after S5 |

## 6. Process rules (from memory, enforced by the lead)

- Every cargo/nextest/maturin call and every `git commit` through `scripts/cargo_guard.sh`;
  `CARGO_BUILD_JOBS=4`, `NEXTEST_TEST_THREADS=4`; two guarded builds at a time (`CARGO_GUARD_SLOTS=2`, 11 GB caps; measured 2026-10-21: the sqlite lane peaks at 8.5 GB anonymous regardless of jobs, so jobs stay 4). Disk, not RAM, caps the worktree count: a warm target dir is 44 GB.
- No `--no-verify`, no `--amend`, agents never push.
- A shipped migration is immutable as bytes; the evidence tsv is generated from the manifest.
- Each slice: cheap legs under `-D warnings`, the full lane INCLUDING `test-anchor` and python,
  its mutation scope at exit 0, the size report delta, then handoff with every claim marked
  TESTED or BELIEVED.
- The lead never touches an agent's worktree while it has a build running or a diff staged.
- Downstream asks during v60 become tickets; Edge adapts once, to the S7 head.

## 7. Risks

- S5 is the least predictable: moving ~13.5k lines of memory-runner tests will expose
  memory-only shortcuts sqlite rejects. That is the point; budget the day and a half.
- S6 is a feature-sized migration on a plane Edge carries; its wire retirement is the one
  Edge-visible break in the cut, so it goes last and is announced with the head.
- Downstream sessions are active; the "no new features" rule will be tested.
