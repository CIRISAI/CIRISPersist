# v60.1.0 and v61.0.0 — task plan: the additive cut, then finish the refactor

v60.1.0 is the additive cut and has shipped (§2). v61.0.0 is the major that finishes the
refactor. The feature asks that touch the membership planes (rooms, census) are built on the new
rows (§3 S1), not before them.

## 0. The two programs at v60.0.0

Measured at the v60.0.0 release:

| program | state at v60 | what remains |
|---|---|---|
| shared logic across backends (#934) | 355 doors: **40 shared** (+8 shared selections), **43 identical** (the same gate written in sqlite and postgres, not lifted), 1 declared, 271 gateless (per-dialect SQL, no decision). Backends 134,737 → 105,198 lines, three copies → two. | lift the 43 identical gates; #934 step 5 (coverage, diff mutants); then #1004 (workspace split) as the end state for the gateless SQL |
| everything as `scores` rows (#988, #991) | done: traces, cirisnode (7 classes), goals, hard_case, detection, the key plane, key grants, takedown notices | **11 typed wire kinds** still cross as their own objects with their own tables: Family, Community, the six membership planes (3 revocations, 2 widenings, the listing), LocationProof, TransportDestination, AccordQuorumEvidence. Below the wire: the accord tables (awaiting steward ratification, CC 4.2), `consent_peer_set`, the 25 `cirislens_*` tables (unscheduled long arc) |

v61 takes the typed kinds from 11 to 3 (LocationProof, TransportDestination,
AccordQuorumEvidence) and schedules those three after.

## 1. Order and ownership

Two releases, in order:

1. **v60.1.0** (MINOR, shipped): bugs and the additive Edge/Server asks. Nothing on the wire, the
   Python surface or an exhaustive enum changed shape; new vocabulary is appended. Three slices,
   two in parallel (A, B) and one after (C).
2. **v61.0.0** (MAJOR): every break together, so Edge adapts once. Branch `release-61.0.0` from
   the v60.1.0 tag. Five slices plus release.

Each slice is built in its own worktree and handed off with every claim marked TESTED or
BELIEVED. It is reviewed, merged into the release branch, and its witnesses are re-run on the
merged head before the next slice is briefed. The process rules are in §5.

Open decisions (the first shapes v61 S3):

- **W beyond 72 h (#1049):** the door refuses only when the standing has also lapsed at receipt
  (the #1099 reading); CC 2.6.7's text refuses unconditionally. Following CC's text is a
  behaviour break and rides v61 S3.
- **`DELEGATION_TERM_ADOPTED_AT`:** fixed at 2026-10-23; the alternative is the v60.0.0 release
  date (2026-10-26). A one-line change.
- **RUSTSEC-2026-0387 (#1127):** stays ignored until CIRISVerify moves to elliptic-curve 0.14;
  the re-pin rides whichever cut that lands in (verify pins flip together).

## 2. v60.1.0 — the additive cut (shipped)

### Slice A — bugs

| issue | what | witness |
|---|---|---|
| #1066 | the room-chunk retention sweep never evicts adopted stream-keyed chunks on a holder (reads minter-only stream-DEK rows) | a holder with an adopted stream chunk past retention: evicted, both backends |
| #1069 | `register_stream_epoch_dek`: an identical re-supply is idempotent `Ok`; a different DEK is a typed conflict | both arms, both backends |
| #1006 | `custody_view`'s `received` orders by this node's storage stamp, not a subscriber-signed instant; `put_delivery_receipt` has no signed instant to order by | ordering by the signed instant; a receipt without one refused |
| #798 | type-keyed folds resolve a claim through its `supersedes` chain | a superseded claim read through the chain |
| #1070 | takedown immediate-removal: no-LocalSigner engines, resume a recorded execution, tombstone/write race | the three cases filed on #1070 |
| #1072 | plaintext DAG doors refuse positioned chunk fields and a mismatched external size at the door | both refusals |
| #1124 | `CryptoTier::InvisibleEncrypted` doc comment says opt-in; sealing is mandatory | doc only; grep `docs/` and `FSD/` for the same wording |

Mutation scope `scope-601-fixes` over the touched predicates; ≤ 55 mutants.

### Slice B — consumer asks

| issue | ask | shape |
|---|---|---|
| #1117 | Edge | expose the accord M-of-N threshold (strict majority over the standing roster) as a function |
| #1118 | Edge | `mesh_config`: five relievable keys for link shaping and the onion tier |
| #1119 | Edge | `delegation_scope::INFRA_RELAY`, appended to the hashed vocabulary |
| #1064 | Edge | export retryability predicates for `KeyGrantRefusalReason` and `DimensionRejected` |
| #1095 | Edge | `chat:call:v1` — one self-subject chat row per attendee |
| #1089 | Server | trace_format v2.8.0 admission: `deployment_profile.run_kind`, the new profile members, gate on `trace_format_version` |
| #1120 | CC rc10 | refuse `identity_amendment:v1` as `identity_amendment_unauthorized` (a family nobody produces yet) |
| #1115 | CC | the `observation:access_assumption:v1` family gate, `score` +1.0 only (CC rc12 manifest) |
| #1113 | CC rc10 4.5.3 | a reversed reconsideration reverses a takedown; `withheld` computed at read |

Every new token registered with CC before the handoff (CC stages it on the ticket). Mutation scope
`scope-601-asks`; ≤ 55 mutants per shard.

### Slice C — tail (after A and B merge)

- #854: cirisnode `subject_key_ids` take canonical ids, so the Emit/Ingest subject gate is one
  gate (the cirisnode rows just moved; this is their last cirisnode-shaped seam).
- #720, second half: the §6.1-precedence read in the lifecycle predicate.
- `certify.sh:314`: the cheap legs' `.secs` files are never written, so their times print `-s`.
- `DELEGATION_TERM_ADOPTED_AT` to the release date, if so decided.
- #1127's re-pin, only if CIRISVerify has tagged the bump.

### v60.1.0 release

CHANGELOG `## [60.1.0]` with an Adoption subsection that says, truthfully, "no break; new
functions and tokens only"; the five axes, pyo3, both clippy, pyi before the chain;
`release.sh 60.1.0 --hold`; Edge gets the candidate; tag on Edge's green. The mutants matrix is
dispatched on the candidate BEFORE the hold is lifted (a slice that deletes or moves tests re-runs
every scope those tests witnessed).

## 3. v61.0.0 — finish the refactor

### S0 — vendor CC rc12 at its tag; re-pin; the signed-object cleanup (#1098)

- rc12 vendored at the tag (never the PR branch): the #1125 readings, the rc11 rooms text, the
  affiliation tokens, `observation:access_assumption` at +1.0, the census families and tokens as
  registered on #1121. Goal tokens repointed from CC#67 to 3.1.9.7.
- #1098 F2 (a bare scope token admitted as the one-element array it denotes; signed bytes never
  normalised), F4 (`envelope_member_null` appended to `malformed_row`), F5 (`witnesses[]` is a
  set-kind member), the 13 recomputed vectors replayed. F1 and F6 stay as filed.
- Evidence rows for every claim id rc12 graduates on persist's rows.

### S1 — planes as rows (#991: the group records and the six membership planes)

The big one. Family and Community become signed rows with projections; the three revocations,
two widenings and the listing become rows on the same plane (CC 3.1.3.2 `membership:{stage}`,
cosigned under the group's `consensus_protocol` through `additional_scrubs[]` and the ONE
counting predicate, `count_distinct_roster_scrubs`). The family-declared `consensus_protocol`
source rule is the admission dispatch. The eight wire kinds join `RETIRED_FRAMED` (positions
kept; the manifest hash does not move); `DIRECTORY_ABI_VERSION` 11 → 12; the directory methods
that read them become projection reads. Every fold that walked the typed tables
(`list_families_for_member_active`, roster folds, `canonical_community`, the self roster) reads
the projection. Retraction of a cosigned row is a cosigned `withdraws` under the same protocol.

Witness on both backends per plane: admit, cosign-short refused, widen, revoke, list, rebuild the
projection byte-equal (`silo_projection::check_projection_rebuild`), and an upgraded node (the
v60 typed rows rehomed once, `rehome_group_records()`, checked by a from-disk count).

### S2 — rooms on the new rows (#1123, #1063, #1100 item 2(i))

- `founder_only` refused above the family (`federation_community_consensus_protocol_violation`,
  rule `founder_only_above_family`); an upgraded-node count of existing founder_only communities
  first.
- `open:self_admit` as a canonical form, public groups only; a self-signed admission row.
- Removal under `open:self_admit`: two distinct cosigning voices and the 259 200 s roster window,
  on S1's `membership:removal` row.
- #1063: deliver a public room's standing proposal to a non-member requester.
- #1100 item 2(i): the reverse path for membership adds, through `two_path`.

### S3 — record-shape breaks (#1126, #1101, #1116, #1122; #1049 if it changes the door)

- #1126 partnership rows take the `consent_record` shape; readers fold both shapes; the bare shape
  refused at admission (`partnership_shape_retired`, registered with CC).
- #1101 a serve seat in an infrastructure community requires an announced owner binding.
- #1116 `identity_occurrence` carries `build_manifest_hash` and the provenance row ref, checked at
  the door.
- #1122 transport destinations: one destination, one live key; a newer route supersedes, or a
  retire door.
- #1049, if the decision is to follow CC 2.6.7's text: refuse beyond W unconditionally.

### S4 — the 43 identical gates onto shared plans; #934 step 5; #1067

- Every door the parity scan reports `identical` becomes `shared` (one plan, thin executors);
  the scan's `identical` class is then a red, not a report.
- #934 step 5: coverage in CI, diff mutants on the changed plans.
- #1067 stream-keyed chunk AAD v2: bind `(epoch, counter, last)`, not `storage_seq`; stored A/V
  chunks re-sealed by a one-time sweep with a from-disk count.

### S5 — release

Version, evidence re-stamp, CHANGELOG `## [61.0.0]` with the Adoption list derived from
`git diff v60.1.0..` (the eight retired kinds, ABI 12, every removed directory method and Python
method, every exhaustive enum that changed, the `Placement` consumers if S2 lands `addressed`),
certify, the mutants matrix on the candidate, `--hold` for Edge's re-gate, tag on Edge's go.

### After v61 (not scheduled here)

- #1121 census doors — on the new membership rows (its `addressed` placement is the one
  exhaustive-enum break of the census; if S2 needs it for `open:self_admit` delivery it moves into
  S2).
- LocationProof, TransportDestination, AccordQuorumEvidence as rows (accord waits on the steward).
- The retirement record (#1079–#1088) as its own major.
- #1004 workspace split; #1100's remaining doors; #974, #976, #962; #747, #728.
- Parked / blocked unchanged: #147, #415, #672, #708, #727, #795, #803, #812, #890, #914, #1005.

## 4. Acceptance

| measure | v60.0.0 | v60.1.0 | v61.0.0 target |
|---|---|---|---|
| doors `identical` in the parity scan | 43 | 43 | **0** (every gate shared or declared) |
| doors on a shared plan | 40 (+8 selections) | ≥ 40 | ≥ 83 |
| typed replication kinds (live / typed) | 12 / 11 | 12 / 11 | **4 / 3** |
| `DIRECTORY_ABI_VERSION` | 11 | 11 | 12 |
| backend lines (sqlite + postgres) | 105,198 | ≤ 105,198 | ≤ 95,000 |
| mutation scopes, all in `mutants.yml`, matrix green on the candidate | 12 | 14 | 18 |
| wire / API breaks | — | **0** | all of them, listed in Adoption |

## 5. Process rules

The rules of `docs/V60_TASK_PLAN.md` §6, plus:

- Every cargo / nextest / maturin call and every `git commit` through `scripts/cargo_guard.sh`;
  `CARGO_GUARD_SLOTS=2` for two parallel slices, `=1` for a lone builder; prebuild a cold
  all-features lane at `CARGO_BUILD_JOBS=1 --no-run` first.
- No `--no-verify`, no `--amend`, no `reset` of another's commit; nobody but the release lead
  pushes. A worktree is handed off only when its builder has stopped: no shell or cargo of its is
  still running, and no instruction to it is unread.
- Every job in the foreground under `timeout`.
- A slice that deletes or moves tests re-runs every mutation scope those tests witnessed before
  its handoff. The matrix is dispatched on the candidate before the hold is lifted.
- A wire claim to another project is read from the function body, never its doc comment.
- Downstream asks during a cut become tickets; Edge adapts once, to the release head.
