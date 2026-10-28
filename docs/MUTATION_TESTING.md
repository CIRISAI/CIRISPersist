# Mutation testing — the per-witness detection matrix

A surviving mutant is a claim about the WITNESS: some test that should guard a
site does not. The mutation matrix records, for each scope, which mutants were
generated, which witnesses killed each one, and which witnesses killed nothing.
It is regenerated on demand by a tool, not chosen by hand (CIRISPersist#1024).

    scripts/mutants.sh <cargo-mutants|mutest> <scope-file>

writes `target/certify-logs/mutants/<scope>/matrix.{json,md}`,
`unvalidated.txt` and `verdict.txt`. `scripts/certify.sh mutants <scope>` runs
the same thing under certify's lock.

## The gate

A run is a gate, not a report (CIRISPersist#1051). Its exit code:

| exit | meaning |
|---:|---|
| 0 | complete, and every surviving mutant is allow-listed with an issue |
| 1 | no matrix (tool missing, red baseline, broken build, or a green baseline whose log yields no status line) |
| 2 | usage, an unresolvable scope, or a malformed allow-list |
| 3 | refused before building: the scope does not fit the budget at `MUTANTS_BASELINE_SECS + N × MUTANTS_SECS_PER_MUTANT` (600 + 120 s by default) |
| 4 | INCOMPLETE: the budget expired or a mutant was never tested |
| 5 | a surviving mutant (`missed`, `timeout`, `caught_out_of_scope`) not in `scripts/mutants/allowed_survivors.txt`; or a mutant cargo-mutants ran that the matrix filed out of scope ("scope disagreement": it was tested and judged nowhere) |

`scripts/mutants_matrix.py verdict` writes the same verdict to
`$GITHUB_STEP_SUMMARY` and as annotations (`::error` for an unlisted survivor
or an incomplete run, `::warning` for an allowed one). An allow-list entry is
`<file>[:<line>] <cargo-mutants' mutation text> #<issue>`: the text is the
tool's own, compared exactly, and a line without an issue number is refused.

The matrix reader strips SGR colour escapes before it matches nextest's
status lines (CI sets `CARGO_TERM_COLOR=always`), and a green baseline whose log
yields no status line is exit 1, never a green run with zero witnesses.

**Selection is by line, through `--in-diff`.** cargo-mutants applies neither
`-F` nor `-E` to its struct-field deletions, so a function-name regex alone
lets mutants from outside the scope in. `resolve` writes the scope as a diff
that adds exactly its lines, minus every test-only item (`#[cfg(test)]`,
`#[cfg(all(test, ..))]`, a `mod *test_support*`), and passes `--in-diff`. The
matrix keeps a mutant whose span touches a scope line, as `--in-diff` does, so a
whole-body replacement that starts on a test-gated statement is still judged.

**A hung witness fails in 60 s.** The run uses nextest's `mutants` profile
(`.config/nextest.toml`): a witness that hangs under a mutant is killed after
three 20 s periods and reads as its FAIL, instead of a 300 s tool timeout
credited to no witness. A witness cannot end an infinite loop in the code under
test, so loops that a mutant could make unbounded are bounded in the code itself
(the fold-mask loop in `src/observe/` is bounded by the mask's popcount, I692 and
I1164).

## Tool choice: cargo-mutants

| | cargo-mutants | mutest-rs |
|---|---|---|
| toolchain | the repo's pinned stable | a pinned nightly (rustc-driver; must match the mutest build) |
| features | `postgres,sqlite,server` | `sqlite,server` only: with `postgres` the build hits an internal compiler error in `mutest-emit` (`deadpool::managed::pool::Pool` path resolution) |
| build | one incremental rebuild per mutant (about 17–83 s) | one meta-mutant build, peak RSS 8.2 GiB |
| test | the scope's witnesses per mutant | a whole-lib-suite profiling pass (about 28 min; it has no test filter), then the mutants |
| async witnesses | all run | its static call graph does not reach them: on the consent scope it ran 1 of 16 witnesses and generated no mutant in the consent gate, where cargo-mutants found 13 |

cargo-mutants runs on the pinned stable toolchain, builds every backend, and
runs every witness under every mutant through nextest with `--no-fail-fast`, so
`killed_by` lists every witness that went red, not only the first. Its cost is
a rebuild per mutant, about 50–55 s each locally and about 168 s on CI runners.
Run it alone (`MUTANTS_JOBS=1`): a build beside it can exhaust memory.

mutest-rs stays supported by `scripts/mutants.sh` for local comparison, and is
not wired into CI. Revisit it when it resolves async call edges.

cargo-mutants runs the ordinary nextest binary, so it inherits the existing
stack handling for the ML-DSA tests unchanged.

## The matrix format

Schema `ciris-persist/mutants-matrix/v1`, one format for both tools
(`scripts/mutants_matrix.py collect`):

```json
{
  "schema": "ciris-persist/mutants-matrix/v1",
  "tool": "cargo-mutants", "tool_version": "27.1.0",
  "scope": "scripts/mutants/scope-consent.txt",
  "test_filter": "test(/i548|i549|i550|i551/)",
  "features": "postgres,sqlite,server",
  "wall_secs": 2954, "budget_secs": 7200, "complete": false,
  "tests": ["observe::tests::sqlite::i549", "..."],
  "mutants": [{"id": 1, "file": "src/observe/mod.rs", "line": 175, "col": 9,
               "description": "src/observe/mod.rs:175:9: replace Fold::bit -> u32 with 0",
               "outcome": "caught", "killed_by": ["observe::tests::sqlite::i549", "..."]}],
  "out_of_scope": ["<generated by the tool, outside every scope range>"],
  "summary": {"mutants": 74, "caught": 42, "caught_out_of_scope": 0, "crashed": 0,
              "missed": 2, "timeout": 3, "unviable": 4, "not_run": 23},
  "kills_per_test": {"observe::tests::sqlite::i549": 41},
  "tests_killing_nothing": ["..."],
  "tests_never_run": ["<mutest only: outside its static call graph>"]
}
```

- `outcome` is `caught | caught_out_of_scope | crashed | missed | timeout |
  unviable | not_run`. For cargo-mutants, a `caught` mutant with an empty
  `killed_by` was caught by a crash or build failure the log does not
  attribute to one test.
- For mutest the outcome is read from the RETAINED witnesses' rows, because
  mutest runs the whole lib suite and the matrix keeps only the scope's
  witnesses. `caught` means a retained witness detected the mutant or crashed
  under it, and `killed_by` names it. `caught_out_of_scope` means the mutant
  was detected, but only by tests outside the scope: it counts as a detection
  by the suite, never as a kill by the witness set the matrix measures.
  `crashed` means the harness crashed under the mutant and no test's row
  attributes it.
- `complete` is false when the budget expired or any in-scope mutant is
  `not_run`. For cargo-mutants the not-run set is read from the tool's own
  `mutants.json`, because an interrupted run's `outcomes.json` lists only the
  mutants that finished.
- `matrix.md` is the same data as two tables: one row per mutant with its
  killers, one row per witness with its kill count. A zero is bold; a witness
  the tool never ran says so.

## Scope files

`scripts/mutants/<name>.txt`. The name becomes the output directory.

```
# comment to end of line
tests: <nextest filterset>      the witnesses measured; required
features: <feature>[,<feature>] the cargo features the sites compile under
                                (default postgres,sqlite,server;
                                MUTANTS_FEATURES still wins)
witnesses: <path> ...           extra witness files for the unvalidated report
                                (every *_invariants.rs counts without listing)
<path>                          every mutant in the file
<path> <fn> [<fn> ...]          only mutants inside these functions
```

To add one:

1. Name the files, and for any file over a few thousand lines, the functions.
   A function name must define exactly one `fn` in the file, or resolution
   fails and names the file and line.
2. Write the `tests:` filter as the witnesses that guard those sites. The
   whole-crate suite is not a sensible default: every mutant runs it.
3. Check it resolves without running anything:
   `python3 scripts/mutants_matrix.py resolve cargo-mutants <scope> /tmp/scope.diff`,
   then `cargo mutants --list` with the printed arguments.
4. Run it: `MUTANTS_BUDGET_SECS=7200 scripts/mutants.sh cargo-mutants <scope>`.
   If it exits 3, shard it.

### The scopes

The shard counts and cadence are in `.github/workflows/mutants.yml`. Each
scope's header comment names the issues and invariants it covers.

| scope | sites | witnesses | cadence |
|---|---|---|---|
| `scope-consent-gate` | the consent gate (`check_capacity_consent_admission`, the `consent_by_humans.rs` folds, `per_principal_stances`) | I548, I570 | nightly |
| `scope-observe` | `src/observe/`: the read and fold counters | I549–I553, I690–I699, I1163–I1164 | nightly, 2 shards |
| `scope-observe-sites` | the call sites in the backend and federation files that feed the counters, and `apply_planned`'s read-back and store-error arms | I548–I551, I1340–I1341 | weekly |
| `scope-s0-hard-case` | `hard_case` rows replicate: the put door and the replicated apply project the row in its transaction | I1165, I960, I962 | nightly |
| `scope-s0-roster-seam` | `nodes_owned_by` (and its owner-binding seek filter) and the test-anchor `W_self` seam; built with `features: test-anchor` | I1161, I1162, I1342 | nightly |
| `scope-s1-cirisnode` | the cirisnode classes as `scores` rows (`src/cirisnode/rows.rs`), the retired objects refused by name, the promotion and delivery row rules | I1166–I1172 and the takedown and legal-basis witnesses | weekly, 5 shards |
| `scope-s2-goals` | goals as `goal:{scale}:v1` rows: `goal.rs`, `goal_projection.rs`, and the backends' goal writers, rebuilds and reads | I1174–I1182 | weekly, 3 shards |
| `scope-s3-key-plane` | the key-record write doors on one plan: `key_plane::plan_key_record_write`, its planners, the shared replicated apply, and each backend's `store_planned_key_record` executor | I1183–I1188 and the doors' standing witnesses | weekly, 3 shards |
| `scope-s4-consent-sweep` | the consent and sweep planes on one plan: `consent_admit`, `sweep_plan`, the holdings read in `key_plane`, the key-grant doors' shared bodies, the observation prune plan, and each backend's `ConsentStore` / `SweepStore` / `RoomEvictionStore` executors | I1192–I1201 and the doors' standing witnesses | weekly, 6 shards |
| `scope-s5-memory-retire` | the single lifecycle predicate (`lifecycle_predicate`, `hiding_composers`), the from-disk tree binding (`store::tree_read`), the fountain assembler, the migrated in-memory sqlite clone (`store::sqlite_scratch`), and the genesis scratch database on both backends with its reaper | I1320, I1321, I1323, I1329–I1332 and the lifecycle and fountain reads | nightly |
| `scope-s6-affiliations` | organisations as affiliations: the licence authority quorum and its walk, the signed-instant verdicts, the licence audience and typed payload, the subject-withdraws carve-out and contest, the affiliation owner-binding, and the delegation term gate | I1210–I1235 and the licensure-chain, grant-scope and key-grant witnesses | weekly, 8 shards |
| `scope-s6v-vendor` | the vendored CC policy: the policy table read at runtime (`governance_policy.rs`), `TwoPathPolicy::check_corridor`, the self-roster admission site, the registry loader, and three refusals (`check_content_hash`, `check_row_mirror_members_closed`, `validate_subject_key_ids`) | I1300–I1311, I84, the CC governance vectors, the self_roster traces and the registry pins | weekly, 3 shards |
| `scope-601-fixes` | the plaintext DAG caller-input checks, idempotent DEK re-supply, the purge path without a `LocalSigner`, the resumed takedown and the bytes floor's in-transaction tombstone read, the signed receipt instant, and the delivery-receipt length rule | I1400–I1409, I1411, I754, I780–I783, I786, I788–I790, I153, I513 | weekly, 4 shards |
| `scope-601-asks` | the accord threshold and its roster read, the key-grant and `DimensionRejected` retryability predicates, the `identity_amendment:v1` gate, and the takedown reversal (fold, withheld read, finalize skip, re-ack candidates, the reversal's authority) | I1360–I1367, I742, I655, I790, I773, I972, I1218 | weekly, 4 shards |

The scope file names carry the work item that introduced them; the name is
what CI and the allow-list key on, so it does not change.

Some witnesses guard no mutable site by construction (for example I1363 and
I1364 in `scope-601-asks`, which check wire shapes), and kill nothing. Some
witnesses read source files as text, such as I551's catalogue checks; no tool
mutates the string literals and `const` lists they check, so they are shown
red by hand edits against a committed checkpoint.

## Per-slice scopes

Every unit of release work (a "slice" of a release plan) ships its own scope:

1. **A scope file, `scripts/mutants/scope-<slice>.txt`**: a `tests:` filter
   naming the slice's witnesses, a `features:` line when a site compiles only
   under a non-default feature, and the files (functions, for any file over a
   few thousand lines) the slice touched.
2. **One runner:** `scripts/cargo_guard.sh scripts/mutants.sh cargo-mutants
   scripts/mutants/scope-<slice>.txt`. No ad-hoc mutation scripts. A mutation
   the tool does not generate (a revert of the fix, say) is checked by hand
   against a committed checkpoint and reported as such, never by a script that
   rewrites source.
3. **The matrix is the mutation evidence**, cited by path:
   `target/certify-logs/mutants/<scope>[-shard-k-of-n]/matrix.json`,
   `verdict.txt`, `unvalidated.txt`.
4. **Green means exit 0 AND an empty `unvalidated.txt`.** Every mutant is
   caught, or allow-listed with a tracking issue; and every witness in the
   filter killed something (a witness that kills nothing is a witness about a
   neighbouring gate). **Exit 3 means shard it** (`MUTANTS_SHARD=k/n`), never
   shrink the scope to fit.
5. **The scope joins the scheduled matrix** (`.github/workflows/mutants.yml`),
   budget-fitted and sharded.
6. `scripts/mutants_scopes_check.py` (certify fast gate `mutscopes`, and CI)
   keeps every scope honest from disk: it resolves, its `tests:` filter is a
   well-formed filterset whose `test(...)` leaves match a `fn` or `mod` name
   under `src/` or `tests/`, its `features:` exist, and every allow-list line
   names an issue.

A release PR also gets the diff-scoped report: `scripts/mutants_diff.sh
origin/main` runs in the `reports (non-gating)` workflow on every `release-*`
PR (and on any PR labelled `run-mutants`), answering "which changed line can be
mutated with no test noticing?" for the whole diff, not only the sites the
scope chose.

### The scope-file template

```
# Mutation scope: <slice> — <one line: what the slice changed>
# (docs/V<NN>_TASK_PLAN.md §<n>; CIRISPersist#<issue>, ...).
#
# - #<issue>: <door or fold>, what changed. Witness I<nnnn> (<backends>).
# - Named sites left OUT of the scope, and why (e.g. a site only an
#   integration target can witness: scripts/mutants.sh runs --lib).
#
# Grammar: docs/MUTATION_TESTING.md "Scope files".
tests: test(/i<nnnn>|i<mmmm>_/)
features: postgres,sqlite,server            # only when not the default

src/federation/<small_file>.rs              # every mutant in the file
src/federation/<big_file>.rs fn_a fn_b      # only inside these functions
```

### The brief paragraph (copy it into every slice brief)

> **Mutation.** Ship `scripts/mutants/scope-<slice>.txt` (template in
> `docs/MUTATION_TESTING.md` "Per-slice scopes"): `tests:` names your
> witnesses, the entries name the files and (for big files) functions you
> changed, `features:` when a site needs a non-default feature. Check it with
> `python3 scripts/mutants_scopes_check.py`, then run `MUTANTS_BUDGET_SECS=7200
> scripts/cargo_guard.sh scripts/mutants.sh cargo-mutants
> scripts/mutants/scope-<slice>.txt` under nohup (exit 3: shard with
> `MUTANTS_SHARD=k/n`, never shrink). Green is exit 0 with an empty
> `unvalidated.txt`; kill every survivor with a witness, or allow-list it in
> `scripts/mutants/allowed_survivors.txt` with its tracking issue. No ad-hoc
> mutation scripts. Your handoff's mutation table is the matrix by path
> (`target/certify-logs/mutants/<scope>/matrix.json`, `verdict.txt`,
> `unvalidated.txt`).

## Unvalidated witnesses

`scripts/unvalidated_witnesses.py <matrix.json> [<scope>]` lists every witness
in a `*_invariants.rs` file, or a file on the scope's `witnesses:` line, that
ran and killed zero mutants. Such a witness is **unvalidated** (in Beyer's
sense): it has never been shown red, so it is a hypothesis about a gate, not
evidence of one.

- A zero is where to look, not automatically a defect: the scope may not
  contain the code the witness guards.
- On an incomplete run a zero is printed `ZERO SO FAR`, not `UNVALIDATED`,
  because a mutant still `not_run` may be the one it kills.
- A witness the tool never executed (mutest's call-graph misses) is `NOT RUN`,
  with no verdict either way.
- The script itself always exits 0 when the matrix reads; the per-slice rule
  above (an empty `unvalidated.txt`) is where it gates.

## Cadence

- **Never per-PR.** The matrix scripts' own witnesses
  (`scripts/mutants_matrix_test.py`, fixtures, no cargo) run per-PR in
  `ci.yml` and in certify's fast tier (`mutmatrix`), and so does the from-disk
  scope check (`mutscopes`). The diff-scoped report (`scripts/mutants_diff.sh`)
  runs, non-gating, on `release-*` PRs.
- **Nightly and weekly**, in `.github/workflows/mutants.yml`: each scope (or
  shard) is its own job with `MUTANTS_JOBS=1` and a 2-hour budget, and each is a
  gate (exit codes above). The weekly Sunday run adds the larger scopes.
- **Locally**: `certify.sh mutants <scope>`, never alongside another cargo in
  the same tree, and never next to `scripts/powerset.sh check`, which rewrites
  `Cargo.toml` without `[dev-dependencies]` for its whole run.

## Knobs

| variable | default | meaning |
|---|---|---|
| `MUTANTS_BUDGET_SECS` | 7200 | wall budget; on expiry the matrix is written from what finished, `complete: false` |
| `MUTANTS_FEATURES` | the scope's `features:`, else `postgres,sqlite,server` | for mutest set `sqlite,server` (postgres ICE) |
| `MUTANTS_JOBS` | 1 | cargo-mutants `-j`; each job is a full crate build |
| `CARGO_BUILD_JOBS` | 3 | per-build parallelism |
| `MUTANTS_SHARD` | none | `k/n`, 0-based: cargo-mutants' `--shard`; output `<scope>-shard-<k>-of-<n>` |
| `MUTANTS_ALLOW` | `scripts/mutants/allowed_survivors.txt` | the allow-list |
| `MUTANTS_BASELINE_SECS`, `MUTANTS_SECS_PER_MUTANT` | 600, 120 | the sizing model for exit 3 |

With `postgres` on, the run goes through `scripts/pg_test_db.sh`, so a postgres
witness gets a fresh database. Without one it returns before its first
assertion, kills nothing, and is reported unvalidated for a reason that is not
its own.
