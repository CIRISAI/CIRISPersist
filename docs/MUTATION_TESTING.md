# Mutation testing — the per-witness detection matrix (CIRISPersist#1024)

Until v53.2.0 every mutation round was hand-picked per PR and recorded only in
the CHANGELOG ("the 10-mutant round"). Nothing said which witness was
load-bearing for which site after the PR merged. A surviving mutant is a claim
about the WITNESS; the matrix is that claim, regenerated on demand, without
hand selection.

    scripts/mutants.sh <cargo-mutants|mutest> <scope-file>

writes `target/certify-logs/mutants/<scope>/matrix.{json,md}`,
`unvalidated.txt` and `verdict.txt`.

## The gate (v54.1.0, CIRISPersist#1051)

Until v54.1.0 the run was report-only. The first scheduled run (650024b1,
2026-10-09) hit its 2-hour budget with 8 of 85 mutants untested, had 6
survivors, and its job was **green**. Its `unvalidated.txt` said "0 witnesses
ran", because `CARGO_TERM_COLOR=always` coloured nextest's status lines and
the matrix reader matched none of them. Now:

| exit | meaning |
|---:|---|
| 0 | complete, and every surviving mutant is allow-listed with an issue |
| 1 | no matrix (tool missing, red baseline, broken build, or a green baseline whose log yields no status line) |
| 2 | usage, an unresolvable scope, or a malformed allow-list |
| 3 | refused before building: the scope does not fit the budget at `MUTANTS_BASELINE_SECS + N × MUTANTS_SECS_PER_MUTANT` (600 + 120 s; measured on that run: baseline 305 s, p90 105 s per mutant) |
| 4 | INCOMPLETE: the budget expired or a mutant was never tested |
| 5 | a surviving mutant (`missed`, `timeout`, `caught_out_of_scope`) not in `scripts/mutants/allowed_survivors.txt`; or a mutant cargo-mutants ran that the matrix filed out of scope ("scope disagreement": it was tested and judged nowhere) |

`scripts/mutants_matrix.py verdict` writes the same verdict to
`$GITHUB_STEP_SUMMARY` and as annotations (`::error` for an unlisted survivor
or an incomplete run, `::warning` for an allowed one). An allow-list entry is
`<file>[:<line>] <cargo-mutants' mutation text> #<issue>`: the text is the
tool's own, compared exactly, and a line without an issue number is refused.

**Selection is by line, through `--in-diff`.** cargo-mutants 27.1 applies
neither `-F` nor `-E` to its struct-field deletions, so a function-name regex
let `delete field as_of` in four functions outside the scope, and two field
deletions in `#[cfg(all(test, ..))] mod r2_test_support`, into every run.
`resolve` now writes the scope as a diff that adds exactly its lines, minus
every test-only item (`#[cfg(test)]`, `#[cfg(all(test, ..))]`, a `mod
*test_support*`), and passes `--in-diff`. The matrix keeps a mutant whose
span touches a scope line, as `--in-diff` does; by first line alone,
`counters()`'s whole-body replacement (it starts on a `#[cfg(test)]`
statement) was tested and then dropped unjudged.

**A hung witness fails in 60 s.** The run uses nextest's `mutants` profile
(`.config/nextest.toml`): a witness that hangs under a mutant is killed after
three 20 s periods and reads as its FAIL, instead of a 300 s tool timeout
credited to no witness (`record_read`'s three loop mutants cost 1049 s of the
first run). I692 additionally bounds the fold-mask loop in a 5 s deadline.

## Verdict: cargo-mutants

Three runs on 2026-10-07/08, all numbers read from the matrices on disk:

- `scope-consent` with cargo-mutants: stopped by the harness at 51 of 74
  (memory pressure from a build beside it). **INCOMPLETE.**
- `scope-consent-gate` with cargo-mutants: the two consent files only, run
  alone after that. **Complete.**
- `scope-consent` with mutest-rs. Complete, but it reached almost nothing.

| | cargo-mutants 27.1.0 | mutest-rs (git 430efed9) |
|---|---|---|
| toolchain | the repo's pinned stable, 1.97.0 | `nightly-2026-07-18` (rustc-driver; must match the mutest build) |
| features | `postgres,sqlite,server` | `sqlite,server` only: with `postgres` the build hits an internal compiler error in `mutest-emit` (`analysis/res.rs:758`, `deadpool::managed::pool::Pool` path resolution) |
| build | baseline 114–267 s; each mutant an incremental rebuild of about 17–83 s | 257 s once (meta-mutant binary), peak RSS 8.2 GiB |
| test | baseline 4–10 s for the scope's witnesses; 3–11 s per mutant, 300 s on a timeout | reference profiling of the WHOLE lib suite: 1688 s (3351 tests; it has no test filter), then 0.2 s of mutant runs |
| witnesses run | every one in the filter, on memory, sqlite and postgres | 1 of 16 |
| mutants generated in the consent gate | 13 | 0 |

| run | in scope | caught | missed | timeout | unviable | not run | wall |
|---|---:|---:|---:|---:|---:|---:|---:|
| cargo-mutants `scope-consent` | 74 | 42 | 2 | 3 | 4 | 23 | 2954 s, stopped |
| cargo-mutants `scope-consent-gate` | 13 | 9 | 1 | 0 | 3 | 0 | 654 s |
| mutest `scope-consent` | 14 | 2 | 12 | 0 | 0 | 0 | 1941 s |

**Why not mutest-rs, though it is the faster design.** Its static call graph
does not reach persist's async witnesses. Of the 16 in-scope witnesses it ran
one, `observe::tests::i551_samples_carry_exactly_the_catalogued_names_and_labels`,
the only synchronous one. Every `i548*`, `i549`, `i550` witness is marked
"never run". The run logged 697 "encountered dynamic call" warnings during call
graph construction (the executor capsule's vtable, `Box::pin(self.run(..))`
futures), and it generated **no mutant at all** in `consent_by_humans.rs` or
`admission.rs`, where cargo-mutants found 13 and the I548 witnesses kill 9.
Add the pinned nightly, the postgres ICE, the 8.2 GiB build and a 28-minute
whole-suite profiling pass per run, and it does not answer the question #1024
asks. Revisit when mutest-rs resolves async call edges.

**Why cargo-mutants.** It runs on the pinned stable toolchain, builds every
backend, and runs every witness under every mutant through nextest with
`--no-fail-fast`, so `killed_by` lists every witness that went red, not the
first. Cost is a rebuild per mutant. Measured: about 55 s per mutant on the
observe run (51 mutants in 2954 s, three of them 300 s timeouts) and 50 s on
the gate run (13 in 654 s). A complete 74-mutant `scope-consent` run is
therefore about 70 min serially (PROJECTED from those rates). Peak RAM per job
was not recorded; the observe run was stopped for memory when a build ran
beside it, so run it alone, `MUTANTS_JOBS=1`.

**The 2 MB test-thread stack / ML-DSA.** mutest's reference pass profiled 3351
lib tests, the ML-DSA hybrid-verify tests among them, with no stack overflow
and no SIGSEGV in the log. The one panic it printed is the intended
`#354 containment probe`. cargo-mutants runs the ordinary nextest binary, so
it inherits the existing stack handling unchanged.

## What the matrices say, against the hand rounds

CHANGELOG `## [53.1.8]` records I548 3/3 and I549–I551 10/10. The tool does
not reproduce those exact mutants. It generates its own, at the same sites.
At those sites it agrees with the hand rounds wherever both ran, and it found
three survivors the hand rounds never tried.

### Consent gate: `scope-consent-gate`, complete

13 mutants in `check_capacity_consent_admission` and the three
`consent_by_humans.rs` folds: 9 caught, 3 unviable, 1 missed. The 3 unviable
are the `Ok(Default::default())` body replacements: the return types have no
`Default`. All 13 I548 witnesses killed at least one mutant, on all three
backends:

| witness (each of memory, sqlite, postgres) | kills |
|---|---:|
| `i548a` | 5 |
| `i548b` | 4 |
| `i548c` | 9 |
| `i548d` | 4 |
| `i548e_one_fold_every_door` (backend-independent) | 1 |

- `check_capacity_consent_admission -> Ok(())` was killed by i548e and every
  b, c and d. The stance check at `admission.rs:4540` was killed by every
  a–d. The tier and self-attestation checks at `:4515` and `:4518` were
  killed by every b–d.
- The fold's subject filter (`:258`), steward skip (`:275`) and the universe
  predicate's `:281`, `:283:21` and `:283:63` operators were killed by i548a
  and i548c; `:281` by i548c alone.
- **The hand round's 3 mutants have no tool equivalent.** All three are
  semantic swaps no operator produces: calling the subject-only
  `resolve_scoped_consent` instead, asking bare `analyze`, and printing the
  constant in the refusal. The tool's 13 cover the same two functions with
  coarser edits. Both sets show the same witnesses load-bearing. The hand
  round's gate reversion went red on i548a, c and e; the tool's `Ok(())` and
  `:4540` flip together went red on all five.
- **The survivor is a witness gap, filed as #1038.** It is
  `consent_by_humans.rs:282:21`, the first `||` replaced with `&&` in
  `resolve_scoped_stance_by_principals_body`. The predicate builds each
  steward `p`'s universe:

  ```rust
  a.attesting_key_id != *p
      || super::precedence::is_structural_composer(&a.attestation_type)
      || for_key_id_of(&a.attestation_envelope) == Some(subject_key_id)
  ```

  The mutant makes it `(A && B) || C`, so a row from another author survives
  only if it is a composer or names the subject. The steward's fold reads one
  kind of row from another author: the substrate's `consent:state:expired`
  record, through `substrate_expiry_bound_to_subject`. That record is not a
  composer and deliberately carries no `for_key_id` (`consent_expiry.rs`
  module doc), so the mutant drops it. A steward's grant that lapsed by
  `expires_at` and was swept then reads `Unspecified` instead of `Expired`
  from `capacity_consent_stance`. The admit verdict is unchanged, because
  neither is `Granted`. So it is not equivalent: the reported stance changes,
  and no I548 case has a swept steward grant. That analysis is from reading
  the code; it was not reproduced with a test.

### Read and fold counters: `scope-consent`, INCOMPLETE at 51 of 74

All 51 that ran are in `src/observe/mod.rs`: 42 caught, 4 unviable, 3
timeouts, 2 missed. The 23 not run are 10 in `src/observe/mod.rs`
(`TelemetrySnapshot::fold` constants from `(1, 0, 0, 1)` on, its `==` at
`:424`, and both `TelemetrySnapshot::samples` replacements at `:431`) and
the 13 consent-gate mutants, which `scope-consent-gate` then ran in full.

| witness | kills |
|---|---:|
| `sqlite::i549` | 41 |
| `memory::i549` | 38 |
| `postgres::i549` | 38 |
| `sqlite::i550` | 25 |
| `postgres::i550` | 24 |
| every `i551*` | 0 so far |

- **The 3 timeouts** are `record_read`'s mask loop at `:316` (`&=` to `|=`,
  `-` to `+`, `-` to `/`). Each never clears the mask, so the witness hangs
  until nextest's 300 s limit. cargo-mutants counts a timeout as detected,
  but no witness is credited with it.
- **The 2 survivors are filed as #1037.** One is `Counters::snapshot`'s
  `n > 0` changed to `>=` (`:247`). The other is `fold`'s `|` changed to `^`
  (`:330`), which only differs when a fold is re-entered with its own bit
  already set.
- **Against I549–I551's 10 hand mutants:**
  - Four have tool equivalents that were caught by the same witness:
    - "a fold scope that omits its own bit" is `Fold::bit -> 0`, killed by
      i549 on all three backends.
    - "`record_read` skipping a door increment" (two hand mutants) is
      `record_read` replaced with `()`, killed by i549 and i550, and the
      `!=` to `==` at `:313`, killed by i549.
    - "sqlite's row mapper not noting envelope bytes" is
      `note_decoded_bytes` replaced with `()`, killed by sqlite::i549.
  - One, "the fold credit dropped from `record_read`", corresponds to the
    `:316` timeouts: detected, not attributed.
  - Three (`pg_envelope_bytes`, `trust_root_valid`, `put_attestation`) are in
    `scope-observe-sites.txt`, which has not run.
  - Two, a value dropped from or added to `catalog::DOOR_VALUES`, cannot be
    generated: neither tool mutates a `const` slice literal or generated any
    mutant in `src/observe/catalog.rs`. I551's from-disk catalogue checks stay
    hand-mutated witnesses.
- **mutest's 12 survivors** are all at `src/observe/mod.rs:431`, inside the
  `Vec::with_capacity` size hint of `TelemetrySnapshot::samples`. They are
  equivalent mutants: a capacity hint never changes the output.

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
  "tests": ["observe::tests::memory::i549", "..."],
  "mutants": [{"id": 1, "file": "src/observe/mod.rs", "line": 175, "col": 9,
               "description": "src/observe/mod.rs:175:9: replace Fold::bit -> u32 with 0",
               "outcome": "caught", "killed_by": ["observe::tests::memory::i549", "..."]}],
  "out_of_scope": ["<generated by the tool, outside every scope range>"],
  "summary": {"mutants": 74, "caught": 42, "caught_out_of_scope": 0, "crashed": 0,
              "missed": 2, "timeout": 3, "unviable": 4, "not_run": 23},
  "kills_per_test": {"observe::tests::memory::i549": 38},
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
  was detected, but only by tests outside the scope: it counts as a
  detection by the suite, never as a kill by the witness set the matrix
  measures. `crashed` means the harness crashed under the mutant and no
  test's row attributes it. Until the Codex review of PR #1039 the mutest
  outcome was copied from mutest's whole-suite flag, which labelled
  out-of-scope detections `caught` with an empty killer list.
- `complete` is false when the budget expired or any in-scope mutant is
  `not_run`. For cargo-mutants the not-run set is read from the tool's own
  `mutants.json`: an interrupted run's `outcomes.json` lists only the mutants
  that finished, and a matrix built from it alone read "complete" until
  v53.2.0 fixed that.
- `matrix.md` is the same data as two tables: one row per mutant with its
  killers, one row per witness with its kill count. A zero is bold; a witness
  the tool never ran says so.

## Scope files

`scripts/mutants/<name>.txt`. The name becomes the output directory.

```
# comment to end of line
tests: <nextest filterset>      the witnesses measured; required
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

Three scopes exist (v54.1.0; `scope-consent.txt` held the first two
together and did not fit its budget):

- `scope-consent-gate.txt`: the consent gate, against the I548 and I570
  witnesses. 19 mutants. v54.0.0 had moved the gate's universe predicate into
  `per_principal_stances`, which the scope did not name: it is named now.
- `scope-observe.txt`: `src/observe/`, against I549–I553 and I690–I692.
  71 mutants, run as two shards (`MUTANTS_SHARD=0/2`, `1/2`).
- `scope-observe-sites.txt`: the call sites in the 3k–28k-line backend and
  federation files that feed the counters. The issue's other starting modules
(the `trust_root.rs` walks beyond `trust_root_valid`) are not yet scoped.

## Unvalidated witnesses

`scripts/unvalidated_witnesses.py <matrix.json> [<scope>]` lists every witness
in a `*_invariants.rs` file, or a file on the scope's `witnesses:` line, that
ran and killed zero mutants. In Beyer 2022's sense such a witness is
**unvalidated**: it has never been shown red, so it is a hypothesis about a
gate, not evidence of one.

- A zero is where to look, not automatically a defect: the scope may not
  contain the code the witness guards.
- On an incomplete run a zero is printed `ZERO SO FAR`, not `UNVALIDATED`,
  because a mutant still `not_run` may be the one it kills.
- A witness the tool never executed (mutest's call-graph misses) is `NOT RUN`,
  with no verdict either way.
- Report-only this cut: always exit 0 when the matrix reads. The intended
  next step is a gate on a complete matrix: a non-empty `UNVALIDATED` list for
  a named scope fails the scheduled job.

Across the runs above:

- **`scope-consent-gate`, complete.** No unvalidated witness. All 13 I548
  witnesses killed at least one mutant.
- **`scope-consent`, incomplete.** 17 witnesses at `ZERO SO FAR`. The 13
  `i548*` among them are settled by the gate run above: their mutants simply
  had not run here. The 4 `i551*` remain.
- **mutest.** `i551_samples_carry_exactly_the_catalogued_names_and_labels`
  killed 2 mutants (the `.clone()` at `src/observe/mod.rs:444`), which
  validates it.
- **Still never shown red by a tool:** `i551_each_backend_records_under_its_own_label`,
  `i551_every_emitted_label_is_catalogued_and_every_catalogued_one_emitted`
  and `i551_strip_comments_strips_both_shapes`. They read source files as
  text, and neither tool mutates the string literals and `const` lists they
  check. The 53.1.8 hand round showed the second one red (the `DOOR_VALUES`
  edits). The other two have no recorded red. Mutating them needs hand
  edits, not a tool.

## Cadence

- **Never per-PR.** The matrix scripts' own witnesses
  (`scripts/mutants_matrix_test.py`, fixtures, no cargo) run per-PR in
  `ci.yml` and in certify's fast tier (`mutmatrix`).
- **Nightly** (v54.1.0): `scope-consent-gate`, and `scope-observe` as two
  shards, each its own job with `MUTANTS_JOBS=1` and a 2-hour budget. Each is
  a gate (exit codes above).
- **Weekly**: `scope-observe-sites` (12 mutants), also a gate.
- Locally: `certify.sh mutants <scope>` once wired (see
  `docs/CI_WIRING_53_2_0.md`), never alongside another cargo in the same tree,
  and never next to `scripts/powerset.sh check`: that rewrites `Cargo.toml`
  without `[dev-dependencies]` for its whole run. The first mutest build here
  failed with 544 "cannot find crate" errors for exactly that reason.

## Knobs

| variable | default | meaning |
|---|---|---|
| `MUTANTS_BUDGET_SECS` | 7200 | wall budget; on expiry the matrix is written from what finished, `complete: false` |
| `MUTANTS_FEATURES` | `postgres,sqlite,server` | for mutest set `sqlite,server` (postgres ICE) |
| `MUTANTS_JOBS` | 1 | cargo-mutants `-j`; each job is a full crate build |
| `CARGO_BUILD_JOBS` | 3 | per-build parallelism |
| `MUTANTS_SHARD` | none | `k/n`, 0-based: cargo-mutants' `--shard`; output `<scope>-shard-<k>-of-<n>` |
| `MUTANTS_ALLOW` | `scripts/mutants/allowed_survivors.txt` | the allow-list |
| `MUTANTS_BASELINE_SECS`, `MUTANTS_SECS_PER_MUTANT` | 600, 120 | the sizing model for exit 3 |

**mutest-rs is not wired into the nightly job** (#1051 asked). The verdict
above still stands: on CI it would need the pinned nightly toolchain and a
from-git build of mutest (no release binary), it cannot build with `postgres`
(the `mutest-emit` ICE), it profiles the whole 3351-test lib suite (28 min)
per run, and it reaches 1 of the scope's async witnesses. A nightly job
would run about 30 minutes to measure one synchronous test.

With `postgres` on, the run goes through `scripts/pg_test_db.sh`, so a
postgres witness gets a fresh database. Without one it returns before its
first assertion, kills nothing, and is reported unvalidated for a reason that
is not its own.
