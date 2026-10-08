# Mutation testing — the per-witness detection matrix (CIRISPersist#1024)

Until v53.2.0 every mutation round was hand-picked per PR and recorded only in
the CHANGELOG ("the 10-mutant round"). Nothing said which witness was
load-bearing for which site after the PR merged. A surviving mutant is a claim
about the WITNESS; the matrix is that claim, regenerated on demand, without
hand selection.

    scripts/mutants.sh <cargo-mutants|mutest> <scope-file>

writes `target/certify-logs/mutants/<scope>/matrix.{json,md}` and
`unvalidated.txt`. It is **report-only**: exit 0 whenever a matrix is written,
however many mutants survive. Non-zero only when no matrix can be produced
(tool missing, red baseline, broken build, unresolvable scope).

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
  "summary": {"mutants": 74, "caught": 42, "missed": 2, "timeout": 3, "unviable": 4, "not_run": 23},
  "kills_per_test": {"observe::tests::memory::i549": 38},
  "tests_killing_nothing": ["..."],
  "tests_never_run": ["<mutest only: outside its static call graph>"]
}
```

- `outcome` is `caught | missed | timeout | unviable | not_run`. A `caught`
  mutant with an empty `killed_by` was caught by a crash or build failure the
  log does not attribute to one test.
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
   `python3 scripts/mutants_matrix.py resolve cargo-mutants <scope>`.
4. Run it: `MUTANTS_BUDGET_SECS=7200 scripts/mutants.sh cargo-mutants <scope>`.

Three scopes exist:

- `scope-consent.txt`: the consent gates and the counters.
- `scope-consent-gate.txt`: the two consent files only, against the I548
  witnesses. It exists so the gate can be measured in about 11 minutes
  without the 61 `observe/` mutants.
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

- **Never per-PR.** `scope-consent` is about 70 minutes serially;
  `scope-consent-gate` 11.
- **Nightly**: `scope-consent` with cargo-mutants, `MUTANTS_JOBS=1`, a 2-hour
  budget, alone on the runner. The artefact is the matrix; a diff in `kills_per_test` from the last
  night is what someone reads.
- **Weekly**: `scope-observe-sites`, whose mutant count is not yet measured,
  with a 4-hour budget.
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

With `postgres` on, the run goes through `scripts/pg_test_db.sh`, so a
postgres witness gets a fresh database. Without one it returns before its
first assertion, kills nothing, and is reported unvalidated for a reason that
is not its own.
