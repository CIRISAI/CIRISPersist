# Tooling — size, API breaks, coverage, unused deps, diff mutants, evidence pointers

These instruments measure the codebase beside the test suite. **Most are
reports.** A report prints what it found and exits 0 on a finding, and every CI
job that runs one is `continue-on-error: true`, so none of them turns `main` or
a PR red. Promoting a report to a gate is a deliberate decision, recorded in
this file when it is made.

**One is a gate: evidence pointers.** Every `evidence/cc_impl.tsv` row must
name a definition that exists at HEAD, because a dead pointer is a false
evidence claim, not a measurement.

Each tool's own *witnesses* (fixture tests that the instrument counts what it
claims to) also gate, like every other tool self-test in certify and the lint
job, because a broken instrument produces a report that looks like evidence.

| tool | script | where it runs | report or gate |
|---|---|---|---|
| size tracking | `scripts/size_report.py` | certify fast stage (`sizereport`); ci-hygiene `reports` (daily); reports.yml `size` (PR) | **report** (`--fail-if-backends-grew` is available for a PR to run against its base; it is not wired to main) |
| size witnesses | `scripts/size_report_test.py` | certify fast stage (`sizetest`); ci.yml `lint` | **gate** (red only if the counter is broken) |
| API breaks | `scripts/api_break_report.sh` | reports.yml `semver` (PR, dispatch) | **report** |
| coverage | `scripts/coverage.sh` | reports.yml `coverage` (weekly Monday, dispatch) | **report** |
| CSD/4 coverage | `scripts/csd4_coverage.py` | reports.yml `csd4` (PR, weekly, dispatch) | **report** |
| unused deps | `cargo machete --with-metadata` | ci-hygiene `reports` (daily) | **report** |
| diff mutants | `scripts/mutants_diff.sh` | reports.yml `mutants-diff` (every `release-*` PR, PR label `run-mutants`, dispatch) | **report**; `scripts/mutants.sh`'s scoped matrix is the gate ([MUTATION_TESTING.md](MUTATION_TESTING.md)) |
| evidence pointers | `scripts/evidence_pointers.py check` (+ `_test.py`) | certify fast stage (`evidenceptr`); ci.yml `lint`; ci-hygiene `evidence-pointers` (daily) | **GATE** |
| Constitution pointers | `scripts/evidence_pointers.py register <claims.tsv>` | certify fast stage (`evidenceptrcc`, when a Constitution checkout is found) | **report** |

Installing the cargo tools locally:

    cargo install --locked cargo-semver-checks cargo-llvm-cov cargo-machete cargo-mutants
    rustup component add llvm-tools-preview      # for cargo-llvm-cov

## Size tracking — `evidence/size.tsv`

    scripts/size_report.py write                       # regenerate the table
    scripts/size_report.py check                       # working tree vs the committed table
    scripts/size_report.py check --against v<tag>      # vs src/ at any git ref
    scripts/size_report.py check --against origin/main --fail-if-backends-grew

One row per `src/**/*.rs` file — code, comment and blank lines, the three
columns tokei reports — then `BACKENDS` (`src/store/{sqlite,postgres}.rs`
summed) and `TOTAL`. Stdlib only, so it runs on any runner without an install.
The counter knows `//`, nested `/* */`, doc comments, and string literals (raw
strings included), so a `//` inside `"http://…"` is code. It is deliberately
`#[cfg(test)]`-blind: it measures what a reader pages through, and an inline
test module is part of that. Its code column agrees with tokei within 0.02%.

The table carries no version or date, so it changes only when `src/` does.
Write it at a release cut so the committed table is that release's size;
`--against <tag>` compares any two points without depending on when the table
was last written.

**`--fail-if-backends-grew`** exits 1 when the BACKENDS total grew. It is the
acceptance check for a PR that moves a door from the backends onto the shared
side (CIRISPersist#934: the backend files' net line count goes down). certify's
`sizereport` leg prints the delta and stays green.

## API breaks — `cargo semver-checks`

    scripts/api_break_report.sh v<tag>      # baseline tag; current = working tree
    scripts/api_break_report.sh             # baseline = the latest v* tag before HEAD

Builds rustdoc JSON for both sides (in `target/semver-checks/`, about 2 GB) and
runs `cargo semver-checks check-release` with:

- **the shipped-shape feature set**, `ci_feature_matrix.py set lint`, on both
  sides (`--only-explicit-features`); the ML features are out, since rustdoc
  would have to build candle/ort for API that consumers do not link;
- **`--release-type minor`**, so the tool reports every change that needs a
  major. Left to infer it from `Cargo.toml`, a major version bump would mark
  the breaks allowed.

It prints one line per lint with its distinct instance count (an item
re-exported at two paths is listed once per path); the full report (every item,
with file and line) is `target/semver/<tag>.txt` and the summary
`target/semver/<tag>.summary`. The CHANGELOG's API-break list and the notes to
consumers are written from it. Exit 0 whatever it finds; 1 only when the tool
produced no verdict.

On a PR, the `semver` job compares against the latest `v*` tag reachable from
the base, so it lists every break since the last release (main's and the PR's
together): the list the next CHANGELOG needs, not this PR's alone.

## Coverage — `cargo llvm-cov`, per feature set

    scripts/coverage.sh <leg> [-- <nextest args>]
    scripts/coverage.sh --features "sqlite" -- -E 'test(/migration_immutability/)'

`<leg>` is a certify/CI leg (`ci_feature_matrix.py legs`); its features are
derived exactly as certify's `leg_cmd` derives them. Coverage is per set, not
one `--all-features` union: a line covered only under the union is a line some
shipped configuration never runs. A postgres set runs through
`scripts/pg_test_db.sh`, so the postgres witnesses execute instead of
skipping. Writes `target/coverage/<set>/{lcov.info,summary.txt,html/}` and
prints the TOTAL line. Instrumented objects go to cargo-llvm-cov's own
`target/llvm-cov-target/`, never mixed with certify's.

**Cost.** A whole leg instrumented costs a certify leg plus the instrumentation
overhead. CI runs every leg weekly (reports.yml, legs derived at run time);
locally, scope it with a nextest filter, and never run a whole leg beside
another build.

Lines, regions and functions only: branch coverage (`--branch`) needs a nightly
toolchain, and this crate pins stable, so the `Branches` column reads `-`.

Why it exists: the mutation matrices prove that witnesses *enforce* what they
guard at chosen sites; they say nothing about code no test executes.

## CSD/4 coverage — `scripts/csd4_coverage.py`

Joins the Constitution's CSD/4 chain manifest (vendored as
`src/federation/namespace/csd4_chain.json`) to `evidence/cc_impl.tsv`, the
witnesses and the mutation scopes, and prints the gap lists: chain references
with no evidence row, evidence rows no atom reaches, atoms with claims but no
witness or no mutation scope, and refusal tokens one side names that the other
never spells. CI writes the report as the `csd4-coverage` artifact and puts the
gap counts in the step summary. Report only.

## Unused dependencies — `cargo machete`

    cargo machete --with-metadata

`--with-metadata` resolves renamed crates through `cargo metadata`, and finds
what the plain mode misses. It currently names two `[dev-dependencies]`,
`hex-literal` and `tracing-subscriber`, which no `.rs` file uses. A finding is
resolved by deleting the dependency or by naming it under
`[package.metadata.cargo-machete] ignored` with the reason.

## Evidence pointers — `scripts/evidence_pointers.py` (a GATE)

    scripts/evidence_pointers.py check                    # evidence/cc_impl.tsv at the working tree
    scripts/evidence_pointers.py check --ref v<tag>       # the tsv and src/ at a git ref
    scripts/evidence_pointers.py register ../CIRISConstitution/constitution/claims.tsv
    python3 scripts/evidence_pointers_test.py             # the checker's witnesses

Every `src/` row of `evidence/cc_impl.tsv` (`path#symbol`) must name a
definition in its cited file. Comments of every kind and every string, byte,
raw and char literal are blanked first. A bare name resolves to an `fn`,
`struct`, `enum`, `trait`, `type`, `const`, `static`, `mod`, `union` or
`macro_rules!` definition, an enum variant, or a named struct field.
`Owner::member` resolves only to a member of a block owned by `Owner`: the
enum, struct, trait or module itself, or an `impl` for it. A mention, a `use`,
a call site or a string never resolves. A symbol that moved to another file
fails until its row is repointed. Cross-repo rows (not under `src/`) resolve at
their own crate's build and are skipped.

It is stricter than the in-crate witness `evidence_cc_impl_pointers_resolve`,
which accepts any non-comment line containing `name(` or `name,` and takes the
bare member of `Owner::member` anywhere in the file; a doc comment or a string
literal in a test list can keep a dead pointer "resolved" there, never here.

`register` checks the Constitution's register (`impl:CIRISPersist/src/…#a,b`
pointers) against this tree. certify runs it as the `evidenceptrcc` report when
it finds a checkout at `CIRIS_CONSTITUTION_DIR` (default `../CIRISConstitution`),
so a release cut lists the rows the next Constitution re-pin must repoint.

What it cannot see: a pointer whose symbol still exists but no longer does what
the claim says.

## Mutants on the diff — `cargo mutants --in-diff`

    scripts/mutants_diff.sh origin/main
    scripts/mutants_diff.sh origin/main -- -F 'plan_enter_mesh'      # one function
    MUTANTS_DIFF_BUDGET_SECS=1800 scripts/mutants_diff.sh <base>

Diffs the working tree against `merge-base(<base>, HEAD)` over `src/**/*.rs`
and mutates exactly the changed lines. Output in `target/mutants-diff/`:
`scope.diff`, `list.txt`, cargo-mutants' `mutants.out/`, and `summary.txt`
(caught / MISSED / timeout / unviable, with every missed mutant named).
Features default to `.cargo/mutants.toml`'s `sqlite`; `MUTANTS_DIFF_FEATURES`
adds more (a set with `postgres` runs through `pg_test_db.sh`). A wall-clock
budget (`MUTANTS_DIFF_BUDGET_SECS`, default 3600) interrupts a long run and the
summary says INCOMPLETE.

CI runs it on every `release-*` PR, on a PR carrying the label **`run-mutants`**,
and by dispatch; never on every PR, because each mutant is a rebuild plus a test
run. A `labeled` event has a concurrency group of its own per label, so adding a
label never cancels a running size or semver report.

It answers a question nobody chose the sites for, "which changed line can be
mutated with no test noticing?", and so it complements `scripts/mutants.sh`'s
scoped matrix (which witness kills which mutant; that one is a gate). A known
limit, shared with the tool: `--in-diff` selects by line, and a change inside a
`#[cfg(all(test, …))]` module that cargo-mutants does not recognise as test code
yields mutants in test code.
