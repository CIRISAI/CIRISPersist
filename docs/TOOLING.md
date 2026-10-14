# Tooling — size, API breaks, coverage, unused deps, diff mutants, evidence pointers (CIRISPersist#934)

v56.0.0 (#1076 slice T) adds six instruments beside the consolidation #934
plans. **Five are reports.** Each prints what it found and exits 0 on a
finding; every CI job that runs one is `continue-on-error: true`, so none of
them turns `main` or a PR red. Promoting any of them to a gate is the
operator's decision, recorded in this file when it is made.

**One is a gate: evidence pointers.** Every `evidence/cc_impl.tsv` row must
name a definition that exists at HEAD, because a dead pointer is a false
evidence claim, not a measurement. It came from the Constitution's review of
the v54 → v55 re-pin, where a dead pointer was repaired by hand.

The other exception is each tool's own *witnesses* (fixture tests that the
instrument counts what it claims to): those gate, like every other tool
self-test in certify and the lint job, because a broken instrument produces
a report that looks like evidence.

| tool | script | where it runs | report or gate |
|---|---|---|---|
| size tracking | `scripts/size_report.py` | certify fast stage (`sizereport`); ci-hygiene `reports` (daily); reports.yml `size` (PR) | **report** (`--fail-if-backends-grew` is the #934 PR criterion, not wired to main) |
| size witnesses | `scripts/size_report_test.py` | certify fast stage (`sizetest`); ci.yml `lint` | **gate** (red only if the counter is broken) |
| API breaks | `scripts/api_break_report.sh` | reports.yml `semver` (PR, dispatch) | **report** |
| coverage | `scripts/coverage.sh` | reports.yml `coverage` (weekly Monday, dispatch) | **report** |
| unused deps | `cargo machete --with-metadata` | ci-hygiene `reports` (daily) | **report** |
| diff mutants | `scripts/mutants_diff.sh` | reports.yml `mutants-diff` (PR label `run-mutants`, dispatch) | **report** — the PR's hand mutation table and `scripts/mutants.sh`'s scoped matrix stay the gates |
| evidence pointers | `scripts/evidence_pointers.py check` (+ `_test.py`) | certify fast stage (`evidenceptr`); ci.yml `lint`; ci-hygiene `evidence-pointers` (daily) | **GATE** |
| Constitution pointers | `scripts/evidence_pointers.py register <claims.tsv>` | certify fast stage (`evidenceptrcc`, when a Constitution checkout is found) | **report** |

Installing the cargo tools locally:

    cargo install --locked cargo-semver-checks cargo-llvm-cov cargo-machete cargo-mutants
    rustup component add llvm-tools-preview      # for cargo-llvm-cov

## Size tracking — `evidence/size.tsv`

    scripts/size_report.py write                       # regenerate the table
    scripts/size_report.py check                       # working tree vs the committed table
    scripts/size_report.py check --against v55.0.0     # vs src/ at any git ref
    scripts/size_report.py check --against origin/main --fail-if-backends-grew

One row per `src/**/*.rs` file — code, comment and blank lines, the three
columns tokei reports — then `BACKENDS` (`src/store/{sqlite,postgres,memory}.rs`
summed) and `TOTAL`. Stdlib only, so it runs on any runner without an install.
The counter knows `//`, nested `/* */`, doc comments, and string literals
(raw strings included), so a `//` inside `"http://…"` is code. It is
deliberately `#[cfg(test)]`-blind: it measures what a reader pages through,
and an inline test module is part of that. On v55.0.0 its code column agrees
with tokei 14.0.0 within 0.02% (BACKENDS 112 411 vs 112 392).

The table carries no version or date, so it changes only when `src/` does.
Write it at a release cut so the committed table is that release's size;
`--against <tag>` compares any two points without depending on when the table
was last written.

**`--fail-if-backends-grew`** exits 1 when the BACKENDS total grew. It is
#934 step 1's acceptance criterion ("the net line count of the three backend
files goes DOWN"), for the PR that moves a door onto the shared side to run
against its base. #1076 also proposes a certify fast gate "the backend total
did not grow unless the CHANGELOG names why"; until the operator promotes it,
certify's `sizereport` leg prints the delta and stays green.

## API breaks — `cargo semver-checks`

    scripts/api_break_report.sh v54.1.1     # baseline tag; current = working tree
    scripts/api_break_report.sh             # baseline = the latest v* tag before HEAD

Builds rustdoc JSON for both sides (in `target/semver-checks/`, ~2 GB) and runs
`cargo semver-checks check-release` with:

- **the shipped-shape feature set**, `ci_feature_matrix.py set lint`, on both
  sides (`--only-explicit-features`); the ML features are out, since rustdoc
  would have to build candle/ort for API Edge does not link;
- **`--release-type minor`**, so the tool reports every change that needs a
  major. Left to infer it from Cargo.toml, a major version bump would mark
  the breaks allowed.

It prints one line per lint with its distinct instance count; the full report
(every item, with file and line) is `target/semver/<tag>.txt` and the summary
`target/semver/<tag>.summary`. The CHANGELOG's API-break list and the note to
Edge are written from it. Exit 0 whatever it finds; 1 only when the tool
produced no verdict.

On this tree, **v54.1.1 → v55.0.0: 12 lints, 71 distinct instance lines**
(an item re-exported at two paths is listed once per path) — 14
`function_missing`, 9 `struct_missing`, 8 `enum_variant_added`, 8
`pub_module_level_const_missing`, 7 `trait_method_added`, 7
`constructible_struct_adds_field`, 6 `inherent_method_missing`, and 3 each
of the parameter-count lints, 2 `struct_pub_field_missing`, 1 generic-params.

On a PR, the `semver` job compares against the latest `v*` tag reachable
from the base, so it lists every break since the last release (main's and the
PR's together) — the list the next CHANGELOG needs, not this PR's alone.

## Coverage — `cargo llvm-cov`, per feature set

    scripts/coverage.sh <leg> [-- <nextest args>]
    scripts/coverage.sh --features "sqlite" -- -E 'test(/migration_immutability/)'

`<leg>` is a certify/CI leg (`ci_feature_matrix.py legs`); its features are
derived exactly as certify's `leg_cmd` derives them. Per set, not one
`--all-features` union: a line covered only under the union is a line some
shipped configuration never runs. A postgres set runs through
`scripts/pg_test_db.sh`, so the postgres witnesses execute instead of
skipping. Writes `target/coverage/<set>/{lcov.info,summary.txt,html/}` and
prints the TOTAL line. Instrumented objects go to cargo-llvm-cov's own
`target/llvm-cov-target/`, never mixed with certify's.

**Cost.** A whole leg instrumented costs a certify leg plus the instrumentation overhead.
CI runs every leg weekly (reports.yml, legs derived at run time); locally,
scope it with a nextest filter, and never run a whole leg beside another
build.

Lines, regions and functions only: branch coverage (`--branch`) needs a
nightly toolchain, and this crate pins stable 1.97.0, so the `Branches`
column reads `-`.

Proven on this tree (2026-10-13): `scripts/coverage.sh --features sqlite --
-E 'test(/migration_immutability/)'` ran 6 tests (3687 skipped) and wrote the
report; `src/store/migration_immutability.rs` 76.34% of lines, 77.19% of
regions; TOTAL 0.08% of lines, as a 6-test scope should read.

Why it exists: the mutation tables prove that witnesses *enforce* what they
guard at chosen sites; they say nothing about code no test executes.

## Unused dependencies — `cargo machete`

    cargo machete --with-metadata

`--with-metadata` resolves renamed crates through `cargo metadata`; the plain
mode reported nothing on v55.0.0, where this one names two
`[dev-dependencies]`: **`hex-literal`** and **`tracing-subscriber`** (no
`hex_literal`/`hex!` or `tracing_subscriber` use in any `.rs` file). They are
listed, not removed: the operator decides, either deleting them or naming them
under `[package.metadata.cargo-machete] ignored` with the reason.

## Evidence pointers — `scripts/evidence_pointers.py` (a GATE)

    scripts/evidence_pointers.py check                    # evidence/cc_impl.tsv at the working tree
    scripts/evidence_pointers.py check --ref v55.0.0      # the tsv and src/ at a git ref
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
fails until its row is repointed. Cross-repo rows (not under `src/`) resolve
at their own crate's build and are skipped.

It is stricter than the in-crate witness `evidence_cc_impl_pointers_resolve`,
which accepts any non-comment line containing `name(` or `name,` and takes
the bare member of `Owner::member` anywhere in the file. That is how the
v54 → v55 dead pointer, `blobs.rs#holds_bytes_attestation_envelope`, stayed
"resolved": a doc comment and a string literal in a test list still named it.

That pointer sat in the Constitution's register, not in this tsv, which
resolves at every tag from v46.0.0 to v55.0.0. `register` checks a register's
`impl:CIRISPersist/src/…#a,b` pointers against this tree: on the register
just before re-pin 16 (CIRISConstitution `fca367d^`) it names exactly that
row, and on the current register it finds none. certify runs it as the
`evidenceptrcc` report when it finds a checkout at `CIRIS_CONSTITUTION_DIR`
(default `../CIRISConstitution`), so a release cut lists the rows the next
re-pin must repoint.

What it cannot see: a pointer whose symbol still exists but no longer does
what the claim says. The other pointer the re-pin repaired,
`admission.rs#STAGED_GOVERNED_FAMILIES`, is that kind.

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

CI runs it only on a PR carrying the label **`run-mutants`** (or by dispatch),
never by default: each mutant is a rebuild plus a test run. The label has to
exist in the repository before anyone can apply it. A `labeled` event has a
concurrency group of its own per label, so adding a label never cancels a
running size or semver report.

Proven on this tree (2026-10-13), against base `911ab18e^`: 137 changed
lines, 46 of them outside test-only items, in 2 files; one mutant
(`src/federation/holding_claim.rs:704`, `reack_own_claims` replaced with
`Ok(Default::default())`); the unmutated baseline green (284 s build, 5 s
test). The mutant's own build and test did not finish, because the session
running it was killed by the out-of-memory killer, so there is no verdict
for it yet. The scope, list and baseline stages are what this proves.

This answers a question nobody chose the sites for — "which changed line can
be mutated with no test noticing?" — and so it complements, and does not
replace, the hand mutation table each PR carries (enforcement at the sites
that matter) or `scripts/mutants.sh`'s scoped matrix (which witness kills
which mutant; that one IS a gate, nightly). Known limit, shared with the
tool: `--in-diff` selects by line, and a change inside a
`#[cfg(all(test, …))]` module that cargo-mutants does not recognise as test
code yields mutants in test code (docs/MUTATION_TESTING.md, "Selection is by
line").
