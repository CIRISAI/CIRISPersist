# v53.2.0 wiring — mutation tier (#1024) and powerset (#1025)

The branch `ci-mutants-powerset` adds scripts and docs only. It does not edit
`scripts/certify.sh`, `scripts/ci_feature_matrix.py` or
`.github/workflows/ci.yml`. These are the lines to add at merge. None of them
has been run; each is BELIEVED until the first run.

## 1. `scripts/certify.sh` — `mutants` (report-only) and `powerset` (compile-only)

Header, after the `certify.sh full` line (the help prints lines 2–9, so widen
that `sed -n '2,9p'` to `'2,11p'`):

```bash
#   certify.sh mutants <scope>  mutation matrix over a scope (REPORT-ONLY; docs/MUTATION_TESTING.md)
#   certify.sh powerset [M/N]   cargo check every depth-2 feature set (docs/FEATURE_MATRIX.md)
```

The mode check:

```bash
    quick|focus|full|mutants|powerset) ;;
    ...
    *) echo "unknown mode '$MODE'; expected quick|focus|full|mutants|powerset" >&2; exit 2 ;;
```

Dispatch, placed **after** the stray-cargo guard's closing `fi` and **before**
`rm -rf "$LOG_DIR"; mkdir -p "$LOG_DIR"`:

```bash
# v53.2.0 (#1024/#1025) — two tiers that never print a certification verdict.
# They come AFTER the lock and the stray guard (one postgres cluster, one
# target dir, and powerset rewrites Cargo.toml) and BEFORE the RUSTFLAGS
# export: under `-D warnings` most mutants would build as unviable, and every
# depth-2 set's dead_code would be a red about nothing. They do not wipe
# $LOG_DIR, so the last full run's logs survive. `exec` keeps fd 8, so the
# lock is held for the whole run.
case "$MODE" in
    mutants)
        [ -n "${1:-}" ] || { echo "usage: certify.sh mutants <scripts/mutants/scope-*.txt>" >&2; exit 2; }
        CERTIFY_LOG_DIR="$LOG_DIR" exec scripts/mutants.sh "${MUTANTS_TOOL:-cargo-mutants}" "$1" ;;
    powerset)
        CERTIFY_LOG_DIR="$LOG_DIR" exec scripts/powerset.sh check ${1:+"$1"} ;;
esac
```

`mutants` is not added to `ALL_KEYS` or to `full`: a scope takes about an
hour and its exit code is not a verdict. `powerset` is not added to `quick`,
which #1025 proposed: 929 sets measured at 17.6–22.8 s each is 4.5–6 h.

## 2. `scripts/ci_feature_matrix.py` — the `powerset` hook

The comparison lives in `scripts/powerset_delta.py`, which imports this module.
A subprocess hook avoids the import cycle. Add to the docstring's `Usage:`:

```
    scripts/ci_feature_matrix.py powerset [--verbose]
                                                 # depth-2 powerset vs certify's hand
                                                 # sets; exit 1 if a hand set is uncovered
```

and in `main()`, before the final `raise SystemExit`:

```python
    if cmd == "powerset":
        # CIRISPersist#1025 — the derived sets against the hand legs.
        import subprocess
        return subprocess.call(
            [sys.executable, str(Path(__file__).with_name("powerset_delta.py")), *argv[2:]],
            stdin=subprocess.DEVNULL,
        )
```

`Path` and `sys` are already imported. The delta needs `cargo-hack` on PATH
and compiles nothing, so it can also join the `featmatrix` cheap leg:
`python3 scripts/ci_feature_matrix.py check && python3 scripts/ci_feature_matrix.py powerset`.

## 3. CI — a separate scheduled workflow, not `ci.yml`

`ci.yml`'s `on:` block is shared by every job. Adding `schedule:` there would
run the whole wheel and mobile matrix nightly unless every job gained an `if:`.
A new file `.github/workflows/mutants.yml` keeps the schedule to these two
jobs:

```yaml
name: mutants and powerset

on:
  schedule:
    - cron: '17 6 * * *'      # nightly: mutants on scope-consent
    - cron: '43 6 * * 0'      # Sunday: also scope-observe-sites and the powerset
  workflow_dispatch:

permissions:
  contents: read

env:
  CARGO_TERM_COLOR: always
  CARGO_NET_RETRY: '10'
  CARGO_HTTP_MULTIPLEXING: 'false'
  CARGO_NET_GIT_FETCH_WITH_CLI: 'true'
  # No RUSTFLAGS: -D warnings here would make most mutants unviable.

jobs:
  mutants:
    name: mutants (${{ matrix.scope }})
    runs-on: ubuntu-latest
    timeout-minutes: 300
    strategy:
      fail-fast: false
      matrix:
        scope: [scope-consent, scope-observe-sites]
    services:
      postgres:
        image: ghcr.io/cirisai/postgres:16
        credentials:
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
        env:
          POSTGRES_USER: ciris
          POSTGRES_PASSWORD: ciris
          POSTGRES_DB: ciris_persist_test
        ports:
          - 5432:5432
        options: >-
          --health-cmd "pg_isready -U ciris"
          --health-interval 5s
          --health-timeout 5s
          --health-retries 10
    steps:
      - name: skip observe-sites except on the weekly run
        id: gate
        run: |
          if [ "${{ matrix.scope }}" = scope-observe-sites ] && [ "${{ github.event.schedule }}" = '17 6 * * *' ]; then
            echo run=false >> "$GITHUB_OUTPUT"; else echo run=true >> "$GITHUB_OUTPUT"; fi
      - uses: actions/checkout@v6
        if: steps.gate.outputs.run == 'true'
      - uses: dtolnay/rust-toolchain@1.97.0
        if: steps.gate.outputs.run == 'true'
      - uses: ./.github/actions/ciriscache
        if: steps.gate.outputs.run == 'true'
        with:
          plat: linux-x86_64
      - uses: taiki-e/install-action@v2
        if: steps.gate.outputs.run == 'true'
        with:
          tool: cargo-nextest,cargo-mutants@27.1.0
      - name: psql client for pg_test_db.sh
        if: steps.gate.outputs.run == 'true'
        run: command -v psql || (sudo apt-get update -qq && sudo apt-get install -y -qq postgresql-client)
      - name: mutation matrix (report-only)
        if: steps.gate.outputs.run == 'true'
        env:
          CIRIS_PERSIST_PG_ADMIN_URL: postgres://ciris:ciris@localhost:5432/ciris_persist_test
          MUTANTS_BUDGET_SECS: ${{ matrix.scope == 'scope-consent' && '7200' || '14400' }}
          MUTANTS_JOBS: '1'
        run: scripts/mutants.sh cargo-mutants scripts/mutants/${{ matrix.scope }}.txt
      - uses: actions/upload-artifact@v4
        if: always() && steps.gate.outputs.run == 'true'
        with:
          name: mutants-${{ matrix.scope }}
          path: target/certify-logs/mutants/${{ matrix.scope }}/
          retention-days: 30

  powerset:
    name: powerset ${{ matrix.part }}/8
    if: github.event_name == 'workflow_dispatch' || github.event.schedule == '43 6 * * 0'
    runs-on: ubuntu-latest
    timeout-minutes: 90
    strategy:
      fail-fast: false
      matrix:
        part: [1, 2, 3, 4, 5, 6, 7, 8]
    steps:
      - uses: actions/checkout@v6
      - uses: dtolnay/rust-toolchain@1.97.0
      - uses: ./.github/actions/ciriscache
        with:
          plat: linux-x86_64
      - uses: taiki-e/install-action@v2
        with:
          tool: cargo-hack
      - name: delta (no compile)
        run: python3 scripts/powerset_delta.py
      - name: cargo check, partition ${{ matrix.part }} of 8
        run: scripts/powerset.sh check ${{ matrix.part }}/8
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: powerset-${{ matrix.part }}
          path: target/certify-logs/powerset/
          retention-days: 30
```

Notes for whoever wires it:

- The mutants job is green whenever a matrix is written. It goes red only when
  no matrix could be produced. Read the uploaded `matrix.md` and
  `unvalidated.txt`.
- The powerset job goes red today. Two sets are known not to compile: `tls`
  without `postgres`, and `pyo3-sqlite` without `pyo3`. See
  `docs/FEATURE_MATRIX.md`. Either fix the feature closures first or mark the
  job `continue-on-error: true` until they are fixed.
- The `ciriscache` composite may only restore. Check whether a scheduled run
  saves under the main key before relying on it for warm builds.
- If the lead prefers `ci.yml` regardless, add the two `schedule:` entries to
  its `on:` and give **every** existing job
  `if: github.event_name != 'schedule'`.
