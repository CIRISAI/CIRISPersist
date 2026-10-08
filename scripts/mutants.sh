#!/usr/bin/env bash
# MUTATION TIER — a per-witness detection matrix over a named scope
# (CIRISPersist#1024).
#
#   scripts/mutants.sh <cargo-mutants|mutest> <scope-file>
#
# Writes target/certify-logs/mutants/<scope>/matrix.{json,md}: every mutant
# the tool generated inside the scope, its outcome, and EVERY witness that
# failed under it. Then scripts/unvalidated_witnesses.py lists the witnesses
# that killed nothing. Format and scope grammar: docs/MUTATION_TESTING.md.
#
# REPORT-ONLY THIS CUT: exits 0 once a matrix is written, however many mutants
# survive. Exits non-zero only when no matrix could be produced (tool missing,
# baseline red, build broken, scope unresolvable).
#
# ── WHY ──────────────────────────────────────────────────────────────────
# Until now every mutation round was hand-picked per PR and recorded only in
# the CHANGELOG ("the 10-mutant round"). Nothing said which witness was
# load-bearing for which site, and a surviving mutant is a claim about the
# WITNESS — one nobody could check after the PR merged. The matrix is that
# claim, regenerated on demand, without hand selection.
#
# ── KNOBS ────────────────────────────────────────────────────────────────
#   MUTANTS_BUDGET_SECS   wall-time budget (default 7200). On expiry the tool
#                         is interrupted and the matrix is written from what
#                         finished, marked "complete": false.
#   MUTANTS_FEATURES      cargo features (default postgres,sqlite,server). The
#                         postgres witnesses need a DSN: the run goes through
#                         scripts/pg_test_db.sh when the feature is on.
#   MUTANTS_JOBS          parallel mutants (cargo-mutants -j; default 1). Each
#                         job is a full build of the crate; mind the RAM.
#
# NEVER RUN NEXT TO A powerset.sh RUN IN THE SAME TREE: that one rewrites
# Cargo.toml for its duration.
set -uo pipefail

cd "$(dirname "$0")/.."

tool="${1:-}"; scope="${2:-}"
if [ -z "$tool" ] || [ -z "$scope" ] || [ ! -f "$scope" ]; then
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi

BUDGET="${MUTANTS_BUDGET_SECS:-7200}"
FEATURES="${MUTANTS_FEATURES:-postgres,sqlite,server}"
JOBS="${MUTANTS_JOBS:-1}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
name="$(basename "$scope" .txt)"
OUT="${CERTIFY_LOG_DIR:-target/certify-logs}/mutants/$name"
rm -rf "$OUT"; mkdir -p "$OUT"
ABS_OUT="$(cd "$OUT" && pwd)"

filter="$(python3 scripts/mutants_matrix.py tests "$scope")" || exit 2

# A postgres witness without a DSN returns before its first assertion and
# passes in 0.00s: it would kill nothing and be reported "unvalidated" for a
# reason that is not the witness's. Give it a database.
pg=()
case ",$FEATURES," in
    *,postgres,*) pg=(scripts/pg_test_db.sh --) ;;
esac

start=$(date +%s)
case "$tool" in
    cargo-mutants)
        command -v cargo-mutants >/dev/null || { echo "cargo install cargo-mutants --locked" >&2; exit 2; }
        mapfile -t sel < <(python3 scripts/mutants_matrix.py resolve cargo-mutants "$scope") || exit 2
        version="$(cargo mutants --version | awk '{print $2}')"
        # CARGO_INCREMENTAL=1: the dev profile turns incremental off (its
        # cache reached 114 GB over the full suite), but each mutant here is a
        # one-function edit to the same crate, one feature set: without it
        # every mutant recompiles the whole crate from scratch.
        # --no-fail-fast: the matrix needs EVERY witness that fails, not the
        # first. --lib: the scope's witnesses are in-crate; the integration
        # binaries would be built for every mutant and never run.
        CARGO_INCREMENTAL=1 timeout --signal=INT --kill-after=120 "$BUDGET" \
            "${pg[@]}" cargo mutants --test-tool nextest --features "$FEATURES" \
            --jobs "$JOBS" --no-shuffle --output "$ABS_OUT" "${sel[@]}" \
            -- --lib --no-fail-fast -E "$filter" \
            </dev/null >"$OUT/tool.log" 2>&1
        rc=$?
        raw="$ABS_OUT/mutants.out"
        ;;
    mutest)
        command -v cargo-mutest >/dev/null || { echo "mutest-rs not installed: see docs/MUTATION_TESTING.md" >&2; exit 2; }
        sel="$(python3 scripts/mutants_matrix.py resolve mutest "$scope")" || exit 2
        version="$(cd "$(dirname "$(command -v cargo-mutest)")" && echo git)"
        # mutest's harness runs the crate's whole lib suite (it has no test
        # filter); the scope's `tests:` line is applied when the matrix is
        # read. -d 10: its reachability depth from each test.
        timeout --signal=INT --kill-after=120 "$BUDGET" \
            "${pg[@]}" cargo mutest run --lib --features "$FEATURES" -d 10 \
            --filter-mutations "$sel" --exhaustive \
            --metadata-out-root-dir "$ABS_OUT/json" \
            </dev/null >"$OUT/tool.log" 2>&1
        rc=$?
        raw="$ABS_OUT/json"
        ;;
    *)
        echo "unknown tool '$tool'; expected cargo-mutants or mutest" >&2; exit 2 ;;
esac
secs=$(( $(date +%s) - start ))
budget_hit=0; [ "$rc" -eq 124 ] && budget_hit=1

# cargo-mutants exits 2 when mutants are missed and 3 on timeouts — a report,
# not a failure. cargo-mutest swallows rustc's 101. Whether a matrix can be
# read is the only verdict.
if ! python3 scripts/mutants_matrix.py collect "$tool" "$raw" "$scope" "$OUT" \
        wall_secs="$secs" budget_secs="$BUDGET" features="$FEATURES" \
        tool_version="$version" budget_hit="$budget_hit" tool_rc="$rc"; then
    echo "NO MATRIX — $tool exited $rc after ${secs}s; see $OUT/tool.log" >&2
    tail -30 "$OUT/tool.log" >&2
    exit 1
fi
python3 scripts/unvalidated_witnesses.py "$OUT/matrix.json" "$scope" | tee "$OUT/unvalidated.txt"
exit 0
