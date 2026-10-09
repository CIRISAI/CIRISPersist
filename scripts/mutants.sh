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
# EXIT CODES (v54.1.0, CIRISPersist#1051 — the first nightly run was green
# with 8 of 85 mutants untested and 6 survivors nobody read):
#   0  complete, and every surviving mutant is in the allow-list with an issue
#   1  no matrix could be produced (tool missing, red baseline, broken build)
#   2  usage / unresolvable scope
#   3  the scope does not fit the budget at the measured per-mutant cost:
#      refused BEFORE running; shard it (MUTANTS_SHARD) or raise the budget
#   4  INCOMPLETE: the budget expired or a mutant was never tested
#   5  a surviving mutant (missed, timeout, caught only out of scope) that
#      scripts/mutants/allowed_survivors.txt does not name
# The verdict is also written to $GITHUB_STEP_SUMMARY and as annotations.
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
#   MUTANTS_SHARD         k/n (0-based k): run only cargo-mutants' k-th slice
#                         of the scope's mutants. Output goes to
#                         <scope>-shard-<k>-of-<n>.
#   MUTANTS_ALLOW         the allow-list (default
#                         scripts/mutants/allowed_survivors.txt).
#   MUTANTS_BASELINE_SECS, MUTANTS_SECS_PER_MUTANT
#                         the sizing model (defaults 600 and 120): a run of N
#                         mutants needs BASELINE + N x PER_MUTANT. Measured on
#                         the first nightly run (ubuntu-latest, 2026-10-09):
#                         baseline 305 s; per mutant mean 78 s, p90 105 s,
#                         max 307 s, excluding timeouts.
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
SHARD="${MUTANTS_SHARD:-}"
ALLOW="${MUTANTS_ALLOW:-scripts/mutants/allowed_survivors.txt}"
BASE_SECS="${MUTANTS_BASELINE_SECS:-600}"
PER_SECS="${MUTANTS_SECS_PER_MUTANT:-120}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
name="$(basename "$scope" .txt)"
shard_args=()
if [ -n "$SHARD" ]; then
    [[ "$SHARD" =~ ^([0-9]+)/([0-9]+)$ ]] && [ "${BASH_REMATCH[1]}" -lt "${BASH_REMATCH[2]}" ] \
        || { echo "MUTANTS_SHARD=$SHARD: expected k/n with 0 <= k < n" >&2; exit 2; }
    [ "$tool" = cargo-mutants ] || { echo "MUTANTS_SHARD is cargo-mutants only" >&2; exit 2; }
    shard_args=(--shard "$SHARD")
    name="$name-shard-${BASH_REMATCH[1]}-of-${BASH_REMATCH[2]}"
fi
[ -f "$ALLOW" ] || { echo "no allow-list at $ALLOW" >&2; exit 2; }
python3 scripts/mutants_matrix.py check-allow "$ALLOW" || exit 2
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
        mapfile -t sel < <(python3 scripts/mutants_matrix.py resolve cargo-mutants "$scope" "$ABS_OUT/scope.diff") || exit 2
        [ "${#sel[@]}" -gt 0 ] || exit 2
        version="$(cargo mutants --version | awk '{print $2}')"
        # Size the run before starting it: a budget that cannot hold the
        # scope ends INCOMPLETE two hours later; say so now, for nothing.
        count="$(cargo mutants --list "${sel[@]}" "${shard_args[@]}" </dev/null 2>"$OUT/list.err" | grep -c .)"
        [ "$count" -gt 0 ] || { echo "the scope lists no mutant; see $OUT/list.err" >&2; cat "$OUT/list.err" >&2; exit 2; }
        need=$(( BASE_SECS + count * PER_SECS ))
        echo "mutants: $count in $name; sized at ${BASE_SECS}s + ${count} x ${PER_SECS}s = ${need}s of a ${BUDGET}s budget"
        if [ "$need" -gt "$BUDGET" ]; then
            echo "::error title=mutants $name does not fit its budget::$count mutants need ${need}s at ${PER_SECS}s each; the budget is ${BUDGET}s. Shard it (MUTANTS_SHARD=k/n) or raise MUTANTS_BUDGET_SECS."
            exit 3
        fi
        # CARGO_INCREMENTAL=1: the dev profile turns incremental off (its
        # cache reached 114 GB over the full suite), but each mutant here is a
        # one-function edit to the same crate, one feature set: without it
        # every mutant recompiles the whole crate from scratch.
        # --no-fail-fast: the matrix needs EVERY witness that fails, not the
        # first. --lib: the scope's witnesses are in-crate; the integration
        # binaries would be built for every mutant and never run.
        # --profile mutants (.config/nextest.toml): a witness that hangs
        # under a mutant is killed at 60 s and reads as a FAIL of that
        # witness, not a 300 s tool timeout credited to no one.
        CARGO_INCREMENTAL=1 timeout --signal=INT --kill-after=120 "$BUDGET" \
            "${pg[@]}" cargo mutants --test-tool nextest --features "$FEATURES" \
            --jobs "$JOBS" --no-shuffle --output "$ABS_OUT" "${sel[@]}" "${shard_args[@]}" \
            -- --lib --no-fail-fast --profile mutants -E "$filter" \
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

# cargo-mutants exits 2 when mutants are missed and 3 on timeouts; neither
# is the verdict. cargo-mutest swallows rustc's 101. The matrix is read
# first, then judged against the allow-list.
if ! python3 scripts/mutants_matrix.py collect "$tool" "$raw" "$scope" "$OUT" \
        wall_secs="$secs" budget_secs="$BUDGET" features="$FEATURES" \
        tool_version="$version" budget_hit="$budget_hit" tool_rc="$rc" shard="$SHARD"; then
    echo "NO MATRIX — $tool exited $rc after ${secs}s; see $OUT/tool.log" >&2
    tail -30 "$OUT/tool.log" >&2
    exit 1
fi
python3 scripts/unvalidated_witnesses.py "$OUT/matrix.json" "$scope" | tee "$OUT/unvalidated.txt"
python3 scripts/mutants_matrix.py verdict "$OUT/matrix.json" "$ALLOW" | tee "$OUT/verdict.txt"
exit "${PIPESTATUS[0]}"
