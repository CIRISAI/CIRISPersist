#!/usr/bin/env bash
# mutants_diff.sh — cargo-mutants over the lines a branch changed
# (CIRISPersist#934, #1076 slice T).
#
#   scripts/mutants_diff.sh <base> [-- <cargo-mutants args>]
#
# Diffs the working tree against merge-base(<base>, HEAD), restricted to
# src/**/*.rs, and runs `cargo mutants --in-diff` on exactly those hunks:
# every mutant cargo-mutants can generate on a changed line, nothing else.
# Arguments after `--` go to cargo-mutants, e.g. `-- -F 'fn_name'` to narrow
# to one function, or `--shard 0/2`.
#
# Output: target/mutants-diff/ — the diff (scope.diff), the mutant list
# (list.txt), cargo-mutants' own mutants.out/ (caught.txt, missed.txt,
# timeout.txt, unviable.txt), and summary.txt, also printed and appended to
# $GITHUB_STEP_SUMMARY when set.
#
# A REPORT, NOT A GATE. The hand mutation tables in each PR, and the scoped
# matrix in scripts/mutants.sh, stay the gate. This answers a broader
# question nobody chose the sites for: "which changed line can be mutated
# with no test noticing?" Exit 0 whatever survived; exit 1 when no verdict
# could be produced (tool missing, red baseline, broken build); exit 2 on
# usage.
#
# KNOBS
#   MUTANTS_DIFF_BUDGET_SECS  total wall-clock cap (default 3600). On expiry the
#                             run is interrupted and the summary says
#                             INCOMPLETE with what finished.
#   MUTANTS_DIFF_FEATURES     extra cargo features (comma or space separated).
#                             The default is .cargo/mutants.toml's `sqlite`; a
#                             set with `postgres` runs via scripts/pg_test_db.sh.
#   MUTANTS_DIFF_JOBS         cargo-mutants -j (default 1; each job is a full
#                             crate build — mind the RAM).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

usage() { sed -n '4,10p' "$0" >&2; exit 2; }
[ $# -ge 1 ] || usage
base="$1"; shift
if [ $# -gt 0 ]; then [ "$1" = "--" ] || usage; shift; fi
command -v cargo-mutants >/dev/null || { echo "cargo-mutants is not installed: cargo install --locked cargo-mutants" >&2; exit 1; }
mb="$(git merge-base "$base" HEAD 2>/dev/null)" || { echo "no merge base between '$base' and HEAD" >&2; exit 2; }

out="${CARGO_TARGET_DIR:-target}/mutants-diff"
rm -rf "$out"; mkdir -p "$out"
out="$(cd "$out" && pwd)"
summary="$out/summary.txt"
emit() { tee -a "$summary"; }

# The scope is the CHANGED lines minus every test-only item, written as a diff
# that adds exactly those lines (mutants_matrix.py's own scope grammar).
# cargo-mutants 27.1 skips a bare `#[cfg(test)]` but not `#[cfg(all(test,
# ..))]` (CIRISPersist#1051), and this crate's *_invariants.rs witness bodies
# sit under exactly that; mutating them measures the tests, not the code.
echo "mutants-diff: base $base (merge-base $(git rev-parse --short "$mb"))" | emit
git diff "$mb" -- 'src/*.rs' >"$out/branch.diff"
python3 - "$mb" "$out/scope.diff" <<'PY' | emit || { echo "could not compute the scope" >&2; exit 1; }
import re, subprocess, sys
sys.path.insert(0, "scripts")
import mutants_matrix as mm
base, out = sys.argv[1:]
d = subprocess.run(["git", "diff", "-U0", base, "--", "src/*.rs"],
                   capture_output=True, text=True, check=True).stdout
ranges, files, changed, kept, file = [], set(), 0, 0, None
for line in d.splitlines():
    if line.startswith("+++ "):
        file = None if line == "+++ /dev/null" else line[6:]
        continue
    m = re.match(r"@@ -\S+ \+(\d+)(?:,(\d+))? @@", line)
    if m and file:
        a, n = int(m[1]), (int(m[2]) if m[2] is not None else 1)
        if not n:
            continue
        changed += n
        segs = mm._subtract(a, a + n - 1, mm.test_gated_ranges(file))
        kept += sum(y - x + 1 for x, y in segs)
        ranges += [(file, x, y) for x, y in segs]
        if segs:
            files.add(file)
open(out, "w").write(mm.scope_diff(ranges) if ranges else "")
print(f"  {changed} changed line(s); {kept} outside test-only items, in {len(files)} file(s)")
PY
if [ ! -s "$out/scope.diff" ]; then
    echo "  no non-test src/ line changed against the base: nothing to mutate" | emit
    exit 0
fi

feat_args=()
pg=()
if [ -n "${MUTANTS_DIFF_FEATURES:-}" ]; then
    feat_args=(--features "$(tr ' ' ',' <<<"$MUTANTS_DIFF_FEATURES")")
    grep -qw postgres <<<"$MUTANTS_DIFF_FEATURES" && pg=(scripts/pg_test_db.sh --)
fi
sel=(--in-diff "$out/scope.diff" "${feat_args[@]}" "$@")

cargo mutants --list "${sel[@]}" </dev/null >"$out/list.txt" 2>"$out/list.err" \
    || { echo "cargo mutants --list failed:" >&2; tail -20 "$out/list.err" >&2; exit 1; }
n="$(grep -c . "$out/list.txt" || true)"
echo "  $n mutant(s) on changed lines" | emit
if [ "$n" -eq 0 ]; then
    echo "  (the changed lines hold nothing cargo-mutants mutates)" | emit
    exit 0
fi

budget="${MUTANTS_DIFF_BUDGET_SECS:-3600}"
t0=$(date +%s)
CARGO_INCREMENTAL=1 timeout --signal=INT --kill-after=120 "$budget" \
    "${pg[@]}" cargo mutants --test-tool nextest -j "${MUTANTS_DIFF_JOBS:-1}" --no-shuffle \
    --output "$out" "${sel[@]}" </dev/null >"$out/run.log" 2>&1
rc=$?
secs=$(( $(date +%s) - t0 ))

mo="$out/mutants.out"
count() { [ -f "$mo/$1" ] && grep -c . "$mo/$1" || echo 0; }
caught=$(count caught.txt); missed=$(count missed.txt)
timeouts=$(count timeout.txt); unviable=$(count unviable.txt)
done_n=$(( caught + missed + timeouts + unviable ))
# cargo-mutants: 0 all caught, 2 missed, 3 timeouts; anything else (1, 4 =
# baseline failed, 124/130 = our budget) is not a clean verdict.
case "$rc" in
    0|2|3) state="complete" ;;
    124|130) state="INCOMPLETE (budget ${budget}s hit)" ;;
    *) state="NO VERDICT (cargo-mutants exit $rc)" ;;
esac
{
    echo "  $state in ${secs}s: $done_n of $n tested — caught $caught, MISSED $missed, timeout $timeouts, unviable $unviable"
    if [ "$missed" -gt 0 ]; then echo "  missed (a changed line no test notices):"; sed 's/^/    /' "$mo/missed.txt"; fi
    if [ "$timeouts" -gt 0 ]; then echo "  timed out:"; sed 's/^/    /' "$mo/timeout.txt"; fi
    echo "  (report only — the PR's hand mutation table is the gate)"
} | emit
[ -n "${GITHUB_STEP_SUMMARY:-}" ] && { echo '```'; cat "$summary"; echo '```'; } >>"$GITHUB_STEP_SUMMARY"
case "$state" in
    NO*) tail -30 "$out/run.log" >&2; exit 1 ;;
esac
exit 0
