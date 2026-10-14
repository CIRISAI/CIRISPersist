#!/usr/bin/env bash
# coverage.sh — line/region coverage for ONE certify feature set
# (CIRISPersist#934, #1076 slice T).
#
#   scripts/coverage.sh <leg> [-- <nextest args>]
#   scripts/coverage.sh --features "<f1 f2 …>" [-- <nextest args>]
#
# <leg> is a certify / CI leg (`python3 scripts/ci_feature_matrix.py legs`);
# its feature set is DERIVED from Cargo.toml exactly as certify's `leg_cmd`
# derives it, never spelled here. `--features` takes an explicit set instead
# (the output directory is then named after it). Arguments after `--` go to
# nextest, e.g. `-- -E 'test(/size_/)'` to cover one slice of the suite.
#
# Writes target/coverage/<set>/:
#   lcov.info     the lcov trace (feeds any viewer, or a diff-coverage tool)
#   summary.txt   `cargo llvm-cov report --summary-only`: per file, then TOTAL
#   html/         the browsable report
# and prints the TOTAL line.
#
# WHY. There was no line or branch coverage. The mutation tables prove that
# the witnesses ENFORCE what they guard at chosen sites; they say nothing about
# code no test ever executes. Coverage per feature set — not one union run —
# because a line covered only under `--all-features` is a line some shipped
# configuration never runs (certify's lesson: certify per feature SET).
#
# A REPORT: exit 0 when a report was written, whatever the percentage — even
# when tests failed (the failures are in the log; certify is the test gate).
# Exit 1 when no report could be produced (tool missing, build broken); exit 2
# on usage. A postgres set runs through scripts/pg_test_db.sh (a fresh,
# single-use database), so the postgres witnesses run rather than skip.
#
# COST. A full leg under instrumentation is a full certify leg plus ~30-50%.
# Run it on CI (reports.yml, weekly) or on a machine with nothing else
# building; locally, scope it with a nextest filter.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
. scripts/ci_env.sh

usage() { sed -n '4,12p' "$0" >&2; exit 2; }
[ $# -ge 1 ] || usage
if [ "$1" = "--features" ]; then
    [ $# -ge 2 ] && [ -n "$2" ] || usage
    feats="$2"; shift 2
    name="features-$(tr -cs 'a-zA-Z0-9_-' '-' <<<"$feats" | sed 's/-$//')"
else
    name="$1"; shift
    feats="$(python3 scripts/ci_feature_matrix.py set "$name")" || {
        echo "unknown leg '$name'; legs: $(python3 scripts/ci_feature_matrix.py legs | tr '\n' ' ')" >&2; exit 2; }
fi
[ -n "$feats" ] || { echo "REFUSING: empty feature set for '$name' — coverage of nothing is not a report" >&2; exit 2; }
if [ $# -gt 0 ]; then
    [ "$1" = "--" ] || usage
    shift
fi
cargo llvm-cov --version >/dev/null 2>&1 || {
    echo "cargo-llvm-cov is not installed: cargo install --locked cargo-llvm-cov" >&2
    echo "  and: rustup component add llvm-tools-preview" >&2; exit 1; }

out="${CARGO_TARGET_DIR:-target}/coverage/$name"
rm -rf "$out"; mkdir -p "$out"
csv="$(tr ' ' ',' <<<"$feats")"
echo "coverage: set '$name' = --features $csv${*:+  nextest: $*}"

# Its own target dir (target/llvm-cov-target, cargo-llvm-cov's default):
# instrumented objects never mix with certify's.
run=(cargo llvm-cov nextest --no-report --no-default-features --features "$csv" --no-fail-fast "$@")
if grep -qw postgres <<<"$feats"; then
    scripts/pg_test_db.sh -- "${run[@]}" 2>&1 | tee "$out/run.log"
else
    "${run[@]}" 2>&1 | tee "$out/run.log"
fi
test_rc=${PIPESTATUS[0]}

cargo llvm-cov report --lcov --output-path "$out/lcov.info" >/dev/null 2>"$out/report.err" \
    && cargo llvm-cov report --summary-only >"$out/summary.txt" 2>>"$out/report.err" \
    && cargo llvm-cov report --html --output-dir "$out/html" >/dev/null 2>>"$out/report.err" || {
    echo "no coverage report could be produced:" >&2; tail -20 "$out/report.err" >&2; exit 1; }

echo
echo "coverage report: $out/"
head -1 "$out/summary.txt"
grep -E '^TOTAL' "$out/summary.txt"
[ "$test_rc" -eq 0 ] || echo "NOTE: the test run exited $test_rc — some tests failed; the report covers what ran (see $out/run.log)."
exit 0
