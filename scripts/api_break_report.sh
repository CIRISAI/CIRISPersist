#!/usr/bin/env bash
# api_break_report.sh — the public-API break list, mechanically
# (CIRISPersist#934, #1076 slice T).
#
#   scripts/api_break_report.sh [<prev-tag>]
#
# Runs `cargo semver-checks check-release` with the working tree as the
# current version and <prev-tag> as the baseline, and prints every lint that
# fired with its instances, then a one-line count. With no argument the
# baseline is the latest `v*` tag reachable from HEAD^ (from HEAD itself
# when HEAD is untagged), i.e. the release this tree follows.
#
# Output: target/semver/<prev-tag>.txt (the full tool output) and
# target/semver/<prev-tag>.summary (the count line and the lint list), both
# also on stdout. The CHANGELOG's "API breaks" list and the note to Edge are
# written from the summary.
#
# WHY. Every recent release is a MAJOR, and the break list was compiled by
# hand from the diff — which is how a removed variant or a new required trait
# method reaches an adopter as a compile error instead of a CHANGELOG line.
#
# A REPORT. Exit 0 whether or not breaks were found (a major release is
# EXPECTED to have them). Exit 1 only when the tool could not produce a
# verdict (not installed, a baseline that does not build, a bad tag); exit 2
# on usage.
#
# KNOBS
#   SEMVER_FEATURES   the feature set both sides are built with. Default: the
#                     shipped shape, `ci_feature_matrix.py set lint` — the
#                     ML features (candle/ort) are out on purpose: rustdoc
#                     would have to build them and they are not API Edge links.
#   SEMVER_RELEASE_TYPE  default `minor`: report every change that needs a
#                     MAJOR. (Left to the tool, a major bump in Cargo.toml
#                     would mark the breaks allowed and list nothing.)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

prev="${1:-}"
if [ $# -gt 1 ]; then echo "usage: $0 [<prev-tag>]" >&2; exit 2; fi
if [ -z "$prev" ]; then
    # HEAD may itself carry the release tag being cut; the baseline is the one
    # before it.
    if git describe --exact-match --tags --match 'v[0-9]*' HEAD >/dev/null 2>&1; then
        prev="$(git describe --tags --abbrev=0 --match 'v[0-9]*' HEAD^ 2>/dev/null)"
    else
        prev="$(git describe --tags --abbrev=0 --match 'v[0-9]*' HEAD 2>/dev/null)"
    fi
    [ -n "$prev" ] || { echo "no v* tag reachable from HEAD; pass one" >&2; exit 2; }
fi
git rev-parse -q --verify "refs/tags/$prev^{commit}" >/dev/null \
    || { echo "not a tag here: $prev (git fetch --tags?)" >&2; exit 2; }
cargo semver-checks --version >/dev/null 2>&1 \
    || { echo "cargo-semver-checks is not installed (cargo install --locked cargo-semver-checks)" >&2; exit 1; }

features="${SEMVER_FEATURES:-$(python3 scripts/ci_feature_matrix.py set lint)}"
[ -n "$features" ] || { echo "empty feature set" >&2; exit 1; }
out_dir="${CARGO_TARGET_DIR:-target}/semver"
mkdir -p "$out_dir"
log="$out_dir/$prev.txt"; summary="$out_dir/$prev.summary"

echo "semver-checks: baseline $prev, current = working tree ($(git rev-parse --short HEAD)$(git diff --quiet HEAD -- || echo '+dirty'))"
echo "  features: $features"
cargo semver-checks check-release \
    --baseline-rev "$prev" \
    --release-type "${SEMVER_RELEASE_TYPE:-minor}" \
    --only-explicit-features --features "${features// /,}" \
    --color never >"$log" 2>&1
rc=$?

# The tool exits 1 for "breaks found" AND for "could not run"; only the
# presence of its own summary line tells them apart.
if ! grep -qE '^ +Summary ' "$log"; then
    echo "semver-checks produced no verdict (exit $rc). Last lines:" >&2
    tail -30 "$log" >&2
    exit 1
fi

{
    # One `--- failure <lint>: <description> ---` header per lint that fired,
    # then `Failed in:` and one two-space-indented line per instance. An item
    # re-exported at two paths is listed twice by the tool; instances here are
    # DISTINCT lines per lint.
    awk '
        /^--- failure / { lint=$3; sub(/:$/, "", lint); desc=$0
                          sub(/^--- failure [^:]+: /, "", desc); sub(/ ---$/, "", desc)
                          order[++nl]=lint; d[lint]=desc; on=0; next }
        /^--- /         { on=0; next }
        /^Failed in:/   { on=1; next }
        on && /^  [^ ]/ { if (!seen[lint, $0]++) { n[lint]++; total++ } }
        END {
            printf "API BREAKS %s -> %s: %d lint(s) fired, %d distinct instance(s)\n", prev, head, nl, total
            for (i = 1; i <= nl; i++) printf "  %-55s %4d  %s\n", order[i], n[order[i]], d[order[i]]
        }' prev="$prev" head="$(git rev-parse --short HEAD)" "$log"
    grep -E '^ +Summary ' "$log" | sed -E 's/^ +/  tool: /'
} | tee "$summary"
echo "  full report: $log"
exit 0
