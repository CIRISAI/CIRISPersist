#!/usr/bin/env bash
# FEATURE POWERSET — compile-only sweep of every feature set up to a depth
# (CIRISPersist#1025).
#
#   scripts/powerset.sh list              print the derived sets, one per line
#   scripts/powerset.sh count             print how many sets there are
#   scripts/powerset.sh check [M/N]       `cargo check` every set (or partition M of N)
#
# ── WHY ──────────────────────────────────────────────────────────────────
# certify.sh's LEGS/AXES are hand-chosen sets: BASE (postgres server pyo3
# sqlite) plus one axis, plus the `rest` complement, plus three backend shapes
# per axis. "Certify per feature SET, never a union" says a cfg-gated break
# lives in a set nobody built. A hand list only finds the breaks someone
# thought to build for. cargo-hack's `--feature-powerset --depth 2` builds
# every single feature and every PAIR (NIST's t-way rule: most interaction
# faults involve one or two parameters), deduplicating sets one feature's
# closure already implies.
#
# It is the COMPILE question only ("does this configuration exist"), like the
# axis sweep. Test legs stay hand-derived until the runtime is measured.
# `scripts/powerset_delta.py` compares the derived sets with the hand legs.
#
# ── WHAT IS LEFT OUT, AND WHY ────────────────────────────────────────────
# Read from ci_feature_matrix.py's NOT_TESTED reasons, restated as one line each:
#   scrub-ner            +500 MB of Candle/Tokenizers/HF-Hub codegen
#   scrub-ort            pulls scrub-ner; `ort` wants a host libonnxruntime
#   default-pipeline-ml  scrub-ner + extract, same reason
#   _pyffi               internal shared gate, never enabled directly
# All four stay COMPILE-covered by the `--all-features` clippy pass.
#
# ── NEVER CONCURRENT WITH ANOTHER CARGO IN THIS TREE ─────────────────────
# `--no-dev-deps` REWRITES Cargo.toml (and Cargo.lock) in place for the whole
# run and restores them at the end. Measured on its first use here: a
# `cargo mutest` build started during a powerset run saw a Cargo.toml with no
# [dev-dependencies] and failed with 544 "cannot find crate `tempfile`"
# errors. certify.sh's `run_bg` legs share one tree, so this leg runs alone
# (after `wait`), or in its own `git worktree`. The guard below refuses a dirty
# Cargo.toml, which is also what a killed run leaves behind.
#
# ── VERDICT ──────────────────────────────────────────────────────────────
# Exit code is cargo-hack's. `--keep-going` builds every set before failing,
# so one red run names every broken set, not the first. No RUSTFLAGS: a
# depth-2 set turns most of the crate off, and `-D warnings` would turn every
# resulting dead_code warning into a red that says nothing about whether the
# set compiles.
set -uo pipefail

cd "$(dirname "$0")/.."

POWERSET_DEPTH="${POWERSET_DEPTH:-2}"
POWERSET_EXCLUDE="${POWERSET_EXCLUDE:-scrub-ner,scrub-ort,default-pipeline-ml,_pyffi}"
LOG_DIR="${CERTIFY_LOG_DIR:-target/certify-logs}/powerset"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"

command -v cargo-hack >/dev/null || {
    echo "cargo-hack not installed: cargo install cargo-hack --locked" >&2; exit 2; }

HACK=(cargo hack --feature-powerset --depth "$POWERSET_DEPTH"
      --exclude-features "$POWERSET_EXCLUDE" --no-dev-deps)

# `--print-command-list` prints one `cargo check ... --features a,b` line per
# set. The set is whatever follows `--features`; no flag means the empty set.
list_sets() {
    "${HACK[@]}" --print-command-list check 2>/dev/null </dev/null \
        | sed -n 's/^cargo check .*--no-default-features//p' \
        | sed -e 's/^ *--features //' -e 's/^ *$/(none)/'
}

mode="${1:-}"
case "$mode" in
    list)  list_sets ;;
    count) list_sets | wc -l ;;
    check)
        if [ -z "${POWERSET_ALLOW_DIRTY:-}" ] && ! git diff --quiet -- Cargo.toml Cargo.lock; then
            echo "REFUSING: Cargo.toml/Cargo.lock are modified. A killed powerset run" >&2
            echo "  leaves them without [dev-dependencies]; restore them first" >&2
            echo "  (POWERSET_ALLOW_DIRTY=1 if the edit is yours)." >&2
            exit 2
        fi
        mkdir -p "$LOG_DIR"
        part=()
        tag="all"
        if [ -n "${2:-}" ]; then
            part=(--partition "$2"); tag="${2/\//of}"
        fi
        log="$LOG_DIR/check-$tag.log"
        start=$(date +%s)
        "${HACK[@]}" --keep-going "${part[@]}" check </dev/null >"$log" 2>&1
        rc=$?
        secs=$(( $(date +%s) - start ))
        echo "$secs" > "$LOG_DIR/check-$tag.secs"
        echo "$rc" > "$LOG_DIR/check-$tag.rc"
        sets=$(grep -c '^info: running `cargo check' "$log")
        echo "powerset depth=$POWERSET_DEPTH partition=$tag: $sets sets, ${secs}s, rc=$rc (log: $log)"
        # cargo-hack names each failed set on its own `process didn't exit
        # successfully` line; list the sets, not the compiler's errors.
        grep "^error: process didn't exit successfully" "$log" \
            | sed -n 's/.*--no-default-features\( --features \([^ `]*\)\)\{0,1\}` (exit.*/  RED: \2/p' \
            | sed 's/RED: $/RED: (none)/' || true
        exit "$rc" ;;
    *)
        sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
        exit 2 ;;
esac
