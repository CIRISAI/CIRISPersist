#!/usr/bin/env bash
# FULL local certification, LANE-PARALLEL — every leg CI runs, DERIVED from the
# same sources CI's own jobs read, so this cannot drift from CI by hand-editing.
#
# EXIT CODE IS THE ONLY VERDICT — captured on its own line immediately after
# each command, before any pipe or echo can overwrite it.
#
# ── WHY THIS LIVES IN THE REPO ───────────────────────────────────────────
# It lived in a scratch directory, which was cleaned, taking with it the
# RUSTFLAGS derivation below — the fix for the defect that shipped as v30.3.1.
# A tool whose absence lets a weaker verdict through is not a scratch file.
#
# ── WHAT IS DERIVED, AND WHY DERIVED RATHER THAN RESTATED ────────────────
# Feature sets come from `scripts/ci_feature_matrix.py`; RUSTFLAGS comes from
# the workflow-level `env:` block in `.github/workflows/ci.yml`. Both are read,
# never copied.
#
# v30.3.1 is the argument. This script set NO RUSTFLAGS while ci.yml sets
# `RUSTFLAGS: -D warnings` at workflow level, so every leg ran on strictly
# easier terms than CI — and v30.3.0 was certified "EVERY CI LEG GREEN BY EXIT
# CODE" on a tree CI then rejected for an `unused_variable`. The clippy leg was
# no help: it runs with the LINT feature set, where the offending parameter IS
# used, so the one leg applying `-D warnings` was the one leg where the bug was
# invisible. A script that restates CI by hand drifts from CI by hand, and every
# such drift is silent and in the optimistic direction.
#
# ── WHAT IS PARALLEL AND WHAT IS NOT ─────────────────────────────────────
#  1. **Cargo's target-directory lock.** Concurrent `cargo` invocations on one
#     target dir do not build concurrently — the second blocks. Lanes do NOT
#     multiply build throughput; they overlap one leg's test RUN with the next
#     leg's build, which is real because both phases are minutes long. Measured:
#     3912s of serial leg-time in 1451s wall clock across 3 lanes (2.7x), at
#     zero extra disk. Per-lane CARGO_TARGET_DIR would parallelise builds too,
#     but each fresh target dir rebuilds the whole dependency graph cold and
#     `target/` already runs to ~100G.
#  2. **Postgres template construction.** `src/test_pg.rs` builds ONE
#     cluster-wide template under `pg_advisory_lock`. PostgreSQL advisory locks
#     include MyDatabaseId, so they are PER-DATABASE — and each leg gets its own
#     database from `pg_test_db.sh`. Two legs starting cold therefore do NOT
#     serialise and can race on `CREATE DATABASE <template>`. Handled by warming
#     the template serially before any lane starts.
#  3. **Test-thread oversubscription.** Each leg would otherwise ask for one
#     test thread per core. Capped per lane so the total stays near core count.
#
# The four non-cargo static gates run FIRST and concurrently — seconds, not
# thirty minutes in, which is where a phantom doc-version reference used to
# surface.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

LANES="${LANES:-3}"
LOG_DIR="${CERTIFY_LOG_DIR:-target/certify-logs}"
rm -rf "$LOG_DIR"; mkdir -p "$LOG_DIR"

CORES="$(nproc)"
PER_LANE=$(( CORES / LANES )); [ "$PER_LANE" -lt 2 ] && PER_LANE=2

# ── RUSTFLAGS, DERIVED FROM ci.yml ───────────────────────────────────────
CI_RUSTFLAGS="$(python3 - <<'PYEOF'
import re, pathlib, sys
text = pathlib.Path('.github/workflows/ci.yml').read_text()
head = text.split('\njobs:')[0]          # workflow-level env, before any job
m = re.search(r'^\s*RUSTFLAGS:\s*(.+?)\s*$', head, re.MULTILINE)
if not m:
    sys.exit('could not find a workflow-level RUSTFLAGS in ci.yml')
print(m.group(1).strip().strip('"').strip("'"))
PYEOF
)" || { echo "REFUSING: could not derive RUSTFLAGS from ci.yml — it may have moved or been removed." >&2; exit 2; }
[ -n "$CI_RUSTFLAGS" ] || { echo "REFUSING: derived an EMPTY RUSTFLAGS; certifying with weaker flags than CI is how a green verdict lies." >&2; exit 2; }
export RUSTFLAGS="$CI_RUSTFLAGS"
echo "RUSTFLAGS (derived from ci.yml): $RUSTFLAGS"

# ── disk guard ───────────────────────────────────────────────────────────
FREE_G="$(df -BG --output=avail . | tail -1 | tr -dc '0-9')"
if [ "${FREE_G:-0}" -lt 15 ]; then
    echo "REFUSING: only ${FREE_G}G free. A build that dies on ENOSPC produces a red that" >&2
    echo "  belongs to the disk, not the change. Reclaim space first." >&2
    exit 2
fi
echo "lanes=$LANES  test-threads/lane=$PER_LANE  cores=$CORES  free=${FREE_G}G"

LEGS="core cirisaudit secrets cirisnode cirisgraph telemetry rest test-anchor"
ALL_KEYS="$LEGS default fmt clippy pyi featmatrix docver pyo3sqlite"

# ── stage 1: fast non-cargo gates, concurrent, fail-fast ─────────────────
echo
echo "=== fast static gates (concurrent) ==="
run_bg() { local name="$1"; shift; ( "$@" >"$LOG_DIR/$name.log" 2>&1; echo $? >"$LOG_DIR/$name.rc" ) & }
run_bg fmt        cargo fmt --all --check
run_bg pyi        python3 scripts/pyi_surface.py check
run_bg featmatrix python3 scripts/ci_feature_matrix.py check
run_bg docver     python3 scripts/doc_version_refs.py
# v30.4.1 (CIRISPersist#618) — the SUBSET compile leg: `_pyffi` WITHOUT `pyo3`.
# `--all-features` is totality by union and structurally cannot omit a feature,
# so it is blind to "A without B". v30.4.0 shipped a `#[cfg(feature = "pyo3")]`
# on a binding whose use was unguarded; every leg here that compiles that module
# enables `pyo3`, so it was invisible locally and broke CIRISEdge's mobile
# cross-compiles. Cheap `cargo check`, kept in the FAST tier on purpose.
run_bg pyo3sqlite cargo check --no-default-features --features "pyo3-sqlite sqlite secrets cirisnode cirisgraph cirisaudit telemetry cirisincident classify scrub extract"
wait
fast_fail=0
for g in fmt pyi featmatrix docver pyo3sqlite; do
    rc="$(cat "$LOG_DIR/$g.rc" 2>/dev/null || echo 99)"
    printf '  %-22s exit=%s\n' "$g" "$rc"
    [ "$rc" -ne 0 ] && fast_fail=1
done
if [ "$fast_fail" -ne 0 ]; then
    echo; echo "NOT CERTIFIED — a fast gate is red; the expensive legs were not run."
    for g in fmt pyi featmatrix docver pyo3sqlite; do
        [ "$(cat "$LOG_DIR/$g.rc" 2>/dev/null || echo 99)" -ne 0 ] && {
            echo "--- $g ---"; tail -20 "$LOG_DIR/$g.log"; }
    done
    echo "SCRIPT_EXIT=1"; exit 1
fi

# ── stage 2: warm the postgres template SERIALLY (see note 2) ────────────
echo
echo "=== warming the postgres template (serial, on purpose) ==="
WARM_LOG="$LOG_DIR/template-warm.log"
scripts/pg_test_db.sh -- cargo nextest run --features postgres,sqlite \
    -E 'test(hard_case_third_party_conferral_parity_postgres_607)' >"$WARM_LOG" 2>&1
WARM_RC=$?
echo "  template warm exit=$WARM_RC  (a red here is a real red — it ran a real test)"
if [ "$WARM_RC" -ne 0 ]; then
    echo "NOT CERTIFIED — template warm-up failed. Logs: $WARM_LOG"
    tail -30 "$WARM_LOG"; echo "SCRIPT_EXIT=1"; exit 1
fi

# ── stage 3: expensive legs, in lanes ────────────────────────────────────
: > "$LOG_DIR/queue"
for leg in $LEGS; do echo "$leg" >> "$LOG_DIR/queue"; done
echo "default" >> "$LOG_DIR/queue"
echo "clippy"  >> "$LOG_DIR/queue"

run_job() {
    local name="$1" log="$LOG_DIR/$1.log" t0 t1 rc
    t0=$(date +%s)
    case "$name" in
        clippy)
            bash -c '
                set -uo pipefail
                LF="$(python3 scripts/ci_feature_matrix.py set lint)" || exit 1
                [ -n "$LF" ] || { echo "EMPTY lint feature set" >&2; exit 1; }
                cargo clippy --features "$LF" --all-targets -- -D warnings' >"$log" 2>&1
            ;;
        default)
            NEXTEST_TEST_THREADS="$PER_LANE" cargo nextest run >"$log" 2>&1
            ;;
        *)
            local feats csv
            feats="$(python3 scripts/ci_feature_matrix.py set "$name")" || {
                echo "FAILED to derive $name" >"$log"; echo 1 >"$LOG_DIR/$name.rc"; return; }
            [ -n "$feats" ] || {
                echo "EMPTY feature set for '$name' — refusing to run a leg that tests nothing" >"$log"
                echo 1 >"$LOG_DIR/$name.rc"; return; }
            csv="$(echo "$feats" | tr ' ' ',')"
            if echo "$feats" | grep -qw postgres; then
                scripts/pg_test_db.sh -- env NEXTEST_TEST_THREADS="$PER_LANE" \
                    cargo nextest run --features "$csv" >"$log" 2>&1
            else
                NEXTEST_TEST_THREADS="$PER_LANE" cargo nextest run --features "$csv" >"$log" 2>&1
            fi
            ;;
    esac
    rc=$?; t1=$(date +%s)
    echo "$rc" > "$LOG_DIR/$name.rc"; echo "$(( t1 - t0 ))" > "$LOG_DIR/$name.secs"
    printf '  %-22s exit=%-3s %4ss  %s\n' "$name" "$rc" "$(( t1 - t0 ))" \
        "$(grep -oE '[0-9]+ tests run: [0-9]+ passed' "$log" | tail -1)"
}

echo
echo "=== expensive legs (${LANES} lanes; feature sets DERIVED from ci_feature_matrix.py) ==="
T_START=$(date +%s)
FIFO="$LOG_DIR/sem"; mkfifo "$FIFO"; exec 9<>"$FIFO"; rm -f "$FIFO"
for _ in $(seq "$LANES"); do printf '.' >&9; done
# ── FAIL FAST ────────────────────────────────────────────────────────────
# Once any leg is red the run cannot certify, so dispatching more legs buys
# nothing but wall clock — a red at leg 2 of 15 used to cost ten more minutes of
# compute for a verdict already decided.
#
# In-flight lanes are NOT killed: they are already paid for, and letting them
# finish is what tells you whether a failure is systematic (several legs, same
# cause) or local to one feature set. Two legs failing identically is a
# different diagnosis from one, and that distinction was worth having the time
# this rule was written for.
any_red() {
    for f in "$LOG_DIR"/*.rc; do
        [ -f "$f" ] || continue
        [ "$(cat "$f")" != "0" ] && return 0
    done
    return 1
}
pids=()
while read -r job; do
    if any_red; then
        echo "  !! STOPPING DISPATCH — a leg is already red; in-flight lanes will finish."
        break
    fi
    read -r -n 1 -u 9
    # `< /dev/null` is LOAD-BEARING. Without it the backgrounded job inherits
    # stdin — which is the job queue — and cargo/nextest read from it, silently
    # swallowing queue lines. Observed: of ten queued jobs, four ran and six
    # never started. They were reported RED (exit=99, no .rc) rather than green,
    # so the verdict stayed honest, but the run was worthless.
    ( run_job "$job"; printf '.' >&9 ) < /dev/null &
    pids+=($!)
done < "$LOG_DIR/queue"
for p in "${pids[@]}"; do wait "$p"; done
exec 9>&-
T_END=$(date +%s)

MISSING=""
while read -r j; do [ -f "$LOG_DIR/$j.rc" ] || MISSING="$MISSING $j"; done < "$LOG_DIR/queue"
if [ -n "$MISSING" ]; then
    echo; echo "!! JOBS THAT NEVER RAN:$MISSING"
    echo "   (not the same as red — the queue drained short. Counted RED below.)"
fi

# ── verdict ──────────────────────────────────────────────────────────────
echo
echo "================ FULL CERTIFICATION VERDICT ================"
fail=0
for k in $ALL_KEYS; do
    rc="$(cat "$LOG_DIR/$k.rc" 2>/dev/null || echo 99)"
    secs="$(cat "$LOG_DIR/$k.secs" 2>/dev/null || echo -)"
    cnt="$(grep -oE '[0-9]+ tests run: [0-9]+ passed' "$LOG_DIR/$k.log" 2>/dev/null | tail -1)"
    if [ "$rc" -eq 99 ]; then
        # 99 is this script's sentinel for a missing .rc — the leg never ran.
        # Calling that RED would claim a failure nobody observed.
        printf '  UNKNOWN %-21s (not run)\n' "$k"; fail=1
    elif [ "$rc" -ne 0 ]; then
        printf '  RED    %-22s exit=%-3s %4ss  %s\n' "$k" "$rc" "$secs" "$cnt"; fail=1
    else
        printf '  green  %-22s exit=%-3s %4ss  %s\n' "$k" "$rc" "$secs" "$cnt"
    fi
done
echo "------------------------------------------------------------"
SUM=0
for k in $LEGS default clippy; do SUM=$(( SUM + $(cat "$LOG_DIR/$k.secs" 2>/dev/null || echo 0) )); done
echo "  sum of leg times (what a serial run costs): ${SUM}s"
echo "  wall clock for the same legs in ${LANES} lanes:   $(( T_END - T_START ))s"
echo "============================================================"
if [ "$fail" -ne 0 ]; then
    echo "NOT CERTIFIED. Logs in $LOG_DIR"; echo "SCRIPT_EXIT=1"; exit 1
fi
echo "EVERY CI LEG GREEN BY EXIT CODE. Logs in $LOG_DIR"
echo "SCRIPT_EXIT=0"
