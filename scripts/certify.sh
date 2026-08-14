#!/usr/bin/env bash
# LOCAL CERTIFICATION — three tiers, one verdict discipline.
#
#   certify.sh quick            fast pre-push filter (~4m). NOT a certification.
#   certify.sh focus <leg> [-E filter]
#                               quick, then ONE leg's WHOLE suite. NOT a certification.
#   certify.sh full             every leg CI runs. The only tier that certifies.
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
# ── WHY THREE TIERS, AND WHY `focus` RUNS A WHOLE SUITE ──────────────────
# The tiers exist because of a specific failure: a new filter field shipped
# without `#[serde(default)]`, breaking every persisted filter. Three
# trace-plane tests would have caught it in minutes. What actually happened was
# that the NEW WITNESS was run, it passed, and a thirty-minute full
# certification was launched to discover a defect a targeted run had already
# been standing next to.
#
# So `focus` does not accept a filter as its verdict. A filter, if given, runs
# FIRST for fast feedback — and then the leg's ENTIRE suite runs regardless, and
# only that produces the exit code. You cannot get a green out of this tier by
# testing only the thing you were thinking about. That is the whole point:
# "run the full suite before the expensive thing" is a rule people forget under
# time pressure, so it is a mechanism here rather than a discipline.
#
# Neither `quick` nor `focus` ever prints a certification verdict. They print
# "PASSED — NOT A CERTIFICATION", because a tier that tests 1 of 10 feature sets
# saying "certified" is how a weaker check comes to stand in for a stronger one.
#
# ── WHAT IS PARALLEL AND WHAT IS NOT ─────────────────────────────────────
#  1. **Cargo's target-directory lock.** Concurrent `cargo` invocations on one
#     target dir do not build concurrently — the second blocks. Lanes do NOT
#     multiply build throughput; they overlap one leg's test RUN with the next
#     leg's build. Per-lane CARGO_TARGET_DIR would parallelise builds too, but
#     each fresh target dir rebuilds the whole dependency graph cold and
#     `target/` already runs to ~100G. Measured on the v30.10.0 certification:
#     builds (including lock waiting) were 1105s of 4611s serial leg-time, and
#     test RUNS were 3506s — **76%**. The lock is not the ceiling; it was
#     assumed to be for several releases, and lane sizing was wrong the whole
#     time as a result. See below.
#  2. **Postgres template construction.** `src/test_pg.rs` builds ONE
#     cluster-wide template under `pg_advisory_lock`. PostgreSQL advisory locks
#     include MyDatabaseId, so they are PER-DATABASE — and each leg gets its own
#     database from `pg_test_db.sh`. Two legs starting cold therefore do NOT
#     serialise and can race on `CREATE DATABASE <template>`. Handled by warming
#     the template serially before any lane starts.
#  3. **FIX THE BINDING CONSTRAINT BEFORE TUNING PARALLELISM.** The same four
#     full certifications, one warm tree, identical work, 19,340 tests — read
#     them as a 2x2, because either row alone gives the wrong answer:
#
#                              5 lanes x 4    8 lanes x 4
#         stock postgres           1437s          1443s     <- tie
#         tuned postgres            917s           731s     <- 8 wins by 20%
#         tuned + PGDATA on tmpfs     -            643s     <- a further 12%
#
#     **Before** the database was fixed, asking for 32 test threads and asking
#     for 20 produced the same wall clock. That is the signature of work that is
#     not CPU-bound, and it made lane tuning look useless — two rounds of it
#     bought 0.4%. **After**, the same comparison shows 20%. Parallelism tuning
#     against a saturated dependency measures the dependency.
#
#     So the order is not negotiable: find what actually binds
#     (`scripts/pg_tune_test_cluster.sh`), fix it, and only then size the lanes.
#     Doing it the other way costs days and produces a confident wrong answer.
#
#     The seductive wrong turn, recorded because it nearly stuck: a thread sweep
#     on ONE leg (test-anchor, 1829 tests) alone on 32 idle cores —
#
#         threads   2      4      6     10     24
#         wall    236s   155s   128s   126s   117s
#
#     — shows a knee at ~6 and predicts ~2.2x from trading threads for lanes. It
#     delivered 0.4%, because that leg was chosen for being SQLITE-ONLY and thus
#     giving a clean signal, which is exactly what made it unrepresentative of
#     the eight postgres legs. A measurement chosen for cleanliness measured
#     something else. (The model was not wrong about CPU — it was invisible
#     behind the database. Once the database moved, wider did win.)
#
#     The cost of 8 lanes is fail-fast reach: of 10 jobs, 3 lanes leaves 7
#     skippable when a leg goes red, 5 leaves 5, 8 leaves only 2. Taken
#     deliberately — green is the common case, the 20% is paid on every run, and
#     at 643s the compute wasted on a red run is far smaller than at 1443s.
#
# ── RESOURCE FAILURES MUST NOT WEAR A CODE FAILURE'S CLOTHES ─────────────
# Two guards, both so that a resource failure is never reported as a defect:
#   * a floor checked BEFORE dispatch, and again before each new lane starts —
#     dispatch pauses rather than overcommitting;
#   * OOM attribution. A leg killed by the kernel exits 137, and this script
#     reports that as INFRASTRUCTURE, distinct from RED. "Your change broke the
#     secrets leg" and "the kernel shot the secrets leg" are different
#     sentences, and only one of them is about the change.
#
# The four non-cargo static gates run FIRST and concurrently — seconds, not
# thirty minutes in, which is where a phantom doc-version reference used to
# surface.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

MODE="${1:-full}"; shift 2>/dev/null || true
case "$MODE" in
    quick|focus|full) ;;
    -h|--help|help)
        sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown mode '$MODE'; expected quick|focus|full" >&2; exit 2 ;;
esac

LOG_DIR="${CERTIFY_LOG_DIR:-target/certify-logs}"
CORES="$(nproc)"

LEGS="core cirisaudit secrets cirisnode cirisgraph telemetry rest test-anchor"
ALL_KEYS="$LEGS default fmt clippy pyi featmatrix docver pyo3sqlite"

FOCUS_LEG=""; FOCUS_FILTER=""
if [ "$MODE" = "focus" ]; then
    FOCUS_LEG="${1:-}"; shift 2>/dev/null || true
    [ -n "$FOCUS_LEG" ] || { echo "focus mode needs a leg: $LEGS" >&2; exit 2; }
    echo " $LEGS " | grep -q " $FOCUS_LEG " || {
        echo "unknown leg '$FOCUS_LEG'; expected one of: $LEGS" >&2; exit 2; }
    [ "${1:-}" = "-E" ] && { FOCUS_FILTER="${2:-}"; }
fi

# ── the concurrency guard ────────────────────────────────────────────────
# Two suites against one postgres cluster produce reds that belong to neither.
# This is not hypothetical: a full suite was once run CONCURRENTLY with a live
# certification against the same DSN, and the cirisnode leg went red for reasons
# that had nothing to do with the tree. That cost a second thirty-minute run to
# discover the first one had been meaningless.
#
# `pg_test_db.sh` gives each leg its own database, so the collision is not the
# database itself — it is the shared cluster, the shared target-dir lock, and
# 32 cores being asked for twice.
mkdir -p "$(dirname "$LOG_DIR")"
exec 8>"$LOG_DIR.lock" || { echo "REFUSING: cannot create $LOG_DIR.lock" >&2; exit 2; }
if ! flock -n 8; then
    echo "REFUSING: another certify.sh holds $LOG_DIR.lock." >&2
    echo "  Two runs on one machine share a postgres cluster, a target-dir lock, and 32 cores." >&2
    echo "  Whatever the second one reports will be about the first one." >&2
    exit 2
fi
# `pgrep -x` matches the process NAME, never the command line. `pgrep -f` would
# match this script's own wrapper, because the wrapper's command line contains
# the pattern — a guard that fires on itself gets disabled within a day.
#
# And the reason is resolved per-process from /proc/PID/cwd, because it differs.
# A cargo in THIS repo holds the target-dir lock; a cargo in a SIBLING repo does
# not, and saying it does is wrong in a way a reader will notice immediately.
# The first thing this guard ever caught was a CIRISServer suite in
# /home/emoore/CIRISServer — a real reason to wait (32 cores and one postgres
# cluster, both contended) but not the reason the message would have given.
# A guard that misdiagnoses is a guard someone turns off.
REPO_ROOT="$(pwd -P)"
STRAY=""; STRAY_SAME=0
while read -r spid scmd; do
    [ -n "${spid:-}" ] || continue
    scwd="$(readlink -f "/proc/$spid/cwd" 2>/dev/null || echo '<gone>')"
    # `cargo` arrives as an absolute rustup toolchain path ~60 chars long, so a
    # naive truncation shows the path and hides the subcommand — the only part
    # that says what the process is doing.
    sargs="${scmd#* }"; [ "$sargs" = "$scmd" ] && sargs=""
    sshort="$(basename "${scmd%% *}") $sargs"
    case "$scwd" in
        "$REPO_ROOT"|"$REPO_ROOT"/*)
            STRAY_SAME=1
            STRAY="$STRAY    [$spid] ${sshort:0:70} — THIS repo: holds the target-dir lock"$'\n' ;;
        *)  STRAY="$STRAY    [$spid] ${sshort:0:70} — in $scwd: contends for cores and the postgres cluster"$'\n' ;;
    esac
done < <(pgrep -x -a 'cargo|cargo-nextest' 2>/dev/null || true)
if [ -n "$STRAY" ]; then
    echo "REFUSING: cargo is already running outside this script —" >&2
    printf '%s' "$STRAY" >&2
    if [ "$STRAY_SAME" -eq 1 ]; then
        echo "  Builds would serialise on the target-dir lock and every timing here would be fiction." >&2
    else
        echo "  Nothing contends on our target dir, but 32 cores and one postgres cluster are" >&2
        echo "  shared — which is exactly how a suite once went red for a reason that was not" >&2
        echo "  in the tree. Waiting costs less than the run you would have to discard." >&2
    fi
    echo "  Set CERTIFY_IGNORE_STRAY=1 only if you know what those processes are." >&2
    [ "${CERTIFY_IGNORE_STRAY:-0}" = "1" ] || exit 2
    echo "  CERTIFY_IGNORE_STRAY=1 — proceeding anyway." >&2
fi

rm -rf "$LOG_DIR"; mkdir -p "$LOG_DIR"

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

# ── disk and memory guards ───────────────────────────────────────────────
FREE_G="$(df -BG --output=avail . | tail -1 | tr -dc '0-9')"
if [ "${FREE_G:-0}" -lt 15 ]; then
    echo "REFUSING: only ${FREE_G}G free. A build that dies on ENOSPC produces a red that" >&2
    echo "  belongs to the disk, not the change. Reclaim space first." >&2
    exit 2
fi
avail_g() { awk '/^MemAvailable:/{printf "%d", $2/1048576}' /proc/meminfo; }
RAM_G="$(avail_g)"
# Budget per lane. A leg is a test binary plus its postgres backends; the floor
# is deliberately conservative because the failure mode it prevents (the kernel
# killing a leg mid-run) costs a whole run and reads like a code failure.
RAM_PER_LANE_G="${CERTIFY_RAM_PER_LANE_G:-2}"
RAM_FLOOR_G="${CERTIFY_RAM_FLOOR_G:-3}"

# ── lane sizing (see note 3) ─────────────────────────────────────────────
# DEFAULT 8, and ONLY valid because the postgres cluster is tuned. On a stock
# cluster this is worth nothing (1443s vs 1437s at 5); on a tuned one it is 20%
# (731s vs 917s). See the 2x2 in note 3 — the lane count is a lever only after
# the database stops being the constraint.
LANES_DEFAULT=8
if [ -n "${LANES:-}" ]; then
    LANE_WHY="LANES=$LANES from the environment"
else
    LANES=$LANES_DEFAULT
    LANE_WHY="default; 20% faster than 5 ON A TUNED CLUSTER (note 3)"
    RAM_LANES=$(( (RAM_G - RAM_FLOOR_G) / RAM_PER_LANE_G ))
    if [ "$RAM_LANES" -lt "$LANES" ]; then
        [ "$RAM_LANES" -lt 1 ] && RAM_LANES=1
        LANE_WHY="RAM-bound: ${RAM_G}G available, ${RAM_PER_LANE_G}G/lane over a ${RAM_FLOOR_G}G floor (would otherwise be $LANES)"
        LANES=$RAM_LANES
    fi
fi
PER_LANE="${PER_LANE:-$(( CORES / LANES ))}"
[ "$LANES" -lt 1 ] && LANES=1
[ "$PER_LANE" -lt 2 ] && PER_LANE=2

echo "mode=$MODE  RUSTFLAGS (derived from ci.yml): $RUSTFLAGS"
echo "cores=$CORES  ram=${RAM_G}G  free-disk=${FREE_G}G"
[ "$MODE" = "full" ] && echo "lanes=$LANES  test-threads/lane=$PER_LANE  ($LANE_WHY)"

# ── stage 1: fast non-cargo gates, concurrent, fail-fast ─────────────────
# Every tier runs these. They are seconds, and they are the gates that used to
# surface thirty minutes into a run.
echo
echo "=== fast static gates (concurrent) ==="
run_bg() { local name="$1"; shift; ( "$@" >"$LOG_DIR/$name.log" 2>&1; echo $? >"$LOG_DIR/$name.rc" ) </dev/null & }
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

# v31.3.0 (CIRISPersist#678) — THE AXIS x BACKEND COMPILE SWEEP.
#
# Every test leg is BASE + axis, and BASE = (postgres, server, pyo3, sqlite) —
# BOTH backends, always. So no leg has ever built an axis feature without a
# backend, or with only one, and the lint pass has the same shape. The matrix
# is itself a union on the backend axis, which is the exact blindness it was
# built to prevent.
#
# That is not theoretical: it cost v31.1.0 TWO build breaks in one day, both
# green on every backend leg —
#   - `--features cirisnode` alone could not compile the test target at all
#     (six media helpers gated broader than their own callers);
#   - the `default` leg died exit=101 on a witness importing a module gated
#     `any(sqlite, postgres)`.
#
# Both were COMPILE errors, so `cargo check` alone catches them — no test run,
# no database, cheap enough to sweep the whole product. Compile-only on
# purpose: this asks "does this configuration exist", not "does it pass".
for _axis in cirisaudit secrets cirisnode cirisgraph telemetry; do
  run_bg "axis-${_axis}-none"   cargo check --all-targets --no-default-features --features "$_axis"
  run_bg "axis-${_axis}-sqlite" cargo check --all-targets --no-default-features --features "$_axis sqlite"
  run_bg "axis-${_axis}-pg"     cargo check --all-targets --no-default-features --features "$_axis postgres"
done
wait
FAST_GATES="fmt pyi featmatrix docver pyo3sqlite"
fast_fail=0
for g in $FAST_GATES; do
    rc="$(cat "$LOG_DIR/$g.rc" 2>/dev/null || echo 99)"
    printf '  %-22s exit=%s\n' "$g" "$rc"
    [ "$rc" -ne 0 ] && fast_fail=1
done
if [ "$fast_fail" -ne 0 ]; then
    echo; echo "STOPPED — a fast gate is red; nothing expensive was run."
    for g in $FAST_GATES; do
        [ "$(cat "$LOG_DIR/$g.rc" 2>/dev/null || echo 99)" -ne 0 ] && {
            echo "--- $g ---"; tail -20 "$LOG_DIR/$g.log"; }
    done
    echo "SCRIPT_EXIT=1"; exit 1
fi

feature_csv() {
    local leg="$1" feats
    feats="$(python3 scripts/ci_feature_matrix.py set "$leg")" || return 1
    [ -n "$feats" ] || return 1
    echo "$feats" | tr ' ' ','
}
needs_pg() { python3 scripts/ci_feature_matrix.py set "$1" | grep -qw postgres; }

# ── warm the postgres template SERIALLY (see note 2) ─────────────────────
warm_template() {
    echo
    echo "=== warming the postgres template (serial, on purpose) ==="
    local log="$LOG_DIR/template-warm.log" rc
    scripts/pg_test_db.sh -- cargo nextest run --features postgres,sqlite \
        -E 'test(hard_case_third_party_conferral_parity_postgres_607)' >"$log" 2>&1
    rc=$?
    echo "  template warm exit=$rc  (a red here is a real red — it ran a real test)"
    if [ "$rc" -ne 0 ]; then
        echo "STOPPED — template warm-up failed. Logs: $log"
        tail -30 "$log"; echo "SCRIPT_EXIT=1"; exit 1
    fi
}

# ═════════════════════════════════════════════════════════════════════════
# TIER: quick / focus
# ═════════════════════════════════════════════════════════════════════════
if [ "$MODE" != "full" ]; then
    # `default` is the whole suite at default features — 46s on the v30.10.0
    # run, and it is the cheapest thing that can fail for a reason the static
    # gates cannot see.
    echo
    echo "=== default-feature suite + clippy (concurrent) ==="
    run_bg default env NEXTEST_TEST_THREADS="$(( CORES / 2 ))" cargo nextest run
    run_bg clippy bash -c '
        set -uo pipefail
        LF="$(python3 scripts/ci_feature_matrix.py set lint)" || exit 1
        [ -n "$LF" ] || { echo "EMPTY lint feature set" >&2; exit 1; }
        cargo clippy --features "$LF" --all-targets -- -D warnings'
    wait
    qfail=0
    for g in default clippy; do
        rc="$(cat "$LOG_DIR/$g.rc" 2>/dev/null || echo 99)"
        printf '  %-22s exit=%s  %s\n' "$g" "$rc" \
            "$(grep -oE '[0-9]+ tests run: [0-9]+ passed' "$LOG_DIR/$g.log" 2>/dev/null | tail -1)"
        [ "$rc" -ne 0 ] && { qfail=1; echo "--- $g ---"; tail -25 "$LOG_DIR/$g.log"; }
    done
    [ "$qfail" -ne 0 ] && { echo; echo "STOPPED — quick tier is red."; echo "SCRIPT_EXIT=1"; exit 1; }

    if [ "$MODE" = "quick" ]; then
        echo
        echo "=========================================================="
        echo "QUICK GATE PASSED — **NOT A CERTIFICATION**."
        echo "  1 of 9 feature sets was tested. Nothing here rules out a"
        echo "  failure behind a feature gate. Use 'focus <leg>' for the"
        echo "  leg you touched, or 'full' before a tag."
        echo "=========================================================="
        echo "SCRIPT_EXIT=0"; exit 0
    fi

    # ── focus: the filter is a courtesy; the WHOLE leg is the verdict ─────
    CSV="$(feature_csv "$FOCUS_LEG")" || {
        echo "REFUSING: empty feature set for '$FOCUS_LEG' — a leg that tests nothing cannot pass." >&2
        echo "SCRIPT_EXIT=2"; exit 2; }
    needs_pg "$FOCUS_LEG" && warm_template

    if [ -n "$FOCUS_FILTER" ]; then
        echo
        echo "=== targeted: $FOCUS_FILTER (fast feedback only — NOT the verdict) ==="
        FLOG="$LOG_DIR/focus-filter.log"
        if needs_pg "$FOCUS_LEG"; then
            scripts/pg_test_db.sh -- cargo nextest run --features "$CSV" -E "$FOCUS_FILTER" >"$FLOG" 2>&1
        else
            cargo nextest run --features "$CSV" -E "$FOCUS_FILTER" >"$FLOG" 2>&1
        fi
        frc=$?
        NRUN="$(grep -oE '[0-9]+ tests run' "$FLOG" | tail -1 | tr -dc '0-9')"
        echo "  exit=$frc  ${NRUN:-0} tests matched"
        # A filter matching nothing is a check that cannot fail. nextest exits 0
        # on an empty match by default, which would read as a pass.
        if [ "${NRUN:-0}" -eq 0 ]; then
            echo "REFUSING: the filter matched ZERO tests. A check that cannot fail is a report." >&2
            tail -15 "$FLOG"; echo "SCRIPT_EXIT=2"; exit 2
        fi
        [ "$frc" -ne 0 ] && { echo "STOPPED — targeted run is red; the full leg was not run."
            tail -40 "$FLOG"; echo "SCRIPT_EXIT=1"; exit 1; }
    fi

    echo
    echo "=== $FOCUS_LEG — ENTIRE suite (this is the verdict) ==="
    LLOG="$LOG_DIR/$FOCUS_LEG.log"; T0=$(date +%s)
    if needs_pg "$FOCUS_LEG"; then
        scripts/pg_test_db.sh -- env NEXTEST_TEST_THREADS="$(( CORES / 2 ))" \
            cargo nextest run --features "$CSV" >"$LLOG" 2>&1
    else
        NEXTEST_TEST_THREADS="$(( CORES / 2 ))" cargo nextest run --features "$CSV" >"$LLOG" 2>&1
    fi
    lrc=$?; T1=$(date +%s)
    echo "  exit=$lrc  $(( T1 - T0 ))s  $(grep -oE '[0-9]+ tests run: [0-9]+ passed' "$LLOG" | tail -1)"
    if [ "$lrc" -ne 0 ]; then
        echo; echo "STOPPED — the $FOCUS_LEG leg is red."; tail -60 "$LLOG"
        echo "SCRIPT_EXIT=1"; exit 1
    fi
    echo
    echo "=========================================================="
    echo "FOCUS GATE PASSED ($FOCUS_LEG) — **NOT A CERTIFICATION**."
    echo "  2 of 9 feature sets were tested. Run 'full' before a tag."
    echo "=========================================================="
    echo "SCRIPT_EXIT=0"; exit 0
fi

# ═════════════════════════════════════════════════════════════════════════
# TIER: full
# ═════════════════════════════════════════════════════════════════════════
warm_template

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
            local csv
            csv="$(feature_csv "$name")" || {
                echo "EMPTY or underivable feature set for '$name' — refusing to run a leg that tests nothing" >"$log"
                echo 1 >"$LOG_DIR/$name.rc"; return; }
            if needs_pg "$name"; then
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
echo "=== expensive legs (${LANES} lanes x ${PER_LANE} threads; feature sets DERIVED from ci_feature_matrix.py) ==="
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
PAUSES=0
pids=()
while read -r job; do
    if any_red; then
        echo "  !! STOPPING DISPATCH — a leg is already red; in-flight lanes will finish."
        break
    fi
    read -r -n 1 -u 9
    # Re-check AFTER blocking on the semaphore, not only before. With 10 jobs in
    # 8 lanes the last two sit here for minutes, and a leg can go red while they
    # wait — checking only at the top of the loop dispatches work whose verdict
    # is already decided, which is the exact cost this rule exists to avoid.
    if any_red; then
        echo "  !! STOPPING DISPATCH — a leg went red while this one waited for a lane."
        break
    fi
    # A lane slot is free, but free RAM is the binding constraint at 8 lanes.
    # Holding the slot rather than launching keeps the pressure bounded, and
    # costs only the time a running leg needs to finish.
    while [ "$(avail_g)" -lt "$RAM_FLOOR_G" ]; do
        PAUSES=$(( PAUSES + 1 ))
        [ "$PAUSES" -eq 1 ] && echo "  .. memory below ${RAM_FLOOR_G}G floor — holding dispatch rather than overcommitting"
        sleep 10
    done
    # `< /dev/null` is LOAD-BEARING. Without it the backgrounded job inherits
    # stdin — which is the job queue — and cargo/nextest read from it, silently
    # swallowing queue lines. Observed: of ten queued jobs, four ran and six
    # never started. They were reported RED (exit=99, no .rc) rather than green,
    # so the verdict stayed honest, but the run was worthless.
    ( run_job "$job"; printf '.' >&9 ) < /dev/null &
    pids+=($!)
done < "$LOG_DIR/queue"
[ "${#pids[@]}" -gt 0 ] && for p in "${pids[@]}"; do wait "$p"; done
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
fail=0; oom=0
for k in $ALL_KEYS; do
    rc="$(cat "$LOG_DIR/$k.rc" 2>/dev/null || echo 99)"
    secs="$(cat "$LOG_DIR/$k.secs" 2>/dev/null || echo -)"
    cnt="$(grep -oE '[0-9]+ tests run: [0-9]+ passed' "$LOG_DIR/$k.log" 2>/dev/null | tail -1)"
    if [ "$rc" -eq 99 ]; then
        # 99 is this script's sentinel for a missing .rc — the leg never ran.
        # Calling that RED would claim a failure nobody observed.
        printf '  UNKNOWN %-21s (not run)\n' "$k"; fail=1
    elif [ "$rc" -eq 137 ]; then
        # SIGKILL. Overwhelmingly the OOM killer at these lane counts. Reporting
        # it as RED would attribute a memory failure to the change under test.
        printf '  INFRA  %-22s exit=137 %4ss  killed (SIGKILL — almost certainly OOM)\n' "$k" "$secs"
        fail=1; oom=1
    elif [ "$rc" -ne 0 ]; then
        printf '  RED    %-22s exit=%-3s %4ss  %s\n' "$k" "$rc" "$secs" "$cnt"; fail=1
    else
        printf '  green  %-22s exit=%-3s %4ss  %s\n' "$k" "$rc" "$secs" "$cnt"
    fi
done
echo "------------------------------------------------------------"
SUM=0
for k in $LEGS default clippy; do SUM=$(( SUM + $(cat "$LOG_DIR/$k.secs" 2>/dev/null || echo 0) )); done
# SUM is the sum of leg times AS RUN — under contention, not in isolation. It
# GROWS with the lane count, because wider lanes make every leg individually
# slower. So SUM/wall is NOT a speedup: at 8x4 it printed "6.57x" for a run that
# was only modestly faster than 3x10, purely because contention had inflated the
# numerator. A metric that improves when you make things worse is worse than no
# metric. WALL CLOCK on a comparably warm tree is the only comparable number.
echo "  wall clock, ${LANES} lanes x ${PER_LANE} threads:  $(( T_END - T_START ))s   <-- the only comparable number"
echo "  sum of leg times AS RUN (contended, grows with lanes — NOT a baseline): ${SUM}s"
[ "$PAUSES" -gt 0 ] && echo "  dispatch paused ${PAUSES}x on the ${RAM_FLOOR_G}G memory floor — consider fewer lanes"
echo "============================================================"
if [ "$oom" -ne 0 ]; then
    echo "AT LEAST ONE LEG WAS KILLED BY THE KERNEL. That is a verdict about this"
    echo "machine, not about the tree. Re-run with fewer lanes:  LANES=4 $0 full"
fi
if [ "$fail" -ne 0 ]; then
    echo "NOT CERTIFIED. Logs in $LOG_DIR"; echo "SCRIPT_EXIT=1"; exit 1
fi
echo "EVERY CI LEG GREEN BY EXIT CODE. Logs in $LOG_DIR"
echo "SCRIPT_EXIT=0"
