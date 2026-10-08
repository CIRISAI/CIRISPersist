#!/usr/bin/env bash
# LOCAL CERTIFICATION — three tiers, one verdict discipline.
#
#   certify.sh quick            fast pre-push filter (~4m). NOT a certification.
#   certify.sh focus <leg> [-E filter]
#                               quick, then ONE leg's WHOLE suite. NOT a certification.
#   certify.sh full             every leg CI runs. The only tier that certifies.
#   certify.sh prebuild         compile every leg (`nextest --no-run`) + the static
#                               gates + clippy; run nothing. NOT a certification.
#   certify.sh fingerprint <full|prebuild> <leg>
#                               print the leg's RUSTFLAGS and cargo command; build
#                               nothing. Read by scripts/fingerprint_check.sh.
#   certify.sh verdict          re-print the verdict table of the run in
#                               $CERTIFY_LOG_DIR; run nothing.
#
# EXIT CODE IS THE ONLY VERDICT — captured on its own line immediately after
# each command, before any pipe or echo can overwrite it. 0 = green, 1 = a leg
# is RED, 3 = no leg is red but at least one was lost to the MACHINE (disk
# floor, killed by a signal, no exit code) — re-run, the tree is unjudged.
#
# ── `prebuild` REPLACES PRE-CERTIFY TEST LANES (CIRISPersist#1010) ───────
# Run `certify.sh prebuild` before the bump commit, then `full`. It compiles
# exactly the units `full` will run, under the same derived RUSTFLAGS. Running
# test lanes first (the old pre-certify step) ran certify's tests twice under a
# different fingerprint — 44–48 min per release for no added assurance, since
# certify is the gate. The pre-push hook builds the `core` leg's fingerprint
# too (scripts/ci_env.sh), so a pushed branch has already warmed the first leg.
#
# WHAT STAYS WARM, MEASURED (v53.2.0): every dependency of every leg, the
# clippy units and the dev wheel. NOT the persist library itself: Cargo.toml's
# `crate-type = ["cdylib", "rlib"]` makes cargo name it WITHOUT a hash
# (`deps/libciris_persist.{rlib,so}` — a cdylib needs a stable name), so all
# feature sets share one output and one fingerprint. Whichever leg built last
# owns it; every other leg sees `FeaturesChanged` and rebuilds the lib and
# each integration-test binary linking it — 1m04s–1m22s per leg on this box
# after a complete prebuild (deps: 0 recompiled). The lib-test binaries the
# hook builds (`--lib`) are hashed and are unaffected.
#
# ── DISK IS RE-CHECKED BEFORE EVERY LEG (CIRISPersist#1012) ──────────────
# The launch-time guard alone let a co-tenant build fill the disk 33–37 min
# into a run (2 of 4 cycles), and the ENOSPC leg printed as `green exit= s`.
# Now, before each leg is dispatched, free space on the target filesystem is
# compared with CERTIFY_MIN_FREE_GB (default 25). Below it, in-flight legs are
# drained (pruning under a running nextest deletes binaries it re-execs per
# test), `scripts/prune_target.py` drops superseded artifacts, and the check is
# repeated. Still below: the leg is recorded DISK — not red, not green — the
# run continues, and the verdict exits 3 with `INFRA: n legs skipped for disk`.
# A leg that went red WITH `No space left on device` in its log is DISK too.
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
    quick|focus|full|prebuild|fingerprint|verdict|keys) ;;
    -h|--help|help)
        sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown mode '$MODE'; expected quick|focus|full|prebuild|fingerprint|verdict" >&2; exit 2 ;;
esac

# shellcheck source=scripts/ci_env.sh
. scripts/ci_env.sh

LOG_DIR="${CERTIFY_LOG_DIR:-target/certify-logs}"
CORES="$(nproc)"

LEGS="core cirisaudit secrets cirisnode cirisgraph telemetry rest test-anchor"

# v32.0.0 (CIRISPersist#694) — the axis sweep's key list is DERIVED, not typed
# out a second time.
#
# Before this, `ALL_KEYS` was a hand-maintained duplicate and it had already
# drifted: `dirdouble` and all fifteen `axis-*` legs were launched by `run_bg`,
# burned full CPU, wrote their `.rc` files — and appeared in no list that anyone
# read. The verdict loop iterates `ALL_KEYS`, so sixteen legs could go red and
# the run still printed EVERY CI LEG GREEN BY EXIT CODE.
#
# Both of those gates exist BECAUSE a check was blind (the axis sweep because
# the feature matrix was a union on the backend axis; the double's check because
# an ungated generated instrument drifts). They were installed here and left
# unread. Deriving the list from the same variable the launcher loops over is
# what stops that from recurring — a second hand-written list is how it started.
AXES="cirisaudit secrets cirisnode cirisgraph telemetry"
AXIS_KEYS=""
for _a in $AXES; do
    AXIS_KEYS="$AXIS_KEYS axis-${_a}-none axis-${_a}-sqlite axis-${_a}-pg"
done
# v35.0.0 (CIRISPersist#669/#710) — `python` is the leg that runs the ARTIFACT
# USERS INSTALL: a maturin dev-wheel built with the feature line DERIVED from
# pyproject's shipped list (`scripts/wheel_features.py line`), then pytest over
# tests/python/. Until now this script — THE release gate — could not run
# tests/python at all, so v34.0.0 was certified "EVERY CI LEG GREEN BY EXIT
# CODE" on a tree whose only Python-reachability witness lived exactly there;
# CI's wheel job caught it instead, by luck. `wheelfeat` is the matching fast
# gate: tested-wheel ⊇ shipped-wheel, seconds, before anything compiles.
# The leg is skippable ONLY by CERTIFY_SKIP_PYTHON=1, and never silently — the
# verdict table carries a SKIPPED line and the run stops claiming full
# certification.
ALL_KEYS="$LEGS default python fmt clippy pyi featmatrix wheelfeat docver pyo3sqlite dirdouble astgates weaver floortoken$AXIS_KEYS"

FOCUS_LEG=""; FOCUS_FILTER=""
if [ "$MODE" = "focus" ]; then
    FOCUS_LEG="${1:-}"; shift 2>/dev/null || true
    [ -n "$FOCUS_LEG" ] || { echo "focus mode needs a leg: $LEGS" >&2; exit 2; }
    echo " $LEGS " | grep -q " $FOCUS_LEG " || {
        echo "unknown leg '$FOCUS_LEG'; expected one of: $LEGS" >&2; exit 2; }
    [ "${1:-}" = "-E" ] && { FOCUS_FILTER="${2:-}"; }
fi

# ── RUSTFLAGS, DERIVED FROM ci.yml ───────────────────────────────────────
# Derived (scripts/ci_env.sh) before any guard, because `fingerprint` must
# report the same value the run would use without taking the run's lock.
CI_RUSTFLAGS="$(ci_rustflags)" || {
    echo "REFUSING: could not derive a non-empty RUSTFLAGS from ci.yml — it may have moved or been removed." >&2
    echo "  Certifying with weaker flags than CI is how a green verdict lies." >&2
    exit 2; }
export RUSTFLAGS="$CI_RUSTFLAGS"

feature_csv() { ci_feature_csv "$1"; }
needs_pg() { python3 scripts/ci_feature_matrix.py set "$1" | grep -qw postgres; }

# The ONE place a leg's cargo invocation is spelled. `full` runs it,
# `prebuild` runs it with `--no-run`, `fingerprint` prints it — so the units
# prebuild compiles are the units full runs, by construction.
#
# 2026-09-22 (CIRISPersist#880) — the substrate_machine property harness
# (170 s + 109 s) tests BACKEND parity and varies by no feature axis; it runs
# in the `rest` leg only (every backend, every feature — the gauntlet), exactly
# as CI's matrix does. Full case count where it runs; the other legs skip it by
# filter. (A filter is not part of the build fingerprint.)
leg_cmd() {
    local name="$1" csv
    LEG_CMD=()
    case "$name" in
        default) LEG_CMD=(cargo nextest run) ;;
        *)
            csv="$(feature_csv "$name")" || return 1
            LEG_CMD=(cargo nextest run --features "$csv")
            [ "$name" = "rest" ] || LEG_CMD+=(-E 'not test(/substrate_machine/)')
            ;;
    esac
}

# `keys`: every verdict key, one line — for scripts/certify_selfcheck.sh,
# which builds synthetic log directories and must cover each key.
if [ "$MODE" = "keys" ]; then printf '%s\n' $ALL_KEYS; exit 0; fi

# ── fingerprint: print, build nothing, take no lock ──────────────────────
if [ "$MODE" = "fingerprint" ]; then
    FP_MODE="${1:-}"; FP_LEG="${2:-}"
    case "$FP_MODE" in full|prebuild) ;; *)
        echo "usage: certify.sh fingerprint <full|prebuild> <leg>" >&2; exit 2 ;; esac
    leg_cmd "$FP_LEG" || { echo "REFUSING: empty or underivable feature set for '$FP_LEG'" >&2; exit 2; }
    [ "$FP_MODE" = "prebuild" ] && LEG_CMD+=(--no-run)
    printf 'RUSTFLAGS=%s\n' "$RUSTFLAGS"
    printf 'CMD='; printf '%q ' "${LEG_CMD[@]}"; echo
    exit 0
fi

# One classifier for every verdict this script prints. Sets CLS to one of
#   green   exit 0
#   RED     a non-zero exit from the command itself — the only class about the tree
#   KILLED  exit > 128: the leg was killed by signal (CLS_SIG); 137 is almost always OOM
#   DISK    skipped by the per-leg disk floor (`.disk`), OR red with ENOSPC in its log
#   UNKNOWN an `.rc` that exists but holds no integer — ENOSPC on the write itself
#   NOTRUN  no `.rc` at all
#   SKIP    an explicit `.skip` marker (CERTIFY_SKIP_PYTHON=1)
# #1012: an empty `.rc` used to fall through every `-eq`/`-ne` test (each one an
# `integer expression expected` error, i.e. false) into the GREEN branch, and an
# ENOSPC leg printed `green rest exit= s`. Green is now reachable from exactly
# one input: an `.rc` holding `0`.
classify() {
    local k="$1" raw
    CLS_RC="-"; CLS_SIG=""
    if [ -f "$LOG_DIR/$k.skip" ]; then CLS=SKIP; return; fi
    if [ -f "$LOG_DIR/$k.disk" ]; then CLS=DISK; return; fi
    if [ ! -f "$LOG_DIR/$k.rc" ]; then CLS=NOTRUN; return; fi
    raw="$(cat "$LOG_DIR/$k.rc" 2>/dev/null)"
    if ! [[ "$raw" =~ ^[0-9]+$ ]]; then
        CLS=UNKNOWN
        grep -qs 'No space left on device' "$LOG_DIR/$k.log" && CLS=DISK
        return
    fi
    CLS_RC="$raw"
    if [ "$raw" -eq 0 ]; then CLS=green
    elif grep -qs 'No space left on device' "$LOG_DIR/$k.log"; then CLS=DISK
    elif [ "$raw" -gt 128 ]; then CLS=KILLED; CLS_SIG="$(kill -l $(( raw - 128 )) 2>/dev/null || echo $(( raw - 128 )))"
    else CLS=RED
    fi
}

# ── verdict ──────────────────────────────────────────────────────────────
# A function so `certify.sh verdict` can re-read an existing log directory —
# which is also how scripts/certify_verdict_check.sh witnesses the table.
print_verdict() {

    # Every row comes from `classify`. Exit 1 iff a leg is RED; otherwise exit 3 if
    # any leg was lost to the machine (DISK / KILLED / UNKNOWN / NOTRUN); 0 only if
    # every key is green (or explicitly SKIPPED, which prints its own refusal).
    echo
    echo "================ FULL CERTIFICATION VERDICT ================"
    n_red=0; n_disk=0; n_killed=0; n_unknown=0; n_notrun=0; oom=0; skipped=0
    for k in $ALL_KEYS; do
        classify "$k"
        secs="$(tr -dc '0-9' < "$LOG_DIR/$k.secs" 2>/dev/null)"; [ -n "$secs" ] || secs="-"
        cnt="$(grep -oE '[0-9]+ tests run: [0-9]+ passed|[0-9]+ passed in [0-9.]+s' "$LOG_DIR/$k.log" 2>/dev/null | tail -1)"
        case "$CLS" in
            SKIP)
                # Only CERTIFY_SKIP_PYTHON writes a .skip marker. Loud on purpose:
                # a skipped leg must cost the reader a sentence, not vanish.
                printf '  SKIP    %-22s SKIPPED (CERTIFY_SKIP_PYTHON=1) — the Python surface was NOT certified\n' "$k"
                skipped=1 ;;
            NOTRUN)
                # No `.rc` — the leg never ran. Calling that RED would claim a
                # failure nobody observed.
                printf '  NOTRUN  %-22s (not run)\n' "$k"; n_notrun=$(( n_notrun + 1 )) ;;
            DISK)
                if [ -f "$LOG_DIR/$k.disk" ]; then
                    printf '  DISK    %-22s skipped: %sG free after prune, floor %sG\n' "$k" "$(cat "$LOG_DIR/$k.disk")" "${MIN_FREE_GB:-?}"
                else
                    printf '  DISK    %-22s exit=%-3s %4ss  ENOSPC in the log — the disk, not the tree\n' "$k" "$CLS_RC" "$secs"
                fi
                n_disk=$(( n_disk + 1 )) ;;
            UNKNOWN)
                printf '  UNKNOWN %-22s exit=?   %4ss  .rc holds no exit code (infra)\n' "$k" "$secs"
                n_unknown=$(( n_unknown + 1 )) ;;
            KILLED)
                # A signal, not an exit. 137 is SIGKILL, overwhelmingly the OOM
                # killer at these lane counts. Reporting it as RED would attribute
                # a machine failure to the change under test.
                printf '  KILLED(%s) %-18s exit=%-3s %4ss\n' "$CLS_SIG" "$k" "$CLS_RC" "$secs"
                [ "$CLS_RC" = 137 ] && oom=1
                n_killed=$(( n_killed + 1 )) ;;
            RED)
                printf '  RED     %-22s exit=%-3s %4ss  %s\n' "$k" "$CLS_RC" "$secs" "$cnt"; n_red=$(( n_red + 1 )) ;;
            green)
                printf '  green   %-22s exit=%-3s %4ss  %s\n' "$k" "$CLS_RC" "$secs" "$cnt" ;;
        esac
    done
    n_infra=$(( n_disk + n_killed + n_unknown + n_notrun ))
    echo "------------------------------------------------------------"
    if [ -n "${T_END:-}" ]; then
        SUM=0
        for k in $LEGS default clippy python; do
            s="$(tr -dc '0-9' < "$LOG_DIR/$k.secs" 2>/dev/null)"; SUM=$(( SUM + ${s:-0} ))
        done
        # SUM is the sum of leg times AS RUN — under contention, not in isolation. It
        # GROWS with the lane count, because wider lanes make every leg individually
        # slower. So SUM/wall is NOT a speedup: at 8x4 it printed "6.57x" for a run that
        # was only modestly faster than 3x10, purely because contention had inflated the
        # numerator. A metric that improves when you make things worse is worse than no
        # metric. WALL CLOCK on a comparably warm tree is the only comparable number.
        echo "  wall clock, ${LANES} lanes x ${PER_LANE} threads:  $(( T_END - T_START ))s   <-- the only comparable number"
        echo "  sum of leg times AS RUN (contended, grows with lanes — NOT a baseline): ${SUM}s"
        [ "$PAUSES" -gt 0 ] && echo "  dispatch paused ${PAUSES}x on the ${RAM_FLOOR_G}G memory floor — consider fewer lanes"
    fi
    echo "============================================================"
    if [ "$oom" -ne 0 ]; then
        echo "AT LEAST ONE LEG WAS KILLED BY THE KERNEL. That is a verdict about this"
        echo "machine, not about the tree. Re-run with fewer lanes:  LANES=4 $0 full"
    fi
    if [ "$n_red" -ne 0 ]; then
        echo "NOT CERTIFIED — $n_red leg(s) RED. Logs in $LOG_DIR"; echo "SCRIPT_EXIT=1"; exit 1
    fi
    if [ "$n_infra" -ne 0 ]; then
        echo "NOT CERTIFIED — no leg is red, but the machine lost $n_infra. The tree is UNJUDGED; re-run."
        echo "INFRA: $n_disk legs skipped for disk, $n_killed killed by a signal, $n_unknown with no exit code, $n_notrun not run."
        echo "Logs in $LOG_DIR"; echo "SCRIPT_EXIT=3"; exit 3
    fi
    if [ "$skipped" -ne 0 ]; then
        # Explicitly requested, explicitly not certified. The one thing this
        # branch must never print is the unqualified verdict below.
        echo "EVERY LEG THAT RAN IS GREEN BY EXIT CODE — but 'python' was SKIPPED (CERTIFY_SKIP_PYTHON=1)."
        echo "The artifact users install was not run. NOT a full certification; do not tag on this run."
        echo "SCRIPT_EXIT=0"; exit 0
    fi
    echo "EVERY CI LEG GREEN BY EXIT CODE. Logs in $LOG_DIR"
    echo "SCRIPT_EXIT=0"; exit 0
}

# ── verdict: re-print the verdict of an existing run, build nothing ─────
if [ "$MODE" = "verdict" ]; then
    [ -d "$LOG_DIR" ] || { echo "no log directory at $LOG_DIR" >&2; exit 2; }
    print_verdict
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

# ── disk and memory guards ───────────────────────────────────────────────
# Free space is measured on the filesystem that holds the TARGET directory —
# that is what a build fills, and with CARGO_TARGET_DIR set it need not be the
# one holding the checkout.
TARGET_ROOT="${CARGO_TARGET_DIR:-target}"
MIN_FREE_GB="${CERTIFY_MIN_FREE_GB:-25}"
target_free_gb() {
    local d="$TARGET_ROOT"
    while [ ! -e "$d" ]; do d="$(dirname "$d")"; done
    df -BG --output=avail "$d" | tail -1 | tr -dc '0-9'
}
FREE_G="$(target_free_gb)"
if [ "${FREE_G:-0}" -lt 15 ]; then
    echo "REFUSING: only ${FREE_G}G free. A build that dies on ENOSPC produces a red that" >&2
    echo "  belongs to the disk, not the change. Reclaim space first." >&2
    exit 2
fi
# Per-leg re-check (see the header, #1012). Returns 0 when the leg may run;
# otherwise writes `<leg>.disk` and returns 1. The CALLER guarantees nothing of
# this run is in flight before calling it below the floor: the prune deletes
# artifacts, and nextest re-execs its test binaries once per test.
disk_guard() {
    local name="$1" free
    free="$(target_free_gb)"
    [ "${free:-0}" -ge "$MIN_FREE_GB" ] && return 0
    echo "  .. disk: ${free}G free on the target filesystem, below the ${MIN_FREE_GB}G floor — pruning before '$name'"
    if ! python3 scripts/prune_target.py --target "$TARGET_ROOT" >>"$LOG_DIR/prune.log" 2>&1; then
        echo "  .. prune_target.py exited non-zero (see $LOG_DIR/prune.log)"
    fi
    echo "  .. $(tail -1 "$LOG_DIR/prune.log" 2>/dev/null)"
    free="$(target_free_gb)"
    if [ "${free:-0}" -ge "$MIN_FREE_GB" ]; then
        echo "  .. disk: ${free}G free after the prune — running '$name'"
        return 0
    fi
    echo "  !! DISK — ${free}G free after the prune, still below ${MIN_FREE_GB}G; '$name' is NOT run"
    echo "${free:-0}" > "$LOG_DIR/$name.disk"
    return 1
}
avail_g() { awk '/^MemAvailable:/{printf "%d", $2/1048576}' /proc/meminfo; }
RAM_G="$(avail_g)"
# Budget per lane. A leg is a test binary plus its postgres backends; the floor
# is deliberately conservative because the failure mode it prevents (the kernel
# killing a leg mid-run) costs a whole run and reads like a code failure.
# 2026-09-22 (CIRISPersist#879) — 2G/lane was a guess that OOM-killed legs twice
# on the 31G box (a 16-thread nextest lane holds ~5G; the python leg's
# thin-LTO cdylib build alone peaks past 10G). The python leg now runs
# ALONE before the lane pool; the feature legs are sized at 6G each.
RAM_PER_LANE_G="${CERTIFY_RAM_PER_LANE_G:-6}"
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
# v43.0.0 (I22) — the storage floor is unconstructible OUTSIDE the crate: a
# `compile_fail` doctest is the one witness that runs as an external crate.
# `cargo nextest` never runs doctests, so without this leg the witness would
# exist and never execute — a check that cannot fail is a report.
run_bg floortoken bash -c 'set -o pipefail; cargo test --quiet --doc --features sqlite -- StorageFloor 2>&1 | tee /dev/stderr | grep -q "test result: ok. 1 passed"'
run_bg dirdouble  python3 scripts/gen_directory_double.py --check
# v53.2.0 (CIRISPersist#1026/#1027) — the ast-grep gate counts and the Weaver
# telemetry registry. Each fetches its pinned tool on first use (cached under
# ~/.cache); offline with no cached copy it exits 3, which reads RED here: a
# gate that could not look has not passed.
run_bg astgates   scripts/ast_gates.sh
run_bg weaver     scripts/weaver_check.sh
# v35.0.0 (CIRISPersist#710) — tested-wheel ⊇ shipped-wheel, and nobody
# hand-spells a `maturin develop --features` list (here or in ci.yml).
run_bg wheelfeat  python3 scripts/wheel_features.py check
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
for _axis in $AXES; do
  run_bg "axis-${_axis}-none"   cargo check --all-targets --no-default-features --features "$_axis"
  run_bg "axis-${_axis}-sqlite" cargo check --all-targets --no-default-features --features "$_axis sqlite"
  run_bg "axis-${_axis}-pg"     cargo check --all-targets --no-default-features --features "$_axis postgres"
done
wait
# v32.0.0 (#694) — `dirdouble` and the axis sweep join the fast gates. They ran
# in this stage all along; only their verdicts were dropped. Reading them HERE,
# before the expensive legs dispatch, is the point of the fast stage: a compile
# break under `--features cirisnode` alone should cost seconds, not the full
# test matrix first.
FAST_GATES="fmt pyi featmatrix wheelfeat docver pyo3sqlite dirdouble astgates weaver floortoken$AXIS_KEYS"

# Every `.rc` this run produced must be claimed by a key someone reads. The log
# directory is wiped at startup, so anything here was written by this run.
#
# This is the part that does not decay. The fix above is correct today; this
# makes the NEXT unread leg announce itself instead of waiting to be found by
# someone reading the script line by line — which is how #694 was found, and is
# not a repeatable detection method.
unclaimed=""
for _rcf in "$LOG_DIR"/*.rc; do
    [ -f "$_rcf" ] || continue
    _k="$(basename "$_rcf" .rc)"
    case " $ALL_KEYS " in
        *" $_k "*) ;;
        *) unclaimed="$unclaimed $_k" ;;
    esac
done
if [ -n "$unclaimed" ]; then
    echo
    echo "STOPPED — leg(s) ran and no list reads their result:$unclaimed"
    echo "  A leg whose exit code nobody inspects is worse than one that never"
    echo "  ran: it produces a log that looks like evidence. Add it to ALL_KEYS"
    echo "  (and to FAST_GATES if it belongs to the fast stage)."
    echo "SCRIPT_EXIT=1"; exit 1
fi

fast_fail=0; fast_infra=0
for g in $FAST_GATES; do
    classify "$g"
    printf '  %-22s exit=%-3s %s\n' "$g" "$CLS_RC" "$( [ "$CLS" = green ] || echo "$CLS")"
    case "$CLS" in
        green) ;;
        RED) fast_fail=1 ;;
        *) fast_infra=1 ;;
    esac
done
if [ "$fast_fail" -ne 0 ] || [ "$fast_infra" -ne 0 ]; then
    echo; echo "STOPPED — a fast gate is not green; nothing expensive was run."
    for g in $FAST_GATES; do
        classify "$g"
        [ "$CLS" = green ] || { echo "--- $g ($CLS) ---"; tail -20 "$LOG_DIR/$g.log" 2>/dev/null; }
    done
    if [ "$fast_fail" -eq 0 ]; then
        echo "INFRA: no fast gate is red, but at least one was lost to the machine. The tree is unjudged."
        echo "SCRIPT_EXIT=3"; exit 3
    fi
    echo "SCRIPT_EXIT=1"; exit 1
fi

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

# Both clippy invocations CI's lint job runs. Every tier calls this one
# function, so `prebuild` warms exactly what `full` and `quick` check.
# v53.1.2 — CI's lint job ALSO runs --all-features: it compiles the test-anchor
# integration tests the lint shape does not (v53.1.1 lost a PR CI round to a
# redundant_guards lint certify never saw). Until v53.2.0 only `quick` ran it;
# `full`, the tier that certifies, ran the lint shape alone.
run_clippy() {
    local lf
    lf="$(python3 scripts/ci_feature_matrix.py set lint)" || return 1
    [ -n "$lf" ] || { echo "EMPTY lint feature set" >&2; return 1; }
    cargo clippy --features "$lf" --all-targets -- -D warnings || return 1
    cargo clippy --all-features --all-targets -- -D warnings
}

# v35.0.0 (#669/#710) — the artifact users install, tested. The feature line is
# DERIVED (`wheel_features.py line` = pyproject's shipped list − written
# exclusions + test-only riders); the venv persists in target/ so
# pip/maturin/pytest install once, and `maturin develop` matches CI's
# wheel-pytest step: --release, under the same derived RUSTFLAGS as every other
# leg. pytest runs as `python -m pytest` so it is the VENV's interpreter — the
# one the wheel was installed into — never a system pytest that would import
# nothing and report it green. First run needs the network (pip: maturin+pytest;
# maturin develop: ciris-verify). `build` stops after the wheel (prebuild).
run_python() {
    local what="$1"
    WHAT="$what" bash -c '
        set -euo pipefail
        WF="$(python3 scripts/wheel_features.py line)"
        [ -n "$WF" ] || { echo "EMPTY derived wheel feature line" >&2; exit 1; }
        echo "tested dev-wheel: --features \"$WF\""
        VENV="target/certify-pyvenv"
        [ -x "$VENV/bin/python" ] || python3 -m venv "$VENV"
        # shellcheck disable=SC1091
        . "$VENV/bin/activate"
        python -m pytest --version >/dev/null 2>&1 && command -v maturin >/dev/null 2>&1 \
            || python -m pip install maturin pytest
        maturin develop --release --features "$WF"
        [ "$WHAT" = build ] && exit 0
        python -m pytest tests/python/ -v
    '
}

# ═════════════════════════════════════════════════════════════════════════
# TIER: prebuild (#1010) — compile what `full` runs; run nothing
# ═════════════════════════════════════════════════════════════════════════
# Serial on purpose: cargo's target-dir lock serialises builds anyway, and with
# nothing in flight between legs the per-leg disk guard may prune safely.
if [ "$MODE" = "prebuild" ]; then
    echo
    echo "=== prebuild: every leg's units, compiled and not run (feature sets DERIVED) ==="
    PB_KEYS=""
    pb_red=0
    pb_one() {  # $1 = key, rest = command
        local key="$1" t0; shift
        PB_KEYS="$PB_KEYS $key"
        disk_guard "$key" || { printf '  %-22s DISK\n' "$key"; return 0; }
        t0=$(date +%s)
        "$@" >"$LOG_DIR/$key.log" 2>&1 </dev/null
        echo $? >"$LOG_DIR/$key.rc"; echo $(( $(date +%s) - t0 )) >"$LOG_DIR/$key.secs"
        classify "$key"
        printf '  %-22s %-7s exit=%-3s %4ss\n' "$key" "$CLS" "$CLS_RC" "$(cat "$LOG_DIR/$key.secs")"
        [ "$CLS" = RED ] && pb_red=1
        return 0
    }
    for leg in $LEGS default; do
        [ "$pb_red" -eq 0 ] || { echo "  !! STOPPING — a build is red; the rest would compile for a verdict already decided."; break; }
        leg_cmd "$leg" || { PB_KEYS="$PB_KEYS build-$leg"; echo "EMPTY or underivable feature set" >"$LOG_DIR/build-$leg.log"
            echo 1 >"$LOG_DIR/build-$leg.rc"; pb_red=1; continue; }
        pb_one "build-$leg" "${LEG_CMD[@]}" --no-run
    done
    [ "$pb_red" -eq 0 ] && pb_one build-clippy run_clippy
    if [ "$pb_red" -eq 0 ] && [ "${CERTIFY_SKIP_PYTHON:-0}" != "1" ]; then
        pb_one build-python run_python build
    fi
    echo
    echo "================ PREBUILD — NOT A CERTIFICATION ================"
    pb_infra=0; pb_disk=0
    for k in $PB_KEYS; do
        classify "$k"
        case "$CLS" in
            green) ;;
            RED) printf '  RED     %-22s see %s\n' "$k" "$LOG_DIR/$k.log"; tail -15 "$LOG_DIR/$k.log" ;;
            DISK) printf '  DISK    %-22s\n' "$k"; pb_infra=$(( pb_infra + 1 )); pb_disk=$(( pb_disk + 1 )) ;;
            *) printf '  %-7s %-22s exit=%s %s\n' "$CLS" "$k" "$CLS_RC" "$CLS_SIG"; pb_infra=$(( pb_infra + 1 )) ;;
        esac
    done
    if [ "$pb_red" -ne 0 ]; then
        echo "STOPPED — a leg does not compile. 'full' would be red; fix it first."
        echo "SCRIPT_EXIT=1"; exit 1
    fi
    if [ "$pb_infra" -ne 0 ]; then
        echo "INFRA: $pb_disk legs skipped for disk, $(( pb_infra - pb_disk )) lost otherwise — those legs are cold."
        echo "SCRIPT_EXIT=3"; exit 3
    fi
    echo "every leg compiled — deps, clippy and the wheel are warm for 'full' (the hashless"
    echo "persist lib relinks per leg; see the header). Nothing was RUN."
    echo "SCRIPT_EXIT=0"; exit 0
fi

# ═════════════════════════════════════════════════════════════════════════
# TIER: quick / focus
# ═════════════════════════════════════════════════════════════════════════
if [ "$MODE" != "full" ]; then
    # `default` is the whole suite at default features — 46s on the v30.10.0
    # run, and it is the cheapest thing that can fail for a reason the static
    # gates cannot see.
    echo
    echo "=== default-feature suite + clippy (concurrent) ==="
    run_bg default env NEXTEST_TEST_THREADS="$(ci_single_leg_threads)" cargo nextest run
    run_bg clippy run_clippy
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
        scripts/pg_test_db.sh -- env NEXTEST_TEST_THREADS="$(ci_single_leg_threads)" \
            cargo nextest run --features "$CSV" >"$LLOG" 2>&1
    else
        NEXTEST_TEST_THREADS="$(ci_single_leg_threads)" cargo nextest run --features "$CSV" >"$LLOG" 2>&1
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
# v35.0.0 (#669) — `python` queues FIRST: its release-profile wheel build is
# the longest single compile in the run, so it should be in the opening wave
# where it overlaps the other legs instead of tailing the whole gate.
#
# CERTIFY_SKIP_PYTHON=1 is the ONLY way not to run it, and it is loud twice:
# here at dispatch, and as a SKIPPED row in the verdict — after which this run
# refuses to call itself a full certification. A leg that can be skipped
# silently is the #669 defect with an env var for a fig leaf.
if [ "${CERTIFY_SKIP_PYTHON:-0}" = "1" ]; then
    echo "  !! CERTIFY_SKIP_PYTHON=1 — the python leg (dev-wheel + pytest tests/python) WILL NOT RUN."
    echo "  !! This run cannot vouch for the artifact users install."
    : > "$LOG_DIR/python.skip"
fi
for leg in $LEGS; do echo "$leg" >> "$LOG_DIR/queue"; done
echo "default" >> "$LOG_DIR/queue"
echo "clippy"  >> "$LOG_DIR/queue"

run_job() {
    local name="$1" log="$LOG_DIR/$1.log" t0 t1 rc
    t0=$(date +%s)
    case "$name" in
        clippy) run_clippy >"$log" 2>&1 ;;
        python) run_python test >"$log" 2>&1 ;;
        *)
            leg_cmd "$name" || {
                echo "EMPTY or underivable feature set for '$name' — refusing to run a leg that tests nothing" >"$log"
                echo 1 >"$LOG_DIR/$name.rc"; return; }
            if [ "$name" != default ] && needs_pg "$name"; then
                scripts/pg_test_db.sh -- env NEXTEST_TEST_THREADS="$PER_LANE" "${LEG_CMD[@]}" >"$log" 2>&1
            else
                NEXTEST_TEST_THREADS="$PER_LANE" "${LEG_CMD[@]}" >"$log" 2>&1
            fi
            ;;
    esac
    rc=$?; t1=$(date +%s)
    echo "$rc" > "$LOG_DIR/$name.rc"; echo "$(( t1 - t0 ))" > "$LOG_DIR/$name.secs"
    # Two count shapes: nextest ("N tests run: N passed") and pytest's summary
    # ("N passed in N.NNs") for the python leg.
    printf '  %-22s exit=%-3s %4ss  %s\n' "$name" "$rc" "$(( t1 - t0 ))" \
        "$(grep -oE '[0-9]+ tests run: [0-9]+ passed|[0-9]+ passed in [0-9.]+s' "$log" | tail -1)"
}

T_START=$(date +%s)
# 2026-09-22 (CIRISPersist#879) — the python leg (dev-wheel: a thin-LTO,
# codegen-units=1 release cdylib) is the peak-RAM process of the whole run
# and was the leg the OOM killer took at LANES=2. It runs ALONE, before the
# lane pool, so the feature legs can run at more than one lane.
if [ ! -f "$LOG_DIR/python.skip" ]; then
    echo
    echo "=== python leg (serial — the peak-RAM build runs alone) ==="
    disk_guard python && run_job python
fi
echo
echo "=== expensive legs (${LANES} lanes x ${PER_LANE} threads; feature sets DERIVED from ci_feature_matrix.py) ==="
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
#
# A DISK leg does NOT stop dispatch: the next leg meets the same per-leg floor
# and is either run or recorded DISK on its own. Anything else that is not
# green (RED, KILLED, an empty `.rc`) does — a second OOM kill decides nothing.
any_red() {
    local f
    for f in "$LOG_DIR"/*.rc; do
        [ -f "$f" ] || continue
        classify "$(basename "$f" .rc)"
        case "$CLS" in green|DISK|SKIP) ;; *) return 0 ;; esac
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
    # #1012 — the disk floor, per leg. Below it, DRAIN first: the prune deletes
    # artifacts, and an in-flight nextest re-execs its test binaries once per
    # test. Draining costs at most one leg's wall clock; pruning under a live
    # leg turns a disk problem into a red that names the tree.
    if [ "$(target_free_gb)" -lt "$MIN_FREE_GB" ] && [ "${#pids[@]}" -gt 0 ]; then
        echo "  .. disk below ${MIN_FREE_GB}G before '$job' — draining ${#pids[@]} in-flight leg(s) before any prune"
        for p in "${pids[@]}"; do wait "$p"; done
        pids=()
    fi
    if ! disk_guard "$job"; then
        printf '.' >&9
        continue
    fi
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
while read -r j; do
    [ -f "$LOG_DIR/$j.rc" ] || [ -f "$LOG_DIR/$j.disk" ] || MISSING="$MISSING $j"
done < "$LOG_DIR/queue"
if [ -n "$MISSING" ]; then
    echo; echo "!! JOBS THAT NEVER RAN:$MISSING"
    echo "   (not the same as red — the queue drained short. Counted NOTRUN below.)"
fi
print_verdict
