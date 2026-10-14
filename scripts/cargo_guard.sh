#!/usr/bin/env bash
# cargo_guard.sh — run ONE cargo (or nextest/maturin) at a time on this box,
# inside a memory-capped cgroup, only when enough RAM is free.
#
#   scripts/cargo_guard.sh cargo nextest run --features sqlite ...
#   scripts/cargo_guard.sh maturin develop --release
#
# Why: four sessions on the shared 31 GB box were OOM-killed by the kernel
# while two or three agents compiled this crate at once. The kernel's OOM
# killer took the terminal scope (every agent in it), not the cargo that
# grew. This wrapper makes a stray cargo the thing that dies instead:
#
#   1. LOCK   — one build at a time: `flock` on $CARGO_GUARD_LOCK
#               (default /tmp/cargo_guard.lock; shared by every user session
#               on the box, Edge included). Waits up to CARGO_GUARD_WAIT_SECS
#               (default 3600) for the lock, then exits 75.
#   2. FLOOR  — refuses to start while `free -g` "available" is below
#               CARGO_GUARD_FLOOR_GB (default 8); polls every 20 s up to the
#               same wait, then exits 76. The lock is held while polling so
#               a second guard does not race into the same headroom.
#   3. CAP    — runs the command in a transient systemd user scope with
#               MemoryMax=$CARGO_GUARD_MAX_GB (default 14) and no swap, so
#               a runaway build is OOM-killed INSIDE its scope (exit 137 /
#               "Killed") and the session that launched it survives.
#               Falls back to no cap (with a warning) when systemd-run is
#               not usable.
#   4. JOBS   — exports CARGO_BUILD_JOBS (default 4) and NEXTEST_TEST_THREADS
#               (default 4) unless already set, the budget that fit beside
#               one other agent.
#
# Exit codes: 75 lock wait exceeded · 76 memory floor never met · 77 usage ·
# otherwise the wrapped command's own code (137 = OOM-killed in its scope).
set -uo pipefail
[ $# -ge 1 ] || { echo "usage: $0 <cargo|maturin|...> args..." >&2; exit 77; }
lock="${CARGO_GUARD_LOCK:-/tmp/cargo_guard.lock}"
wait_secs="${CARGO_GUARD_WAIT_SECS:-3600}"
floor_gb="${CARGO_GUARD_FLOOR_GB:-8}"
max_gb="${CARGO_GUARD_MAX_GB:-14}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
export NEXTEST_TEST_THREADS="${NEXTEST_TEST_THREADS:-4}"
avail_gb() { free -g | awk '/^Mem:/ {print $7}'; }
exec 9>"$lock" || { echo "cargo_guard: cannot open lock $lock" >&2; exit 77; }
if ! flock -w "$wait_secs" 9; then
    echo "cargo_guard: another build held $lock for ${wait_secs}s; giving up (75)" >&2; exit 75
fi
t0=$(date +%s)
while [ "$(avail_gb)" -lt "$floor_gb" ]; do
    if [ $(( $(date +%s) - t0 )) -ge "$wait_secs" ]; then
        echo "cargo_guard: available RAM stayed below ${floor_gb} GB for ${wait_secs}s; giving up (76)" >&2; exit 76
    fi
    sleep 20
done
echo "cargo_guard: lock held, $(avail_gb) GB available, cap ${max_gb} GB, jobs $CARGO_BUILD_JOBS, threads $NEXTEST_TEST_THREADS: $*" >&2
if command -v systemd-run >/dev/null 2>&1 \
   && systemd-run --user --scope -q -p MemoryMax=1M true >/dev/null 2>&1; then
    exec systemd-run --user --scope -q \
        -p "MemoryMax=${max_gb}G" -p MemorySwapMax=0 \
        --setenv=CARGO_BUILD_JOBS --setenv=NEXTEST_TEST_THREADS \
        "$@"
else
    echo "cargo_guard: systemd-run unavailable; running WITHOUT a memory cap" >&2
    exec "$@"
fi
