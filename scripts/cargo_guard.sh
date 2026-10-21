#!/usr/bin/env bash
# cargo_guard.sh — run cargo (or nextest/maturin) inside a memory-capped
# cgroup, at most CARGO_GUARD_SLOTS at a time on this box, only when enough
# RAM is free.
#
#   scripts/cargo_guard.sh cargo nextest run --features sqlite ...
#   scripts/cargo_guard.sh maturin develop --release
#
# Why: four sessions on the shared 31 GB box were OOM-killed by the kernel
# while two or three agents compiled this crate at once. The kernel's OOM
# killer took the terminal scope (every agent in it), not the cargo that
# grew. This wrapper makes a stray cargo the thing that dies instead:
#
#   1. SLOTS  — CARGO_GUARD_SLOTS builds at a time (default 1): `flock` on
#               $CARGO_GUARD_LOCK (slot 0, the pre-slot path every older
#               checkout of this script still takes, so old and new guards
#               contend on the same file) and $CARGO_GUARD_LOCK.<n> for
#               n in 1..SLOTS-1 (default /tmp/cargo_guard.lock; shared by
#               every user session on the box, Edge included). Polls for a free slot up to
#               CARGO_GUARD_WAIT_SECS (default 3600), then exits 75.
#   2. FLOOR  — refuses to start while `free -g` "available" is below
#               CARGO_GUARD_FLOOR_GB (default 8); polls every 20 s up to the
#               same wait, then exits 76. The slot is held while polling so
#               a second guard does not race into the same headroom.
#   3. CAP    — runs the command in a transient systemd user scope with
#               MemoryMax=$CARGO_GUARD_MAX_GB (default 14 with one slot,
#               11 with two, 7 with three), MemoryHigh one GB below it (the
#               kernel throttles and reclaims before it kills), no swap, and
#               memory.oom.group=1 so an OOM kills the WHOLE build (exit 137
#               / "Killed") instead of one rustc, and the session that
#               launched it survives. Falls back to no cap (with a warning)
#               when systemd-run is not usable.
#   4. JOBS   — exports CARGO_BUILD_JOBS and NEXTEST_TEST_THREADS unless
#               already set: 4 with one slot, 2 with two or more.
#   5. STATS  — a sampler (scripts/cgroup_mem_sampler.sh) watches the scope
#               and appends its peak ANONYMOUS memory (the part that OOMs;
#               memory.peak also counts reclaimable page cache) to
#               $CARGO_GUARD_STATS (default ~/.cache/cargo_guard_stats.log).
#               Size the caps from that log, not from memory.peak.
#
# Exit codes: 75 slot wait exceeded · 76 memory floor never met · 77 usage ·
# otherwise the wrapped command's own code (137 = OOM-killed in its scope).
set -uo pipefail
[ $# -ge 1 ] || { echo "usage: $0 <cargo|maturin|...> args..." >&2; exit 77; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lock="${CARGO_GUARD_LOCK:-/tmp/cargo_guard.lock}"
wait_secs="${CARGO_GUARD_WAIT_SECS:-3600}"
floor_gb="${CARGO_GUARD_FLOOR_GB:-8}"
slots="${CARGO_GUARD_SLOTS:-1}"
case "$slots" in 1) dmax=14; djobs=4;; 2) dmax=11; djobs=2;; *) dmax=7; djobs=2;; esac
max_gb="${CARGO_GUARD_MAX_GB:-$dmax}"
high_gb=$(( max_gb > 2 ? max_gb - 1 : max_gb ))
stats="${CARGO_GUARD_STATS:-$HOME/.cache/cargo_guard_stats.log}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$djobs}"
export NEXTEST_TEST_THREADS="${NEXTEST_TEST_THREADS:-$djobs}"
avail_gb() { free -g | awk '/^Mem:/ {print $7}'; }
# 1. SLOTS — take the first free slot; poll until one frees or the wait ends.
t0=$(date +%s); slot=""
while [ -z "$slot" ]; do
    for ((n=0; n<slots; n++)); do
        f="$lock"; [ "$n" -gt 0 ] && f="$lock.$n"
        exec 9>"$f" || { echo "cargo_guard: cannot open lock $f" >&2; exit 77; }
        if flock -n 9; then slot=$n; break; fi
        exec 9>&-
    done
    [ -n "$slot" ] && break
    if [ $(( $(date +%s) - t0 )) -ge "$wait_secs" ]; then
        echo "cargo_guard: all $slots slots held for ${wait_secs}s; giving up (75)" >&2; exit 75
    fi
    sleep 5
done
# 2. FLOOR
while [ "$(avail_gb)" -lt "$floor_gb" ]; do
    if [ $(( $(date +%s) - t0 )) -ge "$wait_secs" ]; then
        echo "cargo_guard: available RAM stayed below ${floor_gb} GB for ${wait_secs}s; giving up (76)" >&2; exit 76
    fi
    sleep 20
done
echo "cargo_guard: slot $slot/$slots, $(avail_gb) GB available, cap ${max_gb} GB (high ${high_gb}), jobs $CARGO_BUILD_JOBS, threads $NEXTEST_TEST_THREADS: $*" >&2
if command -v systemd-run >/dev/null 2>&1 \
   && systemd-run --user --scope -q -p MemoryMax=1M true >/dev/null 2>&1; then
    unit="cargo-guard-$$-$(date +%s)"
    # 5. The scope exists only once systemd-run starts it; a detached helper
    # waits for it and samples until it vanishes.
    (
        cg="/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/app.slice/$unit.scope"
        for _ in $(seq 1 50); do [ -d "$cg" ] && break; sleep 0.2; done
        [ -d "$cg" ] || exit 0
        mkdir -p "$(dirname "$stats")"
        exec "$here/cgroup_mem_sampler.sh" "$cg" "$stats" 2
    ) </dev/null >/dev/null 2>&1 &
    disown 2>/dev/null || true
    # 3. memory.oom.group is set from INSIDE the scope, before the command
    # starts, so there is no window in which a fast allocator can be killed
    # alone and leave its siblings running.
    exec systemd-run --user --scope -q --unit="$unit" \
        -p "MemoryMax=${max_gb}G" -p "MemoryHigh=${high_gb}G" -p MemorySwapMax=0 \
        --setenv=CARGO_BUILD_JOBS --setenv=NEXTEST_TEST_THREADS \
        bash -c 'echo 1 > "/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)/memory.oom.group" 2>/dev/null; exec "$@"' cargo_guard "$@"
else
    echo "cargo_guard: systemd-run unavailable; running WITHOUT a memory cap" >&2
    exec "$@"
fi
