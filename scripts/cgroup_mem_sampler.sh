#!/usr/bin/env bash
# cgroup_mem_sampler.sh <cgroup-dir> <out-log> [interval-secs]
# Samples a cgroup v2 memory.stat until the cgroup vanishes; appends one
# summary line (peak anon, peak file, peak current, oom events) to <out-log>.
# Used by cargo_guard.sh to learn the real (anonymous) peak of a build, since
# memory.peak counts reclaimable page cache too.
set -u
cg="$1"; out="$2"; iv="${3:-2}"
pa=0; pf=0; pc=0; t0=$(date +%s)
while [ -d "$cg" ]; do
    a=$(awk '$1=="anon"{print $2}' "$cg/memory.stat" 2>/dev/null) || break
    f=$(awk '$1=="file"{print $2}' "$cg/memory.stat" 2>/dev/null) || break
    c=$(cat "$cg/memory.current" 2>/dev/null) || break
    [ -n "$a" ] || break
    [ "$a" -gt "$pa" ] && pa=$a; [ "$f" -gt "$pf" ] && pf=$f; [ "$c" -gt "$pc" ] && pc=$c
    ev=$(awk '$1=="max"||$1=="oom_kill"{printf "%s=%s ",$1,$2}' "$cg/memory.events" 2>/dev/null)
    sleep "$iv"
done
printf '%s scope=%s secs=%d peak_anon=%dM peak_file=%dM peak_current=%dM %s\n' \
    "$(date -u +%FT%TZ)" "$(basename "$cg")" $(( $(date +%s) - t0 )) \
    $((pa/1048576)) $((pf/1048576)) $((pc/1048576)) "${ev:-}" >> "$out"
