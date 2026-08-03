#!/usr/bin/env bash
# reap_worktree_targets.sh — reclaim `target/` from FINISHED worktrees.
#
# ── WHY ──────────────────────────────────────────────────────────────────
# Parallel agents each get a git worktree, and each worktree grows its own
# `target/` — ~20G apiece. Nine of them fills a 935G disk. That has already
# happened twice: once it killed a running build, and 203G then 211G had to
# be reclaimed by hand. The mode is quiet as well as expensive — task output
# capture shares the same filesystem, so a full disk makes an agent's output
# look EMPTY rather than failed. A silent failure is the worst kind.
#
# ── WHAT IT DELETES ──────────────────────────────────────────────────────
# Exactly one thing, and only inside a LINKED git worktree:
#
#     <worktree>/target/
#
# Nothing else. Never source, never the worktree itself, never `.git`, never
# a stash, never a branch, never anything in the main checkout. `target/` is
# pure build cache: the entire cost of a mistake here is one rebuild.
#
# ── WHAT IT WILL NOT TOUCH ───────────────────────────────────────────────
# A worktree is reaped only if EVERY rule below holds. Any single failure
# skips it. The rules are mechanical — none of them is a judgement call:
#
#   1. LINKED worktree only. The main checkout is never reaped; it is the
#      shared working area and is always considered live.
#   2. NOT LOCKED. `git worktree lock` is how an active agent claims its
#      tree. A locked worktree is live by declaration.
#   3. MERGED. HEAD must be an ancestor of the integration ref (default
#      `origin/main`) — i.e. the worktree holds no commit that is not
#      already integrated. An unmerged branch is unfinished work.
#   4. CLEAN. `git status --porcelain` must be empty. Untracked files count
#      as dirty: an agent's un-added new file is work, and it is
#      indistinguishable from one.
#   5. NOBODY HOME. No running process may have its cwd inside the
#      worktree, and no process command line may reference it.
#   6. COLD. `target/` must not have been modified within --min-age-minutes
#      (default 60). A build that is between phases is still a build.
#
# Rules 3 and 4 protect work. Rules 1, 2, 5 and 6 protect time.
#
# ── USE ──────────────────────────────────────────────────────────────────
#   scripts/reap_worktree_targets.sh                 # DRY RUN (default)
#   scripts/reap_worktree_targets.sh --apply         # actually delete
#   scripts/reap_worktree_targets.sh --apply --min-age-minutes 180
#   scripts/reap_worktree_targets.sh --base origin/main
#
# The default is a dry run on purpose: it prints the verdict and the reason
# for every worktree, so what it would delete is reviewable before it does.
# Exit status: 0 on success (including "nothing to reap"), 1 on a bad
# argument or a failed delete.

set -uo pipefail

APPLY=0
MIN_AGE_MINUTES=60
BASE_REF="origin/main"

while [ $# -gt 0 ]; do
    case "$1" in
        --apply)             APPLY=1; shift ;;
        --min-age-minutes)   MIN_AGE_MINUTES="${2:-}"; shift 2 ;;
        --base)              BASE_REF="${2:-}"; shift 2 ;;
        -h|--help)           sed -n '2,52p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1 (try --help)" >&2; exit 1 ;;
    esac
done

if ! printf '%s' "$MIN_AGE_MINUTES" | grep -qE '^[0-9]+$'; then
    echo "--min-age-minutes must be a non-negative integer" >&2
    exit 1
fi

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "not inside a git repository" >&2
    exit 1
fi

if ! BASE_SHA="$(git rev-parse --verify --quiet "${BASE_REF}^{commit}")"; then
    echo "cannot resolve --base '$BASE_REF' — fetch it first (e.g. git fetch origin)" >&2
    exit 1
fi

MAIN_WT="$(git worktree list --porcelain | awk '/^worktree /{print $2; exit}')"

# ── which paths are somebody's home right now ────────────────────────────
# Two independent signals, because either alone has a blind spot: a cargo
# process started elsewhere may hold the worktree only in its argv, and a
# shell sitting in the directory may have no argv mention of it at all.
live_paths_file="$(mktemp)"
trap 'rm -f "$live_paths_file"' EXIT
for cwdlink in /proc/[0-9]*/cwd; do
    target="$(readlink "$cwdlink" 2>/dev/null)" || continue
    [ -n "$target" ] && printf '%s\n' "$target"
done > "$live_paths_file" 2>/dev/null
cmdlines_file="$(mktemp)"
trap 'rm -f "$live_paths_file" "$cmdlines_file"' EXIT
for c in /proc/[0-9]*/cmdline; do
    tr '\0' ' ' < "$c" 2>/dev/null; printf '\n'
done > "$cmdlines_file" 2>/dev/null

is_live() {  # $1 = worktree path
    grep -qF -- "$1" "$live_paths_file" && return 0
    grep -qF -- "$1" "$cmdlines_file" && return 0
    return 1
}

human() {  # $1 = size in MiB
    if [ "$1" -ge 1024 ]; then
        awk -v m="$1" 'BEGIN{printf "%.1fG", m/1024}'
    else
        printf '%dM' "$1"
    fi
}

# ── walk the worktrees ───────────────────────────────────────────────────
total_reclaimable_mb=0
total_reaped_mb=0
n_reap=0
n_skip=0

printf '%s\n' "reaper: base=$BASE_REF ($(git rev-parse --short "$BASE_SHA"))  min-age=${MIN_AGE_MINUTES}m  mode=$([ "$APPLY" -eq 1 ] && echo APPLY || echo 'DRY RUN')"
printf '%s\n' "----------------------------------------------------------------------"

# `git worktree list --porcelain` emits one field per line, records separated
# by a blank line. Parsed linearly: a `worktree ` line opens a new record, so
# the previous one is flushed first. A trailing sentinel flushes the last.
wt=""; head_sha=""; locked=0; branch=""

flush_record() {
    [ -n "$wt" ] || return 0

    local label skip size_mb
    label="${branch:-(unknown)}"
    skip=""

    if [ "$wt" = "$MAIN_WT" ]; then
        skip="main checkout (never reaped)"
    elif [ ! -d "$wt" ]; then
        skip="worktree path missing (run: git worktree prune)"
    elif [ "$locked" -eq 1 ]; then
        skip="LOCKED — an agent has claimed it"
    elif [ ! -d "$wt/target" ]; then
        skip="no target/ — nothing to reclaim"
    elif [ -z "$head_sha" ]; then
        skip="no resolvable HEAD"
    elif ! git merge-base --is-ancestor "$head_sha" "$BASE_SHA" 2>/dev/null; then
        skip="UNMERGED — HEAD is not an ancestor of $BASE_REF"
    elif [ -n "$(git -C "$wt" status --porcelain 2>/dev/null)" ]; then
        skip="DIRTY — uncommitted or untracked files present"
    elif is_live "$wt"; then
        skip="LIVE — a running process is in or refers to it"
    elif [ -n "$(find "$wt/target" -maxdepth 1 -newermt "-${MIN_AGE_MINUTES} minutes" -print -quit 2>/dev/null)" ]; then
        skip="WARM — target/ touched within ${MIN_AGE_MINUTES}m"
    fi

    if [ -n "$skip" ]; then
        n_skip=$((n_skip + 1))
        printf 'SKIP  %-34s %s\n' "$label" "$skip"
        return 0
    fi

    size_mb="$(du -sm "$wt/target" 2>/dev/null | awk '{print $1}')"
    size_mb="${size_mb:-0}"
    total_reclaimable_mb=$((total_reclaimable_mb + size_mb))
    n_reap=$((n_reap + 1))

    if [ "$APPLY" -eq 1 ]; then
        if rm -rf -- "$wt/target"; then
            total_reaped_mb=$((total_reaped_mb + size_mb))
            printf 'REAP  %-34s %s freed  (%s)\n' "$label" "$(human "$size_mb")" "$wt/target"
        else
            printf 'ERROR %-34s failed to remove %s\n' "$label" "$wt/target" >&2
            REAP_FAILED=1
        fi
    else
        printf 'WOULD %-34s %s reclaimable  (%s)\n' "$label" "$(human "$size_mb")" "$wt/target"
    fi
}

REAP_FAILED=0
while IFS= read -r line; do
    case "$line" in
        worktree\ *)
            flush_record
            wt="${line#worktree }"; head_sha=""; locked=0; branch=""
            ;;
        HEAD\ *)   head_sha="${line#HEAD }" ;;
        branch\ *) branch="${line#branch refs/heads/}" ;;
        locked*)   locked=1 ;;
        detached)  branch="(detached)" ;;
    esac
done < <(git worktree list --porcelain)
flush_record

printf '%s\n' "----------------------------------------------------------------------"
if [ "$APPLY" -eq 1 ]; then
    printf 'reaped %d worktree target/ dirs, %s freed; %d skipped.\n' \
        "$n_reap" "$(human "$total_reaped_mb")" "$n_skip"
else
    printf '%d reapable (%s reclaimable), %d skipped. Nothing was deleted — re-run with --apply.\n' \
        "$n_reap" "$(human "$total_reclaimable_mb")" "$n_skip"
fi
df -h "$MAIN_WT" | awk 'NR==2{printf "disk: %s used of %s (%s), %s available\n", $3, $2, $5, $4}'
exit "$REAP_FAILED"
