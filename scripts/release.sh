#!/usr/bin/env bash
# release.sh — one command from a finished CHANGELOG section to a pushed tag,
# with no agent in the loop between stages.
#
#   scripts/release.sh <version> [--pr-body FILE] [--merge-body FILE] [--subject TEXT] [--skip-codex]
#   scripts/release.sh --dry-run <version>
#
# Run from the release worktree, on the release branch, with the section
# `## [<version>] - UNRELEASED` written. Stages (docs/RELEASE.md has the why):
#
#   1 preflight   clean tree, branch is not `v<version>`, Cargo.toml at the
#                 previous section's version, the UNRELEASED header present
#   2 cheap       the five no-backend axes, the pyo3 lane, both clippy passes,
#                 pyi_surface — the legs certify most often goes red on late
#   3 bump        Cargo version, evidence/cc_impl.tsv re-stamp (count
#                 asserted), CHANGELOG date, `cargo check`, the release commit
#   4 pr          push the branch, open (or reuse) the PR
#   5 certify     `LANES=${LANES:-1} scripts/certify.sh full`
#   6 prci        wait for the PR's CI run green (auto-retry reruns respected)
#   7 codex       wait (CODEX_TIMEOUT_SECS, default 30 min) for Codex's review of
#                 HEAD; stop on any finding on HEAD; fail OPEN, loudly, if no
#                 review arrives. --skip-codex skips it (operator override)
#   8 ship        scripts/release_ship.sh → merge + tag, prints the tag run id
#   9 stop        print the scripts/release_finish.sh command
#
# RESUME: every completed stage writes `.release/<version>/<stage>.done`; a
# re-run skips it. Stages 2, 5, 6 and 7 record the commit they passed on, and
# count as done only while HEAD is still that commit — commit a fix after a
# red certify and re-run the same command: it re-checks, re-pushes,
# re-certifies and waits on the new run.
#
# Exit codes: 2 usage · 20 preflight · 21 cheap leg red · 22 bump · 23 push/PR ·
# 24 certify red · 25 PR CI red · 26 PR CI timeout · 27 ship (its own code is
# printed) · 28 tree dirty mid-release · 29 certify INFRA (no leg red, a leg
# lost to the machine — re-run) · 30 Codex left findings on HEAD (fix, commit,
# re-run). Each prints one line saying why.
#
# No `--no-verify` and no `--amend` anywhere: the hooks are the gate.
set -uo pipefail

usage() { sed -n '5,6p' "$0" | sed 's/^# *//'; exit 2; }
dry=0; ver=""; pr_body=""; merge_body=""; skip_codex=0
subject_override=""
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) dry=1;;
        --skip-codex) skip_codex=1;;
        --pr-body) pr_body="${2:?--pr-body FILE}"; shift;;
        --merge-body) merge_body="${2:?--merge-body FILE}"; shift;;
        --subject) subject_override="${2:?--subject TEXT}"; shift;;
        -h|--help) usage;;
        -*) echo "unknown flag $1"; usage;;
        *) [ -z "$ver" ] || usage; ver="$1";;
    esac
    shift
done
[ -n "$ver" ] || usage
[[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must be X.Y.Z: $ver"; exit 2; }
for f in "$pr_body" "$merge_body"; do
    [ -z "$f" ] || [ -f "$f" ] || { echo "no such file: $f"; exit 2; }
    [ -z "$f" ] || case "$f" in /*) ;; *) echo "pass body files as absolute paths: $f"; exit 2;; esac
done

cd "$(git rev-parse --show-toplevel)" || exit 2
# shellcheck source=scripts/release_lib.sh
. scripts/release_lib.sh

S=".release/$ver"
CO_AUTHOR="${RELEASE_CO_AUTHOR:-Claude Opus 5.5 <noreply@anthropic.com>}"
SESSION_URL="${RELEASE_SESSION_URL:-https://claude.ai/code/session_016kQb87339uTdFWivk3j2hF}"
prev="$(rl_prev_version CHANGELOG.md "$ver")"
branch="$(git rev-parse --abbrev-ref HEAD)"
cargo_ver="$(grep -m1 '^version = "' Cargo.toml | sed -E 's/version = "([^"]+)"/\1/')"
axes="$(python3 -c 'import sys; sys.path.insert(0, "scripts"); import ci_feature_matrix as m; print(" ".join(m.AXIS_LEGS))')" \
    || { echo "cannot read AXIS_LEGS from scripts/ci_feature_matrix.py"; exit 20; }
lint_set="$(python3 scripts/ci_feature_matrix.py set lint)" || { echo "cannot derive the lint feature set"; exit 20; }
# The commands stage 2 runs, one per line: <key> <command…>. Printed by
# --dry-run, run by stage 2, each with its own marker.
cheap_legs() {
    local a
    for a in $axes; do
        echo "axis-$a cargo check --all-targets --no-default-features --features $a"
    done
    echo "pyo3 cargo nextest run --features pyo3,sqlite -E test(/pyo3/)"
    echo "clippy-lint cargo clippy --features ${lint_set// /,} --all-targets -- -D warnings"
    echo "clippy-all cargo clippy --all-features --all-targets -- -D warnings"
    echo "pyi python3 scripts/pyi_surface.py check"
}

# ── 1. preflight ────────────────────────────────────────────────────────
preflight() {
    local why=""
    [ -z "$(git status --porcelain)" ] || why="dirty tree"
    [ "$branch" != "v$ver" ] || why="branch is named v$ver — the tag push would be ambiguous; rename it release-$ver"
    [ "$branch" != "main" ] && [ "$branch" != "HEAD" ] || why="on '$branch' — run from the release branch"
    [ -n "$prev" ] || why="CHANGELOG has no numbered section after [$ver]"
    grep -qxF "## [$ver] - UNRELEASED" CHANGELOG.md || why="CHANGELOG lacks the header '## [$ver] - UNRELEASED'"
    [ "$cargo_ver" = "$prev" ] || why="Cargo.toml is at $cargo_ver, expected the previous release $prev"
    git ls-remote --exit-code origin "refs/tags/v$ver" >/dev/null 2>&1 && why="tag v$ver already exists on origin"
    [ -z "$why" ] || { echo "PREFLIGHT: $why"; return 20; }
    echo "preflight: $prev → $ver on $branch"
}

if [ "$dry" -eq 1 ]; then
    rc=0
    if [ -d "$S" ] && rl_done "$S" bump; then echo "bump already done — preflight not re-run"; else preflight || rc=$?; fi
    echo "plan for v$ver (state dir $S):"
    for st in preflight cheap bump pr certify prci codex ship; do
        if rl_done "$S" "$st"; then echo "  $st: done ($(head -1 "$S/$st.done"))"; else echo "  $st: pending"; fi
    done
    echo "cheap legs (RUSTFLAGS from ci.yml):"; cheap_legs | sed 's/^/    /'
    echo "commit/merge subject: ${subject_override:-$(rl_subject CHANGELOG.md "$ver")}"
    echo "certify: LANES=${LANES:-1} scripts/certify.sh full"
    if [ "$skip_codex" -eq 1 ]; then echo "codex: SKIPPED (--skip-codex, operator override)"
    else echo "codex: wait up to $(( ${CODEX_TIMEOUT_SECS:-1800} / 60 )) min for $RL_CODEX_BOT's review of HEAD; exit 30 on any finding"; fi
    exit "$rc"
fi

mkdir -p "$S"
[ -z "$pr_body" ] || cp "$pr_body" "$S/pr_body.md"
[ -z "$merge_body" ] || cp "$merge_body" "$S/merge_body.md"
# .release/ is git-ignored, so the state dir never dirties the tree.
if ! rl_done "$S" preflight; then
    preflight || exit 20
    rl_mark "$S" preflight
elif [ -n "$(git status --porcelain)" ]; then
    echo "DIRTY TREE mid-release — commit or stash, then re-run"; git status --short; exit 28
fi

rustflags="$(rl_ci_rustflags)" || { echo "cannot derive RUSTFLAGS from ci.yml"; exit 21; }
export RUSTFLAGS="$rustflags"

# ── 2. cheap legs ───────────────────────────────────────────────────────
head_sha() { git rev-parse HEAD; }
cheap() {
    local key cmd rc
    while read -r key cmd; do
        if rl_done_at "$S" "cheap-$key" "$(head_sha)"; then echo "  $key: green at HEAD — skipped"; continue; fi
        echo "  $key: $cmd"
        # shellcheck disable=SC2086 # cmd is a word list on purpose
        $cmd > "$S/cheap-$key.log" 2>&1 < /dev/null; rc=$?
        [ "$rc" -eq 0 ] || { echo "CHEAP LEG RED: $key (exit $rc) — $S/cheap-$key.log"; tail -20 "$S/cheap-$key.log"; return 21; }
        rl_mark_at "$S" "cheap-$key" "$(head_sha)"
    done < <(cheap_legs)
}
if ! rl_done_at "$S" cheap "$(head_sha)"; then
    echo "--- stage cheap"; cheap || exit 21; rl_mark_at "$S" cheap "$(head_sha)"
fi

# ── 3. bump ─────────────────────────────────────────────────────────────
bump() {
    local today n
    if git log -1 --format=%s | grep -q "^release(v$ver):"; then echo "release commit already at HEAD"; return 0; fi
    today="$(date -u +%Y-%m-%d)"
    sed -i -E "0,/^version = \"${prev//./\\.}\"/s//version = \"$ver\"/" Cargo.toml
    [ "$(grep -m1 '^version = "' Cargo.toml)" = "version = \"$ver\"" ] || { echo "BUMP: Cargo.toml version not rewritten"; return 22; }
    n="$(rl_restamp_evidence evidence/cc_impl.tsv "$prev" "$ver")" || { echo "BUMP: $n"; return 22; }
    echo "evidence/cc_impl.tsv: $n pointers ciris-persist@$prev → @$ver"
    sed -i "s/^## \[$ver\] - UNRELEASED\$/## [$ver] - $today/" CHANGELOG.md
    grep -qxF "## [$ver] - $today" CHANGELOG.md || { echo "BUMP: CHANGELOG header not dated"; return 22; }
    cargo check --features sqlite < /dev/null > "$S/bump-check.log" 2>&1 || { echo "BUMP: cargo check --features sqlite red — $S/bump-check.log"; return 22; }
    cargo test --features sqlite --lib evidence_cc_impl < /dev/null > "$S/bump-evidence.log" 2>&1 \
        || { echo "BUMP: the evidence pin test is red — $S/bump-evidence.log"; return 22; }
    {
        echo "release(v$ver): version, evidence re-stamp — ${subject_override:-$(rl_subject CHANGELOG.md "$ver" 140)}" | sed 's/ — v[0-9.]* — / — /'
        echo
        echo "$(rl_section_headings CHANGELOG.md "$ver")"
        echo
        echo "Co-Authored-By: $CO_AUTHOR"
        echo "Claude-Session: $SESSION_URL"
    } > "$S/commit_msg.txt"
    git add Cargo.toml Cargo.lock CHANGELOG.md evidence/cc_impl.tsv
    git commit -q -F "$S/commit_msg.txt" || { echo "BUMP: git commit refused (a hook is red — read its output above)"; return 22; }
    echo "release commit $(git rev-parse --short HEAD)"
}
if ! rl_done "$S" bump; then
    echo "--- stage bump"
    bump || exit 22
    rl_mark "$S" bump
fi

# ── 4. push + PR ────────────────────────────────────────────────────────
repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)" || { echo "cannot resolve the GitHub repo"; exit 23; }
subject="${subject_override:-$(rl_subject CHANGELOG.md "$ver")}"
pr_stage() {
    local pr remote
    remote="$(git ls-remote origin "refs/heads/$branch" | cut -f1)"
    if [ "$remote" != "$(head_sha)" ]; then
        git push -u origin "HEAD:refs/heads/$branch" || { echo "PUSH refused (pre-push hook or remote) — read the output above"; return 23; }
    fi
    pr="$(rl_get "$S" pr)"
    if [ -z "$pr" ]; then
        pr="$(gh api "repos/$repo/pulls?head=${repo%%/*}:$branch&state=open" --jq '.[0].number // empty')"
    fi
    if [ -z "$pr" ]; then
        [ -f "$S/pr_body.md" ] || rl_changelog_section CHANGELOG.md "$ver" > "$S/pr_body.md"
        # REST, not `gh pr create`/`gh pr edit`: those select Projects-classic
        # fields over GraphQL, which error on this repo.
        pr="$(gh api -X POST "repos/$repo/pulls" -f title="$subject" -f head="$branch" -f base=main -F body=@"$S/pr_body.md" --jq .number)" \
            || { echo "PR create failed"; return 23; }
    fi
    rl_put "$S" pr "$pr"
    echo "PR #$pr at $(git rev-parse --short HEAD)"
}
echo "--- stage pr"; pr_stage || exit 23
pr="$(rl_get "$S" pr)"

# ── 5. certify ──────────────────────────────────────────────────────────
certify() {
    local rc
    echo "LANES=${LANES:-1} scripts/certify.sh full → $S/certify.log"
    LANES="${LANES:-1}" scripts/certify.sh full < /dev/null > "$S/certify.log" 2>&1; rc=$?
    tail -45 "$S/certify.log"
    # Exit 3 (ci-local-gates): no leg RED, but a leg was lost to the machine
    # (disk floor, a signal, an empty .rc, never ran). The tree is unjudged.
    [ "$rc" -eq 3 ] && { echo "CERTIFY INFRA (exit 3): a leg was lost to the machine, the tree is unjudged — free disk/RAM (or lower LANES) and re-run"; return 29; }
    # Exit code AND the verdict line: a skipped python leg exits 0 without it.
    [ "$rc" -eq 0 ] && grep -qx "EVERY CI LEG GREEN BY EXIT CODE. Logs in .*" "$S/certify.log" \
        || { echo "CERTIFY NOT GREEN (exit $rc) — $S/certify.log"; return 24; }
}
if ! rl_done_at "$S" certify "$(head_sha)"; then
    echo "--- stage certify"; certify; rc=$?; [ "$rc" -eq 0 ] || exit "$rc"; rl_mark_at "$S" certify "$(head_sha)"
fi

# ── 6. PR CI ────────────────────────────────────────────────────────────
prci() {
    local head limit waited=0 run st attempt grace ended retry
    head="$(head_sha)"; limit=$(( ${PRCI_TIMEOUT_MIN:-180} * 60 ))
    while [ "$waited" -lt "$limit" ]; do
        run="$(gh run list --commit "$head" --event pull_request --workflow ci.yml --json databaseId --jq '.[0].databaseId // empty' 2>/dev/null)"
        if [ -z "$run" ]; then echo "PR CI on ${head:0:7}: no run yet"; sleep 60; waited=$(( waited + 60 )); continue; fi
        st="$(gh run view "$run" --json status,conclusion --jq '"\(.status)/\(.conclusion)"' 2>/dev/null || echo unknown)"
        echo "PR CI run $run: $st ($(( waited / 60 )) min)"
        case "$st" in
            completed/success) return 0;;
            completed/*)
                # auto-retry.yml re-runs a first-attempt failure with an infra
                # signature. Final only once the run is on attempt >1, or an
                # auto-retry run that started after this one ended has finished
                # without re-running it, or 15 min have passed.
                attempt="$(gh api "repos/$repo/actions/runs/$run" --jq .run_attempt 2>/dev/null || echo 1)"
                ended="$(gh run view "$run" --json updatedAt --jq .updatedAt 2>/dev/null)"
                grace=0
                while [ "$grace" -lt 900 ]; do
                    st="$(gh run view "$run" --json status,conclusion --jq '"\(.status)/\(.conclusion)"' 2>/dev/null || echo unknown)"
                    case "$st" in completed/success) return 0;; completed/*) ;; *) echo "PR CI run $run re-running ($st)"; break;; esac
                    [ "$attempt" -gt 1 ] && break
                    retry="$(gh run list --workflow auto-retry.yml -L 20 --json status,createdAt \
                        --jq "[.[] | select(.createdAt >= \"$ended\" and .status == \"completed\")] | length" 2>/dev/null || echo 0)"
                    [ "$retry" -gt 0 ] && break
                    sleep 60; grace=$(( grace + 60 ))
                done
                case "$st" in completed/*) echo "PR CI NOT GREEN: run $run $st (attempt $attempt) — fix, commit, re-run release.sh"; return 25;; esac;;
        esac
        sleep 60; waited=$(( waited + 60 ))
    done
    echo "PR CI timeout after ${PRCI_TIMEOUT_MIN:-180} min — re-run release.sh to keep waiting"; return 26
}
if ! rl_done_at "$S" prci "$(head_sha)"; then
    echo "--- stage prci"; prci; rc=$?; [ "$rc" -eq 0 ] || exit "$rc"; rl_mark_at "$S" prci "$(head_sha)"
fi

# ── 7. Codex review ─────────────────────────────────────────────────────
# Never ship over Codex findings on HEAD. A review keyed to an older head does
# not count, and the stage is done only while HEAD is the sha it passed on.
if [ "$skip_codex" -eq 1 ]; then
    echo "!!! CODEX REVIEW SKIPPED (--skip-codex, operator override) — shipping PR #$pr without waiting for or reading Codex's review of $(git rev-parse --short HEAD) !!!"
elif ! rl_done_at "$S" codex "$(head_sha)"; then
    echo "--- stage codex"
    rl_codex_review "$repo" "$pr" "$(head_sha)"; rc=$?
    case "$rc" in
        0) ;;
        30) exit 30;;
        31) echo "::warning::Codex review did not arrive; shipping without it (no review of $(git rev-parse --short HEAD) by $RL_CODEX_BOT in $(( ${CODEX_TIMEOUT_SECS:-1800} / 60 )) min)";;
        *) echo "codex stage: unexpected exit $rc — refusing to ship"; exit 30;;
    esac
    rl_mark_at "$S" codex "$(head_sha)"
fi

# ── 8. ship ─────────────────────────────────────────────────────────────
if ! rl_done "$S" ship; then
    echo "--- stage ship"
    [ -f "$S/merge_body.md" ] || rl_changelog_section CHANGELOG.md "$ver" > "$S/merge_body.md"
    scripts/release_ship.sh "$pr" "$ver" "$(git rev-parse --short=7 HEAD)" "$subject" "$PWD/$S/merge_body.md" 2>&1 | tee "$S/ship.log"
    rc="${PIPESTATUS[0]}"
    [ "$rc" -eq 0 ] || { echo "SHIP FAILED: release_ship.sh exit $rc — see its header for the code; $S/ship.log"; exit 27; }
    rl_put "$S" tag_run "$(sed -n 's/^TAG_RUN_ID=//p' "$S/ship.log" | tail -1)"
    rl_mark "$S" ship
fi

# ── 9. stop ─────────────────────────────────────────────────────────────
echo "=== RELEASE_TAGGED v$ver — tag CI run $(rl_get "$S" tag_run) ==="
echo "finish with:  scripts/release_finish.sh $ver $(rl_get "$S" tag_run)"
