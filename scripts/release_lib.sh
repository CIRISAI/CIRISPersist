# release_lib.sh — functions shared by release.sh, release_ship.sh,
# release_finish.sh and release_selftest.sh. Sourced, never executed.
#
# Kept in one place so the CHANGELOG section that becomes the PR body, the
# tag annotation and the release body is cut by ONE function, and so the
# self-test exercises the code the release runs rather than a copy of it.

# rl_prev_version <changelog> <version> — the numbered section after
# [<version>], i.e. where <version>'s section ends. Prints nothing if absent.
# The awk reads to EOF rather than exiting on the first hit: under `pipefail`
# an early-exiting reader SIGPIPEs its writer and fails the pipeline.
rl_prev_version() {
    grep -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' "$1" | sed 's/^## \[//; s/\]//' \
        | RL_V="$2" awk '$0==ENVIRON["RL_V"] {f=1; next} f && !p {print; p=1}'
}

# rl_changelog_section <changelog> <version> — the section for <version>,
# from its `## [<version>]` heading up to (not including) the next numbered
# section's heading. Returns 1 if the section is missing or empty.
#
# Headings are matched as FIXED-STRING prefixes (`index(...) == 1`), passed
# through ENVIRON, never as regex text through `awk -v`: gawk and busybox awk
# process backslash escapes in `-v` values, so `\[` arrived as a bare `[`, the
# pattern became a character class, nothing matched, and the cut came back
# EMPTY with exit 0 (mawk keeps the backslash, so it was green here; Codex on
# PR #1039). The output-is-empty check makes any such regression a refusal.
rl_changelog_section() {
    local file="$1" ver="$2" prev
    prev="$(rl_prev_version "$file" "$ver")"
    [ -n "$prev" ] || return 1
    RL_S="## [$ver]" RL_E="## [$prev]" awk '
        !f && index($0, ENVIRON["RL_S"]) == 1 {f=1}
        f && index($0, ENVIRON["RL_E"]) == 1 {exit}
        f {print; n++}
        END {exit (n > 0 ? 0 : 1)}' "$file"
}

# rl_section_headings <changelog> <version> — the `### ` heading lines of the
# section, joined with "; " and stripped of their `### ` prefix and their
# "Added — " / "Fixed — " kind. The commit and merge subjects are built from it.
rl_section_headings() {
    rl_changelog_section "$1" "$2" | grep -E '^### ' \
        | sed -E 's/^### +//; s/^[A-Za-z]+ — //' | paste -sd ';' - | sed 's/;/; /g'
}

# rl_subject <changelog> <version> [max] — "v<ver> — <headings>" capped for a
# commit/PR subject. Headings are joined until the cap (default 180 chars)
# would be crossed; the rest become "; +N more". The full list lives in the
# PR and merge bodies (the CHANGELOG section), never only in the subject.
# v53.2.0: 16 headings made a 1,200-char subject on the first dry-run.
rl_subject() {
    local cl="$1" ver="$2" max="${3:-180}" out="v$2 — " n=0 kept=0 h
    local -a hs=()
    while IFS= read -r h; do hs+=("$h"); done < <(rl_changelog_section "$cl" "$ver" | grep -E '^### ' | sed -E 's/^### +//; s/^[A-Za-z]+ — //')
    n=${#hs[@]}
    for h in "${hs[@]}"; do
        if [ "$kept" -gt 0 ] && [ $(( ${#out} + ${#h} + 2 )) -gt "$max" ]; then break; fi
        [ "$kept" -gt 0 ] && out="$out; "
        out="$out$h"; kept=$((kept+1))
    done
    [ "$kept" -lt "$n" ] && out="$out; +$((n-kept)) more"
    printf '%s\n' "$out"
}

# rl_restamp_evidence <tsv> <prev> <version> — rewrite every
# `ciris-persist@<prev>` pointer to `@<version>` (a version bump re-stamps the
# evidence pin; supersets.rs::evidence_cc_impl_rows_pin_the_current_crate_version
# is the gate). `@<prev>` must not match a longer version (53.1.8 vs
# 53.1.80). Prints the count; returns 1 if there was nothing to re-stamp or
# the count after differs from the count before.
rl_restamp_evidence() {
    local tsv="$1" p v n_before n_after n_left
    p="$(printf '%s' "$2" | sed 's/\./\\./g')"; v="$(printf '%s' "$3" | sed 's/\./\\./g')"
    n_before="$(grep -oE "ciris-persist@${p}([^0-9.]|\$)" "$tsv" | wc -l)"
    n_after="$(grep -oE "ciris-persist@${v}([^0-9.]|\$)" "$tsv" | wc -l)"
    [ "$n_before" -gt 0 ] || { echo "no ciris-persist@$2 pointers in $tsv"; return 1; }
    sed -i -E "s/ciris-persist@${p}([^0-9.]|\$)/ciris-persist@$3\\1/g" "$tsv"
    n_left="$(grep -oE "ciris-persist@${p}([^0-9.]|\$)" "$tsv" | wc -l)"
    n_after=$(( $(grep -oE "ciris-persist@${v}([^0-9.]|\$)" "$tsv" | wc -l) - n_after ))
    [ "$n_after" -eq "$n_before" ] && [ "$n_left" -eq 0 ] \
        || { echo "re-stamped $n_after of $n_before ciris-persist@$2 pointers ($n_left left)"; return 1; }
    echo "$n_before"
}

# ── stage state ─────────────────────────────────────────────────────────
# One marker file per completed stage under <state-dir>. A stage that has a
# marker is skipped on a re-run; a stage is marked only after its body
# returned 0. Values a later stage needs (the PR number, the head sha) are
# kept as files beside the markers.

rl_done() { [ -f "$1/$2.done" ]; }
rl_mark() { date -u +%Y-%m-%dT%H:%M:%SZ > "$1/$2.done"; }
rl_put() { printf '%s\n' "$3" > "$1/$2"; }
rl_get() { [ -f "$1/$2" ] && cat "$1/$2"; }

# A stage that certifies a COMMIT (cheap legs, certify, PR CI) records the
# sha it passed on, and is done only while that sha is still HEAD.
# rl_resume_check <state-dir> <version> <branch>: resumed state must belong to
# THIS attempt (Codex round 2 on PR #1039). Preflight records the branch and
# bump records the release commit; on every resume the branch must match, and
# once bumped, the release commit must be in HEAD's history, Cargo.toml must be
# at <version> and the CHANGELOG header dated. Exit 32 with one line of reason
# and how to clear; 0 (with a line naming the binding) otherwise, or when no
# stage has completed yet.
rl_resume_check() {
    local S="$1" ver="$2" branch="$3" want sha cv
    [ -f "$S/preflight.done" ] || return 0
    want="$(rl_get "$S" branch)"
    if [ -z "$want" ]; then
        echo "RESUME: $S records no branch (state from before the binding, or hand-made) — if it is this attempt's, bind it: echo $branch > $S/branch$([ -f "$S/bump.done" ] && echo "; git rev-parse <release commit> > $S/bump_sha"); else clear it: rm -rf $S"
        return 32
    fi
    [ "$want" = "$branch" ] || { echo "RESUME: $S belongs to branch '$want', not '$branch' — switch back to '$want', or clear it: rm -rf $S"; return 32; }
    if [ -f "$S/bump.done" ]; then
        sha="$(rl_get "$S" bump_sha)"
        [ -n "$sha" ] || { echo "RESUME: bump is marked done in $S but no release commit is recorded — if HEAD's history has it, bind it: git rev-parse <release commit> > $S/bump_sha; else clear it: rm -rf $S"; return 32; }
        git merge-base --is-ancestor "$sha" HEAD 2>/dev/null \
            || { echo "RESUME: the release commit ${sha:0:12} recorded in $S is not an ancestor of HEAD (reset, rebased or another attempt) — clear it: rm -rf $S"; return 32; }
        cv="$(grep -m1 '^version = "' Cargo.toml | sed -E 's/version = "([^"]+)"/\1/')"
        [ "$cv" = "$ver" ] || { echo "RESUME: bump is done in $S but Cargo.toml is at $cv, not $ver — clear it: rm -rf $S"; return 32; }
        grep -qE "^## \[${ver//./\\.}\] - [0-9]{4}-[0-9]{2}-[0-9]{2}\$" CHANGELOG.md \
            || { echo "RESUME: bump is done in $S but CHANGELOG has no dated '## [$ver] - YYYY-MM-DD' header — clear it: rm -rf $S"; return 32; }
    fi
    if [ -n "${sha:-}" ]; then
        echo "resume: $S bound to $branch, release commit ${sha:0:7} in the history of HEAD, Cargo.toml $ver, CHANGELOG dated"
    else
        echo "resume: $S bound to $branch"
    fi
}

rl_mark_at() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$3" > "$1/$2.done"; }
rl_done_at() { [ -f "$1/$2.done" ] && [ "$(cut -d' ' -f2 "$1/$2.done")" = "$3" ]; }

# rl_ci_rustflags — the workflow-level RUSTFLAGS in ci.yml, read the way
# certify.sh reads it, so these builds share certify's cache and CI's terms.
rl_ci_rustflags() {
    python3 - <<'PYEOF'
import re, pathlib, sys
text = pathlib.Path('.github/workflows/ci.yml').read_text()
head = text.split('\njobs:')[0]
m = re.search(r'^\s*RUSTFLAGS:\s*(.+?)\s*$', head, re.MULTILINE)
if not m or not m.group(1).strip().strip('"').strip("'"):
    sys.exit('could not find a workflow-level RUSTFLAGS in ci.yml')
print(m.group(1).strip().strip('"').strip("'"))
PYEOF
}

# rl_stage <state-dir> <name> <function> — run <function> unless <name> is
# already marked; mark it on success. Returns the function's exit code.
rl_stage() {
    local dir="$1" name="$2" fn="$3" rc
    if rl_done "$dir" "$name"; then
        echo "--- stage $name: already done ($(cat "$dir/$name.done")) — skipped"
        return 0
    fi
    echo "--- stage $name"
    "$fn"; rc=$?
    [ "$rc" -eq 0 ] && rl_mark "$dir" "$name"
    return "$rc"
}

# ── Codex review gate ───────────────────────────────────────────────────
# rl_codex_review <repo> <pr> <head-sha> — wait for chatgpt-codex-connector's
# review of <head-sha> and refuse to ship over its findings. Returns:
#   0  Codex reviewed <head-sha> and left no inline finding on it
#   30 Codex left findings on <head-sha> (each printed as path:line + first line)
#   31 no review of <head-sha> arrived within CODEX_TIMEOUT_SECS (default 1800);
#      the CALLER fails open, loudly — Codex is an external service
#
# v53.2.0: the chain would have merged and tagged ~10 min after Codex posted
# six findings on PR #1039; it was stopped by hand.
#
# "Reviewed <head>" is either a review by the bot whose commit_id is <head>
# (its body reads "**Reviewed commit:** `<sha prefix>`"), or the bot's summary
# issue comment (`<!-- codex-pull-request-review-summary -->`) showing a
# Completed row for `<head7>`: a clean pass posts no review, only a 👍 and that
# row. A review of an OLDER head does not count: Codex re-reviews each push.
#
# A finding is a bot inline comment whose ORIGINAL commit is <head>, or that
# belongs to a bot review of <head>. Not `commit_id == head`: GitHub moves a
# comment's commit_id forward to the newest head while its line is unchanged,
# so already-fixed findings from an older head would block forever.
RL_CODEX_BOT="chatgpt-codex-connector[bot]"
rl_codex_review() {
    local repo="$1" pr="$2" head="$3" h7="${3:0:7}" waited=0 limit="${CODEX_TIMEOUT_SECS:-1800}"
    local poll="${CODEX_POLL_SECS:-60}" reviews summary ids found
    while :; do
        reviews="$(gh api --paginate "repos/$repo/pulls/$pr/reviews" 2>/dev/null | jq -s 'add // []' 2>/dev/null)" || reviews="[]"
        ids="$(jq -c --arg b "$RL_CODEX_BOT" --arg h "$head" \
            '[.[] | select(.user.login == $b and .commit_id == $h) | .id]' <<<"${reviews:-[]}" 2>/dev/null)" || ids="[]"
        summary="$(gh api --paginate "repos/$repo/issues/$pr/comments" 2>/dev/null | jq -s 'add // []' 2>/dev/null \
            | jq -r --arg b "$RL_CODEX_BOT" --arg h7 "\`$h7\`" \
                '[.[] | select(.user.login == $b and (.body | contains("<!-- codex-pull-request-review-summary -->")))
                  | .body | split("\n")[] | select(contains($h7) and contains("Completed"))] | length' 2>/dev/null)" || summary=0
        if [ "${ids:-[]}" != "[]" ] || [ "${summary:-0}" -gt 0 ]; then
            found="$(gh api --paginate "repos/$repo/pulls/$pr/comments" 2>/dev/null | jq -s 'add // []' \
                | jq -r --arg b "$RL_CODEX_BOT" --arg h "$head" --argjson ids "${ids:-[]}" \
                    '.[] | select(.user.login == $b and (.original_commit_id == $h or (.pull_request_review_id as $r | $ids | index($r))))
                     | "\(.path):\(.line // .original_line // "?")  \(.body | split("\n") | map(select(test("[A-Za-z]"))) | .[0] // "" | gsub("<[^>]*>|!\\[[^]]*\\]\\([^)]*\\)|\\*\\*"; "") | sub("^\\s+"; "") | .[0:160])"')" \
                || { echo "codex: review of ${h7} found, but its inline comments could not be read — retrying"; found="?"; }
            if [ "$found" != "?" ]; then
                if [ -n "$found" ]; then
                    echo "CODEX FINDINGS on ${h7} ($(wc -l <<<"$found")):"
                    printf '%s\n' "$found" | sed 's/^/  /'
                    echo "fix, commit, re-run the same command"
                    return 30
                fi
                echo "codex: reviewed ${h7}, no findings"
                return 0
            fi
        fi
        [ "$waited" -lt "$limit" ] || return 31
        echo "codex: no review of ${h7} yet ($(( waited / 60 )) of $(( limit / 60 )) min)"
        sleep "$poll"; waited=$(( waited + poll ))
    done
}
