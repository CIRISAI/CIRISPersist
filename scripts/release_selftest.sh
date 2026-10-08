#!/usr/bin/env bash
# release_selftest.sh — offline self-test of scripts/release_lib.sh, the code
# release.sh / release_ship.sh / release_finish.sh share: the CHANGELOG section
# cut (PR body, tag annotation, release body), the evidence re-stamp, and the
# stage-marker resume logic. No network, no cargo, no bats; runs in seconds.
#
#   scripts/release_selftest.sh        # prints one line per check, exits 1 on any failure
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
# shellcheck source=scripts/release_lib.sh
. scripts/release_lib.sh

fails=0; checks=0
ok() { checks=$((checks + 1)); echo "  ok    $1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); echo "  FAIL  $1"; }
expect_eq() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected [$3], got [$2]"; fi; }

t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT

# ── fixture CHANGELOG ───────────────────────────────────────────────────
# [9.8.10] sits ABOVE [9.8.1] so a pattern for 9.8.1 that is not anchored on
# the closing bracket would start the section in the wrong place.
cat > "$t/CHANGELOG.md" <<'EOF'
# Changelog

## [Unreleased]

## [9.9.0] - UNRELEASED

### Fixed — the door refused what its precheck granted (#11)

Body line with an em dash — and an arrow →.

### Added — counters always on (#12)

- a bullet

## [9.8.10] - 2026-01-03

### Fixed — ten

## [9.8.1] - 2026-01-02

### Fixed — one

## [9.8.0] - 2026-01-01

### Added — the first
EOF

# A second fixture whose headings a bracket-as-character-class pattern would
# mis-match: `^## [53.2.0]` read as a class matches `## 5` and `## 3`, and
# `## [5]` is a bracketed heading that is not a numbered section.
cat > "$t/CHANGELOG2.md" <<'EOF'
# Changelog

## 5 things to know

## 3 more

## [53.2.0] - 2026-10-08

### Added — the release chain (#1018)

## [5]

a non-numbered bracket heading inside 53.2.0's section

## [53.1.8] - 2026-10-07

### Fixed — the score gate (#1013)

## [53.1.7] - 2026-10-06
EOF

# extraction_cases — every case that runs the CHANGELOG cut. Run once per awk
# below: gawk and busybox awk process backslash escapes in `-v` values and
# mawk does not, so a cut that passed regex text through `-v` was green here
# under mawk and empty under gawk (Codex on PR #1039).
extraction_cases() {
    expect_eq "[$1] prev of 9.9.0" "$(rl_prev_version "$t/CHANGELOG.md" 9.9.0)" "9.8.10"
    expect_eq "[$1] prev of 9.8.10" "$(rl_prev_version "$t/CHANGELOG.md" 9.8.10)" "9.8.1"
    expect_eq "[$1] prev of 9.8.1" "$(rl_prev_version "$t/CHANGELOG.md" 9.8.1)" "9.8.0"
    expect_eq "[$1] prev of the oldest is empty" "$(rl_prev_version "$t/CHANGELOG.md" 9.8.0)" ""
    sec="$(rl_changelog_section "$t/CHANGELOG.md" 9.9.0)"
    expect_eq "[$1] section starts at its heading" "$(printf '%s\n' "$sec" | head -1)" "## [9.9.0] - UNRELEASED"
    expect_eq "[$1] section ends before the next numbered heading" "$(printf '%s\n' "$sec" | grep -c '^## ')" "1"
    expect_eq "[$1] section keeps its last body line" "$(printf '%s\n' "$sec" | grep -c '^- a bullet$')" "1"
    expect_eq "[$1] section keeps multibyte text" "$(printf '%s\n' "$sec" | grep -c 'em dash — and an arrow →')" "1"
    sec1="$(rl_changelog_section "$t/CHANGELOG.md" 9.8.1)"
    expect_eq "[$1] 9.8.1 is not 9.8.10" "$(printf '%s\n' "$sec1" | head -1)" "## [9.8.1] - 2026-01-02"
    expect_eq "[$1] 9.8.1 section is two headings long" "$(printf '%s\n' "$sec1" | grep -c '^#')" "2"
    _o="$(rl_changelog_section "$t/CHANGELOG.md" 9.9.0)"; _rc=$?
    if [ "$_rc" -eq 0 ] && [ -n "$_o" ]; then ok "[$1] a found section is non-empty with exit 0"; else bad "[$1] a found section is non-empty with exit 0 (rc=$_rc, ${#_o} bytes)"; fi
    if rl_changelog_section "$t/CHANGELOG.md" 9.7.0 >/dev/null; then bad "[$1] a missing version fails"; else ok "[$1] a missing version fails"; fi
    if rl_changelog_section "$t/CHANGELOG.md" 9.8.0 >/dev/null; then bad "[$1] the oldest section (no end) fails"; else ok "[$1] the oldest section (no end) fails"; fi
    expect_eq "[$1] headings joined" "$(rl_section_headings "$t/CHANGELOG.md" 9.9.0)" \
        "the door refused what its precheck granted (#11); counters always on (#12)"

    # rl_subject: short lists pass through; long lists are capped with "+N more".
    expect_eq "[$1] subject short" "$(rl_subject "$t/CHANGELOG.md" 9.9.0 180)" "v9.9.0 — $(rl_section_headings "$t/CHANGELOG.md" 9.9.0)"
    _sub="$(rl_subject "$t/CHANGELOG.md" 9.9.0 20)"
    case "$_sub" in "v9.9.0 — "*"; +"*" more") ok "[$1] subject capped: $_sub";; *) bad "[$1] subject not capped: $_sub";; esac
    [ "${#_sub}" -le 80 ] && ok "[$1] subject cap length" || bad "[$1] subject cap length ${#_sub}"

    sec2="$(rl_changelog_section "$t/CHANGELOG2.md" 53.2.0)"
    expect_eq "[$1] 53.2.0 starts at its own heading, not at '## 5'" "$(printf '%s\n' "$sec2" | head -1)" "## [53.2.0] - 2026-10-08"
    expect_eq "[$1] 53.2.0 keeps the '## [5]' line and stops at 53.1.8" "$(printf '%s\n' "$sec2" | grep -c '^## ')" "2"
    expect_eq "[$1] 53.2.0 keeps its last body line" "$(printf '%s\n' "$sec2" | grep -c '^a non-numbered bracket heading')" "1"
    expect_eq "[$1] 53.1.8 headings" "$(rl_section_headings "$t/CHANGELOG2.md" 53.1.8)" "the score gate (#1013)"
}

# Every awk on this host, each behind a PATH shim named `awk`: gawk, mawk,
# busybox's awk, the default `awk`, and any extra binaries named in
# RELEASE_SELFTEST_AWKS (space-separated paths).
echo "CHANGELOG section extraction"
awks=()
for a in gawk mawk; do p="$(command -v "$a" 2>/dev/null)" && awks+=("$a=$p"); done
p="$(command -v busybox 2>/dev/null)" && busybox awk 'BEGIN{}' </dev/null 2>/dev/null && awks+=("busybox=$p")
for p in ${RELEASE_SELFTEST_AWKS:-}; do [ -x "$p" ] && awks+=("$(basename "$p")@$p"); done
[ "${#awks[@]}" -gt 0 ] || awks+=("awk=$(command -v awk)")
orig_path="$PATH"
for spec in "${awks[@]}"; do
    name="${spec%%[=@]*}"; bin="${spec#*[=@]}"
    shim="$t/awk-$name"; mkdir -p "$shim"; ln -sf "$bin" "$shim/awk"
    PATH="$shim:$orig_path"; hash -r
    echo " under $name ($bin)"
    extraction_cases "$name"
done
PATH="$orig_path"; hash -r

echo "evidence re-stamp"
printf 'a\tciris-persist@9.8.10\nb\tciris-persist@9.8.10:src/x.rs\nc\tciris-persist@9.8.100\nd\tciris-persist@31.0.0\n' > "$t/cc.tsv"
n="$(rl_restamp_evidence "$t/cc.tsv" 9.8.10 9.9.0)"; rc=$?
expect_eq "re-stamp exit" "$rc" "0"
expect_eq "re-stamp count" "$n" "2"
expect_eq "longer version left alone" "$(grep -c 'ciris-persist@9.8.100$' "$t/cc.tsv")" "1"
expect_eq "other pins left alone" "$(grep -c 'ciris-persist@31.0.0$' "$t/cc.tsv")" "1"
expect_eq "nothing left at prev" "$(grep -cE 'ciris-persist@9\.8\.10([^0-9]|$)' "$t/cc.tsv")" "0"
if rl_restamp_evidence "$t/cc.tsv" 9.8.10 9.9.0 >/dev/null; then bad "a second re-stamp (nothing to do) fails"; else ok "a second re-stamp (nothing to do) fails"; fi

echo "stage state and resume"
S="$t/state"; mkdir -p "$S"
runs=0; count() { runs=$((runs + 1)); }
rl_stage "$S" one count >/dev/null; rl_stage "$S" one count >/dev/null
expect_eq "a done stage is skipped on re-run" "$runs" "1"
fails_left=1; flaky() { runs=$((runs + 1)); [ "$fails_left" -eq 0 ] || { fails_left=0; return 7; }; }
runs=0; rl_stage "$S" two flaky >/dev/null; rc=$?
expect_eq "a failing stage returns its code" "$rc" "7"
if rl_done "$S" two; then bad "a failing stage is not marked"; else ok "a failing stage is not marked"; fi
rl_stage "$S" two flaky >/dev/null; rl_stage "$S" two flaky >/dev/null
expect_eq "a failed stage re-runs once, then is skipped" "$runs" "2"
rl_mark_at "$S" certify aaaa
if rl_done_at "$S" certify aaaa; then ok "a sha stage is done at its sha"; else bad "a sha stage is done at its sha"; fi
if rl_done_at "$S" certify bbbb; then bad "a sha stage is NOT done once HEAD moved"; else ok "a sha stage is NOT done once HEAD moved"; fi
if rl_done_at "$S" absent aaaa; then bad "an absent stage is not done"; else ok "an absent stage is not done"; fi
rl_put "$S" pr 123
expect_eq "a stored value reads back" "$(rl_get "$S" pr)" "123"
expect_eq "an absent value reads empty" "$(rl_get "$S" nope)" ""

echo "release.sh argument handling"
scripts/release.sh --dry-run 1.2 >/dev/null 2>&1; expect_eq "a two-part version is refused" "$?" "2"
scripts/release.sh >/dev/null 2>&1; expect_eq "no version is refused" "$?" "2"
scripts/release.sh 9.9.9 --bogus >/dev/null 2>&1; expect_eq "an unknown flag is refused" "$?" "2"

echo "release_finish.sh tag source"
# A bare origin with an annotated v9.9.0, and clones with a stale, absent,
# equal or unfetchable local tag. A stub `gh` reports run 7 as v9.9.0's green
# push CI, accepts the release edit and keeps the notes file it was handed, so
# the case reads WHICH annotation the script would publish. The fixture has no
# scripts/verify_release.sh, so a script that got that far stops at exit 17.
RF="$PWD/scripts/release_finish.sh"
mkdir -p "$t/rf/bin"
cat > "$t/rf/bin/gh" <<'GHEOF'
#!/usr/bin/env bash
case "$*" in
  "run view"*headBranch*) echo "v9.9.0 push CI";;
  "run view"*status*) echo "completed/success";;
  "release edit"*) while [ $# -gt 0 ]; do [ "$1" = --notes-file ] && cp "$2" "$RF_NOTES"; shift; done;;
  "release view"*body*) cat "$RF_NOTES";;
  "release view"*) echo "assets: none";;
  *) exit 1;;
esac
GHEOF
chmod +x "$t/rf/bin/gh"
(
    set -e
    export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
    git init -q --bare -b main "$t/rf/origin.git"
    git init -q -b main "$t/rf/seed"; cd "$t/rf/seed"
    git commit -q --allow-empty -m one; git commit -q --allow-empty -m two
    git tag -a v9.9.0 -m "v9.9.0: the REMOTE annotation, long enough to be a CHANGELOG section body." HEAD
    git push -q "$t/rf/origin.git" HEAD:refs/heads/main refs/tags/v9.9.0
    git clone -q "$t/rf/origin.git" "$t/rf/stale" 2>/dev/null; cd "$t/rf/stale"
    git tag -d v9.9.0 >/dev/null
    git tag -a v9.9.0 -m "v9.9.0: a STALE local annotation from an abandoned tagging attempt, long enough." HEAD~1
    git clone -q "$t/rf/origin.git" "$t/rf/fresh" 2>/dev/null; git -C "$t/rf/fresh" tag -d v9.9.0 >/dev/null
    git clone -q "$t/rf/origin.git" "$t/rf/same" 2>/dev/null
    git clone -q "$t/rf/origin.git" "$t/rf/notag" 2>/dev/null
    git -C "$t/rf/notag" tag -d v9.9.0 >/dev/null; git -C "$t/rf/notag" remote set-url origin "$t/rf/nonexistent.git"
) || bad "release_finish fixture repos"
rf() {
    : > "$t/rf/notes-$1"
    out="$(cd "$t/rf/$1" && PATH="$t/rf/bin:$PATH" RF_NOTES="$t/rf/notes-$1" FINISH_TIMEOUT_MIN=1 bash "$RF" 9.9.0 7 2>&1)"; rc=$?
    [ -n "${RS_DEBUG:-}" ] && printf '[%s rc=%s]\n%s\n' "$1" "$rc" "$out"
    notes="$(cat "$t/rf/notes-$1")"
}
rf stale
expect_eq "a stale local tag is refused (exit 18)" "$rc" "18"
case "$notes" in *STALE*) bad "the stale local annotation was published";; *) ok "the stale local annotation was not published";; esac
rf fresh
expect_eq "no local tag: the run gets past the release edit" "$rc" "17"
case "$notes" in *REMOTE*) ok "no local tag: origin's annotation is published";; *) bad "no local tag: published [$notes]";; esac
rf same
expect_eq "a local tag equal to origin's is accepted" "$rc" "17"
case "$notes" in *REMOTE*) ok "equal local tag: origin's annotation is published";; *) bad "equal local tag: published [$notes]";; esac
rf notag
expect_eq "an unfetchable tag is refused (exit 19), not hidden" "$rc" "19"

echo "codex review gate (rl_codex_review, stub gh)"
# A stub `gh api --paginate <path>` serves $CX/<path with / as _>.json. HEAD is
# h…, an older pushed head is o…. Waits are seconds here (CODEX_*_SECS).
export CX="$t/cx"; mkdir -p "$CX/bin"
cat > "$CX/bin/gh" <<'GHEOF'
#!/usr/bin/env bash
[ "$1" = api ] || exit 1
for a in "$@"; do p="$a"; done
f="$CX/$(printf '%s' "${p%%\?*}" | tr '/' '_').json"
[ -f "$f" ] && cat "$f" || echo '[]'
GHEOF
chmod +x "$CX/bin/gh"
H=1111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; O=2222222bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
BOT='chatgpt-codex-connector[bot]'
cx_reset() { rm -f "$CX"/*.json; }
cx_review() {  # <id> <commit>
    # shellcheck disable=SC2016  # literal: python / jq / grep text, expanded by them
    python3 -I -c 'import json,sys,os; f=sys.argv[1]; a=json.load(open(f)) if os.path.exists(f) else []
a.append({"id":int(sys.argv[2]),"commit_id":sys.argv[3],"user":{"login":sys.argv[4]},"body":"**Reviewed commit:** `"+sys.argv[3][:10]+"`"}); json.dump(a,open(f,"w"))' \
        "$CX/repos_o_r_pulls_9_reviews.json" "$1" "$2" "$BOT"
}
cx_comment() {  # <review-id> <original_commit> <commit> <path> <line> <title> [login]
    python3 -I -c 'import json,sys,os; f=sys.argv[1]; a=json.load(open(f)) if os.path.exists(f) else []
a.append({"pull_request_review_id":int(sys.argv[2]),"original_commit_id":sys.argv[3],"commit_id":sys.argv[4],"path":sys.argv[5],"line":int(sys.argv[6]),
"user":{"login":sys.argv[8]},"body":"**<sub><sub>![P2 Badge](https://x/y.svg)</sub></sub>  "+sys.argv[7]+"**\n\nmore text"}); json.dump(a,open(f,"w"))' \
        "$CX/repos_o_r_pulls_9_comments.json" "$1" "$2" "$3" "$4" "$5" "$6" "${7:-$BOT}"
}
cx_summary() {  # <commit7> <status word>
    # shellcheck disable=SC2016  # literal: python / jq / grep text, expanded by them
    printf '[{"user":{"login":"%s"},"body":"<!-- codex-pull-request-review-summary -->\\n\\n| Review | Status | Commit |\\n| --- | --- | --- |\\n| Code Review | %s | `%s` |"}]' \
        "$BOT" "$2" "$1" > "$CX/repos_o_r_issues_9_comments.json"
}
cx() { out="$(PATH="$CX/bin:$PATH" CODEX_TIMEOUT_SECS=2 CODEX_POLL_SECS=1 rl_codex_review o/r 9 "$H" 2>&1)"; rc=$?; }

cx_reset; cx_review 100 "$H"; cx
expect_eq "codex: a clean review of HEAD passes" "$rc" "0"
cx_reset; cx_summary 1111111 "✅ **Completed**"; cx
expect_eq "codex: a Completed summary row for HEAD (clean pass, no review) passes" "$rc" "0"
cx_reset; cx_review 50 "$O"; cx_comment 50 "$O" "$O" src/a.rs 3 "old finding"; cx_summary 2222222 "✅ **Completed**"; cx
expect_eq "codex: a review of an OLDER head only times out (31)" "$rc" "31"
case "$out" in *"no review of 1111111 yet"*) ok "codex: it kept polling for HEAD";; *) bad "codex: did not poll: $out";; esac
cx_reset; cx_summary 1111111 "⏳ **In progress**"; cx
expect_eq "codex: an In-progress row for HEAD keeps waiting (31)" "$rc" "31"
cx_reset; cx_review 100 "$H"; cx_comment 100 "$H" "$H" scripts/x.sh 26 "Preserve regex escapes passed to awk"; cx
expect_eq "codex: a finding on HEAD stops with 30" "$rc" "30"
case "$out" in *"scripts/x.sh:26  Preserve regex escapes passed to awk"*"fix, commit, re-run the same command"*) ok "codex: prints path:line, the finding's first line, and what to do";;
    *) bad "codex: finding output: $out";; esac
cx_reset; cx_review 50 "$O"; cx_review 100 "$H"; cx_comment 50 "$O" "$H" src/a.rs 3 "old finding re-anchored to HEAD"; cx
expect_eq "codex: an OLDER head's finding whose commit_id moved to HEAD does not block" "$rc" "0"
cx_reset; cx_review 100 "$H"; cx_comment 7 "$H" "$H" src/a.rs 3 "a human's comment" someone; cx
expect_eq "codex: a non-Codex comment on HEAD does not block" "$rc" "0"
cx_reset; cx_summary 1111111 "✅ **Completed**"; cx_comment 100 "$H" "$H" src/b.rs 9 "finding with no review object seen"; cx
expect_eq "codex: summary says HEAD done, a finding on HEAD still stops (30)" "$rc" "30"

echo "release.sh codex stage"
expect_eq "--skip-codex is a known flag" "$(scripts/release.sh --skip-codex 1.2 2>&1 | grep -c 'unknown flag')" "0"
_l() { grep -n "$1" scripts/release.sh | head -1 | cut -d: -f1; }
if [ "$(_l '"--- stage prci"')" -lt "$(_l '"--- stage codex"')" ] && [ "$(_l '"--- stage codex"')" -lt "$(_l '"--- stage ship"')" ]; then
    ok "the codex stage runs after prci and before ship"; else bad "the codex stage is not between prci and ship"; fi
# shellcheck disable=SC2016  # literal: python / jq / grep text, expanded by them
grep -q 'rl_done_at "$S" codex "$(head_sha)"' scripts/release.sh && ok "the codex marker is keyed to HEAD's sha" || bad "the codex marker is not keyed to HEAD"
grep -q 'for st in preflight cheap bump pr certify prci codex ship' scripts/release.sh && ok "--dry-run lists the codex stage" || bad "--dry-run does not list the codex stage"

echo "release_ship.sh local tag annotation"
# A re-run that finds v<version> locally at the merge sha must also find the
# CHANGELOG section's bytes in it: a stale or hand-written annotation was
# accepted, pushed, and became the release body (Codex on PR #1039). A stub
# `gh` reports PR 9 merged at the fixture's HEAD with a green PR run, main's
# push run visible, and tag run 42; origin is a local bare repo.
RS="$PWD/scripts/release_ship.sh"
mkdir -p "$t/rs/bin"
cat > "$t/rs/bin/gh" <<'GHEOF'
#!/usr/bin/env bash
case "$*" in
  "repo view"*) echo o/r;;
  *".head.sha"*|*".merge_commit_sha"*) cat "$RS_HEAD";;
  *".merged"*) echo true;;
  "run list"*databaseId*) echo 42;;
  "run list"*) echo completed/success;;
  *) exit 1;;
esac
GHEOF
chmod +x "$t/rs/bin/gh"
rs_fixture() {  # <name>: a clone whose HEAD carries CHANGELOG [9.9.0] and the lib
    (
        set -e
        export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
        git init -q --bare -b main "$t/rs/$1.git"
        git init -q -b main "$t/rs/$1"; cd "$t/rs/$1"
        mkdir scripts; cp "$OLDPWD/scripts/release_lib.sh" scripts/; cp "$t/CHANGELOG.md" .
        git add -A; git commit -q -m one
        git remote add origin "$t/rs/$1.git"; git push -q origin HEAD:refs/heads/main
        git rev-parse HEAD > "$t/rs/$1.head"
    )
}
rs() {  # <name>
    : > "$t/rs/body"
    out="$(cd "$t/rs/$1" && PATH="$t/rs/bin:$PATH" RS_HEAD="$t/rs/$1.head" bash "$RS" 9 9.9.0 "$(cut -c1-7 "$t/rs/$1.head")" subj "$t/rs/body" 2>&1)"; rc=$?
    [ -n "${RS_DEBUG:-}" ] && printf '[%s rc=%s]\n%s\n' "$1" "$rc" "$out"
}
rs_fixture fresh; rs fresh
expect_eq "ship: no local tag: cut, pushed, tag run printed (exit 0)" "$rc" "0"
if [ "$(git -C "$t/rs/fresh" ls-remote origin refs/tags/v9.9.0 | cut -f1)" = "$(git -C "$t/rs/fresh" rev-parse refs/tags/v9.9.0)" ]; then ok "ship: the cut tag is on origin"; else bad "ship: the cut tag is not on origin"; fi
rs_fixture rerun; ( cd "$t/rs/rerun" && rl_changelog_section CHANGELOG.md 9.9.0 > "$t/rs/sec.md" && git -c user.name=t -c user.email=t@t tag -a v9.9.0 --cleanup=verbatim -F "$t/rs/sec.md" HEAD ); rs rerun
expect_eq "ship: a re-run with the CHANGELOG's own annotation is accepted (exit 0)" "$rc" "0"
rs_fixture stale; git -C "$t/rs/stale" -c user.name=t -c user.email=t@t tag -a v9.9.0 -m "a hand-written annotation that is long enough to pass a byte-count check, because it pads itself out with words and more words and more words and still more words until it is longer than the section" HEAD; rs stale
expect_eq "ship: a stale local annotation at the right sha is refused (exit 11)" "$rc" "11"
case "$out" in *"git tag -d v9.9.0"*) ok "ship: the refusal says how to clear it";; *) bad "ship: refusal text: $out";; esac
if git -C "$t/rs/stale" ls-remote --exit-code origin refs/tags/v9.9.0 >/dev/null; then bad "ship: the stale tag was pushed"; else ok "ship: the stale tag was not pushed"; fi
rs_fixture light; git -C "$t/rs/light" tag v9.9.0 HEAD; rs light
expect_eq "ship: a lightweight local tag is refused (exit 11)" "$rc" "11"

echo "syntax"
for f in scripts/release.sh scripts/release_ship.sh scripts/release_finish.sh scripts/release_lib.sh scripts/release_selftest.sh; do
    if bash -n "$f"; then ok "bash -n $f"; else bad "bash -n $f"; fi
    if grep -nE -- '--no-verify|--amend' "$f" | grep -v '^[0-9]*:#' | grep -vq 'grep -nE'; then bad "$f uses --no-verify/--amend"; else ok "$f: no --no-verify/--amend"; fi
done

echo "------------------------------------------------------------"
if [ "$fails" -ne 0 ]; then echo "RELEASE SELFTEST: $fails of $checks FAILED"; exit 1; fi
echo "RELEASE SELFTEST: all $checks green"
