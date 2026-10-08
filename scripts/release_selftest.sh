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

echo "CHANGELOG section extraction"
expect_eq "prev of 9.9.0" "$(rl_prev_version "$t/CHANGELOG.md" 9.9.0)" "9.8.10"
expect_eq "prev of 9.8.10" "$(rl_prev_version "$t/CHANGELOG.md" 9.8.10)" "9.8.1"
expect_eq "prev of 9.8.1" "$(rl_prev_version "$t/CHANGELOG.md" 9.8.1)" "9.8.0"
expect_eq "prev of the oldest is empty" "$(rl_prev_version "$t/CHANGELOG.md" 9.8.0)" ""
sec="$(rl_changelog_section "$t/CHANGELOG.md" 9.9.0)"
expect_eq "section starts at its heading" "$(printf '%s\n' "$sec" | head -1)" "## [9.9.0] - UNRELEASED"
expect_eq "section ends before the next numbered heading" "$(printf '%s\n' "$sec" | grep -c '^## ')" "1"
expect_eq "section keeps its last body line" "$(printf '%s\n' "$sec" | grep -c '^- a bullet$')" "1"
expect_eq "section keeps multibyte text" "$(printf '%s\n' "$sec" | grep -c 'em dash — and an arrow →')" "1"
sec1="$(rl_changelog_section "$t/CHANGELOG.md" 9.8.1)"
expect_eq "9.8.1 is not 9.8.10" "$(printf '%s\n' "$sec1" | head -1)" "## [9.8.1] - 2026-01-02"
expect_eq "9.8.1 section is two headings long" "$(printf '%s\n' "$sec1" | grep -c '^#')" "2"
if rl_changelog_section "$t/CHANGELOG.md" 9.7.0 >/dev/null; then bad "a missing version fails"; else ok "a missing version fails"; fi
if rl_changelog_section "$t/CHANGELOG.md" 9.8.0 >/dev/null; then bad "the oldest section (no end) fails"; else ok "the oldest section (no end) fails"; fi
expect_eq "headings joined" "$(rl_section_headings "$t/CHANGELOG.md" 9.9.0)" \
    "the door refused what its precheck granted (#11); counters always on (#12)"

# rl_subject: short lists pass through; long lists are capped with "+N more".
expect_eq "subject short" "$(rl_subject "$t/CHANGELOG.md" 9.9.0 180)" "v9.9.0 — $(rl_section_headings "$t/CHANGELOG.md" 9.9.0)"
_sub="$(rl_subject "$t/CHANGELOG.md" 9.9.0 20)"
case "$_sub" in "v9.9.0 — "*"; +"*" more") ok "subject capped: $_sub";; *) bad "subject not capped: $_sub";; esac
[ "${#_sub}" -le 80 ] && ok "subject cap length" || bad "subject cap length ${#_sub}"

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

echo "syntax"
for f in scripts/release.sh scripts/release_ship.sh scripts/release_finish.sh scripts/release_lib.sh scripts/release_selftest.sh; do
    if bash -n "$f"; then ok "bash -n $f"; else bad "bash -n $f"; fi
    if grep -nE -- '--no-verify|--amend' "$f" | grep -v '^[0-9]*:#' | grep -vq 'grep -nE'; then bad "$f uses --no-verify/--amend"; else ok "$f: no --no-verify/--amend"; fi
done

echo "------------------------------------------------------------"
if [ "$fails" -ne 0 ]; then echo "RELEASE SELFTEST: $fails of $checks FAILED"; exit 1; fi
echo "RELEASE SELFTEST: all $checks green"
