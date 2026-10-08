#!/usr/bin/env bash
# release_ship.sh — the ship half of the release method, checked in so no
# release derives it from the previous one by sed (CIRISPersist#881; the
# "derived ship scripts inherit the previous release" class).
#
#   scripts/release_ship.sh <pr> <version> <expected-head-7> <subject> <body-file>
#
# 1. refuses a dirty tree, a PR head that moved from <expected-head-7>, or a
#    PR head whose CI run is not completed/success (#756);
# 2. merges the PR (merge commit, REST — `gh pr merge` goes through the
#    Projects-classic GraphQL selection that errors on this repo) with
#    <subject>/<body-file>; an already-merged PR is accepted, so a killed run
#    can be re-run;
# 3. waits for main CI on the merge sha — UNLESS the merge commit's TREE is
#    byte-identical to the PR head's tree (no intervening main commit), in
#    which case the PR run already certified these exact bytes and the wait
#    is skipped (−35 min wall per release, CIRISPersist#881);
# 4. cuts the annotated tag v<version> from the CHANGELOG section
#    (`--cleanup=verbatim`, headings kept) at the merge sha; a local tag left by
#    an earlier run is accepted only when its annotation equals the section;
# 5. waits until main's push run on the merge sha is VISIBLE (not complete —
#    CIRISPersist#1008), pushes the tag, and prints the tag's CI run id.
#
# It ENDS there. Waiting for tag CI and setting the release body is
# `scripts/release_finish.sh <version> <tag-run-id>` — a separate command so
# neither half can run into a 2-hour background cap (v53.1.8's ship script
# was killed at that cap while tag CI queued on macOS).
#
# Exit codes: 2 dirty tree · 3 head moved / PR CI not green · 4 merge failed ·
# 5 main CI red · 6 main CI timeout · 7 no CHANGELOG section · 8 tag cut failed ·
# 9 tag sha mismatch · 10 tag push failed · 11 the local tag's annotation is
# not the CHANGELOG section byte for byte (or it is lightweight) · 16 tag run
# never appeared.
#
# BEFORE running this for a release that names a CC version: run
# `scripts/check_vendored_cc.sh <cc-tag>` — the vendored CC files must be the tag's bytes.
set -uo pipefail
pr="${1:?pr number}"; ver="${2:?version}"; want="${3:?expected head sha (7)}"; subject="${4:?merge subject}"; bodyf="${5:?merge body file}"
cd "$(git rev-parse --show-toplevel)" || exit 2
# shellcheck source=scripts/release_lib.sh
. scripts/release_lib.sh
repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner) || { echo "cannot resolve the GitHub repo"; exit 2; }
[ -z "$(git status --porcelain)" ] || { echo "DIRTY TREE"; exit 2; }
head=$(gh api "repos/$repo/pulls/$pr" --jq .head.sha); [ "${head:0:7}" = "$want" ] || { echo "HEAD MOVED: $head"; exit 3; }
head_tree=$(git rev-parse "${head}^{tree}" 2>/dev/null || { git fetch -q origin "$head" && git rev-parse "${head}^{tree}"; })
# The PR run must be GREEN before the merge (#756): the main-CI wait below
# is skipped when the trees match, and that skip leans on this run.
prst=$(gh run list --commit "$head" --workflow ci.yml --event pull_request --json status,conclusion --jq '.[0] | "\(.status)/\(.conclusion)"' 2>/dev/null || echo none)
[ "$prst" = "completed/success" ] || { echo "PR CI on $head NOT GREEN ($prst) — refusing to merge (#756)"; exit 3; }
for attempt in 1 2 3 4 5; do
  [ "$(gh api "repos/$repo/pulls/$pr" --jq .merged)" = true ] && break
  gh api -X PUT "repos/$repo/pulls/$pr/merge" -f merge_method=merge -f sha="$head" -f commit_title="$subject" -F commit_message=@"$bodyf" >/dev/null && break
  echo "merge attempt $attempt failed; retrying in 30s"; sleep 30
done
[ "$(gh api "repos/$repo/pulls/$pr" --jq .merged)" = true ] || { echo "PR #$pr did not merge"; exit 4; }
# The PR's own merge commit, not origin/main's tip: another merge may have
# landed since, and a re-run after a kill must find the same sha.
merge_sha=$(gh api "repos/$repo/pulls/$pr" --jq .merge_commit_sha)
git fetch -q origin main; git cat-file -e "${merge_sha}^{commit}" 2>/dev/null || git fetch -q origin "$merge_sha"
echo "merged: $merge_sha"
merge_tree=$(git rev-parse "${merge_sha}^{tree}")
if [ "$merge_tree" = "$head_tree" ]; then
  echo "merge tree == PR head tree ($merge_tree): the PR run ($prst) certified these bytes — main-CI wait skipped (#881)"
else
  echo "merge tree $merge_tree != PR head tree $head_tree — waiting for main CI on the merge"
  st=none
  for i in $(seq 1 150); do
    st=$(gh run list --branch main --commit "$merge_sha" --workflow ci.yml --json status,conclusion --jq '.[0] | "\(.status)/\(.conclusion)"' 2>/dev/null || echo none)
    echo "main CI: $st"; case "$st" in completed/success) break;; completed/*) echo "MAIN CI NOT GREEN: $st"; exit 5;; esac; sleep 60
  done
  [ "$st" = "completed/success" ] || { echo "main CI timeout after 150 min"; exit 6; }
fi
tmp=$(mktemp -d)
git show "$merge_sha":CHANGELOG.md > "$tmp/cl.md"
rl_changelog_section "$tmp/cl.md" "$ver" > "$tmp/tagbody.md" || { echo "no section for [$ver] (or none after it) in CHANGELOG"; exit 7; }
[ -s "$tmp/tagbody.md" ] || { echo "empty tag body"; exit 7; }
if git rev-parse -q --verify "refs/tags/v$ver" >/dev/null; then
  echo "tag v$ver already exists locally (re-run) — checking it"
else
  git tag -a "v$ver" "$merge_sha" --cleanup=verbatim -F "$tmp/tagbody.md" || exit 8
fi
[ "$(git rev-list -n1 "v$ver")" = "$merge_sha" ] || { echo "tag SHA mismatch: v$ver is not at $merge_sha"; exit 9; }
# The annotation must BE the CHANGELOG section, byte for byte — a fresh cut
# and a re-run alike. A re-run used to accept any local v<ver> at the right
# sha whose body was at least as long; a stale or hand-written annotation was
# then pushed and became the release body (Codex on PR #1039). The raw tag
# object's message is everything after its header's blank line.
if [ "$(git cat-file -t "refs/tags/v$ver")" != tag ]; then
  echo "local v$ver is a lightweight tag, not the CHANGELOG annotation — clear it with: git tag -d v$ver, then re-run"; exit 11
fi
git cat-file tag "refs/tags/v$ver" | sed '1,/^$/d' > "$tmp/stored.md"
in_bytes=$(wc -c < "$tmp/tagbody.md"); out_bytes=$(wc -c < "$tmp/stored.md")
echo "tag body bytes in=$in_bytes stored=$out_bytes headings=$(grep -c '^#' "$tmp/stored.md")"
if ! cmp -s "$tmp/tagbody.md" "$tmp/stored.md"; then
  echo "local v$ver's annotation is not the CHANGELOG [$ver] section at $merge_sha (stale or hand-written):"
  diff "$tmp/tagbody.md" "$tmp/stored.md" | head -20
  if git ls-remote --exit-code origin "refs/tags/v$ver" >/dev/null 2>&1; then
    echo "v$ver is ALREADY on origin — deleting it there is a human decision; nothing pushed"
  else
    echo "clear it with: git tag -d v$ver, then re-run (the tag is cut afresh)"
  fi
  exit 11
fi
# The tag run and main's push run share one concurrency group (#397, keyed on
# the SHA, cancel-in-progress): whichever run is QUEUED LATER cancels the other.
#
# v50.0.0: the tag was pushed the instant the merge landed; main's push run and
# the tag run were queued in the same second, main's came second, and the
# dedup CANCELLED THE TAG RUN — the only run that publishes the release.
# v51.0.0 answered that by waiting for main's run to COMPLETE before the tag
# push. That re-paid the full matrix #881 had just skipped: 64 and 65 min on
# v53.1.5/6 (CIRISPersist#1008).
#
# The v50 failure needed main's run to be queued AFTER the tag's. Waiting only
# until main's run EXISTS (queued, in_progress or already completed) rules that
# out: the tag run is then the newer one and cancels main's, as #397 meant —
# v53.1.7 and v53.1.8 shipped this way. Main's only unique job, the core-1
# cache save, also runs on tags. If main's run never appears (~5 min — e.g. a
# paths filter), push anyway. A cancelled tag run is still re-run by
# release_finish.sh — the backstop for a race this ordering misses.
mst=none
for i in $(seq 1 20); do
  mst=$(gh run list --branch main --commit "$merge_sha" --workflow ci.yml --event push --json status,conclusion --jq '.[0] | "\(.status)/\(.conclusion)"' 2>/dev/null || echo none)
  case "$mst" in none|null/null|"") echo "main push run on $merge_sha not visible yet — waiting before the tag push"; sleep 15;; *) break;; esac
done
echo "main push run on $merge_sha: $mst — pushing the tag"
if [ "$(git ls-remote origin "refs/tags/v$ver" | cut -f1)" = "$(git rev-parse "refs/tags/v$ver")" ]; then
  echo "tag v$ver already on origin (re-run)"
else
  git push origin "refs/tags/v$ver" || { echo "tag push failed"; exit 10; }
fi
echo "tagged v$ver at $merge_sha"
rid=""
for i in $(seq 1 30); do
  rid=$(gh run list --event push --branch "v$ver" --workflow ci.yml --json databaseId --jq '.[0].databaseId // empty' 2>/dev/null)
  [ -n "$rid" ] && break; sleep 10
done
[ -n "$rid" ] || { echo "no CI run for tag v$ver after 5 min"; exit 16; }
echo "TAG_RUN_ID=$rid"
echo "next: scripts/release_finish.sh $ver $rid"
echo "=== RELEASE_SHIP_TAGGED v$ver at $merge_sha ==="
