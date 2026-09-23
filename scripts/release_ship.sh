#!/usr/bin/env bash
# release_ship.sh — the ship half of the release method, checked in so no
# release derives it from the previous one by sed (CIRISPersist#881; the
# "derived ship scripts inherit the previous release" class).
#
#   scripts/release_ship.sh <pr> <version> <expected-head-7> <subject> <body-file>
#
# 1. refuses a dirty tree or a PR head that moved from <expected-head-7>;
# 2. merges the PR (--merge) with <subject>/<body-file>;
# 3. waits for main CI on the merge sha — UNLESS the merge commit's TREE is
#    byte-identical to the PR head's tree (no intervening main commit), in
#    which case the PR run already certified these exact bytes and the wait
#    is skipped (−35 min wall per release, CIRISPersist#881);
# 4. cuts the annotated tag v<version> from the CHANGELOG section
#    (`--cleanup=verbatim`, headings kept; byte count asserted) at the merge sha;
# 5. waits for tag CI, then sets the release body from the same section —
#    polling for the release to EXIST first (tag CI creates it a moment after
#    its last job; an edit before that fails silently).
set -uo pipefail
pr="${1:?pr number}"; ver="${2:?version}"; want="${3:?expected head sha (7)}"; subject="${4:?merge subject}"; bodyf="${5:?merge body file}"
cd "$(git rev-parse --show-toplevel)"
[ -z "$(git status --porcelain)" ] || { echo "DIRTY TREE"; exit 2; }
head=$(gh pr view "$pr" --json headRefOid --jq .headRefOid); [ "${head:0:7}" = "$want" ] || { echo "HEAD MOVED: $head"; exit 3; }
head_tree=$(git rev-parse "${head}^{tree}" 2>/dev/null || { git fetch -q origin "$head" && git rev-parse "${head}^{tree}"; })
gh pr merge "$pr" --merge --subject "$subject" --body-file "$bodyf" || exit 4
git fetch -q origin main; merge_sha=$(git rev-parse origin/main); echo "merged: $merge_sha"
merge_tree=$(git rev-parse "${merge_sha}^{tree}")
if [ "$merge_tree" = "$head_tree" ]; then
  echo "merge tree == PR head tree ($merge_tree): the PR run certified these bytes — main-CI wait skipped (#881)"
else
  echo "merge tree $merge_tree != PR head tree $head_tree — waiting for main CI on the merge"
  st=none
  for i in $(seq 1 150); do
    st=$(gh run list --branch main --commit "$merge_sha" --workflow ci.yml --json status,conclusion --jq '.[0] | "\(.status)/\(.conclusion)"' 2>/dev/null || echo none)
    echo "main CI: $st"; case "$st" in completed/success) break;; completed/*) echo "MAIN CI NOT GREEN: $st"; exit 5;; esac; sleep 60
  done
  [ "$st" = "completed/success" ] || { echo "main CI timeout"; exit 6; }
fi
tmp=$(mktemp -d)
git show "$merge_sha":CHANGELOG.md > "$tmp/cl.md"
prev=$(grep -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' "$tmp/cl.md" | sed 's/^## \[//; s/\]//' | awk -v v="$ver" '$0==v {f=1; next} f {print; exit}')
[ -n "$prev" ] || { echo "no section after [$ver] in CHANGELOG"; exit 7; }
esc() { printf '%s' "$1" | sed 's/\./\\./g'; }
awk -v s="^## \\[$(esc "$ver")\\]" -v e="^## \\[$(esc "$prev")\\]" '$0 ~ s {f=1} f && $0 ~ e {exit} f' "$tmp/cl.md" > "$tmp/tagbody.md"
[ -s "$tmp/tagbody.md" ] || { echo "empty tag body"; exit 7; }
git tag -a "v$ver" "$merge_sha" --cleanup=verbatim -F "$tmp/tagbody.md" || exit 8
[ "$(git rev-list -n1 "v$ver")" = "$merge_sha" ] || { echo "tag SHA mismatch"; exit 9; }
in_bytes=$(wc -c < "$tmp/tagbody.md"); out_bytes=$(git tag -l --format='%(contents)' "v$ver" | wc -c)
echo "tag body bytes in=$in_bytes stored=$out_bytes headings=$(git tag -l --format='%(contents)' "v$ver" | grep -c '^#')"
[ "$out_bytes" -ge "$in_bytes" ] || { echo "tag body LOST bytes"; exit 9; }
git push origin "v$ver" || exit 10; echo "tagged v$ver at $merge_sha"
sleep 90
st=none
for i in $(seq 1 120); do
  st=$(gh run list --event push --branch "v$ver" --json status,conclusion,workflowName --jq '[.[] | select(.workflowName=="CI")] | .[0] | "\(.status)/\(.conclusion)"' 2>/dev/null || echo none)
  echo "tag CI: $st"; case "$st" in completed/success) break;; completed/*) echo "TAG CI NOT GREEN: $st"; exit 11;; esac; sleep 60
done
[ "$st" = "completed/success" ] || { echo "tag CI timeout"; exit 12; }
for i in $(seq 1 30); do gh release view "v$ver" >/dev/null 2>&1 && break; sleep 10; done
gh release view "v$ver" >/dev/null 2>&1 || { echo "release v$ver never appeared"; exit 13; }
gh release view "v$ver" --json assets --jq '[.assets[].name] | join(", ")'
gh release edit "v$ver" --notes-file "$tmp/tagbody.md" >/dev/null || { echo "release edit failed"; exit 14; }
body_bytes=$(gh release view "v$ver" --json body --jq '.body | length')
echo "release body bytes=$body_bytes (tag body $in_bytes)"
[ "$body_bytes" -ge $(( in_bytes - 64 )) ] || { echo "release body too short — not the CHANGELOG section"; exit 15; }
echo "=== RELEASE_SHIP_DONE v$ver at $merge_sha ==="
