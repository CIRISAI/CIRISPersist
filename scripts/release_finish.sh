#!/usr/bin/env bash
# release_finish.sh — the last stage of a release: tag CI → GitHub release →
# release body. Split out of release_ship.sh so that neither half can hit a
# 2-hour background cap (v53.1.8: the ship script was killed at that cap while
# tag CI queued on macOS, and a hand-written script set the release body).
#
#   scripts/release_finish.sh <version> <tag-run-id>
#
# 1. checks <tag-run-id> is the CI run for tag v<version>;
# 2. waits for it to finish green. A run CANCELLED by the same-SHA
#    concurrency group (#397) is re-run, not refused — the backstop for the
#    tag/main ordering release_ship.sh sets up (v50 lesson, CIRISPersist#1008);
# 3. waits for the release to EXIST (tag CI creates it a moment after its last
#    job; an edit before that fails silently);
# 4. sets the release body from the tag's annotation and asserts its BYTES.
#
# Idempotent: re-run the same command after a kill or a timeout; it picks the
# run up wherever it is. FINISH_TIMEOUT_MIN (default 180) bounds the tag-CI wait.
#
# Exit codes: 2 bad arguments / run is not this tag's CI run · 11 tag CI not
# green · 12 tag CI timeout · 13 release never appeared · 14 release edit
# failed · 15 release body too short.
set -uo pipefail
ver="${1:?version}"; rid="${2:?tag CI run id}"
cd "$(git rev-parse --show-toplevel)" || exit 2
case "$rid" in *[!0-9]*|"") echo "tag run id must be numeric: $rid"; exit 2;; esac
info=$(gh run view "$rid" --json headBranch,event,workflowName --jq '"\(.headBranch) \(.event) \(.workflowName)"' 2>/dev/null) \
    || { echo "cannot read run $rid"; exit 2; }
[ "$info" = "v$ver push CI" ] || { echo "run $rid is '$info', not the CI push run for v$ver"; exit 2; }
git fetch -q origin "refs/tags/v$ver:refs/tags/v$ver" 2>/dev/null || true
git rev-parse -q --verify "refs/tags/v$ver" >/dev/null || { echo "tag v$ver not found locally or on origin"; exit 2; }
tmp=$(mktemp -d)
git tag -l --format='%(contents)' "v$ver" > "$tmp/tagbody.md"
in_bytes=$(wc -c < "$tmp/tagbody.md")
[ "$in_bytes" -gt 64 ] || { echo "tag v$ver annotation is $in_bytes bytes — not a CHANGELOG section"; exit 2; }

limit=$(( ${FINISH_TIMEOUT_MIN:-180} * 60 )); waited=0; st=none
while [ "$waited" -lt "$limit" ]; do
  st=$(gh run view "$rid" --json status,conclusion --jq '"\(.status)/\(.conclusion)"' 2>/dev/null || echo unknown)
  echo "tag CI $rid: $st ($(( waited / 60 )) min)"
  case "$st" in
    completed/success) break;;
    completed/cancelled)
      echo "tag run $rid cancelled by the same-SHA dedup — re-running"
      gh run rerun "$rid" >/dev/null 2>&1 || { echo "TAG CI NOT GREEN: $st (re-run refused)"; exit 11; }
      sleep 90; waited=$(( waited + 90 )); continue;;
    completed/*) echo "TAG CI NOT GREEN: $st — inspect run $rid"; exit 11;;
  esac
  sleep 60; waited=$(( waited + 60 ))
done
[ "$st" = "completed/success" ] || { echo "tag CI timeout after ${FINISH_TIMEOUT_MIN:-180} min (last: $st) — re-run this command to keep waiting"; exit 12; }

for i in $(seq 1 30); do gh release view "v$ver" >/dev/null 2>&1 && break; sleep 10; done
gh release view "v$ver" >/dev/null 2>&1 || { echo "release v$ver never appeared (5 min after tag CI)"; exit 13; }
gh release view "v$ver" --json assets --jq '"assets: " + ([.assets[].name] | join(", "))'
gh release edit "v$ver" --notes-file "$tmp/tagbody.md" >/dev/null || { echo "release edit failed"; exit 14; }
# BYTES, not characters: jq's `length` counts code points, and v49.0.0's
# section (85 more bytes than characters — em dashes, arrows) failed this
# check with a body byte-identical to the tag.
body_bytes=$(gh release view "v$ver" --json body --jq '.body' | wc -c)
echo "release body bytes=$body_bytes (tag body $in_bytes)"
[ "$body_bytes" -ge $(( in_bytes - 64 )) ] || { echo "release body too short — not the CHANGELOG section"; exit 15; }
echo "=== RELEASE_SHIP_DONE v$ver at $(git rev-list -n1 "v$ver") ==="
