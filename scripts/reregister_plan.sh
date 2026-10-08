#!/usr/bin/env bash
# reregister_plan.sh — the plan job of .github/workflows/reregister-manifests.yml:
# per version, WHICH tag CI run supplies the wheels, and which wheels must be
# rebuilt from the tag because no run still holds them.
#
#   env VERSIONS TARGETS MODE [DRY_RUN] GITHUB_REPOSITORY GITHUB_OUTPUT  scripts/reregister_plan.sh
#
# Writes `versions`, `rebuild` and `rebuild_versions` (JSON) to $GITHUB_OUTPUT.
#
# Selection. Among the version's push CI runs (newest 20), the run whose
# unexpired artifacts cover the MOST of the needed wheel labels wins; a tie
# goes to the newer run. Only the labels the chosen run lacks are rebuilt.
# Until the Codex review of PR #1039 the newest run holding ANY wheel won, so
# a later partial re-run (one matrix artifact) beat the original run holding
# all four, and three wheels were REBUILT: wheel bytes are not reproducible,
# so `check` then reports MISMATCH and a repost replaces correct rows. The
# per-run coverage table is printed.
#
# Needed labels: the requested targets' wheels; in repost mode all four,
# because repost verifies every reused wheel manifest against its wheel.
#
# Needs gh and jq. Witnessed by scripts/bits_changed_test.sh with a stub gh.
set -euo pipefail
: "${VERSIONS:?}" "${TARGETS:?}" "${MODE:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_OUTPUT:?}"
declare -A LABEL=([x86_64-unknown-linux-gnu]=linux-x86_64 [aarch64-unknown-linux-gnu]=linux-aarch64
                  [aarch64-apple-darwin]=darwin-aarch64 [x86_64-pc-windows-msvc]=windows-x86_64)
declare -A OS=([linux-x86_64]=ubuntu-latest [linux-aarch64]=ubuntu-24.04-arm
               [darwin-aarch64]=macos-14 [windows-x86_64]=windows-latest)
for t in $TARGETS; do
  [ "$t" = python-source-tree ] || [ -n "${LABEL[$t]:-}" ] || { echo "::error::not a target: $t"; exit 1; }
done
need_labels=""
for t in $TARGETS; do if [ -n "${LABEL[$t]:-}" ]; then need_labels="$need_labels ${LABEL[$t]}"; fi; done
[ "$MODE" = repost ] && need_labels="linux-x86_64 linux-aarch64 darwin-aarch64 windows-x86_64"
need_n=$(wc -w <<<"$need_labels")
read -ra vs <<<"$VERSIONS"
versions="[]"; rebuild="[]"; rebuild_versions="[]"
for v in "${vs[@]}"; do
  v="${v#v}"
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "::error::not a version: $v"; exit 1; }
  ids=$(gh run list -R "$GITHUB_REPOSITORY" --branch "v$v" --event push --workflow ci.yml \
          --json databaseId,createdAt --limit 20 --jq 'sort_by(.createdAt) | reverse | .[].databaseId')
  run=""; arts="[]"; best=-1
  echo "v$v: tag runs, newest first — needed wheels covered of $need_n [${need_labels# }]"
  for id in $ids; do
    a=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$id/artifacts?per_page=100" \
          --jq '[.artifacts[] | select(.expired == false) | .name]')
    have=0; held=""
    for l in $need_labels; do
      if jq -e --arg n "ciris_persist-wheel-$l" 'index($n)' <<<"$a" >/dev/null; then have=$((have + 1)); held="$held $l"; fi
    done
    echo "  run $id  $have/$need_n${held:+ [${held# }]}"
    # strictly greater: on a tie the newer run (seen first) stays
    if [ "$have" -gt "$best" ] && [ "$have" -gt 0 ]; then best=$have; run=$id; arts=$a; fi
  done
  bm=$(jq -r --arg n "ciris-persist-build-manifest-$v" 'if index($n) then "true" else "false" end' <<<"$arts")
  echo "v$v: tag run ${run:-NONE with an unexpired needed wheel artifact}${run:+ ($best/$need_n)}; build-manifest artifact: $bm"
  for l in $need_labels; do
    if jq -e --arg n "ciris_persist-wheel-$l" 'index($n)' <<<"$arts" >/dev/null; then
      echo "  $l: tag run $run artifact"
    else
      echo "::warning::v$v $l: no unexpired wheel artifact in the chosen run — the wheel will be REBUILT from the tag (CC 3.1.2.1 supersedes)"
      rebuild=$(jq -c --arg v "$v" --arg l "$l" --arg os "${OS[$l]}" '. + [{version:$v, label:$l, os:$os}]' <<<"$rebuild")
      rebuild_versions=$(jq -c --arg v "$v" 'if index($v) then . else . + [$v] end' <<<"$rebuild_versions")
    fi
  done
  versions=$(jq -c --arg v "$v" --arg r "$run" --arg bm "$bm" '. + [{version:$v, run:$r, bm:$bm}]' <<<"$versions")
done
{
  echo "versions=$versions"; echo "rebuild=$rebuild"; echo "rebuild_versions=$rebuild_versions"
} >> "$GITHUB_OUTPUT"
echo "mode=$MODE targets=[$TARGETS] dry_run=${DRY_RUN:-}"
