#!/usr/bin/env bash
# check_vendored_cc.sh — the ship-time gate on the vendored CC manifests.
#
#   scripts/check_vendored_cc.sh [--commit-only] [<cc-tag>]
#   CC_REPO=<url-or-path> scripts/check_vendored_cc.sh [--commit-only] [<cc-tag>]
#
# Persist vendors these CIRISConstitution files byte-for-byte:
#
#   manifests/namespace_registry.json          -> src/federation/namespace/namespace_registry.json
#   manifests/namespace_match_vectors.json     -> src/federation/namespace/namespace_match_vectors.json
#   manifests/governance_policy.json           -> src/federation/namespace/governance_policy.json      (v60.0.0)
#   manifests/governance_policy_vectors.json   -> src/federation/namespace/governance_policy_vectors.json
#   manifests/csd4_chain.json                  -> src/federation/namespace/csd4_chain.json
#   manifests/topology_vocabulary.json         -> src/federation/namespace/topology_vocabulary.json
#   manifests/signed_object_vectors.json       -> src/federation/namespace/signed_object_vectors.json  (v61.0.0)
#   manifests/family_model.json                -> src/federation/namespace/family_model.json           (v62.0.0, FS-step1)
#   formal/self_roster/traces/*.json           -> tests/fixtures/self_roster/*.json (the six traces)
#
# (pins: registry.rs and cc_manifests.rs; the from-disk witness I1302 checks
# the same property against a local CC checkout when one is present.)
#
# The vendor is taken BY COMMIT (`registry.rs#VENDORED_CC_COMMIT`), which can
# precede the CC release tag; `registry.rs#VENDORED_CC_TAG` records the tag
# (`CcTag::Recorded("<tag>")`) or that it is still pending (`CcTag::Pending`).
#
# v62.0.0 (4r) — the PENDING form is a real check that fails closed:
#   - RECORDED: fetch CC at the tag; the tag must name VENDORED_CC_COMMIT, and
#     every file must be the tag's bytes. A <cc-tag> argument must equal the
#     recorded tag.
#   - PENDING: fetch CC at VENDORED_CC_COMMIT and compare every file byte for
#     byte (exit 1 on any difference); if any CC tag now names the commit,
#     FAIL (exit 4: record it); otherwise exit 3, "CC tag pending" — the
#     release refuses. `--commit-only` turns that last exit into a PASS that
#     says PENDING (for checking a vendor before the tag exists; never for a
#     release). A <cc-tag> argument while pending is a FAIL (exit 2).
# It exits non-zero on any difference, a missing tag or commit, or a fetch
# failure — never "could not look, so fine". Run it before cutting a persist
# release; `scripts/release_ship.sh` refuses a pending tag on its own (exit 17).
# It needs the network, so it is a ship step and is NOT wired into CI.
set -euo pipefail
commit_only=0
if [ "${1:-}" = "--commit-only" ]; then commit_only=1; shift; fi
want_tag="${1:-}"
repo="${CC_REPO:-https://github.com/CIRISAI/CIRISConstitution.git}"
root="$(git rev-parse --show-toplevel)"
dir="$root/src/federation/namespace"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

pinned="$(sed -n 's/^pub const VENDORED_CC_COMMIT: &str = "\([0-9a-f]*\)";$/\1/p' "$dir/registry.rs")"
[ "${#pinned}" -eq 40 ] || { echo "FAIL: VENDORED_CC_COMMIT (a full commit id) not found in registry.rs" >&2; exit 2; }
tag_line="$(grep '^pub const VENDORED_CC_TAG: CcTag = ' "$dir/registry.rs" || true)"
case "$tag_line" in
  'pub const VENDORED_CC_TAG: CcTag = CcTag::Pending;') tag="" ;;
  'pub const VENDORED_CC_TAG: CcTag = CcTag::Recorded("'*'");')
    tag="${tag_line#*Recorded(\"}"; tag="${tag%\");}" ;;
  *) echo "FAIL: cannot read VENDORED_CC_TAG in registry.rs: ${tag_line:-<absent>}" >&2; exit 2 ;;
esac
if [ -z "$tag" ] && [ -n "$want_tag" ]; then
  echo "FAIL: asked for $want_tag, but registry.rs records the CC tag as PENDING (vendored at $pinned)" >&2
  exit 2
fi
if [ -n "$tag" ] && [ -n "$want_tag" ] && [ "$want_tag" != "$tag" ]; then
  echo "FAIL: asked for $want_tag, but registry.rs records the CC tag $tag" >&2
  exit 2
fi

git init -q --bare "$tmp/cc"
if [ -n "$tag" ]; then
  if ! git -C "$tmp/cc" fetch -q --depth 1 "$repo" "refs/tags/$tag:refs/tags/$tag"; then
    echo "FAIL: could not fetch tag $tag from $repo" >&2
    exit 2
  fi
  sha="$(git -C "$tmp/cc" rev-parse "refs/tags/$tag^{commit}")"
  at="$tag"
  echo "CC $tag = $sha"
else
  if ! git -C "$tmp/cc" fetch -q --depth 1 "$repo" "$pinned"; then
    echo "FAIL: could not fetch commit $pinned from $repo" >&2
    exit 2
  fi
  sha="$pinned"
  at="$pinned"
  echo "CC tag PENDING; checking commit $pinned"
fi
echo "vendored at $pinned"

rc=0
n=0
compare() {  # <path in CC at the tag> <local path>
  local cc_path="$1" local_path="$2" name
  name="$(echo "$cc_path" | tr / _)"
  n=$((n + 1))
  if ! git -C "$tmp/cc" show "$sha:$cc_path" > "$tmp/$name"; then
    echo "FAIL: $at carries no $cc_path" >&2; rc=1; return
  fi
  if [ ! -f "$local_path" ]; then
    echo "FAIL: no vendored copy at ${local_path#"$root"/}" >&2; rc=1; return
  fi
  want="$(sha256sum "$tmp/$name" | cut -d' ' -f1)"
  have="$(sha256sum "$local_path" | cut -d' ' -f1)"
  if cmp -s "$tmp/$name" "$local_path"; then
    echo "ok    $cc_path  sha256 $have"
  else
    echo "DIFF  $cc_path  vendored $have  !=  $at $want" >&2
    rc=1
  fi
}
for f in namespace_registry.json namespace_match_vectors.json governance_policy.json \
         governance_policy_vectors.json csd4_chain.json topology_vocabulary.json \
         signed_object_vectors.json family_model.json; do
  compare "manifests/$f" "$dir/$f"
done
for f in "$root"/tests/fixtures/self_roster/*.json; do
  compare "formal/self_roster/traces/$(basename "$f")" "$f"
done

if [ "$rc" -ne 0 ]; then
  echo "FAIL: the vendored CC files are not $at's bytes — re-vendor from it before shipping" >&2
  exit 1
fi
if [ -n "$tag" ]; then
  if [ "$sha" != "$pinned" ]; then
    echo "FAIL: the bytes match, but $tag is commit $sha and VENDORED_CC_COMMIT names $pinned —" \
         "re-pin the commit (and regenerate the binds with gen_namespace_match_binds.py) so the record names the tag's commit" >&2
    exit 1
  fi
  echo "PASS: all $n vendored files are byte-identical to CIRISConstitution $tag ($sha)"
  exit 0
fi
# PENDING: the bytes are the commit's. A tag CC has since cut must be recorded.
named="$(git ls-remote --tags "$repo" | awk -v c="$pinned" '$1 == c { sub("refs/tags/", "", $2); sub("\\^\\{\\}$", "", $2); print $2 }' | sort -u | tr '\n' ' ')"
if [ -n "$named" ]; then
  echo "FAIL: CC tag(s) $named name the vendored commit $pinned — record it in registry.rs (VENDORED_CC_TAG = CcTag::Recorded(\"<tag>\"))" >&2
  exit 4
fi
if [ "$commit_only" -eq 1 ]; then
  echo "PENDING: all $n vendored files are byte-identical to CIRISConstitution $pinned; no CC tag names it yet (--commit-only: not a release check)"
  exit 0
fi
echo "FAIL: CC tag pending — all $n vendored files equal $pinned, but no tag is recorded; a persist release waits for the tag (or run with --commit-only to check the bytes alone)" >&2
exit 3
