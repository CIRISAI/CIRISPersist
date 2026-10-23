#!/usr/bin/env bash
# check_vendored_cc.sh — the ship-time gate on the vendored CC manifests.
#
#   scripts/check_vendored_cc.sh <cc-tag>          # e.g. v1.0-rc6
#   CC_REPO=<url-or-path> scripts/check_vendored_cc.sh <cc-tag>
#
# Persist vendors these CIRISConstitution files byte-for-byte:
#
#   manifests/namespace_registry.json          -> src/federation/namespace/namespace_registry.json
#   manifests/namespace_match_vectors.json     -> src/federation/namespace/namespace_match_vectors.json
#   manifests/governance_policy.json           -> src/federation/namespace/governance_policy.json      (v60.0.0)
#   manifests/governance_policy_vectors.json   -> src/federation/namespace/governance_policy_vectors.json
#   manifests/csd4_chain.json                  -> src/federation/namespace/csd4_chain.json
#   manifests/topology_vocabulary.json         -> src/federation/namespace/topology_vocabulary.json
#   formal/self_roster/traces/*.json           -> tests/fixtures/self_roster/*.json (the six traces)
#
# (pins: registry.rs and cc_manifests.rs; the from-disk witness I1302 checks
# the same property against a local CC checkout when one is present.)
#
# The vendor is taken BY COMMIT (`registry.rs#VENDORED_CC_COMMIT`), which can
# precede the CC release tag. This script fetches CC at <cc-tag> and compares
# every file to its vendored copy byte for byte; it exits non-zero on any
# difference, on a missing tag, or on a fetch failure — never "could not look,
# so fine". Run it before cutting a persist release that names a CC version.
# It needs the network, so it is a ship step and is NOT wired into CI.
set -euo pipefail
tag="${1:?usage: check_vendored_cc.sh <cc-tag>  (e.g. v1.0-rc6)}"
repo="${CC_REPO:-https://github.com/CIRISAI/CIRISConstitution.git}"
root="$(git rev-parse --show-toplevel)"
dir="$root/src/federation/namespace"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

git init -q --bare "$tmp/cc"
if ! git -C "$tmp/cc" fetch -q --depth 1 "$repo" "refs/tags/$tag:refs/tags/$tag"; then
  echo "FAIL: could not fetch tag $tag from $repo" >&2
  exit 2
fi
sha="$(git -C "$tmp/cc" rev-parse "refs/tags/$tag^{commit}")"
pinned="$(sed -n 's/^pub const VENDORED_CC_COMMIT: &str = "\([0-9a-f]*\)";$/\1/p' "$dir/registry.rs")"
[ -n "$pinned" ] || { echo "FAIL: VENDORED_CC_COMMIT not found in registry.rs" >&2; exit 2; }
echo "CC $tag = $sha"
echo "vendored at $pinned"

rc=0
n=0
compare() {  # <path in CC at the tag> <local path>
  local cc_path="$1" local_path="$2" name
  name="$(echo "$cc_path" | tr / _)"
  n=$((n + 1))
  if ! git -C "$tmp/cc" show "$sha:$cc_path" > "$tmp/$name"; then
    echo "FAIL: $tag carries no $cc_path" >&2; rc=1; return
  fi
  if [ ! -f "$local_path" ]; then
    echo "FAIL: no vendored copy at ${local_path#"$root"/}" >&2; rc=1; return
  fi
  want="$(sha256sum "$tmp/$name" | cut -d' ' -f1)"
  have="$(sha256sum "$local_path" | cut -d' ' -f1)"
  if cmp -s "$tmp/$name" "$local_path"; then
    echo "ok    $cc_path  sha256 $have"
  else
    echo "DIFF  $cc_path  vendored $have  !=  $tag $want" >&2
    rc=1
  fi
}
for f in namespace_registry.json namespace_match_vectors.json governance_policy.json \
         governance_policy_vectors.json csd4_chain.json topology_vocabulary.json; do
  compare "manifests/$f" "$dir/$f"
done
for f in "$root"/tests/fixtures/self_roster/*.json; do
  compare "formal/self_roster/traces/$(basename "$f")" "$f"
done

if [ "$rc" -ne 0 ]; then
  echo "FAIL: the vendored CC files are not $tag's bytes — re-vendor from the tag before shipping" >&2
  exit 1
fi
if [ "$sha" != "$pinned" ]; then
  echo "note: the bytes match, but $tag is commit $sha and VENDORED_CC_COMMIT names $pinned —" \
       "re-pin the commit (and regenerate the binds with gen_namespace_match_binds.py) so the record names the tag's commit"
fi
echo "PASS: all $n vendored files are byte-identical to CIRISConstitution $tag"
