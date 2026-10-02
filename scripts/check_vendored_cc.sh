#!/usr/bin/env bash
# check_vendored_cc.sh — the ship-time gate on the vendored CC manifests.
#
#   scripts/check_vendored_cc.sh <cc-tag>          # e.g. v1.0-rc6
#   CC_REPO=<url-or-path> scripts/check_vendored_cc.sh <cc-tag>
#
# Persist vendors two CIRISConstitution files byte-for-byte:
#
#   manifests/namespace_registry.json      -> src/federation/namespace/namespace_registry.json
#   manifests/namespace_match_vectors.json -> src/federation/namespace/namespace_match_vectors.json
#
# The vendor is taken BY COMMIT (`registry.rs#VENDORED_CC_COMMIT`), which can
# precede the CC release tag. This script fetches CC at <cc-tag> and compares
# both files to the vendored copies byte for byte; it exits non-zero on any
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
for f in namespace_registry.json namespace_match_vectors.json; do
  if ! git -C "$tmp/cc" show "$sha:manifests/$f" > "$tmp/$f"; then
    echo "FAIL: $tag carries no manifests/$f" >&2; rc=1; continue
  fi
  want="$(sha256sum "$tmp/$f" | cut -d' ' -f1)"
  have="$(sha256sum "$dir/$f" | cut -d' ' -f1)"
  if cmp -s "$tmp/$f" "$dir/$f"; then
    echo "ok    $f  sha256 $have"
  else
    echo "DIFF  $f  vendored $have  !=  $tag $want" >&2
    rc=1
  fi
done

if [ "$rc" -ne 0 ]; then
  echo "FAIL: the vendored CC files are not $tag's bytes — re-vendor from the tag before shipping" >&2
  exit 1
fi
if [ "$sha" != "$pinned" ]; then
  echo "note: the bytes match, but $tag is commit $sha and VENDORED_CC_COMMIT names $pinned —" \
       "re-pin the commit (and regenerate the binds with gen_namespace_match_binds.py) so the record names the tag's commit"
fi
echo "PASS: both vendored files are byte-identical to CIRISConstitution $tag"
