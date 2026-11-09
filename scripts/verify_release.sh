#!/usr/bin/env bash
# verify_release.sh — check a release's GitHub artifact attestations
# (CIRISPersist#1028). What tag CI's `attest` job signs, this reads back:
#
#   scripts/verify_release.sh v<version> [<tag-run-id>]     # or <version>
#
# The tag run id is what release_ship.sh printed and release_finish.sh holds;
# without it the newest successful CI push run of the tag is used.
#
# 1. downloads the three release tarballs (`ciris-persist-v<ver>-*.tar.gz`);
# 2. downloads each target's `ciris_persist-wheel-<label>` artifact from the
#    tag's CI run and keeps only `ciris_persist-<version>-*.whl`. The wheels
#    live nowhere else: not on PyPI (publishing stopped at 22.0.1, #615) and
#    not as release assets. GitHub expires artifacts after 90 days, so
#    VERIFY_SKIP_WHEELS=1 skips them for an older release, and says so;
# 3. fetches `evidence/cc_impl.tsv` at the tag;
# 3b. (61.1.0 on, CIRISPersist#1234) downloads the two linux wheels' split
#    debuginfo assets `ciris_persist-<ver>-linux-{x86_64,aarch64}.abi3.so.debug`
#    and the release's SHA256SUMS. Each debug file is a provenance subject in
#    step 4; SHA256SUMS must list it with its sha256; and, when the wheels were
#    downloaded, its GNU build-id must be the build-id of the .so inside that
#    target's wheel and the .so's `.gnu_debuglink` must name it — the debug
#    file describes THESE shipped bytes, not some other link;
# 4. runs `gh attestation verify` on each, bound to this repo, to ci.yml as the
#    signing workflow and to `refs/tags/v<ver>` as the source ref, so an
#    attestation from a branch or PR run does not count;
# 5. prints the cc-conformance predicate and checks its crate_version and
#    merge_sha against the tag;
# 6. runs scripts/bits_changed.sh on each desktop wheel (CIRISPersist#1029):
#    its METADATA Version and WHEEL Tag fit (version, target), its sha256 is
#    not the previous release's registered hash nor a known stale one, and
#    the registry's row for (version, target) carries exactly that sha256.
#    With VERIFY_SKIP_WHEELS=1 the bits are reported as NOT checked.
#
# Needs a gh with `gh attestation` (2.49+). GH=/path/to/gh selects one.
#
# Exit codes: 0 every subject verified · 1 a verification or predicate check
# failed (each is listed) · 2 usage, or gh lacks `gh attestation` · 3 a
# download failed (nothing was judged).
set -uo pipefail
v="${1:?usage: verify_release.sh v<version>}"; v="${v#v}"
case "$v" in *[!0-9.]*|"") echo "not a version: $1"; exit 2;; esac
rid="${2:-}"
case "$rid" in *[!0-9]*) echo "tag run id must be numeric: $rid"; exit 2;; esac
tag="v$v"
GH="${GH:-gh}"
repo="${VERIFY_REPO:-CIRISAI/CIRISPersist}"
workflow="$repo/.github/workflows/ci.yml"
cc_type="https://ciris.ai/attestation/cc-conformance/v1"

if ! "$GH" attestation verify --help >/dev/null 2>&1; then
  echo "gh at '$(command -v "$GH" || echo "$GH")' has no 'attestation' command ($("$GH" --version 2>/dev/null | head -1)); need gh 2.49+ — set GH=/path/to/newer/gh"
  exit 2
fi
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

"$GH" release download "$tag" -R "$repo" -p "ciris-persist-$tag-*.tar.gz" -D "$tmp/release" \
  || { echo "DOWNLOAD FAILED: release assets of $tag"; exit 3; }
n=$(find "$tmp/release" -name '*.tar.gz' | wc -l)
[ "$n" -eq 3 ] || { echo "DOWNLOAD FAILED: expected 3 release tarballs for $tag, found $n"; exit 3; }

# 3b. The linux debuginfo (#1234): releases from 61.1.0 carry it.
debug_labels=(linux-x86_64 linux-aarch64)
has_debug=0
[ "$(printf '%s\n' 61.1.0 "$v" | sort -V | head -1)" = 61.1.0 ] && has_debug=1
if [ "$has_debug" = 1 ]; then
  "$GH" release download "$tag" -R "$repo" -p "ciris_persist-$v-linux-*.abi3.so.debug" -p SHA256SUMS -D "$tmp/debug" \
    || { echo "DOWNLOAD FAILED: debuginfo assets / SHA256SUMS of $tag"; exit 3; }
  for label in "${debug_labels[@]}"; do
    [ -s "$tmp/debug/ciris_persist-$v-$label.abi3.so.debug" ] \
      || { echo "DOWNLOAD FAILED: ciris_persist-$v-$label.abi3.so.debug is not an asset of $tag"; exit 3; }
  done
  [ -s "$tmp/debug/SHA256SUMS" ] || { echo "DOWNLOAD FAILED: SHA256SUMS of $tag"; exit 3; }
else
  echo "SKIP  linux debuginfo: $tag predates 61.1.0 (#1234), which first shipped it"
fi

if [ "${VERIFY_SKIP_WHEELS:-0}" = 1 ]; then
  echo "SKIP  desktop wheels (VERIFY_SKIP_WHEELS=1) — their provenance is NOT checked"
else
  if [ -z "$rid" ]; then
    rid=$("$GH" run list -R "$repo" --branch "$tag" --event push --workflow ci.yml \
            --json databaseId,conclusion --jq '[.[] | select(.conclusion == "success")][0].databaseId // empty')
    [ -n "$rid" ] || { echo "DOWNLOAD FAILED: no successful CI push run for $tag"; exit 3; }
  fi
  echo "wheels: tag run $rid's ciris_persist-wheel-<label> artifacts"
  for label in linux-x86_64 linux-aarch64 darwin-aarch64 windows-x86_64; do
    "$GH" run download "$rid" -R "$repo" -n "ciris_persist-wheel-$label" -D "$tmp/wheels/ciris_persist-wheel-$label" \
      || { echo "DOWNLOAD FAILED: ciris_persist-wheel-$label of run $rid (expired after 90 days? VERIFY_SKIP_WHEELS=1)"; exit 3; }
  done
  # Only this version's wheels: through v53.1.8 the artifacts also carried
  # stale wheels restored from the build cache.
  find "$tmp/wheels" -name '*.whl' ! -name "ciris_persist-$v-*.whl" -delete
  n=$(find "$tmp/wheels" -name '*.whl' | wc -l)
  [ "$n" -eq 4 ] || { echo "DOWNLOAD FAILED: expected 4 ciris_persist-$v wheels in run $rid, found $n"; exit 3; }
fi

"$GH" api -H 'Accept: application/vnd.github.raw' "repos/$repo/contents/evidence/cc_impl.tsv?ref=$tag" \
  > "$tmp/cc_impl.tsv" || { echo "DOWNLOAD FAILED: evidence/cc_impl.tsv at $tag"; exit 3; }
[ -s "$tmp/cc_impl.tsv" ] || { echo "DOWNLOAD FAILED: evidence/cc_impl.tsv at $tag is empty"; exit 3; }

bind=(-R "$repo" --signer-workflow "$workflow" --source-ref "refs/tags/$tag")
fails=0
while IFS= read -r f; do
  if "$GH" attestation verify "$f" "${bind[@]}" >/dev/null 2>"$tmp/err"; then
    echo "ok    provenance  $(basename "$f")"
  else
    echo "FAIL  provenance  $(basename "$f"): $(tail -1 "$tmp/err")"; fails=$((fails + 1))
  fi
done < <(find "$tmp/release" "$tmp/wheels" "$tmp/debug" -type f \( -name '*.tar.gz' -o -name '*.whl' -o -name '*.abi3.so.debug' \) 2>/dev/null | sort)

# 3b. Each debug file: listed in SHA256SUMS with its hash, and the companion of
# the .so its target's wheel ships (same build-id, debuglink names it).
build_id() { readelf -n -W "$1" 2>/dev/null | sed -n 's/.*Build ID: *\([0-9a-f]*\).*/\1/p' | head -1; }
if [ "$has_debug" = 1 ]; then
  for label in "${debug_labels[@]}"; do
    name="ciris_persist-$v-$label.abi3.so.debug"; f="$tmp/debug/$name"
    want=$(sha256sum "$f" | cut -d' ' -f1)
    listed=$(awk -v n="$name" '{ f = $2; sub(/^\*/, "", f) } f == n { print $1 }' "$tmp/debug/SHA256SUMS")
    if [ "$listed" = "$want" ]; then
      echo "ok    sha256sums  $name"
    else
      echo "FAIL  sha256sums  $name: SHA256SUMS lists '${listed:-nothing}', the asset is $want"; fails=$((fails + 1))
    fi
    if [ "${VERIFY_SKIP_WHEELS:-0}" = 1 ]; then
      echo "SKIP  debuginfo   $name: no wheel to match its build-id against (VERIFY_SKIP_WHEELS=1)"
      continue
    fi
    if ! command -v readelf >/dev/null; then
      echo "FAIL  debuginfo   $name: no readelf to read build-ids with"; fails=$((fails + 1)); continue
    fi
    whl=$(find "$tmp/wheels/ciris_persist-wheel-$label" -name "ciris_persist-$v-*.whl" | head -1)
    mkdir -p "$tmp/so/$label"
    if [ -z "$whl" ] || ! python3 -c 'import sys, zipfile
z = zipfile.ZipFile(sys.argv[1]); m = [n for n in z.namelist() if n.endswith(".abi3.so")]
assert len(m) == 1, m
open(sys.argv[2], "wb").write(z.read(m[0]))' "$whl" "$tmp/so/$label/shipped.so" 2>"$tmp/err"; then
      echo "FAIL  debuginfo   $name: cannot read the .so of the $label wheel: $(tail -1 "$tmp/err")"; fails=$((fails + 1)); continue
    fi
    so_id=$(build_id "$tmp/so/$label/shipped.so"); dbg_id=$(build_id "$f")
    link=$(readelf --string-dump=.gnu_debuglink "$tmp/so/$label/shipped.so" 2>/dev/null | sed -n 's/^ *\[ *0\] *//p' | head -1)
    if [ -n "$so_id" ] && [ "$so_id" = "$dbg_id" ] && [ "$link" = "$name" ]; then
      echo "ok    debuginfo   $name: build-id $so_id is the $label wheel's .so, whose debuglink names it"
    else
      echo "FAIL  debuginfo   $name: build-id '${dbg_id:-none}' vs the $label wheel's .so '${so_id:-none}', debuglink '${link:-none}'"
      fails=$((fails + 1))
    fi
  done
fi

if pred=$("$GH" attestation verify "$tmp/cc_impl.tsv" "${bind[@]}" --predicate-type "$cc_type" \
            --format json --jq '.[0].verificationResult.statement.predicate' 2>"$tmp/err"); then
  echo "ok    cc-conformance  evidence/cc_impl.tsv sha256 $(sha256sum "$tmp/cc_impl.tsv" | cut -d' ' -f1)"
  echo "      predicate $pred"
  got_ver=$(printf '%s' "$pred" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("crate_version",""))')
  [ "$got_ver" = "$v" ] || { echo "FAIL  predicate crate_version '$got_ver' != $v"; fails=$((fails + 1)); }
  tag_sha=$("$GH" api "repos/$repo/commits/$tag" --jq .sha 2>/dev/null || true)
  got_sha=$(printf '%s' "$pred" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("merge_sha",""))')
  [ -n "$tag_sha" ] && [ "$got_sha" = "$tag_sha" ] \
    || { echo "FAIL  predicate merge_sha '$got_sha' != $tag's commit '$tag_sha'"; fails=$((fails + 1)); }
else
  echo "FAIL  cc-conformance  evidence/cc_impl.tsv: $(tail -1 "$tmp/err")"; fails=$((fails + 1))
fi

# 6. did the bits change, and does the registry carry them (#1029)?
here="$(cd "$(dirname "$0")" && pwd)"
bits_note="every wheel's bits checked against the registry"
declare -A TARGET_OF=(
  [linux-x86_64]=x86_64-unknown-linux-gnu [linux-aarch64]=aarch64-unknown-linux-gnu
  [darwin-aarch64]=aarch64-apple-darwin [windows-x86_64]=x86_64-pc-windows-msvc
)
bits() {  # $1 label, then bits_changed.sh's arguments after <version> <target>
  local label="$1" t; shift; t="${TARGET_OF[$label]}"
  for mode in "" --after-publish; do
    if "$here/bits_changed.sh" $mode "$v" "$t" "$@" >"$tmp/bits" 2>&1; then
      echo "ok    bits${mode:+ (registered)}  $label: $(tail -1 "$tmp/bits" | cut -c1-120)"
    else
      echo "FAIL  bits${mode:+ (registered)}  $label: $(grep -m1 '^FAIL' "$tmp/bits" || tail -1 "$tmp/bits")"; fails=$((fails + 1))
    fi
  done
}
if [ "${VERIFY_SKIP_WHEELS:-0}" != 1 ]; then
  for label in "${!TARGET_OF[@]}"; do bits "$label" "$tmp/wheels/ciris_persist-wheel-$label"; done
else
  echo "SKIP  bits  (VERIFY_SKIP_WHEELS=1) — the registered wheel hashes are NOT checked"
  bits_note="the wheels' bits were NOT checked"
fi

if [ "$fails" -ne 0 ]; then echo "VERIFY RELEASE $tag: $fails FAILED"; exit 1; fi
echo "VERIFY RELEASE $tag: every attestation verified; $bits_note"
