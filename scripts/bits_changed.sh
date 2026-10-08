#!/usr/bin/env bash
# bits_changed.sh — did the bits change? (CIRISPersist#1029)
#
# Through v53.1.8 the tag job signed and registered `ls *.whl | head -1`, and a
# cache-restored `target/wheels/` put a v29.0.0 wheel first: the registry
# vouched for v29 bytes under the v53.1.8 name on two targets. This gate asks,
# per (version, target), the questions that would have refused that:
#
#   1. exactly ONE `ciris_persist-<version>-*.whl` for the target's platform tag
#      is in the directory (0 or 2+ fails and lists the files);
#   2. the wheel's own `*.dist-info/METADATA` `Version:` is <version>, and every
#      `Tag:` line in its `WHEEL` file fits the target;
#   3. sha256(wheel) differs from the hash the registry holds for the PREVIOUS
#      release on this target (a 404 there = first release on the target);
#   4. sha256(wheel) is not a known stale hash
#      (evidence/manifest_remediation/known_stale_hashes.txt), unless that line
#      names <version> as the hash's true version;
#   5. (--after-publish) the registry's row for (<version>, target) carries
#      exactly sha256(wheel).
#
#   scripts/bits_changed.sh [opts] <version> <target> <wheel-dir-or-file>
#   scripts/bits_changed.sh [opts] <version> <target> --sha256 <hex> --filename <name>
#   scripts/bits_changed.sh [opts] <version> python-source-tree --sha256 <tree-hash>
#
# python-source-tree (the fifth registered target, a hash over
# python/ciris_persist) skips checks 1-2. Check 3 lets its hash equal the
# previous release's ONLY when `git diff --quiet v<prev> v<version> --
# python/ciris_persist` is empty, and says so (before the tag exists, on a PR
# or main run, HEAD stands in for v<version> and the line names it); a wheel
# never gets that exemption, because a wheel embeds its version.
#
#   --after-publish             run 1, 2, 5 instead of 1-4
#   --attestation-digest <hex>  also assert sha256(wheel) == <hex>
#   --prev <version>            previous release (default: $BITS_CHANGED_PREV, else
#                               the newest v-tag below <version>, from `git tag`,
#                               else `git ls-remote`)
#   --sha256 <hex> --filename <name>
#                               judge a published file by its digest (PyPI
#                               lists one per file) without the bytes: check 1
#                               is skipped and check 2 reads the filename only
#
# Env: BITS_CHANGED_REGISTRY_BASE (default https://us.registry.ciris-services-1.ai),
# BITS_CHANGED_DENYLIST (default <repo>/evidence/manifest_remediation/known_stale_hashes.txt),
# BITS_CHANGED_RETRIES (default 4; 429/5xx/connection errors are retried,
# honouring Retry-After up to 60 s).
#
# Exit codes (one line of reason each):
#   0 every check passed        2 usage
#  10 check 1: not exactly one wheel for the target
#  11 check 2: METADATA Version missing or != <version>
#  12 check 2: WHEEL Tag (or filename tag) does not fit the target
#  13 check 3: same bytes as the previous release's registered row
#  14 check 4: a known stale hash
#  15 check 5: the registered row's binary_hash != sha256(wheel), or no row
#  16 --attestation-digest != sha256(wheel)
#  17 a registry read failed (not 200, not a 404 where 404 is allowed)
#  18 no previous version could be determined
set -uo pipefail

usage() { sed -n '2,/^set -uo/p' "$0" | sed 's/^# \{0,1\}//; /^set -uo/d' >&2; exit 2; }
die() { local code="$1"; shift; echo "FAIL  $*"; exit "$code"; }

after_publish=0; att=""; prev="${BITS_CHANGED_PREV:-}"; given_sha=""; given_name=""; pos=()
while [ $# -gt 0 ]; do
  case "$1" in
    --after-publish) after_publish=1; shift;;
    --attestation-digest) att="${2:-}"; shift 2 || usage;;
    --prev) prev="${2:-}"; shift 2 || usage;;
    --sha256) given_sha="${2:-}"; shift 2 || usage;;
    --filename) given_name="${2:-}"; shift 2 || usage;;
    -h|--help) usage;;
    --*) echo "unknown flag: $1" >&2; exit 2;;
    *) pos+=("$1"); shift;;
  esac
done
ver="${pos[0]:-}"; target="${pos[1]:-}"; src="${pos[2]:-}"
ver="${ver#v}"
case "$ver" in ""|*[!0-9.]*) echo "usage: version '$ver' is not N.N.N" >&2; exit 2;; esac
is_tree=0; [ "$target" = python-source-tree ] && is_tree=1
if [ "$is_tree" = 1 ]; then
  if [ -z "$given_sha" ] || [ -n "$given_name" ] || [ -n "$src" ]; then
    echo "usage: python-source-tree is not a wheel: pass its tree hash as --sha256 <hex>, nothing else" >&2; exit 2
  fi
  given_sha="${given_sha#sha256:}"
  [[ "$given_sha" =~ ^[0-9a-f]{64}$ ]] || { echo "usage: --sha256 is not 64 hex: $given_sha" >&2; exit 2; }
elif [ -n "$given_sha" ] || [ -n "$given_name" ]; then
  if [ -z "$given_sha" ] || [ -z "$given_name" ] || [ -n "$src" ]; then
    echo "usage: --sha256 and --filename go together, in place of a wheel path" >&2; exit 2
  fi
  given_sha="${given_sha#sha256:}"
  [[ "$given_sha" =~ ^[0-9a-f]{64}$ ]] || { echo "usage: --sha256 is not 64 hex: $given_sha" >&2; exit 2; }
else
  [ -n "$src" ] || usage
fi
if [ -n "$att" ]; then
  att="${att#sha256:}"
  [[ "$att" =~ ^[0-9a-f]{64}$ ]] || { echo "usage: --attestation-digest is not 64 hex: $att" >&2; exit 2; }
fi

# The target triple ↔ wheel platform tag map. A tag fits when it matches the
# glob; a filename's compressed tag set (a.b) must fit in every member.
case "$target" in
  aarch64-unknown-linux-gnu) plat_glob='manylinux*_aarch64';;
  x86_64-unknown-linux-gnu)  plat_glob='manylinux*_x86_64';;
  x86_64-pc-windows-msvc)    plat_glob='win_amd64';;
  aarch64-apple-darwin)      plat_glob='macosx*_arm64';;
  python-source-tree)        plat_glob='';;
  *) echo "usage: unknown target '$target' (aarch64-unknown-linux-gnu, x86_64-unknown-linux-gnu, x86_64-pc-windows-msvc, aarch64-apple-darwin, python-source-tree)" >&2; exit 2;;
esac
plat_fits() {  # $1 = platform tag, possibly a compressed set a.b.c
  local p; local IFS=.
  [ -n "$1" ] || return 1
  for p in $1; do
    # shellcheck disable=SC2053  # the right side IS a glob
    [[ "$p" == $plat_glob ]] || return 1
  done
}
name_plat() { local b="${1%.whl}"; echo "${b##*-}"; }  # last dash field of a wheel name

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
base="${BITS_CHANGED_REGISTRY_BASE:-https://us.registry.ciris-services-1.ai}"; base="${base%/}"
denylist="${BITS_CHANGED_DENYLIST:-$repo_root/evidence/manifest_remediation/known_stale_hashes.txt}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# The paths the python-source-tree manifest hashes (build_manifest.sh signs
# `--tree python/ --tree-include ciris_persist`).
TREE_PATHS="python/ciris_persist"

# ── 1. exactly one wheel for (version, target) ──────────────────────────────
if [ "$is_tree" = 1 ]; then
  wheel_name="python-source-tree"
  echo "skip  1  python-source-tree is not a wheel: judging its tree hash ($TREE_PATHS)"
elif [ -n "$given_sha" ]; then
  wheel_name="$given_name"
  echo "skip  1  no bytes (--sha256): judging $wheel_name by its published digest"
else
  if [ -d "$src" ]; then
    cands=()
    mapfile -t all < <(find "$src" -maxdepth 1 -type f -name "ciris_persist-${ver}-*.whl" | sort)  # bits:select
    for f in "${all[@]}"; do plat_fits "$(name_plat "$(basename "$f")")" && cands+=("$f"); done
    if [ "${#cands[@]}" -ne 1 ]; then
      echo "      in $src: $(find "$src" -maxdepth 1 -name '*.whl' -printf '%f ' 2>/dev/null)"
      die 10 "1  ${#cands[@]} ciris_persist-${ver} wheels for $target ($plat_glob) in $src; need exactly 1"
    fi
    wheel="${cands[0]}"
  elif [ -f "$src" ]; then
    wheel="$src"
    b="$(basename "$wheel")"
    if [[ "$b" != "ciris_persist-${ver}-"*.whl ]] || ! plat_fits "$(name_plat "$b")"; then
      die 10 "1  $b is not a ciris_persist-${ver} wheel for $target ($plat_glob)"
    fi
  else
    die 10 "1  no such wheel dir or file: $src"
  fi
  wheel_name="$(basename "$wheel")"
  echo "ok    1  $wheel_name"
fi

# ── 2. the wheel's own identity ─────────────────────────────────────────────
if [ "$is_tree" = 1 ]; then
  echo "skip  2  no METADATA or WHEEL in a source tree"
  sha="$given_sha"
elif [ -n "$given_sha" ]; then
  # ciris_persist-<ver>-<python>-<abi>-<plat>.whl: no bytes, so the filename.
  fver="$(echo "$wheel_name" | cut -d- -f2)"
  [ "$fver" = "$ver" ] || die 11 "2  filename $wheel_name names version '$fver', not $ver"
  plat_fits "$(name_plat "$wheel_name")" || die 12 "2  filename $wheel_name tag '$(name_plat "$wheel_name")' does not fit $target ($plat_glob)"
  echo "ok    2  filename names $ver for $target (no METADATA: bytes not fetched)"
  sha="$given_sha"
else
  meta="$(unzip -Z1 "$wheel" 2>/dev/null | grep -E '^[^/]+\.dist-info/METADATA$' || true)"
  whl="$(unzip -Z1 "$wheel" 2>/dev/null | grep -E '^[^/]+\.dist-info/WHEEL$' || true)"
  [ "$(printf '%s\n' "$meta" | grep -c .)" -eq 1 ] || die 11 "2  $wheel_name has $(printf '%s\n' "$meta" | grep -c .) dist-info/METADATA files, need 1"
  [ "$(printf '%s\n' "$whl" | grep -c .)" -eq 1 ] || die 12 "2  $wheel_name has $(printf '%s\n' "$whl" | grep -c .) dist-info/WHEEL files, need 1"
  mver="$(unzip -p "$wheel" "$meta" | tr -d '\r' | sed -n 's/^Version: *//p' | head -1)"
  [ "$mver" = "$ver" ] || die 11 "2  $wheel_name METADATA Version '$mver' != $ver"
  tags="$(unzip -p "$wheel" "$whl" | tr -d '\r' | sed -n 's/^Tag: *//p')"
  [ -n "$tags" ] || die 12 "2  $wheel_name WHEEL has no Tag: line"
  while IFS= read -r t; do
    plat_fits "${t##*-}" || die 12 "2  $wheel_name WHEEL Tag '$t' does not fit $target ($plat_glob)"
  done <<<"$tags"
  echo "ok    2  METADATA Version $mver; WHEEL Tag $(echo "$tags" | tr '\n' ' ')"
  sha="$(sha256sum "$wheel" | cut -d' ' -f1)"
fi
echo "      sha256 $sha"

if [ -n "$att" ]; then
  [ "$att" = "$sha" ] || die 16 "    attestation digest $att != sha256 $sha"
  echo "ok       attestation digest == sha256"
fi

# GET with bounded retries on 429 / 5xx / no connection. Prints the HTTP code;
# the body lands in $2.
reg_get() {  # $1 url, $2 out file
  local tries="${BITS_CHANGED_RETRIES:-4}" i=0 code wait
  while :; do
    code="$(curl -sS -o "$2" -D "$tmp/hdr" -w '%{http_code}' --max-time 30 "$1" 2>"$tmp/curlerr")" || code="${code:-000}"
    case "$code" in 429|5??|000) ;; *) echo "$code"; return;; esac
    [ "$i" -lt "$tries" ] || { echo "$code"; return; }
    i=$((i + 1))
    wait="$(sed -n 's/^[Rr]etry-[Aa]fter: *\([0-9]*\).*/\1/p' "$tmp/hdr" 2>/dev/null | head -1)"
    [ -n "$wait" ] || wait=$((i * 5)); [ "$wait" -le 60 ] || wait=60
    echo "      registry $code on $1; retry $i/$tries in ${wait}s" >&2
    sleep "$wait"
  done
}
row_hash() {  # $1 json file -> binary_hash without "sha256:"
  python3 -I -c 'import json,sys; h=json.load(open(sys.argv[1])).get("binary_hash") or ""; print(h[7:] if h.startswith("sha256:") else h)' "$1"
}
fm_url() { echo "$base/v1/verify/function-manifest/$1/$target?project=ciris-persist"; }

if [ "$after_publish" -eq 0 ]; then
  # ── 3. not the previous release's registered bytes ────────────────────────
  if [ -z "$prev" ]; then
    tags_list="$(git -C "$repo_root" tag -l 'v*' --sort=-v:refname 2>/dev/null)"
    if [ -z "$tags_list" ]; then
      tags_list="$(git -C "$repo_root" ls-remote --tags --refs origin 'v*' 2>/dev/null | sed 's#.*refs/tags/##' | sort -rV)"
    fi
    prev="$( { printf '%s\n' "$tags_list" | sed -n 's/^v\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)$/\1/p'; echo "$ver"; } \
              | sort -uV | grep -B1 -x -F "$ver" | grep -v -x -F "$ver" | tail -1)"
    [ -n "$prev" ] || die 18 "3  no v-tag below $ver (git tag and git ls-remote both empty?); pass --prev"
  fi
  prev="${prev#v}"
  code="$(reg_get "$(fm_url "$prev")" "$tmp/prev.json")"
  case "$code" in
    404) echo "ok    3  no registered row for $prev on $target: first release on this target";;
    200)
      ph="$(row_hash "$tmp/prev.json")" || die 17 "3  registry row for $prev/$target is not JSON"
      [ -n "$ph" ] || die 17 "3  registry row for $prev/$target has no binary_hash"
      if [ "$ph" != "$sha" ]; then
        echo "ok    3  differs from $prev's registered ${ph:0:16}…"
      elif [ "$is_tree" = 1 ]; then
        # A source tree carries no version, so an unchanged tree hashes the
        # same — allowed only when git shows the hashed paths did not change.
        # A wheel embeds its version and never gets this exemption.
        git -C "$repo_root" rev-parse -q --verify "refs/tags/v$prev^{commit}" >/dev/null \
          || die 13 "3  sha256 $sha equals $prev's registered hash and tag v$prev is not in this checkout, so 'unchanged' cannot be shown (fetch tags)"
        # On a PR (or any run before the tag) v<version> does not exist yet:
        # the tree being signed is HEAD's, so judge against HEAD and say so.
        if git -C "$repo_root" rev-parse -q --verify "refs/tags/v$ver^{commit}" >/dev/null; then
          to="v$ver"; to_why=""
        else
          git -C "$repo_root" rev-parse -q --verify "HEAD^{commit}" >/dev/null \
            || die 13 "3  sha256 $sha equals $prev's registered hash and neither tag v$ver nor HEAD resolves, so 'unchanged' cannot be shown"
          to="HEAD"; to_why=" (tag v$ver not yet in this checkout: judged at HEAD $(git -C "$repo_root" rev-parse --short HEAD))"
        fi
        git -C "$repo_root" diff --quiet "v$prev" "$to" -- $TREE_PATHS; drc=$?
        case "$drc" in
          0) echo "ok    3  equals $prev's registered hash; ALLOWED: $TREE_PATHS is unchanged between v$prev and $to$to_why (git diff empty)";;
          1) die 13 "3  sha256 $sha is the hash registered for $prev on $target, but $TREE_PATHS changed between v$prev and $to$to_why: the bits did not change";;
          *) die 13 "3  sha256 $sha equals $prev's registered hash and git diff v$prev $to failed (exit $drc)";;
        esac
      else
        die 13 "3  sha256 $sha is the hash registered for $prev on $target: the bits did not change"
      fi;;
    *) die 17 "3  registry read for $prev/$target returned HTTP $code ($(head -c 200 "$tmp/prev.json" 2>/dev/null; cat "$tmp/curlerr" 2>/dev/null))";;
  esac

  # ── 4. not a known stale hash ─────────────────────────────────────────────
  [ -f "$denylist" ] || die 14 "4  denylist $denylist is missing: a gate that cannot look has not passed"
  hit="$(grep -v '^[[:space:]]*#' "$denylist" | awk -v h="$sha" '$1 == h' | head -1)"
  if [ -n "$hit" ]; then
    true_ver="$(echo "$hit" | awk '{print $2}')"
    [ "$true_ver" = "$ver" ] || die 14 "4  sha256 $sha is a known stale hash (the $true_ver wheel): $hit"
    echo "ok    4  listed, but as $ver's own wheel"
  else
    echo "ok    4  not in $(basename "$denylist")"
  fi
else
  # ── 5. the registered row carries these bytes ─────────────────────────────
  code="$(reg_get "$(fm_url "$ver")" "$tmp/cur.json")"
  case "$code" in
    200) ;;
    404) die 15 "5  no registered row for $ver on $target";;
    *) die 17 "5  registry read for $ver/$target returned HTTP $code ($(head -c 200 "$tmp/cur.json" 2>/dev/null; cat "$tmp/curlerr" 2>/dev/null))";;
  esac
  rh="$(row_hash "$tmp/cur.json")" || die 17 "5  registry row for $ver/$target is not JSON"
  [ "$rh" = "$sha" ] || die 15 "5  registered binary_hash for $ver/$target is '$rh', wheel sha256 is $sha"
  echo "ok    5  registered binary_hash == sha256"
fi
echo "BITS CHANGED ok $ver $target $wheel_name sha256 $sha"
