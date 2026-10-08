#!/usr/bin/env bash
# snapshot_manifests.sh — record a registered manifest row before it is
# overwritten (CIRISPersist#1029).
#
# CIRISRegistry upserts manifest rows in place, keyed (project, version,
# target), and keeps no history (CIRISRegistry#144). A re-post of a corrected
# manifest erases the wrong one. This script writes the three public reads of
# each (version, target) verbatim, so the superseded row stays on record:
#
#   evidence/manifest_remediation/<v>/<t>.function.json  GET /v1/verify/function-manifest/{v}/{t}?project=ciris-persist
#   evidence/manifest_remediation/<v>/<t>.build.json     GET /v1/verify/build-manifest/ciris-persist/{v}/{t}
#   evidence/manifest_remediation/<v>/<t>.builds.json    GET /v1/builds/{v}?project=ciris-persist&target={t}
#
#   scripts/snapshot_manifests.sh <version> <target> [<target>...]
#
# A pair is written only when all three reads return 200, and never over an
# existing snapshot: the first snapshot of a row is the record, so a second
# one taken after a re-post would record the CORRECTED row as the old one.
# .github/workflows/reregister-manifests.yml refuses to re-post a pair that
# has no committed `.function.json`.
#
# Env: SNAPSHOT_REGISTRY_BASE (default https://us.registry.ciris-services-1.ai),
# SNAPSHOT_ROOT (default <repo>/evidence/manifest_remediation).
#
# Exit codes: 0 every pair written · 2 usage · 4 a snapshot already exists
# (nothing written for that pair) · 5 a registry read failed (nothing written
# for that pair). Every pair is attempted; the exit is the first failure's.
set -uo pipefail
ver="${1:-}"; shift || true
ver="${ver#v}"
case "$ver" in ""|*[!0-9.]*) echo "usage: snapshot_manifests.sh <version> <target>..." >&2; exit 2;; esac
[ $# -ge 1 ] || { echo "usage: snapshot_manifests.sh <version> <target>..." >&2; exit 2; }
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
base="${SNAPSHOT_REGISTRY_BASE:-https://us.registry.ciris-services-1.ai}"; base="${base%/}"
root="${SNAPSHOT_ROOT:-$repo_root/evidence/manifest_remediation}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

get() {  # $1 url, $2 out; prints the HTTP code. Retries 429/5xx/no connection.
  local i=0 code wait
  while :; do
    code="$(curl -sS -o "$2" -D "$tmp/hdr" -w '%{http_code}' --max-time 30 "$1" 2>/dev/null)" || code="${code:-000}"
    case "$code" in 429|5??|000) ;; *) echo "$code"; return;; esac
    [ "$i" -lt "${SNAPSHOT_RETRIES:-4}" ] || { echo "$code"; return; }
    i=$((i + 1))
    wait="$(sed -n 's/^[Rr]etry-[Aa]fter: *\([0-9]*\).*/\1/p' "$tmp/hdr" 2>/dev/null | head -1)"
    [ -n "$wait" ] || wait=$((i * 5)); [ "$wait" -le 60 ] || wait=60
    echo "  registry $code on $1; retry $i in ${wait}s" >&2
    sleep "$wait"
  done
}

rc=0
for t in "$@"; do
  case "$t" in ""|*[!a-z0-9_-]*) echo "usage: target '$t' is not a target triple" >&2; exit 2;; esac
  dir="$root/$ver"
  existing=""
  for kind in function build builds; do
    [ -e "$dir/$t.$kind.json" ] && existing="$existing $t.$kind.json"
  done
  if [ -n "$existing" ]; then
    echo "REFUSED  $ver/$t: snapshot exists ($existing ) — the first snapshot is the record"
    [ "$rc" -ne 0 ] || rc=4; continue
  fi
  ok=1
  for kind in function build builds; do
    case "$kind" in
      function) url="$base/v1/verify/function-manifest/$ver/$t?project=ciris-persist";;
      build)    url="$base/v1/verify/build-manifest/ciris-persist/$ver/$t";;
      builds)   url="$base/v1/builds/$ver?project=ciris-persist&target=$t";;
    esac
    code="$(get "$url" "$tmp/$t.$kind.json")"
    if [ "$code" != 200 ]; then
      echo "FAIL     $ver/$t: GET $url returned HTTP $code"; ok=0; break
    fi
  done
  if [ "$ok" -ne 1 ]; then [ "$rc" -ne 0 ] || rc=5; continue; fi
  mkdir -p "$dir"
  for kind in function build builds; do mv "$tmp/$t.$kind.json" "$dir/$t.$kind.json"; done
  h="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("binary_hash",""))' "$dir/$t.function.json" 2>/dev/null)"
  echo "wrote    $ver/$t: function, build, builds (binary_hash ${h:-?})"
done
exit "$rc"
