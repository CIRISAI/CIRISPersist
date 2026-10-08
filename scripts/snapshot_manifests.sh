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
#   scripts/snapshot_manifests.sh verify <version> <target> [<target>...]
#   scripts/snapshot_manifests.sh verify-reuse <version> <dir> <target> [<target>...]
#
# A pair is written only when all three reads return 200, and never over an
# existing snapshot: the first snapshot of a row is the record, so a second
# one taken after a re-post would record the CORRECTED row as the old one.
# .github/workflows/reregister-manifests.yml refuses to re-post a pair that
# has no committed `.function.json`.
#
# `verify` writes nothing. It reads the same three endpoints and compares each
# live body to its committed snapshot as CANONICAL JSON (sorted keys, no
# whitespace), the whole body: a row re-signed, re-keyed, or with new extras,
# source metadata or signatures under the SAME binary_hash differs, and a
# repost over it would erase a row the evidence never recorded (Codex on PR
# #1039; the workflow's guard compared binary_hash only). Any difference is
# refused with the differing JSON paths. reregister-manifests.yml runs it
# before every repost.
#
# Env: SNAPSHOT_REGISTRY_BASE (default https://us.registry.ciris-services-1.ai),
# SNAPSHOT_ROOT (default <repo>/evidence/manifest_remediation).
#
# Exit codes: 0 every pair written · 2 usage · 4 a snapshot already exists
# (nothing written for that pair) · 5 a registry read failed (nothing written
# for that pair). Every pair is attempted; the exit is the first failure's.
# verify: 0 every live read equals its snapshot · 2 usage · 5 a registry read
# failed · 6 a live read differs from its snapshot · 7 a snapshot is missing.
#
# `verify-reuse` reads no registry: it compares <dir>/manifest-<t>.json (what
# `build_manifest.sh fetch-reuse` just fetched, verbatim, and register will
# re-post) with the committed <t>.build.json, the same canonical comparison
# and the same exit codes (7 also when the fetched file is missing). It closes
# the window between `verify` and the fetch: a row that moved in between is
# refused rather than re-posted (Codex round 2 on PR #1039).
set -uo pipefail
mode=snapshot
case "${1:-}" in verify|verify-reuse) mode="$1"; shift;; esac
ver="${1:-}"; shift || true
reuse_dir=""
if [ "$mode" = verify-reuse ]; then
  reuse_dir="${1:-}"; shift || true
  [ -n "$reuse_dir" ] || { echo "usage: snapshot_manifests.sh verify-reuse <version> <dir> <target>..." >&2; exit 2; }
fi
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

url_of() {  # $1 kind, $2 target
  case "$1" in
    function) echo "$base/v1/verify/function-manifest/$ver/$2?project=ciris-persist";;
    build)    echo "$base/v1/verify/build-manifest/ciris-persist/$ver/$2";;
    builds)   echo "$base/v1/builds/$ver?project=ciris-persist&target=$2";;
  esac
}

# canon_diff <snapshot> <live>: exit 0 when equal as canonical JSON; else
# prints up to 12 differing JSON paths and exits 1 (3 if either is not JSON).
canon_diff() {
  python3 -I - "$1" "$2" <<'PYEOF'
import json, sys
try:
    a, b = (json.load(open(p)) for p in sys.argv[1:3])
except (OSError, ValueError) as e:
    print(f"    not JSON: {e}"); sys.exit(3)
canon = lambda x: json.dumps(x, sort_keys=True, separators=(",", ":"))
if canon(a) == canon(b):
    sys.exit(0)
out = []
def walk(x, y, path):
    if isinstance(x, dict) and isinstance(y, dict):
        for k in sorted(set(x) | set(y)):
            if k not in x: out.append(f"{path}.{k}: only live")
            elif k not in y: out.append(f"{path}.{k}: only in the snapshot")
            else: walk(x[k], y[k], f"{path}.{k}")
    elif isinstance(x, list) and isinstance(y, list) and len(x) == len(y):
        for i, (u, v) in enumerate(zip(x, y)): walk(u, v, f"{path}[{i}]")
    elif canon(x) != canon(y):
        s = lambda v: (canon(v)[:40] + "...") if len(canon(v)) > 43 else canon(v)
        out.append(f"{path or '.'}: snapshot {s(x)} live {s(y)}")
walk(a, b, "")
for line in out[:12]: print("    " + line)
if len(out) > 12: print(f"    ... {len(out) - 12} more")
sys.exit(1)
PYEOF
}

rc=0
if [ "$mode" = verify-reuse ]; then
  for t in "$@"; do
    case "$t" in ""|*[!a-z0-9_-]*) echo "usage: target '$t' is not a target triple" >&2; exit 2;; esac
    snap="$root/$ver/$t.build.json"; got="$reuse_dir/manifest-$t.json"
    if [ ! -s "$snap" ]; then echo "MISSING  $ver/$t.build: no snapshot at $snap"; [ "$rc" -ne 0 ] || rc=7; continue; fi
    if [ ! -s "$got" ]; then echo "MISSING  $ver/$t: no fetched $got"; [ "$rc" -ne 0 ] || rc=7; continue; fi
    if d="$(canon_diff "$snap" "$got")"; then
      echo "same     $ver/$t.build: the fetched manifest is the snapshot"
    else
      echo "DIFFERS  $ver/$t.build: the fetched manifest is not the committed snapshot"; printf '%s\n' "$d"
      [ "$rc" -ne 0 ] || rc=6
    fi
  done
  exit "$rc"
fi
if [ "$mode" = verify ]; then
  for t in "$@"; do
    case "$t" in ""|*[!a-z0-9_-]*) echo "usage: target '$t' is not a target triple" >&2; exit 2;; esac
    for kind in function build builds; do
      snap="$root/$ver/$t.$kind.json"
      if [ ! -s "$snap" ]; then
        echo "MISSING  $ver/$t.$kind: no snapshot at $snap"; [ "$rc" -ne 0 ] || rc=7; continue
      fi
      url="$(url_of "$kind" "$t")"
      code="$(get "$url" "$tmp/live.json")"
      if [ "$code" != 200 ]; then
        echo "FAIL     $ver/$t.$kind: GET $url returned HTTP $code"; [ "$rc" -ne 0 ] || rc=5; continue
      fi
      if d="$(canon_diff "$snap" "$tmp/live.json")"; then
        echo "same     $ver/$t.$kind: the live row is the snapshot"
      else
        echo "DIFFERS  $ver/$t.$kind: the live row is not the committed snapshot"; printf '%s\n' "$d"
        [ "$rc" -ne 0 ] || rc=6
      fi
    done
  done
  exit "$rc"
fi

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
    url="$(url_of "$kind" "$t")"
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
