#!/usr/bin/env bash
# weaver_check.sh — the telemetry registry gate (CIRISPersist#1027).
#
#   scripts/weaver_check.sh            # check; exit non-zero on any finding
#   scripts/weaver_check.sh --write    # re-render telemetry/catalog.json
#
# telemetry/registry/ is persist's OpenTelemetry Weaver semantic-convention
# registry: the seven read counters and their closed label sets. This script
#   1. runs `weaver registry check --future` on it (names, units, references,
#      enum members);
#   2. renders it through telemetry/templates/registry/catalog/ into
#      catalog.json and requires the committed telemetry/catalog.json to be
#      byte-identical. The I552 witness (src/observe/tests.rs) compares that
#      file to TELEMETRY_CATALOG in both directions, so the YAML, the JSON and
#      the Rust table cannot drift without a red.
#
# Weaver is pinned: WEAVER (a path) wins; else `weaver` on PATH if it is the
# pinned version; else the pinned release is downloaded into
# ${WEAVER_CACHE:-$HOME/.cache/ciris-weaver}, its .sha256 checked. Offline with
# no cached copy: exit 3, nothing judged.
#
# Exit codes: 0 green · 1 the registry check failed or catalog.json is stale ·
# 2 usage · 3 weaver could not be obtained.
set -uo pipefail
WEAVER_VERSION=0.27.0
cd "$(git rev-parse --show-toplevel)" || exit 2
write=0
case "${1:-}" in --write) write=1;; "") ;; *) echo "usage: weaver_check.sh [--write]"; exit 2;; esac

weaver_bin() {
  if [ -n "${WEAVER:-}" ]; then echo "$WEAVER"; return; fi
  if command -v weaver >/dev/null 2>&1 && weaver --version 2>/dev/null | grep -qx "weaver $WEAVER_VERSION"; then
    command -v weaver; return
  fi
  local dir="${WEAVER_CACHE:-$HOME/.cache/ciris-weaver}/$WEAVER_VERSION"
  local triple; case "$(uname -m)" in
    x86_64) triple=x86_64-unknown-linux-gnu;; aarch64|arm64) triple=aarch64-unknown-linux-gnu;;
    *) echo "no pinned weaver build for $(uname -m)" >&2; return 1;; esac
  [ "$(uname -s)" = Linux ] || { echo "the pinned download is Linux-only; set WEAVER=" >&2; return 1; }
  if [ ! -x "$dir/weaver-$triple/weaver" ]; then
    mkdir -p "$dir" || return 1
    local url="https://github.com/open-telemetry/weaver/releases/download/v$WEAVER_VERSION/weaver-$triple.tar.xz"
    curl -fsSL "$url" -o "$dir/w.tar.xz" && curl -fsSL "$url.sha256" -o "$dir/w.sha256" || return 1
    [ "$(cut -d' ' -f1 "$dir/w.sha256")" = "$(sha256sum "$dir/w.tar.xz" | cut -d' ' -f1)" ] \
      || { echo "weaver tarball sha256 mismatch" >&2; return 1; }
    tar -xJf "$dir/w.tar.xz" -C "$dir" || return 1
  fi
  echo "$dir/weaver-$triple/weaver"
}

W=$(weaver_bin) || { echo "WEAVER UNAVAILABLE: could not obtain weaver $WEAVER_VERSION"; exit 3; }
echo "$("$W" --version) ($W)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

if ! "$W" registry check -r telemetry/registry --future > "$tmp/check.log" 2>&1; then
  cat "$tmp/check.log"; echo "WEAVER CHECK RED: telemetry/registry"; exit 1
fi
# weaver check exits 0 with a diagnostic report in some cases (a manifest
# warning); treat any reported diagnostic as red.
if grep -q '×' "$tmp/check.log"; then
  cat "$tmp/check.log"; echo "WEAVER CHECK RED: diagnostics reported"; exit 1
fi
echo "ok    weaver registry check (telemetry/registry)"

"$W" registry generate -r telemetry/registry -t telemetry/templates catalog "$tmp/out" --future \
  > "$tmp/gen.log" 2>&1 || { cat "$tmp/gen.log"; echo "WEAVER GENERATE RED"; exit 1; }
if [ "$write" = 1 ]; then
  cp "$tmp/out/catalog.json" telemetry/catalog.json; echo "wrote telemetry/catalog.json"; exit 0
fi
if ! cmp -s "$tmp/out/catalog.json" telemetry/catalog.json; then
  diff -u telemetry/catalog.json "$tmp/out/catalog.json" | head -40
  echo "STALE: telemetry/catalog.json is not the registry's rendering — scripts/weaver_check.sh --write, then run I552"
  exit 1
fi
echo "ok    telemetry/catalog.json is the registry's rendering"
echo "WEAVER CHECK GREEN"
