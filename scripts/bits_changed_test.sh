#!/usr/bin/env bash
# bits_changed_test.sh — witnesses for scripts/bits_changed.sh (CIRISPersist#1029).
# Offline: fixture wheels are minimal zips (dist-info METADATA + WHEEL only) and
# the registry is a local python http.server stub (BITS_CHANGED_REGISTRY_BASE).
# Runs in a few seconds; a certify fast gate (`bitschanged`) and a CI lint step.
#
# Case (b) carries the mutation the bug was: the `# bits:select` line is
# replaced by `ls *.whl | head -1` in a copy, and the copy must go RED on a
# directory holding a 29.0.0 and a 53.1.8 wheel — the v53.1.8 tag run's shape.
#
# The second half drives scripts/build_manifest.sh (the sign + register logic
# ci.yml's tag job and reregister-manifests.yml share) with a fake
# ciris-build-sign: selection beside a stale wheel, the gate before signing,
# the remediation reuse rule, the register argv and the read-back.
#
# Exit 0 every case as expected, 1 a case failed, 2 the harness could not run.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
GATE="$PWD/scripts/bits_changed.sh"
for t in python3 unzip curl git sha256sum; do
  command -v "$t" >/dev/null || { echo "✗ $t not found" >&2; exit 2; }
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/bits-changed-test.XXXXXX")"
SRV_PID=""
# shellcheck disable=SC2317  # invoked by the EXIT trap
cleanup() { if [ -n "$SRV_PID" ]; then kill "$SRV_PID" 2>/dev/null; fi; rm -rf "$WORK"; }
trap cleanup EXIT
fails=0; n=0

V=53.1.8; PREV=53.1.7; T=aarch64-unknown-linux-gnu
PLAT=manylinux_2_34_aarch64

# mkwheel <out-path> <metadata-version> <wheel-tag-platform>
mkwheel() {
  python3 -I - "$1" "$2" "$3" <<'PY'
import sys, zipfile
out, ver, plat = sys.argv[1:4]
with zipfile.ZipFile(out, "w") as z:
    di = f"ciris_persist-{ver}.dist-info"
    z.writestr(f"{di}/METADATA", f"Metadata-Version: 2.4\nName: ciris-persist\nVersion: {ver}\n")
    z.writestr(f"{di}/WHEEL", f"Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: false\nTag: cp310-abi3-{plat}\n")
    z.writestr("ciris_persist/__init__.py", f"# {ver} {plat}\n")
PY
}
sha() { sha256sum "$1" | cut -d' ' -f1; }

# The stub registry: files under $WORK/reg/<url path>, query strings ignored;
# any path containing /fail500/ answers 500.
mkdir -p "$WORK/reg" "$WORK/bin"
cat >"$WORK/bin/stub.py" <<'PY'
import http.server, os, sys
root = sys.argv[1]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if "/fail500/" in path:
            self.send_response(500); self.end_headers(); self.wfile.write(b"boom"); return
        f = os.path.join(root, path.lstrip("/"))
        if os.path.isfile(f):
            body = open(f, "rb").read()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers(); self.wfile.write(b'{"error":"not found"}')
    def log_message(self, *a): pass
s = http.server.HTTPServer(("127.0.0.1", 0), H)
open(sys.argv[2], "w").write(str(s.server_address[1]))
s.serve_forever()
PY
python3 -I "$WORK/bin/stub.py" "$WORK/reg" "$WORK/port" </dev/null >/dev/null 2>&1 &
SRV_PID=$!
for _ in $(seq 1 50); do [ -s "$WORK/port" ] && break; sleep 0.1; done
[ -s "$WORK/port" ] || { echo "✗ stub registry did not start" >&2; exit 2; }
PORT="$(cat "$WORK/port")"
export BITS_CHANGED_REGISTRY_BASE="http://127.0.0.1:$PORT"
export BITS_CHANGED_RETRIES=0
EMPTY_DENY="$WORK/deny-empty.txt"; echo "# none" >"$EMPTY_DENY"
export BITS_CHANGED_DENYLIST="$EMPTY_DENY"

# reg_row <version> <target> <hex>: the stub serves a function-manifest row
reg_row() {
  mkdir -p "$WORK/reg/v1/verify/function-manifest/$1"
  printf '{"target":"%s","binary_version":"%s","binary_hash":"sha256:%s"}' "$2" "$1" "$3" \
    >"$WORK/reg/v1/verify/function-manifest/$1/$2"
}
reg_clear() { rm -rf "$WORK/reg/v1"; }

# expect <case> <want-exit> <must-match ERE> -- <command...>
expect() {
  local name="$1" want="$2" must="$3"; shift 4
  local out rc; n=$((n + 1))
  out="$("$@" 2>&1)"; rc=$?
  if [ "$rc" -eq "$want" ] && grep -qE "$must" <<<"$out"; then
    printf '  ok    %-34s exit=%-2s %s\n' "$name" "$rc" "$(grep -E "$must" <<<"$out" | head -1 | sed 's/^ *//' | cut -c1-90)"
  else
    printf '  FAIL  %-34s exit=%s (want %s, /%s/)\n' "$name" "$rc" "$want" "$must"
    while IFS= read -r l; do echo "        | $l"; done <<<"$out"; fails=$((fails + 1))
  fi
}

# ── fixtures ────────────────────────────────────────────────────────────────
W="ciris_persist-$V-cp310-abi3-$PLAT.whl"
OLD="ciris_persist-29.0.0-cp310-abi3-$PLAT.whl"
mkdir -p "$WORK/a" "$WORK/b" "$WORK/c" "$WORK/f" "$WORK/g"
mkwheel "$WORK/a/$W" "$V" "$PLAT"
mkwheel "$WORK/b/$W" "$V" "$PLAT"; mkwheel "$WORK/b/$OLD" 29.0.0 "$PLAT"
mkwheel "$WORK/c/$W" 29.0.0 "$PLAT"                       # name says 53.1.8, bytes say 29.0.0
mkwheel "$WORK/f/$W" "$V" "$PLAT"
mkwheel "$WORK/f/ciris_persist-$V-cp310-abi3-manylinux_2_28_aarch64.whl" "$V" manylinux_2_28_aarch64
mkwheel "$WORK/g/$W" "$V" manylinux_2_34_x86_64           # name aarch64, WHEEL Tag x86_64
# other targets' wheels beside ours are not candidates
mkwheel "$WORK/a/ciris_persist-$V-cp310-abi3-win_amd64.whl" "$V" win_amd64
A_SHA="$(sha "$WORK/a/$W")"

echo "bits_changed.sh witnesses"
# (a) one correct wheel
reg_clear
expect "a: correct, no prev row (404)"   0 'first release on this target' -- "$GATE" --prev "$PREV" "$V" "$T" "$WORK/a"
reg_row "$PREV" "$T" "$(printf '0%.0s' $(seq 64))"
expect "a: correct, prev row differs"    0 "^BITS CHANGED ok $V $T $W"     -- "$GATE" --prev "$PREV" "$V" "$T" "$WORK/a"
expect "a: wheel given as a file"        0 "^BITS CHANGED ok"              -- "$GATE" --prev "$PREV" "$V" "$T" "$WORK/a/$W"
expect "a: windows wheel, windows target" 0 "win_amd64"                    -- "$GATE" --prev "$PREV" "$V" x86_64-pc-windows-msvc "$WORK/a"

# (b) old + new in one dir: selects new; the `ls | head -1` mutant goes RED
expect "b: 29.0.0 + 53.1.8 selects 53.1.8" 0 "^ok    1  $W"                -- "$GATE" --prev "$PREV" "$V" "$T" "$WORK/b"
mkdir -p "$WORK/mut/scripts"
# shellcheck disable=SC2016  # the replacement is shell text, written literally
sed 's|^\( *\)mapfile -t all < <(find .*# bits:select$|\1mapfile -t all < <(ls "$src"/*.whl \| head -1)  # mutant|' \
  "$GATE" >"$WORK/mut/scripts/bits_changed.sh"
chmod +x "$WORK/mut/scripts/bits_changed.sh"
if cmp -s "$GATE" "$WORK/mut/scripts/bits_changed.sh" || ! grep -q '# mutant$' "$WORK/mut/scripts/bits_changed.sh"; then
  echo "  FAIL  b: mutation did not apply (the '# bits:select' line moved?)"; fails=$((fails + 1)); n=$((n + 1))
else
  expect "b: MUTANT ls|head -1 is red"   11 "METADATA Version '29.0.0' != $V" -- "$WORK/mut/scripts/bits_changed.sh" --prev "$PREV" "$V" "$T" "$WORK/b"
fi

# (c) the name says 53.1.8, the METADATA says 29.0.0
expect "c: METADATA version mismatch"     11 "METADATA Version '29.0.0' != $V" -- "$GATE" --prev "$PREV" "$V" "$T" "$WORK/c"

# (d) the same bytes as the previous release's registered row
reg_row "$PREV" "$T" "$A_SHA"
expect "d: hash == previous registered"   13 'the bits did not change'      -- "$GATE" --prev "$PREV" "$V" "$T" "$WORK/a"
reg_clear

# (e) a known stale hash
printf '# x\n%s  29.0.0  %s  fixture\n' "$A_SHA" "$T" >"$WORK/deny.txt"
expect "e: denylisted"                    14 'known stale hash'              -- env BITS_CHANGED_DENYLIST="$WORK/deny.txt" "$GATE" --prev "$PREV" "$V" "$T" "$WORK/a"
printf '%s  %s  %s  fixture\n' "$A_SHA" "$V" "$T" >"$WORK/deny-own.txt"
expect "e: listed as its own version"     0  'listed, but as'                -- env BITS_CHANGED_DENYLIST="$WORK/deny-own.txt" "$GATE" --prev "$PREV" "$V" "$T" "$WORK/a"
expect "e: denylist missing is red"       14 'is missing'                    -- env BITS_CHANGED_DENYLIST="$WORK/nope.txt" "$GATE" --prev "$PREV" "$V" "$T" "$WORK/a"

# check 1 and 2 edges
expect "1: two 53.1.8 aarch64 wheels"     10 '2 ciris_persist-53.1.8 wheels' -- "$GATE" --prev "$PREV" "$V" "$T" "$WORK/f"
expect "1: no wheel for the target"       10 '0 ciris_persist-53.1.8 wheels' -- "$GATE" --prev "$PREV" "$V" aarch64-apple-darwin "$WORK/a"
expect "1: file of another version"       10 'is not a ciris_persist-53.1.8' -- "$GATE" --prev "$PREV" "$V" "$T" "$WORK/b/$OLD"
expect "2: WHEEL Tag for another arch"    12 "does not fit $T"               -- "$GATE" --prev "$PREV" "$V" "$T" "$WORK/g"
expect "usage: unknown target"            2  'unknown target'                -- "$GATE" "$V" riscv64-unknown-linux-gnu "$WORK/a"

# 5. --after-publish and the attestation digest
reg_row "$V" "$T" "$A_SHA"
expect "5: registered == wheel"           0  'registered binary_hash == sha256' -- "$GATE" --after-publish "$V" "$T" "$WORK/a"
expect "5: + attestation digest equal"    0  'attestation digest == sha256'  -- "$GATE" --after-publish --attestation-digest "$A_SHA" "$V" "$T" "$WORK/a"
expect "5: attestation digest differs"    16 'attestation digest'            -- "$GATE" --after-publish --attestation-digest "$(printf 'f%.0s' $(seq 64))" "$V" "$T" "$WORK/a"
reg_row "$V" "$T" 51193a5afd0789337ca75b2704d413be720307134486242775540050f5cc4a0a
expect "5: registered row is stale"       15 "registered binary_hash for $V/$T is '51193a5a" -- "$GATE" --after-publish "$V" "$T" "$WORK/a"
reg_clear
expect "5: no registered row"             15 'no registered row'             -- "$GATE" --after-publish "$V" "$T" "$WORK/a"

# a registry error is not a pass
expect "3: registry 500 is red"           17 'HTTP 500'                      -- "$GATE" --prev fail500 "$V" "$T" "$WORK/a"
expect "5: registry unreachable is red"   17 'HTTP 000'                      -- env BITS_CHANGED_REGISTRY_BASE=http://127.0.0.1:9 "$GATE" --after-publish "$V" "$T" "$WORK/a"

# --sha256 mode (a published file judged by its listed digest)
expect "sha mode: pass"                   0  'filename names 53.1.8'         -- "$GATE" --prev "$PREV" --sha256 "$A_SHA" --filename "$W" "$V" "$T"
expect "sha mode: filename version"       11 "names version '29.0.0'"        -- "$GATE" --prev "$PREV" --sha256 "$A_SHA" --filename "$OLD" "$V" "$T"
expect "sha mode: denylisted"             14 'known stale hash'              -- env BITS_CHANGED_DENYLIST="$WORK/deny.txt" "$GATE" --prev "$PREV" --sha256 "$A_SHA" --filename "$W" "$V" "$T"

# PREVIOUS_VERSION from git tags: newest v-tag below the version
G="$WORK/git"; mkdir -p "$G/scripts"; cp "$GATE" "$G/scripts/"
if ! git -C "$G" init -q || ! git -C "$G" -c user.name=t -c user.email=t@t commit -q --allow-empty -m t; then
  echo "✗ fixture git repo" >&2; exit 2
fi
for tg in v1.0.0 v1.2.0 v1.10.0 v2.0.0 v2.0.0-rc1 v3.0.0; do git -C "$G" tag "$tg" || exit 2; done
W2="$WORK/p/ciris_persist-2.0.0-cp310-abi3-$PLAT.whl"; W1="$WORK/p/ciris_persist-1.0.0-cp310-abi3-$PLAT.whl"
mkdir -p "$WORK/p"; mkwheel "$W2" 2.0.0 "$PLAT"; mkwheel "$W1" 1.0.0 "$PLAT"
reg_row 1.10.0 "$T" "$(sha "$W2")"
expect "prev: 2.0.0's prev is 1.10.0"     13 'registered for 1.10.0'         -- "$G/scripts/bits_changed.sh" 2.0.0 "$T" "$W2"
reg_clear
expect "prev: none below 1.0.0"           18 'no v-tag below 1.0.0'          -- "$G/scripts/bits_changed.sh" 1.0.0 "$T" "$W1"

# ── scripts/build_manifest.sh: the sign logic both workflows call ───────────
# A fake ciris-build-sign writes {target, binary_version, binary_hash} and logs
# its argv, so the selection, the gate before signing and the reuse rule are
# exercised without keys or a registry write.
echo
echo "build_manifest.sh witnesses (fake ciris-build-sign)"
BM="$PWD/scripts/build_manifest.sh"
cat >"$WORK/bin/ciris-build-sign" <<'SH'
#!/usr/bin/env bash
echo "$*" >>"$FAKE_SIGN_LOG"
sub="$1"; shift
[ "$sub" = sign ] || exit 0
while [ $# -gt 0 ]; do
  case "$1" in --binary) b="$2";; --target) t="$2";; --binary-version) v="$2";; --output) o="$2";; esac; shift
done
h=""; [ -n "${b:-}" ] && h="sha256:$(sha256sum "$b" | cut -d' ' -f1)"
printf '{"target":"%s","binary_version":"%s","binary_hash":"%s"}\n' "$t" "$v" "$h" >"$o"
SH
chmod +x "$WORK/bin/ciris-build-sign"
export PATH="$WORK/bin:$PATH" FAKE_SIGN_LOG="$WORK/sign.log"
export CIRIS_BUILD_ED25519_SECRET=eA== CIRIS_BUILD_MLDSA_SECRET=eA== BITS_CHANGED_PREV="$PREV"
WH="$WORK/wheels"
declare -A LP=([linux-x86_64]=manylinux_2_34_x86_64 [linux-aarch64]=manylinux_2_34_aarch64 [darwin-aarch64]=macosx_11_0_arm64 [windows-x86_64]=win_amd64)
for l in "${!LP[@]}"; do mkdir -p "$WH/ciris_persist-wheel-$l"; mkwheel "$WH/ciris_persist-wheel-$l/ciris_persist-$V-cp310-abi3-${LP[$l]}.whl" "$V" "${LP[$l]}"; done
mkwheel "$WH/ciris_persist-wheel-linux-aarch64/$OLD" 29.0.0 "$PLAT"      # v53.1.8's stale neighbour
echo '{}' >"$WORK/extras.json"
hash_in() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["binary_hash"])' "$1"; }
AARCH_SHA="sha256:$(sha "$WH/ciris_persist-wheel-linux-aarch64/$W")"

expect "bm: tag mode signs 4 + source tree" 0 'signed aarch64-unknown-linux-gnu: '"$W" -- "$BM" sign --version "$V" --wheels "$WH" --out "$WORK/o1" --extras "$WORK/extras.json" --source-tree
n=$((n + 1))
if [ "$(hash_in "$WORK/o1/manifest-aarch64-unknown-linux-gnu.json")" = "$AARCH_SHA" ] && [ "$(wc -l <"$WORK/o1/signed-binary-targets.txt")" -eq 4 ] && [ -s "$WORK/o1/manifest-python-source-tree.json" ]; then
  echo "  ok    bm: aarch64 manifest signs the $V wheel, 4 targets listed"
else echo "  FAIL  bm: aarch64 manifest hash $(hash_in "$WORK/o1/manifest-aarch64-unknown-linux-gnu.json") != $AARCH_SHA, or targets/source tree missing"; fails=$((fails + 1)); fi

# the gate runs before signing: a denylisted wheel is never signed
printf '%s  29.0.0  x  t\n' "${AARCH_SHA#sha256:}" >"$WORK/deny-aarch.txt"
expect "bm: denylisted wheel is not signed"  1 'bits_changed.sh refused aarch64-unknown-linux-gnu' -- env BITS_CHANGED_DENYLIST="$WORK/deny-aarch.txt" "$BM" sign --version "$V" --wheels "$WH" --out "$WORK/o2" --extras "$WORK/extras.json" --source-tree

# remediation: re-sign two targets, reuse the other two + the source tree unchanged
mkdir -p "$WORK/orig"; cp "$WORK/o1"/manifest-*.json "$WORK/extras.json" "$WORK/orig/"; mv "$WORK/orig/extras.json" "$WORK/orig/persist-extras-$V.json"
: >"$FAKE_SIGN_LOG"
expect "bm: remediation re-signs 2, reuses 2" 0 'reused x86_64-unknown-linux-gnu' -- "$BM" sign --version "$V" --wheels "$WH" --out "$WORK/o3" --reuse "$WORK/orig" --targets "aarch64-unknown-linux-gnu x86_64-pc-windows-msvc"
n=$((n + 1))
if [ "$(grep -c '^sign ' "$FAKE_SIGN_LOG")" -eq 2 ] && [ "$(wc -l <"$WORK/o3/signed-binary-targets.txt")" -eq 4 ] && cmp -s "$WORK/orig/manifest-python-source-tree.json" "$WORK/o3/manifest-python-source-tree.json"; then
  echo "  ok    bm: exactly 2 signs; 4 binary targets + the source tree registered"
else echo "  FAIL  bm: $(grep -c '^sign ' "$FAKE_SIGN_LOG") signs, $(wc -l <"$WORK/o3/signed-binary-targets.txt") targets"; fails=$((fails + 1)); fi
printf '{"target":"x86_64-unknown-linux-gnu","binary_version":"%s","binary_hash":"sha256:%s"}\n' "$V" 51193a5afd0789337ca75b2704d413be720307134486242775540050f5cc4a0a >"$WORK/orig/manifest-x86_64-unknown-linux-gnu.json"
expect "bm: a wrong reused row is refused"  1 'that row is wrong too' -- "$BM" sign --version "$V" --wheels "$WH" --out "$WORK/o4" --reuse "$WORK/orig" --targets "aarch64-unknown-linux-gnu x86_64-pc-windows-msvc"
cp "$WORK/o1/manifest-x86_64-unknown-linux-gnu.json" "$WORK/orig/"
rm -rf "$WH/ciris_persist-wheel-windows-x86_64"
expect "bm: a named target with no wheel"   1 'no 53.1.8 wheel for named target x86_64-pc-windows-msvc' -- "$BM" sign --version "$V" --wheels "$WH" --out "$WORK/o5" --reuse "$WORK/orig" --targets "x86_64-pc-windows-msvc"

# register posts every target in the out dir; --dry-run reaches the tool
: >"$FAKE_SIGN_LOG"
expect "bm: register --dry-run"             0 'nothing posted' -- "$BM" register --version "$V" --commit abc --out "$WORK/o3" --dry-run
n=$((n + 1))
if grep -q '^register --dry-run ' "$FAKE_SIGN_LOG" && [ "$(grep -o -- '--target ' "$FAKE_SIGN_LOG" | wc -l)" -eq 5 ]; then
  echo "  ok    bm: register got --dry-run and 5 --target"
else echo "  FAIL  bm: register argv: $(cat "$FAKE_SIGN_LOG")"; fails=$((fails + 1)); fi

# after-publish reads every registered row back
for t in aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu aarch64-apple-darwin; do
  reg_row "$V" "$t" "$(hash_in "$WORK/o1/manifest-$t.json" | sed 's/^sha256://')"
done
mkdir -p "$WH/ciris_persist-wheel-windows-x86_64"; mkwheel "$WH/ciris_persist-wheel-windows-x86_64/ciris_persist-$V-cp310-abi3-win_amd64.whl" "$V" win_amd64
reg_row "$V" x86_64-pc-windows-msvc 8a1e5a8f53e102cb2604a36b7faf7266ad94fa920a8b9e808443a8b1cf60eb12
expect "bm: after-publish finds a stale row" 1 'x86_64-pc-windows-msvc does not carry its wheel' -- "$BM" after-publish --version "$V" --wheels "$WH" --out "$WORK/o1"
reg_row "$V" x86_64-pc-windows-msvc "$(sha "$WH/ciris_persist-wheel-windows-x86_64/ciris_persist-$V-cp310-abi3-win_amd64.whl")"
expect "bm: after-publish all rows match"    0 'BITS CHANGED ok 53.1.8 x86_64-pc-windows-msvc' -- "$BM" after-publish --version "$V" --wheels "$WH" --out "$WORK/o1"
reg_clear

echo
if [ "$fails" -eq 0 ]; then echo "bits_changed_test: $n/$n as expected"; exit 0; fi
echo "bits_changed_test: $fails of $n FAILED"; exit 1
