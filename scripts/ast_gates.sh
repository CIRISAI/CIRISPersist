#!/usr/bin/env bash
# ast_gates.sh — the from-disk gates ported to ast-grep (CIRISPersist#1026).
#
#   scripts/ast_gates.sh
#
# Runs `ast-grep scan --json` with sgconfig.yml over the crate root and
# compares each rule's per-file match count with rules/expected.json, exactly,
# in both directions: a rule with no expected entry, an expected rule with no
# rule file, a file a rule scans with no expected count, or any count that
# differs is red. A rule matches the syntax tree, so a call in a comment or a
# string literal is not a call by construction (the "from-disk counts must
# strip comments" lesson). Each ported gate keeps its Rust text witness, and
# src/ast_gate_parity.rs holds the Rust counts equal to the same expected.json.
#
# Hermetic: the scan root is CARGO_MANIFEST_DIR when set, else this checkout's
# toplevel — never another worktree. A shared CARGO_TARGET_DIR once made a
# from-disk gate read the MAIN checkout's sources; this script reads only the
# tree it was invoked for, and prints which.
#
# ast-grep is pinned: AST_GREP (a path) wins; else `ast-grep` on PATH if it is
# the pinned version; else the pinned x86_64 Linux release is downloaded into
# ${AST_GREP_CACHE:-$HOME/.cache/ciris-ast-grep}, sha256-checked (the release
# publishes no checksum file, so the digest is pinned here).
#
# Exit codes: 0 green · 1 a count differs or a rule/expectation is unpaired ·
# 2 usage or a broken root · 3 ast-grep (or PyYAML) could not be obtained.
set -uo pipefail
AST_GREP_VERSION=0.45.3
AST_GREP_ZIP_SHA256=f8ac830881339d1edee6b2652f54798c0f4da5a827f2db38a08ee31117783ce8
[ $# -eq 0 ] || { echo "usage: ast_gates.sh"; exit 2; }
root="${CARGO_MANIFEST_DIR:-$(git rev-parse --show-toplevel 2>/dev/null)}"
[ -n "$root" ] && [ -f "$root/sgconfig.yml" ] && [ -f "$root/rules/expected.json" ] \
  || { echo "no sgconfig.yml + rules/expected.json under '$root'"; exit 2; }
cd "$root" || exit 2
echo "scan root: $(pwd -P)"

sg_bin() {
  if [ -n "${AST_GREP:-}" ]; then echo "$AST_GREP"; return; fi
  if command -v ast-grep >/dev/null 2>&1 && ast-grep --version 2>/dev/null | grep -qx "ast-grep $AST_GREP_VERSION"; then
    command -v ast-grep; return
  fi
  [ "$(uname -s)/$(uname -m)" = Linux/x86_64 ] || { echo "the pinned download is x86_64 Linux only; set AST_GREP=" >&2; return 1; }
  local dir="${AST_GREP_CACHE:-$HOME/.cache/ciris-ast-grep}/$AST_GREP_VERSION"
  if [ ! -x "$dir/ast-grep" ]; then
    mkdir -p "$dir" || return 1
    curl -fsSL "https://github.com/ast-grep/ast-grep/releases/download/$AST_GREP_VERSION/app-x86_64-unknown-linux-gnu.zip" \
      -o "$dir/sg.zip" || return 1
    [ "$(sha256sum "$dir/sg.zip" | cut -d' ' -f1)" = "$AST_GREP_ZIP_SHA256" ] \
      || { echo "ast-grep zip sha256 mismatch" >&2; return 1; }
    python3 -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$dir/sg.zip" "$dir" || return 1
    chmod +x "$dir/ast-grep"
  fi
  echo "$dir/ast-grep"
}

SG=$(sg_bin) || { echo "AST-GREP UNAVAILABLE: could not obtain ast-grep $AST_GREP_VERSION"; exit 3; }
echo "$("$SG" --version) ($SG)"
python3 -c 'import yaml' 2>/dev/null || { echo "PyYAML unavailable (reads the rules' files: lists)"; exit 3; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
"$SG" scan -c sgconfig.yml --json=compact > "$tmp/scan.json" 2> "$tmp/scan.err" \
  || { cat "$tmp/scan.err"; echo "AST-GREP SCAN FAILED"; exit 1; }

python3 - "$tmp/scan.json" <<'PY'
import collections, glob, json, os, sys
import yaml

matches = json.load(open(sys.argv[1]))
expected = {k: v for k, v in json.load(open("rules/expected.json")).items() if not k.startswith("_")}
rules = {}
for path in sorted(glob.glob("rules/*.yml")):
    doc = yaml.safe_load(open(path))
    rid = doc["id"]
    if os.path.basename(path) != rid + ".yml":
        print(f"RED   {path}: id {rid} does not match its file name"); sys.exit(1)
    rules[rid] = doc.get("files") or []

got = collections.Counter((m["ruleId"], m["file"]) for m in matches)
red = 0
for rid in sorted(set(rules) | set(expected)):
    if rid not in rules:
        print(f"RED   {rid}: expected.json names it, rules/ has no rule"); red += 1; continue
    if rid not in expected:
        print(f"RED   {rid}: rule with no expected.json entry"); red += 1; continue
    files = set(rules[rid])
    if any(any(c in f for c in "*?[") for f in files):
        print(f"RED   {rid}: files: must list paths, not globs (each needs an expected count)"); red += 1
    if files != set(expected[rid]):
        print(f"RED   {rid}: files {sorted(files)} != expected {sorted(expected[rid])}"); red += 1
    for f in sorted(files | set(expected[rid])):
        want, have = expected[rid].get(f), got.get((rid, f), 0)
        if not os.path.isfile(f):
            print(f"RED   {rid}: {f} does not exist"); red += 1
        elif want != have:
            print(f"RED   {rid}: {f} has {have} match(es), expected {want}"); red += 1
        else:
            print(f"ok    {rid}: {f} {have}")
stray = {k for k in got if k[0] not in expected or k[1] not in expected.get(k[0], {})}
for rid, f in sorted(stray):
    print(f"RED   {rid}: unexpected matches in {f}"); red += 1
if red:
    print(f"AST GATES RED: {red}"); sys.exit(1)
print(f"AST GATES GREEN: {len(rules)} rules")
PY
