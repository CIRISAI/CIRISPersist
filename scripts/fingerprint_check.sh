#!/usr/bin/env bash
# fingerprint_check.sh — do the pre-push hook, `certify.sh prebuild` and
# certify's `core` leg compile the SAME units? (CIRISPersist#1010)
#
# A compiled unit is reused only when its fingerprint matches, and three
# inputs a script controls are in every unit's fingerprint: RUSTFLAGS, the
# feature set, and the cargo profile. This check does not restate any of
# them. It asks each consumer what it WOULD run — the hook with
# CIRIS_HOOK_FINGERPRINT_ONLY=1, certify with `fingerprint <mode> core` — and
# both print the very array they execute. It then compares the triples and
# exits 1 if any differ.
#
# What it does NOT compare, on purpose: target selection (`--lib`), `-E`
# filters, `--no-run` and test threads. None is in a unit's fingerprint; the
# hook's `--lib` builds a subset of the core leg's units, and the dependency
# graph is shared whole.
#
#   scripts/fingerprint_check.sh          exit 0 = one fingerprint, 1 = drift
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

hook_out="$(CIRIS_HOOK_FINGERPRINT_ONLY=1 scripts/hooks/pre-push </dev/null)" \
    || { echo "✗ the pre-push hook could not report its fingerprint" >&2; exit 1; }
pre_out="$(scripts/certify.sh fingerprint prebuild core)" \
    || { echo "✗ certify.sh could not report the prebuild fingerprint" >&2; exit 1; }
full_out="$(scripts/certify.sh fingerprint full core)" \
    || { echo "✗ certify.sh could not report the core leg's fingerprint" >&2; exit 1; }

HOOK_OUT="$hook_out" PRE_OUT="$pre_out" FULL_OUT="$full_out" python3 - <<'PYEOF'
import os, shlex, sys

def triple(label, text):
    flags = cmd = None
    for line in text.splitlines():
        if line.startswith("RUSTFLAGS="):
            flags = line[len("RUSTFLAGS="):]
        elif line.startswith("CMD="):
            cmd = shlex.split(line[len("CMD="):])
    if flags is None or cmd is None:
        sys.exit(f"✗ {label}: no RUSTFLAGS=/CMD= lines in its report:\n{text}")
    feats, profile = None, "test (inherits dev)"
    i = 0
    while i < len(cmd):
        a = cmd[i]
        if a in ("--features", "-F"):
            feats = cmd[i + 1]; i += 1
        elif a.startswith("--features="):
            feats = a.split("=", 1)[1]
        elif a == "--all-features":
            feats = "<all>"
        elif a in ("--release", "-r"):
            profile = "release"
        elif a in ("--cargo-profile", "--profile"):
            profile = cmd[i + 1]; i += 1
        i += 1
    if "--no-default-features" in cmd:
        feats = f"{feats} (no-default)"
    fs = "<default>" if feats is None else ",".join(sorted(f for f in feats.replace(",", " ").split() if f))
    return (" ".join(flags.split()), fs, profile), " ".join(cmd[:3])

rows = [
    ("pre-push hook", *triple("pre-push hook", os.environ["HOOK_OUT"])),
    ("certify prebuild core", *triple("certify prebuild", os.environ["PRE_OUT"])),
    ("certify full core", *triple("certify full", os.environ["FULL_OUT"])),
]
for name, (flags, feats, profile), tool in rows:
    print(f"  {name:24} RUSTFLAGS={flags!r:16} profile={profile:20} runner={tool}")
    print(f"  {'':24} features={feats}")
ref = rows[2][1]
bad = [name for name, t, _ in rows if t != ref]
if bad:
    for name, t, _ in rows:
        if t != ref:
            for axis, mine, theirs in zip(("RUSTFLAGS", "features", "profile"), t, ref):
                if mine != theirs:
                    print(f"✗ {name}: {axis} {mine!r} != certify core's {theirs!r}", file=sys.stderr)
    print("✗ FINGERPRINT DRIFT — these consumers compile disjoint units; every"
          " dependency is built once per distinct triple.", file=sys.stderr)
    sys.exit(1)
print("✓ one fingerprint: the hook, prebuild and certify's core leg share (RUSTFLAGS, features, profile)")
PYEOF
rc=$?

# Advisory, never the verdict: the hook git actually runs lives in the COMMON
# .git/hooks (shared by every worktree) and links into the shared checkout,
# so until this branch merges there it is the OLD body.
installed="$(git rev-parse --git-path hooks/pre-push 2>/dev/null)"
if [ -n "$installed" ] && [ -e "$installed" ] && ! cmp -s "$(readlink -f "$installed")" scripts/hooks/pre-push; then
    echo "  note: the INSTALLED pre-push ($(readlink -f "$installed")) differs from this tree's"
    echo "        scripts/hooks/pre-push — pushes run the installed one until it is updated."
fi
# Build scripts re-run (and recompile their dependents) when env they declare
# via rerun-if-env-changed changes. pyo3's reads VIRTUAL_ENV; the hook and
# certify inherit it from whoever launches them.
[ -n "${VIRTUAL_ENV:-}" ] && echo "  note: VIRTUAL_ENV is set ($VIRTUAL_ENV) — pyo3's build script keys on it; launch the hook and certify from the same environment."
exit "$rc"
