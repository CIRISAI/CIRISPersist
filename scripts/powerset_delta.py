#!/usr/bin/env python3
"""powerset_delta.py — the derived powerset against certify's hand legs.

CIRISPersist#1025. `scripts/powerset.sh list` derives every feature set up to
depth 2 with cargo-hack. certify.sh builds a hand-chosen list: its LEGS (each
resolved by `ci_feature_matrix.py set <leg>`), the `lint` set, and the axis
sweep's three backend shapes per AXES entry. This script reads both and says:

  * which hand sets the powerset builds EXACTLY (same feature closure);
  * which hand sets it covers PAIRWISE only: every pair of the set's features
    is built together by some derived set, but not the whole set at once. A
    depth-2 powerset cannot contain a 4..30-feature leg; pairwise is what
    depth 2 claims;
  * which hand sets it does NOT cover even pairwise — a feature in the leg is
    excluded from the powerset, or unknown to Cargo.toml. Exit 1 on any.
  * the derived sets no hand set equals: configurations nothing builds today.

Read-only. Nothing here edits certify.sh or ci_feature_matrix.py; both are
parsed, never restated.

Usage:
    scripts/powerset_delta.py              # summary + exit code
    scripts/powerset_delta.py --verbose    # also every powerset-only set
"""
from __future__ import annotations

import itertools
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import ci_feature_matrix as cfm  # noqa: E402

CERTIFY = REPO / "scripts" / "certify.sh"
POWERSET = REPO / "scripts" / "powerset.sh"


def certify_list(var: str) -> list[str]:
    """A `VAR="a b c"` assignment from certify.sh, split."""
    m = re.search(rf'^{var}="([^"]*)"', CERTIFY.read_text(), re.MULTILINE)
    if not m:
        raise SystemExit(f"certify.sh has no {var}= line")
    return m.group(1).split()


def hand_sets() -> dict[str, list[str]]:
    """Every feature set certify.sh builds, by the name certify gives it."""
    sets: dict[str, list[str]] = {}
    for leg in [*certify_list("LEGS"), "lint"]:
        sets[leg] = cfm.feature_set(leg).split()
    # The axis sweep: `--features "$_axis"`, `"$_axis sqlite"`, `"$_axis postgres"`.
    for axis in certify_list("AXES"):
        sets[f"axis-{axis}-none"] = [axis]
        sets[f"axis-{axis}-sqlite"] = [axis, "sqlite"]
        sets[f"axis-{axis}-pg"] = [axis, "postgres"]
    # One-line `run_bg <key> ... cargo ...` legs whose feature list is literal
    # (`default` has none: the empty set). A `$` in the list is a derived set
    # already read above; `--all-features` is reported, not compared.
    for m in re.finditer(r"^\s*run_bg (\S+) (.*\bcargo (?:check|test|nextest run|clippy)\b.*)$",
                         CERTIFY.read_text(), re.MULTILINE):
        key, cmd = m.group(1), m.group(2)
        if key in sets or "--all-features" in cmd:
            continue
        f = re.search(r'--features (?:"([^"]*)"|(\S+))', cmd)
        if f is None:
            sets[key] = []
        elif "$" not in (lit := f.group(1) or f.group(2)):
            sets[key] = lit.replace(",", " ").split()
    return sets


def derived_sets() -> list[frozenset[str]]:
    out = subprocess.run(
        ["bash", str(POWERSET), "list"], capture_output=True, text=True, check=True,
        stdin=subprocess.DEVNULL,
    ).stdout
    sets = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        sets.append(frozenset() if line == "(none)" else frozenset(line.split(",")))
    if not sets:
        raise SystemExit("powerset.sh list printed no sets")
    return sets


def main(argv: list[str]) -> int:
    verbose = "--verbose" in argv
    declared = set(cfm.declared_features())
    derived = derived_sets()
    derived_closures = {frozenset(cfm.closure(sorted(d))) for d in derived}
    derived_features = set().union(*derived)

    exact, pairwise, uncovered = [], [], []
    for name, feats in hand_sets().items():
        unknown = sorted(set(feats) - declared)
        missing = sorted(set(feats) - derived_features)
        if unknown or missing:
            uncovered.append((name, f"not in the powerset: {', '.join(unknown + missing)}"))
            continue
        if frozenset(cfm.closure(feats)) in derived_closures:
            exact.append(name)
            continue
        gaps = [
            (a, b) for a, b in itertools.combinations(sorted(set(feats)), 2)
            if not any({a, b} <= c for c in derived_closures)
        ]
        if gaps:
            uncovered.append((name, f"pairs never built together: {gaps[:5]}"))
        else:
            pairwise.append((name, len(feats)))

    hand_closures = {frozenset(cfm.closure(f)) for f in hand_sets().values()}
    powerset_only = sorted(
        (sorted(d) for d in derived if frozenset(cfm.closure(sorted(d))) not in hand_closures),
        key=lambda s: (len(s), s),
    )

    print(f"powerset: {len(derived)} derived sets (depth from scripts/powerset.sh)")
    print(f"hand:     {len(hand_sets())} sets certify.sh builds (LEGS + lint + AXES x 3 shapes + literal run_bg legs)")
    print("          the --all-features clippy pass is not compared: it carries the excluded set by design")
    print()
    print(f"EXACT    ({len(exact)}): the powerset builds this very set")
    for name in exact:
        print(f"  {name}")
    print(f"PAIRWISE ({len(pairwise)}): every pair of its features is built together; the whole set is not")
    for name, n in pairwise:
        print(f"  {name} ({n} features)")
    print(f"UNCOVERED ({len(uncovered)})")
    for name, why in uncovered:
        print(f"  {name}: {why}")
    print()
    print(f"POWERSET-ONLY ({len(powerset_only)}): derived sets no hand set equals")
    shown = powerset_only if verbose else powerset_only[:15]
    for s in shown:
        print(f"  {','.join(s) or '(none)'}")
    if not verbose and len(powerset_only) > len(shown):
        print(f"  ... {len(powerset_only) - len(shown)} more (--verbose)")
    return 1 if uncovered else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
