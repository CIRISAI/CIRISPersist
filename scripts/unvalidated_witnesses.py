#!/usr/bin/env python3
"""unvalidated_witnesses.py — witnesses in a mutation scope that killed nothing.

CIRISPersist#1024. A witness that no mutant in its module makes fail has never
been shown to catch anything; until it is, it is a hypothesis about a gate
(Beyer 2022's "unvalidated witness"). This reads a matrix written by
`scripts/mutants.sh` and lists every test that ran and killed zero mutants,
when the test is defined in a `*_invariants.rs` file or in a file the scope
names on a `witnesses:` line.

REPORT-ONLY this cut: always exits 0 when the matrix can be read. A zero is
not automatically a defect: the scope may simply not contain the code the
witness guards. It says where to look.

Usage:
    scripts/unvalidated_witnesses.py <matrix.json> [<scope-file>]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import mutants_matrix as mm  # noqa: E402


def test_file(test: str) -> str | None:
    """The source file a lib test `a::b::c::name` is defined in: the longest
    module prefix that is a file (`src/a/b.rs` or `src/a/b/mod.rs`)."""
    parts = test.split("::")[:-1]
    for n in range(len(parts), 0, -1):
        stem = "src/" + "/".join(parts[:n])
        for cand in (stem + ".rs", stem + "/mod.rs"):
            if (REPO / cand).is_file():
                return cand
    return None


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    matrix = json.loads(Path(argv[1]).read_text())
    extra = set(mm.parse_scope(argv[2])["witnesses"]) if len(argv) > 2 else set()
    kills = matrix["kills_per_test"]
    rows = []
    for test in matrix["tests"]:
        f = test_file(test)
        if f is None or not (f.endswith("_invariants.rs") or f in extra):
            continue
        rows.append((f, test, kills.get(test, 0)))
    never = set(matrix.get("tests_never_run", []))
    zero = [r for r in rows if r[2] == 0 and r[1] not in never]
    unrun = [r for r in rows if r[1] in never]
    print(f"unvalidated witnesses — {matrix['scope']} ({matrix['tool']}, "
          f"{matrix['summary']['mutants']} mutants, "
          f"{'complete' if matrix['complete'] else 'INCOMPLETE run'})")
    print(f"  {len(rows) - len(unrun)} witnesses ran; {len(zero)} killed no mutant")
    for f, test, _ in sorted(zero):
        print(f"  UNVALIDATED  {test}  ({f})")
    if unrun:
        print(f"  {len(unrun)} more were never run by the tool (no verdict either way):")
        for f, test, _ in sorted(unrun):
            print(f"  NOT RUN      {test}  ({f})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
