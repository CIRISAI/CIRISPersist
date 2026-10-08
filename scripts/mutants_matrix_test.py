#!/usr/bin/env python3
"""mutants_matrix_test.py — witnesses for scripts/mutants_matrix.py's mutest
collector, against a fixture mutest output. No tool run, no cargo.

    python3 scripts/mutants_matrix_test.py

mutest's harness runs the WHOLE lib suite, and the matrix keeps only the
scope's witnesses. A mutant's outcome must therefore come from the retained
witnesses' rows, not from mutest's overall flag: a mutant only an
out-of-scope test detected is `caught_out_of_scope`, and a crash no retained
row attributes is `crashed` (Codex on PR #1039).
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutants_matrix as mm  # noqa: E402

TESTS = ["a::kept_one", "a::kept_two", "b::other"]
# One column per mutation (ids 1..7), one row per test:
#   1 kept_one detects                      -> caught by kept_one
#   2 only the out-of-scope test detects    -> caught_out_of_scope
#   3 harness crash, no row attributes it   -> crashed
#   4 nobody detects                        -> missed
#   5 kept_two times out, nobody detects    -> timeout
#   6 kept_two crashes the harness          -> caught by kept_two
#   7 out-of-scope test times out           -> caught_out_of_scope
ROWS = {
    "a::kept_one": "D--.-..",
    "a::kept_two": "---.TC.",
    "b::other":    "-D-.--T",
}
OVERALL = "DDC-TCT"
WANT = {
    1: ("caught", ["a::kept_one"]),
    2: ("caught_out_of_scope", []),
    3: ("crashed", []),
    4: ("missed", []),
    5: ("timeout", ["a::kept_two"]),
    6: ("caught", ["a::kept_two"]),
    7: ("caught_out_of_scope", []),
}


def write_fixture(root: Path) -> None:
    lib = root / "ciris_persist"
    lib.mkdir(parents=True)
    muts = [{"mutation_id": i, "display_name": f"m{i}", "mutation_op": "op",
             "origin_span": {"path": "src/x.rs", "begin": [10 + i, 5]}}
            for i in range(1, len(OVERALL) + 1)]
    (lib / "mutations.json").write_text(json.dumps({"mutations": muts}))
    ev = {"tests": [{"name": t} for t in TESTS],
          "mutation_runs": [{"mutation_detection_matrix": {
              "overall_detections": OVERALL,
              "test_detections": [ROWS[t] for t in TESTS]}}]}
    (lib / "evaluation.json").write_text(json.dumps(ev))


SCOPE = {"tests": "test(/kept/)", "witnesses": [],
         "entries": [{"file": "src/x.rs", "fns": []}]}


class MutestOutcomes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write_fixture(self.root / "json")
        self.tests, self.mutants, self.dropped, self.unreached = \
            mm.collect_mutest(self.root / "json", SCOPE)

    def tearDown(self):
        self.tmp.cleanup()

    def test_only_the_scope_witnesses_are_kept(self):
        self.assertEqual(self.tests, ["a::kept_one", "a::kept_two"])

    def test_outcome_comes_from_the_retained_rows(self):
        got = {m["id"]: (m["outcome"], m["killed_by"]) for m in self.mutants}
        self.assertEqual(got, WANT)

    def test_a_caught_mutant_always_names_a_retained_killer(self):
        for m in self.mutants:
            if m["outcome"] == "caught":
                self.assertTrue(m["killed_by"], m)

    def test_summary_counts_every_outcome(self):
        mx = mm.write_matrix("mutest", "scope.txt", SCOPE, self.tests, self.mutants,
                             self.dropped, self.unreached, self.root / "out", {})
        s = mx["summary"]
        self.assertEqual(
            {k: s.get(k) for k in ("mutants", "caught", "caught_out_of_scope", "crashed",
                                   "missed", "timeout", "unviable", "not_run")},
            {"mutants": 7, "caught": 2, "caught_out_of_scope": 2, "crashed": 1,
             "missed": 1, "timeout": 1, "unviable": 0, "not_run": 0})
        self.assertEqual(sum(v for k, v in s.items() if k != "mutants"), s["mutants"])
        md = (self.root / "out" / "matrix.md").read_text()
        self.assertIn("caught out of scope", md)


if __name__ == "__main__":
    unittest.main(verbosity=2)
