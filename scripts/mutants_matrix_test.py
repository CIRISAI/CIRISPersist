#!/usr/bin/env python3
"""mutants_matrix_test.py — witnesses for scripts/mutants_matrix.py and
scripts/unvalidated_witnesses.py, against fixture tool outputs. No tool run,
no cargo.

    python3 scripts/mutants_matrix_test.py

v54.1.0 (CIRISPersist#1051): the cargo-mutants collector is read against a
trimmed copy of the first nightly run's own output
(scripts/mutants/testdata/cargo-mutants-27.1/, run 37936369914 on 650024b1,
logs cut to nextest's status lines with their colour escapes intact). That
run's matrix listed 0 witnesses and credited no kill, because the escapes hid
every status line from the parser; the report then said "0 witnesses ran".
The verdict (exit 0/4/5), the allow-list grammar and the test-only exclusion
are witnessed here too, each against an input that must make it fail.

mutest's harness runs the WHOLE lib suite, and the matrix keeps only the
scope's witnesses. A mutant's outcome must therefore come from the retained
witnesses' rows, not from mutest's overall flag: a mutant only an
out-of-scope test detected is `caught_out_of_scope`, and a crash no retained
row attributes is `crashed` (Codex on PR #1039).
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutants_matrix as mm  # noqa: E402
import unvalidated_witnesses as uw  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "mutants" / "testdata" / "cargo-mutants-27.1"

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
        # `src/x.rs` exists only in the fixture: the whole file is in scope.
        with mock.patch.object(mm, "scope_ranges", return_value=[("src/x.rs", 1, 10**9)]):
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


# ── cargo-mutants, the first nightly run's own output ──────────────────────

OBSERVE = [("src/observe/mod.rs", 1, 10**9), ("src/observe/catalog.rs", 1, 10**9)]
OBSERVE_SCOPE = {"tests": "test(/i548|i549|i550|i551/)", "witnesses": ["src/observe/tests.rs"],
                 "entries": [{"file": f, "fns": []} for f, _, _ in OBSERVE]}


class CargoMutantsRealArtifact(unittest.TestCase):
    def setUp(self):
        # The fixture's line numbers are 650024b1's; pin the ranges so a
        # later edit to src/observe/ cannot move a fixture mutant out of scope.
        with mock.patch.object(mm, "scope_ranges", return_value=OBSERVE):
            self.tests, self.mutants, self.dropped, self.unreached = \
                mm.collect_cargo_mutants(FIXTURE, OBSERVE_SCOPE)
        self.by_site = {m["description"].split(": ", 1)[0]: m for m in self.mutants}

    def test_every_witness_the_baseline_ran_is_read_through_the_colour_escapes(self):
        self.assertEqual(len(self.tests), 22, self.tests)
        self.assertIn("observe::tests::memory::i549", self.tests)

    def test_kills_are_attributed_to_the_witnesses_that_failed(self):
        bit = self.by_site["src/observe/mod.rs:177:9"]
        self.assertEqual(bit["outcome"], "caught")
        self.assertEqual(bit["killed_by"], ["observe::tests::memory::i549",
                                            "observe::tests::postgres::i549",
                                            "observe::tests::sqlite::i549"])

    def test_each_outcome_is_read(self):
        got = {site: m["outcome"] for site, m in self.by_site.items()}
        self.assertEqual(got, {
            "src/observe/mod.rs:177:9": "caught",
            "src/observe/mod.rs:189:9": "unviable",
            "src/observe/mod.rs:249:22": "missed",
            "src/observe/mod.rs:318:18": "timeout",
            "src/observe/mod.rs:289:5": "not_run",
            "src/observe/catalog.rs:53:9": "not_run",
        })

    def test_a_mutant_whose_span_enters_the_scope_is_judged(self):
        # `counters()`'s whole-body replacement starts on its `#[cfg(test)]`
        # statement (lines 289-292, a test-only hole) and ends on `&GLOBAL`
        # (293). `--in-diff` keeps it, so the tool tests it; judged by its
        # first line alone the matrix filed it out of scope, where a
        # survivor never reaches the verdict.
        holed = [("src/observe/mod.rs", 1, 288), ("src/observe/mod.rs", 293, 10**9),
                 ("src/observe/catalog.rs", 1, 10**9)]
        with mock.patch.object(mm, "scope_ranges", return_value=holed):
            _, mutants, dropped, _ = mm.collect_cargo_mutants(FIXTURE, OBSERVE_SCOPE)
        sites = {m["description"].split(": ", 1)[0] for m in mutants}
        self.assertIn("src/observe/mod.rs:289:5", sites)
        self.assertFalse([d for d in dropped if "replace counters" in d], dropped)
        # A span wholly inside the hole stays out.
        self.assertFalse(mm.in_scope(holed, "src/observe/mod.rs", 289, 292))

    def test_the_unvalidated_report_counts_the_witnesses_that_ran(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            mm.write_matrix("cargo-mutants", "scope.txt", OBSERVE_SCOPE, self.tests, self.mutants,
                            self.dropped, self.unreached, out, {"budget_hit": "1", "tool_rc": "124"})
            scope = out / "scope.txt"
            scope.write_text("tests: test(/i549/)\nwitnesses: src/observe/tests.rs\nsrc/observe/mod.rs\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(uw.main(["uw", str(out / "matrix.json"), str(scope)]), 0)
        report = buf.getvalue()
        # 13 I548 witnesses (an *_invariants.rs) + 9 in src/observe/tests.rs.
        self.assertIn("22 witnesses ran;", report)
        self.assertNotIn(" 0 witnesses ran", report)
        self.assertIn("ZERO SO FAR", report)

    def test_a_green_baseline_with_no_readable_status_line_is_refused(self):
        # The parser failing must not read as "no witness ran".
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "log").mkdir()
            (root / "log" / "baseline.log").write_text("\x1b[1mPASSED\x1b[0m everything\n")
            (root / "outcomes.json").write_text(json.dumps({"outcomes": [
                {"scenario": "Baseline", "summary": "Success", "log_path": "log/baseline.log"}]}))
            with self.assertRaises(SystemExit) as e:
                mm.collect_cargo_mutants(root, OBSERVE_SCOPE)
            self.assertIn("no nextest result line", str(e.exception))


# ── scope selection: test-only items and the --in-diff ─────────────────────

GATED_SRC = """pub fn prod(a: u32) -> u32 {
    a + 1
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod r2_test_support {
    pub fn helper() -> u32 { 2 }
}

#[cfg(any(test, feature = "x"))]
pub fn maybe_prod() -> u32 { 3 }

#[cfg(not(test))]
pub fn not_test() -> u32 { 4 }

pub fn with_probe() {
    #[cfg(test)]
    crate::probe::record("}");
    let _ = 5;
}

mod pqc_test_support {
    pub fn x() {}
}
"""


class TestOnlyItemsLeaveTheScope(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.file = str(Path(self.tmp.name) / "x.rs")
        Path(self.file).write_text(GATED_SRC)

    def tearDown(self):
        self.tmp.cleanup()

    def test_only_test_only_items_are_cut(self):
        self.assertEqual(mm.test_gated_ranges(self.file), [(5, 8), (17, 18), (22, 24)])

    def test_the_diff_adds_exactly_the_scope_lines(self):
        scope = {"entries": [{"file": self.file, "fns": []}]}
        ranges = mm.scope_ranges(scope)
        added = [n for n, line in enumerate(mm.scope_diff(ranges).splitlines()[4:], 1)
                 if line.startswith("+")]
        cut = {5, 6, 7, 8, 17, 18, 22, 23, 24}
        self.assertEqual(added, [n for n in range(1, 25) if n not in cut])
        header = mm.scope_diff(ranges).splitlines()[3]
        self.assertEqual(header, f"@@ -1,{len(cut)} +1,24 @@")

    def test_a_named_fn_keeps_only_its_production_lines(self):
        scope = {"entries": [{"file": self.file, "fns": ["with_probe"]}]}
        self.assertEqual(mm.scope_ranges(scope), [(self.file, 16, 16), (self.file, 19, 20)])


# ── the verdict ─────────────────────────────────────────────────────────────


def _matrix(outcomes: dict[str, str], complete: bool = True, rc: str = "2") -> dict:
    mutants = []
    for i, (desc, outcome) in enumerate(outcomes.items(), 1):
        file, line, _ = desc.split(":", 2)
        mutants.append({"id": i, "file": file, "line": int(line), "col": 1,
                        "description": desc, "outcome": outcome, "killed_by": []})
    summary = {"mutants": len(mutants), **{k: sum(m["outcome"] == k for m in mutants)
                                           for k in mm.OUTCOMES}}
    return {"scope": "scripts/mutants/scope-x.txt", "tool": "cargo-mutants", "complete": complete,
            "tool_rc": rc, "summary": summary, "mutants": mutants}


SNAPSHOT = "src/observe/mod.rs:249:22: replace > with >= in Counters::snapshot"
FOLD = "src/observe/mod.rs:344:59: replace | with ^ in fold"
CAUGHT = "src/observe/mod.rs:177:9: replace Fold::bit -> u32 with 0"


class Verdict(unittest.TestCase):
    def allow(self, text: str) -> list[dict]:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write(text)
        self.addCleanup(os.unlink, f.name)
        return mm.parse_allow_list(f.name)

    def test_complete_with_every_survivor_listed_passes(self):
        allow = self.allow("# comment\nsrc/observe/mod.rs:249 replace > with >= in Counters::snapshot #1037\n")
        rc, ann, md = mm.verdict(_matrix({SNAPSHOT: "missed", CAUGHT: "caught"}), allow)
        self.assertEqual(rc, 0)
        self.assertTrue(ann[0].startswith("::warning file=src/observe/mod.rs,line=249,"), ann)
        self.assertIn("#1037", "\n".join(md))

    def test_an_unlisted_survivor_fails_with_an_error_annotation(self):
        allow = self.allow("src/observe/mod.rs:249 replace > with >= in Counters::snapshot #1037\n")
        rc, ann, _ = mm.verdict(_matrix({SNAPSHOT: "missed", FOLD: "missed"}), allow)
        self.assertEqual(rc, 5)
        self.assertTrue(any(a.startswith("::error file=src/observe/mod.rs,line=344,") for a in ann), ann)

    def test_a_timeout_is_a_survivor(self):
        rc, _, _ = mm.verdict(_matrix({"src/observe/mod.rs:318:18: replace &= with |= in record_read": "timeout"}), [])
        self.assertEqual(rc, 5)

    def test_the_listed_line_must_match_when_given(self):
        allow = self.allow("src/observe/mod.rs:250 replace > with >= in Counters::snapshot #1037\n")
        self.assertEqual(mm.verdict(_matrix({SNAPSHOT: "missed"}), allow)[0], 5)
        allow = self.allow("src/observe/mod.rs replace > with >= in Counters::snapshot #1037 any line\n")
        self.assertEqual(mm.verdict(_matrix({SNAPSHOT: "missed"}), allow)[0], 0)

    def test_an_incomplete_run_fails_even_with_no_survivor(self):
        rc, ann, md = mm.verdict(_matrix({CAUGHT: "caught", "src/x.rs:1:1: y": "not_run"}, complete=False, rc="124"), [])
        self.assertEqual(rc, 4)
        self.assertIn("INCOMPLETE", ann[0])
        self.assertIn("budget hit (tool exit 124)", "\n".join(md))

    def test_a_tested_mutant_filed_out_of_scope_fails(self):
        mx = _matrix({CAUGHT: "caught"})
        mx["out_of_scope"] = ["src/observe/mod.rs:289:5: replace counters -> &'static Counters with x"]
        rc, ann, md = mm.verdict(mx, [])
        self.assertEqual(rc, 5)
        self.assertIn("scope disagreement", ann[0])
        self.assertIn("FAIL (scope disagreement)", "\n".join(md))
        mx["tool"] = "mutest"
        self.assertEqual(mm.verdict(mx, [])[0], 0)

    def test_an_allow_entry_without_an_issue_is_refused(self):
        for bad in ("src/observe/mod.rs:249 replace > with >= in Counters::snapshot\n",
                    "src/observe/mod.rs:249 #1037\n",
                    "replace > with >= #1037\n"):
            with self.assertRaises(SystemExit, msg=bad):
                self.allow(bad)

    def test_the_main_entry_writes_the_step_summary_and_returns_the_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            m, a, summary = (Path(tmp) / n for n in ("m.json", "allow.txt", "summary.md"))
            m.write_text(json.dumps(_matrix({FOLD: "missed"})))
            a.write_text("# empty\n")
            env = {"GITHUB_STEP_SUMMARY": str(summary), "GITHUB_REPOSITORY": "o/r",
                   "GITHUB_SERVER_URL": "https://github.com"}
            with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(io.StringIO()) as out:
                rc = mm.main(["mm", "verdict", str(m), str(a)])
            self.assertEqual(rc, 5)
            self.assertIn("::error file=src/observe/mod.rs,line=344", out.getvalue())
            self.assertIn("not allow-listed", summary.read_text())

    def test_the_committed_allow_list_parses(self):
        mm.parse_allow_list(str(Path(__file__).resolve().parent / "mutants" / "allowed_survivors.txt"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
