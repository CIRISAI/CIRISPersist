#!/usr/bin/env python3
"""size_report_test.py — witnesses for scripts/size_report.py (CIRISPersist#934).

    python3 scripts/size_report_test.py

The counter against Rust snippets whose answer is known (comments inside
strings, nested block comments, raw strings, lifetimes vs char literals), and
the table / check / --fail-if-backends-grew against a fixture tree under
SIZE_REPORT_ROOT, including a `--against REF` baseline from a fixture git repo.
"""
from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import size_report as sr  # noqa: E402


def run(argv: list[str], root: Path) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, {"SIZE_REPORT_ROOT": str(root)}), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = sr.main(["size_report.py", *argv])
    return rc, out.getvalue(), err.getvalue()


class Counter(unittest.TestCase):
    def test_basic_three_columns(self):
        src = "fn a() {}\n\n// c\n    \nlet x = 1; // trailing\n/// doc\n//! inner\n"
        self.assertEqual(sr.count_rust(src), (2, 3, 2))

    def test_block_comments_nest_and_span_lines(self):
        src = "/* a\n /* nested */\n still comment\n*/\nfn f() {} /* tail\n*/\n"
        # lines 1-4 comment; line 5 code (code + comment); line 6 comment
        self.assertEqual(sr.count_rust(src), (1, 5, 0))

    def test_comment_markers_inside_strings_are_code(self):
        src = 'let u = "http://x/*y";\nlet z = 2;\n'
        self.assertEqual(sr.count_rust(src), (2, 0, 0))

    def test_multiline_string_lines_are_code_even_if_blank_or_slashy(self):
        src = 'let s = "a\n\n// not a comment\n/* nor this\n";\n// real\n'
        self.assertEqual(sr.count_rust(src), (5, 1, 0))

    def test_raw_strings(self):
        src = 'let s = r#"has " and /* inside\n// still string\n"#;\n// real\n'
        self.assertEqual(sr.count_rust(src), (3, 1, 0))

    def test_escaped_quote_does_not_close_the_string(self):
        src = 'let s = "a\\"/*b";\nlet t = 1;\n'
        self.assertEqual(sr.count_rust(src), (2, 0, 0))

    def test_lifetimes_and_char_literals(self):
        # `'"'` must not open a string; `'a` must not swallow the line.
        src = "fn f<'a>(x: &'a str) -> char { '\"' }\nlet c = '\\'';\n// c\n"
        self.assertEqual(sr.count_rust(src), (2, 1, 0))

    def test_escaped_quote_char_literal_does_not_open_a_string(self):
        src = "let q = '\\\"';\n// real\n"
        self.assertEqual(sr.count_rust(src), (1, 1, 0))

    def test_identifier_ending_in_r_is_not_a_raw_prefix(self):
        src = 'for"x" in y {}\n// c\n'
        self.assertEqual(sr.count_rust(src), (1, 1, 0))

    def test_cfg_test_is_counted(self):
        src = "#[cfg(test)]\nmod t {\n    #[test]\n    fn x() {}\n}\n"
        self.assertEqual(sr.count_rust(src), (5, 0, 0))


def tree(base: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


FILES = {
    "src/lib.rs": "pub mod store;\n// c\n",
    "src/store/sqlite.rs": "fn s() {}\n\n",
    "src/store/postgres.rs": "fn p() {}\n",
    "src/store/memory.rs": "fn m() {}\n",
    "src/ünïcode.rs": "fn u() {}\n",
    "src/data.json": "{}\n",
}


class Table(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        tree(self.root, FILES)
        (self.root / "evidence").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_write_is_sorted_rs_only_with_backends_and_total(self):
        rc, _, _ = run(["write"], self.root)
        self.assertEqual(rc, 0)
        lines = (self.root / sr.TARGET).read_text(encoding="utf-8").splitlines()
        body = [l for l in lines if not l.startswith("#")]
        self.assertEqual(body[0], "path\tcode\tcomment\tblank\tlines")
        paths = [l.split("\t")[0] for l in body[1:]]
        self.assertEqual(paths, sorted(p for p in FILES if p.endswith(".rs")) + ["BACKENDS", "TOTAL"])
        self.assertIn("BACKENDS\t3\t0\t1\t4", body)
        self.assertIn("TOTAL\t5\t1\t1\t7", body)

    def test_write_is_stable(self):
        run(["write"], self.root)
        first = (self.root / sr.TARGET).read_bytes()
        run(["write"], self.root)
        self.assertEqual(first, (self.root / sr.TARGET).read_bytes())

    def test_check_unchanged_reports_nothing_moved(self):
        run(["write"], self.root)
        rc, out, _ = run(["check", "--fail-if-backends-grew"], self.root)
        self.assertEqual(rc, 0)
        self.assertIn("no file changed size", out)

    def test_check_is_a_report_even_when_backends_grew(self):
        run(["write"], self.root)
        tree(self.root, {"src/store/sqlite.rs": "fn s() {}\n\nfn t() {}\n"})
        rc, out, _ = run(["check"], self.root)
        self.assertEqual(rc, 0)
        self.assertRegex(out, r"src/store/sqlite\.rs\s+2\s+3\s+\+1")
        self.assertRegex(out, r"BACKENDS\s+4\s+5\s+\+1")

    def test_fail_if_backends_grew_is_red_on_growth(self):
        run(["write"], self.root)
        tree(self.root, {"src/store/memory.rs": "fn m() {}\nfn n() {}\n"})
        rc, out, _ = run(["check", "--fail-if-backends-grew"], self.root)
        self.assertEqual(rc, 1)
        self.assertIn("RED", out)

    def test_fail_if_backends_grew_ignores_non_backend_growth_and_shrink(self):
        run(["write"], self.root)
        tree(self.root, {"src/lib.rs": "pub mod store;\n// c\nfn more() {}\n",
                         "src/store/sqlite.rs": "fn s() {}\n"})
        rc, out, _ = run(["check", "--fail-if-backends-grew"], self.root)
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"BACKENDS\s+4\s+3\s+-1")

    def test_added_and_removed_files_are_named(self):
        run(["write"], self.root)
        (self.root / "src/lib.rs").unlink()
        tree(self.root, {"src/new.rs": "fn n() {}\n"})
        _, out, _ = run(["check"], self.root)
        self.assertRegex(out, r"src/lib\.rs\s+2\s+0\s+-2 removed")
        self.assertRegex(out, r"src/new\.rs\s+0\s+1\s+\+1 added")

    def test_missing_baseline_is_usage_not_green(self):
        rc, _, err = run(["check"], self.root)
        self.assertEqual(rc, 2)
        self.assertIn("no evidence/size.tsv", err)

    def test_against_a_git_ref(self):
        def git(*a):
            subprocess.run(["git", "-C", str(self.root), *a], check=True, capture_output=True)
        git("init", "-q")
        git("-c", "user.name=t", "-c", "user.email=t@t", "add", "-A")
        git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base")
        tree(self.root, {"src/store/postgres.rs": "fn p() {}\nfn q() {}\n"})
        rc, out, _ = run(["check", "--against", "HEAD", "--fail-if-backends-grew"], self.root)
        self.assertEqual(rc, 1, out)
        self.assertIn("working tree vs HEAD", out)
        with self.assertRaises(SystemExit):
            run(["check", "--against", "no-such-ref"], self.root)


class RealTree(unittest.TestCase):
    def test_committed_tsv_parses_and_names_the_backends(self):
        tsv = Path(__file__).resolve().parent.parent / sr.TARGET
        if not tsv.is_file():
            self.skipTest("no committed evidence/size.tsv yet")
        rows = sr.parse(tsv.read_text(encoding="utf-8"))
        for b in sr.BACKENDS:
            self.assertIn(b, rows)


if __name__ == "__main__":
    unittest.main(verbosity=1)
