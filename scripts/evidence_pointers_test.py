#!/usr/bin/env python3
"""evidence_pointers_test.py — witnesses for scripts/evidence_pointers.py
(CIRISPersist#934, #1076 slice T item 0).

    python3 scripts/evidence_pointers_test.py

The gate must be RED on: a row to a missing symbol; a symbol that MOVED to
another file (until the row is repointed, then green); a name that survives
only in a doc comment, a block comment, a string literal or a call site (the
v54 -> v55 `holds_bytes_attestation_envelope` shape); `Owner::member` when the
member belongs to a different owner; a malformed row; an empty table. And
GREEN on every definition form the real table uses. The last witnesses run
the real tree: it passes, and deleting one real cited definition while every
other mention of the name stays makes it fail.
"""
from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_pointers as ep  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
HEADER = "# comment\ndecimal_id\tclaim_id\trepo\tpath#symbol\tcrate@version\n"

A_RS = '''\
//! module doc naming fn ghost_in_doc
use crate::other::imported_only;

/// [`ghost_in_doc`] is mentioned here.
pub fn present(x: u8) -> u8 { x }

pub(crate) async fn present_async() {}
pub const fn present_const_fn() {}
pub const LIMIT: usize = 3;
pub static GLOBAL: u8 = 0;
pub type Alias = u8;
macro_rules! present_macro { () => {} }

pub enum Op {
    #[serde(rename = "strip")]
    StripField { name: String },
    Drop(u8),
    Keep,
    Code = 4,
}

pub struct Row<'a, T: Clone> where T: Send {
    pub(crate) holder: &'a T,
    count: usize,
}

pub struct Unit;
pub struct Tuple(u8);

impl<'a, T: Clone + Send> Row<'a, T> {
    pub fn from_attestation(&self) -> u8 { calls_only(1) }
    const MAX: u8 = 1;
}

impl std::fmt::Display for Unit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Ok(()) }
}

pub trait Policy { fn admit_key_record(&self); }

/* fn ghost_in_block /* nested fn ghost_nested */ */
const NAMES: &[&str] = &["ghost_in_string", "fn ghost_fn_in_string"];
const RAW: &str = r#"fn ghost_in_raw() {}"#;
const CH: char = '"'; pub fn after_char_quote() {}

fn caller() { ghost_called(1); let v = [ghost_listed, 2]; }

#[cfg(test)]
mod tests {
    #[test]
    fn a_witness() {}
}
'''

B_RS = "pub fn moved_here() {}\npub enum Other { Keep2, Shared }\npub enum Op2 { Shared }\n"


def tree(rows: list[str], files: dict[str, str] | None = None) -> tempfile.TemporaryDirectory:
    d = tempfile.TemporaryDirectory()
    root = Path(d.name)
    (root / "evidence").mkdir()
    (root / "evidence/cc_impl.tsv").write_text(HEADER + "".join(r + "\n" for r in rows))
    for rel, text in (files or {"src/a.rs": A_RS, "src/b.rs": B_RS}).items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    return d


def row(ptr: str, dec: str = "3.1.1") -> str:
    return f"{dec}\tCLM-x\tCIRISPersist\t{ptr}\tciris-persist@1.0.0"


def run(root: str, *args: str) -> tuple[int, str]:
    buf = io.StringIO()
    with mock.patch.dict(os.environ, {"EVIDENCE_POINTERS_ROOT": root}), \
            contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        rc = ep.main(["evidence_pointers.py", *args])
    return rc, buf.getvalue()


class Predicate(unittest.TestCase):
    def test_every_definition_form_resolves(self):
        for sym in ["present", "present_async", "present_const_fn", "LIMIT", "GLOBAL",
                    "Alias", "present_macro", "Op", "Row", "Unit", "Tuple", "Policy",
                    "Op::StripField", "Op::Drop", "Op::Keep", "Op::Code",
                    "Row::from_attestation", "Row::MAX", "Row::holder", "Row::count",
                    "Policy::admit_key_record", "Unit::fmt", "after_char_quote",
                    "crate::a::Op::Keep", "StripField", "holder", "a_witness"]:
            self.assertTrue(ep.defines(A_RS, sym), sym)

    def test_a_mention_is_not_a_definition(self):
        for sym in ["ghost_in_doc", "ghost_in_block", "ghost_nested", "ghost_in_string",
                    "ghost_fn_in_string", "ghost_in_raw", "ghost_called", "ghost_listed",
                    "imported_only", "calls_only", "missing"]:
            self.assertFalse(ep.defines(A_RS, sym), sym)

    def test_a_member_must_belong_to_the_named_owner(self):
        self.assertFalse(ep.defines(A_RS, "Op::from_attestation"))
        self.assertFalse(ep.defines(A_RS, "Row::StripField"))
        self.assertFalse(ep.defines(A_RS, "Policy::present"))
        self.assertFalse(ep.defines(A_RS, "Missing::Keep"))
        self.assertTrue(ep.defines(B_RS, "Op2::Shared"))
        self.assertFalse(ep.defines(B_RS, "Op2::Keep2"))

    def test_the_holds_bytes_shape(self):
        # v54 -> v55: the function was deleted; its name stayed in a doc
        # comment and in a string literal in a test's list, the exact text the
        # in-crate witness's `<name>,` pattern accepts.
        src = ('/// through `holds_bytes_attestation_envelope`, the one builder.\n'
               'pub fn holding_claim_row() {}\n'
               '#[cfg(test)] mod t { const L: &[&str] = &[\n'
               '    "holds_bytes_attestation_envelope",\n]; }\n')
        self.assertFalse(ep.defines(src, "holds_bytes_attestation_envelope"))
        self.assertTrue(ep.defines(src, "holding_claim_row"))


class Gate(unittest.TestCase):
    def test_all_resolving_is_green(self):
        with tree([row("src/a.rs#present"), row("src/a.rs#Op::StripField"),
                   row("ciris-verify-core/src/x.rs#elsewhere")]) as d:
            rc, out = run(d, "check")
            self.assertEqual(rc, 0, out)
            self.assertIn("all 2 ", out)
            self.assertIn("1 cross-repo rows skipped", out)

    def test_a_missing_symbol_is_red(self):
        with tree([row("src/a.rs#present"), row("src/a.rs#gone_fn")]) as d:
            rc, out = run(d, "check")
            self.assertEqual(rc, 1)
            self.assertIn("DEAD", out)
            self.assertIn("src/a.rs#gone_fn", out)
            self.assertIn("1 of 2", out)

    def test_a_missing_file_is_red(self):
        with tree([row("src/nope.rs#present")]) as d:
            rc, out = run(d, "check")
            self.assertEqual(rc, 1)
            self.assertIn("file does not exist", out)

    def test_a_moved_symbol_is_red_until_repointed(self):
        with tree([row("src/a.rs#moved_here")]) as d:
            self.assertEqual(run(d, "check")[0], 1)
        with tree([row("src/b.rs#moved_here")]) as d:
            self.assertEqual(run(d, "check")[0], 0)

    def test_a_malformed_row_is_red(self):
        with tree(["3.1.1\tCLM-x\tCIRISPersist\tsrc/a.rs#present"]) as d:
            rc, out = run(d, "check")
            self.assertEqual(rc, 1)
            self.assertIn("malformed", out)
        with tree([row("src/a.rs")]) as d:
            self.assertEqual(run(d, "check")[0], 1)

    def test_an_empty_table_is_red(self):
        with tree([]) as d:
            rc, out = run(d, "check")
            self.assertEqual(rc, 1)
            self.assertIn("emptied", out)

    def test_register_mode(self):
        reg = ("claim_id\tdecimal\ttext\tpointers\tstatus\n"
               "CLM-a\t3.1\tx\timpl:CIRISPersist/src/a.rs#present,Op::Keep impl:CIRISVerify/src/z.rs#q\testablished\n"
               "CLM-b\t3.2\tx\tstaged:CIRISPersist#1 impl:CIRISPersist/src/a.rs#ghost_in_string\tstaged\n")
        with tree([row("src/a.rs#present")]) as d:
            p = Path(d) / "claims.tsv"
            p.write_text(reg)
            rc, out = run(d, "register", str(p))
            self.assertEqual(rc, 1)
            self.assertIn("1 of 3", out)
            self.assertIn("CLM-b", out)
            p.write_text(reg.splitlines(True)[0] + reg.splitlines(True)[1])
            self.assertEqual(run(d, "register", str(p))[0], 0)

    def test_usage(self):
        with tree([]) as d:
            self.assertEqual(run(d)[0], 2)
            self.assertEqual(run(d, "bogus")[0], 2)
            self.assertEqual(run(d, "check", "--ref")[0], 2)


class RealTree(unittest.TestCase):
    def test_the_real_table_resolves(self):
        rc, out = run(str(REPO), "check")
        self.assertEqual(rc, 0, out)

    def test_deleting_one_real_definition_turns_it_red(self):
        # A real cited function, its definition renamed in a copy of the file;
        # every call site, doc link and string naming it stays. The gate must
        # go red on exactly that row.
        tsv = (REPO / ep.TSV).read_text()
        rows, _ = ep.tsv_pointers(tsv)
        ptr = next(p for _, _, p in rows
                   if "::" not in p and p.endswith("#check_skew_bound"))
        path, sym = ptr.split("#")
        text = (REPO / path).read_text()
        self.assertIn(f"fn {sym}(", text)
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "evidence").mkdir()
            (Path(d) / ep.TSV).write_text(HEADER + row(ptr) + "\n")
            (Path(d) / path).parent.mkdir(parents=True)
            (Path(d) / path).write_text(text)
            self.assertEqual(run(d, "check")[0], 0)
            (Path(d) / path).write_text(text.replace(f"fn {sym}(", f"fn {sym}_renamed(", 1))
            rc, out = run(d, "check")
            self.assertEqual(rc, 1, out)
            self.assertIn(ptr, out)


if __name__ == "__main__":
    unittest.main(verbosity=1)
