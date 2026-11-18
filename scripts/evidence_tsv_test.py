#!/usr/bin/env python3
"""evidence_tsv_test.py — witnesses for scripts/evidence_tsv.py (CIRISPersist#1052).

    python3 scripts/evidence_tsv_test.py

Fixture trees (a Cargo.toml, a manifest, a tsv) under EVIDENCE_TSV_ROOT. The
check must be red on drift in each direction (a row only the tsv has, an entry
only the manifest has) and on a stale version stamp, and the real tree must
pass. v62.0.0: the span_sha256 column — a src/ row's cell is the hash of the
cited item's text, so a body change under an unchanged name reds the check, a
symbol that is not exactly one item fails generation, and `span_excluded`
holds only while the symbol does not hash.
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
import evidence_tsv as et  # noqa: E402
import span_of  # noqa: E402

# The fixture sources the two src/ rows cite (and the late entries' targets).
SOURCES = {
    "src/federation/admission.rs": "pub fn resolve_withdraws_admission_rule_at() -> u8 {\n    1\n}\n",
    "src/federation/topology.rs": "/// doc\npub const DEFAULT_DELEGATION_DEPTH: usize = 5;\n",
    "src/lib.rs": "pub fn y() {}\npub fn twice() {}\nmod m { pub fn twice() {} }\n",
}


def span(path: str, sym: str) -> str:
    return span_of.span_sha256(SOURCES[path], sym)


def entry(dec, claim, path, **kw):
    return {"decimal_id": dec, "claim_id": claim, "repo": "CIRISPersist",
            "path#symbol": path, "tsv_target": et.TARGET, **kw}


ENTRIES = [
    entry("3.3.1", "CLM-a", "src/federation/admission.rs#resolve_withdraws_admission_rule_at"),
    entry("4.1.1", "CLM-b", "src/federation/topology.rs#DEFAULT_DELEGATION_DEPTH",
          tsv_comment_before=["", "# a section note"]),
    entry("3.1.1", "CLM-c", "ciris-verify-core/src/accord_genesis.rs#build", crate="ciris-persist@31.0.0"),
    {**entry("3.1.9.4", "CLM-d", "src/safety/watchlist.rs#enable_watchlist"),
     "tsv_target": "n/a", "tsv_excluded": "the file does not exist"},
]


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "evidence").mkdir()
        (self.root / et.MANIFEST_REL).parent.mkdir(parents=True)
        for rel, text in SOURCES.items():
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.root / rel).write_text(text)
        (self.root / "Cargo.toml").write_text('[package]\nname = "ciris-persist"\nversion = "54.1.0"\n\n[dependencies]\nx = { version = "1.0" }\n')
        self.write_manifest(ENTRIES)
        self.assertEqual(self.run_main("write")[0], 0)

    def tearDown(self):
        self.tmp.cleanup()

    def write_manifest(self, entries):
        (self.root / et.MANIFEST_REL).write_text(
            json.dumps({"evidence_export": {"CIRISPersist": entries}}, indent=1))

    def tsv(self) -> Path:
        return self.root / et.TARGET

    def run_main(self, cmd):
        with mock.patch.dict(os.environ, {"EVIDENCE_TSV_ROOT": str(self.root)}), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            rc = et.main(["et", cmd])
        return rc, out.getvalue()

    def test_the_generated_rows(self):
        rows = [r for r in self.tsv().read_text().splitlines() if r and not r.startswith("#")][1:]
        self.assertEqual(rows, [
            "3.3.1\tCLM-a\tCIRISPersist\tsrc/federation/admission.rs#resolve_withdraws_admission_rule_at\tciris-persist@54.1.0\t"
            + span("src/federation/admission.rs", "resolve_withdraws_admission_rule_at"),
            "4.1.1\tCLM-b\tCIRISPersist\tsrc/federation/topology.rs#DEFAULT_DELEGATION_DEPTH\tciris-persist@54.1.0\t"
            + span("src/federation/topology.rs", "DEFAULT_DELEGATION_DEPTH"),
            "3.1.1\tCLM-c\tCIRISPersist\tciris-verify-core/src/accord_genesis.rs#build\tciris-persist@31.0.0\t",
        ])
        self.assertIn("\n\n# a section note\n4.1.1\t", self.tsv().read_text())
        self.assertEqual(self.run_main("check")[0], 0)

    def test_a_row_only_the_tsv_has_is_red(self):
        with self.tsv().open("a") as f:
            f.write("9.9\tCLM-hand\tCIRISPersist\tsrc/lib.rs#x\tciris-persist@54.1.0\n")
        rc, out = self.run_main("check")
        self.assertEqual(rc, 1)
        self.assertIn("-9.9\tCLM-hand", out)
        self.assertIn("EVIDENCE TSV DRIFT", out)

    def test_an_entry_only_the_manifest_has_is_red(self):
        self.write_manifest(ENTRIES + [entry("5.1", "CLM-new", "src/lib.rs#y")])
        rc, out = self.run_main("check")
        self.assertEqual(rc, 1)
        self.assertIn("+5.1\tCLM-new", out)

    def test_a_version_bump_changes_every_src_row_and_no_other(self):
        cargo = self.root / "Cargo.toml"
        cargo.write_text(cargo.read_text().replace('version = "54.1.0"', 'version = "54.2.0"', 1))
        rc, out = self.run_main("check")
        self.assertEqual(rc, 1)
        self.assertEqual(out.count("+3.") + out.count("+4."), 2, out)  # the two src/ rows
        self.assertNotIn("+3.1.1\tCLM-c", out)                       # the cross-repo row keeps its stamp
        self.assertNotIn('"1.0"', self.tsv().read_text())             # a dependency's version is not ours

    def test_an_excluded_entry_needs_a_reason(self):
        bad = [*ENTRIES[:3], {**ENTRIES[3], "tsv_excluded": ""}]
        self.write_manifest(bad)
        with self.assertRaises(SystemExit):
            self.run_main("check")

    def test_a_body_change_under_an_unchanged_name_is_red(self):
        src = self.root / "src/federation/admission.rs"
        src.write_text(src.read_text().replace("    1\n", "    2\n"))
        rc, out = self.run_main("check")
        self.assertEqual(rc, 1)
        self.assertIn("+3.3.1\tCLM-a", out)
        # a doc comment above the item is not its span
        src.write_text("/// a new doc line\n" + SOURCES["src/federation/admission.rs"])
        self.assertEqual(self.run_main("check")[0], 0)

    def test_a_symbol_that_is_not_one_item_fails_generation(self):
        for sym in ("missing", "twice"):
            self.write_manifest(ENTRIES + [entry("5.1", "CLM-new", f"src/lib.rs#{sym}")])
            with self.assertRaises(SystemExit):
                self.run_main("check")

    def test_span_excluded_holds_only_while_the_symbol_does_not_hash(self):
        ok = entry("5.1", "CLM-new", "src/lib.rs#twice", span_excluded="two declarations")
        self.write_manifest(ENTRIES + [ok])
        self.assertEqual(self.run_main("write")[0], 0)
        self.assertIn("src/lib.rs#twice\tciris-persist@54.1.0\t\n", self.tsv().read_text())
        stale = entry("5.1", "CLM-new", "src/lib.rs#y", span_excluded="no longer true")
        self.write_manifest(ENTRIES + [stale])
        with self.assertRaises(SystemExit):
            self.run_main("check")
        for bad in (entry("5.1", "CLM-new", "src/lib.rs#twice", span_excluded=""),
                    entry("5.2", "CLM-new", "ciris-verify-core/src/x.rs#y", crate="c@1", span_excluded="x")):
            self.write_manifest(ENTRIES + [bad])
            with self.assertRaises(SystemExit):
                self.run_main("check")

    def test_a_cross_repo_row_needs_its_own_stamp(self):
        self.write_manifest([entry("3.1.1", "CLM-c", "ciris-verify-core/src/x.rs#y")])
        with self.assertRaises(SystemExit):
            self.run_main("check")


class RealTree(unittest.TestCase):
    def test_the_committed_tsv_is_the_generated_one(self):
        with mock.patch.dict(os.environ, {"EVIDENCE_TSV_ROOT": ""}), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            rc = et.main(["et", "check"])
        self.assertEqual(rc, 0, out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
