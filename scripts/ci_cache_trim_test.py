#!/usr/bin/env python3
"""ci_cache_trim_test.py — witnesses for scripts/ci_cache_trim.py (CIRISPersist#1022).

    python3 scripts/ci_cache_trim_test.py

A fixture target/ with this crate's outputs and its dependencies' side by side:
the trim must remove every own output and no dependency's, including the ones
whose names start with an own name.
"""
from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_cache_trim as ct  # noqa: E402

H = "0123456789abcdef"
OWN = [
    "debug/deps/ciris_persist-" + H,               # the lib test binary
    "debug/deps/ciris_persist-" + H + ".d",
    "debug/deps/libciris_persist-" + H + ".rlib",
    "debug/deps/libciris_persist-" + H + ".rmeta",
    "debug/deps/qa_harness-" + H,                  # an integration test
    "debug/deps/projection-" + H,                  # a bench
    "debug/examples/derive_steward-" + H,
    "debug/examples/derive_steward",
    "debug/libciris_persist.rlib",                 # uplifted
    "debug/libciris_persist.d",
    "debug/.fingerprint/ciris-persist-" + H + "/lib-ciris_persist",
    "debug/build/ciris-persist-" + H + "/output",
    "debug/incremental/ciris_persist-1x2y3z/s-abc/dep-graph.bin",
    "release/deps/libciris_persist-" + H + ".so",
    "release/libciris_persist.so",
    "aarch64-linux-android/release/deps/libciris_persist-" + H + ".so",   # a cross build
]
KEEP = [
    "debug/deps/libserde-" + H + ".rlib",
    "debug/deps/libciris_verify_core-" + H + ".rlib",
    "debug/deps/libciris_persist_derive-" + H + ".rlib",   # an own-name PREFIX, another crate
    "debug/.fingerprint/ciris-persist-derive-" + H + "/lib-x",
    "debug/.fingerprint/serde-" + H + "/lib-serde",
    "debug/build/pyo3-ffi-" + H + "/output",
    "release/deps/libtokio-" + H + ".rlib",
    "release/.fingerprint/tokio-" + H + "/lib-tokio",
    "debug/.cargo-lock",
    "aarch64-linux-android/release/deps/libring-" + H + ".rlib",
]
NAMES = ["ciris-persist", "qa_harness", "projection", "derive_steward"]


class Trim(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.t = Path(self.tmp.name) / "target"
        for rel in OWN + KEEP:
            p = self.t / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"x" * 1000)

    def tearDown(self):
        self.tmp.cleanup()

    def run_trim(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(ct.main(["ct", str(self.t), *NAMES]), 0)
        return out.getvalue()

    def test_every_own_output_goes(self):
        self.run_trim()
        left = [r for r in OWN if (self.t / r).exists()]
        self.assertEqual(left, [])
        for d in ("debug/.fingerprint/ciris-persist-" + H, "debug/build/ciris-persist-" + H,
                  "debug/incremental/ciris_persist-1x2y3z"):
            self.assertFalse((self.t / d).exists(), d)

    def test_no_dependency_output_goes(self):
        self.run_trim()
        gone = [r for r in KEEP if not (self.t / r).exists()]
        self.assertEqual(gone, [])

    def test_it_reports_what_it_freed(self):
        self.assertIn("removed 16 own outputs", self.run_trim())

    def test_a_missing_target_is_not_an_error(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ct.main(["ct", str(self.t / "nope"), *NAMES]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
