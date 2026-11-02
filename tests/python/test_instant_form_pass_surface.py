"""v61 (CC 2.6.2) — the open-time instant-form pass, from the host surface.

`Engine(...)` runs the pass at open (the same leg every Rust constructor
runs, `Engine::settle_at_open`). `settle_instant_forms_json()` runs it again
on demand and returns its counts. The pass over v60-shaped rows is witnessed
in-crate through the Python constructor itself (I-IFP-10, sqlite and
postgres: `src/ffi/pyo3/instant_form_open_tests.rs`), because no door admits
an offset-form row for this test to seed. This checks the surface: the eight
counts, and that a second call re-states nothing. Skips on a non-sqlite wheel.
"""
from __future__ import annotations

import json
import os
import secrets
import tempfile

import pytest

import ciris_persist

COUNTS = (
    "scanned",
    "violations",
    "healed",
    "already_healed",
    "heal_refused",
    "own_left",
    "kept_in_force",
    "set_aside",
)


def test_settle_instant_forms_json_reports_the_counts_and_is_idempotent() -> None:
    ciris_persist.reset_engine()
    d = tempfile.mkdtemp()
    seed = os.path.join(d, "seed")
    pqc_seed = os.path.join(d, "pqc.seed")
    with open(seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    with open(pqc_seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    alias = "ifp-" + secrets.token_hex(8)
    try:
        eng = ciris_persist.Engine(
            "sqlite:///" + os.path.join(d, "node.db"),
            alias,
            local_key_id=alias,
            local_key_path=seed,
            local_pqc_key_id=alias + "-pqc",
            local_pqc_key_path=pqc_seed,
        )
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        for _ in range(2):
            counts = json.loads(eng.settle_instant_forms_json())
            assert set(COUNTS) <= set(counts), counts
            assert counts["healed"] == 0, counts
            assert counts["set_aside"] == 0, counts
            assert counts["heal_refused"] == 0, counts
    finally:
        eng.close(force=True)
        ciris_persist.reset_engine()
