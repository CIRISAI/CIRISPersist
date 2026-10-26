"""v60.0.0 (CIRISPersist#1002; steward ruling 2026-10-25, parity even for
genesis) — ``PyEngine.install_genesis_bundle_roster_json`` on the wheel.

The import door replays the bundle on a scratch the engine's own backend
provisions (an in-memory SQLite clone here; a scratch database on postgres).
Re-importing the compiled bundle a booted node already holds writes nothing
new and reports every record held; a tampered bundle raises ``ValueError``
naming ``federation_genesis_bundle_invalid`` and installs nothing.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile

import pytest

import ciris_persist

SEED_JSON = os.path.join(
    os.path.dirname(__file__), "..", "..", "src", "federation", "genesis", "canonical_seed.json"
)


def _engine():
    ciris_persist.reset_engine()
    d = tempfile.mkdtemp()
    seed = os.path.join(d, "seed")
    pqc_seed = os.path.join(d, "pqc.seed")
    with open(seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    with open(pqc_seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    alias = "node-" + secrets.token_hex(8)
    try:
        return ciris_persist.Engine(
            "sqlite::memory:",
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


def test_install_genesis_bundle_roster_json_reimport_and_tamper() -> None:
    with open(SEED_JSON, encoding="utf-8") as fh:
        bundle_json = fh.read()
    eng = _engine()
    try:
        report = json.loads(eng.install_genesis_bundle_roster_json(bundle_json))
        assert report["records"], report
        assert all(r["outcome"] != "installed" for r in report["records"]), report

        tampered = json.loads(bundle_json)
        tampered["produced_at"] = "2099-01-01T00:00:00+00:00"
        with pytest.raises(ValueError, match="federation_genesis_bundle_invalid"):
            eng.install_genesis_bundle_roster_json(json.dumps(tampered))
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()
