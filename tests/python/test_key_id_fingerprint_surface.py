"""v59.0.0 (CIRISPersist#1103, CC 2.6.8) — I1153 at Python ``put_public_key``.

A host's raw registration through the wheel refuses a key id that does not end
in ``-<fp>`` of its own Ed25519 key (``federation_malformed_row:
key_registration: key_id_fingerprint_mismatch``) and admits one that does.
"""

import json

import pytest

import ciris_persist


def _engine(tmp_path):
    seed = tmp_path / "fp.seed"
    pqc_seed = tmp_path / "fp.pqc"
    seed.write_bytes(bytes([0x5A] * 32))
    pqc_seed.write_bytes(bytes([0xA5] * 32))
    alias = "fp-surface"
    ciris_persist.reset_engine()
    try:
        return ciris_persist.Engine(
            "sqlite::memory:",
            alias,
            local_key_id=alias,
            local_key_path=str(seed),
            local_pqc_key_id=alias + "-pqc",
            local_pqc_key_path=str(pqc_seed),
        ), alias
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise


def test_put_public_key_refuses_a_mismatched_id_and_admits_a_derived_one_1103(tmp_path) -> None:
    eng, alias = _engine(tmp_path)
    try:
        # The engine registers its own key under the DERIVED id
        # (`<alias>-<fp>`), through the unchecked in-process executor.
        derived = eng.register_self_federation_key("agent", alias)
        assert derived != alias and derived.startswith(alias + "-"), derived
        record = json.loads(eng.lookup_public_key(derived))

        bad = dict(record, key_id="fp-surface-mismatched")
        with pytest.raises(ValueError) as refused:
            eng.put_public_key(json.dumps({"record": bad}))
        assert "key_id_fingerprint_mismatch" in str(refused.value), refused.value
        assert eng.lookup_public_key("fp-surface-mismatched") is None

        # The derived id passes the gate (an identical re-put is a no-op).
        eng.put_public_key(json.dumps({"record": record}))
        assert eng.lookup_public_key(derived) is not None
    finally:
        ciris_persist.reset_engine()
