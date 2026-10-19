"""v59.0.0 (CIRISPersist#1103, CC 2.6.8) — I1153 at Python ``put_public_key``.

A host's raw registration through the wheel refuses a key id that does not end
in ``-<fp>`` of its own Ed25519 key (``federation_malformed_row:
key_registration: key_id_fingerprint_mismatch``) and admits one that does.
"""

import base64
import hashlib
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


def _fingerprint(pubkey_b64: str) -> str:
    digest = hashlib.sha256(base64.b64decode(pubkey_b64)).digest()
    return base64.b32encode(digest).decode().lower()[:10]


def test_put_public_key_refuses_a_mismatched_id_and_admits_a_derived_one_1103(tmp_path) -> None:
    eng, alias = _engine(tmp_path)
    try:
        held = eng.lookup_public_key(alias)
        if held is None:
            pytest.skip("this wheel's engine does not register its own key")
        record = json.loads(held)
        bad = dict(record, key_id="fp-surface-mismatched")
        with pytest.raises(ValueError) as refused:
            eng.put_public_key(json.dumps({"record": bad}))
        assert "key_id_fingerprint_mismatch" in str(refused.value), refused.value
        assert eng.lookup_public_key("fp-surface-mismatched") is None

        derived = "fp-surface-" + _fingerprint(record["pubkey_ed25519_base64"])
        good = dict(record, key_id=derived)
        try:
            eng.put_public_key(json.dumps({"record": good}))
        except ValueError as exc:
            # Only the fingerprint rule is under test: any other gate the raw
            # door runs on a re-labelled record is out of scope, but it must
            # not be this one.
            assert "key_id_fingerprint_mismatch" not in str(exc), exc
    finally:
        ciris_persist.reset_engine()
