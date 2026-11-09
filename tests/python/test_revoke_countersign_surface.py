"""v61.1.0 (CIRISPersist#1226; CC rc14 4.4.3.2.8,
``CLM-affiliation-one-voice-countersign``) — the Python surface of the cohort
revoke door's co-signatures.

The Rust witnesses (I1610–I1615, sqlite and postgres) prove that a
countersigned removal through ``revoke_member`` admits, that a missing or
wrong-signer countersign is refused, that a forged one is refused at
verification, and that the JSON a host sends round-trips into the spec that
drives the door. This file asks what a host sees from the wheel: the
``cosignatures`` member of ``revoke_spec_json`` is READ (a malformed list is a
refusal, not silently dropped), and a ``self`` removal carrying one is refused.
"""
from __future__ import annotations

import json

import pytest

import ciris_persist


def _engine(tmp_path, name: str, fill: int):
    """A sqlite engine with a hybrid LocalSigner from fixed seeds, or a skip."""
    seed = tmp_path / f"{name}.seed"
    pqc_seed = tmp_path / f"{name}.pqc"
    seed.write_bytes(bytes([fill] * 32))
    pqc_seed.write_bytes(bytes([fill ^ 0xFF] * 32))
    alias = f"revoke-countersign-{name}"
    ciris_persist.reset_engine()
    try:
        return ciris_persist.Engine(
            "sqlite::memory:",
            alias,
            local_key_id=alias,
            local_key_path=str(seed),
            local_pqc_key_id=alias + "-pqc",
            local_pqc_key_path=str(pqc_seed),
        )
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise


def _spec(**extra) -> str:
    spec = {
        "effective_at": "2026-01-01T00:00:00Z",
        "authority_key_id": "seat",
        "scrub_signature_classical": "AA==",
    }
    spec.update(extra)
    return json.dumps(spec)


COSIGNATURE = {
    "authority_key_id": "official",
    "scrub_signature_classical": "AA==",
}


def test_malformed_cosignatures_are_refused_not_dropped(tmp_path) -> None:
    e = _engine(tmp_path, "malformed", 0xC1)
    try:
        # A co-signature missing its signer: the list is decoded, so the
        # decode names the missing member (before #1226 the member was an
        # unknown field and was dropped unread).
        with pytest.raises(ValueError, match=r"revoke_spec_json: .*authority_key_id"):
            e.cohort_revoke_member("affiliations", "g", "m", _spec(cosignatures=[{}]))
        with pytest.raises(ValueError, match=r"revoke_spec_json: .*scrub_signature_classical"):
            e.cohort_revoke_member(
                "affiliations", "g", "m", _spec(cosignatures=[{"authority_key_id": "official"}])
            )
        with pytest.raises(ValueError, match=r"revoke_spec_json: "):
            e.cohort_revoke_member("affiliations", "g", "m", _spec(cosignatures="official"))
    finally:
        ciris_persist.reset_engine()


def test_a_well_formed_cosignature_decodes_and_reaches_the_door(tmp_path) -> None:
    e = _engine(tmp_path, "wellformed", 0xC2)
    try:
        # Well-formed: decoding passes, and the door refuses on its own
        # grounds (the signers are not registered), never at decode.
        with pytest.raises(Exception) as info:
            e.cohort_revoke_member(
                "affiliations", "g", "m", _spec(cosignatures=[COSIGNATURE])
            )
        assert "revoke_spec_json" not in str(info.value), info.value
    finally:
        ciris_persist.reset_engine()


def test_a_self_removal_carries_no_cosignature(tmp_path) -> None:
    e = _engine(tmp_path, "self", 0xC3)
    try:
        with pytest.raises(ValueError) as info:
            e.cohort_revoke_member("self", "ident", "occ", _spec(cosignatures=[COSIGNATURE]))
        assert "revoke_spec_json" not in str(info.value), info.value
        # D19 — the refusal is led by its stable token.
        assert "self_removal_cosignatures_refused" in str(info.value), info.value
    finally:
        ciris_persist.reset_engine()
