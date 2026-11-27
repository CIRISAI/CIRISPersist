"""v62.0.0 (v62 P8-fix10; CC 3.4.8) — I3534: Lens's detection path from the
wheel: draft, sign (composite), submit.

Lens is a Python detection producer. In edition 2 a detection is the
detector's own ``detection:{detector}`` statement, so the wheel gives a host
the three steps:

1. ``Engine.detection_draft(event_json, subject=None)`` →
   ``{"protected", "payload", "sig_structure"}`` (hex);
2. ``Engine.sign_draft(draft_json)`` → the assembled ``COSE_Sign1`` bytes,
   signed by the engine's composite key (ML-DSA-65 + Ed25519);
3. ``Engine.put_edition2_statement(statement)``.

Standing is the conferral plane's (``infra:detect`` from a root this node
trusts, CC 3.4.8), never the key's type. This file witnesses the path end to
end on a node WITHOUT the conferral: the row is held, by reason
(``reserved_family_unseated``, CC 3.4.7's token for ``detection:*``; v62.0.0
D4, it was ``reserved_prefix_emitter_mismatch``), read through
``voice_status``.

The conferred leg (the row LANDS and projects) is witnessed in Rust, I3523
(sqlite and postgres), over the same drafted bytes: chartering a trust root
and conferring ``infra:detect`` needs a root's pre-rotation commitment and
trust edges the wheel has no producer for.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

import ciris_persist


def _event(signing_key_id: str) -> dict:
    # Now (after the key registered): an instant inside the detector key's
    # record window.
    ts = datetime.now(timezone.utc)
    return {
        "detection_id": "6f1c1f6e-3b1a-4e0e-9a51-0c3c7d1b2a90",
        "trace_id": "lens-trace-i3534",
        "body_sha256": [7] * 32,
        "detector": "hash_chain_integrity",
        "severity": "warning",
        "cohort_cell": {"agent_role": "x"},
        "conformity_variant": "numeric",
        "conformity_payload": {"score": 0.25},
        "lens_core_version": "1.0.0",
        "ratchet_calibration_version": 3,
        "canonical_bytes": list(b'{"a":1}'),
        # The earlier signature members: ignored (the statement's composite
        # signature is the detector's).
        "ed25519_sig": [],
        "ml_dsa_65_sig": [],
        "signing_key_id": signing_key_id,
        "ts": ts.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    }


def test_draft_sign_submit_is_held_without_the_conferral(engine_factory, tmp_path) -> None:
    eng = engine_factory("lens", 0x1E, dsn=f"sqlite:///{tmp_path / 'lens.db'}")
    try:
        key = eng.register_self_federation_key("agent")
        draft = json.loads(eng.detection_draft(json.dumps(_event(key))))
        assert set(draft) == {"protected", "payload", "sig_structure"}, draft
        for member in draft.values():
            assert bytes.fromhex(member), draft

        statement = eng.sign_draft(json.dumps(draft))
        assert isinstance(statement, bytes) and statement, statement

        out = json.loads(eng.put_edition2_statement(statement))
        assert out["plane"] == "pending", out
        state = json.loads(eng.voice_status(out["row_id"]))
        assert state["status"] == "waiting", state
        assert state["reason"] == "reserved_family_unseated", state

        # The same bytes again: idempotent, the same row.
        again = json.loads(eng.put_edition2_statement(statement))
        assert again["row_id"] == out["row_id"], again
    finally:
        eng.close(force=True)


def test_sign_draft_refuses_a_mismatched_sig_structure(engine_factory, tmp_path) -> None:
    eng = engine_factory("lens-x", 0x1F, dsn=f"sqlite:///{tmp_path / 'lens-x.db'}")
    try:
        key = eng.register_self_federation_key("agent")
        draft = json.loads(eng.detection_draft(json.dumps(_event(key))))
        draft["sig_structure"] = "00" + draft["sig_structure"][2:]
        with pytest.raises(ValueError):
            eng.sign_draft(json.dumps(draft))
        with pytest.raises(ValueError):
            eng.detection_draft(json.dumps({"not": "a detection"}))
    finally:
        eng.close(force=True)


def test_the_earlier_detection_door_is_gone() -> None:
    assert hasattr(ciris_persist.Engine, "detection_draft")
    assert hasattr(ciris_persist.Engine, "sign_draft")
    assert not hasattr(ciris_persist.Engine, "put_detection_event")


def test_detection_draft_names_the_stated_signing_key(engine_factory, tmp_path) -> None:
    """v62.0.0 (HEAD-fix5p) — ``detection_draft(…, signer_kid=None)``: the
    draft's protected header names the key id the detector will sign with
    when it is stated (a rotated key, a second device); absent, the detector
    identity's own key, as before; a ``signer_kid`` that is not 32 bytes of
    hex is a ``ValueError``."""
    eng = engine_factory("lens-k", 0x20, dsn=f"sqlite:///{tmp_path / 'lens-k.db'}")
    try:
        key = eng.register_self_federation_key("agent")
        event = json.dumps(_event(key))
        stated = "ab" * 32
        default = json.loads(eng.detection_draft(event))
        named = json.loads(eng.detection_draft(event, signer_kid=stated))
        assert stated in named["protected"], named
        assert stated not in default["protected"], default
        # the payload is the detection's own, whichever key signs it
        assert named["payload"] == default["payload"]
        with pytest.raises(ValueError):
            eng.detection_draft(event, signer_kid="zz")
    finally:
        eng.close(force=True)
