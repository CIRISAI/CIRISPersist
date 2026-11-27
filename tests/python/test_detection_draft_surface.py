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
trusts, CC 3.4.8), never the key's type. v62.0.0 (HEAD-fix6; "a root grant
confers BY NAMING") — the draft is made as the producer states it: it names
the bundle and the acceptance of the conferring grant it stands on, so on a
node holding NO acceptance (this file's: the wheel has no producer for a
root's charter and trust edges) ``detection_draft`` refuses (``stands_on``)
rather than drafting a row that would count for nobody. The conferred leg
(drafted, signed, LANDED and projected) is witnessed in Rust, I3523 / I7102
(sqlite and postgres).
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


def test_detection_draft_is_refused_without_an_acceptance(engine_factory, tmp_path) -> None:
    """v62.0.0 (HEAD-fix6; Constitution, "a root grant confers BY NAMING") —
    a detection is signed under a root grant (``infra:detect``), so its draft
    names the bundle AND the acceptance of the conferring grant it stands on
    (``refs.also.stands_on``). A detector holding no acceptance is not drafted
    a row that would count for nobody: ``ValueError`` naming ``stands_on``.
    (Before HEAD-fix6 this file drafted, signed and submitted such a row and
    saw it held ``reserved_family_unseated``; the conferred leg, drafted with
    its acceptance, lands in Rust, I3523 / I7102, sqlite and postgres.)"""
    eng = engine_factory("lens", 0x1E, dsn=f"sqlite:///{tmp_path / 'lens.db'}")
    try:
        key = eng.register_self_federation_key("agent")
        with pytest.raises(ValueError, match="stands_on"):
            eng.detection_draft(json.dumps(_event(key)))
    finally:
        eng.close(force=True)


def test_sign_draft_refuses_a_mismatched_sig_structure(engine_factory, tmp_path) -> None:
    eng = engine_factory("lens-x", 0x1F, dsn=f"sqlite:///{tmp_path / 'lens-x.db'}")
    try:
        eng.register_self_federation_key("agent")
        # v62.0.0 (HEAD-fix6) — a draft is no longer obtainable from
        # ``detection_draft`` on a node with no conferral; the parts here are
        # an empty protected map and payload, and the Sig_structure stated for
        # them is NOT theirs (one byte off), so it is refused, never signed.
        sig_structure = "846a5369676e61747572653141a04041a0"
        draft = {
            "protected": "a0",
            "payload": "a0",
            "sig_structure": "85" + sig_structure[2:],
        }
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


def test_detection_draft_takes_a_signer_kid(engine_factory, tmp_path) -> None:
    """v62.0.0 (HEAD-fix5p, HEAD-fix6) — ``detection_draft(…, signer_kid=None)``
    takes the key id the detector will sign with; one that is not 32 bytes of
    hex is a ``ValueError`` naming it. A well-formed one reaches the producer,
    which (no acceptance held on this node) refuses ``stands_on``. That the
    drafted header names the stated kid is witnessed in Rust (I6138, on the
    same builder)."""
    eng = engine_factory("lens-k", 0x20, dsn=f"sqlite:///{tmp_path / 'lens-k.db'}")
    try:
        key = eng.register_self_federation_key("agent")
        event = json.dumps(_event(key))
        with pytest.raises(ValueError, match="signer_kid"):
            eng.detection_draft(event, signer_kid="zz")
        with pytest.raises(ValueError, match="stands_on"):
            eng.detection_draft(event, signer_kid="ab" * 32)
    finally:
        eng.close(force=True)
