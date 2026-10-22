"""v60.0.0 (CIRISPersist#988 item 1, #803, #854) — the cirisnode surface is
thin wrappers that plan ROWS, end to end from Python.

Every cirisnode class is a hybrid-signed `scores` row now. The method names
stayed; each write takes the class's BODY (no id, author or signature), signs
the row with the engine's own key and returns its `attestation_id`. The Rust
witnesses (I1166–I1173) prove the doors on every backend; this file asks
whether a host can drive them through the wheel it imports:

- a Contribution, a vote on it, a credits balance (projected into the ledger,
  the read naming the row, the projection its own rebuild);
- a takedown notice filed as a `takedown_notice:{basis}:v1` row and executed by
  `cirisnode_process_takedown_admission_json` from its row id;
- the retired objects refused by name (a v59 typed envelope, a `key_grant`
  Contribution) and the retired key-grant Contribution methods absent.
"""
from __future__ import annotations

import hashlib
import json

import pytest

import ciris_persist

RETIRED_METHODS = [
    "cirisnode_put_key_grant_json",
    "cirisnode_retire_key_grants_json",
    "cirisnode_list_key_grants_for_json",
    "cirisnode_list_key_grants_for_content_json",
    "cirisnode_list_key_grants_for_filtered_json",
    "cirisnode_list_key_grants_for_scope_epoch_json",
    "cirisnode_list_takedowns_for_json",
]


def _engine(tmp_path):
    """A sqlite engine with a hybrid LocalSigner from fixed seeds, or a skip."""
    seed = tmp_path / "node.seed"
    pqc_seed = tmp_path / "node.pqc"
    seed.write_bytes(bytes([0x3D] * 32))
    pqc_seed.write_bytes(bytes([0x3D ^ 0xFF] * 32))
    alias = "cirisnode-rows-node"
    ciris_persist.reset_engine()
    try:
        eng = ciris_persist.Engine(
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
    if not hasattr(eng, "cirisnode_put_contribution"):
        pytest.skip("wheel built without the cirisnode feature")
    return eng


def _contribution(kind: str, payload: dict) -> str:
    return json.dumps(
        {
            "contribution_type": "proposal",
            "subject": {"domain": "health", "language": "en", "subject": kind},
            "payload": payload,
        }
    )


def test_the_classes_are_rows_from_python(tmp_path) -> None:
    eng = _engine(tmp_path)
    try:
        me = eng.register_self_federation_key("user", "ref-node", None, None, None)

        cid = eng.cirisnode_put_contribution(_contribution("arc_question", {"q": 1}))
        page = json.loads(eng.cirisnode_list_contributions(me))
        assert [r["attestation_id"] for r in page["items"]] == [cid], page
        row = page["items"][0]
        assert row["attestation_envelope"]["dimension"] == "contribution:arc_question:v1"
        assert row["scrub_signature_pqc"], "the row is hybrid-signed"

        vid = eng.cirisnode_cast_vote(json.dumps({"contribution_id": cid, "score": 0.5}))
        votes = json.loads(eng.cirisnode_list_votes(cid))
        assert [r["attestation_id"] for r in votes["items"]] == [vid], votes

        bid = eng.cirisnode_update_credits_ledger(
            json.dumps(
                {
                    "contributor_id": me,
                    "domain": "health",
                    "language": "en",
                    "subject": "arc_question",
                    "new_balance": 4.5,
                    "source_contribution": cid,
                }
            )
        )
        ledger = json.loads(eng.cirisnode_get_credits_ledger(me, "health", "en", "arc_question"))
        assert ledger["balance"] == 4.5 and ledger["attestation_id"] == bid, ledger
        assert json.loads(eng.cirisnode_check_ledger_projection("credits_ledger")) == {
            "live": 1,
            "rebuilt": 1,
        }
        assert eng.cirisnode_rehome_ledgers() == 0
    finally:
        ciris_persist.reset_engine()


def test_a_takedown_notice_is_a_row_from_python(tmp_path) -> None:
    eng = _engine(tmp_path)
    try:
        me = eng.register_self_federation_key("user", "ref-node", None, None, None)
        sha = hashlib.sha256(b"cirisnode-rows-takedown").hexdigest()
        # The content's establishing row names this node as its signed subject
        # (CC 4.5.5 `subject_of`): this node holds the takedown duty over it.
        eng.emit_attestation_self(
            json.dumps(
                {
                    "attestation_type": "scores",
                    "attestation_envelope": {
                        "dimension": "content:established:v1",
                        "score": 1.0,
                        "confidence": 1.0,
                        "evidence_refs": [sha],
                    },
                    "subject_key_ids": [me],
                    "cohort_scope": "federation",
                }
            )
        )
        notice = {
            "content_sha256": sha,
            "legal_basis": "ncmec_csam",
            "jurisdiction": "US",
            "good_faith_statement": "good faith",
            "claim_text": "claim",
            "expires_at": "2099-01-01T00:00:00Z",
        }
        nid = eng.cirisnode_put_contribution(_contribution("takedown_notice", notice))
        report = json.loads(eng.cirisnode_process_takedown_admission_json(nid))
        assert report["tombstoned"] is True, report
        assert report["notice_attestation_id"] == nid, report
        assert report["legal_basis"] == "ncmec_csam", report
        # The pre-v60 spelling is not CC's: refused at decode.
        bad = dict(notice, legal_basis="dmca_512")
        with pytest.raises(Exception):
            eng.cirisnode_put_contribution(_contribution("takedown_notice", bad))
        with pytest.raises(ValueError, match="takedown_unauthorised"):
            eng.cirisnode_process_takedown_admission_json("not-a-notice-row")
    finally:
        ciris_persist.reset_engine()


def test_retired_objects_are_refused_by_name(tmp_path) -> None:
    eng = _engine(tmp_path)
    try:
        for name in RETIRED_METHODS:
            assert not hasattr(eng, name), f"{name} is retired (v60.0.0)"
        v59 = json.loads(_contribution("arc_question", {"q": 1}))
        v59.update(
            {
                "contribution_id": "01HX5ABCDEFGHIJK",
                "author_id": "Zm9vYmFy",
                "signature": {"ed25519": "AAAA", "ml_dsa_65": None},
                "submitted_at": "2026-01-01T00:00:00Z",
            }
        )
        with pytest.raises(Exception, match="cirisnode_typed_object_retired"):
            eng.cirisnode_put_contribution(json.dumps(v59))
        with pytest.raises(Exception, match="cirisnode_key_grant_retired"):
            eng.cirisnode_put_contribution(_contribution("key_grant", {}))
    finally:
        ciris_persist.reset_engine()
