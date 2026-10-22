"""v60.0.0 (CIRISPersist#988 item 4, CC 3.1.9.7) — a Goal is a signed
`goal:{scale}:v1` row, end to end from Python.

The Rust witnesses (I1174–I1182) prove the gate, the fold and the doors on
every backend; this file asks whether a host can drive them through the wheel
it imports: declare, amend, retire and disown a goal; read the projection;
watch the M-1 gate refuse a body without its alignment and the retired v59
typed Goal refused by name; and check the projection against its rebuild.
"""
from __future__ import annotations

import json

import pytest

import ciris_persist


def _engine(tmp_path):
    """A sqlite engine with a hybrid LocalSigner from fixed seeds, or a skip."""
    seed = tmp_path / "node.seed"
    pqc_seed = tmp_path / "node.pqc"
    seed.write_bytes(bytes([0x4E] * 32))
    pqc_seed.write_bytes(bytes([0x4E ^ 0xFF] * 32))
    alias = "goal-rows-node"
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
    return eng


def _body(text: str, scale: str = "self", **extra) -> str:
    body = {
        "goal_text": text,
        "scale": scale,
        "meta_goal_alignment": {"dimension": "justice", "rationale": "fair to outsiders"},
    }
    body.update(extra)
    return json.dumps(body)


def test_a_goal_is_a_row_from_python(tmp_path) -> None:
    eng = _engine(tmp_path)
    try:
        me = eng.register_self_federation_key("user", "ref-goal-node", None, None, None)

        gid = eng.cirisnode_put_goal_json(
            _body("publish the report", "cohort", cohort_id="stewards", score=-0.5)
        )
        goal = json.loads(eng.cirisnode_get_goal_json(gid))
        assert goal["goal_id"] == gid
        assert goal["attestation_id"] == gid
        assert goal["declared_by_key_id"] == me
        assert (goal["scale"], goal["cohort_id"], goal["score"]) == ("cohort", "stewards", -0.5)
        assert goal["meta_goal_alignment"]["dimension"] == "justice"

        head = eng.cirisnode_amend_goal_json(gid, _body("publish it quarterly"))
        goal = json.loads(eng.cirisnode_get_goal_json(gid))
        assert (goal["goal_text"], goal["attestation_id"], goal["scale"]) == (
            "publish it quarterly",
            head,
            "self",
        )
        listed = json.loads(eng.cirisnode_list_goals_json(json.dumps({"scale": "self"})))
        assert [g["goal_id"] for g in listed] == [gid]
        with pytest.raises(ValueError):
            eng.cirisnode_list_goals_json(json.dumps({"scope_kind": "single_declarer"}))

        eng.cirisnode_retire_goal_json(gid)
        assert json.loads(eng.cirisnode_list_goals_json("{}")) == []
        retired = json.loads(
            eng.cirisnode_list_goals_json(json.dumps({"include_retired": True}))
        )
        assert [g["goal_id"] for g in retired] == [gid]
        assert retired[0]["retired_at"]

        eng.cirisnode_recant_goal_json(gid)
        assert eng.cirisnode_get_goal_json(gid) is None

        assert json.loads(eng.cirisnode_check_goal_projection()) == {"live": 0, "rebuilt": 0}
        assert json.loads(eng.cirisnode_rehome_goals()) == {"rehomed": 0, "dropped": 0}
    finally:
        ciris_persist.reset_engine()


def test_m1_and_the_retired_typed_goal_are_refused(tmp_path) -> None:
    eng = _engine(tmp_path)
    try:
        eng.register_self_federation_key("user", "ref-goal-node", None, None, None)
        no_m1 = json.dumps({"goal_text": "t", "scale": "self"})
        with pytest.raises(ValueError):
            eng.cirisnode_put_goal_json(no_m1)
        empty_rationale = json.dumps(
            {
                "goal_text": "t",
                "scale": "self",
                "meta_goal_alignment": {"dimension": "justice", "rationale": " "},
            }
        )
        with pytest.raises(ValueError, match="goal_meta_alignment_malformed"):
            eng.cirisnode_put_goal_json(empty_rationale)
        typed = json.loads(_body("t"))
        typed["goal_id"] = "00000000-0000-4000-8000-000000000000"
        with pytest.raises(ValueError, match="goal_typed_object_retired"):
            eng.cirisnode_put_goal_json(json.dumps(typed))
        with pytest.raises(ValueError):
            eng.cirisnode_put_goal_json(_body("t", "cohort"))
        assert json.loads(eng.cirisnode_list_goals_json("{}")) == []
    finally:
        ciris_persist.reset_engine()
