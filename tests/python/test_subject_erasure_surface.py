"""v58.0.0 (CIRISPersist#1094 item 2; CC 4.5.3) — the DSAR doors on the wheel.

Both Python DSAR doors now route through the Rust Engine, which signs the
subject's proxy grant and `withdraws` with the node key before the store
erases. This pins the host-reachable shape: with no node identity the
erasure is refused typed (`NodeIdentityRequired`) before anything moves;
with the node key registered, an erasure of an unknown agent is the
idempotent all-zero result, on both doors. The withdraws route itself is
witnessed in Rust (I966, I974) on every backend.
"""
from __future__ import annotations

import pytest

import ciris_persist


def _engine(key: str):
    try:
        return ciris_persist.Engine(dsn="sqlite://:memory:", signing_key_id=key)
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise


def test_erasure_without_a_node_identity_is_refused_typed() -> None:
    eng = _engine("i1094-no-node")
    with pytest.raises(ciris_persist.NodeIdentityRequired):
        eng.delete_traces_for_agent_id_hash("agent-without-a-node")
    with pytest.raises(ciris_persist.NodeIdentityRequired):
        eng.delete_traces_for_agent("agent-without-a-node", "some-key")


def test_erasure_with_the_node_key_is_idempotent_on_both_doors() -> None:
    eng = _engine("i1094-node")
    eng.register_self_federation_key("node", "i1094-node")
    full = eng.delete_traces_for_agent_id_hash("agent-never-seen")
    assert full["trace_events"] == 0
    assert full["trace_llm_calls"] == 0
    assert full["detection_events_tombstoned"] == 0
    assert isinstance(full["erased_at"], str)
    keyed = eng.delete_traces_for_agent("agent-never-seen", "some-key")
    assert keyed["trace_events_deleted"] == 0
    assert keyed["federation_keys_deleted"] == 0
