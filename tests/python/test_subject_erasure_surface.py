"""v58.0.0 (CIRISPersist#1094 item 2; CC 4.5.3) — the DSAR doors on the wheel.

Both Python DSAR doors now route through the Rust Engine, which signs the
subject's proxy grant and `withdraws` with the node key before the store
erases. This pins the host-reachable shape on both doors: with no node
identity the erasure is refused typed (`NodeIdentityRequired`) before
anything moves. The withdraws route itself is witnessed in Rust (I966 on
every backend; I974 through the Engine with a real node signer).
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


def test_the_dsar_doors_refuse_without_a_node_identity() -> None:
    # A process hosts exactly one engine: one engine, closed after.
    eng = _engine("i1094-no-node")
    try:
        with pytest.raises(ciris_persist.NodeIdentityRequired):
            eng.delete_traces_for_agent_id_hash("agent-without-a-node")
        with pytest.raises(ciris_persist.NodeIdentityRequired):
            eng.delete_traces_for_agent("agent-without-a-node", "some-key")
    finally:
        eng.close()
