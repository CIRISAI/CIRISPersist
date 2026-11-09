"""CIRISPersist#1235 — read attribution is reachable from the PACKAGE.

``set_caller_scope`` sets the caller label this thread's door reads are
credited to, and ``caller_scope`` is its context manager. The checks call
both and read the result back through ``Engine.telemetry_snapshot()``.
"""
from __future__ import annotations

import uuid

import pytest

import ciris_persist


def test_set_caller_scope_returns_what_it_replaced() -> None:
    assert ciris_persist.set_caller_scope(None) is None
    assert ciris_persist.set_caller_scope("py.first") is None
    assert ciris_persist.set_caller_scope("py.second") == "py.first"
    assert ciris_persist.set_caller_scope(None) == "py.second"


@pytest.mark.parametrize("bad", ["", "Upper", "0lead", "sp ace", "unattributed", "a" * 49])
def test_a_malformed_label_is_refused_and_changes_nothing(bad: str) -> None:
    ciris_persist.set_caller_scope("py.kept")
    try:
        with pytest.raises(ValueError):
            ciris_persist.set_caller_scope(bad)
        assert ciris_persist.set_caller_scope("py.kept") == "py.kept"
    finally:
        ciris_persist.set_caller_scope(None)


def test_caller_scope_nests_innermost_wins_and_restores() -> None:
    with ciris_persist.caller_scope("py.outer"):
        with ciris_persist.caller_scope("py.inner"):
            assert ciris_persist.set_caller_scope("py.inner") == "py.inner"
        assert ciris_persist.set_caller_scope("py.outer") == "py.outer"
    assert ciris_persist.set_caller_scope(None) is None


def test_a_read_under_the_scope_is_credited_to_its_label() -> None:
    try:
        eng = ciris_persist.Engine(dsn="sqlite://:memory:", signing_key_id="qa-1235")
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    label = f"py.t{uuid.uuid4().hex[:8]}"

    def credited() -> int:
        snap = eng.telemetry_snapshot()
        assert {"reads", "folds", "callers"} <= set(snap)
        return sum(
            c["reads"]
            for c in snap["callers"]
            if c["caller"] == label and c["door"] == "list_attestations_since"
        )

    try:
        before = credited()
        with ciris_persist.caller_scope(label):
            eng.list_attestations_since(None, None, 10)
        eng.list_attestations_since(None, None, 10)
        assert credited() - before == 1
    finally:
        eng.close(force=True)
