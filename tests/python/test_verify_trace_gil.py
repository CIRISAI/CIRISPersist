"""CIRISPersist#580 — ``Engine.verify_trace`` drives its whole path correctly
with the GIL released.

#580 moved the directory lookup + verify inside ``py.detach`` and deliberately
left the error mapping OUTSIDE it (building a ``PyErr`` is CPython work). That
restructure had **no behavioural coverage at all**: the FFI ``verify_trace``
wrapper has no Rust test, and the inner ``crate::verify::verify_trace`` tests
exercise the pure function, not the boundary. A refactor whose only guard is
"it compiles" is exactly the shape that ships a regression.

These tests go through a real wheel — ``import ciris_persist``, a real
``Engine`` — and exercise the two paths through the detach:

* the REJECT path (unknown signing key), which returns from inside the detach
  and then maps to a ``ValueError`` outside it;
* the malformed-input path, which raises *before* the detach is entered.

Both would hang rather than fail if the detach were composed wrongly (a nested
GIL acquire inside a released-GIL region deadlocks), so a passing run is also
evidence there is no deadlock — the failure mode #580 worried about.

Skips on a wheel built without the ``sqlite`` feature, matching
``test_sqlite_engine.py``. Note CI's python leg builds
``--features test-panic,pyo3`` with no substrate, so these skip there for the
same reason the fourteen engine-level tests in that file already do.
"""
from __future__ import annotations

import json
import pathlib

import pytest

import ciris_persist

FIXTURE = (
    pathlib.Path(__file__).resolve().parents[1]
    / "fixtures"
    / "wire"
    / "2.7.0"
    / "generic_0afd50b2.json"
)


def _engine() -> ciris_persist.Engine:
    """A sqlite-backed Engine, or skip on a wheel without the feature.

    The skip is DELIBERATELY narrow — ``ValueError`` whose message names both
    ``sqlite`` and ``feature``, matching ``test_sqlite_engine.py`` — and every
    other error re-raises. A broad ``except Exception`` here swallowed a
    ``RuntimeError`` from a malformed DSN during development and turned these
    three tests into silent skips that reported as a green run. A test that
    skips itself on any failure is worse than no test: it looks like coverage.
    """
    ciris_persist.reset_engine()
    try:
        return ciris_persist.Engine(
            dsn="sqlite://:memory:", signing_key_id="verify-trace-580"
        )
    except ValueError as exc:  # pragma: no cover — depends on wheel features
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise


@pytest.fixture()
def engine():
    eng = _engine()
    try:
        yield eng
    finally:
        eng.close(force=True)
        ciris_persist.reset_engine()
        ciris_persist.engine_teardown_wait(10.0)


def test_verify_trace_rejects_an_unknown_key_through_the_detached_path(engine) -> None:
    """The REJECT path: the lookup runs inside the detach and misses, and the
    error is built into a ``PyErr`` outside it.

    This is the exact control flow #580 restructured. Before the fix the same
    lookup happened with the GIL held; the observable answer must be
    unchanged.
    """
    trace = json.loads(FIXTURE.read_text())
    trace["signature_key_id"] = "definitely-not-registered-580"

    with pytest.raises(ValueError) as excinfo:
        engine.verify_trace(json.dumps(trace))

    assert "verify_unknown_key" in str(excinfo.value), (
        f"expected the stable verify_unknown_key token, got {excinfo.value!r}"
    )


def test_verify_trace_rejects_malformed_json_before_the_detach(engine) -> None:
    """The early-return path: decoding fails before the detach is entered, so
    the error must still surface as a ``ValueError`` and not a hang."""
    with pytest.raises(ValueError) as excinfo:
        engine.verify_trace("{not valid json")
    assert "CompleteTrace JSON decode" in str(excinfo.value)


def test_verify_trace_is_callable_repeatedly_without_wedging(engine) -> None:
    """Ten rejects in a row.

    A detach that is entered but not correctly exited shows up as a hang on
    the *second* call, not the first — so one call proves less than it looks.
    """
    trace = json.loads(FIXTURE.read_text())
    trace["signature_key_id"] = "definitely-not-registered-580"
    payload = json.dumps(trace)
    for _ in range(10):
        with pytest.raises(ValueError):
            engine.verify_trace(payload)
