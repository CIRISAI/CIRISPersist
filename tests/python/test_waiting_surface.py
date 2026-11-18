"""v62.0.0 (CC 2.7) — I3608: ``ciris_persist.Waiting`` is reachable from the
PACKAGE and keeps the type every wait had.

Under CC 2.7 a refusal whose missing piece may still arrive (a signer's key
record, a row the write names, a roster's protocol) is a WAIT: nothing was
stored, and the same row re-offered later can be admitted. Persist raises
every wait as ``Waiting``. Every wait arm raised ``ValueError`` before v62, so
``Waiting`` is a ``ValueError`` subclass: ``except ValueError`` keeps
catching it, and a host that wants to tell a wait from a terminal refusal
catches ``Waiting`` first (or reads ``getattr(e, "retryable", False)``).

The Rust leg (I3607, ``src/ffi/pyo3/wait_taxonomy_tests.rs``) proves each
wait arm raises it with its args and the ``kind`` / ``retryable`` attributes;
this file proves a host can import and catch it the way it is documented.
"""
from __future__ import annotations

import ciris_persist


def test_waiting_is_exported_from_the_package() -> None:
    from ciris_persist import Waiting  # noqa: F401

    assert "Waiting" in ciris_persist.__all__


def test_waiting_is_a_value_error_and_not_a_runtime_error() -> None:
    assert issubclass(ciris_persist.Waiting, ValueError)
    assert not issubclass(ciris_persist.Waiting, RuntimeError)


def test_except_value_error_still_catches_a_wait() -> None:
    caught = None
    try:
        raise ciris_persist.Waiting("federation_link_not_held: family")
    except ValueError as e:  # the pre-v62 handler
        caught = e
    assert isinstance(caught, ciris_persist.Waiting)
    assert str(caught).startswith("federation_link_not_held")
