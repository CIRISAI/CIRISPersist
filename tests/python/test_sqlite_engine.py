"""v1.0.0 (CIRISAgent#756) — typed exception hierarchy smoke.

Validates the agent-facing exception classes are exported correctly so
`from ciris_persist import NotFound, Conflict, ...` and
`except NotFound:` work in the agent's 2.9.0 adoption code.

Full Engine construction (with signing-key + keyring setup) is
exercised by the Rust-side substrate tests
(`secrets::sqlite::tests::secrets_sqlite_round_trip_full_lifecycle`,
`cirisnode::sqlite::tests::cirisnode_sqlite_round_trip_full_lifecycle`,
etc.) which run against in-memory SQLite without any keyring
dependency. This file just smoke-tests the wheel-level surface that
the agent imports.
"""
from __future__ import annotations

import ciris_persist


def test_typed_exception_hierarchy_exported() -> None:
    """v1.0.0 (CIRISAgent#755 + #756 sign-off) — the four typed
    exception classes are exported from the module so agent code can
    `except NotFound:` etc. for retry-policy granularity."""
    assert hasattr(ciris_persist, "PersistError")
    assert hasattr(ciris_persist, "NotFound")
    assert hasattr(ciris_persist, "Conflict")
    assert hasattr(ciris_persist, "Transient")
    assert hasattr(ciris_persist, "Permanent")

    # All four extend the common base.
    assert issubclass(ciris_persist.NotFound, ciris_persist.PersistError)
    assert issubclass(ciris_persist.Conflict, ciris_persist.PersistError)
    assert issubclass(ciris_persist.Transient, ciris_persist.PersistError)
    assert issubclass(ciris_persist.Permanent, ciris_persist.PersistError)

    # Base extends the built-in Exception (NOT BaseException — uvicorn-
    # style `except Exception:` must catch them).
    assert issubclass(ciris_persist.PersistError, Exception)
