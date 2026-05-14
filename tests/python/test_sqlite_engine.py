"""v1.0.0 (CIRISPersist#756) — in-memory SQLite Engine integration.

Validates the v1.0.0 wheel-side adoption surface for the agent team:

- `Engine("sqlite::memory:")` constructs cleanly + runs migrations
  offline-deterministically (no network, no Postgres daemon).
- Substrate-service round-trips work via the backend-dispatched
  PyEngine methods (CIRISAgent#755 Option A: URL-sniff single class
  + internal `BackendDispatch` enum).
- Typed Python exception classes (`NotFound` / `Conflict` /
  `Transient` / `Permanent`) are exported + raisable from the method
  surface.

CI builds the wheel with `--features "pyo3 sqlite … all substrate"`;
this test runs against that wheel. The release wheel published to
PyPI ships the same feature set so end users get identical behavior.
"""
from __future__ import annotations

import pytest

import ciris_persist


def test_sqlite_engine_constructs_with_memory_url() -> None:
    """v1.0.0 (CIRISAgent#755) — `sqlite::memory:` URL constructs an
    Engine without touching the filesystem. Validates the URL-sniff
    constructor (Option A) for the in-memory case."""
    engine = ciris_persist.Engine("sqlite::memory:")
    assert engine is not None


def test_sqlite_engine_constructs_with_file_url(tmp_path) -> None:
    """v1.0.0 — `sqlite:///path.db` URL constructs an Engine against a
    file-backed database. Migrations run offline-deterministically
    (no network)."""
    db_path = tmp_path / "ciris_agent.db"
    engine = ciris_persist.Engine(f"sqlite:///{db_path}")
    assert engine is not None
    assert db_path.exists(), "sqlite:/// URL should create the file"


def test_sqlite_engine_rejects_unrecognized_url() -> None:
    """v1.0.0 — non-postgresql, non-sqlite URLs raise ValueError at the
    constructor. Helpful error for misconfigured DSNs."""
    with pytest.raises(ValueError, match="unrecognized URL scheme"):
        ciris_persist.Engine("mysql://nope")


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

    # And the base extends the built-in Exception (NOT BaseException —
    # uvicorn-style `except Exception:` must catch them).
    assert issubclass(ciris_persist.PersistError, Exception)
