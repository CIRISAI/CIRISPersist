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


def test_engine_lifecycle_exceptions_exported() -> None:
    """v1.6.8 (CIRISPersist#75-78) — the three engine-lifecycle
    exception classes are exported and derive from PersistError, so
    in-process adapter code can `except EngineConfigMismatch:` /
    `except EngineClosed:` / `except EngineUsedAcrossFork:` or catch
    the `PersistError` umbrella."""
    for name in ("EngineConfigMismatch", "EngineClosed", "EngineUsedAcrossFork"):
        assert hasattr(ciris_persist, name), f"{name} not exported"
        cls = getattr(ciris_persist, name)
        assert issubclass(cls, ciris_persist.PersistError), (
            f"{name} must derive from PersistError"
        )
        # And therefore from the built-in Exception.
        assert issubclass(cls, Exception)


def test_engine_has_lifecycle_surface() -> None:
    """v1.6.8 — the Engine class exposes the close() teardown door
    and the is_closed lifecycle getter (CIRISPersist#77). Construction
    itself is exercised by the Rust-side substrate tests + the
    CIRISAgent 2.9.0 suite; this just pins the public surface."""
    assert hasattr(ciris_persist.Engine, "close")
    assert hasattr(ciris_persist.Engine, "is_closed")


def test_engine_has_cohabitation_surface() -> None:
    """v1.7.0 (CIRISPersist#79 + #80) — the Engine class exposes the
    in-process-cohabitation surface: engine_handle() for injecting
    the singleton into an adapter, and the consumer registry
    (register/deregister/list/count) so the agent + NodeCore +
    LensCore can attach/detach safely. Behavior is exercised by the
    downstream cohabitation suite; this pins the public surface."""
    for attr in (
        "engine_handle",
        "register_consumer",
        "deregister_consumer",
        "list_consumers",
        "consumer_count",
        "substrate_owner",
    ):
        assert hasattr(ciris_persist.Engine, attr), f"Engine.{attr} missing"


def test_register_consumer_validation() -> None:
    """v1.7.4 (#82) + v1.7.5 (#82 review) — register_consumer rejects
    unknown substrate-family names and over-long consumer names, and
    substrate_owner reports the declared owner. In-memory SQLite needs
    no keyring, so the behavior is exercisable here.

    Skips when the wheel was built without the `sqlite` feature — the
    CI `full features` job builds postgres-only (per pyproject), so
    this behavior test only runs against a sqlite-enabled build."""
    import pytest

    try:
        eng = ciris_persist.Engine(dsn="sqlite://:memory:", signing_key_id="qa-key")
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        eng.register_consumer("nodecore", ["cirisnode"])
        assert eng.substrate_owner("cirisnode") == "nodecore"
        assert eng.substrate_owner("cirisgraph") is None

        # v1.7.4 — typo in a substrate family is rejected.
        with pytest.raises(ValueError):
            eng.register_consumer("typo", ["cirsnode"])

        # v1.7.5 — over-long consumer name is rejected.
        with pytest.raises(ValueError):
            eng.register_consumer("x" * 300, [])
    finally:
        eng.close(force=True)
