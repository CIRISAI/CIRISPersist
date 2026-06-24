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
        # v1.9.0 (#84) — change-feed surface.
        "subscribe",
        "unsubscribe",
        "publish_change",
        "list_subscriptions",
        "subscription_count",
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


def test_change_feed_pubsub() -> None:
    """v1.9.0 (CIRISPersist#84) — subscribe/publish_change/unsubscribe:
    a callback fires for its substrate with (substrate, event_json),
    not for others; unsubscribe stops delivery; an unknown substrate
    raises ValueError. Skips on a non-sqlite wheel (see
    test_register_consumer_validation)."""
    import pytest

    try:
        eng = ciris_persist.Engine(dsn="sqlite://:memory:", signing_key_id="qa-key")
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        received: list[tuple[str, str]] = []
        sub_id = eng.subscribe("cirisnode", lambda s, ev: received.append((s, ev)))
        assert eng.subscription_count == 1

        delivered = eng.publish_change("cirisnode", '{"seq":1}')
        assert delivered == 1
        assert received == [("cirisnode", '{"seq":1}')]

        # A publish on a different substrate must not reach this sub.
        assert eng.publish_change("cirisgraph", '{"x":1}') == 0
        assert received == [("cirisnode", '{"seq":1}')]

        # Unsubscribe stops delivery.
        assert eng.unsubscribe(sub_id) is True
        assert eng.subscription_count == 0
        assert eng.publish_change("cirisnode", '{"seq":2}') == 0
        assert received == [("cirisnode", '{"seq":1}')]

        # Double-unsubscribe is idempotent; unknown substrate rejected.
        assert eng.unsubscribe(sub_id) is False
        with pytest.raises(ValueError):
            eng.subscribe("bogus_substrate", lambda s, ev: None)
        with pytest.raises(ValueError):
            eng.publish_change("bogus_substrate", "{}")
    finally:
        eng.close(force=True)


def test_reset_engine_unpins_singleton() -> None:
    """v1.10.1 (CIRISPersist#88) — reset_engine() un-pins the
    process-singleton handle-free, recovering the orphan case (a
    fixture that dropped its handle without close()) so a following
    Engine() with a different config constructs cleanly. Skips on a
    non-sqlite wheel."""
    import pytest

    # No-op when nothing is pinned (also clears any prior-test state).
    ciris_persist.reset_engine()

    try:
        a = ciris_persist.Engine(dsn="sqlite://:memory:", signing_key_id="reset-a")
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise

    # Orphan case: drop the only handle WITHOUT calling close(). The
    # Rust process-singleton stays pinned with nothing referencing it.
    del a
    # reset_engine() un-pins it — without this, the next Engine() with
    # a different signing_key_id would raise EngineConfigMismatch.
    ciris_persist.reset_engine()
    b = ciris_persist.Engine(dsn="sqlite://:memory:", signing_key_id="reset-b")
    assert b.is_closed is False
    del b

    # Correct under repeated reset/construct cycles, each a distinct
    # config (would all be EngineConfigMismatch without the reset).
    for i in range(10):
        ciris_persist.reset_engine()
        eng = ciris_persist.Engine(
            dsn="sqlite://:memory:", signing_key_id=f"reset-cycle-{i}"
        )
        del eng

    # Leave a clean slate for any following test in this process.
    ciris_persist.reset_engine()


def test_retention_ffi_round_trip_large_bytes() -> None:
    """v6.0.1 (CIRISPersist#218) — Lane E retention FFI: set/get/list/run
    cross the boundary as JSON, and a realistically large (10 TiB) u64
    byte value round-trips exactly through the Python int (the
    `u64 stored as i64` SQL gotcha must not corrupt the boundary value).
    Skips on a non-sqlite wheel (see test_register_consumer_validation)."""
    import json

    import pytest

    ciris_persist.reset_engine()
    try:
        eng = ciris_persist.Engine(dsn="sqlite://:memory:", signing_key_id="retention-key")
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        # 10 TiB — a realistic disk-pressure cap, far above i32 and well
        # within u64. Deliberately NOT u64::MAX (that narrows to -1 as i64).
        ten_tib = 10 * (1024**4)  # 10_995_116_277_760
        target = 8 * (1024**4)

        # set: identifiers validated in the Rust layer; large u64 caps.
        eng.set_retention(
            "telemetry_raw",
            min_keep_secs=3600,
            time_column="ts",
            pressure_trigger_bytes=ten_tib,
            pressure_target_bytes=target,
            interval_secs=86_400,
        )

        # get: large byte value round-trips exactly (no i64 corruption).
        got = json.loads(eng.get_retention("telemetry_raw"))
        assert got["min_keep_secs"] == 3600
        assert got["time_column"] == "ts"
        assert got["pressure_trigger_bytes"] == ten_tib
        assert got["pressure_target_bytes"] == target
        assert got["interval_secs"] == 86_400

        # get on an unknown table is None.
        assert eng.get_retention("no_such_table") is None

        # list: contains exactly the one policy, with the value intact.
        rows = json.loads(eng.list_retention())
        assert len(rows) == 1
        assert rows[0]["table_name"] == "telemetry_raw"
        assert rows[0]["policy"]["pressure_trigger_bytes"] == ten_tib

        # run: pressure-gated; with an empty in-memory db far below the
        # 10 TiB trigger, the sweep is a no-op but still reports per table.
        reports = json.loads(eng.run_retention())
        assert isinstance(reports, list)
        by_table = {r["table_name"]: r for r in reports}
        assert "telemetry_raw" in by_table
        rep = by_table["telemetry_raw"]
        assert rep["swept"] is False  # db_size well under the 10 TiB trigger
        assert rep["rows_deleted"] == 0
        # db_size_bytes is a u64 that also rides the JSON boundary.
        assert isinstance(rep["db_size_bytes"], int)
        assert rep["db_size_bytes"] >= 0

        # the injection gate is not bypassed at the FFI boundary, and a
        # failed `validate_sql_identifier` raises a PERMANENT error: an
        # injection-shaped identifier can never succeed on retry. (#218
        # corrected the v5.9.0 (#209) `Error::Backend` → `InvalidArgument`,
        # which `translate_error_kind` maps to `Permanent` rather than the
        # retryable `Transient`.) Both the table_name and time_column paths
        # route through the gate.
        with pytest.raises(ciris_persist.Permanent):
            eng.set_retention(
                "bad; DROP TABLE x",
                min_keep_secs=1,
                time_column="ts",
            )
        with pytest.raises(ciris_persist.Permanent):
            eng.set_retention(
                "telemetry_raw",
                min_keep_secs=1,
                time_column="ts; --",
            )
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_register_self_then_put_blob_signing_275() -> None:
    """v10.0.1 (CIRISPersist#275) — regression for the canonical
    "register my self key, then store a blob I hold" flow.

    The #247 floor (v9.3.0) made every federation-tier emit's
    `scrub_key_id` the DERIVED federation key_id
    (`derive_key_id(<alias>, <pubkey>)` = `<label>-<fp>`), but
    `register_self_federation_key` kept registering the bare keystore
    ALIAS — so `put_blob_signing`'s holds_bytes scrub FK pointed at a row
    that never existed and FK-failed (`blob_attestation_emission_failed`)
    on every persist >= 9.3.0. The fix registers (and returns) the derived
    id. Skips on a non-sqlite wheel."""
    import base64
    import hashlib
    import json
    import os
    import secrets
    import tempfile
    import uuid

    import pytest

    ciris_persist.reset_engine()
    seed = os.path.join(tempfile.mkdtemp(), "seed")
    with open(seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    alias = "node-" + secrets.token_hex(8)
    try:
        eng = ciris_persist.Engine(
            "sqlite::memory:", alias, local_key_id=alias, local_key_path=seed
        )
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        kid = eng.register_self_federation_key("agent", "ref", None, None, None)
        # The registered + returned key_id is the DERIVED wire id, NOT the
        # bare alias — this is the heart of the #275 fix.
        assert kid != alias, "register_self must register the derived id, not the alias"
        assert kid.startswith(alias + "-"), f"derived id shape <label>-<fp>: {kid!r}"

        # #275 3rd surface — the stored pubkey_ed25519_base64 must be a valid
        # 32-byte Ed25519 key (not the 65-byte P-256 point the keystore
        # software/TPM fallback would yield), or any read-back verify
        # (verify_hybrid_via_directory) fails invalid_length.
        row = json.loads(eng.lookup_keys_for_identity("ref"))[0]
        pubkey = base64.b64decode(row["pubkey_ed25519_base64"])
        assert len(pubkey) == 32, f"stored pubkey must be 32-byte Ed25519, got {len(pubkey)}"

        # The canonical self-holds-bytes ingest must NOT FK-fail now.
        body = b"hello-275"
        sha = hashlib.sha256(body).hexdigest()
        eng.put_blob_signing(
            sha,
            base64.b64encode(body).decode(),
            None,
            None,
            kid,
            "2026-05-28T13:45:09.000Z",
            str(uuid.uuid4()),
        )
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()
