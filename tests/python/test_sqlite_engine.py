"""v1.0.0 (CIRISAgent#756) — typed exception hierarchy smoke.

Validates the agent-facing exception classes are exported correctly so
`from ciris_persist import NotFound, Conflict, ...` and
`except NotFound:` work in the agent's 2.9.0 adoption code.

Full Engine construction (with signing-key + keyring setup) is
exercised by the Rust-side substrate tests
(`secrets::sqlite::tests::secrets_sqlite_round_trip_full_lifecycle`,
the cirisnode witnesses (`cirisnode::rows_invariants`),
etc.) which run against in-memory SQLite without any keyring
dependency. This file just smoke-tests the wheel-level surface that
the agent imports.
"""
from __future__ import annotations

import ciris_persist

# v62.0.0 — an identity-ref (CIRISVerify `edition2::IDENTITY_REF_PREFIX`).
IDENTITY_REF_PREFIX = "urn:ietf:params:oauth:ckt:sha-256:"


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
    ALIAS — so `put_blob_signing`'s holding-claim scrub FK pointed at a row
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
    d = tempfile.mkdtemp()
    seed = os.path.join(d, "seed")
    pqc_seed = os.path.join(d, "pqc.seed")
    with open(seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    with open(pqc_seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    alias = "node-" + secrets.token_hex(8)
    try:
        # v21.3.0 (#513) — the FIPS floor made the self-signed authority path
        # hybrid-mandatory, so the node needs a PQC key too. This test predates
        # that cut and CI never re-ran it (the `pyo3` wheel has no sqlite, so it
        # SKIPS there) — the classical-only Engine it used to build now fails
        # the hybrid-Strict verify at put_community.
        eng = ciris_persist.Engine(
            "sqlite::memory:",
            alias,
            local_key_id=alias,
            local_key_path=seed,
            local_pqc_key_id=alias + "-pqc",
            local_pqc_key_path=pqc_seed,
        )
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        kid = eng.register_self_federation_key("agent")
        # The registered + returned key_id is the DERIVED wire id, NOT the
        # bare alias — this is the heart of the #275 fix.
        assert kid != alias, "register_self must register the derived id, not the alias"
        # v62.0.0 — the returned id is the key's identity-ref (CC 2.6.1), not
        # the earlier `<label>-<fp>` shape; its form is witnessed in
        # test_edition2_surface.py (I2510).
        assert kid.startswith(IDENTITY_REF_PREFIX), kid

        # #275 3rd surface — the stored pubkey_ed25519_base64 must be a valid
        # 32-byte Ed25519 key (not the 65-byte P-256 point the keystore
        # software/TPM fallback would yield), or any read-back verify
        # fails invalid_length.
        # v62.0.0 — read through the key's edition-2 projection (the
        # `identity_ref` argument of register_self is gone).
        row = json.loads(eng.lookup_public_key(kid))
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

        # The commons door's holding claim (v55.0.0: custody:ack:v1 `here` at
        # federation, CIRISPersist#989) is stored under the registered id. Read
        # back through a host door. (v62.0.0: the earlier per-row PQC-half
        # assertion is gone; a row is one composite statement.)
        # v56.0.0 (CIRISPersist#1001): one bounded page, narrowed to the
        # custody family.
        rows = json.loads(eng.list_attestations_by(kid, 500, None, "custody:ack:"))["items"]
        claims = [
            r
            for r in rows
            if r.get("attestation_type") == "scores"
            and (r.get("attestation_envelope") or {}).get("dimension") == "custody:ack:v1"
        ]
        assert claims, "the holding claim is stored under the derived id"

        # #295 — local_derived_key_id() returns the SAME registered/verified
        # derived id (the footgun-free one), distinct from the bare alias.
        assert eng.local_derived_key_id() == kid
        assert eng.local_derived_key_id() != eng.local_key_id()
        assert eng.local_key_id() == alias
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_emit_attestation_self_rejects_uppercase_subject_key_id_293():
    """#293 (CC 2.6.3 / §0.6) — emit_attestation_self must REFUSE a
    non-lowercase subject_key_ids[] element (uppercase-hex from the issue
    repro), while the canonical lowercase form of the same id is admitted.
    The rule rejects the encoding, not the subject."""
    import json
    import os
    import secrets
    import tempfile

    import pytest

    ciris_persist.reset_engine()
    d = tempfile.mkdtemp()
    seed = os.path.join(d, "s")
    with open(seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    pqc = os.path.join(d, "p")
    with open(pqc, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    alias = "n" + secrets.token_hex(6)
    try:
        eng = ciris_persist.Engine(
            "sqlite::memory:",
            alias,
            local_key_id=alias,
            local_key_path=seed,
            local_pqc_key_id=alias + "-pqc",
            local_pqc_key_path=pqc,
        )
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        eng.register_self_federation_key("agent")
        upper = "FF7C5632DAE6EF3AE7F6283BD35268BC7910332414AA8A1C35A1645CA0295F61"

        # Uppercase-hex subject id — must be refused (was admitted on 10.4.0).
        with pytest.raises(ValueError):
            eng.emit_attestation_self(
                json.dumps(
                    {
                        "attestation_type": "scores:x",
                        "subject_key_ids": [upper],
                        "attestation_envelope": {
                            "id": "e293",
                            "dimension": "identity_binding:v1",
                            "score": 1.0,
                            "confidence": 0.9,
                        },
                    }
                )
            )

        # The canonical lowercase form of the SAME id is admitted.
        eng.emit_attestation_self(
            json.dumps(
                {
                    "attestation_type": "scores:x",
                    "subject_key_ids": [upper.lower()],
                    "attestation_envelope": {
                        "id": "e293ok",
                        "dimension": "identity_binding:v1",
                        "score": 1.0,
                        "confidence": 0.9,
                    },
                }
            )
        )
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_nodes_stewarded_by_json_pyo3_299():
    """#299 — the outbound steward-binding reader nodes_stewarded_by_json() is bound
    to Python and returns valid JSON. A freshly registered user-role key owns
    itself (clause-1 self-binding, the exact inverse of steward_bindings_of);
    an unrelated key owns nothing. Skips on a non-sqlite wheel."""
    import json
    import os
    import secrets
    import tempfile

    import pytest

    ciris_persist.reset_engine()
    seed = os.path.join(tempfile.mkdtemp(), "seed")
    with open(seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    alias = "user-" + secrets.token_hex(8)
    try:
        eng = ciris_persist.Engine(
            "sqlite::memory:", alias, local_key_id=alias, local_key_path=seed
        )
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        kid = eng.register_self_federation_key("user")
        # A user-role key owns itself (exact inverse: kid ∈ nodes_stewarded_by(kid)
        # ⟺ kid ∈ steward_bindings_of(kid), the clause-1 self-binding).
        owned = json.loads(eng.nodes_stewarded_by_json(kid))
        assert isinstance(owned, list)
        assert kid in owned, owned
        # The inverse holds the other way too.
        assert kid in json.loads(eng.steward_bindings_of_json(kid))
        # An unknown key owns nothing.
        assert json.loads(eng.nodes_stewarded_by_json("nobody-" + secrets.token_hex(4))) == []
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_consent_expiry_sweep_and_scoped_stance_reachable_from_python_866():
    """v44.8.0 (CIRISPersist#866) — the two new consent doors are host-reachable:
    `run_consent_expiry_sweep_json` returns the sweep report shape, and
    `resolve_scoped_stance_by_principals` returns `{state, retain_until}`."""
    import json

    import pytest

    ciris_persist.reset_engine()
    try:
        eng = ciris_persist.Engine(dsn="sqlite://:memory:", signing_key_id="cs-866")
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        report = json.loads(eng.run_consent_expiry_sweep_json())
        assert set(report.keys()) == {
            "rows_scanned",
            "grants_seen",
            "lapsed",
            "already_recorded",
            "emitted",
            "skipped",
            "scan_truncated",
        }
        assert report["emitted"] == 0, "an empty engine records nothing"
        stance = json.loads(
            eng.resolve_scoped_stance_by_principals("target-866", "subject-866", "retain")
        )
        assert stance == {"state": "unspecified", "retain_until": None}
        with pytest.raises(ValueError):
            eng.run_consent_expiry_sweep_json(now_iso="not-a-timestamp")
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_deletion_window_watch_reachable_from_python_543() -> None:
    """v22.0.0 (CIRISPersist#543 / ciris.ai/contextual-integrity) — the
    deletion-window breach sweep is reachable THROUGH the FFI.

    ciris.ai publishes that "if subjects revoke and the window expires
    without deletion proof, the network itself raises a breach signal".
    CIRISEdge and CIRISServer reach persist through this wheel, so a sweep
    they cannot call is a signal the network cannot raise — the same
    unreachability that made the AV-77 de-admission gate a sanction nobody
    could enable. The judgment + emission are proven per-backend on the Rust
    side; this pins that a HOST can drive a pass and read the report.
    Skips on a non-sqlite wheel (see test_register_consumer_validation)."""
    import json

    import pytest

    ciris_persist.reset_engine()
    try:
        eng = ciris_persist.Engine(dsn="sqlite://:memory:", signing_key_id="dw-543")
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        report = json.loads(eng.run_deletion_window_watch_json())
        assert set(report.keys()) == {
            "rows_scanned",
            "windows_seen",
            "within_window",
            "deleted_in_time",
            "breaches",
            "malformed",
            # v44.8.0 (#866 C1b) — the subject's `retain:<window>` bound,
            # counted beside the producer's `deletion_window` promise.
            "retain_window_breaches",
            "scan_truncated",
        }
        # An empty substrate owes nobody a breach signal.
        assert report["breaches"] == 0
        assert report["scan_truncated"] is False

        # `now_iso` makes a pass replayable; a bad one is a caller error, not
        # a silent wall-clock fallback.
        replay = json.loads(
            eng.run_deletion_window_watch_json(now_iso="2026-07-27T00:00:00Z")
        )
        assert replay == report
        with pytest.raises(ValueError):
            eng.run_deletion_window_watch_json(now_iso="not-a-timestamp")
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_put_blob_scoped_aad_b64_binds_the_seal_831() -> None:
    """#831 (`BLOB_ENCRYPTION_AT_REST.md` §11.2 (7) / §11.3 (5) / I40) —
    ``put_blob_scoped(..., aad_b64=)`` folds caller-supplied associated data
    into the seal, never stores it, and ``read_blob_as(..., aad_b64=)`` must
    present the same bytes: another row's data fails AFTER authorization as
    a backend/crypto ``RuntimeError`` (not ``blob_not_granted``), a stranger
    presenting the right data is still ``blob_not_granted``, and data at a
    plaintext tier is refused rather than dropped. The positional
    signatures are unchanged (``aad_b64`` is a trailing keyword, default
    ``None``). Skips on a non-sqlite wheel."""
    import base64
    import json
    import os
    import secrets
    import tempfile

    import pytest

    ciris_persist.reset_engine()
    d = tempfile.mkdtemp()
    seed = os.path.join(d, "seed")
    pqc_seed = os.path.join(d, "pqc.seed")
    with open(seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    with open(pqc_seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    alias = "node-" + secrets.token_hex(8)
    try:
        eng = ciris_persist.Engine(
            "sqlite::memory:",
            alias,
            local_key_id=alias,
            local_key_path=seed,
            local_pqc_key_id=alias + "-pqc",
            local_pqc_key_path=pqc_seed,
        )
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        kid = eng.register_self_federation_key("agent")
        # One keyed occurrence of the self identity — the grantee. The
        # occurrence key IS the identity key (the v3.12.0 binding shape; the
        # occurrence column carries an FK to `federation_keys`, and the self
        # key is the one this engine registered). The node's own content-tier
        # pubkeys are a valid recipient shape; persist opens through its
        # self-retention row, so the grantee's private halves are never
        # needed here.
        keys = eng.self_enc_pubkeys()
        occ = kid
        eng.put_identity_occurrence_json(
            json.dumps(
                {
                    "identity_key_id": kid,
                    "occurrence_key_id": occ,
                    "device_class": "server",
                    "hardware_attestation": None,
                    "asserted_at": "2026-09-09T00:00:00Z",
                    "valid_until": None,
                    "encryption_pubkeys": {
                        "x25519_base64": keys["x25519_base64"],
                        "ml_kem_768_base64": keys["ml_kem_768_base64"],
                    },
                    "persist_row_hash": "",
                }
            )
        )

        body = b"alice's message body"
        body_b64 = base64.b64encode(body).decode()
        row_alice = base64.b64encode(b"alice\n2026-09-09T00:00:00.000Z\n1").decode()
        row_mallory = base64.b64encode(b"mallory\n2026-09-09T00:00:01.000Z\n1").decode()

        put = json.loads(eng.put_blob_scoped("self", body_b64, kid, None, aad_b64=row_alice))
        assert put["tier"] == "invisible_encrypted", put
        assert occ in put["granted"], put
        sha = put["at_rest_sha256"]

        # The sealing data opens it.
        assert base64.b64decode(eng.read_blob_as(sha, occ, aad_b64=row_alice)) == body

        # Another row's data does not — and it is NOT an authorization refusal.
        with pytest.raises(RuntimeError) as ei:
            eng.read_blob_as(sha, occ, aad_b64=row_mallory)
        assert "blob_not_granted" not in str(ei.value)
        # v47.1.0 (#842): typed, and it names the blob that did not open.
        assert str(ei.value).startswith("blob_seal_did_not_open: " + sha), str(ei.value)
        # Nor does the positional call (no data): the seal demands what bound it.
        with pytest.raises(RuntimeError):
            eng.read_blob_as(sha, occ)

        # A stranger presenting the right data is refused FIRST, by authorization.
        with pytest.raises(ValueError) as ei:
            eng.read_blob_as(sha, "stranger-" + secrets.token_hex(4), aad_b64=row_alice)
        assert "blob_not_granted" in str(ei.value)

        # The positional write (no data) is the v43 row: readable without data.
        put0 = json.loads(eng.put_blob_scoped("self", base64.b64encode(b"unbound").decode(), kid))
        assert base64.b64decode(eng.read_blob_as(put0["at_rest_sha256"], occ)) == b"unbound"

        # Data at a plaintext tier: refused, not dropped.
        with pytest.raises(ValueError) as ei:
            eng.put_blob_scoped("federation", body_b64, None, None, aad_b64=row_alice)
        assert "blob_not_granted" not in str(ei.value)

        # A malformed aad_b64 is an input error, before anything is sealed.
        with pytest.raises(ValueError) as ei:
            eng.put_blob_scoped("self", body_b64, kid, aad_b64="%%not-base64%%")
        assert "aad_b64" in str(ei.value)
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_put_blob_scoped_reports_the_roster_partition_843() -> None:
    """#843 (BLOB_ENCRYPTION_AT_REST.md §12.11, I54) — the JSON a Python
    caller reads partitions the ROSTER. The founder of a community write who
    has no occurrence is ``absent`` and ``readable_by_nobody`` is true — the
    case CIRISServer#590 / CIRISEdge#599 hit, where ``excluded`` was the only
    field to read and it said nothing about her. One identity walks
    absent → excluded → granted; a commons write is readable by everyone.
    Skips on a non-sqlite wheel."""
    import base64
    import json
    import os
    import secrets
    import tempfile

    import pytest

    ciris_persist.reset_engine()
    d = tempfile.mkdtemp()
    seed = os.path.join(d, "seed")
    pqc_seed = os.path.join(d, "pqc.seed")
    with open(seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    with open(pqc_seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    alias = "node-" + secrets.token_hex(8)
    try:
        eng = ciris_persist.Engine(
            "sqlite::memory:",
            alias,
            local_key_id=alias,
            local_key_path=seed,
            local_pqc_key_id=alias + "-pqc",
            local_pqc_key_path=pqc_seed,
        )
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        # The node's own key is the community's key AND its one member (a
        # primitive identity needs no steward binding at put_community).
        kid = eng.register_self_federation_key("primitive")
        now = "2026-09-09T00:00:00.000Z"
        eng.put_community_json(
            json.dumps(
                {
                    "community_key_id": kid,
                    "community_name": "Pair",
                    "members": [{"key_id": kid, "joined_at": now, "role": "founder"}],
                    "founded_at": now,
                    "consensus_protocol": "majority",
                    "policy_blob": None,
                    "persist_row_hash": "",
                }
            )
        )
        body = base64.b64encode(b"minutes").decode()

        def occurrence(enc):
            return json.dumps(
                {
                    "identity_key_id": kid,
                    "occurrence_key_id": kid,
                    "device_class": "server",
                    "hardware_attestation": None,
                    "asserted_at": now,
                    "valid_until": None,
                    "encryption_pubkeys": enc,
                    "persist_row_hash": "",
                }
            )

        # 1. The founder has NO occurrence: absent, and nobody can read.
        r = json.loads(eng.put_blob_scoped("community", body, kid))
        assert r["tier"] == "community_dek", r
        assert r["granted"] == [] and r["excluded"] == [], r
        assert r["roster"] == {"granted": [], "excluded": [], "absent": [kid]}, r
        assert r["readable_by_nobody"] is True, r

        # 2. A bare occurrence: the member is excluded, still nobody.
        eng.put_identity_occurrence_json(occurrence(None))
        r = json.loads(eng.put_blob_scoped("community", body, kid))
        assert r["granted"] == [] and r["excluded"] == [kid], r
        assert r["roster"] == {"granted": [], "excluded": [kid], "absent": []}, r
        assert r["readable_by_nobody"] is True, r

        # 3. Keyed: granted, and the content is readable.
        keys = eng.self_enc_pubkeys()
        eng.put_identity_occurrence_json(
            occurrence(
                {
                    "x25519_base64": keys["x25519_base64"],
                    "ml_kem_768_base64": keys["ml_kem_768_base64"],
                }
            )
        )
        r = json.loads(eng.put_blob_scoped("community", body, kid))
        assert r["granted"] == [kid] and r["excluded"] == [], r
        assert r["roster"] == {
            "granted": [{"member_key_id": kid, "occurrence_key_ids": [kid]}],
            "excluded": [],
            "absent": [],
        }, r
        assert r["readable_by_nobody"] is False, r
        assert base64.b64decode(eng.read_blob_as(r["at_rest_sha256"], kid)) == b"minutes"

        # A commons write is readable by everyone and says so.
        r = json.loads(eng.put_blob_scoped("federation", body, None))
        assert r["tier"] == "plaintext", r
        assert r["roster"] == {"granted": [], "excluded": [], "absent": []}, r
        assert r["readable_by_nobody"] is False, r
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_would_hold_adopt_and_hold_breadth_846() -> None:
    """#846 (`BLOB_REPLICATION.md` §4 / §6) — the three doors are reachable
    from Python and keep their ``BlobError`` class. ``would_hold_json``
    answers ``hold: false`` with ``blob_not_party_to`` for a community this
    node is not a member of and ``hold: true`` for the commons (everyone is
    party to it); ``adopt_sealed_blob_json`` refuses bytes without the
    envelope shape and a bad disposition before anything is written;
    ``hold_breadth()`` is ``on_demand`` for a node nobody conferred
    ``infra:serve`` on. Skips on a non-sqlite wheel."""
    import base64
    import json
    import os
    import secrets
    import tempfile

    import pytest

    ciris_persist.reset_engine()
    d = tempfile.mkdtemp()
    seed = os.path.join(d, "seed")
    pqc_seed = os.path.join(d, "pqc.seed")
    with open(seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    with open(pqc_seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    alias = "node-" + secrets.token_hex(8)
    try:
        eng = ciris_persist.Engine(
            "sqlite::memory:",
            alias,
            local_key_id=alias,
            local_key_path=seed,
            local_pqc_key_id=alias + "-pqc",
            local_pqc_key_path=pqc_seed,
        )
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        eng.register_self_federation_key("agent")
        peer = "peer-" + secrets.token_hex(4)

        # Not party to a community we are not a member of: the answer, not an error.
        theirs = json.loads(
            eng.would_hold_json(
                json.dumps(
                    {
                        "author_key_id": peer,
                        "cohort_scope": "community",
                        "community_key_id": "comm-" + secrets.token_hex(4),
                        "epoch": 1,
                        "tier": "community_dek",
                    }
                )
            )
        )
        assert theirs["hold"] is False
        assert theirs["kind"] == "blob_not_party_to"

        # The commons is everyone's: held under normal pressure.
        commons = json.loads(
            eng.would_hold_json(
                json.dumps({"author_key_id": peer, "cohort_scope": "federation", "tier": "plaintext"})
            )
        )
        assert commons == {"hold": True}

        # Adopt: bytes without the envelope shape are an input error, class kept.
        with pytest.raises(ValueError) as ei:
            eng.adopt_sealed_blob_json(
                json.dumps(
                    {
                        "envelope_b64": base64.b64encode(b"not an envelope").decode(),
                        "author_key_id": peer,
                        "cohort_scope": "federation",
                        "tier": "plaintext",
                        "disposition": "local_only",
                    }
                )
            )
        assert "blob_invalid_argument" in str(ei.value)

        # A bad disposition is refused before the door is reached.
        with pytest.raises(ValueError) as ei:
            eng.adopt_sealed_blob_json(
                json.dumps(
                    {
                        "envelope_b64": base64.b64encode(b"x").decode(),
                        "author_key_id": peer,
                        "cohort_scope": "community",
                        "tier": "community_dek",
                        "disposition": "maybe",
                    }
                )
            )
        assert "disposition" in str(ei.value)

        # Serve standing governs breadth, and nobody conferred any.
        assert eng.hold_breadth() == "on_demand"
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_reack_holding_claims_once_is_host_reachable_989() -> None:
    """v55.0.0 (#989, CC 3.1.3.3 rule 5) — the re-ack pass is reachable from
    Python and returns its report as JSON. A fresh commons claim is a day
    younger than the renewal threshold, so one pass renews nothing and finds
    it fresh; a second pass is the same (idempotent). Skips on a non-sqlite
    wheel."""
    import base64
    import hashlib
    import json
    import os
    import secrets
    import tempfile

    import pytest

    ciris_persist.reset_engine()
    d = tempfile.mkdtemp()
    seed = os.path.join(d, "seed")
    pqc_seed = os.path.join(d, "pqc.seed")
    with open(seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    with open(pqc_seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    alias = "node-" + secrets.token_hex(8)
    try:
        eng = ciris_persist.Engine(
            "sqlite::memory:",
            alias,
            local_key_id=alias,
            local_key_path=seed,
            local_pqc_key_id=alias + "-pqc",
            local_pqc_key_path=pqc_seed,
        )
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        eng.register_self_federation_key("agent")
        body = b"commons bytes " + secrets.token_bytes(8)
        put = json.loads(
            eng.put_blob_scoped("federation", base64.b64encode(body).decode(), None, None)
        )
        assert put["at_rest_sha256"] == hashlib.sha256(body).hexdigest(), put
        for _ in range(2):
            report = json.loads(eng.reack_holding_claims_once())
            assert set(report) == {
                "scanned", "renewed", "fresh", "not_held", "not_in_cohort", "failed", "converted",
                "withheld", "deferred",
                # v60.1.0 (#1113) — a reversed takedown's re-ack.
                "restored",
            }, report
            assert report["restored"] == 0, report
            assert report["withheld"] == 0, report
            # v56.0.0 (#1071): a pass renews at most the cap; the rest is deferred
            # to the next pass. One fresh claim defers nothing.
            assert report["deferred"] == 0, report
            assert report["scanned"] == 1 and report["fresh"] == 1, report
            assert report["renewed"] == 0 and report["failed"] == 0, report
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()
