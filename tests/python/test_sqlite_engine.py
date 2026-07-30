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

        # #295 — local_derived_key_id() returns the SAME registered/verified
        # derived id (the footgun-free one), distinct from the bare alias.
        assert eng.local_derived_key_id() == kid
        assert eng.local_derived_key_id() != eng.local_key_id()
        assert eng.local_key_id() == alias
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_local_derived_key_id_pyo3_295():
    """#295 — the pyo3 Engine exposes local_derived_key_id(): the DERIVED
    federation key_id (`<label>-<fp>`) the substrate registers + verifies,
    so consumers stop re-implementing derive_key_id. Distinct from the bare
    local_key_id() alias. Skips on a non-sqlite wheel."""
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
        derived = eng.local_derived_key_id()
        # Shape: <alias>-<fingerprint>, NOT the bare alias.
        assert derived != alias
        assert derived.startswith(alias + "-"), f"derived shape <label>-<fp>: {derived!r}"
        assert eng.local_key_id() == alias
        # Stable across calls (pure derivation over the composed signer).
        assert eng.local_derived_key_id() == derived
        # It is exactly the id register_self registers + returns (the FK target).
        assert eng.register_self_federation_key("agent", "ref", None, None, None) == derived
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_put_community_json_round_trip_290() -> None:
    """v10.4.0 (CIRISPersist#290) — `put_community_json` brings a community
    into existence over the wheel (symmetric with `put_family_json`). Before
    this, the only community surfaces were add/lookup/active — none could
    CREATE one — so the §11.10 moderation-authority walk's authority set was
    always empty. Round-trips create → lookup. Skips on a non-sqlite wheel."""
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
        # The community_key_id + each member must FK a registered
        # federation_keys row. Register as `primitive` — the put_community
        # steward-binding gate (CC 3.2 UnstewardedCommunityMember) is exempt for
        # primitive identities; agent/node members would need a steward-
        # binding chain (which the conformance harness supplies in the real
        # moderation flow, but isn't needed to prove the FFI admits a row).
        kid = eng.register_self_federation_key("primitive", "ref", None, None, None)
        now = "2026-06-25T00:00:00.000Z"
        eng.put_community_json(
            json.dumps(
                {
                    "community_key_id": kid,
                    "community_name": "T",
                    "members": [{"key_id": kid, "joined_at": now, "role": "founder"}],
                    "founded_at": now,
                    "consensus_protocol": "majority",
                    "policy_blob": None,
                    "persist_row_hash": "",
                }
            )
        )
        # The community now exists + is readable (the authority root the
        # §11.10 moderation walk needs).
        got = json.loads(eng.lookup_community_json(kid))
        assert got["community_key_id"] == kid
        assert any(m["key_id"] == kid for m in got["members"]), got
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
        eng.register_self_federation_key("agent", "ref", None, None, None)
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
        kid = eng.register_self_federation_key("user", "ref", None, None, None)
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


def test_accord_live_quorum_ffi_302():
    """#302 — the accord live-quorum write-through FFI is bound and routes
    JSON through the backend: M4 nonce gate (issue + fail-closed reject +
    admit), proposal round-trip via the anchor index, and active-halt H2
    set/clear semantics. The verify-before-mutation participation path needs
    real hybrid signatures and is covered exhaustively by the Rust tests."""
    import json
    import os
    import secrets
    import tempfile

    import pytest

    ciris_persist.reset_engine()
    seed = os.path.join(tempfile.mkdtemp(), "seed")
    with open(seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    alias = "n" + secrets.token_hex(6)
    try:
        eng = ciris_persist.Engine(
            "sqlite::memory:", alias, local_key_id=alias, local_key_path=seed
        )
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        # M4: nonce gate.
        assert eng.accord_nonce_issued("fam", "n1") is False
        proposal = {
            "family_key_id": "fam",
            "action": "fire",
            "nonce": "n1",
            "window_until": "2031-01-01T00:00:00Z",
            "prior_family_digest": "pfd-abc",
            "payload_sha256": "psh-def",
        }
        # Proposal before the nonce is issued → ValueError (M4 fail-closed).
        with pytest.raises(ValueError):
            eng.put_accord_proposal_json(
                json.dumps({"proposal": proposal, "authority_signature": None})
            )
        eng.issue_accord_nonce("fam", "n1")
        assert eng.accord_nonce_issued("fam", "n1") is True
        # Now admitted; the anchor index returns it (verbatim round-trip).
        eng.put_accord_proposal_json(
            json.dumps({"proposal": proposal, "authority_signature": None})
        )
        rows = json.loads(eng.list_accord_proposals_by_anchor_json("fire", "pfd-abc"))
        assert len(rows) == 1
        assert rows[0]["proposal"]["nonce"] == "n1"

        # H2 active halt: set, wrong-id resume no-ops, right-id clears.
        eng.set_active_halt("fam", "halt-X")
        assert json.loads(eng.get_active_halt_json("fam"))["active_halt_id"] == "halt-X"
        eng.clear_active_halt("fam", "halt-WRONG")
        assert eng.get_active_halt_json("fam") is not None
        eng.clear_active_halt("fam", "halt-X")
        assert eng.get_active_halt_json("fam") is None
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_pyengine_seeds_family_and_canonical() -> None:
    """v13.4.1 (CIRISPersist#392) — the pyo3 `Engine()` ctor must run the SAME
    genesis seed as the Rust `with_signer`: a fresh Engine has the entrenched
    HUMANITY_ACCORD family (#386) AND the baked 2-of-3 `ciris-canonical-1`
    canonical server (#390). This is the guard for the drift where the pyo3
    ctor stopped at the holder seed, so wheel consumers (the server) got
    neither. Skips on a non-sqlite wheel."""
    import json
    import pytest

    try:
        eng = ciris_persist.Engine(dsn="sqlite://:memory:", signing_key_id="genesis-seed-key")
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        # #390 — the baked 2-of-3 canonical server is trusted out of the box.
        assert eng.is_canonical("ciris-canonical-1-d7bdeu223k") is True
        servers = json.loads(eng.list_canonical_servers())
        assert len(servers) == 1
        assert servers[0]["key_id"] == "ciris-canonical-1-d7bdeu223k"

        # #386 — the entrenched quorum:2/3 HUMANITY_ACCORD family resolves.
        fam_json = eng.lookup_family_json("humanity-accord")
        assert fam_json is not None, "the accord family must be seeded on the pyo3 path"
        fam = json.loads(fam_json)
        assert fam["consensus_protocol"] == "quorum:2/3"
        assert len(fam["members"]) == 3
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_pyengine_canonical_bootstrap_hints() -> None:
    """v13.6.0 (CIRISPersist#402, CIRISEdge#296) — a fresh Engine exposes the
    baked canonical's dial hints as a flat {key_id, kind, destination} list, so
    the agent-embedded edge auto-seeds the canonical TCP dial without parsing
    persist's signed registration_envelope. Skips on a non-sqlite wheel."""
    import json
    import pytest

    try:
        eng = ciris_persist.Engine(dsn="sqlite://:memory:", signing_key_id="genesis-seed-key")
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        hints = json.loads(eng.canonical_bootstrap_hints())
        # The baked 2-of-3 canonical carries one `ip` dial hint (#390).
        assert isinstance(hints, list) and len(hints) >= 1
        ip_hints = [h for h in hints if h["kind"] == "ip"]
        assert len(ip_hints) == 1, f"expected exactly one ip dial hint, got {hints}"
        h = ip_hints[0]
        assert h["key_id"] == "ciris-canonical-1-d7bdeu223k"
        assert h["destination"] == "108.61.242.236:4242"
        # Flat object shape — edge reads these keys directly, not a tuple/array.
        assert set(h.keys()) == {"key_id", "kind", "destination"}
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_local_sign_hybrid_matches_hand_composition_470() -> None:
    """v17.7.0 (CIRISPersist#470) — cross-boundary DIFFERENTIAL test for the
    single hybrid-sign verb.

    ``Engine.local_sign_hybrid(msg)`` must be *exactly* equivalent to the
    hand-composition every PyO3 consumer previously had to write —
    ``local_sign(msg)`` then ``local_pqc_sign(msg + classical_sig)`` (the
    canonical bound rule ``pqc = Sign_PQC(message ‖ ed25519_sig)``). This is
    the authority-equivalence guard from the crypto-DRY assessment: the rule
    now lives in ONE place (LocalSigner::sign_hybrid) and this test pins the
    PyO3 surface to it from the consumer's side, so lens-core can migrate off
    its hand-composed site knowing the bytes are identical.

    Ed25519 is deterministic (RFC 8032) so the classical halves compare
    byte-for-byte. ML-DSA-65 signing is randomized ("hedged", FIPS 204), so
    the PQC halves cannot be compared byte-for-byte — instead we assert the
    verb's PQC signature has the ML-DSA-65 shape and, critically, that the
    hand-composed bound signature and the verb's signature are BOTH accepted
    /interchangeable over the same bound preimage (same key, same preimage).
    Skips on a non-sqlite wheel."""
    import os
    import secrets
    import tempfile

    import pytest

    ciris_persist.reset_engine()
    d = tempfile.mkdtemp()
    ed_seed = os.path.join(d, "ed.seed")
    pqc_seed = os.path.join(d, "pqc.seed")
    with open(ed_seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    with open(pqc_seed, "wb") as fh:
        fh.write(secrets.token_bytes(32))
    alias = "dry470-" + secrets.token_hex(6)
    try:
        eng = ciris_persist.Engine(
            "sqlite::memory:",
            alias,
            local_key_id=alias,
            local_key_path=ed_seed,
            local_pqc_key_id=alias + "-pqc",
            local_pqc_key_path=pqc_seed,
        )
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise
    try:
        msg = b"CIRISPersist#470 pyo3 differential"

        # The single verb.
        out = eng.local_sign_hybrid(msg)
        assert set(out.keys()) == {"classical_sig", "pqc_sig"}
        classical = out["classical_sig"]
        pqc = out["pqc_sig"]
        assert isinstance(classical, bytes) and len(classical) == 64
        # ML-DSA-65 signatures are 3309 bytes (FIPS 204).
        assert isinstance(pqc, bytes) and len(pqc) == 3309

        # The hand-composition it replaces (the pre-#470 consumer pattern).
        hand_classical = eng.local_sign(msg)
        hand_pqc = eng.local_pqc_sign(msg + hand_classical)

        # Classical halves: Ed25519 is deterministic — byte-identical.
        assert classical == hand_classical, (
            "local_sign_hybrid's classical half must be byte-identical to "
            "local_sign — both delegate to the same LocalSigner"
        )
        # PQC halves: ML-DSA-65 is randomized, so assert shape parity (same
        # scheme, same preimage family) rather than byte equality. The
        # Rust-side round-trip test (sign_hybrid_round_trips_verify_hybrid_strict)
        # proves the verb's bound preimage verifies under HybridPolicy::Strict
        # and that a raw-preimage signature is rejected.
        assert len(hand_pqc) == len(pqc) == 3309
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
