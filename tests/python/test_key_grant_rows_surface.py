"""v55.0.0 (CIRISPersist#989, #981; CC 3.3.2 rc7, CC 5.3.3.2.5) — the
per-recipient key-grant row and the caller-supplied stream epoch DEK, end to
end from Python.

Slice B moved every key wrap onto one `scores` row per recipient
(`key_grant:{axis}:v1`) and changed the JSON `emit_key_grant` takes and
`apply_replicated_key_grant` admits. The Rust witnesses (I742–I757) prove the
doors on every backend; this file asks whether a host can drive a real signed
round trip through the wheel: node A seals, A's rows go to node B as JSON, and
B's admission (signature, the one audience rule, the projection) answers.

The engine is a process singleton, so the two nodes run one after the other in
this process: A's key records, its occurrence and its signed rows are carried
to B as the JSON a replication bridge would carry. B is told about A's
occurrence through the trusted-local occurrence door; the signed occurrence
door is the edge bridge's, not the wheel's.
"""
from __future__ import annotations

import base64
import copy
import json

import pytest

import ciris_persist

KEY_GRANT_PREFIX = "key_grant:"


def _engine(tmp_path, name: str, fill: int):
    """A sqlite engine with a hybrid LocalSigner from fixed seeds, or a skip."""
    seed = tmp_path / f"{name}.seed"
    pqc_seed = tmp_path / f"{name}.pqc"
    # Fixed bytes, not urandom: a failure here should reproduce.
    seed.write_bytes(bytes([fill] * 32))
    pqc_seed.write_bytes(bytes([fill ^ 0xFF] * 32))
    alias = f"kg-rows-{name}"
    ciris_persist.reset_engine()
    try:
        return ciris_persist.Engine(
            "sqlite::memory:",
            alias,
            local_key_id=alias,
            local_key_path=str(seed),
            local_pqc_key_id=alias + "-pqc",
            local_pqc_key_path=str(pqc_seed),
        )
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise


def _occurrence(eng, identity: str, occurrence: str, enc: dict) -> None:
    eng.put_identity_occurrence_json(
        json.dumps(
            {
                "identity_key_id": identity,
                "occurrence_key_id": occurrence,
                "device_class": "server",
                "hardware_attestation": None,
                "asserted_at": "2026-09-09T00:00:00Z",
                "valid_until": None,
                "encryption_pubkeys": enc,
                "transport_binding": None,
                "persist_row_hash": "",
            }
        )
    )


def _key_grant_rows(eng, signer: str) -> list[dict]:
    return [
        r
        for r in json.loads(eng.list_attestations_by(signer))
        if str((r.get("attestation_envelope") or {}).get("dimension", "")).startswith(
            KEY_GRANT_PREFIX
        )
    ]


def test_key_grant_rows_round_trip_between_two_nodes_989(tmp_path) -> None:
    # ── Node A: a self stream under a caller-supplied epoch DEK ──────────
    a = _engine(tmp_path, "a", 0x5A)
    try:
        ka = a.register_self_federation_key("agent", "ref-a", None, None, None)
        enc_a = a.self_enc_pubkeys()
        _occurrence(a, ka, ka, enc_a)

        stream = "py-989-stream"
        dek = bytes(range(32))
        reg = json.loads(
            a.register_stream_epoch_dek("self", ka, stream, 0, base64.b64encode(dek).decode())
        )
        assert reg["stream_id"] == stream and reg["epoch"] == 0, reg
        assert "keep" not in reg and reg["tier"] == "invisible_encrypted", reg
        assert reg["granted"] == [ka], reg
        # One DEK per (stream, epoch): a second supply is refused, terminally.
        with pytest.raises(ValueError, match="blob_stream_epoch_dek_exists") as exc:
            a.register_stream_epoch_dek(
                "self", ka, stream, 0, base64.b64encode(bytes(32)).decode()
            )
        body = json.loads(str(exc.value).split(": ", 1)[1])
        assert body["retryable"] is False, body

        segs = [b"live call segment one " * 20, b"live call segment two " * 30]
        for seq, seg in enumerate(segs):
            a.put_blob_chunk_scoped(
                "self", stream, seq, base64.b64encode(seg).decode(), 0, community_key_id=ka
            )
        sealed = json.loads(a.seal_stream_scoped("self", stream, community_key_id=ka))
        manifest = sealed["manifest_sha256"]
        assert sealed["total_size"] == sum(len(s) for s in segs), sealed
        assert base64.b64decode(a.read_blob_as(manifest, ka)) == b"".join(segs)

        # The rows the seal emitted: one per recipient per axis, each a
        # structural `scores` row, signed by A, naming its recipient.
        content_axis = {
            "axis": "content",
            "at_rest_sha256": manifest,
            "cohort_scope": "self",
            "owner_key_id": ka,
        }
        emitted = json.loads(a.emit_key_grant(json.dumps(content_axis)))
        assert emitted["axis"] == content_axis, emitted
        assert emitted["already_emitted"] == [ka], emitted
        assert emitted["withheld"] == [] and emitted["sealer_refused"] is None, emitted
        rows = _key_grant_rows(a, ka)
        by_dim = {r["attestation_envelope"]["dimension"]: r for r in rows}
        assert set(by_dim) == {"key_grant:content:v1", "key_grant:stream:v1"}, list(by_dim)
        for r in rows:
            assert r["attestation_type"] == "scores", r["attestation_type"]
            assert r["attesting_key_id"] == ka and r["attested_key_id"] == ka
            assert r["scrub_signature_pqc"], "a key-grant row is hybrid-signed"
        assert by_dim["key_grant:content:v1"]["attestation_envelope"]["at_rest_sha256"] == manifest
        assert by_dim["key_grant:stream:v1"]["attestation_envelope"]["stream_id"] == stream

        key_records = json.loads(a.list_signed_key_records_since(None, None, 100))
    finally:
        a.close(force=True)
    ciris_persist.reset_engine()

    # ── Node B: admit A's rows ───────────────────────────────────────────
    b = _engine(tmp_path, "b", 0xB5)
    try:
        b.register_self_federation_key("agent", "ref-b", None, None, None)
        content_row = by_dim["key_grant:content:v1"]
        stream_row = by_dim["key_grant:stream:v1"]

        # Before B knows A's occurrence, the recipient is outside the one
        # audience rule: refused, and re-offerable once it lands.
        with pytest.raises(ValueError, match="recipient_not_in_audience"):
            b.apply_replicated_key_grant(json.dumps({"attestation": stream_row}))

        for rec in key_records:
            b.apply_replicated_key_record(json.dumps(rec))
        _occurrence(b, ka, ka, enc_a)

        # A row whose wrap was altered in flight no longer verifies.
        forged = copy.deepcopy(stream_row)
        wrap = json.loads(forged["attestation_envelope"]["wrapped_dek"])
        wrap["ciphertext_b64"] = base64.b64encode(bytes(48)).decode()
        forged["attestation_envelope"]["wrapped_dek"] = json.dumps(wrap)
        with pytest.raises(ValueError, match="unverified"):
            b.apply_replicated_key_grant(json.dumps({"attestation": forged}))

        # The stream wrap is held: admitted and projected.
        got = json.loads(b.apply_replicated_key_grant(json.dumps({"attestation": stream_row})))
        assert got["axis"] == {
            "axis": "stream",
            "stream_id": stream,
            "epoch": 0,
            "cohort_scope": "self",
            "owner_key_id": ka,
        }, got
        assert got["recipient_key_id"] == ka, got
        assert (got["attestation"], got["projected"], got["pending"]) == ("inserted", True, False), got

        # The content wrap is admitted and kept pending: B holds none of the
        # bytes it opens (it is not party to A's self content).
        got = json.loads(b.apply_replicated_key_grant(json.dumps({"attestation": content_row})))
        assert got["axis"] == content_axis, got
        assert (got["attestation"], got["projected"], got["pending"]) == ("inserted", False, True), got

        # Re-delivery is idempotent.
        for row in (stream_row, content_row):
            again = json.loads(b.apply_replicated_key_grant(json.dumps({"attestation": row})))
            assert again["attestation"] == "unchanged", again

        held = {r["attestation_id"] for r in _key_grant_rows(b, ka)}
        assert held == {stream_row["attestation_id"], content_row["attestation_id"]}, held
    finally:
        b.close(force=True)
    ciris_persist.reset_engine()
