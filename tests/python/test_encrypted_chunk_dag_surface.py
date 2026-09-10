"""CIRISPersist#832 (`FSD/BLOB_ENCRYPTION_AT_REST.md` §12) — chunked content
under the envelope, end-to-end from Python.

The Rust witnesses (`chunk_dag_cascade::invariants`, I32–I39) prove the doors
on both backends. This file asks the question they cannot: **can a host reach
them through the wheel?** The shape this repo keeps finding — a full gate ×
backend matrix green while no consumer can call the feature — is why the
witness lives at the boundary a consumer imports.

Everything below runs through the shipped surface, on a `self` cohort so no
community fixture is needed: `register_self_federation_key` registers the
node's derived key, `put_identity_occurrence_json` publishes an occurrence of
that identity carrying `self_enc_pubkeys()` (so the DEK is wrapped to it),
`put_blob_chunk_scoped` appends sealed segments, `stream_chunks_json` lists
them before any seal, `seal_stream_scoped` writes the sealed manifest,
`read_blob_range_as` decrypts a plaintext range across a chunk boundary,
`read_blob_as` returns the whole content, `get_blob_range` still serves
ciphertext, and a stranger gets the stable `blob_not_granted` token.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets

import pytest

import ciris_persist

CRBLOB_MAGIC = b"CRBLOB\x01\x00"
ENVELOPE_OVERHEAD = 8 + 12 + 16  # magic + nonce + GCM tag


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _engine(tmp_path):
    seed = tmp_path / "seed.key"
    pqc_seed = tmp_path / "pqc.key"
    seed.write_bytes(secrets.token_bytes(32))
    pqc_seed.write_bytes(secrets.token_bytes(32))
    alias = "node-" + secrets.token_hex(8)
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


def _segment(seed: int, n: int) -> bytes:
    return bytes(((i * 2654435761 + seed) & 0xFF) for i in range(n))


def test_encrypted_chunk_dag_round_trips_through_the_wheel_832(tmp_path) -> None:
    eng = _engine(tmp_path)
    try:
        # The identity and ONE occurrence of it, keyed for content delivery.
        kid = eng.register_self_federation_key("agent", "ref", None, None, None)
        enc = eng.self_enc_pubkeys()
        eng.put_identity_occurrence_json(
            json.dumps(
                {
                    "identity_key_id": kid,
                    "occurrence_key_id": kid,
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

        stream = "py-832-" + secrets.token_hex(4)
        segs = [_segment(1, 3000), _segment(2, 1500)]
        chunk_shas = []
        for seq, seg in enumerate(segs):
            r = json.loads(
                eng.put_blob_chunk_scoped("self", stream, seq, _b64(seg), 0, community_key_id=kid)
            )
            assert r["tier"] == "invisible_encrypted", r
            assert r["epoch"] is None, r
            assert kid in r["granted"], r
            chunk_shas.append(r["chunk_sha256"])

        # The live handle, before any seal: tier + plaintext size per chunk.
        listing = json.loads(eng.stream_chunks_json(stream))
        assert listing["sth_tree_size"] is None
        assert [c["seq"] for c in listing["chunks"]] == [0, 1]
        for c, seg, sha in zip(listing["chunks"], segs, chunk_shas):
            assert c["chunk_sha256"] == sha
            assert c["crypto_tier"] == "invisible_encrypted"
            assert c["cohort_scope"] == "self"
            assert c["plaintext_size"] == len(seg)
            assert c["size_bytes"] == len(seg) + ENVELOPE_OVERHEAD

        # The storage layer serves CIPHERTEXT for a chunk: magic prefix, and
        # the chunk is addressed by those bytes.
        head = eng.get_blob_range(chunk_shas[0], 0, 7)
        assert head == CRBLOB_MAGIC
        stored = base64.b64decode(json.loads(eng.get_blob_json(chunk_shas[0]))["inline"])
        assert hashlib.sha256(stored).hexdigest() == chunk_shas[0], "addressed by ciphertext"
        assert stored != segs[0]
        assert len(stored) == len(segs[0]) + ENVELOPE_OVERHEAD

        sealed = json.loads(eng.seal_stream_scoped("self", stream, community_key_id=kid))
        assert sealed["tier"] == "invisible_encrypted"
        assert sealed["chunk_count"] == 2
        assert sealed["total_size"] == 4500
        manifest = sealed["manifest_sha256"]

        plain = segs[0] + segs[1]
        # The decrypting range read, across the chunk boundary.
        got = base64.b64decode(eng.read_blob_range_as(manifest, kid, 2990, 3010))
        assert got == plain[2990:3011]
        # The whole read is the content, not the manifest.
        assert base64.b64decode(eng.read_blob_as(manifest, kid)) == plain
        # #831 — associated data is REAL on every new surface: a read
        # presenting data the seal was not bound to fails after
        # authorization, as a backend/crypto error, never as not-granted.
        with pytest.raises(RuntimeError, match="blob_backend"):
            eng.read_blob_range_as(manifest, kid, 0, 9, aad_b64=_b64(b"x"))

        # And the bound case, end to end on the chunk surface: chunks and
        # manifest sealed under the same data open under it and only it.
        bound_stream = "py-831-" + secrets.token_hex(4)
        row_data = _b64(b"alice\n2026-09-10T00:00:00Z\n0")
        for seq, seg in enumerate(segs):
            eng.put_blob_chunk_scoped(
                "self", bound_stream, seq, _b64(seg), 0, community_key_id=kid, aad_b64=row_data
            )
        bound = json.loads(
            eng.seal_stream_scoped("self", bound_stream, community_key_id=kid, aad_b64=row_data)
        )["manifest_sha256"]
        assert base64.b64decode(eng.read_blob_range_as(bound, kid, 2990, 3010, aad_b64=row_data)) == plain[2990:3011]
        assert base64.b64decode(eng.read_blob_as(bound, kid, aad_b64=row_data)) == plain
        with pytest.raises(RuntimeError, match="blob_backend"):
            eng.read_blob_as(bound, kid)

        # RFC 9110 bounds against the PLAINTEXT total.
        with pytest.raises(ValueError, match="blob_range_not_satisfiable"):
            eng.read_blob_range_as(manifest, kid, 4500, 4600)

        # The manifest row is opaque at the storage layer — an envelope, not
        # JSON — and the storage range read never decrypts.
        assert eng.get_blob_range(manifest, 0, 7) == CRBLOB_MAGIC

        # A stranger is refused with the stable token, whole and by range.
        with pytest.raises(ValueError, match="blob_not_granted"):
            eng.read_blob_as(manifest, "stranger-" + secrets.token_hex(4))
        with pytest.raises(ValueError, match="blob_not_granted"):
            eng.read_blob_range_as(manifest, "stranger-" + secrets.token_hex(4), 0, 1)
        with pytest.raises(ValueError, match="blob_not_granted"):
            eng.read_blob_range_as(chunk_shas[0], "stranger-" + secrets.token_hex(4), 0, 1)
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_commons_seal_stream_refuses_a_sealed_chunk_row_832(tmp_path) -> None:
    """I32, commons half, from Python: a stream carrying a `self`-sealed chunk
    row cannot be sealed by the commons `seal_stream`."""
    eng = _engine(tmp_path)
    try:
        kid = eng.register_self_federation_key("agent", "ref", None, None, None)
        stream = "py-832-mixed-" + secrets.token_hex(4)
        eng.put_blob_chunk_scoped("self", stream, 0, _b64(b"sealed"), 0, community_key_id=kid)
        with pytest.raises(ValueError, match="blob_invalid_argument"):
            eng.seal_stream(stream)
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_a_stream_belongs_to_its_first_append_and_a_chunk_to_its_position_837_838(tmp_path) -> None:
    """#837 / #838 (`FSD/BLOB_ENCRYPTION_AT_REST.md` §12.9–§12.10) through the
    wheel: the listing reports the stream's row (cohort, community, owner =
    this node's derived key); an append naming another cohort on the same id
    is refused with the stable `blob_invalid_argument` token; a chunk reads
    by POSITION (`read_stream_chunk_as`) and no longer by its sha alone
    (`blob_backend`: a crypto-class error after authorization); a stranger
    is `blob_not_granted`; an unknown position is `blob_invalid_argument`."""
    eng = _engine(tmp_path)
    try:
        kid = eng.register_self_federation_key("agent", "ref", None, None, None)
        enc = eng.self_enc_pubkeys()
        eng.put_identity_occurrence_json(
            json.dumps(
                {
                    "identity_key_id": kid,
                    "occurrence_key_id": kid,
                    "device_class": "server",
                    "hardware_attestation": None,
                    "asserted_at": "2026-09-10T00:00:00Z",
                    "valid_until": None,
                    "encryption_pubkeys": enc,
                    "transport_binding": None,
                    "persist_row_hash": "",
                }
            )
        )
        stream = "py-837-" + secrets.token_hex(4)
        segs = [_segment(5, 700), _segment(6, 300)]
        shas = []
        for seq, seg in enumerate(segs):
            r = json.loads(eng.put_blob_chunk_scoped("self", stream, seq, _b64(seg), 0, community_key_id=kid))
            shas.append(r["chunk_sha256"])

        # #837 — the stream's row rides with the listing.
        listing = json.loads(eng.stream_chunks_json(stream))
        assert listing["stream"] == {
            "cohort_scope": "self",
            "community_key_id": kid,
            "owner_key_id": kid,
        }, listing
        assert json.loads(eng.stream_chunks_json("never-" + secrets.token_hex(4)))["stream"] is None
        # Another cohort on the same id is refused at the chunk, storing nothing.
        with pytest.raises(ValueError, match="blob_invalid_argument"):
            eng.put_blob_chunk_scoped("federation", stream, 2, _b64(b"public"), 0)
        assert len(json.loads(eng.stream_chunks_json(stream))["chunks"]) == 2

        # #838 — by position: opens at its own position, refuses a stranger,
        # refuses an unknown position; by sha alone it no longer opens.
        assert base64.b64decode(eng.read_stream_chunk_as(stream, 0, kid)) == segs[0]
        assert base64.b64decode(eng.read_stream_chunk_as(stream, 1, kid)) == segs[1]
        with pytest.raises(ValueError, match="blob_not_granted"):
            eng.read_stream_chunk_as(stream, 0, "stranger-" + secrets.token_hex(4))
        with pytest.raises(ValueError, match="blob_invalid_argument"):
            eng.read_stream_chunk_as(stream, 9, kid)
        with pytest.raises(RuntimeError, match="blob_backend"):
            eng.read_blob_as(shas[0], kid)
        with pytest.raises(RuntimeError, match="blob_backend"):
            eng.read_stream_chunk_as(stream, 0, kid, aad_b64=_b64(b"not what it was written under"))

        # The sealed DAG still assembles through the manifest, whole and by range.
        sealed = json.loads(eng.seal_stream_scoped("self", stream, community_key_id=kid))
        plain = segs[0] + segs[1]
        assert base64.b64decode(eng.read_blob_as(sealed["manifest_sha256"], kid)) == plain
        assert base64.b64decode(eng.read_blob_range_as(sealed["manifest_sha256"], kid, 695, 705)) == plain[695:706]
        # The relay's opaque read of a chunk is unchanged.
        assert eng.get_blob_range(shas[0], 0, 7) == CRBLOB_MAGIC
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()
