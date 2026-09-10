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
            local_key_path=seed,
            local_pqc_key_id=alias + "-pqc",
            local_pqc_key_path=pqc_seed,
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
            assert r["tier"] == "InvisibleEncrypted", r
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
        assert sealed["tier"] == "InvisibleEncrypted"
        assert sealed["chunk_count"] == 2
        assert sealed["total_size"] == 4500
        manifest = sealed["manifest_sha256"]

        plain = segs[0] + segs[1]
        # The decrypting range read, across the chunk boundary.
        got = base64.b64decode(eng.read_blob_range_as(manifest, kid, 2990, 3010))
        assert got == plain[2990:3011]
        # The whole read is the content, not the manifest.
        assert base64.b64decode(eng.read_blob_as(manifest, kid)) == plain
        # `aad_b64` is accepted on every new surface (the #831 hook, inert).
        assert base64.b64decode(eng.read_blob_range_as(manifest, kid, 0, 9, aad_b64=_b64(b"x"))) == plain[:10]

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
