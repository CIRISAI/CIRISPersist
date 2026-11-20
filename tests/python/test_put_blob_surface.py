"""v62.0.0 (T2-fix11; CC 6.1.3) — ``Engine.put_blob`` from the wheel.

A holding claim is a CC 6.1 object: ONE composite signature, stated as the
holder's edition-2 ``custody:{kind}`` statement. ``put_blob`` takes that
statement (``claim_hex``) beside the bytes: the bytes are checked and stored,
then the claim goes through the statement door. The earlier surface is gone
(a clean break): ``put_blob_json`` (whose payload carried the bound-hybrid
``PutBlobAttestation``) and the interim name ``put_blob_edition2``.

- I3196: node A writes a blob with ``put_blob_signing`` (its own composite
  claim). B receives A's key, then ``put_blob(sha, bytes, …, claim_hex)`` with
  A's claim statement: the bytes land and A is a listed holder on B. A claim
  naming another blob is refused (``ValueError``) and stores nothing. The
  earlier names are absent.

The engine is a process singleton, so A and B run one after the other.
"""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone

import pytest

import ciris_persist
from conftest import carry_statements, deliver


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def test_put_blob_takes_the_composite_claim_statement_i3196(engine_factory) -> None:
    """I3196 — the edition-2 ``put_blob``: the holder's composite claim
    statement lands the bytes and the holder; a claim for another blob is
    refused and stores nothing; ``put_blob_json`` / ``put_blob_edition2`` are
    absent."""
    data = b"t2-fix11 put_blob bytes"
    sha = hashlib.sha256(data).hexdigest()
    other = b"t2-fix11 another blob"
    other_sha = hashlib.sha256(other).hexdigest()

    # ── Node A: its key, and one blob it holds (its own composite claim) ──
    a = engine_factory("pba", 0x71)
    try:
        ka = a.register_self_federation_key("user")
        a.put_blob_signing(
            sha,
            _b64(data),
            None,
            None,
            ka,
            datetime.now(timezone.utc).isoformat(),
            str(uuid.uuid4()),
        )
        carried = carry_statements(a)
    finally:
        a.close(force=True)
    # A's claim statement: the custody statement naming the blob's digest.
    claims = [st for st, _rid, plane in carried if bytes.fromhex(sha) in st and plane != "key_plane"]
    assert len(claims) == 1, [(plane, len(st)) for st, _r, plane in carried]
    claim_hex = claims[0].hex()
    keys = [c for c in carried if c[2] == "key_plane"]
    assert keys, "A's key plane is carried"

    # ── Node B: A's key, then the bytes with A's claim ──────────────────
    b = engine_factory("pbb", 0x72)
    try:
        b.register_self_federation_key("user")
        deliver(b, keys)
        for gone in ("put_blob_json", "put_blob_edition2"):
            assert not hasattr(b, gone), f"I3196: {gone} is deleted (clean break)"

        # A claim naming another blob: refused, nothing stored.
        with pytest.raises(ValueError):
            b.put_blob(other_sha, _b64(other), None, None, claim_hex)
        assert not b.has_blob_json(other_sha), "I3196: a refused claim stores nothing"

        # The claim for these bytes: the bytes land and A is a holder.
        b.put_blob(sha, _b64(data), None, None, claim_hex)
        assert b.has_blob_json(sha)
        holders = json.loads(b.list_holders_json(sha))
        assert ka in holders, ("I3196: A's composite claim lists A as a holder", holders)
    finally:
        b.close(force=True)
