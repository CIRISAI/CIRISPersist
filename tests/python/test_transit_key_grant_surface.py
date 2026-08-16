"""v34.0.0 (CIRISPersist#704, CIRISEdge#492) — the TRANSIT key-grant surface,
end-to-end from Python.

This cut generalizes `key_grant` addressing from `(stream_id, epoch)` to
`(scope_kind, scope_id, epoch)` so a CIRIS peer can rotate its IFAC transit
passphrase as a PQC grant instead of an operator hand-distributing a shared
secret. Consumers (CIRISEdge, CIRISServer) reach persist through the Python
wheel and through nothing else.

So the Rust-side tests in `src/cirisnode/{sqlite,postgres}.rs` — which do cover
the collision predicate — cannot answer the question this file exists to ask:
**can a host actually call it?** Before this cut the only Python entry point for
epoch-addressed grants was `cirisnode_list_key_grants_for_stream_epoch_json`,
which pinned `scope_kind = stream_epoch` at both backend arms. Every Rust gate
was green and no host could reach a transit grant. This repo has shipped that
exact class before (a full gate x backend matrix passing while no host could
enable the feature), which is why the witness lives HERE, at the boundary a
consumer imports, and not one layer down.

The whole loop runs through the shipped wheel surface — `local_sign` +
`canonicalize_envelope_for_signing` to produce the signed envelope,
`cirisnode_put_key_grant_json` to write it, and
`cirisnode_list_key_grants_for_scope_epoch_json` to read it back. No test-only
door, and no third-party crypto dependency: a signer the test built itself
would prove the test can sign, not that a consumer can.
"""
from __future__ import annotations

import base64
import json
import os
import uuid

import pytest

import ciris_persist

# The IFAC hash-truncation size the transit grant carries. NOT a secret and
# deliberately NOT wrapped: a recipient needs it to size the interface
# (`add_tcp_server_ifac(addr, netname, passphrase, size)`) BEFORE it can unwrap
# the passphrase, so folding it into the ciphertext makes the grant unusable by
# the party it is addressed to. That makes it the field most likely to be lost
# in transit through the FFI, and it is asserted on the way back out below.
IFAC_SIZE = 64

# The PQC wrap. `WrapAlgorithm` is single-variant since the classical v1 wrap
# was removed earlier in this cut, so this is the only token that decodes.
WRAP_ALGORITHM = "x25519_mlkem768_aes256_gcm_hkdf_sha256"


def _engine(tmp_path):
    """A sqlite engine with a LOCAL signing identity, or a skip.

    The local identity is what makes this test dependency-free: `local_sign`
    is the engine's own Ed25519 door, so the envelope is signed by the same
    surface a consumer signs with.
    """
    seed = tmp_path / "local.key"
    # LocalSigner reads a raw 32-byte Ed25519 seed. Fixed bytes, not urandom:
    # a failure here should reproduce.
    seed.write_bytes(bytes([0xA7] * 32))
    ciris_persist.reset_engine()
    try:
        return ciris_persist.Engine(
            dsn="sqlite://:memory:",
            signing_key_id="transit-grant-suite",
            local_key_id="transit-grant-local",
            local_key_path=os.fspath(seed),
        )
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise


def _sign_key_grant(eng, *, scope: str, scope_id: str, epoch: int, payload_extra: dict):
    """Build + sign a scope-epoch-addressed `key_grant` ContributionEnvelope.

    `author_id` IS the Ed25519 pubkey (SCHEMA.md 2.2), so the envelope is
    self-verifying and no federation_keys row is needed.
    """
    payload = {
        "recipient_key_id": "recipient-" + uuid.uuid4().hex[:12],
        "epoch": epoch,
        "wrapped_dek_base64": base64.b64encode(bytes(range(48))).decode(),
        "wrap_algorithm": WRAP_ALGORITHM,
        "ratchet_version": 3,
        "key_validity_window": {
            "not_before": "2026-08-16T00:00:00Z",
            "not_after": "2026-09-16T00:00:00Z",
        },
        "scope": scope,
        "scope_id": scope_id,
        "rotation_chain": [],
    }
    payload.update(payload_extra)
    env = {
        "contribution_id": str(uuid.uuid4()),
        "contribution_type": "proposal",
        "author_id": eng.local_public_key_b64(),
        "subject": {"domain": "transit", "language": "en", "subject": "key_grant"},
        "payload": payload,
        "witness_set": None,
        "signature": {
            "ed25519": "",
            "ml_dsa_65": None,
            "signed_at": "2026-08-16T00:00:00Z",
        },
        # Whole-second Z form — chrono re-serializes `submitted_at` from the
        # parsed struct when it verifies, and the canonical bytes must match
        # byte-for-byte.
        "submitted_at": "2026-08-16T00:00:00Z",
    }
    canonical = eng.canonicalize_envelope_for_signing(json.dumps(env))
    env["signature"]["ed25519"] = base64.b64encode(eng.local_sign(canonical)).decode()
    return env, payload


def test_transit_membership_grant_round_trips_through_python(tmp_path) -> None:
    """THE feature of v34.0.0, exercised from the surface that ships.

    Write a `transit_membership` grant carrying the IFAC netname, epoch,
    wrapped passphrase and `ifac_size`; read it back through the scope-epoch
    door; recover every field. An assertion per field, not a dict compare, so
    a regression names the field it dropped.
    """
    eng = _engine(tmp_path)
    if not hasattr(eng, "cirisnode_put_key_grant_json"):
        pytest.skip("wheel built without the cirisnode feature")
    try:
        netname = "ciris-transit-" + uuid.uuid4().hex[:8]
        epoch = 11
        env, sent = _sign_key_grant(
            eng,
            scope="transit_membership",
            scope_id=netname,
            epoch=epoch,
            payload_extra={"ifac_size": IFAC_SIZE},
        )
        eng.cirisnode_put_key_grant_json(json.dumps(env))

        rows = json.loads(
            eng.cirisnode_list_key_grants_for_scope_epoch_json(
                "transit_membership", netname, epoch
            )
        )
        assert len(rows) == 1, f"expected exactly the grant just written, got {rows}"
        assert rows[0]["contribution_id"] == env["contribution_id"]
        got = rows[0]["payload"]

        assert got["scope"] == "transit_membership"
        assert got["scope_id"] == netname, "the IFAC netname must survive as scope_id"
        assert got["epoch"] == epoch
        assert got["recipient_key_id"] == sent["recipient_key_id"]
        assert got["wrapped_dek_base64"] == sent["wrapped_dek_base64"], (
            "the wrapped transit passphrase is the payload; a grant that loses "
            "it is a grant that delivers no key"
        )
        assert got["wrap_algorithm"] == WRAP_ALGORITHM
        assert got["ratchet_version"] == sent["ratchet_version"]
        assert got["key_validity_window"] == sent["key_validity_window"]
        # The one the recipient cannot derive and cannot unwrap without.
        assert "ifac_size" in got, (
            "ifac_size did not make the round trip — the recipient cannot size "
            "the interface, so the passphrase it unwraps is unusable"
        )
        assert got["ifac_size"] == IFAC_SIZE
    finally:
        eng.close(force=True)


def test_scope_kind_separates_a_colliding_netname_from_a_stream_id(tmp_path) -> None:
    """The cross-scope collision the `scope_kind` predicate exists to prevent.

    `scope_id` is an id WITHIN a `scope_kind`: an IFAC netname and a stream id
    are drawn from different vocabularies and may collide as strings. Two
    grants at the SAME id and SAME epoch, differing only in `scope_kind`, must
    not see each other — otherwise two scopes' wrapped DEKs fuse into one
    authorization list.

    This is the only shape that witnesses the predicate FROM PYTHON. Every
    other test here uses one scope, and so would pass whether the Python door
    forwards `scope_kind` or pins it — which is precisely the defect this cut
    removed from `cirisnode_list_key_grants_for_stream_epoch_json`.
    """
    eng = _engine(tmp_path)
    if not hasattr(eng, "cirisnode_put_key_grant_json"):
        pytest.skip("wheel built without the cirisnode feature")
    try:
        collide = "collide-" + uuid.uuid4().hex[:8]
        epoch = 7
        transit_env, _ = _sign_key_grant(
            eng,
            scope="transit_membership",
            scope_id=collide,
            epoch=epoch,
            payload_extra={"ifac_size": IFAC_SIZE},
        )
        stream_env, _ = _sign_key_grant(
            eng, scope="stream_epoch", scope_id=collide, epoch=epoch, payload_extra={}
        )
        eng.cirisnode_put_key_grant_json(json.dumps(transit_env))
        eng.cirisnode_put_key_grant_json(json.dumps(stream_env))

        transit = json.loads(
            eng.cirisnode_list_key_grants_for_scope_epoch_json(
                "transit_membership", collide, epoch
            )
        )
        assert [r["contribution_id"] for r in transit] == [
            transit_env["contribution_id"]
        ], "the transit read must not see the streaming grant at the same (id, epoch)"

        stream = json.loads(
            eng.cirisnode_list_key_grants_for_scope_epoch_json(
                "stream_epoch", collide, epoch
            )
        )
        assert [r["contribution_id"] for r in stream] == [
            stream_env["contribution_id"]
        ], "the streaming read must not see the transit grant at the same (id, epoch)"
    finally:
        eng.close(force=True)


def test_unusable_scope_kind_is_refused_not_answered_with_an_empty_list(
    tmp_path,
) -> None:
    """A `scope_kind` no grant can be stored under RAISES.

    `key_grant_scope_kind` is projected only for epoch-addressed grants, so a
    typo or a content scope matches no row by construction and would return
    `[]` — indistinguishable from "no grants issued for this netname". On a
    key-delivery read that is a fail-open: the caller concludes it holds no
    key material and carries on. The refusal names the tokens that do work.
    """
    eng = _engine(tmp_path)
    if not hasattr(eng, "cirisnode_list_key_grants_for_scope_epoch_json"):
        pytest.skip("wheel built without the cirisnode feature")
    try:
        for bad in ("transit-membership", "TRANSIT_MEMBERSHIP", "", "stream"):
            with pytest.raises(ValueError) as caught:
                eng.cirisnode_list_key_grants_for_scope_epoch_json(bad, "any-id", 1)
            assert "transit_membership" in str(caught.value), (
                "the refusal must name the accepted tokens, or the caller has "
                f"no way to fix the call: {caught.value}"
            )
        # Real scopes that are not epoch-addressed are refused too, and the
        # message says WHY rather than repeating the vocabulary list.
        for content_scope in ("single_content", "group_member", "subscription_tier"):
            with pytest.raises(ValueError) as caught:
                eng.cirisnode_list_key_grants_for_scope_epoch_json(
                    content_scope, "any-id", 1
                )
            assert "not epoch-addressed" in str(caught.value)
    finally:
        eng.close(force=True)


def test_stream_epoch_pinned_reader_is_gone() -> None:
    """`cirisnode_list_key_grants_for_stream_epoch_json` is REMOVED, not aliased.

    A deprecated shim would have kept returning the streaming half, so a
    caller asking it for transit grants would get `[]` and read it as "none
    issued" — the same false assurance the refusal above exists to remove.
    Deleting the name makes the call an immediate `AttributeError` that says
    which method is gone.
    """
    # The presence check comes FIRST. On a wheel built without `cirisnode`
    # neither name exists, and asserting the absence alone would be a check
    # that cannot fail — it would report green on a build where the whole
    # surface is missing.
    if not hasattr(ciris_persist.Engine, "cirisnode_list_key_grants_for_scope_epoch_json"):
        pytest.skip("wheel built without the cirisnode feature")
    assert not hasattr(
        ciris_persist.Engine, "cirisnode_list_key_grants_for_stream_epoch_json"
    ), "the scope_kind-pinned reader must not survive alongside its replacement"
