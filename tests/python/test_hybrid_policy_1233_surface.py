"""v61.1.0 (CIRISPersist#1233, CC 5.3.2.4.3.1) — I1563: at the wheel, the
verify doors accept only ``"strict"``.

CC 5.3.2.4.3.1: "a verifier's hybrid-required check is always-on, never an
operator toggle". ``Engine.verify_hybrid``, ``Engine.verify_hybrid_via_directory``
and the three ``verify_signed_*`` methods keep their ``policy`` argument until
v62 removes it, and refuse every value except ``"strict"`` with
``ValueError("verify_policy_violation")`` before any decode, lookup or crypto.

The Rust witnesses (I1560, I1561 on sqlite and postgres; I1562 through the
capsule) prove the same doors from inside the crate; this proves them through
the installed wheel.
"""

import base64
import secrets

import pytest

import ciris_persist

NOT_STRICT = ["ed25519_fallback", "soft_freshness", "STRICT", "strict ", "", "hybrid"]


def _engine(tmp_path):
    alias = "hp1233-" + secrets.token_hex(6)
    seed = tmp_path / "ed.seed"
    pqc_seed = tmp_path / "pqc.seed"
    seed.write_bytes(secrets.token_bytes(32))
    pqc_seed.write_bytes(secrets.token_bytes(32))
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


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def test_verify_hybrid_via_directory_accepts_only_strict_1233(tmp_path) -> None:
    eng = _engine(tmp_path)
    try:
        kid = eng.register_self_federation_key("agent", "ref-1233", None, None, None)
        msg = b"CIRISPersist#1233 I1563"
        out = eng.local_sign_hybrid(msg)
        ed_sig = _b64(out["classical_sig"])
        pqc_sig = _b64(out["pqc_sig"])

        got = eng.verify_hybrid_via_directory(msg, kid, ed_sig, pqc_sig, "strict")
        assert got["outcome"] == "hybrid_verified", got

        for policy in NOT_STRICT:
            # A VALID hybrid signature is refused by policy.
            with pytest.raises(ValueError) as e:
                eng.verify_hybrid_via_directory(msg, kid, ed_sig, pqc_sig, policy, 3600.0, 1.0)
            assert str(e.value) == "verify_policy_violation", (policy, str(e.value))
            # And the refusal precedes the directory lookup.
            with pytest.raises(ValueError) as e:
                eng.verify_hybrid_via_directory(msg, "no-such-key-1233", ed_sig, None, policy)
            assert str(e.value) == "verify_policy_violation", (policy, str(e.value))

        with pytest.raises(ValueError) as e:
            eng.verify_hybrid_via_directory(msg, "no-such-key-1233", ed_sig, pqc_sig, "strict")
        assert str(e.value) == "verify_unknown_key"

        for method in (
            eng.verify_signed_key_record,
            eng.verify_signed_attestation,
            eng.verify_signed_revocation,
        ):
            for policy in NOT_STRICT:
                with pytest.raises(ValueError) as e:
                    method("{", policy)
                assert str(e.value) == "verify_policy_violation", (method, policy)
            with pytest.raises(ValueError) as e:
                method("{", "strict")
            assert "JSON decode" in str(e.value), (method, str(e.value))
    finally:
        eng.close(force=True)
        ciris_persist.reset_engine()


def test_verify_hybrid_refuses_before_any_decode_1233(tmp_path) -> None:
    eng = _engine(tmp_path)
    try:
        for policy in NOT_STRICT:
            with pytest.raises(ValueError) as e:
                eng.verify_hybrid(b"m", "!!!", "!!!", "!!!", "!!!", policy)
            assert str(e.value) == "verify_policy_violation", (policy, str(e.value))
        with pytest.raises(ValueError) as e:
            eng.verify_hybrid(b"m", "!!!", "!!!", "!!!", "!!!", "strict")
        assert str(e.value) == "verify_hybrid_base64"
    finally:
        eng.close(force=True)
        ciris_persist.reset_engine()
