"""v60.0.0 (CIRISPersist#1036, #1048; CC 2.4, 3.3.9) — the Python surface of
"an organisation is an affiliation", end to end from the wheel.

The Rust witnesses (I1210–I1234) prove the gates on sqlite and postgres; this
file asks what a host sees: the three retired operational doors are gone from
the Engine, and `grant_delegation` / `add_moderator` sign the term they are
given, refusing a term-bearing edge minted without one
(`federation_delegation_term_required`).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import ciris_persist

RETIRED = (
    "put_organization",
    "put_org_membership",
    "put_partner_record",
    "list_organizations_for",
    "list_org_memberships_for",
    "list_partner_records_for",
    "list_organizations_since",
    "list_org_memberships_since",
    "list_partner_records_since",
    "list_signed_partner_records_since",
)


def _engine(tmp_path, name: str, fill: int):
    """A sqlite engine with a hybrid LocalSigner from fixed seeds, or a skip."""
    seed = tmp_path / f"{name}.seed"
    pqc_seed = tmp_path / f"{name}.pqc"
    seed.write_bytes(bytes([fill] * 32))
    pqc_seed.write_bytes(bytes([fill ^ 0xFF] * 32))
    alias = f"affiliation-{name}"
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


def _rfc3339(at: datetime) -> str:
    return at.isoformat().replace("+00:00", "Z")


def test_the_three_operational_doors_are_retired() -> None:
    for name in RETIRED:
        assert not hasattr(ciris_persist.Engine, name), name


def test_producer_doors_sign_the_term(tmp_path) -> None:
    # Node A: a key the granter can name as its delegate.
    a = _engine(tmp_path, "a", 0xA6)
    try:
        ka = a.register_self_federation_key("agent", "ref-aff-a", None, None, None)
        record_a = a.lookup_public_key(ka)
        assert record_a is not None
    finally:
        ciris_persist.reset_engine()

    b = _engine(tmp_path, "b", 0xB6)
    try:
        b.register_self_federation_key("user", "ref-aff-b", None, None, None)
        b.put_public_key(record_a)

        # A term-bearing edge with no term is refused: CC supplies no default.
        with pytest.raises(ValueError, match="delegation_term_required"):
            b.grant_delegation(ka, ["grant"], False)
        with pytest.raises(ValueError, match="delegation_term_required"):
            b.add_moderator("community-x", ka, "moderate")
        # Past the one-year ceiling is refused too.
        far = datetime.now(timezone.utc) + timedelta(days=400)
        with pytest.raises(ValueError, match="delegation_term_required"):
            b.grant_delegation(ka, ["grant"], False, delegation_valid_until=_rfc3339(far))
        # An unreadable instant is refused before anything is signed.
        with pytest.raises(ValueError, match="not an RFC 3339 instant"):
            b.grant_delegation(ka, ["grant"], False, delegation_valid_until="next year")

        # A bounded term is signed onto the edge.
        until = datetime.now(timezone.utc) + timedelta(days=90)
        edge_id = b.grant_delegation(
            ka, ["grant"], False, delegation_valid_until=_rfc3339(until)
        )
        assert isinstance(edge_id, str) and edge_id
        # A scope that needs no term stays open-ended.
        assert b.grant_delegation(ka, ["consent_revocation"], False)
    finally:
        ciris_persist.reset_engine()


def test_term_parameters_are_keyword_optional() -> None:
    for door in ("grant_delegation", "add_moderator"):
        sig = getattr(ciris_persist.Engine, door).__text_signature__ or ""
        assert "delegation_valid_from=None" in sig, (door, sig)
        assert "delegation_valid_until=None" in sig, (door, sig)
