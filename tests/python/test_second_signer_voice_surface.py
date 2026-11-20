"""v62.0.0 (v62 P8-fix5; CC 2.6.1.9, CC 2.7.3) — I3533: a second signer's
voice, from the wheel: list, then voice, then seated.

A delegation is HELD until its delegate voices it (K2's second-signer gate).
The Rust witnesses (I3525–I3531, sqlite and postgres, and through the
directory capsule) prove the door; this file asks what a host sees:

- the granter's ``voice_status`` of the row answers ``waiting`` with HTTP 424
  (``count_short``), never an exception;
- the delegate's ``held_rows_for()`` (its own key) lists the row in role
  ``delegate``, with the author's statement;
- the delegate's ``voice_held_row`` answers ``seated`` (200), and its list no
  longer names the row.

The drafted form (``voice_draft`` → sign elsewhere → ``submit_voice``) is
witnessed in Rust (I3527, I3528, and I3531 through the capsule).

The engine is a process singleton, so the parties take turns over ONE sqlite
file (``engine_factory(..., dsn=...)``), closing between turns.
"""
from __future__ import annotations

import json

import pytest

import ciris_persist


def _dsn(tmp_path) -> str:
    return f"sqlite:///{tmp_path / 'second-signer.db'}"


def test_list_voice_seated(engine_factory, tmp_path) -> None:
    dsn = _dsn(tmp_path)

    # The delegate D registers.
    d = engine_factory("ssv-d", 0xD5, dsn=dsn)
    try:
        kd = d.register_self_federation_key("user")
    finally:
        d.close(force=True)

    # The granter A delegates to D: held, not refused.
    a = engine_factory("ssv-a", 0xA5, dsn=dsn)
    try:
        a.register_self_federation_key("user")
        row = a.grant_delegation(kd, ["act_on_behalf"], False)
        state = json.loads(a.voice_status(row))
        assert state["status"] == "waiting", state
        assert state["http_status"] == 424, state
        assert state["reason"] == "count_short", state
        assert state["row_id"] == row, state
    finally:
        a.close(force=True)

    # D lists it, voices it, and it seats.
    d = engine_factory("ssv-d", 0xD5, dsn=dsn)
    try:
        listed = json.loads(d.held_rows_for())
        mine = [h for h in listed if h["row_id"] == row]
        assert len(mine) == 1, listed
        assert mine[0]["role"] == "delegate", mine
        assert mine[0]["sub"] == kd, mine
        assert kd in mine[0]["parties"], mine
        assert bytes.fromhex(mine[0]["statement"]), mine
        # the role filter
        assert json.loads(d.held_rows_for(role="bound_node")) == [], "no other role"

        seated = json.loads(d.voice_held_row(row))
        assert seated["status"] == "seated", seated
        assert seated["http_status"] == 200, seated
        assert all(h["row_id"] != row for h in json.loads(d.held_rows_for()))
    finally:
        d.close(force=True)

    # A reads it seated.
    a = engine_factory("ssv-a", 0xA5, dsn=dsn)
    try:
        assert json.loads(a.voice_status(row))["status"] == "seated"
    finally:
        a.close(force=True)


def test_a_malformed_row_id_is_a_value_error(engine_factory, tmp_path) -> None:
    eng = engine_factory("ssv-x", 0x5A, dsn=_dsn(tmp_path))
    try:
        with pytest.raises(ValueError):
            eng.voice_status("not-a-row-id")
    finally:
        eng.close(force=True)


def test_the_surface_is_present() -> None:
    for name in ("held_rows_for", "voice_status", "voice_held_row", "voice_draft", "submit_voice"):
        assert hasattr(ciris_persist.Engine, name), name
    for gone in (
        "held_delegations_for",
        "delegation_status",
        "voice_delegation",
        "delegation_voice_draft",
        "submit_delegation_voice",
    ):
        assert not hasattr(ciris_persist.Engine, gone), gone
