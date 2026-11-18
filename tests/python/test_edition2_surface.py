"""v62.0.0 (JSON-cut slice D; CC 2.6.1, 2.6.1.2, 2.6.1.11, 2.6.1.12) — the
edition-2 surface, end to end from the wheel.

A v62 node reads and produces only edition-2 statements (CBOR payload, one
composite ``COSE_Sign1``). The Rust witnesses prove the door, the mapping and
the store on sqlite and postgres; this file asks what a host sees through
``import ciris_persist``:

- I2510: ``register_self_federation_key`` returns the key's identity-ref, the
  same as ``local_derived_key_id()``, and the key reads back as its edition-2
  projection; the pre-v62 five-argument call is a ``TypeError``.
- I2511: ``put_edition2_statement`` on the producing node: a re-put of a held
  statement changes nothing and names its row; an offered id the bytes do not
  name is ``row_id_mismatch``; a JSON object, or bytes in no form, is
  ``earlier_form_object`` (the door's own check, switch or no switch).
- I2512: two nodes. A's statements are carried to B and applied with
  ``apply_replicated_statement``: a row before its signer's key waits
  (``federation_attester_key_unknown``, retryable), the key lands, the row
  lands under the id A computed, re-delivery is ``unchanged``.
- I2513: ``edition2_statements_since`` pages in admission order and resumes
  from the opaque cursor it hands out.
- I2514: ``bundles_in_force_json()`` is a JSON list, one entry per tip:
  ``{object_id, version, prev, asserted_at, family_key_id, holders,
  serve_nodes, counted}``; it takes no pin.
- I2515: once ``earlier_form_doors_shut()`` (slice F), every earlier-form
  JSON door still on the Engine refuses by name, as a ``ValueError``.

The engine is a process singleton, so the two nodes of I2512 run one after the
other: A's statements are carried to B as the bytes a replication bridge would
carry, each with the row id A offers it under.
"""
from __future__ import annotations

import base64
import json
import re

import pytest

import ciris_persist
from conftest import carry_statements, deliver, is_identity_ref, served_statements

#: ``ValueError`` text of a refusal at the edition-2 door (plane ``edition2``).
EDITION2_REFUSAL = "federation_malformed_row: edition2: "

#: A cursor handed out by ``edition2_statements_since``:
#: ``<admitted_us>:<statement_id, 64 hex>``.
CURSOR = re.compile(r"^-?[0-9]+:[0-9a-f]{64}$")

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _goal(text: str) -> str:
    """A self-scale goal body (CC 3.1.9.7) that meets the M-1 gate."""
    return json.dumps(
        {
            "goal_text": text,
            "scale": "self",
            "meta_goal_alignment": {"dimension": "justice", "rationale": "fair to outsiders"},
        }
    )


# ── I2510 ────────────────────────────────────────────────────────────────


def test_register_self_returns_the_identity_ref_i2510(engine_factory) -> None:
    """I2510 — the registered key is named by its identity-ref, everywhere a
    host reads it, and the earlier argument list is gone (a clean break)."""
    eng = engine_factory("reg", 0x21)
    try:
        kid = eng.register_self_federation_key("agent")
        assert is_identity_ref(kid), kid
        assert eng.local_derived_key_id() == kid
        assert eng.local_derived_key_id() != eng.local_key_id()
        # Idempotent: the same key, the same id.
        assert eng.register_self_federation_key("agent") == kid

        # The read model: the key's edition-2 projection, both halves of the
        # composite key filled (Ed25519 32 bytes, ML-DSA-65 1952 bytes).
        record = json.loads(eng.lookup_public_key(kid))
        assert record["key_id"] == kid, record
        assert len(base64.b64decode(record["pubkey_ed25519_base64"])) == 32, record
        assert len(base64.b64decode(record["pubkey_ml_dsa_65_base64"])) == 1952, record
        assert "agent" in record["identity_type"].split(","), record

        # The key travels as one key-plane statement the node serves.
        planes = [plane for _, _, plane in carry_statements(eng)]
        assert "key_plane" in planes, planes

        # The pre-v62 call (identity_ref, registration envelope, roles) is not
        # read as something else: it is a TypeError.
        with pytest.raises(TypeError):
            eng.register_self_federation_key("agent", "ref", None, None, None)
    finally:
        eng.close(force=True)


# ── I2511 ────────────────────────────────────────────────────────────────


def test_put_edition2_statement_on_the_producing_node_i2511(engine_factory) -> None:
    """I2511 — the local statement door: idempotent on a held statement,
    names its row, refuses an id the bytes do not name, and refuses the
    earlier form by name."""
    eng = engine_factory("put", 0x32)
    try:
        kid = eng.register_self_federation_key("user")
        gid = eng.cirisnode_put_goal_json(_goal("publish the report"))

        served = served_statements(eng)
        assert served, "the node serves the statements it produced"
        by_plane: dict[str, list[tuple[bytes, str]]] = {}
        for _, st in served:
            out = json.loads(eng.put_edition2_statement(st))
            assert set(out) == {"plane", "row_id", "new"}, out
            assert out["new"] is False, ("a held statement re-put is not new", out)
            assert HEX64.match(out["row_id"]), out
            by_plane.setdefault(out["plane"], []).append((st, out["row_id"]))
            # Offered under the id it names: the same answer.
            again = json.loads(eng.put_edition2_statement(st, out["row_id"].upper()))
            assert again == out, (again, out)
        assert "key_plane" in by_plane, list(by_plane)
        # The goal row is a row, stored under the id the node computed: the
        # goal id the producer returned is that row id.
        assert gid in [rid for _, rid in by_plane.get("row", [])], (gid, by_plane.get("row"))

        # An offered id the bytes do not name: terminal, by name.
        st, rid = by_plane["row"][0]
        wrong = ("0" if rid[0] != "0" else "1") + rid[1:]
        with pytest.raises(ValueError) as e:
            eng.put_edition2_statement(st, wrong)
        assert str(e.value).startswith(EDITION2_REFUSAL + "row_id_mismatch"), str(e.value)
        # A malformed offered id never reaches the door.
        with pytest.raises(ValueError) as e:
            eng.put_edition2_statement(st, "not-hex")
        assert str(e.value).startswith("offered_row_id"), str(e.value)

        # The earlier form at the edition-2 door: a JSON object (as str
        # bytes) and bytes in no form, both `earlier_form_object`, both
        # ValueError (the type of the malformed-row arm).
        record = eng.lookup_public_key(kid)
        for earlier in (record.encode(), json.dumps({"record": json.loads(record)}).encode(), b"\x00no form"):
            with pytest.raises(ValueError) as e:
                eng.put_edition2_statement(earlier)
            assert str(e.value).startswith(EDITION2_REFUSAL + "earlier_form_object"), str(e.value)
    finally:
        eng.close(force=True)


# ── I2512 ────────────────────────────────────────────────────────────────


def test_statements_round_trip_between_two_nodes_i2512(engine_factory) -> None:
    """I2512 — produce on A, carry the bytes, apply on B."""
    # ── Node A: a key and one row ────────────────────────────────────────
    a = engine_factory("a", 0x5A)
    try:
        ka = a.register_self_federation_key("user")
        gid = a.cirisnode_put_goal_json(_goal("keep the commons open"))
        carried = carry_statements(a)
    finally:
        a.close(force=True)
    keys = [c for c in carried if c[2] == "key_plane"]
    rows = [c for c in carried if c[2] == "row" and c[1] == gid]
    assert keys, carried
    assert len(rows) == 1, ("A serves its goal row once", gid, [c[1:] for c in carried])
    goal_st, goal_rid, _ = rows[0]

    # ── Node B: admit A's statements ─────────────────────────────────────
    b = engine_factory("b", 0xB5)
    try:
        assert b.lookup_public_key(ka) is None

        # The row before its signer's key: it waits. Retryable, by name, and
        # the caller must not advance its cursor; nothing is stored.
        with pytest.raises(ValueError) as e:
            b.apply_replicated_statement(goal_st, goal_rid)
        assert str(e.value).startswith("federation_attester_key_unknown"), str(e.value)

        # Offered under an id the bytes do not name: terminal.
        key_st, key_rid, _ = keys[0]
        wrong = ("0" if key_rid[0] != "0" else "1") + key_rid[1:]
        with pytest.raises(ValueError) as e:
            b.apply_replicated_statement(key_st, wrong)
        assert str(e.value).startswith(EDITION2_REFUSAL + "row_id_mismatch"), str(e.value)
        assert b.lookup_public_key(ka) is None

        # A's key lands; the read model answers for it.
        outs = deliver(b, keys)
        assert any(o["outcome"] == "admitted" for o in outs), outs
        for o, (_, rid, _) in zip(outs, keys):
            assert o["advances_cursor"] is True, o
            if o["outcome"] == "admitted":
                assert (o["plane"], o["row_id"], o["new"]) == ("key_plane", rid, True), o
        assert json.loads(b.lookup_public_key(ka))["key_id"] == ka

        # Now the row lands, under the id A computed.
        got = json.loads(b.apply_replicated_statement(goal_st, goal_rid))
        assert got == {
            "outcome": "admitted",
            "plane": "row",
            "row_id": goal_rid,
            "new": True,
            "advances_cursor": True,
        }, got
        held = json.loads(b.list_attestations_by(ka, 500, None, "goal:"))["items"]
        assert goal_rid in [r["attestation_id"] for r in held], held

        # Re-delivery changes nothing.
        again = json.loads(b.apply_replicated_statement(goal_st, goal_rid))
        assert (again["outcome"], again["new"], again["row_id"]) == ("unchanged", False, goal_rid), again

        # B now serves A's statements byte for byte, as received.
        b_served = {bytes(st) for _, st in served_statements(b)}
        assert goal_st in b_served and keys[0][0] in b_served
    finally:
        b.close(force=True)


# ── I2513 ────────────────────────────────────────────────────────────────


def test_edition2_statements_since_pages_and_resumes_i2513(engine_factory) -> None:
    """I2513 — the serving cursor: one page or many, the same statements in
    the same order; each cursor resumes after its own statement."""
    eng = engine_factory("since", 0x43)
    try:
        eng.register_self_federation_key("user")
        for i in range(3):
            eng.cirisnode_put_goal_json(_goal(f"goal {i}"))

        whole = served_statements(eng)
        assert len(whole) >= 4, len(whole)
        for cursor, st in whole:
            assert CURSOR.match(cursor), cursor
            assert isinstance(st, bytes) and st, st
        # Admission order: the (admitted_us, statement_id) positions rise.
        positions = [(int(c.split(":")[0]), c.split(":")[1]) for c, _ in whole]
        assert positions == sorted(positions) and len(set(positions)) == len(positions), positions

        # One at a time gives the same sequence.
        assert served_statements(eng, page=1) == whole
        # Resuming after the k-th statement serves exactly the rest.
        for k in range(len(whole)):
            rest = eng.edition2_statements_since(whole[k][0], 1000)
            assert rest == whole[k + 1 :], k
        # From the start, a page is bounded by its limit.
        assert eng.edition2_statements_since(None, 2) == whole[:2]

        with pytest.raises(ValueError) as e:
            eng.edition2_statements_since("not-a-cursor", 10)
        assert str(e.value).startswith("cursor"), str(e.value)
    finally:
        eng.close(force=True)


# ── I2514 ────────────────────────────────────────────────────────────────


def test_bundles_in_force_json_shape_i2514(engine_factory) -> None:
    """I2514 — the bundles in force, as a host reads them: one entry per tip
    of the held genesis lineage (CC 2.6.1.11), empty when none is held."""
    eng = engine_factory("bundles", 0x54)
    try:
        bundles = json.loads(eng.bundles_in_force_json())
        assert isinstance(bundles, list), bundles
        for b in bundles:
            assert set(b) == {
                "object_id",
                "version",
                "prev",
                "asserted_at",
                "family_key_id",
                "holders",
                "serve_nodes",
                "counted",
            }, b
            assert HEX64.match(b["object_id"]), b
            assert isinstance(b["version"], int) and b["version"] >= 1, b
            # A fresh genesis is version 1 with no prev; a later bundle names one.
            assert (b["prev"] is None) == (b["version"] == 1), b
            assert b["prev"] is None or HEX64.match(b["prev"]), b
            assert isinstance(b["asserted_at"], int) and b["asserted_at"] > 0, b
            assert isinstance(b["family_key_id"], str) and b["family_key_id"], b
            for member in ("holders", "serve_nodes"):
                refs = b[member]
                assert isinstance(refs, list) and refs, (member, b)
                assert all(is_identity_ref(r) for r in refs), (member, refs)
                # A set (roster / seat order, not sorted): no duplicates.
                assert len(set(refs)) == len(refs), (member, refs)
            assert isinstance(b["counted"], list), b
            assert b["counted"] == sorted(b["counted"]), b
        # Two tips are a fork; each is its own object.
        assert len({b["object_id"] for b in bundles}) == len(bundles), bundles

        # The pin is gone (C1): the call takes no argument.
        with pytest.raises(TypeError):
            eng.bundles_in_force_json("ab" * 32)
    finally:
        eng.close(force=True)


# ── I2515 ────────────────────────────────────────────────────────────────

#: The earlier-form JSON doors that take one JSON string (D1.api.md's table).
#: Slice F may delete a door outright; an absent door is closed too.
EARLIER_FORM_DOORS = (
    "put_public_key",
    "register_federation_key",
    "put_attestation",
    "apply_replicated_attestation",
    "put_revocation",
    "apply_replicated_key_grant",
    "put_identity_occurrence_json",
    "put_family_json",
    "put_community_json",
    "put_lineage_head_cosign_json",
    "apply_replicated_purge_json",
)


def _doors_shut() -> bool:
    return bool(ciris_persist.earlier_form_doors_shut())


def test_earlier_form_doors_shut_is_reachable_from_the_package_i2515() -> None:
    """I2515 (reachability) — the switch a host reads is on the package."""
    assert isinstance(ciris_persist.earlier_form_doors_shut(), bool)


@pytest.mark.skipif(
    not hasattr(ciris_persist, "earlier_form_doors_shut") or not _doors_shut(),
    reason="the earlier-form doors open until slice F flips EARLIER_FORM_DOORS_SHUT",
)
def test_every_earlier_form_door_refuses_by_name_i2515(engine_factory) -> None:
    """I2515 — with the switch on, an earlier-form JSON object at any door
    still on the Engine is refused before it is decoded:
    ``ValueError("federation_malformed_row: <plane>: earlier_form_object …")``,
    the type of the malformed-row arm. The plane is not pinned."""
    eng = engine_factory("shut", 0x65)
    try:
        eng.register_self_federation_key("agent")
        present = [name for name in EARLIER_FORM_DOORS if hasattr(eng, name)]
        for name in present:
            with pytest.raises(ValueError) as e:
                getattr(eng, name)("{}")
            text = str(e.value)
            assert text.startswith("federation_malformed_row: "), (name, text)
            assert "earlier_form_object" in text, (name, text)
        # The edition-2 door stays open beside them.
        served = served_statements(eng)
        assert served
        assert json.loads(eng.put_edition2_statement(served[0][1]))["new"] is False
    finally:
        eng.close(force=True)
