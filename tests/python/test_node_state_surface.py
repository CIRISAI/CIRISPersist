"""CIRISServer#356 — the operator read surface, proven HOST-REACHABLE.

A ``#[pyfunction]`` that exists is not a shipped feature. This repo's
most-repeated defect is machinery that exists and does no work: AV-77's
de-admission gate passed a full ``{gate} x {backend}`` witness matrix while no
host could enable it, #444's route table was accepted but never projected,
#589, the missing ``py.typed`` marker. Every one of them was proven by a
fixture that reached past the surface a consumer actually uses.

So these tests take the consumer's path and nothing else: build a wheel,
``import ciris_persist``, construct an ``Engine``, call the method by name, and
assert the return CONTRACT — the keys, the token vocabulary, and the three
properties #356 asks the surface to guarantee:

1. ``"unknown"`` is representable, and it is neither ``"green"`` nor absent.
2. The zeroes are distinguished — different facts do not share a token.
3. The read-only overdue query writes nothing, proven by the aggregate's own
   ``read_only`` flag and by the emitting sibling being a separate name.

Skips on a wheel built without the ``sqlite`` feature (see
``test_sqlite_engine.py`` for the same guard).
"""
from __future__ import annotations

import json

import pytest

import ciris_persist

# The band vocabulary. Closed, lowercase, and four-valued.
BANDS = {"green", "yellow", "red", "unknown"}

# Every #356 binding this cut added, plus the three that already reached
# Python. A missing attribute here is the AV-77 failure mode exactly.
BINDINGS = (
    "node_state_json",
    "trust_root_verdict_json",
    "resolve_key_statement_standing_json",
    "resolve_quarantine_json",
    "resolve_reverse_quorum_json",
    "peer_quota_observation_json",
    "list_consent_revocation_promotion_overdue_readonly_json",
    "list_consent_revocation_promotion_overdue_json",
    "resolve_transit_eligibility_json",
    "is_load_bearing_json",
)


def _engine(key: str):
    try:
        return ciris_persist.Engine(dsn="sqlite://:memory:", signing_key_id=key)
    except ValueError as exc:
        if "sqlite" in str(exc) and "feature" in str(exc):
            pytest.skip("wheel built without the sqlite feature")
        raise


def test_every_356_binding_is_present_on_the_wheel() -> None:
    """The bindings exist on the class a consumer imports — not merely in
    ``src/ffi/pyo3.rs``. A signal with no reachable binding does not exist for
    CIRISServer or CIRISEdge, which reach persist only through this FFI."""
    for name in BINDINGS:
        assert hasattr(ciris_persist.Engine, name), f"{name} is not on the wheel"


def test_node_state_json_contract() -> None:
    """The aggregate answers, in one call, with the documented shape."""
    eng = _engine("ns356-agg")
    try:
        state = json.loads(eng.node_state_json())

        # The envelope.
        assert set(state) >= {
            "as_of",
            "band",
            "trust_root",
            "key_statements",
            "quarantine",
            "consent_sla",
            "peer_quota",
            "clock_dependent",
            "targeted",
        }
        assert state["band"] in BANDS

        # Every signal carries a band, and every band is in the closed set.
        for signal in (
            "trust_root",
            "key_statements",
            "quarantine",
            "consent_sla",
            "peer_quota",
        ):
            assert state[signal]["band"] in BANDS, signal

        # (3) The consent-SLA leg is READ-ONLY, and says so in the payload.
        assert state["consent_sla"]["read_only"] is True

        # Clock-dependence is stated, not left to be discovered.
        assert state["clock_dependent"], "the clock-dependent fields must be named"
        assert "trust_root.drill_band" in state["clock_dependent"]

        # The signals that are NOT node facts are named with the binding that
        # answers each, so their absence here is legible rather than silent.
        assert state["targeted"], "targeted signals must be enumerated"
        for entry in state["targeted"]:
            assert set(entry) == {"signal", "requires", "binding"}
            assert hasattr(ciris_persist.Engine, entry["binding"]), entry["binding"]
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_unknown_is_representable_and_is_not_green() -> None:
    """(1) A host that never declared its own key id gets ``"unknown"`` on every
    self-scoped signal — never green, never omitted — and ``unknown[]`` names
    each one so the roll-up cannot swallow it."""
    eng = _engine("ns356-unknown")
    try:
        state = json.loads(eng.node_state_json())

        assert state["trust_root"]["standing"] == "no_self_key"
        assert state["trust_root"]["band"] == "unknown"
        # An uncomputable signal is ABSENT, never a healthy default.
        assert "standing" not in state["key_statements"]
        assert state["key_statements"]["band"] == "unknown"
        assert "state" not in state["quarantine"]
        assert state["quarantine"]["band"] == "unknown"

        assert state["band"] == "unknown", "the headline must not read green"
        for name in (
            "trust_root",
            "trust_root.drill_band",
            "key_statements",
            "quarantine",
        ):
            assert name in state["unknown"], f"unknown[] must name {name}"

        # Declaring the key moves the SAME node off unknown, which is what
        # makes the unknown a statement about the reader rather than the node.
        eng.set_self_key_id("ns356-declared-key")
        after = json.loads(eng.node_state_json())
        assert after["trust_root"]["standing"] == "no_trust_edges"
        assert after["trust_root"]["band"] == "red"
        assert after["key_statements"]["standing"] == "stands"
        assert after["quarantine"]["state"] == "not_quarantined"
        assert "key_statements" not in after["unknown"]
        eng.set_self_key_id(None)
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_the_zeroes_do_not_share_a_token() -> None:
    """(2) "nobody answered" and "answered no" are different facts. Two
    different ways of having no valid trust root produce two different tokens
    on two different bands — a fold that collapsed them would re-introduce the
    defect the typed standings exist to prevent."""
    eng = _engine("ns356-zeroes")
    try:
        eng.set_self_key_id(None)
        undeclared = json.loads(eng.node_state_json())
        declared = json.loads(eng.node_state_json(self_key_id="ns356-somebody"))

        assert undeclared["trust_root"]["standing"] != declared["trust_root"]["standing"]
        assert undeclared["trust_root"]["band"] != declared["trust_root"]["band"]
        assert {
            undeclared["trust_root"]["standing"],
            declared["trust_root"]["standing"],
        } == {"no_self_key", "no_trust_edges"}

        # The peer-quota zero is the other one: slot_denials == 0 on a fresh
        # engine is UNTESTED, not clean, and tracked_peers is what tells them
        # apart.
        quota = json.loads(eng.peer_quota_observation_json())
        assert quota["process_local"] is True
        assert quota["slot_denials"] == 0
        assert quota["tracked_peers"] == 0
        # 609: the refusal axes ride the same payload — empty on a fresh
        # engine, but PRESENT, so "no refusals" and "not measured" differ.
        assert quota["refusals_by_budget"] == {}
        assert quota["refused_keys_in_window"] == 0
        assert undeclared["peer_quota"]["band"] == "unknown"
        assert undeclared["peer_quota"]["note"], "the volatility rides in the payload"
        assert "process-local" in undeclared["peer_quota"]["note"]
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_readonly_overdue_query_emits_nothing() -> None:
    """(3) The non-emitting overdue query answers the same question as its
    emitting sibling and is a SEPARATE name, so a dashboard can poll it.

    On an empty substrate both return ``[]``; what this pins at the wheel level
    is that the read-only name exists, is callable, and returns the same
    payload shape. The zero-write property itself is asserted against a live
    overdue row on all three backends by
    ``node_state::parity_test_support::assert_overdue_readonly_writes_nothing``,
    which counts ``hard_case`` rows before and after."""
    eng = _engine("ns356-readonly")
    try:
        ro = json.loads(eng.list_consent_revocation_promotion_overdue_readonly_json())
        emitting = json.loads(eng.list_consent_revocation_promotion_overdue_json())
        assert isinstance(ro, list)
        assert ro == emitting, "the twins must not drift on the same (now, sla)"

        # The SLA window is a parameter on both.
        assert (
            json.loads(
                eng.list_consent_revocation_promotion_overdue_readonly_json(
                    sla_seconds=1
                )
            )
            == []
        )

        # And the aggregate routes through the read-only one.
        assert json.loads(eng.node_state_json())["consent_sla"]["read_only"] is True
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_every_json_arm_is_a_truthy_string() -> None:
    """The recurring FFI defect this surface must not repeat: every ``*_json``
    returns a JSON *string* on both arms, so ``"false"`` and ``'{"valid":
    false}'`` are truthy in Python. ``if engine.is_named_moderator_json(...)``
    granted authority to every key and shipped undetected for releases.

    So: assert the adjudicators return non-empty ``str`` on their REFUSING arm,
    which is exactly the condition that makes a bare truth-test wrong."""
    eng = _engine("ns356-truthy")
    try:
        # `set_self_key_id` writes a process-global slot, so pin it explicitly
        # rather than inheriting whatever an earlier test in this file left.
        eng.set_self_key_id(None)
        verdict = eng.trust_root_verdict_json("ns356-a", "ns356-b")
        assert isinstance(verdict, str) and verdict
        assert bool(verdict) is True, "the refusing arm is TRUTHY — parse it"
        assert json.loads(verdict)["valid"] is False

        standing = eng.resolve_key_statement_standing_json("ns356-a")
        assert isinstance(standing, str) and bool(standing) is True
        assert json.loads(standing)["standing"] == "stands"

        quarantine = eng.resolve_quarantine_json("ns356-a")
        assert isinstance(quarantine, str) and bool(quarantine) is True
        assert json.loads(quarantine)["state"] == "not_quarantined"

        state = eng.node_state_json()
        assert isinstance(state, str) and bool(state) is True
        assert json.loads(state)["band"] == "unknown", (
            "a wholly unknown node still returns a truthy string"
        )
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_clock_is_pinnable_and_bad_clocks_are_caller_errors() -> None:
    """Several of these bands move on elapsed time alone, so the reads take an
    explicit clock. A malformed one is a ``ValueError`` naming the parameter,
    never a silent wall-clock fallback."""
    eng = _engine("ns356-clock")
    try:
        pinned = json.loads(eng.node_state_json(now="2026-07-27T00:00:00Z"))
        assert pinned["as_of"].startswith("2026-07-27T00:00:00")
        # Same clock, same answer — the fold has no state of its own.
        again = json.loads(eng.node_state_json(now="2026-07-27T00:00:00Z"))
        assert again == pinned

        for call in (
            lambda: eng.node_state_json(now="not-a-timestamp"),
            lambda: eng.resolve_quarantine_json("k", now="not-a-timestamp"),
            lambda: eng.resolve_key_statement_standing_json(
                "k", statement_at="not-a-timestamp"
            ),
        ):
            with pytest.raises(ValueError):
                call()
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()


def test_reverse_quorum_refuses_an_action_this_node_never_saw() -> None:
    """An id this node does not hold is a ``ValueError``, not a fold about
    nothing — an empty fold would be indistinguishable from a real
    ``"not_governed"`` verdict, which is the class of answer this whole surface
    exists to stop producing. An unrecognised cohort is likewise a refusal."""
    eng = _engine("ns356-rq")
    try:
        with pytest.raises(ValueError) as missing:
            eng.resolve_reverse_quorum_json("community", "c-1", "ns356-no-such-action")
        # The message names the id, which can only be produced AFTER the
        # backend read ran and came back empty — so this also witnesses that
        # the binding reaches the directory rather than failing at the border.
        assert "ns356-no-such-action" in str(missing.value)

        with pytest.raises(ValueError) as bad_cohort:
            eng.resolve_reverse_quorum_json("species", "c-1", "ns356-no-such-action")
        assert "rostered cohort" in str(bad_cohort.value)

        # All four rostered cohorts parse; none of them is the thing refused.
        for cohort in ("self", "family", "community", "affiliations"):
            with pytest.raises(ValueError) as exc:
                eng.resolve_reverse_quorum_json(cohort, "c-1", "ns356-no-such-action")
            assert "rostered cohort" not in str(exc.value), cohort
    finally:
        eng.close(force=True)
    ciris_persist.reset_engine()
