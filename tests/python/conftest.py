"""Shared fixtures for the wheel's pytest suite.

v62.0.0 (JSON-cut slice D) — the edition-2 witnesses need two engines that
sign with fixed composite keys, one after the other (the engine is a process
singleton). ``engine_factory`` builds one: a sqlite engine with both halves of
the LocalSigner from fixed seeds, so a failure reproduces, or a skip on a
wheel built without the sqlite feature (the same narrow skip every engine-level
test in this directory uses: a ``ValueError`` naming both ``sqlite`` and
``feature``; any other error re-raises).

Older files keep their own ``_engine`` helpers; nothing here changes them.
"""
from __future__ import annotations

import json
from typing import Callable, Iterator

import pytest

import ciris_persist

#: An identity-ref (CIRISVerify ``edition2::IDENTITY_REF_PREFIX`` followed by
#: the base64url, unpadded, SHA-256 thumbprint of the composite public key:
#: 43 characters).
IDENTITY_REF_PREFIX = "urn:ietf:params:oauth:ckt:sha-256:"
IDENTITY_REF_TAIL_LEN = 43


def is_identity_ref(s: object) -> bool:
    """The shape CIRISVerify's ``is_identity_ref`` accepts."""
    if not isinstance(s, str) or not s.startswith(IDENTITY_REF_PREFIX):
        return False
    tail = s[len(IDENTITY_REF_PREFIX) :]
    return len(tail) == IDENTITY_REF_TAIL_LEN and all(
        c.isascii() and (c.isalnum() or c in "-_") for c in tail
    )


@pytest.fixture
def engine_factory(tmp_path) -> Iterator[Callable[..., "ciris_persist.Engine"]]:
    """``engine_factory(name, fill)`` — a fresh sqlite engine signing with the
    composite key whose Ed25519 seed is ``fill`` × 32 and whose ML-DSA-65
    seed is ``fill ^ 0xFF`` × 32. Resets the singleton first; the caller
    closes it (``eng.close(force=True)``) before building the next one.
    """

    def make(name: str, fill: int, *, dsn: str = "sqlite::memory:") -> "ciris_persist.Engine":
        seed = tmp_path / f"{name}.seed"
        pqc_seed = tmp_path / f"{name}.pqc"
        seed.write_bytes(bytes([fill] * 32))
        pqc_seed.write_bytes(bytes([fill ^ 0xFF] * 32))
        alias = f"e2-{name}"
        ciris_persist.reset_engine()
        try:
            return ciris_persist.Engine(
                dsn,
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

    yield make
    ciris_persist.reset_engine()


def served_statements(eng: "ciris_persist.Engine", page: int = 1000) -> list[tuple[str, bytes]]:
    """Every edition-2 statement ``eng`` holds, in its admission order, as
    ``(cursor, bytes)``: the serving cursor walked to its end, ``page`` at a
    time (``Engine.edition2_statements_since``)."""
    out: list[tuple[str, bytes]] = []
    cursor = None
    while True:
        got = eng.edition2_statements_since(cursor, page)
        out.extend(got)
        if len(got) < page:
            return out
        cursor = got[-1][0]


def carry_statements(eng: "ciris_persist.Engine") -> list[tuple[bytes, str, str]]:
    """What a replication bridge carries off ``eng``: each held statement with
    the row id it is offered under and its plane, as
    ``(bytes, row_id, plane)``. The row id is the producing node's own answer:
    a re-put of a held statement through ``put_edition2_statement`` changes
    nothing (``new`` is False) and names the row."""
    carried = []
    for _, st in served_statements(eng):
        again = json.loads(eng.put_edition2_statement(st))
        assert again["new"] is False, again
        carried.append((bytes(st), again["row_id"], again["plane"]))
    return carried


def deliver(eng: "ciris_persist.Engine", carried: list[tuple[bytes, str, str]]) -> list[dict]:
    """Deliver ``carried`` to ``eng`` through ``apply_replicated_statement``,
    in order; every outcome must be admitted or unchanged (a statement this
    node already holds, for example a genesis it was born with)."""
    outs = []
    for st, row_id, _plane in carried:
        out = json.loads(eng.apply_replicated_statement(st, row_id))
        assert out["outcome"] in ("admitted", "unchanged"), out
        outs.append(out)
    return outs
