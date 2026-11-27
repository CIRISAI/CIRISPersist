"""v62.0.0 (WD-fix18; RESIGN-6's rule) — the Python face of I4423: the
OPTIONAL ``author_kid_hex`` kwarg of ``Engine.publish_self_occurrence``.

A bind whose author is not this node returns the author's voice DRAFTED
(``author_draft``) for the author's pen. The draft's protected header names
the key the author will sign with:

- absent (today's behaviour): the author identity's own key, the kid an
  identity-ref names (the base64url tail decoded);
- ``author_kid_hex``: exactly that 32-byte kid (a second device, a rotated
  key), and NOT the identity's own;
- a value that is not 32 bytes of hex: ``ValueError``, nothing published.

The door judging the drafted voice on arrival is witnessed in Rust (I4423,
sqlite and postgres). The engine is a process singleton, so the parties take
turns over ONE sqlite file, closing between turns.
"""
from __future__ import annotations

import base64
import json

import pytest

from conftest import IDENTITY_REF_PREFIX, is_identity_ref

#: The CDE (deterministic CBOR) head of a 32-byte byte string: major type 2,
#: one length byte (0x58), length 32 (0x20).
BSTR32 = "5820"


def _own_kid_hex(identity_ref: str) -> str:
    assert is_identity_ref(identity_ref), identity_ref
    tail = identity_ref[len(IDENTITY_REF_PREFIX) :]
    kid = base64.urlsafe_b64decode(tail + "=")
    assert len(kid) == 32, identity_ref
    return kid.hex()


def _dsn(tmp_path) -> str:
    return f"sqlite:///{tmp_path / 'author-kid.db'}"


def _register_person(engine_factory, dsn: str) -> str:
    p = engine_factory("akid-person", 0x71, dsn=dsn)
    try:
        return p.register_self_federation_key("user")
    finally:
        p.close(force=True)


def _publish(engine_factory, dsn: str, person: str, **kw) -> dict:
    n = engine_factory("akid-device", 0x72, dsn=dsn)
    try:
        n.register_self_federation_key("user")
        return json.loads(n.publish_self_occurrence(person, "phone", None, **kw))
    finally:
        n.close(force=True)


def test_absent_names_the_author_identitys_own_key(engine_factory, tmp_path) -> None:
    dsn = _dsn(tmp_path)
    person = _register_person(engine_factory, dsn)
    out = _publish(engine_factory, dsn, person)
    assert out["landed"] is False, out
    assert out["author_voice_hex"] is None, out
    draft = out["author_draft"]
    assert draft is not None, out
    assert BSTR32 + _own_kid_hex(person) in draft["protected"], draft


def test_stated_kid_is_the_one_the_draft_names(engine_factory, tmp_path) -> None:
    dsn = _dsn(tmp_path)
    person = _register_person(engine_factory, dsn)
    other = bytes(range(0xA0, 0xC0)).hex()
    assert other != _own_kid_hex(person)
    out = _publish(engine_factory, dsn, person, author_kid_hex=other)
    assert out["landed"] is False, out
    draft = out["author_draft"]
    assert draft is not None, out
    assert BSTR32 + other in draft["protected"], draft
    assert _own_kid_hex(person) not in draft["protected"], draft


@pytest.mark.parametrize("bad", ["", "zz" * 32, "ab" * 31, "ab" * 33])
def test_a_kid_that_is_not_32_bytes_of_hex_is_a_value_error(
    engine_factory, tmp_path, bad: str
) -> None:
    dsn = _dsn(tmp_path)
    person = _register_person(engine_factory, dsn)
    n = engine_factory("akid-device", 0x72, dsn=dsn)
    try:
        n.register_self_federation_key("user")
        with pytest.raises(ValueError, match="author_kid_hex"):
            n.publish_self_occurrence(person, "phone", None, author_kid_hex=bad)
    finally:
        n.close(force=True)
