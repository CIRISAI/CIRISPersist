"""v60.1.0 (docs/V61_TASK_PLAN.md §2 slice B) — the consumer asks at the wheel.

- CIRISPersist#1117: ``accord_threshold_for(n)`` is the strict majority, and
  ``Engine.accord_threshold()`` reports ``(m, n)`` over this node's standing
  accord roster with ``m`` that same rule of ``n``.
"""

import pytest

import ciris_persist


def _engine(tmp_path, alias):
    seed = tmp_path / f"{alias}.seed"
    pqc_seed = tmp_path / f"{alias}.pqc"
    seed.write_bytes(bytes([0x3C] * 32))
    pqc_seed.write_bytes(bytes([0xC3] * 32))
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


def test_accord_threshold_for_is_the_strict_majority_1117() -> None:
    for n, m in [(0, 1), (1, 1), (2, 2), (3, 2), (4, 3), (5, 3), (9, 5)]:
        assert ciris_persist.accord_threshold_for(n) == m, n
        assert 2 * ciris_persist.accord_threshold_for(n) > n


def test_engine_accord_threshold_reports_m_of_its_standing_roster_1117(tmp_path) -> None:
    eng = _engine(tmp_path, "v601-accord")
    try:
        m, n = eng.accord_threshold()
        assert isinstance(m, int) and isinstance(n, int)
        assert m == ciris_persist.accord_threshold_for(n), (m, n)
    finally:
        del eng
        ciris_persist.reset_engine()
