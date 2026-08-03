"""CIRISPersist#581 — the v24.3.0 teardown API is reachable from the PACKAGE.

#572 added four bounded-teardown entry points on the native module. This
file is the proof they are reachable the way a consumer actually imports
them — ``import ciris_persist`` — rather than by reaching past the package
into ``ciris_persist.ciris_persist``.

**Why this file is pytest and not a Rust test.** A Rust test can prove a
function is registered on the module (``m.add_function(...)``); it cannot
prove the package re-exports it, and it cannot prove the ``.pyi`` describes
the thing that actually runs. This repo's most-repeated defect is a feature
that exists in code with no path a host can call (v22's AV-77 certified a
gate matrix no host could enable; #444 was the same shape). A ``.pyi`` stub
is a *claim about a callable surface*, so the claim is checked here, against
a built wheel, by CI's ``pytest tests/python/`` step.

The checks deliberately go past ``hasattr``: they call each function and
assert its RETURN CONTRACT. That is what rots. Before #581 the stub for
``reset_engine`` read ``def reset_engine() -> None`` — no parameter, no
return — describing pre-v24.3.0 behaviour, while the real function took
``timeout_seconds`` and returned ``"deferred"``. A consumer trusting that
stub would never check the value that tells them teardown had NOT finished.
"""
from __future__ import annotations

import ast
import pathlib

import ciris_persist

#: The tokens every teardown entry point answers with (`TeardownOutcome`).
OUTCOMES = {"drained", "deferred", "timed_out", "no_engine"}

#: The four #572 entry points, as #581 requires them to be importable.
TEARDOWN_EXPORTS = (
    "reset_engine",
    "engine_teardown_wait",
    "engine_teardowns_in_flight",
)


def test_teardown_functions_are_on_the_package_not_just_the_native_module() -> None:
    """The import a consumer actually writes."""
    from ciris_persist import (  # noqa: F401
        engine_teardown_wait,
        engine_teardowns_in_flight,
        reset_engine,
    )

    for name in TEARDOWN_EXPORTS:
        assert hasattr(ciris_persist, name), (
            f"{name} is not on the ciris_persist package. Registering it on "
            f"the native module is not enough — consumers would have to write "
            f"`from ciris_persist.ciris_persist import {name}`, reaching past "
            f"the public API, which is how a private path becomes a contract."
        )
        assert name in ciris_persist.__all__, (
            f"{name} is importable but missing from __all__, so "
            f"`from ciris_persist import *` does not bring it in and type "
            f"checkers treat it as private re-export."
        )


def test_close_blocking_is_on_the_engine_type() -> None:
    """``Engine.close_blocking`` is the handle-side half of the recipe."""
    assert hasattr(ciris_persist.Engine, "close_blocking"), (
        "Engine.close_blocking is missing from the exported Engine type"
    )


def test_teardowns_in_flight_reports_a_count() -> None:
    """Cheap, non-blocking, and an ``int`` — usable in an assertion."""
    n = ciris_persist.engine_teardowns_in_flight()
    assert isinstance(n, int), f"expected an int, got {type(n)!r}"
    assert n >= 0


def test_reset_engine_returns_an_outcome_token_not_none() -> None:
    """**The stub-rot regression.**

    ``reset_engine`` returned ``None`` before v24.3.0 and the ``.pyi`` still
    said so until #581. It now returns an outcome token, and that token is
    the only way a caller learns teardown was *deferred* rather than done.
    With no engine pinned this is a no-op returning ``"no_engine"``.
    """
    outcome = ciris_persist.reset_engine()
    assert outcome is not None, (
        "reset_engine returned None — the pre-v24.3.0 contract. The return "
        "value is how a caller learns teardown was deferred (#572)."
    )
    assert outcome in OUTCOMES, f"unknown teardown outcome {outcome!r}"


def test_engine_teardown_wait_returns_an_outcome_token() -> None:
    """The second half of the fixture recipe, callable with no engine."""
    outcome = ciris_persist.engine_teardown_wait(1.0)
    assert outcome in OUTCOMES, f"unknown teardown outcome {outcome!r}"


def test_the_fixture_recipe_572_exists_to_enable_actually_runs() -> None:
    """End-to-end, exactly as #572 documents it for consumer fixtures —
    replacing a ``time.sleep(0.2)`` guess with a deterministic wait."""
    import gc

    ciris_persist.reset_engine()
    gc.collect()
    assert ciris_persist.engine_teardown_wait(10.0) == "drained"
    assert ciris_persist.engine_teardowns_in_flight() == 0


def test_the_package_is_marked_typed_or_the_stubs_are_dead_weight() -> None:
    """PEP 561 — without a ``py.typed`` marker, every type checker SKIPS the
    package's inline stubs entirely.

    This is not a detail about the three symbols #581 added. Without the
    marker the whole ~1900-line ``ciris_persist.pyi`` is invisible
    downstream: mypy reports *"Skipping analyzing ciris_persist: module is
    installed, but missing library stubs or py.typed marker"* and every
    annotation in it does nothing. The stub file has always shipped in the
    wheel; the marker never did, so the stubs had never once been read by a
    consumer's type checker.

    A ``.pyi`` is a claim about a callable surface. This asserts the claim
    can actually be received.
    """
    import ciris_persist as _pkg

    marker = pathlib.Path(_pkg.__file__).resolve().parent / "py.typed"
    assert marker.exists(), (
        "python/ciris_persist/py.typed is missing. Without it PEP 561 tells "
        "every type checker to ignore ciris_persist.pyi, so the stubs ship "
        "and are never read."
    )


def test_the_pyi_stubs_describe_the_functions_that_actually_exist() -> None:
    """The stub is a claim about a callable surface — check the claim.

    Parses the shipped ``.pyi`` and asserts each teardown entry point is
    declared, that ``reset_engine`` is no longer declared as the
    zero-argument ``-> None`` form, and that the declared names match what
    the package really exports. A stub that has silently drifted from the
    runtime is worse than a missing one: it is trusted.
    """
    stub_path = (
        pathlib.Path(__file__).resolve().parents[2]
        / "python"
        / "ciris_persist"
        / "ciris_persist.pyi"
    )
    if not stub_path.exists():  # pragma: no cover — wheel-only layouts
        import pytest

        pytest.skip(f"stub not present at {stub_path}")

    tree = ast.parse(stub_path.read_text())
    module_fns = {
        n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)
    }

    for name in TEARDOWN_EXPORTS:
        assert name in module_fns, f"{name} has no .pyi stub"

    reset = module_fns["reset_engine"]
    assert reset.args.args, (
        "reset_engine's stub declares no parameters — the pre-v24.3.0 shape. "
        "It takes timeout_seconds (#572)."
    )
    returns = ast.unparse(reset.returns) if reset.returns else "None"
    assert returns == "str", (
        f"reset_engine's stub returns {returns!r}; it returns an outcome "
        f"token (str) since v24.3.0, and the token is load-bearing (#572)."
    )

    engine = next(
        n
        for n in tree.body
        if isinstance(n, ast.ClassDef) and n.name == "Engine"
    )
    engine_methods = {
        n.name for n in engine.body if isinstance(n, ast.FunctionDef)
    }
    assert "close_blocking" in engine_methods, (
        "Engine.close_blocking has no .pyi stub"
    )
