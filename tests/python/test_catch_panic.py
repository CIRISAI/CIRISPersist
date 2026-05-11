"""v0.5.4 (CIRISPersist#29) — regression test for the FFI catch_panic
layer.

Closes the gap left by CIRISPersist#24, where a Rust panic on an
aggregate-on-empty-CTE NULL cascaded through the PyO3 boundary as
``PanicException`` (subclass of ``BaseException``). uvicorn's normal
``try: ... except Exception:`` request-handler error path doesn't
catch ``BaseException`` — the panic landed at uvicorn's process-level
fallback and SIGABRT'd the worker (when ``panic = "abort"`` was set in
Cargo.toml). v0.5.3 changed Cargo.toml's panic policy to ``"unwind"``
and added the explicit ``catch_panic`` wrapper at every PyO3 entry
point; v0.5.4 completed the wrap sweep across the pre-v0.5.0 surface.

The injector (``_test_inject_panic``) is a feature-gated module-level
function that bypasses Engine construction (no Postgres / keyring
setup needed) so this test isolates the FFI catch_panic layer's
behavior. It only exists when the crate is built with
``--features test-panic``; release wheels don't expose it.
"""
from __future__ import annotations

import sys

import pytest

import ciris_persist

LensQueryError = getattr(ciris_persist, "LensQueryError", None)

# `_test_inject_panic` lives on the inner pyo3 module; it's
# intentionally not re-exported in the public `__all__` since release
# wheels don't compile it in (gated on `--features test-panic`).
try:
    from ciris_persist.ciris_persist import _test_inject_panic as _inject
except ImportError:
    _inject = None  # type: ignore[assignment]


pytestmark = pytest.mark.skipif(
    _inject is None,
    reason=(
        "ciris_persist not built with --features test-panic; "
        "CI builds the wheel with that feature (release wheels don't)."
    ),
)


def test_lens_query_error_exported() -> None:
    """v0.5.3 (CIRISPersist#27) must export LensQueryError."""
    assert LensQueryError is not None, (
        "LensQueryError not exported; v0.5.3+ wheel required."
    )
    assert issubclass(LensQueryError, Exception), (
        f"LensQueryError must subclass Exception; got mro={LensQueryError.__mro__}"
    )


def test_panic_surfaces_as_lens_query_error() -> None:
    """Rust panic crossing the FFI boundary must become LensQueryError."""
    with pytest.raises(LensQueryError) as excinfo:
        _inject("synthetic panic for CIRISPersist#29")
    assert "synthetic panic for CIRISPersist#29" in str(excinfo.value), (
        f"Panic message lost in conversion; got: {excinfo.value!r}"
    )


def test_panic_caught_by_bare_except_exception() -> None:
    """uvicorn's request handler uses ``except Exception:`` — confirm
    the panic-converted error is caught by that pattern. This is the
    actual CIRISPersist#24 failure shape: PanicException's
    BaseException parent slipped past this guard."""
    caught = False
    try:
        _inject("uvicorn-shape panic test")
    except Exception:  # noqa: BLE001 — uvicorn-shape catch is the point
        caught = True
    assert caught, (
        "Rust panic was NOT caught by `except Exception:` — uvicorn's "
        "request-handler error path would not catch it either. "
        "This is the CIRISPersist#24 wedge mode."
    )


def test_panic_is_not_panic_exception() -> None:
    """PyO3's built-in trampoline raises ``pyo3.exceptions.PanicException``
    which subclasses BaseException. Confirm catch_panic preempted that
    path — the converted error is NOT a PanicException."""
    try:
        from pyo3.exceptions import PanicException  # type: ignore[import-not-found]
    except ImportError:
        # PyO3 exposes PanicException under a private path that varies
        # by version; the precise name doesn't matter for this assert.
        # The behavioral assert is: it IS a normal Exception, not a
        # BaseException-only class (covered by other tests).
        return

    with pytest.raises(LensQueryError) as excinfo:
        _inject("not a PanicException")
    assert not isinstance(excinfo.value, PanicException), (
        "Got PanicException; catch_panic wrapper didn't fire."
    )


def test_module_survives_repeated_panics() -> None:
    """The point of ``panic = unwind`` + catch_panic is that the
    process survives. Verify N injected panics still raise (not
    segfault / not abort), and that a normal call works afterward."""
    for i in range(5):
        with pytest.raises(LensQueryError):
            _inject(f"panic iter {i}")
    # Sanity: a non-panic call afterward returns normally.
    assert isinstance(ciris_persist.__version__, str)
    assert ciris_persist.__version__, "version string is empty"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
