#!/usr/bin/env python3
"""wheel_features.py — the TESTED wheel's feature line, DERIVED from the
SHIPPED wheel's feature list.

CIRISPersist#710. The wheel users install is built by `maturin build` with NO
`--features`, so it ships exactly `pyproject.toml [tool.maturin] features` —
~27 features. The wheel pytest tested was built by `maturin develop --features
test-panic,pyo3,sqlite,cirisnode`, and `--features` on the maturin CLI
REPLACES the pyproject list, it does not union with it (verified on v34.0.0 by
building that exact line and probing the module). So the tested artifact was a
hand-maintained SUBSET of the shipped one: cirisgraph, cirisaudit, telemetry,
secrets, extract, classify, scrub, encrypted-kv and the entire cirislens_*
family were shipped and never imported under pytest. v34.0.0 appended
`cirisnode` for one slice — by hand, which is how the list got there in the
first place. A hand-written list is a second source of truth, and it drifts
silently and in the optimistic direction (#585, same class).

The cure is derivation, not diligence — the same cure `ci_feature_matrix.py`
applies to the Rust test matrix. This script reads pyproject's shipped list
(the ONLY inventory of what users install) and answers two questions:

  * **What feature line does a tested dev-wheel build with?** — `line`.
    (shipped − EXCLUDED) + TEST_ONLY, comma-separated for `maturin develop
    --features`. ci.yml's wheel-pytest step and certify.sh's `python` leg both
    ask; neither spells a feature out. A feature added to pyproject lands in
    the tested wheel automatically, with nothing to remember.
  * **Is the tested wheel still a superset of the shipped one?** — `check`.
    Fails, loudly and by name, if any shipped feature is neither in the
    derived line nor excluded here in writing — and if ci.yml or certify.sh
    has gone back to spelling a `maturin develop --features` list by hand,
    which is the #710 defect reopening.

CIRISPersist#669 is the other half of the same theme: `certify.sh full` — THE
release gate — never ran tests/python at all, so v34.0.0 was certified "EVERY
CI LEG GREEN BY EXIT CODE" by a script structurally unable to run the only
witness that the headline feature was Python-reachable. certify.sh's `python`
leg now exists and derives its feature line from here; `check` fails if that
leg stops deriving (or disappears).

Usage:
    scripts/wheel_features.py shipped   # pyproject's shipped list, one per line
    scripts/wheel_features.py line      # the derived maturin-develop feature line (CSV)
    scripts/wheel_features.py check     # the gate; exit 1 + names on any gap
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CARGO_TOML = REPO / "Cargo.toml"
PYPROJECT = REPO / "pyproject.toml"
CI_YML = REPO / ".github" / "workflows" / "ci.yml"
CERTIFY = REPO / "scripts" / "certify.sh"

# ── The plan ────────────────────────────────────────────────────────────────

#: Shipped features the TESTED build must NOT enable, each with the reason in
#: writing. A key that stops being shipped fails `check` (no stale entries);
#: an empty reason fails `check` (no unexplained exclusions). Adding an entry
#: here is a reviewable act — which is the entire difference from #710, where
#: omission required no act at all.
EXCLUDED: dict[str, str] = {
    "extension-module": (
        "tells PyO3 not to link libpython — correct for the RELEASED cdylib "
        "(`maturin build` takes it from pyproject; the importing interpreter "
        "provides the symbols), but under `maturin develop`/`cargo test` it "
        "strips libpython from binaries that need it (Cargo.toml's v1.13.0 "
        "note: `undefined symbol: _Py_DecRef`). The dev-wheel has linked "
        "libpython normally since v0.5.4 and is imported by a real "
        "interpreter either way. This is the ONE divergence between the "
        "tested and shipped shapes, and it is linking metadata, not code — "
        "it gates no module and no symbol."
    ),
}

#: Test-only riders: features the TESTED build adds that the shipped wheel
#: must NOT carry. `check` fails if one of these ever appears in pyproject's
#: shipped list — a panic injector in a release wheel is a defect, not a
#: coverage win.
TEST_ONLY: dict[str, str] = {
    "test-panic": (
        "compiles the FFI panic injector (`_test_inject_panic`) that "
        "tests/python/test_catch_panic.py drives to prove a Rust panic "
        "surfaces as `LensQueryError` (Exception), not `PanicException` "
        "(BaseException). Release wheels gate it out."
    ),
}


def shipped_features() -> list[str]:
    """The wheel users install: `pyproject.toml [tool.maturin] features`, in
    declaration order. `maturin build` runs with no `--features`, so this list
    IS the shipped artifact's shape."""
    with PYPROJECT.open("rb") as fh:
        return list(tomllib.load(fh)["tool"]["maturin"]["features"])


def declared_features() -> list[str]:
    """Every feature in `Cargo.toml [features]` — what cargo will accept."""
    with CARGO_TOML.open("rb") as fh:
        return list(tomllib.load(fh)["features"])


def derived() -> list[str]:
    """(shipped − EXCLUDED) + TEST_ONLY, in stable order."""
    return [f for f in shipped_features() if f not in EXCLUDED] + list(TEST_ONLY)


# ── The gate ────────────────────────────────────────────────────────────────


def _shell_lines(path: Path) -> list[str]:
    """Non-comment lines of a shell/YAML file. Both YAML comments and the
    shell comments inside `run:` blocks start with `#`, and several of them
    QUOTE old `maturin develop --features …` lines as history — prose must not
    be able to trip (or satisfy) this gate."""
    return [
        ln
        for ln in path.read_text().splitlines()
        if not ln.lstrip().startswith("#")
    ]


#: A YAML step label (`- name: maturin develop (…)`) is prose, not a command.
YAML_NAME_LINE = re.compile(r"^\s*-?\s*name:")

#: A hand-spelled feature list on a `maturin develop` line — the #710 defect.
#: `--features` must be a `$`-expansion of the derived line, never a literal.
#: The lookahead tolerates quoting/escaping (`"$WF"`, `\"${WF}\"`), so an echo
#: that PRINTS the derived line does not read as spelling one.
HAND_SPELLED_DEVELOP = re.compile(r"--features\s+(?![\"'\\]*\$)")

#: The derived call, as an ACTUAL command substitution — `$(python3
#: scripts/wheel_features.py line)`. Matched against comment-stripped lines
#: only. Both constraints exist because a mutation survived without them: with
#: a plain substring test on raw text, a comment MENTIONING `wheel_features.py
#: line` kept this gate green after the real call was replaced by a literal
#: `WF="test-panic,pyo3"`. Prose must not be able to satisfy the gate.
DERIVED_CALL = re.compile(r"\$\(\s*python3 scripts/wheel_features\.py line\s*\)")

#: Same discipline for certify's fast gate: the invocation, not a mention.
CHECK_CALL = re.compile(r"python3 scripts/wheel_features\.py check\b")


def check() -> int:
    problems: list[str] = []
    shipped = shipped_features()
    declared = set(declared_features())
    tested = set(derived())

    # 1. The shipped list may only name features cargo knows. A name here that
    #    is not a Cargo feature means the RELEASE `maturin build` (which takes
    #    this list) fails — or worse, ships without the intended module. Name
    #    it here, seconds in, not ten minutes into a wheel build.
    for f in shipped:
        if f not in declared:
            problems.append(
                f"pyproject [tool.maturin] features ships {f!r}, which is not a "
                f"feature in Cargo.toml — `maturin build` would be rejected by "
                f"cargo, and the derived test line inherits the same poison."
            )

    # 2. No stale or unexplained exclusion.
    for name, reason in EXCLUDED.items():
        if name not in shipped:
            problems.append(
                f"EXCLUDED names {name!r}, which pyproject no longer ships — "
                f"stale entry; delete it."
            )
        if not reason.strip():
            problems.append(
                f"EXCLUDED[{name!r}] has no reason. A shipped feature held out "
                f"of the tested wheel must say why, in writing, here."
            )

    # 3. Test-only riders must be real features and must NOT ship.
    for name, reason in TEST_ONLY.items():
        if name not in declared:
            problems.append(
                f"TEST_ONLY names {name!r}, which is not a feature in "
                f"Cargo.toml — stale entry; delete it."
            )
        if name in shipped:
            problems.append(
                f"TEST_ONLY feature {name!r} appears in pyproject's SHIPPED "
                f"list — a test-only injector must never ride a release wheel."
            )
        if not reason.strip():
            problems.append(f"TEST_ONLY[{name!r}] has no reason.")

    # 4. THE SUPERSET INVARIANT — tested ⊇ (shipped − EXCLUDED). Recomputed
    #    from the inputs, independently of how `derived()` is written, so an
    #    edit to the derivation itself cannot silently narrow the tested wheel.
    for f in shipped:
        if f not in EXCLUDED and f not in tested:
            problems.append(
                f"shipped feature {f!r} is in NO tested wheel build and is not "
                f"in EXCLUDED. The wheel users install would carry code pytest "
                f"never imports (#710). Either the derivation is broken or the "
                f"exclusion belongs on the record with a reason."
            )

    # 5. ci.yml and certify.sh must ASK for the tested feature line, never
    #    spell it. This is the check that keeps #710 closed: the first
    #    hand-edited `maturin develop --features a,b,c` in either file fails
    #    here by name, before anything builds.
    for path, label in ((CI_YML, "ci.yml"), (CERTIFY, "certify.sh")):
        if not path.exists():
            problems.append(f"{label} not found at {path} — the anchor moved; fix this script.")
            continue
        lines = _shell_lines(path)
        if not any(DERIVED_CALL.search(ln) for ln in lines):
            problems.append(
                f"{label} has no `$(python3 scripts/wheel_features.py line)` "
                f"command substitution outside comments — its tested wheel "
                f"build no longer derives from the shipped list, which is the "
                f"#710 defect (ci.yml) / the #669 leg going dark (certify.sh)."
            )
        for ln in lines:
            if "maturin develop" not in ln or YAML_NAME_LINE.match(ln):
                continue
            if "--features" not in ln:
                problems.append(
                    f"{label} runs `maturin develop` with NO --features — that "
                    f"build takes pyproject's list verbatim, i.e. WITH "
                    f"extension-module and WITHOUT the test-only riders; the "
                    f"tested shape must come from `wheel_features.py line`. "
                    f"Line: {ln.strip()!r}"
                )
            elif HAND_SPELLED_DEVELOP.search(ln):
                problems.append(
                    f"{label} hand-spells a `maturin develop --features` list "
                    f"— a second source of truth about the tested wheel, and "
                    f"it WILL drift (#710). Take it from `wheel_features.py "
                    f"line`. Line: {ln.strip()!r}"
                )
        if label == "certify.sh" and not any(CHECK_CALL.search(ln) for ln in lines):
            problems.append(
                "certify.sh no longer runs `python3 scripts/wheel_features.py "
                "check` among its fast static gates (outside comments) — this "
                "gate would only run in CI, and the release gate is certify "
                "(#669)."
            )

    # 6. The RELEASE wheel build must take its shape from pyproject alone. A
    #    `--features` on `maturin build` in ci.yml would make the shipped
    #    artifact diverge from the list this whole derivation reads.
    for ln in _shell_lines(CI_YML):
        if YAML_NAME_LINE.match(ln):
            continue
        if "maturin build" in ln and "--features" in ln:
            problems.append(
                f"ci.yml passes --features to `maturin build` — the shipped "
                f"wheel would no longer be pyproject's list, which is the "
                f"single source everything here derives from. Line: "
                f"{ln.strip()!r}"
            )

    if problems:
        for p in problems:
            print(f"::error title=wheel features::{p}")
            print(f"✗ {p}", file=sys.stderr)
        return 1

    print(
        f"✓ wheel coverage: {len(shipped)} features shipped; "
        f"{len(tested)} in the tested dev-wheel "
        f"({len(EXCLUDED)} excluded with a written reason, "
        f"{len(TEST_ONLY)} test-only rider"
        f"{'' if len(TEST_ONLY) == 1 else 's'}); "
        f"tested ⊇ shipped − excluded; no hand-spelled maturin feature lists."
    )
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "shipped":
        print("\n".join(shipped_features()))
        return 0
    if cmd == "line":
        print(",".join(derived()))
        return 0
    if cmd == "check":
        return check()
    raise SystemExit(f"unknown command {cmd!r}")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
