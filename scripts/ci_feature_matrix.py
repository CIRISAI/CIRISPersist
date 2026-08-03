#!/usr/bin/env python3
"""ci_feature_matrix.py — CI's feature coverage, DERIVED from Cargo.toml.

CIRISPersist#585. `secrets-server` sat broken on `main` for three releases
(the CIRISPersist#565 `capability_roles` rename never reached
`src/server/secrets.rs`) while every CI run stayed green, because the feature
sets clippy and the test matrix ran against were **hand-written lists inside
`.github/workflows/ci.yml`**. A hand-written list is a second source of truth
about which features exist, and it drifted from `Cargo.toml` silently. Same
class as the CIRISPersist#444 route table and the v22 AV-77 "SHIPPED means
HOST-REACHABLE" lesson: an inventory that is supposed to mirror a real one,
maintained by diligence.

The cure is derivation, not diligence. `Cargo.toml [features]` is the only
inventory. This script reads it and answers two questions:

  * **What does each CI job compile?** — `set <leg>`. `ci.yml` asks; it never
    spells a feature list out. A feature added to `Cargo.toml` lands in the
    `rest` leg automatically, with nothing to remember.
  * **Is anything uncovered?** — `check`. Fails, loudly and by name, if a
    declared feature is compiled by no job, or is run by no test leg without
    a written reason.

Two coverage axes, and they are NOT the same claim:

  COMPILE  Every declared feature is compiled + clippy-linted. Guaranteed by
           construction: the `lint` job runs `cargo clippy --all-features
           --all-targets -- -D warnings`, which cannot omit a feature. `check`
           asserts that invocation is still in `ci.yml`; deleting it is the
           only way to reopen the #585 hole, and it now fails the build.

  TEST     Every declared feature has its tests EXECUTED by some invocation of
           `linux-x86_64-test` — a matrix leg, or a `RIDER` step on one. Not
           free — a leg is a runner — so a feature may be held out, but only
           via `NOT_TESTED` below, which demands a reason and is checked for
           staleness. Held-out features are still COMPILE-covered; nothing is
           ever dropped silently.

Usage:
    scripts/ci_feature_matrix.py list            # declared features, one per line
    scripts/ci_feature_matrix.py legs            # matrix-leg names, one per line
    scripts/ci_feature_matrix.py set <name>      # space-separated cargo feature string
                                                 # (a leg, a rider, or `lint`)
    scripts/ci_feature_matrix.py report          # human-readable coverage table
    scripts/ci_feature_matrix.py check           # the gate; exit 1 + names on any gap
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CARGO_TOML = REPO / "Cargo.toml"
CI_YML = REPO / ".github" / "workflows" / "ci.yml"
PYPROJECT = REPO / "pyproject.toml"

# ── The plan ────────────────────────────────────────────────────────────────

#: Carried by every test leg: both backends + the HTTP surface + the FFI. The
#: substrate axes below are `cfg`-independent of each other, so one leg per
#: axis parallelizes instead of summing (see ci.yml's matrix comment).
BASE = ("postgres", "server", "pyo3", "sqlite")

#: One leg per substrate axis, each = BASE + itself. These exist for
#: wall-clock, not for coverage — `rest` would cover them too.
AXIS_LEGS = ("cirisaudit", "secrets", "cirisnode", "cirisgraph", "telemetry")

#: The narrow set the `lint` job's FIRST clippy pass uses. It is NOT redundant
#: with `--all-features`: `dead_code` / `unused_imports` fire only when a
#: feature is OFF, so the shipped-shape pass catches lints the total pass
#: structurally cannot. Derived as BASE + the substrate axes so it can never
#: drift from the test matrix.
LINT_SHIPPED = BASE + AXIS_LEGS

#: Test invocations that are NOT matrix rows. A configuration too small to
#: deserve a whole runner rides an existing leg as an extra step instead —
#: `name -> (host leg, feature set)`. They count toward TEST coverage exactly
#: as a leg does, and `check` verifies ci.yml still runs each one.
#:
#: `test-anchor` is here rather than in a leg because it is a CONFIGURATION,
#: not a flag: the feature compiles the genesis relaxation in and
#: `ciris_verify_core::test_anchor::test_anchor_active()` (reading
#: `CIRIS_TEST_TRUST_ROOT`) switches it on. Folding the flag into a 30-feature
#: leg would certify nothing — with the env unset the relaxation is inert. It
#: needs its own invocation, and nextest's process isolation is load-bearing
#: because the genesis fixtures use `std::env::set_var`.
RIDERS: dict[str, tuple[str, tuple[str, ...]]] = {
    "test-anchor": ("cirisaudit", ("sqlite", "test-anchor")),
}

#: Features deliberately held out of every TEST leg, each with the reason.
#: They remain COMPILE-covered by the `--all-features` clippy pass. A key that
#: stops being a real feature fails `check` (no stale entries); an empty reason
#: fails `check` (no unexplained holdouts). Adding a feature here is a
#: reviewable act — which is the entire difference from #585, where omission
#: required no act at all.
NOT_TESTED: dict[str, str] = {
    "default": "the empty default set; `cargo nextest run` with no --features IS this leg (the wire_format_fixtures step)",
    "extension-module": "tells PyO3 not to link libpython — correct for the cdylib wheel, but it strips libpython from the test binary too, which then fails to link with `undefined symbol: _Py_DecRef`. See the Cargo.toml note. Compile-covered by clippy (metadata-only, never links).",
    "test-panic": "its entire surface is one `#[pyfunction]` (`_test_inject_panic`) reachable only from Python. It IS exercised — by the pytest catch_panic regression the `core` leg runs after `maturin develop --features test-panic,pyo3` — just not by a Rust leg, which would compile it and call it zero times.",
    "scrub-ner": "+500MB of Candle/Tokenizers/HF-Hub codegen, AND it turns an existing test into a network call: `ner::tests::stub_returns_not_configured_without_setup` reaches `is_configured()`, which under this feature is `BACKEND.get_or_init(init)` — a lazy XLM-R/DistilBERT load from `CIRISLENS_NER_MODEL_DIR` or, failing that, HF Hub. Compile-covered by the `--all-features` clippy pass, which is check-only and pays none of the codegen.",
    "scrub-ort": "pulls `scrub-ner`, so it inherits that reason; additionally `ort` is built `load-dynamic`, so the ORT arm (reached when `CIRISLENS_NER_BACKBONE=ort`) wants a host libonnxruntime the runners do not carry.",
    "default-pipeline-ml": "a bundle whose only content is `scrub-ner` + `extract`; held out for the same reason as `scrub-ner`.",
    "_pyffi": "internal shared gate, not meant to be enabled directly (it would give a PyEngine with no backend). Every leg gets it transitively via `pyo3`.",
}


def declared_features() -> list[str]:
    """Every feature in `Cargo.toml [features]`, in declaration order."""
    with CARGO_TOML.open("rb") as fh:
        return list(tomllib.load(fh)["features"])


def feature_graph() -> dict[str, list[str]]:
    """`feature -> the sibling features it enables` (dep:/crate features dropped)."""
    with CARGO_TOML.open("rb") as fh:
        table = tomllib.load(fh)["features"]
    return {
        name: [e for e in enables if e in table]
        for name, enables in table.items()
    }


def closure(seeds: list[str]) -> set[str]:
    """Everything `cargo --features <seeds>` actually turns on, transitively."""
    graph = feature_graph()
    seen: set[str] = set()
    stack = list(seeds)
    while stack:
        f = stack.pop()
        if f in seen:
            continue
        seen.add(f)
        stack.extend(graph.get(f, ()))
    return seen


def legs() -> dict[str, list[str]]:
    """The full test matrix, derived. `rest` is the complement — that is what
    makes a NEW feature impossible to forget."""
    plan: dict[str, list[str]] = {"core": list(BASE)}
    for axis in AXIS_LEGS:
        plan[axis] = [*BASE, axis]
    spoken = (
        set(BASE)
        | set(AXIS_LEGS)
        | set(NOT_TESTED)
        | {f for _host, fs in RIDERS.values() for f in fs}
    )
    plan["rest"] = [*BASE, *(f for f in declared_features() if f not in spoken)]
    return plan


def test_invocations() -> dict[str, list[str]]:
    """Every feature set CI actually RUNS tests under: matrix legs + riders."""
    plan = legs()
    for name, (_host, fs) in RIDERS.items():
        plan[name] = list(fs)
    return plan


def feature_set(leg: str) -> str:
    if leg == "lint":
        return " ".join(LINT_SHIPPED)
    plan = test_invocations()
    if leg not in plan:
        raise SystemExit(
            f"unknown leg {leg!r}; known: {', '.join([*plan, 'lint'])}"
        )
    return " ".join(plan[leg])


# ── The gate ────────────────────────────────────────────────────────────────

#: The COMPILE-totality anchor. `check` fails if this leaves ci.yml, because
#: its departure is exactly the #585 hole reopening. Anchored to a `run:` line,
#: not just any line — a comment that merely MENTIONS the command must not be
#: able to satisfy the gate.
ALL_FEATURES_CLIPPY = re.compile(
    r"^\s*(?:run:\s*|- run:\s*|\s+)cargo clippy\s+--all-features\s+--all-targets"
    r"\s+--\s+-D warnings\s*$",
    re.M,
)

#: ci.yml must ASK for its feature sets, never spell them.
DERIVED_CALL = re.compile(r"ci_feature_matrix\.py set ")

#: The matrix rows, e.g. `- { name: core, leg: core, gauntlet: true }`.
MATRIX_LEG = re.compile(r"^\s*-\s*\{\s*name:\s*(\S+?)\s*,\s*leg:\s*(\S+?)\s*,", re.M)


def check() -> int:
    problems: list[str] = []
    declared = declared_features()
    plan = legs()

    # 0. The plan may only name features that exist — otherwise `set <leg>`
    #    emits a list cargo rejects, and the failure lands 10 minutes into a
    #    build instead of here.
    for label, names in (
        ("BASE", BASE),
        ("AXIS_LEGS", AXIS_LEGS),
        ("LINT_SHIPPED", LINT_SHIPPED),
        *((f"RIDERS[{n!r}]", fs) for n, (_h, fs) in RIDERS.items()),
    ):
        for f in names:
            if f not in declared:
                problems.append(
                    f"{label} names {f!r}, which is not a feature in Cargo.toml — "
                    f"`cargo --features` would reject it."
                )

    # 0b. A rider may not shadow a leg (or `lint`) — `set <name>` would then
    #     silently answer for the wrong invocation.
    for name in RIDERS:
        if name in plan or name == "lint":
            problems.append(
                f"rider {name!r} shadows a matrix leg of the same name; "
                f"`set {name}` would be ambiguous. Rename one."
            )

    # 1. No stale or unexplained holdout.
    for name, reason in NOT_TESTED.items():
        if name not in declared:
            problems.append(
                f"NOT_TESTED names {name!r}, which is not a feature in Cargo.toml — "
                f"stale entry; delete it."
            )
        if not reason.strip():
            problems.append(
                f"NOT_TESTED[{name!r}] has no reason. A feature held out of every "
                f"test leg must say why, in writing, here."
            )

    # 2. TEST coverage: enabled by some invocation, or held out on the record.
    tested = set()
    for names in test_invocations().values():
        tested |= closure(names)
    for f in declared:
        if f not in tested and f not in NOT_TESTED:
            problems.append(
                f"feature {f!r} is run by NO test invocation and is not in "
                f"NOT_TESTED. Either it belongs in a leg or a rider, or add it to "
                f"NOT_TESTED with a reason."
            )

    # 3. COMPILE coverage: the totality anchor is still in the workflow.
    ci = CI_YML.read_text()
    if not ALL_FEATURES_CLIPPY.search(ci):
        problems.append(
            "ci.yml no longer runs `cargo clippy --all-features --all-targets -- "
            "-D warnings`. That invocation is the ONLY thing that makes compile "
            "coverage total by construction; without it a new feature can go "
            "uncompiled exactly as `secrets-server` did for three releases (#585)."
        )
    if not DERIVED_CALL.search(ci):
        problems.append(
            "ci.yml no longer calls `ci_feature_matrix.py set` — it has gone back "
            "to spelling feature lists out by hand, which is the #585 defect."
        )

    # 4. The workflow's legs and this script's legs are the same legs.
    found = MATRIX_LEG.findall(ci)
    if not found:
        problems.append(
            "could not find the `linux-x86_64-test` matrix rows in ci.yml "
            "(expected `- { name: X, leg: Y, ... }`). The anchor moved: fix this "
            "script rather than deleting the check."
        )
    else:
        in_yaml = {leg for _, leg in found}
        missing = sorted(set(plan) - in_yaml)
        extra = sorted(in_yaml - set(plan))
        if missing:
            problems.append(
                f"legs defined here but absent from ci.yml's matrix: {missing}. "
                f"Their features are never tested."
            )
        if extra:
            problems.append(
                f"ci.yml's matrix names legs this script does not define: {extra}. "
                f"`set <leg>` will fail at runtime."
            )

    # 4b. Every rider is still actually invoked, and still on the leg that
    #     hosts it. A rider silently dropped from ci.yml would be a
    #     configuration that stops being tested while this gate keeps counting
    #     it as covered — the gate lying in the #585 direction.
    for name, (host, _fs) in RIDERS.items():
        if f"ci_feature_matrix.py set {name}" not in ci:
            problems.append(
                f"rider {name!r} is counted as test coverage here but ci.yml never "
                f"runs `ci_feature_matrix.py set {name}`. Either restore the step or "
                f"move {name!r} to NOT_TESTED with a reason."
            )
        elif f"matrix.substrate.leg == '{host}'" not in ci:
            problems.append(
                f"rider {name!r} is declared to ride the {host!r} leg, but ci.yml has "
                f"no step gated on that leg. Its host moved; update RIDERS."
            )

    # 5. Deployment shapes may only name features that exist.
    shapes = _deployment_shapes()
    for var in ("IOS_PYO3_FEATURES", "MOBILE_FEATURES"):
        if f"{var}:" in ci and f"ci.yml {var}" not in shapes:
            problems.append(
                f"ci.yml still declares {var} but this script could no longer parse "
                f"it — a silently-skipped check is worse than no check. Fix the "
                f"pattern in `_deployment_shapes`."
            )
    for label, names in shapes.items():
        for f in sorted(set(names) - set(declared)):
            problems.append(f"{label} names {f!r}, which is not a declared feature.")

    if problems:
        for p in problems:
            print(f"::error title=feature matrix::{p}")
            print(f"✗ {p}", file=sys.stderr)
        return 1

    print(
        f"✓ feature coverage: {len(declared)} features declared; "
        f"{len(declared) - len(NOT_TESTED)} run by a test invocation "
        f"({len(plan)} matrix legs + {len(RIDERS)} rider"
        f"{'' if len(RIDERS) == 1 else 's'}); "
        f"{len(NOT_TESTED)} compile-only with a written reason; "
        f"0 uncovered."
    )
    return 0


def _deployment_shapes() -> dict[str, list[str]]:
    """The wheel / iOS / Android feature lists. These are DEPLOYMENT shapes,
    not coverage — they say what ships, not what is checked — but a name in
    them that no longer exists is still drift worth failing on."""
    shapes: dict[str, list[str]] = {}
    ci = CI_YML.read_text()
    for var in ("IOS_PYO3_FEATURES", "MOBILE_FEATURES"):
        m = re.search(rf"{var}:\s*>-\n((?:\s{{8}}\S.*\n)+)", ci)
        if m:
            shapes[f"ci.yml {var}"] = m.group(1).split()
    with PYPROJECT.open("rb") as fh:
        shapes["pyproject [tool.maturin] features"] = tomllib.load(fh)["tool"][
            "maturin"
        ]["features"]
    return shapes


def report() -> int:
    declared = declared_features()
    plan = test_invocations()
    per_leg = {name: closure(names) for name, names in plan.items()}
    width = max(len(f) for f in declared)
    print(f"{len(declared)} features declared in Cargo.toml\n")
    for f in declared:
        where = [leg for leg, s in per_leg.items() if f in s]
        if where:
            print(f"  {f:<{width}}  test: {', '.join(where)}")
        else:
            print(f"  {f:<{width}}  compile-only — {NOT_TESTED.get(f, 'UNCOVERED')}")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "list":
        print("\n".join(declared_features()))
        return 0
    if cmd == "legs":
        print("\n".join(legs()))
        return 0
    if cmd == "set":
        if len(argv) != 3:
            raise SystemExit("usage: ci_feature_matrix.py set <leg>")
        print(feature_set(argv[2]))
        return 0
    if cmd == "report":
        return report()
    if cmd == "check":
        return check()
    raise SystemExit(f"unknown command {cmd!r}")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
