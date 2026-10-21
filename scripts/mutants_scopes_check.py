#!/usr/bin/env python3
"""mutants_scopes_check.py — every mutation scope still means something
(CIRISPersist v60.0.0, docs/V60_TASK_PLAN.md §3, docs/MUTATION_TESTING.md
"Per-slice scopes").

    scripts/mutants_scopes_check.py              check scripts/mutants/ from disk
    scripts/mutants_scopes_check.py --self-test  the checker's own witnesses

From v60 every slice ships its mutation set as `scripts/mutants/scope-*.txt`,
and the nightly matrix runs them. A scope rots silently: a function it names
is renamed (resolution fails at 2 a.m., not at review), its `tests:` filter
stops naming any test (every mutant "missed", or worse, the filter is a typo
nextest reads as "no tests" and the baseline passes in 0 s), or the
allow-list grows a line nobody owns. This checks, without cargo:

1. every scope RESOLVES: `mutants_matrix.py resolve cargo-mutants <scope>
   <tmp.diff>` exits 0 (each file exists; each named function defines
   exactly one `fn` in it) and the diff is non-empty;
2. every `tests:` filter is non-empty and WELL-FORMED: a nextest filterset
   built from the predicates this repo uses (`test`, `package`, `binary`,
   `binary_id`, `kind`, `deps`, `rdeps`, `platform`, `all`, `none`,
   `default`) joined by `|`, `+`, `or`, `&`, `and`, `-`, `not`, `!` and
   parentheses, each `/regex/` compiling; and each `test(...)` predicate
   MATCHES at least one `fn` or `mod` name under src/ or tests/ (a test's
   full name is its module path and its fn, so a filter that matches no
   identifier on disk matches no test);
3. every name on a scope's `features:` line is a feature in Cargo.toml;
4. every line of `allowed_survivors.txt` parses and carries `#<issue>`.

Exit 0 when all hold, 1 with `<file>: <reason>` lines otherwise, 2 on usage.
Stdlib only.
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCOPES = REPO / "scripts" / "mutants"
ALLOW = SCOPES / "allowed_survivors.txt"
MATRIX = REPO / "scripts" / "mutants_matrix.py"

#: nextest filterset predicates (nextest 0.9 grammar).
PREDICATES = {"test", "package", "binary", "binary_id", "kind", "deps", "rdeps",
              "platform", "all", "none", "default"}
#: Predicates that take no argument.
NULLARY = {"all", "none", "default"}
#: `#<issue>` on an allow-list line (mutants_matrix.ALLOW_LINE's own shape).
ALLOW_LINE = re.compile(r"^(?P<file>[^\s:]+\.rs)(?::(?P<line>\d+))?\s+(?P<desc>.+?)\s+#(?P<issue>\d+)\b(?P<why>.*)$")
IDENT = re.compile(r"\b(?:fn|mod)\s+(r#)?([A-Za-z_][A-Za-z0-9_]*)")


class FilterError(Exception):
    pass


# ── the filterset grammar ───────────────────────────────────────────────────


def _tokens(text: str) -> list[tuple[str, str]]:
    """(kind, value): op, name, lparen, rparen, matcher (raw text inside a
    predicate's parentheses)."""
    out, i = [], 0
    while i < len(text):
        c = text[i]
        if c.isspace():
            i += 1
        elif c in "|&+-!":
            out.append(("op", c)); i += 1
        elif c == "(":
            out.append(("lparen", c)); i += 1
        elif c == ")":
            out.append(("rparen", c)); i += 1
        elif c.isalpha() or c == "_":
            j = i
            while j < len(text) and (text[j].isalnum() or text[j] == "_"):
                j += 1
            word = text[i:j]
            k = j
            while k < len(text) and text[k].isspace():
                k += 1
            if word in ("or", "and", "not"):
                out.append(("op", word)); i = j
            elif k < len(text) and text[k] == "(":
                # A predicate: read its argument up to the matching `)`,
                # honouring a /regex/ that contains parentheses.
                m, depth, in_re = k + 1, 0, False
                while m < len(text):
                    ch = text[m]
                    if ch == "\\" and in_re:
                        m += 2; continue
                    if ch == "/" and (in_re or not text[k + 1:m].strip()):
                        in_re = not in_re
                    elif not in_re and ch == "(":
                        depth += 1
                    elif not in_re and ch == ")":
                        if depth == 0:
                            break
                        depth -= 1
                    m += 1
                if m >= len(text):
                    raise FilterError(f"unclosed `{word}(`")
                out.append(("pred", word))
                out.append(("matcher", text[k + 1:m].strip()))
                i = m + 1
            else:
                raise FilterError(f"bare word {word!r} (a predicate needs parentheses)")
        else:
            raise FilterError(f"unexpected {c!r} at {i}")
    return out


def _matcher(pred: str, raw: str) -> tuple[str, str]:
    """(kind, value) of a predicate's matcher: regex, exact, contains, glob."""
    if pred in NULLARY:
        if raw:
            raise FilterError(f"{pred}() takes no argument")
        return ("none", "")
    if not raw:
        raise FilterError(f"{pred}() needs a matcher")
    if raw.startswith("/"):
        if len(raw) < 3 or not raw.endswith("/"):
            raise FilterError(f"{pred}({raw}): an unterminated or empty /regex/")
        body = raw[1:-1]
        try:
            re.compile(body)
        except re.error as e:
            raise FilterError(f"{pred}({raw}): the regex does not compile: {e}") from None
        return ("regex", body)
    if raw[0] in "=~#":
        if len(raw) == 1:
            raise FilterError(f"{pred}({raw}): an empty matcher")
        return ({"=": "exact", "~": "contains", "#": "glob"}[raw[0]], raw[1:])
    return ("contains", raw)


def parse_filter(text: str) -> list[tuple[str, str, str]]:
    """Parse a filterset; return its (predicate, matcher kind, value) leaves.
    Raises FilterError on anything nextest would refuse."""
    toks = _tokens(text)
    leaves: list[tuple[str, str, str]] = []
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else (None, None)

    def expr():
        nonlocal pos
        term()
        while peek()[0] == "op" and peek()[1] in ("|", "+", "or", "&", "and", "-"):
            pos += 1
            term()

    def term():
        nonlocal pos
        kind, val = peek()
        if kind == "op" and val in ("not", "!"):
            pos += 1
            term()
        elif kind == "lparen":
            pos += 1
            expr()
            if peek()[0] != "rparen":
                raise FilterError("unbalanced parentheses")
            pos += 1
        elif kind == "pred":
            if val not in PREDICATES:
                raise FilterError(f"unknown predicate {val}()")
            pos += 1
            m_kind, m_val = _matcher(val, toks[pos][1])
            pos += 1
            leaves.append((val, m_kind, m_val))
        else:
            raise FilterError(f"expected a predicate, got {val!r}")

    if not toks:
        raise FilterError("empty filterset")
    expr()
    if pos != len(toks):
        raise FilterError(f"trailing {toks[pos][1]!r}")
    return leaves


def _glob(pat: str) -> re.Pattern:
    return re.compile("^" + re.escape(pat).replace(r"\*", ".*").replace(r"\?", ".") + "$")


def leaf_matches(kind: str, value: str, idents: set[str]) -> bool:
    """Does a `test(...)` leaf match any identifier on disk? A test's name is
    `mod::path::fn`, so a leaf is read by its LAST path segment (for a
    regex, when that segment compiles on its own; otherwise the whole regex
    is tried per identifier). A leaf matching no `fn`/`mod` name on disk
    matches no test."""
    last = value.rsplit("::", 1)[-1]
    if kind == "regex":
        try:
            r = re.compile(last if "::" in value else value)
        except re.error:
            r = re.compile(value)
        return any(r.search(i) for i in idents)
    if kind == "contains":
        return any(last in i for i in idents)
    if kind == "exact":
        return last in idents
    if kind == "glob":
        g = _glob(last)
        return any(g.match(i) for i in idents)
    return True


def disk_identifiers() -> set[str]:
    out: set[str] = set()
    for root in (REPO / "src", REPO / "tests"):
        for p in root.rglob("*.rs"):
            out.update(m[1] for m in IDENT.findall(p.read_text(encoding="utf-8", errors="replace")))
    # `mod name;` file modules and the macro-generated backend modules.
    out.update({"memory", "sqlite", "postgres", "tests"})
    return out


# ── the checks ──────────────────────────────────────────────────────────────


def tests_line(scope: Path) -> str | None:
    """The scope's `tests:` value as mutants_matrix.parse_scope reads it
    (text after `#` is a comment, so a `#glob` matcher cannot be written)."""
    for raw in scope.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.startswith("tests:"):
            return line[len("tests:"):].strip()
    return None


def _rel(p: Path) -> Path:
    return p.relative_to(REPO) if p.is_relative_to(REPO) else p


def cargo_features() -> set[str]:
    text = (REPO / "Cargo.toml").read_text(encoding="utf-8")
    m = re.search(r"^\[features\]\s*$(.*?)^\[", text, re.MULTILINE | re.DOTALL)
    return set(re.findall(r"^([A-Za-z0-9_-]+)\s*=", m[1], re.MULTILINE)) if m else set()


def features_line(scope: Path) -> list[str]:
    for raw in scope.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.startswith("features:"):
            return line[len("features:"):].replace(",", " ").split()
    return []


def check_scope(scope: Path, idents: set[str]) -> list[str]:
    errs = []
    rel = _rel(scope)
    known = cargo_features()
    for f in features_line(scope):
        if f not in known:
            errs.append(f"{rel}: `features:` names {f!r}, which Cargo.toml does not define")
    with tempfile.TemporaryDirectory() as tmp:
        diff = Path(tmp) / "scope.diff"
        r = subprocess.run([sys.executable, str(MATRIX), "resolve", "cargo-mutants", str(scope), str(diff)],
                           capture_output=True, text=True, cwd=REPO)
        if r.returncode != 0:
            errs.append(f"{rel}: does not resolve: {(r.stderr or r.stdout).strip().splitlines()[-1:]}")
        elif not diff.is_file() or not diff.read_text().strip():
            errs.append(f"{rel}: resolves to an empty diff (every named line is test-only or absent)")
    t = tests_line(scope)
    if t is None or not t:
        errs.append(f"{rel}: no `tests:` filter, or an empty one")
        return errs
    try:
        leaves = parse_filter(t)
    except FilterError as e:
        errs.append(f"{rel}: `tests: {t}` is not a well-formed filterset: {e}")
        return errs
    tests = [(k, v) for p, k, v in leaves if p == "test"]
    if not tests:
        errs.append(f"{rel}: `tests: {t}` has no test(...) predicate: it does not name the witnesses")
    for k, v in tests:
        if not leaf_matches(k, v, idents):
            errs.append(f"{rel}: `tests:` leaf test({v}) matches no fn or mod name under src/ or tests/")
    return errs


def check_allow(path: Path) -> list[str]:
    errs = []
    if not path.is_file():
        return [f"{path}: missing"]
    for n, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not ALLOW_LINE.match(line):
            errs.append(f"{_rel(path)}:{n}: carries no `#<issue>` (or does not parse): {raw!r}")
    return errs


def run(scopes: list[Path], allow: Path) -> list[str]:
    idents = disk_identifiers()
    errs = []
    if not scopes:
        errs.append(f"{SCOPES.relative_to(REPO)}: no scope-*.txt at all")
    for s in scopes:
        errs += check_scope(s, idents)
    errs += check_allow(allow)
    return errs


# ── self-test ───────────────────────────────────────────────────────────────


def self_test() -> int:
    """The checker fails on each thing it claims to check (a check that
    cannot fail is a report)."""
    bad = 0

    def expect(cond: bool, what: str):
        nonlocal bad
        if not cond:
            bad += 1
            print(f"SELF-TEST FAIL: {what}")

    ok = ["test(/i549|i550|i69[0-9]/)", "test(=a::b) | test(~c)",
          "not test(/x/) & package(ciris-persist)", "(test(/a(b)c/) + kind(lib)) - test(=z)", "all()"]
    for f in ok:
        try:
            parse_filter(f)
        except FilterError as e:
            expect(False, f"{f!r} should parse: {e}")
    for f in ["", "test(/i549", "test(/[/)", "tset(/x/)", "test()", "test(/x/) |", "(test(/x/)",
              "test /x/", "all(x)", "test(/x/) test(/y/)"]:
        try:
            parse_filter(f)
            expect(False, f"{f!r} should be refused")
        except FilterError:
            pass
    idents = {"i1163_metrics_unit", "observe", "tests", "sqlite"}
    expect(leaf_matches("regex", "i116[34]_", idents), "a regex leaf that matches")
    expect(not leaf_matches("regex", "i9999", idents), "a regex leaf that matches nothing")
    expect(not leaf_matches("exact", "observe::tests::nope", idents), "an exact leaf that matches nothing")

    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        good = d / "scope-good.txt"
        good.write_text("tests: test(/i1163_/)\nsrc/observe/catalog.rs\n")
        nofile = d / "scope-nofile.txt"
        nofile.write_text("tests: test(/i1163_/)\nsrc/observe/no_such_file.rs\n")
        nofn = d / "scope-nofn.txt"
        nofn.write_text("tests: test(/i1163_/)\nsrc/observe/catalog.rs no_such_fn\n")
        badf = d / "scope-badfilter.txt"
        badf.write_text("tests: test(/i1163_\nsrc/observe/catalog.rs\n")
        nomatch = d / "scope-nomatch.txt"
        nomatch.write_text("tests: test(/i99999_never/)\nsrc/observe/catalog.rs\n")
        badfeat = d / "scope-badfeat.txt"
        badfeat.write_text("tests: test(/i1163_/)\nfeatures: sqlite,no-such-feature\nsrc/observe/catalog.rs\n")
        expect(bool(check_scope(badfeat, disk_identifiers())), "an unknown feature is refused")
        allow_bad = d / "allow.txt"
        allow_bad.write_text("# comment\nsrc/observe/mod.rs:1 replace > with >= in f\n")
        allow_ok = d / "allow_ok.txt"
        allow_ok.write_text("src/observe/mod.rs:1 replace > with >= in f #1112 why\n")
        disk = disk_identifiers()
        expect(check_scope(good, disk) == [], f"a good scope passes: {check_scope(good, disk)}")
        for s, what in [(nofile, "a missing file"), (nofn, "a missing fn"), (badf, "a malformed filter"),
                        (nomatch, "a filter matching no test")]:
            expect(bool(check_scope(s, disk)), f"{what} is refused")
        expect(any("no `#<issue>`" in e for e in check_allow(allow_bad)),
               "an allow-list line without #<issue> is refused")
        expect(check_allow(allow_ok) == [], "an allow-list line with #<issue> passes")
    print("mutants_scopes_check self-test:", "OK" if not bad else f"{bad} FAILED")
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    if argv[1:] == ["--self-test"]:
        return self_test()
    if argv[1:]:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    scopes = sorted(SCOPES.glob("scope-*.txt"))
    errs = run(scopes, ALLOW)
    for e in errs:
        print(e)
    print(f"mutants_scopes_check: {len(scopes)} scope(s), {'FAIL' if errs else 'OK'}"
          + (f" ({len(errs)} problem(s))" if errs else ""))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
