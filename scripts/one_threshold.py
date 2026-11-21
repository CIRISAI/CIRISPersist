#!/usr/bin/env python3
"""one_threshold.py: a strict majority has ONE spelling (no cargo).

    scripts/one_threshold.py check        exit 1 on a second spelling
    scripts/one_threshold.py --self-test  the gate's own witnesses

v62.0.0 (TR-fix1; Eric's rule, CC 4.2.6): an accord act counts at a strict
majority of the STANDING roster (2·yes > N, never a fixed 2 or 3):
`admission::accord_threshold(n)`, over the holders of the genesis bundle in
force (`accord_threshold_now`).

v62.0.0 (VA-genesis-fns): every strict majority in persist routes to ONE pair
of helpers in `admission.rs`: `strict_majority(n) = n / 2 + 1` (its count)
and `is_strict_majority(yes, n) = yes > n / 2` (its predicate). This covers
the accord's `accord_threshold`, a room's `majority` protocol, a
reverse-quorum floor and a two-path threshold. Each body is a one-line seam:
since VA-repin (Verify 23.3.3) it calls Verify's `edition2::strict_majority` /
`is_strict_majority`.

Red in production code (stripped by earlier_form_doors.py: comments,
literals and test-gated code blanked) outside ALLOWED:

- `x / 2 + 1`, the count;
- `2 * x > n` and `x > n / 2`, the predicate;
- a call to, or an import of, Verify's `accord_genesis::strict_majority`,
  `edition2::strict_majority` or `edition2::is_strict_majority`.

ALLOWED holds the two seams, by (file, enclosing fn). An ALLOWED entry that no
longer matches anything is red too, so the list cannot outlive its sites.

v62.0.0 (SM-fix1) — and no FIXED count stands in for it. Also red, in the
same production code (test and `test-anchor` code excepted, as above):
  - a string literal `"quorum:M/N"` with fixed numbers, plain, byte or raw
    (v22's membership builder defaulted a prior envelope with no protocol to
    `"quorum:2/3"`: a rule nobody signed; SM-fix1 refuses it). A group's
    protocol is read from its own record; a format such as
    `"quorum:{m}/{n}"` is not matched;
  - `QuorumPolicy::new(<int>, <int>)`, `ThresholdPolicy::new(<int>, <int>)`
    or `accord_threshold(<int>)`: a threshold over a fixed roster size.
"""
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import earlier_form_doors as efd  # noqa: E402

COUNT = re.compile(r"[A-Za-z_][\w.()]*\s*/\s*2\s*\+\s*1\b")
PREDICATE = re.compile(
    r"\b2\s*\*\s*[A-Za-z_][\w.()]*\s*>(?!=)\s*[A-Za-z_]"
    r"|[A-Za-z_][\w.()]*\s*>\s*[A-Za-z_][\w.()]*\s*/\s*2\b(?!\s*\+)"
)
# a call or an import (`use ...::accord_genesis::strict_majority;`)
VERIFY_CALL = re.compile(
    r"\b(?:accord_genesis|edition2)\s*::\s*(?:\{[^}]*\b)?(?:is_)?strict_majority\b"
)

# (file, enclosing fn): why
ALLOWED = {
    ("src/federation/admission.rs", "strict_majority"):
        "THE count (the seam to Verify's edition2::strict_majority)",
    ("src/federation/admission.rs", "is_strict_majority"):
        "THE predicate (the seam to Verify's edition2::is_strict_majority)",
}


def enclosing_fn(code: str, at: int) -> str:
    best = None
    for m in efd.FN_RE.finditer(code, 0, at):
        body = efd.block_body(code, m.end())
        if body and body[0] <= at <= body[1]:
            best = m.group(1)
    return best or "<top>"


# v62.0.0 (SM-fix1) — a fixed count in production code.
FIXED_LITERAL = re.compile(r'^(?:b|b?r#*)?"quorum:\d+/\d+"#*$')
FIXED_CALL = re.compile(
    r"\b(?:(?:QuorumPolicy|ThresholdPolicy)::new\(\s*\d+\s*,\s*\d+\s*\)"
    r"|accord_threshold\(\s*\d+\s*\))"
)


def literal_spans(text: str) -> list[tuple[int, int]]:
    """(start, end) of every string literal (plain, byte, raw), skipping
    comments: the same token walk as earlier_form_doors.strip."""
    spans: list[tuple[int, int]] = []
    n, i = len(text), 0
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j == -1 else j
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            i = j
        elif c in "rb" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")) \
                and (raw := efd._raw_start(text, i)) is not None:
            hashes, j = raw
            close = '"' + "#" * hashes
            e = text.find(close, j)
            e = n if e == -1 else e + len(close)
            spans.append((i, e))
            i = e
        elif c == '"' or (c == "b" and text.startswith('b"', i)
                          and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_"))):
            j = i + (2 if c == "b" else 1)
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            spans.append((i, j + 1))
            i = j + 1
        elif c == "'":
            j = efd._char_end(text, i)
            i = max(j, i + 1)
        elif c.isalnum() or c == "_":
            while i < n and (text[i].isalnum() or text[i] == "_"):
                i += 1
        else:
            i += 1
    return spans


def scan_fixed(base: Path, tree) -> list[str]:
    """v62.0.0 (SM-fix1) — the fixed counts in production code."""
    red: list[str] = []
    for rel in tree.glob("src/**/*.rs"):
        code = tree.code(rel) or ""
        for m in FIXED_CALL.finditer(code):
            line = code.count("\n", 0, m.start()) + 1
            red.append(f"{rel}:{line}: a fixed threshold `{m.group(0)}`; count the standing "
                       f"roster with admission::accord_threshold(n) or the group's own protocol")
        if tree.is_test_file(rel):
            continue
        raw = (base / rel).read_text(encoding="utf-8", errors="replace")
        spans = [(a, b) for a, b in literal_spans(raw) if FIXED_LITERAL.match(raw[a:b])]
        if not spans:
            continue
        # A literal is production iff it survives the test stripper.
        marked = list(efd.strip(raw))
        for a, b in spans:
            for k in range(a, b):
                if marked[k] != "\n":
                    marked[k] = "L"
        kept, _ = efd.strip_tests("".join(marked), rel, raw)
        for a, b in spans:
            if kept[a] == "L":
                line = raw.count("\n", 0, a) + 1
                red.append(f"{rel}:{line}: a fixed `{raw[a:b]}` protocol literal in production "
                           f"code; read the group's own consensus_protocol (or refuse)")
    return red


def scan(base: Path) -> list[str]:
    # test-anchor code (never in a wheel) is test code, as the LONE scan reads it
    tree = efd.Tree(base, anchored=True)
    red: list[str] = []
    used: set[tuple[str, str]] = set()
    for rel in tree.glob("src/**/*.rs"):
        code = tree.code(rel) or ""
        hits = []
        for m in COUNT.finditer(code):
            # `bytes * 3 / 2 + 1`-style growth factors are not a majority.
            head = code[max(0, m.start() - 12):m.start() + len(m.group(0).split("/")[0])]
            if re.search(r"\*\s*\d+\s*\)?\s*$", head):
                continue
            hits.append((m, "a second spelling of a strict-majority count"))
        for m in PREDICATE.finditer(code):
            hits.append((m, "a second spelling of a strict-majority test"))
        for m in VERIFY_CALL.finditer(code):
            hits.append((m, "a direct call to Verify's strict majority"))
        for m, what in hits:
            fn = enclosing_fn(code, m.start())
            key = (rel, fn)
            if key in ALLOWED:
                used.add(key)
                continue
            line = code.count("\n", 0, m.start()) + 1
            red.append(f"{rel}:{line} ({fn}): {what} `{m.group(0).strip()}`; call "
                       f"admission::strict_majority / is_strict_majority (or accord_threshold)")
    for key in sorted(set(ALLOWED) - used):
        red.append(f"{key[0]} ({key[1]}): an ALLOWED entry no longer matches a site; delete it")
    red.extend(scan_fixed(base, tree))
    return red


SEAMS = ("pub const fn strict_majority(n: usize) -> usize { n / 2 + 1 }\n"
         "pub const fn is_strict_majority(y: usize, n: usize) -> bool { y > n / 2 }\n"
         "pub const fn accord_threshold(n: usize) -> usize { strict_majority(n) }\n")
SEAMS_AT_REPIN = ("pub const fn strict_majority(n: usize) -> usize { ciris_verify_core::edition2::strict_majority(n) }\n"
                  "pub const fn is_strict_majority(y: usize, n: usize) -> bool { ciris_verify_core::edition2::is_strict_majority(y, n) }\n")


def tree(extra: dict[str, str], admission: str = SEAMS) -> dict[str, str]:
    files = {"src/lib.rs": "pub mod federation;\n",
             "src/federation/mod.rs": "pub mod admission;\npub mod other;\n",
             "src/federation/admission.rs": admission,
             "src/federation/other.rs": "\n"}
    files.update(extra)
    return files


def self_test() -> int:
    cases = [
        ("the two seams pass", tree({}), 0),
        ("the seams at the re-pin pass", tree({}, SEAMS_AT_REPIN), 0),
        ("a second count is red",
         tree({"src/federation/other.rs": "pub const fn required_count(h: usize) -> usize { h / 2 + 1 }\n"}), 1),
        ("a second predicate (2 * x > n) is red",
         tree({"src/federation/other.rs": "fn ok(v: usize, n: usize) -> bool { 2 * v > n }\n"}), 1),
        ("a second predicate (x > n / 2) is red",
         tree({"src/federation/other.rs": "fn ok(v: usize, n: usize) -> bool { v > n / 2 }\n"}), 1),
        ("a direct Verify call is red",
         tree({"src/federation/other.rs": "fn m(n: usize) -> usize { ciris_verify_core::accord_genesis::strict_majority(n) }\n"}), 1),
        ("an import of Verify's helper is red",
         tree({"src/federation/other.rs": "use ciris_verify_core::accord_genesis::strict_majority;\n"}), 1),
        ("a grouped import of Verify's helper is red",
         tree({"src/federation/other.rs": "use ciris_verify_core::edition2::{is_strict_majority, Digest32};\n"}), 1),
        ("a growth factor is not a majority",
         tree({"src/federation/other.rs": "fn g(b: usize) -> usize { (b * 3) / 2 + 1 }\n"}), 0),
        ("comments, literals and tests are not production",
         tree({"src/federation/other.rs": "// x / 2 + 1\nconst S: &str = \"2 * v > n\";\n#[cfg(test)]\nmod t { fn f(n: usize) -> usize { n / 2 + 1 } }\n"}), 0),
        # v62.0.0 (SM-fix1) — fixed counts.
        ("a fixed quorum literal default in production is red",
         tree({"src/federation/other.rs": "const P: &str = \"quorum:2/3\";\nfn f(e: &V) -> &str { e.get(\"cp\").unwrap_or(P) }\n"}), 1),
        ("a byte or raw fixed literal is red too",
         tree({"src/federation/other.rs": "const P: &[u8] = b\"quorum:2/3\";\nconst Q: &str = r\"quorum:3/5\";\n"}), 2),
        ("a fixed literal in a comment, a format, a test or test-anchor code is not",
         tree({"src/federation/other.rs": "// \"quorum:2/3\"\nfn f(m: usize, n: usize) -> String { format!(\"quorum:{m}/{n}\") }\n#[cfg(test)]\nmod t { const P: &str = \"quorum:2/3\"; }\n#[cfg(feature = \"test-anchor\")]\npub fn seed() -> &'static str { \"quorum:2/3\" }\n"}), 0),
        ("a fixed threshold call is red; one over n is not",
         tree({"src/federation/other.rs": "fn g() -> usize { accord_threshold(3) }\nfn h() -> Q { QuorumPolicy::new(2, 3) }\nfn k(n: usize) -> usize { accord_threshold(n) }\n"}), 2),
        ("a stale ALLOWED entry is red",
         tree({}, "pub const fn strict_majority(n: usize) -> usize { n / 2 + 1 }\n"), 1),
    ]
    bad = 0
    for name, files, want in cases:
        with tempfile.TemporaryDirectory() as d:
            for rel, text in files.items():
                p = Path(d) / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text)
            got = len(scan(Path(d)))
            ok = got == want
            bad += not ok
            print(("ok  " if ok else "FAIL"), name, f"(reds {got}, want {want})")
    print(f"self-test: {len(cases) - bad}/{len(cases)}")
    return 1 if bad else 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    if sys.argv[1:] != ["check"]:
        print(__doc__)
        return 2
    red = scan(Path(__file__).resolve().parent.parent)
    for r in red:
        print("RED", r)
    print("GREEN" if not red else f"RED: {len(red)}")
    return 1 if red else 0


if __name__ == "__main__":
    sys.exit(main())
