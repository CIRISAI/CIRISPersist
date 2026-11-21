#!/usr/bin/env python3
"""one_threshold.py: the holders' strict majority has ONE spelling (no cargo).

    scripts/one_threshold.py check        exit 1 on a second spelling
    scripts/one_threshold.py --self-test  the gate's own witnesses

v62.0.0 (TR-fix1; Eric's rule, CC 4.2.6): an accord act counts at a strict
majority of the STANDING roster (2·yes > N, never a fixed 2 or 3). That count
is `admission::accord_threshold(n) = n / 2 + 1`, over the holders of the
genesis bundle in force (`accord_threshold_now`). A second function that
spells `x / 2 + 1` is how the copies drifted before (trust_root_group's
`holders_required`, transport_rebind's `required_count`).

The scan reads production code only. It uses earlier_form_doors.py's
stripper, so comments, literals and test-gated code are blanked. It fails on
any `<expr> / 2 + 1` outside ALLOWED. ALLOWED holds the ONE spelling and the
majorities of OTHER rosters (a room's `majority` protocol is the group's own
count, not the holders'), each by (file, enclosing fn). An ALLOWED entry that
no longer matches is red too, so the list cannot outlive its sites.

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
import os
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import earlier_form_doors as efd  # noqa: E402

PATTERN = re.compile(r"[A-Za-z_][\w.()]*\s*/\s*2\s*\+\s*1\b")

# (file, enclosing fn): why
ALLOWED = {
    ("src/federation/admission.rs", "accord_threshold"):
        "THE spelling of the holders' strict majority",
    ("src/federation/consensus.rs", "evaluate_counted"):
        "a room's `majority` / unanimous-removal protocol (the group's own roster)",
    ("src/federation/consensus.rs", "required_signatures_at"):
        "a room's `majority` protocol (the group's own roster)",
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
        for m in PATTERN.finditer(code):
            # `bytes * 3 / 2 + 1`-style growth factors are not a majority.
            if re.search(r"\*\s*\d+\s*\)?\s*$", code[max(0, m.start() - 12):m.start() + len(m.group(0).split("/")[0])]):
                continue
            fn = enclosing_fn(code, m.start())
            key = (rel, fn)
            line = code.count("\n", 0, m.start()) + 1
            if key in ALLOWED:
                used.add(key)
                continue
            red.append(f"{rel}:{line} ({fn}): a second spelling of a strict majority "
                       f"`{m.group(0)}`; call admission::accord_threshold, or list a "
                       f"non-holder roster in ALLOWED with why")
    for key in sorted(set(ALLOWED) - used):
        red.append(f"{key[0]} ({key[1]}): an ALLOWED entry no longer matches a site; delete it")
    red.extend(scan_fixed(base, tree))
    return red


def self_test() -> int:
    cases = [
        ("the one spelling passes",
         {"src/lib.rs": "pub mod federation;\n",
          "src/federation/mod.rs": "pub mod admission;\npub mod consensus;\n",
          "src/federation/admission.rs": "pub const fn accord_threshold(n: usize) -> usize { n / 2 + 1 }\n",
          "src/federation/consensus.rs": "fn evaluate_counted(n: usize) -> usize { n / 2 + 1 }\nfn required_signatures_at(n: usize) -> usize { n / 2 + 1 }\n"},
         0),
        ("a second holders' spelling is red",
         {"src/lib.rs": "pub mod federation;\n",
          "src/federation/mod.rs": "pub mod admission;\npub mod consensus;\npub mod edition2;\n",
          "src/federation/admission.rs": "pub const fn accord_threshold(n: usize) -> usize { n / 2 + 1 }\n",
          "src/federation/consensus.rs": "fn evaluate_counted(n: usize) -> usize { n / 2 + 1 }\nfn required_signatures_at(n: usize) -> usize { n / 2 + 1 }\n",
          "src/federation/edition2.rs": "pub const fn required_count(holders: usize) -> usize { holders / 2 + 1 }\n"},
         1),
        ("a spelling in a comment, a literal or a test is not production",
         {"src/lib.rs": "pub mod federation;\n",
          "src/federation/mod.rs": "pub mod admission;\npub mod consensus;\n",
          "src/federation/admission.rs": "pub const fn accord_threshold(n: usize) -> usize { n / 2 + 1 }\n// x / 2 + 1\nconst S: &str = \"n / 2 + 1\";\n#[cfg(test)]\nmod t { fn f(n: usize) -> usize { n / 2 + 1 } }\n",
          "src/federation/consensus.rs": "fn evaluate_counted(n: usize) -> usize { n / 2 + 1 }\nfn required_signatures_at(n: usize) -> usize { n / 2 + 1 }\n"},
         0),
        # v62.0.0 (SM-fix1) — fixed counts.
        ("a fixed quorum literal default in production is red",
         {"src/lib.rs": "pub mod federation;\n",
          "src/federation/mod.rs": "pub mod admission;\npub mod consensus;\npub mod gmc;\n",
          "src/federation/admission.rs": "pub const fn accord_threshold(n: usize) -> usize { n / 2 + 1 }\n",
          "src/federation/consensus.rs": "fn evaluate_counted(n: usize) -> usize { n / 2 + 1 }\nfn required_signatures_at(n: usize) -> usize { n / 2 + 1 }\n",
          "src/federation/gmc.rs": "const P: &str = \"quorum:2/3\";\nfn f(e: &V) -> &str { e.get(\"cp\").unwrap_or(P) }\n"},
         1),
        ("a byte or raw fixed literal is red too",
         {"src/lib.rs": "pub mod federation;\n",
          "src/federation/mod.rs": "pub mod admission;\npub mod consensus;\npub mod gmc;\n",
          "src/federation/admission.rs": "pub const fn accord_threshold(n: usize) -> usize { n / 2 + 1 }\n",
          "src/federation/consensus.rs": "fn evaluate_counted(n: usize) -> usize { n / 2 + 1 }\nfn required_signatures_at(n: usize) -> usize { n / 2 + 1 }\n",
          "src/federation/gmc.rs": "const P: &[u8] = b\"quorum:2/3\";\nconst Q: &str = r\"quorum:3/5\";\n"},
         2),
        ("a fixed literal in a comment, a format, a test or test-anchor code is not",
         {"src/lib.rs": "pub mod federation;\n",
          "src/federation/mod.rs": "pub mod admission;\npub mod consensus;\n",
          "src/federation/admission.rs": "pub const fn accord_threshold(n: usize) -> usize { n / 2 + 1 }\n// \"quorum:2/3\"\nfn f(m: usize, n: usize) -> String { format!(\"quorum:{m}/{n}\") }\n#[cfg(test)]\nmod t { const P: &str = \"quorum:2/3\"; }\n#[cfg(feature = \"test-anchor\")]\npub fn seed() -> &'static str { \"quorum:2/3\" }\n",
          "src/federation/consensus.rs": "fn evaluate_counted(n: usize) -> usize { n / 2 + 1 }\nfn required_signatures_at(n: usize) -> usize { n / 2 + 1 }\n"},
         0),
        ("a fixed threshold call is red; one over n is not",
         {"src/lib.rs": "pub mod federation;\n",
          "src/federation/mod.rs": "pub mod admission;\npub mod consensus;\n",
          "src/federation/admission.rs": "pub const fn accord_threshold(n: usize) -> usize { n / 2 + 1 }\nfn g() -> usize { accord_threshold(3) }\nfn h() -> Q { QuorumPolicy::new(2, 3) }\nfn k(n: usize) -> usize { accord_threshold(n) }\n",
          "src/federation/consensus.rs": "fn evaluate_counted(n: usize) -> usize { n / 2 + 1 }\nfn required_signatures_at(n: usize) -> usize { n / 2 + 1 }\n"},
         2),
        ("a stale ALLOWED entry is red",
         {"src/lib.rs": "pub mod federation;\n",
          "src/federation/mod.rs": "pub mod admission;\npub mod consensus;\n",
          "src/federation/admission.rs": "pub const fn accord_threshold(n: usize) -> usize { n / 2 + 1 }\n",
          "src/federation/consensus.rs": "fn evaluate_counted(n: usize) -> usize { n / 2 + 1 }\n"},
         1),
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
