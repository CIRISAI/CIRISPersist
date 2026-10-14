#!/usr/bin/env python3
"""evidence_pointers.py — every evidence pointer must name a DEFINITION that
exists in src/ (CIRISPersist#934, #1076 slice T, item 0).

    scripts/evidence_pointers.py check [--ref <git-ref>]
        every src/ row of evidence/cc_impl.tsv; exit 1 on any miss
    scripts/evidence_pointers.py register <claims.tsv> [--ref <git-ref>]
        every `impl:CIRISPersist/src/...#sym[,sym]` pointer in a
        CIRISConstitution register (constitution/claims.tsv), resolved
        against THIS tree; exit 1 on any miss

`--ref` reads the files (src/, and for `check` the tsv too) at a git ref
instead of the working tree.

A GATE. A pointer whose symbol is gone is a false evidence claim: the
Constitution's register says "established" and cites code that is not
there. After v54 -> v55 the Constitution's re-pin found two such pointers
by hand (CIRISConstitution fca367d), and nothing in this repo caught them.
One of them, `blobs.rs#holds_bytes_attestation_envelope`, survived because
the in-crate witness `evidence_cc_impl_pointers_resolve` accepts a line
containing `<name>,` or `<name>(`, and the deleted function's name still
sat in a string literal in a test list and in a doc comment.

THE PREDICATE. Comments (line, block, nested, doc) and string, byte-string,
raw-string and char literals are blanked first. Then a symbol resolves in
the cited FILE (not anywhere in src/: a moved symbol fails until its row is
repointed) when it is defined there:

  bare `name`     `fn|struct|enum|trait|type|const|static|mod|union name`,
                  `macro_rules! name`, a variant of an enum in the file, or
                  a named field of a struct in the file
  `Owner::member` `member` is defined INSIDE a block whose owner is `Owner`:
                  `enum/struct/union/trait/mod Owner { .. }` or
                  `impl .. Owner<..> { .. }` / `impl Trait for Owner { .. }`
                  (an fn/const/type/static item, a variant, or a field).
                  Longer paths use their last two segments.

A call site, a `use`, a match arm, a mention in a comment or a string never
resolves. Exit 0 all resolve, 1 any miss or a malformed row, 2 usage.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

TSV = "evidence/cc_impl.tsv"
ITEM_KW = r"(?:fn|struct|enum|trait|type|const|static|mod|union)"
# A lookahead, so the scan overlaps: in `const fn name` the `const` match
# must not consume the `fn` whose name is the definition.
ITEM_DEF = rf"(?=\b{ITEM_KW}\s+([A-Za-z_]\w*))"


def root() -> Path:
    # EVIDENCE_POINTERS_ROOT: a fixture tree for scripts/evidence_pointers_test.py.
    return Path(os.environ.get("EVIDENCE_POINTERS_ROOT") or Path(__file__).resolve().parent.parent)


# ── stripping ────────────────────────────────────────────────────────────
def strip(text: str) -> str:
    """The source with every comment and literal blanked (newlines kept), so
    nothing that is not code can look like a definition."""
    out = list(text)
    n, i = len(text), 0

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j == -1 else j
            blank(i, j); i = j
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1; j += 2
                elif text.startswith("*/", j):
                    depth -= 1; j += 2
                else:
                    j += 1
            blank(i, j); i = j
        elif c in "rb" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")) \
                and (raw := _raw_start(text, i)) is not None:
            hashes, j = raw
            close = '"' + "#" * hashes
            e = text.find(close, j)
            e = n if e == -1 else e + len(close)
            blank(i, e); i = e
        elif c == '"' or (c == "b" and text.startswith('b"', i)
                          and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_"))):
            j = i + (2 if c == "b" else 1)
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            blank(i, j + 1); i = j + 1
        elif c == "'":
            j = _char_end(text, i)
            if j > i + 1:
                blank(i, j)
            i = max(j, i + 1)
        elif c.isalnum() or c == "_":
            while i < n and (text[i].isalnum() or text[i] == "_"):
                i += 1
        else:
            i += 1
    return "".join(out)


def _raw_start(text: str, i: int):
    """(hashes, index after the opening quote) if r"…", r#"…"#, br#"…"# starts at i."""
    j = i + 2 if text.startswith("br", i) else i + 1 if text[i] == "r" else None
    if j is None:
        return None
    k = j
    while k < len(text) and text[k] == "#":
        k += 1
    return (k - j, k + 1) if k < len(text) and text[k] == '"' else None


def _char_end(text: str, i: int) -> int:
    """At a `'`: the index after a char literal, or i+1 for a lifetime/label."""
    if text.startswith("'\\", i):
        e = text.find("'", i + 2)
        return e + 1 if e != -1 else i + 1
    if i + 2 < len(text) and text[i + 2] == "'" and text[i + 1] != "\n":
        return i + 3
    return i + 1


# ── definitions ──────────────────────────────────────────────────────────
def _brace_pairs(s: str) -> dict[int, int]:
    """Every `{` index -> its matching `}` index, in one pass."""
    pairs, stack = {}, []
    for k, ch in enumerate(s):
        if ch == "{":
            stack.append(k)
        elif ch == "}" and stack:
            pairs[stack.pop()] = k
    return pairs


def _top_level(body: str) -> str:
    """`body` with everything nested inside (), [], {} removed: what sits at
    the block's own depth (an enum's variants, a struct's fields)."""
    out, depth = [], 0
    for ch in body:
        if ch in "([{":
            if depth == 0:
                out.append(ch)
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                out.append(ch)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def _skip_angles(s: str, k: int) -> int:
    """At `<`: the index after its matching `>` (`->` is not a bracket)."""
    depth = 0
    while k < len(s):
        if s[k] == "<":
            depth += 1
        elif s[k] == ">" and s[k - 1] != "-":
            depth -= 1
            if depth == 0:
                return k + 1
        k += 1
    return k


def blocks(code: str):
    """Yield (kind, owner, top-level member text) for every enum, struct,
    union, trait, mod and impl block in stripped code."""
    pairs = _brace_pairs(code)
    for m in re.finditer(r"\b(enum|struct|union|trait|mod)\s+([A-Za-z_]\w*)", code):
        k = m.end()
        # the header runs to the block's `{` — or ends at `;` / `(` (a unit
        # or tuple struct, an out-of-line `mod x;`), which has no members here
        while k < len(code) and code[k] not in "{;(":
            k = _skip_angles(code, k) if code[k] == "<" else k + 1
        if k < len(code) and code[k] == "{":
            yield m[1], m[2], _top_level(code[k + 1:pairs.get(k, len(code))])
    for m in re.finditer(r"\bimpl\b", code):
        k = m.end()
        while k < len(code) and code[k].isspace():
            k += 1
        if k < len(code) and code[k] == "<":
            k = _skip_angles(code, k)
        h = k
        while k < len(code) and code[k] not in "{;":
            k = _skip_angles(code, k) if code[k] == "<" else k + 1
        if k >= len(code) or code[k] != "{":
            continue
        header = re.split(r"\bwhere\b", code[h:k])[0]
        header = re.split(r"\bfor\b", header)[-1]
        header = re.sub(r"<.*", "", header, flags=re.S)
        owner = re.findall(r"[A-Za-z_]\w*", header)
        if owner:
            yield "impl", owner[-1], _top_level(code[k + 1:pairs.get(k, len(code))])


def _members(kind: str, top: str) -> set[str]:
    names = set(re.findall(ITEM_DEF, top))
    if kind == "enum":
        for piece in top.split(","):
            piece = re.sub(r"#\s*\[\]", "", piece)
            m = re.match(r"\s*([A-Za-z_]\w*)\s*(?:[({=]|$)", piece)
            if m:
                names.add(m[1])
    if kind in ("struct", "union"):
        for piece in top.split(","):
            piece = re.sub(r"#\s*\[\]", "", piece)
            m = re.match(r"\s*(?:pub\s*(?:\(\))?\s*)?([A-Za-z_]\w*)\s*:(?!:)", piece)
            if m:
                names.add(m[1])
    return names


class Analysis:
    """One file, stripped once: its item names, and members per (kind, owner)."""

    def __init__(self, src: str):
        self.code = code = strip(src)
        self.items = set(re.findall(ITEM_DEF, code)) \
            | set(re.findall(r"\bmacro_rules!\s*([A-Za-z_]\w*)", code))
        self.owned: dict[str, set[str]] = {}     # owner -> members
        self.data_members: set[str] = set()      # every variant / named field
        for kind, owner, top in blocks(code):
            names = _members(kind, top)
            self.owned.setdefault(owner, set()).update(names)
            if kind in ("enum", "struct", "union"):
                self.data_members |= names - set(re.findall(ITEM_DEF, top))


_ANALYSES: dict[str, Analysis] = {}


def defines(src: str, symbol: str) -> bool:
    """Does `src` (raw Rust text) DEFINE `symbol` (`name` or `Owner::member`)?"""
    a = _ANALYSES.get(src)
    if a is None:
        a = _ANALYSES[src] = Analysis(src)
    parts = symbol.split("::")
    if len(parts) == 1:
        return parts[0] in a.items or parts[0] in a.data_members
    return parts[-1] in a.owned.get(parts[-2], set())


# ── the rows ─────────────────────────────────────────────────────────────
class Source:
    """src/ files from the working tree under root(), or at a git ref."""

    def __init__(self, base: Path, ref: str | None):
        self.base, self.ref, self.cache = base, ref, {}

    def read(self, path: str) -> str | None:
        if path not in self.cache:
            if self.ref:
                r = subprocess.run(["git", "-C", str(self.base), "show", f"{self.ref}:{path}"],
                                   capture_output=True, text=True)
                self.cache[path] = r.stdout if r.returncode == 0 else None
            else:
                p = self.base / path
                self.cache[path] = p.read_text() if p.is_file() else None
        return self.cache[path]


def resolve(src: Source, pointer: str) -> str | None:
    """None if `path#sym` resolves, else why not."""
    path, _, sym = pointer.partition("#")
    if not sym:
        return "no #symbol"
    text = src.read(path)
    if text is None:
        return "file does not exist"
    if not defines(text, sym):
        return f"no definition of {sym} in {path}"
    return None


def tsv_pointers(text: str):
    """(line_no, label, pointer) for every src/ row; raises ValueError on a malformed row."""
    skipped = 0
    rows = []
    for no, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#") or line.startswith("decimal_id\t"):
            continue
        cols = line.split("\t")
        if len(cols) != 5 or "#" not in cols[3]:
            raise ValueError(f"{TSV}:{no}: malformed row (5 columns, path#symbol): {line!r}")
        if cols[3].startswith("src/"):
            rows.append((no, cols[1], cols[3]))
        else:
            skipped += 1   # a cross-repo citation resolves at its own crate's build
    return rows, skipped


def register_pointers(text: str):
    """(line_no, claim id, pointer) for every `impl:CIRISPersist/src/...#a,b`
    token; a comma-separated fragment is one pointer per symbol."""
    rows = []
    for no, line in enumerate(text.splitlines(), 1):
        claim = line.split("\t", 1)[0]
        for path, frag in re.findall(r"impl:CIRISPersist/(src/[^\s#]+)#([^\s]+)", line):
            for sym in filter(None, frag.split(",")):
                rows.append((no, claim, f"{path}#{sym}"))
    return rows


def main(argv: list[str]) -> int:
    args = argv[1:]
    ref = None
    if "--ref" in args:
        i = args.index("--ref")
        if i + 1 >= len(args):
            print(__doc__, file=sys.stderr); return 2
        ref = args[i + 1]
        del args[i:i + 2]
    base = root()
    src = Source(base, ref)
    where = f"src/ at {ref}" if ref else "the working tree"
    if args == ["check"]:
        try:
            tsv = src.read(TSV)
            if tsv is None:
                print(f"EVIDENCE POINTERS: {TSV} is missing in {where}"); return 1
            rows, skipped = tsv_pointers(tsv)
        except ValueError as e:
            print(f"EVIDENCE POINTERS: {e}"); return 1
        what = f"{TSV} src/ rows"
    elif len(args) == 2 and args[0] == "register":
        rows, skipped = register_pointers(Path(args[1]).read_text()), 0
        what = f"impl:CIRISPersist pointers in {args[1]}"
    else:
        print(__doc__, file=sys.stderr); return 2
    misses = [(no, label, p, why) for no, label, p in rows if (why := resolve(src, p))]
    for no, label, p, why in misses:
        print(f"  DEAD  line {no}  {label}  {p}: {why}")
    if not rows:
        print(f"EVIDENCE POINTERS: no {what} found — a parse change emptied the check")
        return 1
    if misses:
        print(f"EVIDENCE POINTERS: {len(misses)} of {len(rows)} {what} name no definition in "
              f"{where}. Repoint the row (for cc_impl.tsv: edit namespace_supersets.json's "
              f"evidence_export, then `scripts/evidence_tsv.py write`).")
        return 1
    print(f"evidence pointers: all {len(rows)} {what} resolve to a definition in {where}"
          + (f" ({skipped} cross-repo rows skipped)" if skipped else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
