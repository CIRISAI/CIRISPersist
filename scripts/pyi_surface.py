#!/usr/bin/env python3
"""The Python type stub must describe — and CLASSIFY — the surface PyO3 exports.

# Why this exists

`python/ciris_persist/ciris_persist.pyi` was a hand-maintained list standing in
for a real inventory: the `#[pyclass]` / `#[pymethods]` / `#[pyfunction]` items
under `src/ffi/`. It drifted, in the way every hand-maintained list in this repo
has drifted (CIRISPersist#541, #532, #585, #588, #590): 509 symbols exported,
119 documented, and 10 of the 14 names the `#[pymodule]` registers absent.

That was harmless for the package's entire life, because **no type checker ever
read the stub** — the wheel shipped no PEP 561 `py.typed` marker, so checkers
skipped the package outright (CIRISPersist#581).

v26.0.0 shipped the marker. The stub became load-bearing in a single commit, and
the drift became *worse than the absence it replaced*:

- **before** — a checker skipped `ciris_persist` and inferred `Any`. A call to
  an undocumented method type-checked, correctly, as unknown.
- **after** — a checker reads an authoritative-looking stub that omits 390 real
  symbols, and reports calling them as **errors**. A server developer is told
  that working API does not exist.

A wrong stub is worse than a missing one: a missing stub degrades to `Any` and
the caller learns nothing; a wrong stub is *believed*. That risk was recorded in
the CHANGELOG when the marker shipped. This is that risk landing, and this
script is the gate that stops it recurring (CIRISPersist#595).

# The classification, and why the gate enforces one

CIRISConstitution#83 ratifies a taxonomy of wrongs carved by ONE question:

    "What different kind of wrong happens if I vary this?"

A category justified by convenience — "these all start with `list_`" — is not a
category under that ruling. So this gate does NOT derive a class from a name
prefix. The authority is `scripts/ffi_taxonomy.tsv`, one pinned row per exported
symbol, reviewed by a human. The gate enforces that the pin is TOTAL (every
exported symbol has a class) and FRESH (no row survives its symbol) — the same
inversion `src/federation/family_rules.rs` applies to namespace families and
`scripts/ci_feature_matrix.py` applies to Cargo features. A class change is then
a visible one-line diff by a named author, not an edit nobody reviews.

Normative force is PER ROW, and only some rows carry it (CIRISConstitution#83):

  BINDING    structural   cannot vary — breaks the process, the handle, or dispatch
             deontic      changes what the mesh permits; a wrong stub here is a
                          security finding, not a docs nit
             testimonial  makes the record unable to prove what happened
             axiomatic    the cross-harness variable; changing it changes what
                          two repos are even comparing
  DESCRIPTIVE ontological, epistemic, empirical, procedural, axiotic,
             nomological, pragmatic — revisable on this repo's authority
  EMPTY      contingent   — see `report`; principled, not an oversight

# What `check` enforces

1. **Pin totality.** Every exported symbol has a row in `ffi_taxonomy.tsv`.
   A new `#[pymethods]` fn with no class fails the build.
2. **Pin freshness.** Every row names a symbol that still exists.
3. **Stub completeness.** Every exported symbol has a `def` in the stub, and
   every class / exception / constant the `#[pymodule]` registers is declared.
4. **Binding-class strengthening.** The four binding classes get checks the
   descriptive ones do not:
   - `structural` and `axiomatic` must be HAND-WRITTEN. "Cannot vary" is not a
     claim a generator gets to make.
   - `deontic` and `testimonial` must carry a non-empty docstring in the stub,
     and must have a `///` doc in the Rust. A door that refuses, or a record
     that testifies, has to say so.
   - A `deontic` / `testimonial` symbol returning `PyResult<String>` must be
     typed `-> str`, never `-> Any`. This is not pedantry: these methods return
     a JSON string on BOTH arms, so `'{"eligible": false}'` is TRUTHY. A stub
     that says `Any` invites `if engine.resolve_transit_eligibility_json(...)`,
     which permits exactly what the method refused.

# What `check` deliberately does NOT enforce

**Semantic correctness.** Parameter names, arity, defaults and Python types are
DERIVED from the Rust signature — which is authoritative for the FFI boundary,
since PyO3 generates the conversion from exactly those types. What is *not*
verified is what the values mean: `-> str` is true and says nothing about the
JSON schema inside the string, and `filter_json: str` does not say which filter
grammar. Those schemas live in the Rust doc comments and are not machine-checked
against the stub.

So: **a passing `check` means the stub is COMPLETE, not that it is CORRECT.**
Read a green run as "no symbol is invisible to a consumer's type checker", never
as "the described types are right".

Usage:
    scripts/pyi_surface.py check      # the gate; exit 1 + names on any gap
    scripts/pyi_surface.py emit       # regenerate the stub's derived entries
    scripts/pyi_surface.py report     # the taxonomy table
    scripts/pyi_surface.py propose    # rows to add to the pin, unclassified
"""

from __future__ import annotations

import collections
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FFI_DIR = ROOT / "src" / "ffi"
PYI = ROOT / "python" / "ciris_persist" / "ciris_persist.pyi"
TAXONOMY = ROOT / "scripts" / "ffi_taxonomy.tsv"

# `#[pyclass]` Rust type → the stub class a consumer imports. A registered
# pyclass with no entry here is a hard error: every one of its methods would be
# reported nonexistent by a checker.
CLASS_FOR_IMPL = {
    "PyEngine": "Engine",
    "ScoringFactorStream": "ScoringFactorStream",
    "PyReconsiderDosGuard": "ReconsiderDosGuard",
}

# Generated entries are marked so `emit` can replace them without ever touching
# a hand-written one. A hand-written entry is any `def` whose body does not open
# with this marker.
GEN_MARK = "(derived)"

CLASSES = {
    # class          binding?  one-line statement of the wrong
    "structural": (True, "breaks the process, the handle, or dispatch — the machine stops working"),
    "deontic": (True, "changes what the mesh permits — a wrong entry here is a security finding"),
    "testimonial": (True, "makes the record unable to prove what happened; everything still runs"),
    "axiomatic": (True, "changes the decomposition premise two repos are cross-checking"),
    "ontological": (False, "changes who this node, this key, or this identity IS"),
    "epistemic": (False, "changes how uncertainty is held — bands, absence, liveness"),
    "empirical": (False, "makes a checkable, re-derivable world-fact wrong"),
    "procedural": (False, "changes orchestration — when and by whom, not what is true"),
    "axiotic": (False, "re-ranks outcomes without newly permitting any act"),
    "nomological": (False, "changes the model every other symbol reasons under"),
    "pragmatic": (False, "changes register or address, not content"),
    "contingent": (False, "out of scope by construction — see `report` for why this is empty"),
}
BINDING = {c for c, (b, _) in CLASSES.items() if b}

# v29.0.0 (CIRISOntology#3/#1, ratified; CIRISPersist#600) — the frames a
# `testimonial` assignment may declare. Each answers WHOSE record, REPAIRABLE
# BY WHOM, FROM WHAT; the full definitions live in ffi_taxonomy.tsv's header,
# where the reader making an assignment will actually be looking.
#
# This set is CLOSED on purpose. Free-text frames would let an assignment
# declare a frame that says nothing, which is an undeclared frame wearing a
# name — and `repairable_does_not_factor` is a proof that the frame is the
# whole content of the claim, not decoration on it.
FRAMES = {
    "self_audit",
    "log_commitment",
    "delivery_event",
    "equivocation_evidence",
    "erasure_effect",
    "upstream_attestation",
}

# ── Rust → Python type mapping ──────────────────────────────────────────────
# PyO3 generates the extraction/conversion from exactly these Rust types, so the
# mapping is derivation, not guesswork. Anything unmapped falls back to `Any`,
# which is honest rather than wrong.
_PARAM_TYPES = {
    "&str": "str", "String": "str", "&String": "str",
    "Option<&str>": "str | None", "Option<String>": "str | None",
    "bool": "bool", "Option<bool>": "bool | None",
    "f32": "float", "f64": "float", "Option<f64>": "float | None",
    "&[u8]": "bytes", "Vec<u8>": "bytes",
    "Vec<String>": "list[str]", "Option<Vec<String>>": "list[str] | None",
}
_INTS = {"i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "usize", "isize"}
# Injected by PyO3 or bound by the method receiver — never passed by a caller.
_INJECTED = re.compile(r"^(Python<.*>|PyRef<.*>|PyRefMut<.*>)$")


def _py_param(rust: str) -> str:
    r = re.sub(r"\s+", " ", rust).strip()
    if r in _PARAM_TYPES:
        return _PARAM_TYPES[r]
    if r in _INTS:
        return "int"
    m = re.fullmatch(r"Option<(.+)>", r)
    if m and m.group(1) in _INTS:
        return "int | None"
    if "PyBytes" in r:
        return "bytes"
    return "Any"


def _py_return(rust: str, owner_class: str) -> str:
    r = re.sub(r"\s+", " ", rust).strip()
    m = re.fullmatch(r"PyResult<(.*)>", r)
    if m:
        r = m.group(1).strip()
    if r in ("()", ""):
        return "None"
    if r in ("String", "&str", "&'static str"):
        return "str"
    if r == "Option<String>":
        return "str | None"
    if r == "Vec<String>":
        return "list[str]"
    if r == "Option<Vec<String>>":
        return "list[str] | None"
    if r == "bool":
        return "bool"
    if r in _INTS:
        return "int"
    if r in ("f32", "f64"):
        return "float"
    if r in ("Self", "PyEngine") or r.endswith(f"<{owner_class}>"):
        return owner_class
    if r in CLASS_FOR_IMPL.values():
        return r
    if _INJECTED.match(r):
        return owner_class
    inner = re.fullmatch(r"Option<(.+)>", r)
    base, opt = (inner.group(1) if inner else r), bool(inner)
    if "PyDict" in base:
        out = "dict[str, Any]"
    elif "PyList" in base:
        out = "list[Any]"
    elif "PyBytes" in base:
        out = "bytes"
    elif "PyCapsule" in base:
        out = "Any"
    elif "PyAny" in base:
        return "Any"
    else:
        return "Any"
    return f"{out} | None" if opt else out


# ── Rust source parsing ─────────────────────────────────────────────────────
def _decomment(line: str) -> str:
    """Blank string literals and line comments so brace/paren depth is real."""
    out, i, n = [], 0, len(line)
    while i < n:
        c = line[i]
        if c == '"':
            i += 1
            while i < n:
                if line[i] == "\\":
                    i += 2
                    continue
                if line[i] == '"':
                    i += 1
                    break
                i += 1
            out.append('""')
            continue
        if c == "/" and i + 1 < n and line[i + 1] == "/":
            break
        out.append(c)
        i += 1
    return "".join(out)


_FN = re.compile(r"\s*(?:pub(?:\([a-z]+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\b")


class Symbol:
    __slots__ = ("owner", "name", "rust_name", "params", "ret", "flags", "cfg", "doc", "src")

    def __init__(self, owner, name, rust_name, params, ret, flags, cfg, doc, src):
        self.owner = owner          # stub class name, or "MODULE"
        self.name = name            # the name a consumer imports
        self.rust_name = rust_name
        self.params = params        # [(py_name, py_type, default_or_None)]
        self.ret = ret              # python return annotation
        self.flags = flags          # {"new","getter","setter","staticmethod","classmethod"}
        self.cfg = cfg              # list of #[cfg(...)] strings — build-conditional
        self.doc = doc              # first paragraph of the Rust /// doc
        self.src = src              # "path:line"

    @property
    def key(self) -> tuple[str, str]:
        return (self.owner, self.name)


def _impl_blocks(lines: list[str]):
    out, i = [], 0
    while i < len(lines):
        if lines[i].strip().startswith("#[pymethods]"):
            j = i + 1
            while j < len(lines) and not re.match(r"\s*impl\b", lines[j]):
                j += 1
            if j >= len(lines):
                break
            m = re.search(r"impl\s+([A-Za-z0-9_]+)", lines[j])
            owner = m.group(1) if m else "?"
            depth, started, k = 0, False, j
            while k < len(lines):
                s = _decomment(lines[k])
                depth += s.count("{") - s.count("}")
                if "{" in s:
                    started = True
                if started and depth <= 0:
                    break
                k += 1
            out.append((owner, j, k))
            i = k
        i += 1
    return out


def _attrs_and_doc(lines: list[str], fn_line: int):
    """The contiguous attribute + `///` run immediately above a fn."""
    attrs: list[str] = []
    docs: list[str] = []
    buf: list[str] = []
    i = fn_line - 1
    while i >= 0:
        raw = lines[i]
        s = raw.strip()
        if buf:
            buf.insert(0, raw)
            joined = "\n".join(buf)
            if buf[0].lstrip().startswith("#[") and joined.count("(") == joined.count(")"):
                attrs.insert(0, joined)
                buf = []
            i -= 1
            continue
        if s.startswith("///"):
            docs.insert(0, s[3:].strip())
            i -= 1
            continue
        if s.startswith("//"):
            i -= 1
            continue
        if s.endswith("]"):
            buf = [raw]
            if raw.lstrip().startswith("#[") and raw.count("(") == raw.count(")"):
                attrs.insert(0, raw)
                buf = []
            i -= 1
            continue
        break
    para: list[str] = []
    for d in docs:
        if not d and para:
            break
        if d:
            para.append(d)
    return attrs, " ".join(para)


def _signature(lines: list[str], fn_line: int):
    src, i = "", fn_line
    while i < len(lines):
        src += lines[i] + "\n"
        st = _decomment(src)
        if st.count("(") and st.count("(") == st.count(")"):
            break
        i += 1
    name = re.search(r"\bfn\s+([A-Za-z_0-9]+)", src).group(1)
    p0 = src.index("(")
    d, p1 = 0, len(src) - 1
    for idx in range(p0, len(src)):
        if src[idx] == "(":
            d += 1
        elif src[idx] == ")":
            d -= 1
            if d == 0:
                p1 = idx
                break
    tail, j = src[p1 + 1:], i
    while "{" not in _decomment(tail) and ";" not in tail and j + 1 < len(lines):
        j += 1
        tail += "\n" + lines[j]
    m = re.match(r"\s*->\s*(.+)", tail.split("{")[0], re.S)
    ret = re.sub(r"\s*where\s.*", "", re.sub(r"\s+", " ", m.group(1)).strip()) if m else "()"
    return name, src[p0 + 1:p1], ret


def _split_params(params: str) -> list[str]:
    params = re.sub(r"//[^\n]*", "", params)
    out, depth, cur = [], 0, ""
    for ch in params:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
            continue
        cur += ch
    if cur.strip():
        out.append(cur.strip())
    return [p for p in out if p]


def _defaults(sig_attr: str | None) -> dict[str, str]:
    """`#[pyo3(signature = (a, b=None, c=false))]` → {"b": "None", "c": "False"}."""
    if not sig_attr:
        return {}
    m = re.search(r"signature\s*=\s*\((.*)\)\s*\)\s*\]", sig_attr, re.S)
    if not m:
        return {}
    lit = {"None": "None", "true": "True", "false": "False"}
    out: dict[str, str] = {}
    for part in _split_params(m.group(1)):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        v = v.strip()
        # A non-literal default (a Rust const) is honestly `...` in a stub:
        # "has a default, whose value this stub does not claim to know".
        out[k.strip()] = lit.get(v, v if re.fullmatch(r"-?\d+(\.\d+)?", v) else "...")
    return out


def exported() -> list[Symbol]:
    """Every symbol PyO3 exports, from every FFI source — not just pyo3.rs.

    Scanning the whole directory is the point: `PyReconsiderDosGuard` lives in
    `wheel_reconsider_dos.rs`, and a pyo3.rs-only scan reported 505 symbols
    while the wheel exported 508.
    """
    syms: list[Symbol] = []
    for path in sorted(FFI_DIR.rglob("*.rs")):
        lines = path.read_text().split("\n")
        rel = path.relative_to(ROOT)
        for rust_owner, start, end in _impl_blocks(lines):
            cls = CLASS_FOR_IMPL.get(rust_owner)
            if cls is None:
                raise SystemExit(
                    f"::error title=pyi surface::`#[pymethods] impl {rust_owner}` "
                    f"({rel}) is exported to Python, but CLASS_FOR_IMPL names no stub "
                    f"class for it. Add the mapping AND the class, or a type checker "
                    f"reports every one of its methods as nonexistent."
                )
            depth = 0
            for ln in range(start, end + 1):
                if depth == 1 and _FN.match(lines[ln]):
                    syms.append(_build(lines, ln, cls, rel))
                depth += _decomment(lines[ln]).count("{") - _decomment(lines[ln]).count("}")
        for ln, line in enumerate(lines):
            if line.strip() == "#[pyfunction]":
                nxt = ln + 1
                while nxt < len(lines) and not _FN.match(lines[nxt]):
                    nxt += 1
                if nxt < len(lines):
                    syms.append(_build(lines, nxt, "MODULE", rel))
    return syms


def _build(lines: list[str], ln: int, cls: str, rel: Path) -> Symbol:
    attrs, doc = _attrs_and_doc(lines, ln)
    rust_name, raw_params, raw_ret = _signature(lines, ln)
    name, sig_attr, flags, cfg = rust_name, None, set(), []
    for a in attrs:
        a1 = re.sub(r"\s+", " ", a.strip())
        m = re.match(r'#\[pyo3\(name\s*=\s*"([A-Za-z_0-9]+)"\)\]', a1)
        if m:
            name = m.group(1)
            continue
        if a1.startswith("#[pyo3(signature"):
            sig_attr = a1
            continue
        m = re.match(r"#\[(getter|setter)(?:\(([A-Za-z_0-9]+)\))?\]", a1)
        if m:
            flags.add(m.group(1))
            if m.group(2):
                name = m.group(2)
            continue
        if a1 in ("#[staticmethod]", "#[classmethod]", "#[new]"):
            flags.add(a1[2:-1])
            continue
        if a1.startswith("#[cfg("):
            cfg.append(a1)
    if "new" in flags:
        name = "__init__"
    defaults = _defaults(sig_attr)
    params: list[tuple[str, str, str | None]] = []
    for raw in _split_params(raw_params):
        if raw in ("&self", "&mut self", "self") or raw.startswith("self:"):
            continue
        if ":" not in raw:
            continue
        pname, ptype = raw.split(":", 1)
        pname, ptype = pname.strip().lstrip("&"), ptype.strip()
        if _INJECTED.match(re.sub(r"\s+", " ", ptype)):
            continue
        if not pname.isidentifier():
            continue
        params.append((pname, _py_param(ptype), defaults.get(pname)))
    owner_cls = cls if cls != "MODULE" else "Engine"
    ret = "None" if "new" in flags else _py_return(raw_ret, owner_cls)
    return Symbol(cls, name, rust_name, params, ret, flags, cfg, doc, f"{rel}:{ln + 1}")


# ── the pin ─────────────────────────────────────────────────────────────────
def pinned() -> dict[tuple[str, str], str]:
    out: dict[tuple[str, str], str] = {}
    for i, raw in enumerate(TAXONOMY.read_text().split("\n"), 1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            raise SystemExit(
                f"{TAXONOMY.name}:{i}: expected 'owner<TAB>symbol<TAB>class<TAB>frame'"
            )
        owner, sym, cls = parts[0].strip(), parts[1].strip(), parts[2].strip()
        frame = parts[3].strip() if len(parts) > 3 else ""
        if cls not in CLASSES:
            raise SystemExit(
                f"{TAXONOMY.name}:{i}: '{cls}' is not one of the CIRISConstitution#83 "
                f"classes: {', '.join(sorted(CLASSES))}"
            )
        # v29.0.0 (CIRISOntology#3/#1, ratified; #600) — `testimonial` is a
        # RELATION. `repairable_does_not_factor` proves no artifact-only
        # procedure can assign it, so an undeclared frame is UNWARRANTED AS
        # STATED rather than merely undocumented. Verify's own
        # `Arity::testimonial` refuses an undeclared frame instead of
        # defaulting one; this is the same refusal at persist's pin, because a
        # defaulted frame is exactly the unstated assumption that silently
        # decides the verdict.
        if cls == "testimonial" and not frame:
            raise SystemExit(
                f"{TAXONOMY.name}:{i}: {owner}.{sym} is `testimonial` with NO FRAME. "
                f"State whose record it is, repairable by whom, from what — one of: "
                f"{', '.join(sorted(FRAMES))}. If it cannot state one, it is misfiled "
                f"by construction and belongs in another class."
            )
        if cls != "testimonial" and frame:
            raise SystemExit(
                f"{TAXONOMY.name}:{i}: {owner}.{sym} is `{cls}` and carries frame "
                f"'{frame}'. A frame relativises REPAIRABILITY, which only "
                f"`testimonial` turns on; carrying one elsewhere implies a "
                f"discriminator that class does not use."
            )
        if frame and frame not in FRAMES:
            raise SystemExit(
                f"{TAXONOMY.name}:{i}: {owner}.{sym} declares frame '{frame}', which is "
                f"not defined in this file's header. Define it there — WHOSE record, "
                f"REPAIRABLE BY WHOM, FROM WHAT — or use one of: "
                f"{', '.join(sorted(FRAMES))}. A frame nobody defined is an undeclared "
                f"frame wearing a name."
            )
        out[(owner, sym)] = cls
    return out


def pinned_frames() -> dict[tuple[str, str], str]:
    """The frame per symbol, empty for every non-`testimonial` row."""
    out: dict[tuple[str, str], str] = {}
    for raw in TAXONOMY.read_text().split("\n"):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        out[(parts[0].strip(), parts[1].strip())] = (
            parts[3].strip() if len(parts) > 3 else ""
        )
    return out


# ── the stub ────────────────────────────────────────────────────────────────
_DEF = re.compile(r"^(?P<indent>[ ]*)(?:@[\w.]+[^\n]*\n\s*)*def\s+(?P<name>[A-Za-z_0-9]+)\s*\(", re.M)


def _enclosing_class(text: str, pos: int) -> str:
    """The `class X:` a def at `pos` belongs to, or "MODULE"."""
    last = "MODULE"
    for m in re.finditer(r"^class\s+([A-Za-z_0-9]+)", text, re.M):
        if m.start() > pos:
            break
        last = m.group(1)
    return last


def documented() -> tuple[dict[tuple[str, str], str], set[str]]:
    """({(class, name): block}, {module-level names}) as the stub declares them."""
    text = PYI.read_text()
    blocks = _qualified_defs(text)
    top: set[str] = set()
    for m in re.finditer(r"^([A-Za-z_][A-Za-z_0-9]*)\s*:\s*\S", text, re.M):
        top.add(m.group(1))
    for m in re.finditer(r"^class\s+([A-Za-z_0-9]+)", text, re.M):
        top.add(m.group(1))
    for m in re.finditer(r"^([A-Za-z_][A-Za-z_0-9]*)\s*=", text, re.M):
        top.add(m.group(1))
    return blocks, top


def _qualified_defs(text: str) -> dict[tuple[str, str], str]:
    """{(class, name): source block} — class-qualified, so same-named methods
    on different classes never stand in for one another."""
    hits = list(_DEF.finditer(text))
    out: dict[tuple[str, str], str] = {}
    for i, m in enumerate(hits):
        indent = len(m.group("indent"))
        owner = "MODULE" if indent == 0 else _enclosing_class(text, m.start())
        end = len(text)
        for nxt in hits[i + 1:]:
            if len(nxt.group("indent")) <= indent:
                end = nxt.start()
                break
        else:
            tail = re.search(r"^(?:class |# ---|[A-Za-z_])", text[m.end():], re.M)
            if tail:
                end = m.end() + tail.start()
        # A `class X:` header sits BETWEEN two same-indent defs, so the span
        # above would swallow it into the previous class's last method.
        nxt_cls = re.search(r"^class\s", text[m.end():end], re.M)
        if nxt_cls:
            end = m.end() + nxt_cls.start()
        out[(owner, m.group("name"))] = _trim(text[m.start():end])
    return out


def _trim(block: str) -> str:
    """Drop the trailing blank/comment run a slice picks up from the NEXT
    section header. Without this, `emit` carries a header into the block above
    it and re-emits its own header beside it, growing the file every run."""
    lines = block.rstrip().split("\n")
    while lines and (not lines[-1].strip() or lines[-1].lstrip().startswith("#")):
        lines.pop()
    return "\n".join(lines) + "\n"


def _render(sym: Symbol, cls: str) -> str:
    ind = "    " if sym.owner != "MODULE" else ""
    dec = ""
    if "getter" in sym.flags:
        dec = f"{ind}@property\n"
    elif "staticmethod" in sym.flags:
        dec = f"{ind}@staticmethod\n"
    elif "classmethod" in sym.flags:
        dec = f"{ind}@classmethod\n"
    recv = []
    if sym.owner != "MODULE" and "staticmethod" not in sym.flags:
        recv = ["cls" if "classmethod" in sym.flags else "self"]
    args = list(recv)
    for pname, ptype, default in sym.params:
        args.append(f"{pname}: {ptype}" + (f" = {default}" if default is not None else ""))
    doc = sym.doc or ""
    doc = re.sub(r"[`*]", "", doc)
    doc = re.sub(r"\s+", " ", doc).strip()
    # A Rust doc is free text. A stray backslash becomes an invalid escape in a
    # non-raw Python string, and a `"""` or a trailing `"` closes the docstring
    # early — either way `emit` would write a .pyi that does not parse.
    doc = doc.replace("\\", "\\\\").replace('"""', "'''").rstrip('"')
    if len(doc) > 150:
        doc = doc[:147].rstrip().rstrip("\\") + "..."
    note = f" — {doc}" if doc else ""
    cfg = f" [build-conditional: {' '.join(sym.cfg)}]" if sym.cfg else ""
    body = f'{ind}    """{GEN_MARK} {cls}{note}{cfg}"""\n'
    return f"{dec}{ind}def {sym.name}({', '.join(args)}) -> {sym.ret}:\n{body}"


def _section(cls: str, indent: str) -> str:
    binding, wrong = CLASSES[cls]
    tag = "BINDING" if binding else "descriptive"
    bar = "=" * (66 - len(indent))
    return (
        f"\n{indent}# {bar}\n"
        f"{indent}# {cls.upper()}  ({tag})\n"
        f"{indent}# Varying one of these {wrong}.\n"
        f"{indent}# {bar}\n"
    )


ORDER = ["structural", "deontic", "testimonial", "axiomatic", "ontological",
         "nomological", "epistemic", "empirical", "axiotic", "procedural",
         "pragmatic", "contingent"]

BEGIN = "# --- pyi_surface: BEGIN GENERATED REGION ---"
END = "# --- pyi_surface: END GENERATED REGION ---"


def _class_prologues(region: str) -> dict[str, str]:
    """`class X:` → the hand-written docstring between the header and the first
    member. Preserved verbatim across every `emit`."""
    out: dict[str, str] = {}
    for m in re.finditer(r"^class\s+([A-Za-z_0-9]+)[^\n]*:\n", region, re.M):
        body = region[m.end():]
        stop = re.search(r"^(?:class |\s*(?:@|def |# =))", body, re.M)
        pro = body[: stop.start()] if stop else body
        if pro.strip():
            out[m.group(1)] = pro.rstrip("\n")
    return out


def emit() -> int:
    text = PYI.read_text()
    if BEGIN not in text or END not in text:
        raise SystemExit(
            f"{PYI.name} has no `{BEGIN}` / `{END}` markers. `emit` rewrites only the "
            f"region between them; everything outside is preserved byte-for-byte."
        )
    head, rest = text.split(BEGIN, 1)
    region, tail = rest.split(END, 1)
    prologues = _class_prologues(region)

    # Class-QUALIFIED, not name-keyed: `__init__` exists on Engine and on
    # ReconsiderDosGuard, and a name-keyed map lets the generated one shadow —
    # and then silently destroy — the hand-written one.
    # v31.1.0 (CIRISPersist#676) — the marker is searched over the WHOLE block.
    #
    # It used to be searched over `b.split("\n", 2)[-1][:400]` — everything
    # after the SECOND newline. A generated entry is `def` + a one-line
    # docstring, so that slice is the EMPTY STRING and the marker was never
    # found: 359 of 522 blocks were misclassified as hand-written and had
    # never regenerated since the day they were first emitted. The three the
    # old test did catch were the `@staticmethod` ones, which are three lines
    # because of the decorator — the bug hid behind its own exceptions.
    #
    # `check` cannot see this: it verifies coverage and classification, not
    # whether a docstring still matches its source. So the stub could promise
    # a contract the code had stopped honouring, which is what CIRISPersist#667
    # shipped into review — a resume field that had changed underneath it.
    #
    # Safe as a whole-block search: every block carrying the marker is the
    # generated shape (`def` + `"""(derived) ..."""`, optionally decorated),
    # verified by census before this changed. A hand-written block would have
    # to quote the marker itself to be caught.
    kept = {
        k: b for k, b in _qualified_defs(region).items()
        if GEN_MARK not in b
    }
    pin, syms = pinned(), exported()
    by_owner: dict[str, list[Symbol]] = collections.defaultdict(list)
    for s in syms:
        by_owner[s.owner].append(s)

    chunks = [BEGIN, ""]
    for owner in ["Engine", "ScoringFactorStream", "ReconsiderDosGuard", "MODULE"]:
        group = by_owner.get(owner, [])
        if not group:
            continue
        ind = "" if owner == "MODULE" else "    "
        if owner == "MODULE":
            chunks.append("\n# " + "=" * 68)
            chunks.append("# MODULE-LEVEL FUNCTIONS")
            chunks.append("# " + "=" * 68)
        else:
            chunks.append(f"\nclass {owner}:")
            if owner in prologues:
                chunks.append(prologues[owner])
        buckets: dict[str, list[Symbol]] = collections.defaultdict(list)
        for s in group:
            buckets[pin.get(s.key, "contingent")].append(s)
        wrote_any = False
        for cls in ORDER:
            members = sorted(buckets.get(cls, []), key=lambda s: s.name)
            if not members:
                continue
            chunks.append(_section(cls, ind))
            for s in members:
                wrote_any = True
                chunks.append(kept.pop(s.key, None) or _render(s, cls))
        if not wrote_any and owner != "MODULE":
            chunks.append(f"{ind}...")
    leftovers = sorted(f"{o}.{n}" for o, n in kept)
    if leftovers:
        raise SystemExit(
            f"::error title=pyi surface::hand-written stub entries inside the generated "
            f"region name symbols PyO3 does not export: {', '.join(sorted(leftovers))}. "
            f"Move them outside the markers or delete them — a stub that describes a "
            f"method the wheel does not have is the same defect as omitting one."
        )
    out = head + "\n".join(chunks).rstrip() + "\n\n" + END + tail
    PYI.write_text(out)
    print(f"emitted {len(syms)} symbols into {PYI.relative_to(ROOT)}")
    return 0


# ── module-level attributes the `#[pymodule]` registers ─────────────────────
def module_attrs() -> list[str]:
    src = (FFI_DIR / "pyo3.rs").read_text()
    out = []
    for m in re.finditer(r'm\.add\(\s*"([A-Za-z_0-9]+)"', src):
        out.append(m.group(1))
    for m in re.finditer(r"m\.add_class::<([A-Za-z0-9_:<>]+)>", src):
        rust = m.group(1).split("::")[-1]
        out.append(CLASS_FOR_IMPL.get(rust, rust))
    return sorted(set(out))


def check() -> int:
    syms = exported()
    pin = pinned()
    have, top = documented()
    fails: list[str] = []

    live = {s.key for s in syms}
    unpinned = sorted(s.key for s in syms if s.key not in pin)
    if unpinned:
        shown = "\n".join(f"    {o}.{n}" for o, n in unpinned[:20])
        fails.append(
            f"{len(unpinned)} exported symbol(s) carry NO classification in "
            f"{TAXONOMY.relative_to(ROOT)}:\n{shown}"
            + (f"\n    ... and {len(unpinned) - 20} more" if len(unpinned) > 20 else "")
            + "\n  Every FFI symbol is classified by the wrong that varying it causes "
              "(CIRISConstitution#83). Add a row: '<owner>\\t<symbol>\\t<class>'. Run "
              "`scripts/pyi_surface.py propose` for the unclassified rows, then CHOOSE "
              "the class — the prefix is not the answer."
        )
    stale = sorted(k for k in pin if k not in live)
    if stale:
        fails.append(
            f"{len(stale)} classification row(s) name symbols PyO3 no longer exports: "
            + ", ".join(f"{o}.{n}" for o, n in stale[:20])
            + "\n  Delete them. A pin that outlives its symbol is the drift this gate exists to stop."
        )

    missing = [s for s in syms if s.key not in have]
    if missing:
        shown = "\n".join(f"    {s.owner}.{s.name}   ({s.src})" for s in missing[:20])
        fails.append(
            f"{len(missing)} of {len(syms)} PyO3-exported symbols are absent from "
            f"{PYI.relative_to(ROOT)}:\n{shown}"
            + (f"\n    ... and {len(missing) - 20} more" if len(missing) > 20 else "")
            + "\n  Since v26.0.0 the wheel ships a PEP 561 `py.typed` marker, so this stub "
              "is READ. An absent symbol is not merely undocumented — a consumer's type "
              "checker reports calling it as an error, for API that works. Run "
              "`scripts/pyi_surface.py emit`."
        )

    missing_attrs = [a for a in module_attrs() if a not in top]
    if missing_attrs:
        fails.append(
            "the `#[pymodule]` registers these names, and the stub declares none of them: "
            + ", ".join(missing_attrs)
            + "\n  `python/ciris_persist/__init__.py` re-exports them, so a checker fails on "
              "persist's OWN package before it ever reaches a consumer."
        )

    for s in syms:
        cls = pin.get(s.key)
        if cls not in BINDING:
            continue
        block = have.get(s.key, "")
        if cls in ("structural", "axiomatic") and GEN_MARK in block:
            fails.append(
                f"{s.owner}.{s.name} is `{cls}` (BINDING) but its stub entry is generated. "
                f"'Cannot vary' / 'the cross-harness variable' are not claims a generator "
                f"gets to make — describe it by hand."
            )
        if cls in ("deontic", "testimonial"):
            if not re.search(r'"""', block):
                fails.append(
                    f"{s.owner}.{s.name} is `{cls}` (BINDING) with no docstring in the stub. "
                    f"A door that refuses, or a record that testifies, has to say what it costs."
                )
            if not s.doc:
                fails.append(
                    f"{s.owner}.{s.name} is `{cls}` (BINDING) with no `///` doc at {s.src}. "
                    f"The stub has nothing to derive a statement from."
                )
            if s.ret == "Any" and re.search(r"->\s*Any\b", block):
                fails.append(
                    f"{s.owner}.{s.name} is `{cls}` (BINDING) and typed `-> Any`. These "
                    f"return a JSON string on BOTH arms, so the refusal is TRUTHY; `Any` "
                    f"invites `if engine.{s.name}(...)`, which permits what it refused."
                )

    if fails:
        print("\n\n".join(f"X {f}" for f in fails), file=sys.stderr)
        print(
            f"::error title=pyi surface::{len(fails)} FFI-surface gate failure(s); "
            f"the wheel ships py.typed, so an undescribed or unclassified symbol reaches "
            f"consumers as 'does not exist'"
        )
        return 1

    counts = collections.Counter(pin[s.key] for s in syms)
    tally = "  ".join(f"{c}={counts[c]}" for c in ORDER if counts[c])
    # ── The evidence-layer projection must not drift from its source. ──────
    # `evidence/ffi_classification.tsv` exists because CIRISConstitution asked
    # for it: testimonial rows living only in a gated TSV is itself a
    # testimonial-class state, and the class should not exemplify its own
    # wrong. But a projection nothing checks is just a second hand-maintained
    # list — the defect this whole module exists to close. So it is checked.
    #
    # This comment said "53 testimonial rows" from #595 until v29.0.0. There
    # were never 53 — the file held 49, and 53 was carried verbatim into
    # CIRISPersist#597 and #600 as though counted. Exactly the class the
    # v28.3.0 doc-version gate was built for, in the module that gates counts
    # for a living. It is 37 now, and it is not written here, because the count
    # is derived two lines below and a second copy would rot the same way.
    proj = ROOT / "evidence" / "ffi_classification.tsv"
    if not proj.exists():
        print(
            f"\u2717 {proj.relative_to(ROOT)} is missing. The Constitution reads the "
            "evidence layer, not scripts/. Run `pyi_surface.py surface` to regenerate it.",
            file=sys.stderr,
        )
        print("::error title=ffi classification::evidence projection absent")
        return 1
    # v29.0.0 (#600) — the FRAME is compared too. Without it the projection
    # could carry a stale or absent frame while its class column matched, and
    # the evidence layer CC actually reads would state an unwarranted
    # testimonial assignment while this gate called it clean.
    frames_pin = pinned_frames()
    want = {
        (s_.owner, s_.name, pin[s_.key], frames_pin.get(s_.key, ""))
        for s_ in syms
        if s_.key in pin
    }
    have = set()
    for line in proj.read_text().splitlines():
        if line.startswith("#") or not line.strip() or line.startswith("class\t"):
            continue
        f = line.split("\t")
        if len(f) >= 5:
            have.add((f[3], f[4], f[0], f[5].strip() if len(f) > 5 else ""))
    if want != have:
        missing, extra = sorted(want - have)[:5], sorted(have - want)[:5]
        print(
            f"\u2717 {proj.relative_to(ROOT)} has drifted from scripts/ffi_taxonomy.tsv.\n"
            f"   in the pin, absent from evidence: {missing}\n"
            f"   in evidence, absent from the pin: {extra}\n"
            "   Regenerate with `pyi_surface.py surface`. A projection that can disagree "
            "with its source is the two-lists class, one layer out.",
            file=sys.stderr,
        )
        print("::error title=ffi classification::evidence projection drifted from the pin")
        return 1

    print(f"OK type stub covers and classifies all {len(syms)} PyO3-exported symbols.")
    print(f"   {tally}")
    print("   COMPLETE, not CORRECT: derived types are structurally exact and")
    print("   semantically unverified — see this script's module docstring.")
    return 0


def report() -> int:
    syms = exported()
    pin = pinned()
    by: dict[str, list[Symbol]] = collections.defaultdict(list)
    for s in syms:
        by[pin.get(s.key, "UNCLASSIFIED")].append(s)
    print(f"{len(syms)} exported symbols\n")
    for cls in ORDER:
        binding, wrong = CLASSES[cls]
        members = sorted(by.get(cls, []), key=lambda s: (s.owner, s.name))
        tag = "BINDING" if binding else "descriptive"
        print(f"== {cls} ({len(members)}, {tag}) — varying one {wrong}")
        cfgd = sum(1 for s in members if s.cfg)
        if members:
            print(f"   build-conditional: {cfgd}/{len(members)}")
        for s in members:
            print(f"   {s.owner}.{s.name}")
        print()
    if by.get("UNCLASSIFIED"):
        print(f"!! {len(by['UNCLASSIFIED'])} UNCLASSIFIED")
        return 1
    return 0


def propose() -> int:
    pin = pinned()
    todo = [s for s in exported() if s.key not in pin]
    if not todo:
        print("# every exported symbol is classified")
        return 0
    print(f"# {len(todo)} unclassified. Replace CHOOSE-A-CLASS by asking what different")
    print(f"# kind of wrong happens if you vary the symbol. Classes: {', '.join(ORDER)}")
    for s in sorted(todo, key=lambda s: (s.owner, s.name)):
        if s.doc:
            print(f"# {s.doc[:110]}")
        print(f"{s.owner}\t{s.name}\tCHOOSE-A-CLASS")
    return 0


def surface() -> int:
    """Regenerate `evidence/ffi_classification.tsv` from `scripts/ffi_taxonomy.tsv`.

    **This subcommand did not exist until v25.2.0**, and `check()` had been
    telling people to run it since #595 shipped. The projection is gated
    against its source and there was no supported way to regenerate it, so the
    only route through a red gate was to hand-edit the artifact the gate calls
    a projection — which is the two-lists class the gate was built to close,
    reintroduced by the gate's own error message. Found while landing
    CIRISPersist#570 ask 1.

    The header comment block is preserved verbatim except for the `Counts at
    this revision:` line, which is a derived fact and is rewritten. Data rows
    are `class\\tbinding\\tclass_count\\towner\\tsymbol`, sorted by (class,
    owner, symbol) — the order the existing artifact is already in, so a
    regeneration on an unchanged tree is a no-op diff.
    """
    syms = exported()
    pin = pinned()
    unclassified = [s for s in syms if s.key not in pin]
    if unclassified:
        print(
            "✗ refusing to regenerate the projection while "
            f"{len(unclassified)} symbol(s) carry no class: "
            f"{[f'{s.owner}.{s.name}' for s in unclassified[:5]]}. "
            "Classify them in scripts/ffi_taxonomy.tsv first — a projection of "
            "an incomplete pin is a projection that reads as complete.",
            file=sys.stderr,
        )
        return 1

    # Sorted by (class, owner, symbol) ALPHABETICALLY — matching the artifact
    # that already exists, not `ORDER`. Regenerating an unchanged tree must
    # produce a zero-line diff, or the first person to run this gets a 500-line
    # reorder they cannot review and will be tempted to skip reading.
    frames = pinned_frames()
    rows = sorted((pin[s.key], s.owner, s.name, frames.get(s.key, "")) for s in syms)
    counts = collections.Counter(r[0] for r in rows)
    proj = ROOT / "evidence" / "ffi_classification.tsv"
    old = proj.read_text().splitlines()
    header = [ln for ln in old if ln.startswith("#")]
    tally = " ".join(
        f"{c}={counts[c]}" for c, _ in counts.most_common() if counts[c]
    )
    header = [
        f"# Counts at this revision: {tally}" if ln.startswith("# Counts at this revision:") else ln
        for ln in header
    ]
    out = list(header)
    # `frame` is APPENDED, not inserted: the drift check reads owner/symbol at
    # fixed indices 3/4, and shifting them would make a column-order change
    # look like a clean pass on rows it was no longer comparing.
    out.append("class\tbinding\tclass_count\towner\tsymbol\tframe")
    for cls, owner, name, frame in rows:
        binding = "binding" if CLASSES[cls][0] else "descriptive"
        out.append(f"{cls}\t{binding}\t{counts[cls]}\t{owner}\t{name}\t{frame}")
    proj.write_text("\n".join(out) + "\n")
    print(f"OK wrote {len(rows)} rows to {proj.relative_to(ROOT)}")
    print(f"   {tally}")
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    fn = {
        "check": check,
        "emit": emit,
        "report": report,
        "propose": propose,
        "surface": surface,
    }.get(cmd)
    if fn is None:
        raise SystemExit(
            f"unknown subcommand {cmd!r}; try check | emit | report | propose | surface"
        )
    raise SystemExit(fn())
