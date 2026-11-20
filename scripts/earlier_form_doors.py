#!/usr/bin/env python3
"""earlier_form_doors.py — no write door admits an object of the earlier
form (v62.0.0, JSON-cut slice F; CC 2.6.1.12 "nothing carries", CC 8.11).

    scripts/earlier_form_doors.py check        the gate; exit 1 on any red
    scripts/earlier_form_doors.py list         every door found, with its row
    scripts/earlier_form_doors.py --self-test  the gate's own witnesses
    scripts/earlier_form_doors.py unignore     CP2 only: delete every CP2 ignore
                                               (refused while the switch is off)
    scripts/earlier_form_doors.py release-check  red while any
                                               `v62-CP2 rewrite pending` test
                                               remains (release.sh stage 2)

A GATE, FROM DISK, NO CARGO. Slice F shuts the earlier-form doors with one
switch (`edition2::door::EARLIER_FORM_DOORS_SHUT`) read by one shared
refusal (`refuse_earlier_form` / `refuse_earlier_form_row`). The switch
shuts only the doors WIRED to the refusal. This gate holds the wiring: a new
write door that takes a signed object and forgets the refusal turns it red.
It gates the PROPERTY ("every door that takes an object refuses the earlier
form or is the edition-2 door"), not the doors that exist today.

THE INVENTORY (found, not listed). Four surfaces:

  trait    every method of a door trait in TRAITS (`FederationDirectory`,
           src/federation/mod.rs; `BlobStorage`, src/federation/blobs.rs) whose
           parameter list names an OBJECT type (OBJECT_TYPES below: any
           `Signed*` type, the cosign / accord-evidence / genesis-bundle /
           wholeness / accord-payload types, a raw `serde_json::Value`) or a
           parameter named `*json*`.
  pyo3     every `#[pyfunction]` / `#[pymethods]` fn in src/ffi/pyo3.rs and
           src/ffi/pyo3/*.rs whose body calls an inventoried trait door by
           name (`.put_family(`), or names an OBJECT type, or whose own name
           is a write verb ending in `_json`.
  capsule  every `DirectoryOp` variant (src/ffi/directory_capsule.rs) whose
           fields name an OBJECT type; its body is its arm in the dispatch.
  http     every non-GET route handler registered in src/server/*.rs.

Every inventoried door must have exactly one row in
scripts/earlier_form_doors.tsv, and every row must name a door the inventory
found (a stale row is red: a deleted door's row is deleted with it).

THE ROWS. `surface<TAB>door<TAB>verdict<TAB>route<TAB>note`:

  refuses   the door refuses the earlier form. `route` is the call chain
            from the door's body to the refusal, hops joined by `>`:
              `path/in/src.rs::fn` or `path.rs::Owner::fn`   a function
              `trait:<door>`   a trait door this gate itself verifies
            Each hop must be CALLED from the previous body (`name(`, or
            `name::<..>(`, comments and literals blanked, test code
            removed). The last function hop must call `refuse_earlier_form(`
            or `refuse_earlier_form_row(` UNCONDITIONALLY: at the top level
            of its body, not inside an `if`, `match`, closure or block. An
            empty route means the door's own body calls it.
  edition2  the door is the edition-2 entry: the chain's last function hop
            (or, with an empty route, the door's own body) calls one of
            EDITION2_ENTRIES (`put_statement`,
            `apply_replicated_statement`, `admit_row`,
            `require_statement_form`), each of which refuses a non-statement
            by name (I1902).
  retired   the door refuses every input with a named retirement
            (`EnvelopeKindRetired`, or `Unsupported` naming the retired
            method) and reads nothing: no decode, no verifier, no trait door.
  exempt    the door takes no earlier-form CEG object. `note` must say why
            (a node-local write of an unsigned struct; a plane CC has not
            ruled; a request-auth signature, not a row). An exemption is a
            reviewed one-line diff, not a silence.

A trait door is checked on EVERY backend: in each of
`impl FederationDirectory for SqliteBackend` (store/sqlite.rs) and `... for
PostgresBackend` (store/postgres.rs) its override's body, or the trait's
default body where a backend does not override, must call the first hop.
The generated double (directory_double.rs) and the capsule's OpsDirectory
proxy delegate to a real backend, which is where the refusal runs; they are
not doors of their own.

TEST CODE is removed before any body is read: an item under `#[cfg(test)]`,
`#[cfg(all(test, ..))]`, `#[test]` or `#[tokio::test..]`, and every file
whose `mod` is declared under one of those. Any other spelling of a
test-only cfg on an item in a file the gate reads (`cfg(any(test))`, a
split attribute) is refused: the gate must know every test gating form it
skips.

THE CP2 IGNORES. A test that can only pass with the doors shut is parked as
`#[ignore = "v62-CP2: needs EARLIER_FORM_DOORS_SHUT"]` until the switch flips.
The gate reads the switch from `edition2/door.rs` (production code): while it
is `false` the markers are allowed; once it is `true`, ANY `#[ignore = "v62-CP2…"]`
attribute left in src/ or tests/ is red: a parked witness that never
un-parks is a check that cannot fail. A marker in a comment is not an
attribute. A spelling that starts `v62-CP2` but is not the exact string is
red whatever the switch, so no marker escapes `unignore` by a typo.
`unignore` deletes each marker line (the attribute alone on its line) and
refuses while the switch is off.

Exit 0 green, 1 red, 2 usage or a broken tree.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

TSV = "scripts/earlier_form_doors.tsv"
TRAIT_FILE = "src/federation/mod.rs"
TRAIT_NAME = "FederationDirectory"
# v62.0.0 (F0-cp6c) — every trait whose methods are write doors, not only the
# directory: `BlobStorage` (`put_holding_claim` hid there, taking an earlier
# bound-hybrid claim the directory gate never inventoried). Each is read from
# its file and checked on every backend's impl, as `FederationDirectory` is.
TRAITS = (
    (TRAIT_FILE, TRAIT_NAME),
    ("src/federation/blobs.rs", "BlobStorage"),
)
BACKENDS = (
    ("src/store/sqlite.rs", "SqliteBackend"),
    ("src/store/postgres.rs", "PostgresBackend"),
)
PYO3_FILES_GLOB = ("src/ffi/pyo3.rs", "src/ffi/pyo3/*.rs")
CAPSULE_FILE = "src/ffi/directory_capsule.rs"
CAPSULE_ENUM = "DirectoryOp"
CAPSULE_DISPATCH = "dispatch_directory_op"
SERVER_GLOB = "src/server/*.rs"

REFUSALS = ("refuse_earlier_form", "refuse_earlier_form_row")
SWITCH_FILE = "src/federation/edition2/door.rs"
CP2_IGNORE = '#[ignore = "v62-CP2: needs EARLIER_FORM_DOORS_SHUT"]'
CP2_ANY = re.compile(r'#\s*\[\s*ignore\s*=\s*"v62-CP2[^"]*"\s*\]')
# The lead's bridge for a held test whose owner is rewriting it on edition 2:
# allowed in development, a release blocker (`release-check`).
CP2_REWRITE = re.compile(r'#\[ignore = "v62-CP2 rewrite pending: \S[^"]*"\]')
# The dispatch layers: a body here matches on the backend
# (`BackendDispatch::Sqlite(b) => ..`) or wraps its work in a closure
# (`catch_panic(|| ..)`, `py.detach(move || ..)`), so a hop FROM one of these
# need only call the next hop somewhere in its body. Every hop from a
# federation or store body is held to the top-level rule, and the refusal
# itself always is.
DISPATCH_LAYERS = ("src/engine.rs", "src/ffi/")
EDITION2_ENTRIES = (
    "put_statement",
    "apply_replicated_statement",
    "admit_row",
    "require_statement_form",
)
# A type that carries a signed object of the earlier form (a JSON object
# signed over its JCS image). `Signed*` is the crate's naming convention for
# every such wire type; the rest are the object types that do not follow it.
OBJECT_TYPES = re.compile(
    r"\bSigned[A-Z]\w*"
    r"|\bLineageHeadCosign\b"
    r"|\bAccordQuorumEvidence\b"
    r"|\bGenesisBundle\b"
    r"|\bWholenessWitness\b"
    # v62.0.0 (F0-cp6c) — a holder's claim as the earlier form carries it
    # (`scrub_signature_classical` + `scrub_signature_pqc`, bound hybrid)
    r"|\bPutBlobAttestation\b"
    r"|\bAccord(?:Proposal|Participation|Decision)\b"
    r"|\bStewardPurgeNotice\b"
    # a roster change's spec carries its authority's / countersigners'
    # earlier-form signatures
    r"|\bAdmitSpec\b|\bRevokeSpec\b|\bGroupSupersedeProof\b"
    r"|\bserde_json\s*::\s*Value\b"
)
JSON_PARAM = re.compile(r"\b\w*json\w*\s*:")
WRITE_VERB_JSON = re.compile(
    r"^(?:put|apply|install|pin|attach|adopt|register|rebind|store|grant|revoke|"
    r"deregister|widen|withdraw|import|ingest|admit|accept|receive|bake|amend|"
    r"seed|insert|upsert|record|set|add)_\w*json$"
)
# A write verb as a `_`-separated segment of a host-surface name
# (`put_family_json`, `cirisnode_put_goal_json`, `apply_replicated_purge_json`).
WRITE_SEGMENT = re.compile(
    r"(?:^|_)(?:put|apply|install|pin|attach|adopt|register|rebind|store|grant|revoke|"
    r"deregister|widen|withdraw|import|ingest|admit|accept|receive|bake|amend|seed|"
    r"insert|upsert|record|supersede)(?:_|$)"
)
# The earlier form's verifiers: a host door that calls one of these is
# judging a JSON object signed over its JCS image, whatever it then stores.
EARLIER_FORM_VERIFIERS = re.compile(
    r"\b(?:verify_hybrid|verify_hybrid_via_directory|verify_hybrid_with_policy|"
    r"verify_key_registration|verify_proof_of_possession|verify_record_signed_by|"
    r"verify_row_hybrid_signature|verify_signed_[a-z_]+)\s*(?:::\s*<[^;{}]*?>\s*)?\("
)
# v62.0.0 (F0-cp5) — a door that verifies ONE composite signature under the
# signer's live edition-2 key (RULINGS "composite signatures only"): its chain
# ends in a body that calls the shared verifier and no earlier-form verifier.
# v62.0.0 (F0-cp5b; CC 6.1.3) — and the CC 6.1 objects' composite verifiers,
# each over its own binary preimage (one composite primitive, two framings).
COMPOSITE_ENTRIES = (
    "verify_composite_via_directory",
    "verify_sig19",
    "verify_witness",
    "verify_aggregation_meta",
    "verify_storage_budget_v1",
    "verify_corpus_want_v1",
    # a transparency head's composite under its producer's key (CC 2.6.1.7)
    "verify_sth_signature",
)
# v62.0.0 (F0-cp6) — a CC 6.1.3 substrate plane: its chain ends in a body
# whose first word is the one predicate (`substrate_form`), called
# unconditionally at the body's top level, so the one predicate decides its form.
SUBSTRATE_ENTRIES = ("substrate_form",)
# v62.0.0 (F0-cp6c) — `pending`: a KNOWN earlier-form door routed to an owner
# for migration. `check` allows it (the note must name the owner);
# `release-check` is red while any remains, like a rewrite-pending test.
# v62.0.0 (F0-cp6d) — a NODE-LOCAL door (fountain coding: not a CC object):
# its chain ends in a body that calls the node-local rule unconditionally, so
# another node's object is refused by name.
NODE_LOCAL_ENTRIES = ("require_node_local_producer",)
VERDICTS = ("refuses", "edition2", "retired", "exempt", "composite", "substrate", "pending",
            "node_local")
SURFACES = ("trait", "pyo3", "capsule", "http")


def root() -> Path:
    # EARLIER_FORM_DOORS_ROOT: a fixture tree for --self-test. Otherwise the
    # checkout this script sits in — never another worktree.
    return Path(os.environ.get("EARLIER_FORM_DOORS_ROOT") or Path(__file__).resolve().parent.parent)


# ── stripping: comments, literals, test code ─────────────────────────────
def strip(text: str) -> str:
    """Every comment and literal blanked (newlines kept)."""
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
            blank(i, j)
            i = j
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c in "rb" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")) \
                and (raw := _raw_start(text, i)) is not None:
            hashes, j = raw
            close = '"' + "#" * hashes
            e = text.find(close, j)
            e = n if e == -1 else e + len(close)
            blank(i, e)
            i = e
        elif c == '"' or (c == "b" and text.startswith('b"', i)
                          and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_"))):
            j = i + (2 if c == "b" else 1)
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            blank(i, j + 1)
            i = j + 1
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
    j = i + 2 if text.startswith("br", i) else i + 1 if text[i] == "r" else None
    if j is None:
        return None
    k = j
    while k < len(text) and text[k] == "#":
        k += 1
    return (k - j, k + 1) if k < len(text) and text[k] == '"' else None


def _char_end(text: str, i: int) -> int:
    if text.startswith("'\\", i):
        e = text.find("'", i + 2)
        return e + 1 if e != -1 else i + 1
    if i + 2 < len(text) and text[i + 2] == "'" and text[i + 1] != "\n":
        return i + 3
    return i + 1


def brace_pairs(s: str) -> dict[int, int]:
    pairs, stack = {}, []
    for k, ch in enumerate(s):
        if ch == "{":
            stack.append(k)
        elif ch == "}" and stack:
            pairs[stack.pop()] = k
    return pairs


# Test code is any item under an attribute that compiles it ONLY under
# `cfg(test)`: `#[test]`, `#[tokio::test..]`, or `#[cfg(P)]` where P cannot
# hold with `test` false (`test`, `all(test, ..)`, `all(.., test)`,
# `any(test)`, ...). `cfg(any(test, feature = "x"))` compiles in production
# and is read as production. P is evaluated, not pattern-matched, so no
# spelling of a test-only cfg is missed; a cfg naming `test` that does not
# parse is refused (UnknownTestGate) rather than guessed.
TEST_FN_ATTR = re.compile(r"#\s*\[\s*(?:test|tokio\s*::\s*test\b[^\]]*)\s*\]")
CFG_ATTR = re.compile(r"#\s*\[\s*cfg\s*\(")
ANY_ATTR = re.compile(r"#\s*!?\s*\[")


class UnknownTestGate(Exception):
    pass


def _attr_end(code: str, k: int) -> int:
    """At `#`: the index after the attribute's closing `]`."""
    j = code.index("[", k)
    depth = 0
    while j < len(code):
        if code[j] == "[":
            depth += 1
        elif code[j] == "]":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return len(code)


def _cfg_can(pred: str) -> tuple[bool, bool]:
    """(can be true, can be false) of a cfg predicate with `test` false and
    every other atom free. Raises ValueError when it does not parse."""
    toks = re.findall(r"[A-Za-z_]\w*|[(),=]|\S", pred)
    pos = 0

    def node() -> tuple[bool, bool]:
        nonlocal pos
        if pos >= len(toks):
            raise ValueError("eof")
        t = toks[pos]
        pos += 1
        if t in ("all", "any", "not") and pos < len(toks) and toks[pos] == "(":
            pos += 1
            kids = []
            while toks[pos] != ")":
                kids.append(node())
                if toks[pos] == ",":
                    pos += 1
            pos += 1
            if t == "not":
                if len(kids) != 1:
                    raise ValueError("not/1")
                return kids[0][1], kids[0][0]
            if t == "all":
                return all(k[0] for k in kids), any(k[1] for k in kids) or not kids
            return any(k[0] for k in kids), all(k[1] for k in kids)
        if not re.fullmatch(r"[A-Za-z_]\w*", t):
            raise ValueError(t)
        if pos < len(toks) and toks[pos] == "=":
            pos += 1  # `feature = "x"`: the literal is blanked to nothing
            return True, True
        if t == "test":
            return False, True
        return True, True

    try:
        r = node()
    except (IndexError, ValueError) as e:
        raise ValueError(str(e)) from None
    if pos != len(toks):
        raise ValueError("trailing")
    return r


def test_attrs(code: str, path: str):
    """Yield (start, end) of every attribute that makes its item test-only."""
    for m in TEST_FN_ATTR.finditer(code):
        yield m.start(), m.end()
    for m in CFG_ATTR.finditer(code):
        end = _attr_end(code, m.start())
        inner = code[m.end():end].rstrip()
        inner = inner[:-1].rstrip()  # the attribute's `]`
        if not inner.endswith(")"):
            continue
        pred = inner[:-1]  # the cfg's `)`
        if not re.search(r"\btest\b", pred):
            continue
        try:
            can_true, _ = _cfg_can(pred)
        except ValueError:
            line = code.count("\n", 0, m.start()) + 1
            raise UnknownTestGate(
                f"{path}:{line}: a test cfg this gate cannot read: {' '.join(code[m.start():end].split())}")
        if not can_true:
            yield m.start(), end


def strip_tests(code: str, path: str) -> tuple[str, set[str]]:
    """`code` (already literal-stripped) with every test-gated item blanked;
    and the names of `mod x;` declarations that are test-gated (whole test
    files). Raises UnknownTestGate on a test cfg this gate cannot read."""
    # an inner `#![cfg(P)]` gates the whole file
    for m in re.finditer(r"#\s*!\s*\[\s*cfg\s*\(", code):
        outer = code[:m.start()] + "#" + " " * (code.index("[", m.start()) - m.start() - 1) + code[code.index("[", m.start()):]
        if any(a == m.start() for a, _ in test_attrs(outer, path)):
            return re.sub(r"[^\n]", " ", code), set()
    out = list(code)
    pairs = brace_pairs(code)
    test_mods: set[str] = set()
    for a_start, a_end in sorted(test_attrs(code, path)):
        k = a_end
        # past further attributes and whitespace to the item
        while True:
            while k < len(code) and code[k].isspace():
                k += 1
            if k < len(code) and code[k] == "#" and ANY_ATTR.match(code, k):
                k = _attr_end(code, k)
                continue
            break
        mm = re.match(r"(?:pub\s*(?:\([^)]*\))?\s*)?mod\s+([A-Za-z_]\w*)\s*;", code[k:])
        if mm:
            test_mods.add(mm.group(1))
        j, depth = k, 0
        while j < len(code):
            if code[j] in "([":
                depth += 1
            elif code[j] in ")]":
                depth -= 1
            elif code[j] in "{;" and depth == 0:
                break
            j += 1
        end = pairs.get(j, j) + 1 if j < len(code) and code[j] == "{" else j + 1
        for q in range(a_start, min(end, len(code))):
            if out[q] != "\n":
                out[q] = " "
    return "".join(out), test_mods


class Tree:
    """src/ under a root, each file stripped once (comments, literals, test
    code). A file whose `mod` is test-gated reads as empty."""

    def __init__(self, base: Path):
        self.base = base
        self._code: dict[str, str] = {}
        self._test_files: set[str] | None = None
        self._parent_mods: dict[str, tuple[None, set[str]]] = {}

    def _parent(self, rel: str) -> tuple[str, str] | None:
        """(the file that declares this module, the module's name)."""
        p = Path(rel)
        if p.name in ("lib.rs", "main.rs") and p.parent.as_posix() == "src":
            return None
        if p.name == "mod.rs":
            name, d = p.parent.name, p.parent.parent
        else:
            name, d = p.stem, p.parent
        if d.as_posix() == "src":
            for top in ("src/lib.rs", "src/main.rs"):
                if (self.base / top).is_file():
                    return top, name
            return None
        for cand in (d.with_suffix(".rs"), d / "mod.rs"):
            if (self.base / cand).is_file():
                return cand.as_posix(), name
        return None

    def is_test_file(self, rel: str) -> bool:
        """Is this file a module declared under a test-only cfg (or inside
        one)? Read from its declaring parent, up the module tree."""
        if self._test_files is None:
            self._test_files = set()
            self._not_test: set[str] = set()
        if rel in self._test_files:
            return True
        if rel in self._not_test:
            return False
        parent = self._parent(rel)
        test = False
        if parent is not None:
            prel, name = parent
            if self.is_test_file(prel):
                test = True
            else:
                raw = (self.base / prel).read_text(encoding="utf-8", errors="replace")
                _, mods = self._parent_mods.get(prel) or strip_tests(strip(raw), prel)
                self._parent_mods[prel] = (None, mods)
                test = name in mods
        (self._test_files if test else self._not_test).add(rel)
        return test

    def code(self, rel: str) -> str | None:
        if rel not in self._code:
            p = self.base / rel
            if not p.is_file():
                return None
            if self.is_test_file(rel):
                self._code[rel] = ""
            else:
                raw = p.read_text(encoding="utf-8", errors="replace")
                self._code[rel], _ = strip_tests(strip(raw), rel)
        return self._code[rel]

    def glob(self, pattern: str) -> list[str]:
        return sorted(p.relative_to(self.base).as_posix() for p in self.base.glob(pattern) if p.is_file())


# ── items ────────────────────────────────────────────────────────────────
FN_RE = re.compile(r"\bfn\s+([A-Za-z_]\w*)")


def block_body(code: str, header_at: int) -> tuple[int, int] | None:
    """The (start, end) of the `{ .. }` body after `header_at` (exclusive of
    the braces), or None when the item ends at `;` first."""
    k = header_at
    depth_paren = 0
    while k < len(code):
        ch = code[k]
        if ch in "([":
            depth_paren += 1
        elif ch in ")]":
            depth_paren -= 1
        elif ch == ";" and depth_paren == 0:
            return None
        elif ch == "{" and depth_paren == 0:
            end = brace_pairs_cached(code).get(k)
            return (k + 1, end) if end is not None else None
        k += 1
    return None


_PAIRS: dict[str, dict[int, int]] = {}


def brace_pairs_cached(code: str) -> dict[int, int]:
    if code not in _PAIRS:
        _PAIRS[code] = brace_pairs(code)
    return _PAIRS[code]


def fns_at_depth0(code: str, start: int, end: int):
    """Yield (name, header_index, body-or-None) for each fn defined directly
    inside code[start:end] (not nested in an inner block)."""
    depth = 0
    for m in re.finditer(r"[{}]|\bfn\s+([A-Za-z_]\w*)", code[start:end]):
        t = m.group(0)
        if t == "{":
            depth += 1
        elif t == "}":
            depth -= 1
        elif depth == 0:
            at = start + m.start()
            yield m.group(1), at, block_body(code, at)


def find_block(code: str, header: re.Pattern) -> tuple[int, int] | None:
    m = header.search(code)
    if not m:
        return None
    k = code.find("{", m.end() - 1)
    end = brace_pairs_cached(code).get(k)
    return (k + 1, end) if end is not None else None


def params_of(code: str, header_at: int) -> str:
    k = code.index("(", header_at)
    depth = 0
    for j in range(k, len(code)):
        if code[j] == "(":
            depth += 1
        elif code[j] == ")":
            depth -= 1
            if depth == 0:
                return code[k + 1:j]
    return code[k + 1:]


def fn_bodies(tree: Tree, rel: str, name: str) -> list[str]:
    """Every production body of `fn name` in `rel`; `Owner::name` limits it
    to fns inside a block (impl/trait/mod) whose owner is `Owner`."""
    code = tree.code(rel)
    if code is None:
        return []
    owner = None
    if "::" in name:
        owner, name = name.rsplit("::", 1)
        owner = owner.rsplit("::", 1)[-1]
    out = []
    if owner is None:
        for m in re.finditer(rf"\bfn\s+{re.escape(name)}\b", code):
            b = block_body(code, m.start())
            if b:
                out.append(code[b[0]:b[1]])
        return out
    for hm in re.finditer(rf"\b(?:impl\b[^{{;]*?\b{re.escape(owner)}\b[^{{;]*|(?:trait|mod)\s+{re.escape(owner)}\b[^{{;]*)\{{", code):
        k = hm.end() - 1
        end = brace_pairs_cached(code).get(k)
        if end is None:
            continue
        for fname, at, body in fns_at_depth0(code, k + 1, end):
            if fname == name and body:
                out.append(code[body[0]:body[1]])
    return out


def calls(body: str, name: str) -> bool:
    return re.search(rf"\b{re.escape(name)}\s*(?:::\s*<[^;{{}}]*?>\s*)?\(", body) is not None


def calls_at_top_level(body: str, names: tuple[str, ...]) -> bool:
    """A call of one of `names` at the body's own depth: not inside an inner
    `{ .. }` (an if / match / loop / closure / block) — an unconditional
    statement of the function."""
    depth = 0
    top = []
    for ch in body:
        if ch == "{":
            depth += 1
            top.append(" ")
        elif ch == "}":
            depth -= 1
            # a block that closes at the body's depth ends a statement
            top.append(";" if depth == 0 else " ")
        else:
            top.append(ch if depth == 0 else (" " if ch != "\n" else "\n"))
    flat = "".join(top)
    if any(calls(flat, n) for n in names):
        for n in names:
            for m in re.finditer(rf"\b{n}\s*\(", flat):
                stmt_start = max(flat.rfind(";", 0, m.start()), 0)
                stmt = flat[stmt_start:m.start()]
                # braces are already blanked, so an `if`/`match` branch
                # cannot reach here; a call in an `if` condition or a `match`
                # scrutinee runs unconditionally. What is still conditional
                # at this depth: a closure's body and a short-circuit operand.
                if re.search(r"\|[^|]*\|\s*$|&&|\|\|", stmt):
                    continue
                return True
    return False


# ── the inventory ────────────────────────────────────────────────────────
class Door:
    def __init__(self, surface: str, name: str, bodies: list[tuple[str, str]]):
        self.surface = surface
        self.name = name
        self.bodies = bodies  # (where, body text)


def trait_doors(tree: Tree, errors: list[str]) -> dict[str, Door]:
    doors: dict[str, Door] = {}
    for i, (trait_file, trait_name) in enumerate(TRAITS):
        for name, door in one_trait_doors(tree, errors, trait_file, trait_name, required=i == 0).items():
            if name in doors:
                errors.append(f"trait door `{name}` is a method of two inventoried traits; "
                              f"rename one (rows are keyed by name)")
            doors[name] = door
    return doors


def one_trait_doors(tree: Tree, errors: list[str], trait_file: str, trait_name: str,
                    required: bool) -> dict[str, Door]:
    code = tree.code(trait_file)
    if code is None:
        if required:
            errors.append(f"{trait_file}: missing")
        return {}
    span = find_block(code, re.compile(rf"\btrait\s+{trait_name}\b[^{{]*\{{"))
    if not span:
        errors.append(f"{trait_file}: no `trait {trait_name}`")
        return {}
    defaults: dict[str, str | None] = {}
    carrying: set[str] = set()
    for name, at, body in fns_at_depth0(code, *span):
        params = params_of(code, at)
        defaults[name] = code[body[0]:body[1]] if body else None
        if OBJECT_TYPES.search(params) or JSON_PARAM.search(params):
            carrying.add(name)
    if not carrying:
        return {}
    impls: list[tuple[str, dict[str, str]]] = []
    for rel, ty in BACKENDS:
        bcode = tree.code(rel)
        if bcode is None:
            errors.append(f"{rel}: missing")
            continue
        bspan = find_block(bcode, re.compile(rf"\bimpl\b[^{{;]*\b{trait_name}\s+for\s+{ty}\b[^{{]*\{{"))
        if not bspan:
            errors.append(f"{rel}: no `impl {trait_name} for {ty}`")
            continue
        impls.append((rel, {n: bcode[b[0]:b[1]] for n, _, b in fns_at_depth0(bcode, *bspan) if b}))
    doors = {}
    for name in sorted(carrying):
        bodies = []
        for rel, fns in impls:
            if name in fns:
                bodies.append((f"{rel}::{name}", fns[name]))
            elif defaults.get(name) is not None:
                bodies.append((f"{trait_file}::{trait_name}::{name} (default, not overridden in {rel})", defaults[name]))
            else:
                errors.append(f"trait {name}: {rel} neither overrides it nor has a default body to read")
        doors[name] = Door("trait", name, bodies)
    return doors


def pyo3_doors(tree: Tree, trait: dict[str, Door]) -> dict[str, Door]:
    found: list[tuple[str, str, str, str]] = []  # (owner, name, where, body)
    files = []
    for g in PYO3_FILES_GLOB:
        files += tree.glob(g)
    for rel in files:
        code = tree.code(rel)
        if not code:
            continue
        fns = []
        for m in re.finditer(r"#\s*\[\s*pymethods\s*\]", code):
            im = re.compile(r"\bimpl\b[^{;]*?\b([A-Za-z_]\w*)\s*(?:<[^{;]*>)?\s*\{").search(code, m.end())
            if not im:
                continue
            k = im.end() - 1
            end = brace_pairs_cached(code).get(k)
            if end:
                fns += [(im.group(1), n, at, b) for n, at, b in fns_at_depth0(code, k + 1, end)]
        for m in re.finditer(r"#\s*\[\s*pyfunction\b[^\]]*\]", code):
            fm = FN_RE.search(code, m.end())
            if fm:
                fns.append(("", fm.group(1), fm.start(), block_body(code, fm.start())))
        for owner, name, at, body in fns:
            if not body:
                continue
            text = code[body[0]:body[1]]
            params = params_of(code, at)
            hit = WRITE_VERB_JSON.match(name) \
                or EARLIER_FORM_VERIFIERS.search(text) \
                or (WRITE_SEGMENT.search(name) and JSON_PARAM.search(params)) \
                or OBJECT_TYPES.search(params) \
                or re.search(r"\bSigned[A-Z]\w*", text) \
                or any(re.search(rf"\.\s*{re.escape(d)}\s*\(", text) for d in trait)
            if hit:
                found.append((owner, name, f"{rel}::{name}", text))
    names = [n for _, n, _, _ in found]
    doors: dict[str, Door] = {}
    for owner, name, where, text in found:
        key = name if names.count(name) == 1 or not owner else f"{owner}::{name}"
        if key in doors:
            doors[key].bodies.append((where, text))
        else:
            doors[key] = Door("pyo3", key, [(where, text)])
    return doors


_ONE_PAT = r"\b" + CAPSULE_ENUM + r"\s*::\s*[A-Z]\w*\s*(?:\{[^{}]*\}|\([^()]*\))?"
ARM_RE = re.compile(rf"((?:{_ONE_PAT}\s*\|\s*)*{_ONE_PAT})\s*=>")


def capsule_dispatch_arms(code: str, errors: list[str]) -> list[tuple[str, set[str], str]]:
    """Every arm of the match in `fn CAPSULE_DISPATCH` (the op's door: other
    matches over the enum — a classifier, a proxy's constructor — are not),
    as (where, the variants its patterns name, its body)."""
    m = re.search(rf"\bfn\s+{CAPSULE_DISPATCH}\b", code)
    span = block_body(code, m.start()) if m else None
    if not span:
        errors.append(f"{CAPSULE_FILE}: no `fn {CAPSULE_DISPATCH}`")
        return []
    start, end = span
    out = []
    arms = list(ARM_RE.finditer(code, start, end))
    for i, am in enumerate(arms):
        pats = set(re.findall(rf"\b{CAPSULE_ENUM}\s*::\s*([A-Z]\w*)", am.group(1)))
        k = am.end()
        while k < end and code[k].isspace():
            k += 1
        if k < end and code[k] == "{":
            body = code[k + 1:brace_pairs_cached(code).get(k, end)]
        else:
            body = code[k:arms[i + 1].start() if i + 1 < len(arms) else end]
        names = "|".join(sorted(pats))
        out.append((f"{CAPSULE_FILE}::{CAPSULE_DISPATCH} arm {names}", pats, body))
    return out


def capsule_doors(tree: Tree, errors: list[str]) -> dict[str, Door]:
    code = tree.code(CAPSULE_FILE)
    if code is None:
        return {}
    span = find_block(code, re.compile(rf"\benum\s+{CAPSULE_ENUM}\b[^{{]*\{{"))
    if not span:
        errors.append(f"{CAPSULE_FILE}: no `enum {CAPSULE_ENUM}`")
        return {}
    body = code[span[0]:span[1]]
    variants: dict[str, str] = {}
    depth, cur, start = 0, None, 0
    for m in re.finditer(r"[{}()\[\]]|\b([A-Z][A-Za-z0-9_]*)\b", body):
        t = m.group(0)
        if t in "{([":
            depth += 1
        elif t in "})]":
            depth -= 1
        elif depth == 0 and m.group(1):
            if cur:
                variants[cur] = body[start:m.start()]
            cur, start = m.group(1), m.end()
    if cur:
        variants[cur] = body[start:]
    dispatch_arms = capsule_dispatch_arms(code, errors)
    doors = {}
    for v, fields in variants.items():
        if not OBJECT_TYPES.search(fields):
            continue
        arms = []
        for where, pats, body_text in dispatch_arms:
            if v in pats:
                arms.append((where, body_text))
        doors[v] = Door("capsule", v, arms)
    return doors


def http_doors(tree: Tree) -> dict[str, Door]:
    doors = {}
    files = tree.glob(SERVER_GLOB)
    for rel in files:
        code = tree.code(rel)
        if not code:
            continue
        for m in re.finditer(r"\b(post|put|patch|delete)\s*\(\s*([A-Za-z_][\w:]*)", code):
            handler = [p for p in m.group(2).split("::") if p][-1]
            if handler in doors:
                continue
            bodies = []
            for r2 in files:
                for b in fn_bodies(tree, r2, handler):
                    bodies.append((f"{r2}::{handler}", b))
            doors[handler] = Door("http", handler, bodies)
    return doors


def inventory(tree: Tree, errors: list[str]) -> dict[tuple[str, str], Door]:
    trait = trait_doors(tree, errors)
    inv = {("trait", k): v for k, v in trait.items()}
    inv.update({("pyo3", k): v for k, v in pyo3_doors(tree, trait).items()})
    inv.update({("capsule", k): v for k, v in capsule_doors(tree, errors).items()})
    inv.update({("http", k): v for k, v in http_doors(tree).items()})
    return inv


# ── the rows ─────────────────────────────────────────────────────────────
def read_rows(base: Path, errors: list[str]) -> dict[tuple[str, str], tuple[str, list[str], str]]:
    p = base / TSV
    if not p.is_file():
        errors.append(f"{TSV}: missing")
        return {}
    rows = {}
    for n, line in enumerate(p.read_text().splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) != 5:
            errors.append(f"{TSV}:{n}: want 5 tab-separated columns, got {len(cols)}")
            continue
        surface, door, verdict, route, note = (c.strip() for c in cols)
        if surface not in SURFACES:
            errors.append(f"{TSV}:{n}: surface {surface!r} is not one of {SURFACES}")
        if verdict not in VERDICTS:
            errors.append(f"{TSV}:{n}: verdict {verdict!r} is not one of {VERDICTS}")
        # `a > b | c > d`: two chains, and BOTH must hold (a door whose body
        # dispatches per backend names each backend's chain)
        hops = [[h.strip() for h in chain.split(">") if h.strip()] for chain in route.split("|")] \
            if route not in ("", "-") else []
        if any(not chain for chain in hops):
            errors.append(f"{TSV}:{n}: an empty chain in route {route!r}")
        if verdict == "exempt" and (hops or not note or note == "-"):
            errors.append(f"{TSV}:{n}: an exemption has no route and must say why in `note`")
        if verdict == "retired" and hops:
            errors.append(f"{TSV}:{n}: a retired door has no route")
        if verdict == "pending" and (hops or not re.search(r"\bowner:\s*\S", note)):
            errors.append(f"{TSV}:{n}: a pending door has no route and its note names `owner: <who>`")
        if (surface, door) in rows:
            errors.append(f"{TSV}:{n}: a second row for {surface} {door}")
        rows[(surface, door)] = (verdict, hops, note)
    return rows


def trait_doors_called(body: str, trait_names: set[str]) -> set[str]:
    return {d for d in trait_names if re.search(rf"(?:\.|::)\s*{re.escape(d)}\s*\(", body)}


def check_chain(tree: Tree, where: str, body: str, verdict: str, hops: list[str],
                verified: dict[str, bool], trait_names: set[str], errors: list[str],
                label: str, relax_first: bool = False) -> bool:
    """`relax_first`: a host surface (PyO3, capsule) wraps its dispatch in a
    closure or a per-backend `match`, so its OWN body's first call may sit
    anywhere in it; every later hop is held to the top-level rule."""
    terminals = REFUSALS if verdict == "refuses" \
        else COMPOSITE_ENTRIES if verdict == "composite" \
        else SUBSTRATE_ENTRIES if verdict == "substrate" \
        else NODE_LOCAL_ENTRIES if verdict == "node_local" else EDITION2_ENTRIES
    cur_where, cur_bodies = where, [body]

    def called(b: str, name: str, first: bool) -> bool:
        relaxed = (first and relax_first) or cur_where.startswith(DISPATCH_LAYERS)
        return calls(b, name) if relaxed else calls_at_top_level(b, (name,))

    for i, hop in enumerate(hops):
        first = i == 0
        if hop == "trait:*":
            for b in cur_bodies:
                doors = trait_doors_called(b, trait_names)
                if not doors:
                    errors.append(f"{label}: {cur_where} calls no inventoried trait door")
                    return False
                bad = sorted(d for d in doors if not verified.get(d))
                if bad:
                    errors.append(f"{label}: {cur_where} calls trait door(s) {', '.join(bad)}, "
                                  f"which this gate does not verify as refusing")
                    return False
            return True
        if hop.startswith("trait:"):
            door = hop[len("trait:"):]
            if not all(called(b, door, first) for b in cur_bodies):
                errors.append(f"{label}: {cur_where} does not call `{door}(`")
                return False
            if not verified.get(door):
                errors.append(f"{label}: routes through trait door `{door}`, which this gate does not verify as refusing")
                return False
            return True
        if ".rs::" not in hop:
            errors.append(f"{label}: hop {hop!r} is neither `path.rs::fn`, `trait:<door>` nor `trait:*`")
            return False
        rel, fn = hop.split(".rs::", 1)
        rel = (rel if rel.startswith("src/") else "src/" + rel) + ".rs"
        callee = fn.rsplit("::", 1)[-1]
        for b in cur_bodies:
            if not called(b, callee, first):
                how = "" if (first and relax_first) or cur_where.startswith(DISPATCH_LAYERS) \
                    else " unconditionally (at its body's top level)"
                errors.append(f"{label}: {cur_where} does not call `{callee}(`{how}")
                return False
        nxt = fn_bodies(tree, rel, fn)
        if not nxt:
            errors.append(f"{label}: no production `fn {fn}` in {rel}")
            return False
        cur_where, cur_bodies = f"{rel}::{fn}", nxt
    for b in cur_bodies:
        if verdict in ("refuses", "substrate", "node_local"):
            # the refusal itself is never relaxed: a host door that refuses in
            # its own body refuses before its closure, not inside a branch
            ok = calls_at_top_level(b, terminals)
        else:
            ok = any(calls(b, t) for t in terminals)
        if not ok:
            what = "call `refuse_earlier_form(_row)(` unconditionally (at its body's top level)" \
                if verdict == "refuses" \
                else "call `substrate_form(` unconditionally (at its body's top level)" \
                if verdict == "substrate" \
                else "call `require_node_local_producer(` unconditionally (at its body's top level)" \
                if verdict == "node_local" else f"call one of {', '.join(terminals)}"
            errors.append(f"{label}: {cur_where} does not {what}")
            return False
        if verdict == "composite":
            earlier = sorted({m.group(0).split("(")[0].strip() for m in EARLIER_FORM_VERIFIERS.finditer(b)})
            if earlier:
                errors.append(f"{label}: {cur_where} is `composite` but still calls an earlier-form "
                              f"verifier ({', '.join(earlier)})")
                return False
    return True


def check_retired(where: str, body: str, trait_names: set[str], errors: list[str], label: str) -> bool:
    """A retired door refuses every input with a named retirement
    (`EnvelopeKindRetired`, or `Unsupported` naming the retired method), and
    reads nothing: it parses no object, calls
    no verifier and no trait door."""
    if not re.search(r"\bEnvelopeKindRetired\b|\bUnsupported\s*\{", body):
        errors.append(f"{label}: {where} does not refuse with `EnvelopeKindRetired` / `Unsupported`")
        return False
    reads = [n for n in ("from_str", "from_value", "from_slice") if calls(body, n)]
    reads += [m.group(0) for m in EARLIER_FORM_VERIFIERS.finditer(body)]
    reads += [d for d in trait_names if re.search(rf"\.\s*{re.escape(d)}\s*\(", body)]
    if reads:
        errors.append(f"{label}: {where} is `retired` but still reads its object ({', '.join(sorted(set(reads)))})")
        return False
    return True


def switch_is_shut(base: Path) -> bool | None:
    """The production value of `EARLIER_FORM_DOORS_SHUT`, or None."""
    p = base / SWITCH_FILE
    if not p.is_file():
        return None
    code, _ = strip_tests(strip(p.read_text(encoding="utf-8", errors="replace")), SWITCH_FILE)
    m = re.search(r"\bconst\s+EARLIER_FORM_DOORS_SHUT\s*:\s*bool\s*=\s*(true|false)\s*;", code)
    return None if not m else m.group(1) == "true"


def cp2_markers(base: Path) -> list[tuple[str, int, str]]:
    """Every `#[ignore = "v62-CP2…"]` ATTRIBUTE (not a comment) in src/ and
    tests/: (path, line, the attribute text)."""
    out = []
    for top in ("src", "tests"):
        for p in sorted((base / top).rglob("*.rs")):
            raw = p.read_text(encoding="utf-8", errors="replace")
            if "v62-CP2" not in raw:
                continue
            code = strip(raw)
            rel = p.relative_to(base).as_posix()
            for m in CP2_ANY.finditer(raw):
                # a comment is blanked whole; a live attribute keeps `#[ignore`
                if re.match(r"#\s*\[\s*ignore", code[m.start():m.end()]):
                    out.append((rel, raw.count("\n", 0, m.start()) + 1, m.group(0)))
    return out


def cp2_errors(base: Path) -> list[str]:
    errors = []
    shut = switch_is_shut(base)
    if shut is None:
        return [f"{SWITCH_FILE}: no `const EARLIER_FORM_DOORS_SHUT: bool = true|false;` to read"]
    for rel, line, text in cp2_markers(base):
        if CP2_REWRITE.fullmatch(text):
            continue  # the bridge; `release-check` refuses it
        if text != CP2_IGNORE:
            errors.append(f"{rel}:{line}: a CP2 ignore not spelled exactly {CP2_IGNORE} "
                          f'nor `#[ignore = "v62-CP2 rewrite pending: <owner> …"]`: {text}')
        elif shut:
            errors.append(f"{rel}:{line}: {CP2_IGNORE} remains with the doors shut: "
                          f"run `earlier_form_doors.py unignore`")
    if shut:
        errors += earlier_form_wrapper_errors(base)
    return errors


EF_CALL = re.compile(r"\bwith_earlier_form(_async|_doors_shut)?\s*\(")
EF_TAG = re.compile(r"//\s*CP2 (skeleton|held):")


def earlier_form_wrapper_errors(base: Path) -> list[str]:
    """With the switch on, every fixture call that turns the earlier form back
    on must say why it is still there: `// CP2 skeleton: ...` (an unsigned
    shape re-signed as edition 2 before any door) or `// CP2 held: ...` (in a
    test ignored `#[ignore = "v62: ..."]`), in the comment block right above
    the call. `with_earlier_form_doors_shut` is gone with the open state it
    forced shut; a call to it is red."""
    errors = []
    for top in ("src", "tests"):
        for p in sorted((base / top).rglob("*.rs")):
            rel = p.relative_to(base).as_posix()
            if rel.endswith("edition2/fixture_switch.rs"):
                continue
            raw = p.read_text(encoding="utf-8", errors="replace")
            if "with_earlier_form" not in raw:
                continue
            code = strip(raw)
            lines = raw.split("\n")
            for m in EF_CALL.finditer(code):
                if re.search(r"\bfn\s*$", code[max(0, m.start() - 10):m.start()]):
                    continue  # a definition, not a call
                ln = code.count("\n", 0, m.start()) + 1
                if m.group(1) == "_doors_shut":
                    errors.append(f"{rel}:{ln}: `with_earlier_form_doors_shut` is gone with the flip; "
                                  f"the switch is on, so call the door directly")
                    continue
                k = ln - 2
                tag = None
                block = []
                while k >= 0 and lines[k].strip().startswith("//"):
                    block.append(lines[k])
                    t = EF_TAG.search(lines[k])
                    tag = t.group(1) if t else tag
                    k -= 1
                if tag is None:
                    errors.append(f"{rel}:{ln}: an earlier-form fixture scope with the doors shut: "
                                  f"delete the witness, or tag it `// CP2 skeleton:` / `// CP2 held:`")
                    continue
                if tag != "held":
                    continue
                named = HELD_RUNNERS.search(" ".join(reversed(block)))
                if named:
                    # A shared body held by its runners in another file: every
                    # runner named must be an ignored test somewhere.
                    for fn in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", named.group(1)):
                        if fn not in ignored_fns(base):
                            errors.append(f"{rel}:{ln}: `// CP2 held:` names runner `{fn}`, "
                                          f'which is not a test ignored `#[ignore = "v62: ..."]`')
                elif not IGNORE_V62.search(raw):
                    errors.append(f"{rel}:{ln}: `// CP2 held:` in a file with no "
                                  f'`#[ignore = "v62: ..."]` test (or name its runners: `runners: a, b`)')
    return errors


HELD_RUNNERS = re.compile(r"\brunners:\s*([A-Za-z0-9_,\s]+?)\s*(?:\.|//|$)")
IGNORE_V62 = re.compile(r'#\s*\[\s*ignore\s*=\s*"v62(: |-CP2 rewrite pending: )')
_IGNORED: dict = {}


def ignored_fns(base: Path) -> set:
    """Every fn under src/ and tests/ whose attribute run carries a v62 ignore."""
    key = str(base)
    if key not in _IGNORED:
        found = set()
        for top in ("src", "tests"):
            for p in sorted((base / top).rglob("*.rs")):
                raw = p.read_text(encoding="utf-8", errors="replace")
                if "v62" not in raw:
                    continue
                for m in re.finditer(r"((?:^[ \t]*#\[[^\n]*\]\s*\n)+)[ \t]*(?:pub(?:\([^)]*\))?\s+)?"
                                     r"(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)", raw, re.M):
                    if IGNORE_V62.search(m.group(1)):
                        found.add(m.group(2))
        _IGNORED[key] = found
    return _IGNORED[key]


def release_check(base: Path) -> int:
    """The release gate: v62.0 cannot tag with a held owner rewrite. Every
    `#[ignore = "v62-CP2 rewrite pending: <owner> …"]` left in src/ or tests/
    is red here (and only here: `check` allows the bridge)."""
    left = [(r, n, t) for r, n, t in cp2_markers(base) if CP2_REWRITE.fullmatch(t)]
    for rel, line, text in left:
        print(f"RED  {rel}:{line}: {text}: the owner's edition-2 rewrite has not landed")
    # v62.0.0 (F0-cp6c) — a `pending` door row is a known earlier-form door
    # awaiting its owner's migration: no release with one left.
    pending = [(k, v) for k, v in read_rows(base, []).items() if v[0] == "pending"]
    for (surface, door), (_, _, note) in pending:
        print(f"RED  {TSV}: {surface} `{door}` is pending its migration ({note})")
    n = len(left) + len(pending)
    print("GREEN: no v62-CP2 rewrite or door pending" if not n else f"RED: {n} pending")
    return 0 if not n else 1


def unignore(base: Path) -> int:
    if switch_is_shut(base) is not True:
        print(f"refused: {SWITCH_FILE} does not set EARLIER_FORM_DOORS_SHUT = true; "
              f"the CP2 ignores stay until the switch flips")
        return 1
    removed = 0
    by_file: dict[str, list[int]] = {}
    for rel, line, text in cp2_markers(base):
        if text == CP2_IGNORE:
            by_file.setdefault(rel, []).append(line)
    for rel, lines in by_file.items():
        p = base / rel
        L = p.read_text(encoding="utf-8").split("\n")
        for n in sorted(lines, reverse=True):
            if L[n - 1].strip() != CP2_IGNORE:
                print(f"refused: {rel}:{n} holds more than the attribute; remove it by hand")
                return 1
            del L[n - 1]
            removed += 1
        p.write_text("\n".join(L), encoding="utf-8")
        print(f"{rel}: removed {len(lines)}")
    print(f"unignore: {removed} CP2 ignore(s) removed")
    return 0


# v62.0.0 (F0-cp7; RULINGS "composite signatures only, no standalone
# component signers") — a STANDALONE component verify in production code: the
# bound-hybrid family, a raw Ed25519 / ML-DSA-65 verifier, or an Ed25519 key
# built to check a signature. A composite is checked by
# `CompositePublicKey::verify` (`composite_verify`, `sig19`) and is not matched.
LONE_VERIFY = re.compile(
    r"\b(?:verify_hybrid|verify_hybrid_via_directory|verify_hybrid_with_policy|"
    r"verify_trace_hybrid|verify_ed25519_only_with_policy)\s*\("
    r"|\b(?:HybridVerifier|Ed25519Verifier|MlDsa65Verifier|MlDsa65SoftwareVerifier)\b"
    r"|\.verify_strict\s*\("
    r"|\bed25519_dalek::Verifier\b"
)
# The deliberate standalone verifies, each with why. Nothing else may verify a
# lone component (the media chunk trailer, CC 5.3.3.5, is Edge's).
LONE_VERIFY_ALLOWED = {
    "src/audit/verify.rs":
        "an audit entry's INNER Ed25519 signature by a local actor whose actor_id IS the "
        "Ed25519 key, over bytes no other node verifies (CC 1.13.4; the served gate is the "
        "composite-signed head); not an edition-2 key's half",
    "src/federation/edition2/receipts.rs":
        "SCITT receipts (RFC 9942) under a trusted transparency service's own COSE key; not a "
        "CIRIS identity's component",
}


def lone_verify_errors(tree: "Tree") -> list[str]:
    """Every production standalone component verify outside
    [`LONE_VERIFY_ALLOWED`] is red; an allow-list entry whose file no longer
    holds one is red too (stale)."""
    errors = []
    found: set[str] = set()
    for rel in tree.glob("src/**/*.rs"):
        code = tree.code(rel)
        if not code:
            continue
        for m in LONE_VERIFY.finditer(code):
            if rel in LONE_VERIFY_ALLOWED:
                found.add(rel)
                continue
            line = code.count("\n", 0, m.start()) + 1
            errors.append(f"{rel}:{line}: a standalone component verify (`{m.group(0).strip()}`): "
                          f"v62 verifies ONE composite (composite_verify / sig19); a lone "
                          f"Ed25519 or ML-DSA-65 half, or the bound-hybrid pair, never verifies")
    for rel in sorted(set(LONE_VERIFY_ALLOWED) - found):
        if tree.code(rel) is not None:
            errors.append(f"{rel}: in LONE_VERIFY_ALLOWED but holds no standalone verify; "
                          f"remove the entry")
    return errors


def check(base: Path) -> tuple[list[str], dict]:
    try:
        return _check(base)
    except UnknownTestGate as e:
        # a file this gate reads holds a test cfg it cannot evaluate: it
        # cannot tell that file's test code from its production code
        return [str(e)], {}


def _check(base: Path) -> tuple[list[str], dict]:
    errors: list[str] = cp2_errors(base)
    tree = Tree(base)
    errors += lone_verify_errors(tree)
    inv = inventory(tree, errors)
    rows = read_rows(base, errors)
    for key in sorted(set(inv) - set(rows)):
        errors.append(f"UNCLASSIFIED {key[0]} door `{key[1]}`: add a row to {TSV} "
                      f"(refuses with its route, edition2, or exempt with why)")
    for key in sorted(set(rows) - set(inv)):
        errors.append(f"STALE row {key[0]} `{key[1]}`: the inventory finds no such door")
    verified: dict[str, bool] = {}
    # trait doors first: pyo3 / capsule rows may route through them, and a
    # trait door may route through another (`trait:put_attestation_with_origin`)
    order = sorted(inv, key=lambda k: (SURFACES.index(k[0]), k[1]))
    trait_names = {k[1] for k in inv if k[0] == "trait"}
    pending = [k for k in order if k[0] == "trait"]
    for _ in range(len(pending) + 1):
        progressed = False
        for key in list(pending):
            if key not in rows:
                pending.remove(key)
                continue
            verdict, hops, _ = rows[key]
            deps = {h[6:] for chain in hops for h in chain if h.startswith("trait:") and h != "trait:*"}
            if any("trait:*" in chain for chain in hops):
                deps |= {d for _, b in inv[key].bodies for d in trait_doors_called(b, trait_names)}
            deps.discard(key[1])
            if any(("trait", d) in pending for d in deps):
                continue
            pending.remove(key)
            progressed = True
            ok = verdict in ("exempt", "pending")
            trait_names = {k[1] for k in inv if k[0] == "trait"}
            if verdict == "retired":
                ok = bool(inv[key].bodies) and all(
                    check_retired(w, b, trait_names, errors, f"trait `{key[1]}`") for w, b in inv[key].bodies)
            elif verdict not in ("exempt", "pending"):
                door = inv[key]
                ok = bool(door.bodies) and all(
                    check_chain(tree, w, b, verdict, chain, verified, trait_names, errors, f"trait `{key[1]}`")
                    for w, b in door.bodies for chain in (hops or [[]]))
            verified[key[1]] = ok and verdict in ("refuses", "edition2", "retired", "composite", "substrate",
                                                  "node_local")
        if not progressed:
            break
    for key in pending:
        errors.append(f"trait `{key[1]}`: its route cycles through trait doors")
    for key in order:
        if key[0] == "trait" or key not in rows:
            continue
        verdict, hops, _ = rows[key]
        if verdict in ("exempt", "pending"):
            continue
        door = inv[key]
        if not door.bodies:
            errors.append(f"{key[0]} `{key[1]}`: no body found to read")
            continue
        trait_names = {k[1] for k in inv if k[0] == "trait"}
        label = f"{key[0]} `{key[1]}`"
        for w, b in door.bodies:
            if verdict == "retired":
                check_retired(w, b, trait_names, errors, label)
                continue
            for chain in hops or [[]]:
                check_chain(tree, w, b, verdict, chain, verified, trait_names, errors, label,
                            relax_first=key[0] in ("pyo3", "capsule"))
            # whatever its route, a host door that reaches a trait door
            # reaches it as the door's caller: every trait door it calls must
            # itself refuse (an exempt row is the only way past this)
            bad = sorted(d for d in trait_doors_called(b, trait_names) if not verified.get(d))
            if bad:
                errors.append(f"{label}: {w} calls trait door(s) {', '.join(bad)}, "
                              f"which this gate does not verify as refusing")
    return errors, {"inventory": inv, "rows": rows}


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if argv == ["unignore"]:
        return unignore(root())
    if argv == ["release-check"]:
        return release_check(root())
    if argv not in (["check"], ["list"]):
        print(__doc__.split("\n\n")[1])
        return 2
    base = root()
    print(f"root: {base}")
    errors, data = check(base)
    if argv == ["list"]:
        rows = data.get("rows", {})
        for key in sorted(data.get("inventory", {}), key=lambda k: (SURFACES.index(k[0]), k[1])):
            r = rows.get(key)
            print(f"{key[0]:8} {key[1]:55} {r[0] if r else 'UNCLASSIFIED':9} {' > '.join(r[1]) if r else ''}")
    counts = {s: sum(1 for k in data.get("inventory", {}) if k[0] == s) for s in SURFACES}
    print("doors: " + ", ".join(f"{s} {n}" for s, n in counts.items()))
    for e in errors:
        print(f"RED  {e}")
    print("GREEN" if not errors else f"RED: {len(errors)}")
    return 0 if not errors else 1


# ── self-test ────────────────────────────────────────────────────────────
FIX_MOD = """\
pub mod door_x;
#[cfg(test)]
mod some_invariants;
pub trait FederationDirectory: Send + Sync {
    /// a door that takes a `SignedFamily` — the doc names no call
    async fn put_family(&self, family: SignedFamily) -> Result<(), Error>;
    async fn put_attestation(&self, a: SignedAttestation) -> Result<(), Error> {
        self.put_attestation_with_origin(a, WriteOrigin::Wire).await
    }
    async fn put_attestation_with_origin(&self, a: SignedAttestation, o: WriteOrigin) -> Result<(), Error>;
    async fn put_statement_bytes(&self, json_bytes: &[u8]) -> Result<(), Error>;
    async fn put_local_note(&self, note: &str) -> Result<(), Error>;
    async fn list_families(&self) -> Result<Vec<SignedFamily>, Error>;
}
"""
FIX_DOOR = """\
pub(crate) async fn plan_family(f: SignedFamily) -> Result<(), Error> {
    super::edition2::door::refuse_earlier_form("family")?;
    let _ = verify(f)?;
    Ok(())
}
pub(crate) async fn put_attestation_planned(a: SignedAttestation) -> Result<(), Error> {
    super::edition2::door::refuse_earlier_form_row("attestation", &a.attestation)?;
    Ok(())
}
pub(crate) async fn statement_entry(b: &[u8]) -> Result<(), Error> {
    put_statement(b).await
}
#[cfg(test)]
mod tests {
    // a test fn of the same name that refuses must not make the door green
    fn plan_other() { refuse_earlier_form("x"); }
}
"""
FIX_SQLITE = """\
impl crate::federation::FederationDirectory for SqliteBackend {
    async fn put_family(&self, family: SignedFamily) -> Result<(), Error> {
        crate::federation::door_x::plan_family(family).await
    }
    async fn put_attestation_with_origin(&self, a: SignedAttestation, o: WriteOrigin) -> Result<(), Error> {
        crate::federation::door_x::put_attestation_planned(a).await
    }
    async fn put_statement_bytes(&self, json_bytes: &[u8]) -> Result<(), Error> {
        crate::federation::door_x::statement_entry(json_bytes).await
    }
    async fn put_local_note(&self, note: &str) -> Result<(), Error> { Ok(()) }
    async fn list_families(&self) -> Result<Vec<SignedFamily>, Error> { Ok(vec![]) }
}
"""
# v62.0.0 (F0-cp6c) — a second door trait, its impls on both backends.
FIX_BLOBS = "pub trait BlobStorage: Send + Sync {\n    async fn put_claim(&self, c: PutBlobAttestation) -> Result<(), BlobError>;\n    fn cap(&self) -> usize;\n}\n"
FIX_BLOBS_IMPL = "\nimpl crate::federation::BlobStorage for SqliteBackend {\n    async fn put_claim(&self, c: PutBlobAttestation) -> Result<(), BlobError> { store(c).await }\n    fn cap(&self) -> usize { 1 }\n}\n"
FIX_PYO3 = """\
#[pymethods]
impl PyEngine {
    fn put_family_json(&self, family_json: &str) -> PyResult<()> {
        let f: SignedFamily = serde_json::from_str(family_json)?;
        self.dir.put_family(f)
    }
    fn get_thing(&self) -> PyResult<()> { Ok(()) }
}
"""
FIX_CAPSULE = """\
pub enum DirectoryOp {
    PutFamily { family: SignedFamily },
    ApplyReplicatedKeyRecord { record: SignedKeyRecord },
    ListFamilies,
}
async fn dispatch_directory_op(dir: &dyn FederationDirectory, op: DirectoryOp) -> DirectoryOpResult {
    match op {
        DirectoryOp::PutFamily { family } => match dir.put_family(family).await {
            Ok(()) => DirectoryOpResult::Unit,
            Err(e) => DirectoryOpResult::Err(e.to_string()),
        },
        DirectoryOp::ApplyReplicatedKeyRecord { record } => {
            let _ = record;
            DirectoryOpResult::Err(Error::EnvelopeKindRetired { kind: EnvelopeKind::Key }.to_string())
        }
        DirectoryOp::ListFamilies => DirectoryOpResult::Unit,
    }
}
"""
FIX_SERVER = """\
pub fn router() -> Router {
    Router::new()
        .route("/a", post(post_ingest::<F>))
        .route("/s", post(post_signed::<F>))
        .route("/u", post(post_substrate::<F>))
        .route("/l", post(post_local::<F>))
        .route("/h", get(get_health::<F>))
}
async fn post_ingest(body: Bytes) -> Response { verify_request(body) }
async fn post_signed(body: Bytes) -> Response { verify_composite_via_directory(d, &body, k, &s, 0).await }
async fn post_local(body: Bytes) -> Response {
    fountain::require_node_local_producer(&m, me)?;
    store(body)
}
async fn post_substrate(body: Bytes) -> Response {
    let form = substrate::substrate_form(SubstratePlane::AuditEntry);
    verify_inner(body)
}
"""
FIX_SWITCH = "pub const EARLIER_FORM_DOORS_SHUT: bool = {};\n"
FIX_PARKED = """\
#[cfg(test)]
mod tests {{
    #[tokio::test]
    {marker}
    async fn needs_the_doors_shut() {{}}
    // {CP2} in a comment is not an attribute
}}
"""
CP2 = '#[ignore = "v62-CP2: needs EARLIER_FORM_DOORS_SHUT"]'
FIX_TSV = """\
# surface\tdoor\tverdict\troute\tnote
trait\tput_family\trefuses\tfederation/door_x.rs::plan_family\t-
trait\tput_attestation\trefuses\ttrait:put_attestation_with_origin\t-
trait\tput_attestation_with_origin\trefuses\tfederation/door_x.rs::put_attestation_planned\t-
trait\tput_statement_bytes\tedition2\tfederation/door_x.rs::statement_entry\t-
pyo3\tput_family_json\trefuses\ttrait:put_family\t-
capsule\tPutFamily\trefuses\ttrait:put_family\t-
capsule\tApplyReplicatedKeyRecord\tretired\t-\t-
http\tpost_ingest\texempt\t-\trequest auth, not a CEG row
http\tpost_signed\tcomposite\t-\t-
http\tpost_substrate\tsubstrate\t-\t-
http\tpost_local\tnode_local\t-\t-
"""


def _write_fixture(d: Path, overrides: dict[str, str] | None = None) -> None:
    files = {
        "src/federation/mod.rs": FIX_MOD,
        "src/federation/door_x.rs": FIX_DOOR,
        "src/federation/some_invariants.rs": "fn put_x(j: SignedFamily) { }\n",
        "src/store/sqlite.rs": FIX_SQLITE,
        "src/store/postgres.rs": FIX_SQLITE.replace("SqliteBackend", "PostgresBackend"),
        "src/ffi/pyo3.rs": FIX_PYO3,
        "src/ffi/directory_capsule.rs": FIX_CAPSULE,
        "src/server/mod.rs": FIX_SERVER,
        SWITCH_FILE: FIX_SWITCH.format("false"),
        TSV: FIX_TSV,
    }
    files.update(overrides or {})
    for rel, text in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def self_test() -> int:
    cases: list[tuple[str, dict[str, str], str | None]] = [
        ("the fixture is green", {}, None),
        # every negative names the substring its red must carry: a red for
        # the wrong reason is not this case's witness
        ("a new object door with no row is red",
         {"src/federation/mod.rs": FIX_MOD.replace(
             "    async fn put_local_note",
             "    async fn put_widening(&self, w: SignedFamilyWidening) -> Result<(), Error> { Ok(()) }\n"
             "    async fn put_local_note")},
         "UNCLASSIFIED trait door `put_widening`"),
        ("a door taking `*_json: &str` is inventoried",
         {"src/federation/mod.rs": FIX_MOD.replace(
             "    async fn put_local_note",
             "    async fn put_thing(&self, thing_json: &str) -> Result<(), Error> { Ok(()) }\n"
             "    async fn put_local_note")},
         "UNCLASSIFIED trait door `put_thing`"),
        ("the refusal removed from the planned door is red",
         {"src/federation/door_x.rs": FIX_DOOR.replace(
             '    super::edition2::door::refuse_earlier_form("family")?;\n', "")},
         "door_x.rs::plan_family does not call `refuse_earlier_form(_row)(` unconditionally"),
        ("the refusal in a comment is red",
         {"src/federation/door_x.rs": FIX_DOOR.replace(
             '    super::edition2::door::refuse_earlier_form("family")?;',
             '    // super::edition2::door::refuse_earlier_form("family")?;')},
         "plan_family does not call `refuse_earlier_form"),
        ("the refusal in a string is red",
         {"src/federation/door_x.rs": FIX_DOOR.replace(
             '    super::edition2::door::refuse_earlier_form("family")?;',
             '    let _ = "refuse_earlier_form(";')},
         "plan_family does not call `refuse_earlier_form"),
        ("the refusal under an `if` is red",
         {"src/federation/door_x.rs": FIX_DOOR.replace(
             '    super::edition2::door::refuse_earlier_form("family")?;',
             '    if f.is_json() { super::edition2::door::refuse_earlier_form("family")?; }')},
         "plan_family does not call `refuse_earlier_form"),
        ("the refusal behind `&&` is red",
         {"src/federation/door_x.rs": FIX_DOOR.replace(
             '    super::edition2::door::refuse_earlier_form("family")?;',
             '    let _ = f.is_json() && super::edition2::door::refuse_earlier_form("family").is_err();')},
         "plan_family does not call `refuse_earlier_form"),
        ("the refusal inside a closure is red",
         {"src/federation/door_x.rs": FIX_DOOR.replace(
             '    super::edition2::door::refuse_earlier_form("family")?;',
             '    let r = || super::edition2::door::refuse_earlier_form("family");')},
         "plan_family does not call `refuse_earlier_form"),
        ("a host door whose `trait:*` reaches an exempt trait door is red",
         {TSV: FIX_TSV.replace("pyo3\tput_family_json\trefuses\ttrait:put_family", "pyo3\tput_family_json\trefuses\ttrait:*")
                      .replace("trait\tput_family\trefuses\tfederation/door_x.rs::plan_family\t-", "trait\tput_family\texempt\t-\tno")},
         "calls trait door(s) put_family, which this gate does not verify"),
        ("every `|` chain must hold",
         {TSV: FIX_TSV.replace("pyo3\tput_family_json\trefuses\ttrait:put_family",
                               "pyo3\tput_family_json\trefuses\ttrait:put_family | trait:put_attestation")},
         "pyo3 `put_family_json`: src/ffi/pyo3.rs::put_family_json does not call `put_attestation(`"),
        ("a refusal only in a #[cfg(test)] fn of the routed name is red",
         {"src/federation/door_x.rs": FIX_DOOR.replace(
             "pub(crate) async fn plan_family", "pub(crate) async fn plan_family_old").replace(
             "mod tests {", "mod tests {\n    fn plan_family() { refuse_earlier_form(\"family\"); }")},
         "no production `fn plan_family`"),
        ("a refusal only in a #[cfg(all(test, ..))] fn is red",
         {"src/federation/door_x.rs": FIX_DOOR.replace(
             "pub(crate) async fn plan_family", "#[cfg(all(test, feature = \"sqlite\"))]\npub(crate) async fn plan_family")},
         "no production `fn plan_family`"),
        ("a refusal only in a #[tokio::test] fn is red",
         {"src/federation/door_x.rs": FIX_DOOR.replace(
             "pub(crate) async fn plan_family", "#[tokio::test(flavor = \"multi_thread\")]\npub(crate) async fn plan_family")},
         "no production `fn plan_family`"),
        ("a refusal only under #[cfg(all(feature = .., test))] is test code",
         {"src/federation/door_x.rs": FIX_DOOR.replace(
             "pub(crate) async fn plan_family", "#[cfg(all(feature = \"sqlite\", not(miri), test))]\npub(crate) async fn plan_family")},
         "no production `fn plan_family`"),
        ("a refusal only under #[cfg(any(test))] is test code",
         {"src/federation/door_x.rs": FIX_DOOR.replace(
             "pub(crate) async fn plan_family", "#[cfg(any(test))]\npub(crate) async fn plan_family")},
         "no production `fn plan_family`"),
        ("#[cfg(any(test, feature = ..))] is production",
         {"src/federation/door_x.rs": FIX_DOOR.replace(
             "pub(crate) async fn plan_family", "#[cfg(any(test, feature = \"sqlite\"))]\npub(crate) async fn plan_family")},
         None),
        ("#[cfg(not(test))] is production",
         {"src/federation/door_x.rs": FIX_DOOR.replace(
             "pub(crate) async fn plan_family", "#[cfg(not(test))]\npub(crate) async fn plan_family")},
         None),
        ("a file under #![cfg(test)] is test code",
         {"src/federation/door_x.rs": "#![cfg(test)]\n" + FIX_DOOR},
         "no production `fn plan_family`"),
        ("a test cfg that does not parse is red",
         {"src/federation/door_x.rs": "#[cfg(all(test,, ))]\nfn x() {}\n" + FIX_DOOR},
         "a test cfg this gate cannot read"),
        ("one backend that skips the hop is red",
         {"src/store/postgres.rs": FIX_SQLITE.replace("SqliteBackend", "PostgresBackend").replace(
             "crate::federation::door_x::plan_family(family).await", "store_family(family).await")},
         "src/store/postgres.rs::put_family does not call `plan_family(`"),
        ("a backend override of a defaulted door is read, not the default",
         {"src/store/sqlite.rs": FIX_SQLITE.replace(
             "    async fn put_local_note",
             "    async fn put_attestation(&self, a: SignedAttestation) -> Result<(), Error> { store(a) }\n"
             "    async fn put_local_note")},
         "src/store/sqlite.rs::put_attestation does not call `put_attestation_with_origin(`"),
        ("a read that returns an object is not a door",
         {TSV: FIX_TSV + "trait\tlist_families\texempt\t-\ta read\n"},
         "STALE row trait `list_families`"),
        ("a stale row is red",
         {TSV: FIX_TSV + "trait\tput_gone\trefuses\t-\t-\n"},
         "STALE row trait `put_gone`"),
        ("an exemption without a reason is red",
         {TSV: FIX_TSV.replace("exempt\t-\trequest auth, not a CEG row", "exempt\t-\t-")},
         "an exemption has no route and must say why"),
        ("a pyo3 door that stops calling the trait door is red",
         {"src/ffi/pyo3.rs": FIX_PYO3.replace("self.dir.put_family(f)", "store_json(f)")},
         "pyo3 `put_family_json`: src/ffi/pyo3.rs::put_family_json does not call `put_family(`"),
        ("a pyo3 door routed through an exempt trait door is red",
         {TSV: FIX_TSV.replace("trait\tput_family\trefuses\tfederation/door_x.rs::plan_family\t-",
                               "trait\tput_family\texempt\t-\tno")},
         "which this gate does not verify as refusing"),
        ("a new capsule op carrying an object, unclassified, is red",
         {"src/ffi/directory_capsule.rs": FIX_CAPSULE.replace(
             "    ListFamilies,", "    ListFamilies,\n    PutRevocation { revocation: SignedRevocation },")},
         "UNCLASSIFIED capsule door `PutRevocation`"),
        ("a retired arm that starts reading its object again is red",
         {"src/ffi/directory_capsule.rs": FIX_CAPSULE.replace(
             "            let _ = record;", "            let _ = dir.put_family(record);")},
         "is `retired` but still reads its object (put_family)"),
        ("a retired arm that stops naming its retirement is red",
         {"src/ffi/directory_capsule.rs": FIX_CAPSULE.replace(
             "Error::EnvelopeKindRetired { kind: EnvelopeKind::Key }", "Error::Backend")},
         "does not refuse with `EnvelopeKindRetired`"),
        ("a classifier's arm over the same op is not its door",
         {"src/ffi/directory_capsule.rs": FIX_CAPSULE + "fn plane(op: &DirectoryOp) -> Option<&str> { match op { DirectoryOp::PutFamily { .. } | DirectoryOp::ListFamilies => Some(\"family\"), _ => None } }\n"},
         None),
        ("an op with no dispatch arm is red",
         {"src/ffi/directory_capsule.rs": FIX_CAPSULE.replace(
             "        DirectoryOp::PutFamily { family } => match", "        DirectoryOp::Other { family } => match")},
         "capsule `PutFamily`: no body found"),
        ("an arm under a `|` pattern is the door of each op it names",
         {"src/ffi/directory_capsule.rs": FIX_CAPSULE.replace(
             "        DirectoryOp::ApplyReplicatedKeyRecord { record } => {",
             "        DirectoryOp::ListFamilies | DirectoryOp::ApplyReplicatedKeyRecord { record } => {").replace(
             "        DirectoryOp::ListFamilies => DirectoryOpResult::Unit,\n", "")},
         None),
        ("a proxy constructing an op is not an arm",
         {"src/ffi/directory_capsule.rs": FIX_CAPSULE + "fn proxy(a: SignedFamily) { let o = match w { WriteOrigin::Wire => DirectoryOp::PutFamily { family }, }; run_op(&DirectoryOp::PutFamily { family }); }\n"},
         None),
        ("a new POST route, unclassified, is red",
         {"src/server/mod.rs": FIX_SERVER.replace(
             '.route("/h"', '.route("/b", post(post_bundle::<F>))\n        .route("/h"')},
         "UNCLASSIFIED http door `post_bundle`"),
        ("an edition2 door that stops reaching the entry is red",
         {"src/federation/door_x.rs": FIX_DOOR.replace("    put_statement(b).await", "    store_json(b).await")},
         "statement_entry does not call one of put_statement"),
        ("a composite door that stops calling the shared verifier is red",
         {"src/server/mod.rs": FIX_SERVER.replace("verify_composite_via_directory(d, &body, k, &s, 0).await",
                                                  "check_sig(&body)")},
         "post_signed does not call one of verify_composite_via_directory"),
        ("a composite door that also calls an earlier-form verifier is red",
         {"src/server/mod.rs": FIX_SERVER.replace("verify_composite_via_directory(d, &body, k, &s, 0).await",
                                                  "{ verify_hybrid_via_directory(d, &body); verify_composite_via_directory(d, &body, k, &s, 0).await }")},
         "is `composite` but still calls an earlier-form verifier (verify_hybrid_via_directory)"),
        ("a substrate door whose gate moved under an `if` is red",
         {"src/server/mod.rs": FIX_SERVER.replace(
             "    let form = substrate::substrate_form(SubstratePlane::AuditEntry);",
             "    if big(&body) { let form = substrate::substrate_form(SubstratePlane::AuditEntry); }")},
         "post_substrate does not call `substrate_form(` unconditionally"),
        ("a substrate door without the gate is red",
         {"src/server/mod.rs": FIX_SERVER.replace(
             "    let form = substrate::substrate_form(SubstratePlane::AuditEntry);\n", "")},
         "post_substrate does not call `substrate_form(`"),
        ("a second door trait (BlobStorage) is inventoried: an object door with no row is red",
         {"src/federation/blobs.rs": FIX_BLOBS,
          "src/store/sqlite.rs": FIX_SQLITE + FIX_BLOBS_IMPL,
          "src/store/postgres.rs": (FIX_SQLITE + FIX_BLOBS_IMPL).replace("SqliteBackend", "PostgresBackend")},
         "UNCLASSIFIED trait door `put_claim`"),
        ("a pending door row passes `check` when it names its owner",
         {"src/federation/blobs.rs": FIX_BLOBS,
          "src/store/sqlite.rs": FIX_SQLITE + FIX_BLOBS_IMPL,
          "src/store/postgres.rs": (FIX_SQLITE + FIX_BLOBS_IMPL).replace("SqliteBackend", "PostgresBackend"),
          TSV: FIX_TSV + "trait\tput_claim\tpending\t-\tthe earlier claim; owner: T2\n"},
         None),
        ("a pending door row with no owner is red",
         {"src/federation/blobs.rs": FIX_BLOBS,
          "src/store/sqlite.rs": FIX_SQLITE + FIX_BLOBS_IMPL,
          "src/store/postgres.rs": (FIX_SQLITE + FIX_BLOBS_IMPL).replace("SqliteBackend", "PostgresBackend"),
          TSV: FIX_TSV + "trait\tput_claim\tpending\t-\tthe earlier claim\n"},
         "its note names `owner: <who>`"),
        ("a node-local door without the producer rule is red",
         {"src/server/mod.rs": FIX_SERVER.replace(
             "    fountain::require_node_local_producer(&m, me)?;\n", "")},
         "post_local does not call `require_node_local_producer(`"),
        ("a standalone component verify in production code is red (F0-cp7)",
         {"src/federation/w.rs": "pub fn v(k: &[u8], m: &[u8], s: &[u8]) -> bool {\n    ciris_crypto::Ed25519Verifier.verify_strict(k, m, s).unwrap_or(false)\n}\n"},
         "a standalone component verify"),
        ("the bound-hybrid verify returning is red (F0-cp7)",
         {"src/federation/w.rs": "pub fn v() { let _ = crate::verify::hybrid::verify_hybrid_via_directory(d, m, k, e, p, s, None); }\n"},
         "a standalone component verify (`verify_hybrid_via_directory"),
        ("a standalone verify in test code is not production (F0-cp7)",
         {"src/federation/w.rs": "#[cfg(test)]\nmod tests {\n    fn v(k: &[u8], m: &[u8], s: &[u8]) { let _ = ciris_crypto::Ed25519Verifier.verify_strict(k, m, s); }\n}\n"},
         None),
        ("an allow-listed standalone verify passes, and a stale entry is red (F0-cp7)",
         {"src/audit/verify.rs": "fn f() {}\n"},
         "in LONE_VERIFY_ALLOWED but holds no standalone verify"),
        ("a door's whole test-gated module file is not production",
         {"src/federation/some_invariants.rs": "pub fn plan_family() { refuse_earlier_form(\"x\"); }\n",
          TSV: FIX_TSV.replace("federation/door_x.rs::plan_family", "federation/some_invariants.rs::plan_family")},
         "no production `fn plan_family` in src/federation/some_invariants.rs"),
    ]
    parked = FIX_PARKED.format(marker=CP2, CP2=CP2)
    cases += [
        ("a CP2 ignore with the switch off is allowed",
         {"tests/parked.rs": parked}, None),
        ("a CP2 ignore with the switch on is red",
         {"tests/parked.rs": parked, SWITCH_FILE: FIX_SWITCH.format("true")},
         "tests/parked.rs:4: " + CP2 + " remains with the doors shut"),
        ("a CP2 ignore only in a comment is not red",
         {"tests/parked.rs": parked.replace("    " + CP2 + "\n", ""), SWITCH_FILE: FIX_SWITCH.format("true")},
         None),
        ("a CP2 ignore spelled otherwise is red even with the switch off",
         {"tests/parked.rs": FIX_PARKED.format(marker='#[ignore = "v62-CP2 needs the switch"]', CP2=CP2)},
         "a CP2 ignore not spelled exactly"),
        ("with the switch on, an untagged earlier-form fixture scope is red",
         {SWITCH_FILE: FIX_SWITCH.format("true"),
          "src/federation/w.rs": "fn t() { let r = e2::with_earlier_form(|| build()); }\n"},
         "an earlier-form fixture scope with the doors shut"),
        ("with the switch on, a `CP2 skeleton` scope is allowed",
         {SWITCH_FILE: FIX_SWITCH.format("true"),
          "src/federation/w.rs": "fn t() {\n    // CP2 skeleton: re-signed as edition 2\n    // before any door.\n    let r = e2::with_earlier_form(|| build());\n}\n"},
         None),
        ("with the switch on, `CP2 held` without an ignored test is red",
         {SWITCH_FILE: FIX_SWITCH.format("true"),
          "src/federation/w.rs": "async fn t() {\n    // CP2 held: owner rewrite\n    e2::with_earlier_form_async(async {}).await;\n}\n"},
         "`// CP2 held:` in a file with no"),
        ("with the switch on, `CP2 held` beside an ignored test is allowed",
         {SWITCH_FILE: FIX_SWITCH.format("true"),
          "src/federation/w.rs": '#[tokio::test]\n#[ignore = "v62: x card pending (CC next edition)"]\nasync fn t() {\n    // CP2 held: x\n    e2::with_earlier_form_async(async {}).await;\n}\n'},
         None),
        ("with the switch on, the forcing scope is red",
         {SWITCH_FILE: FIX_SWITCH.format("true"),
          "src/federation/w.rs": "async fn t() { door::with_earlier_form_doors_shut(f()).await; }\n"},
         "`with_earlier_form_doors_shut` is gone with the flip"),
        ("with the switch off, an untagged scope is allowed",
         {"src/federation/w.rs": "fn t() { let r = e2::with_earlier_form(|| build()); }\n"},
         None),
        ("a mention in a comment is not a call",
         {SWITCH_FILE: FIX_SWITCH.format("true"),
          "src/federation/w.rs": "// once wrapped in with_earlier_form(|| x)\nfn t() {}\n"},
         None),
        ("a `v62-CP2 rewrite pending` bridge passes `check` with the switch on",
         {SWITCH_FILE: FIX_SWITCH.format("true"),
          "src/federation/w.rs": '#[tokio::test]\n#[ignore = "v62-CP2 rewrite pending: P8 (I1)"]\nasync fn t() {\n    // CP2 held: owner rewrite\n    e2::with_earlier_form_async(async {}).await;\n}\n'},
         None),
        ("a `CP2 held` body may name its ignored runners in another file",
         {SWITCH_FILE: FIX_SWITCH.format("true"),
          "src/federation/w.rs": "pub async fn body() {\n    // CP2 held: runners: run_a, run_b.\n    e2::with_earlier_form_async(async {}).await;\n}\n",
          "src/store/r.rs": '#[tokio::test]\n#[ignore = "v62-CP2 rewrite pending: E0 (x)"]\nasync fn run_a() { body().await }\n#[tokio::test]\n#[ignore = "v62: x card pending (CC next edition)"]\nasync fn run_b() { body().await }\n'},
         None),
        ("a `CP2 held` body naming a runner that is not ignored is red",
         {SWITCH_FILE: FIX_SWITCH.format("true"),
          "src/federation/w.rs": "pub async fn body() {\n    // CP2 held: runners: run_a, run_b.\n    e2::with_earlier_form_async(async {}).await;\n}\n",
          "src/store/r.rs": '#[tokio::test]\n#[ignore = "v62-CP2 rewrite pending: E0 (x)"]\nasync fn run_a() { body().await }\n#[tokio::test]\nasync fn run_b() { body().await }\n'},
         "names runner `run_b`"),
        ("a bridge with no owner is red",
         {"tests/parked.rs": FIX_PARKED.format(marker='#[ignore = "v62-CP2 rewrite pending: "]', CP2=CP2)},
         "a CP2 ignore not spelled exactly"),
        ("a missing switch is red",
         {SWITCH_FILE: "pub const OTHER: bool = true;\n"},
         "no `const EARLIER_FORM_DOORS_SHUT"),
        ("a switch set only in test code does not count",
         {"tests/parked.rs": parked,
          SWITCH_FILE: "#[cfg(test)]\npub const EARLIER_FORM_DOORS_SHUT: bool = true;\n"},
         "no `const EARLIER_FORM_DOORS_SHUT"),
    ]
    failed = 0
    # release-check: red on a bridge, green without one; unignore leaves it
    for marker, want_rc in (('#[ignore = "v62-CP2 rewrite pending: P8 (I1)"]', 1), (None, 0)):
        d = Path(tempfile.mkdtemp(prefix="efd-"))
        try:
            files = {SWITCH_FILE: FIX_SWITCH.format("true")}
            if marker:
                files["tests/parked.rs"] = FIX_PARKED.format(marker=marker, CP2=CP2)
            _write_fixture(d, files)
            import contextlib, io
            with contextlib.redirect_stdout(io.StringIO()):
                rc = release_check(d)
                unignore(d)
            ok = rc == want_rc and (not marker or marker in (d / "tests/parked.rs").read_text())
        finally:
            shutil.rmtree(d, ignore_errors=True)
        print(f"{'PASS' if ok else 'FAIL'} release-check {'with' if marker else 'without'} a bridge")
        failed += 0 if ok else 1
    # release-check: red on a pending door row (F0-cp6c)
    d = Path(tempfile.mkdtemp(prefix="efd-"))
    try:
        _write_fixture(d, {SWITCH_FILE: FIX_SWITCH.format("true"),
                           TSV: FIX_TSV + "http\tpost_other\tpending\t-\towner: T2\n"})
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            rc = release_check(d)
        ok = rc == 1
    finally:
        shutil.rmtree(d, ignore_errors=True)
    print(f"{'PASS' if ok else 'FAIL'} release-check with a pending door")
    failed += 0 if ok else 1
    # unignore: refused while off, removes the attribute (not the comment) once on
    for shut, want_rc, want_left in (("false", 1, 1), ("true", 0, 0)):
        d = Path(tempfile.mkdtemp(prefix="efd-"))
        try:
            _write_fixture(d, {"tests/parked.rs": FIX_PARKED.format(marker=CP2, CP2=CP2),
                               SWITCH_FILE: FIX_SWITCH.format(shut)})
            import contextlib, io
            with contextlib.redirect_stdout(io.StringIO()):
                rc = unignore(d)
            left = len(cp2_markers(d))
            text = (d / "tests/parked.rs").read_text()
            ok = rc == want_rc and left == want_left and ("// " + CP2) in text
            if shut == "true":
                errors, _ = check(d)
                ok = ok and not errors
        finally:
            shutil.rmtree(d, ignore_errors=True)
        print(f"{'PASS' if ok else 'FAIL'} unignore with the switch {shut}")
        failed += 0 if ok else 1
    for name, overrides, want in cases:
        d = Path(tempfile.mkdtemp(prefix="efd-"))
        try:
            _write_fixture(d, overrides)
            errors, _ = check(d)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        if want is None:
            ok = not errors
        else:
            ok = any(want in e for e in errors)
        print(f"{'PASS' if ok else 'FAIL'} {name}")
        if not ok:
            failed += 1
            for e in errors or ["(green)"]:
                print(f"     got: {e}")
    print(f"self-test: {len(cases) + 5 - failed}/{len(cases) + 5}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
