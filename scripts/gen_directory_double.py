#!/usr/bin/env python3
"""Generate `src/federation/directory_double.rs` — the FederationDirectory
fault-injecting double (CIRISPersist#603).

WHY GENERATED. The trait has 162 required methods and grows most releases. A
hand-written double is 162 chances to typo a delegation, and it rots the moment
someone adds a method. This parses the trait and emits every delegation, so the
double tracks the trait by construction.

WHY NOT A MACRO. A declarative macro cannot enumerate a trait's methods, and a
proc-macro crate is a heavier dependency than a script that emits committed code
a reviewer can read. The generated file IS committed: `cargo` never runs this,
so there is no build-time codegen and no surprise at compile time.

The compiler is still the backstop — but ONLY for required methods. If the
trait gains a `;`-terminated method and nobody regenerates, the double fails to
COMPILE, loud and at the right moment. A method added with a DEFAULT BODY is
different: the double silently inherits the default, so a backend that
overrides it is not reached even when no fault was requested, and nothing
fails. Found on PR #786 (CIRISPersist#785), and again on #1232.

Blanket-delegating every default would be WRONG. Some defaults are PROVIDED
COMPOSITIONS — `active_family_key_ids_for` calls `list_families_for_member`
through `self`. Delegated to the inner backend, that composition runs where
this wrapper's fault table does not exist, so a fault injected on the inner
call is silently not observed. That would break fault injection in the double
whose entire purpose is fault injection.

So a default is delegated when it is a LEAF backend operation (backends
override it; it composes no other trait method through `self`), and stays out
when it is a provided composition.

v61.1.0 (D9) — LEAVES ARE FOUND, NOT LISTED. A default whose body is exactly
`Err(Error::Unsupported { .. })`, optionally after `let _ = ...;` statements
that consume the arguments, composes nothing through `self` by construction,
so it is a leaf and is delegated automatically (`is_unsupported_leaf`). The
hand lists are now overrides only: DELEGATED_DEFAULTS names the leaves whose
default is NOT an `Unsupported` refusal (a no-op, `None`, "none held"), which
the parser cannot tell from a composition; NOT_DELEGATED names an
`Unsupported`-bodied default the double must still not delegate (empty today;
each entry needs its reason). #1232 was exactly the gap this closes: 61.0.5's
`list_attestations_naming_by_dimension` was a leaf nobody listed.

Run:  python3 scripts/gen_directory_double.py
Check: python3 scripts/gen_directory_double.py --check   (CI: fails if stale)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# v61.1.0 (D9) — OVERRIDES ONLY. Every defaulted method whose body is an
# `Err(Error::Unsupported { .. })` refusal is a leaf and is delegated without
# being listed (`is_unsupported_leaf`); 24 names left this list when that
# landed, among them #1225's `list_attestations_naming_by_dimension`, the one
# #1232 found missing. `parse_defaults` refuses a name here that the parser
# already finds, so the list cannot regrow its redundant half.
#
# DELEGATED_DEFAULTS — leaves whose default is NOT an `Unsupported` refusal, so
# the parser cannot tell them from a composition. Each is a leaf backend
# operation: backends override it, it composes no other trait method through
# `self`, and a consumer wrapping a backend in this double must reach the
# override rather than the default.
DELEGATED_DEFAULTS = (
    # The wire-hash family's one non-`Unsupported` member (its default is a
    # generic `Backend` "not implemented"); the rest of the family is found.
    # #785's separation is a statement about how the family's reads relate;
    # delegating one and not another would make that relationship differ
    # through the double from what it is against a bare backend.
    "lookup_signed_record_by_content_hash",
    # v50.0.0 (#916) — defaulted no-op, overridden by sqlite/postgres (the
    # receive doors' re-wrap); through the double it must reach the override.
    "rewrap_own_epochs_for_device",
    # v55.0.0 (CIRISPersist#989) — the key-grant hooks: leaf operations the
    # sqlite / postgres backends override (the held content's author, the
    # projection into the grant tables); neither composes a trait method.
    "key_grant_held_owner",
    "project_key_grant_row",
    # v50.0.0 (PR #921 review, F1) — defaulted `None`, overridden by every
    # backend. A SYNC accessor (emitted by name in `render`): the double hands
    # out the INNER backend's cache, so a verdict read through the double is
    # cached where the backend caches it, while every input the cache key
    # reads still goes through this double's fault table. Without it a fault
    # injected here could never meet a cached verdict.
    "trust_root_standing_cache",
    # #973 (CC 3.2 T4a) — defaulted "none held", overridden by every backend;
    # the trust-root reads ask it for every unlabelled `delegates_to`, so
    # through the double it must reach the backend's held set.
    "trust_direction_held_among",
)

# NOT_DELEGATED — an `Unsupported`-bodied default the double must NOT delegate,
# each with its reason. Empty: such a body names no trait method, so it
# composes nothing through `self`, and delegating it can only reach a
# backend's override. (v53.1.5's compositions — `list_attestations_by_
# dimension_prefix`, `list_attestations_for_dimension_prefix`,
# `list_composers_referencing_any`, and v55's `list_holders_sized` — are not
# `Unsupported`-bodied, so they are not found and stay out on their own:
# through the double they run the default over the delegated leaves, and a
# fault on a leaf is observed.)
NOT_DELEGATED: tuple[str, ...] = ()

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "federation" / "mod.rs"
OUT = ROOT / "src" / "federation" / "directory_double.rs"


def trait_body(text: str) -> str:
    i = text.find("pub trait FederationDirectory")
    if i < 0:
        sys.exit("could not find `pub trait FederationDirectory`")
    j = text.index("{", i)
    depth, k = 0, j
    while True:
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                break
        k += 1
    return text[j + 1 : k]


def split_args(arg_str: str) -> list[str]:
    """Split a Rust argument list on top-level commas (generics/tuples nest)."""
    out, depth, cur = [], 0, ""
    for ch in arg_str:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def terminates(line: str) -> bool:
    """True iff `line` carries a `;` OUTSIDE any bracket — a statement end.

    A `;` inside a type (`&[u8; 32]`) is not one. v45.0.0 (#871): the first
    trait method taking a 32-byte array argument made the bare `";" in line`
    test reset the buffer mid-signature and drop the method silently.
    """
    depth = 0
    for ch in line:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        elif ch == ";" and depth <= 0:
            return True
    return False


RAW_OPEN = re.compile(r'r(#*)"')
CHAR_LIT = re.compile(r"'(\\.[^']*|[^\\'])'")


def sanitize(text: str) -> str:
    """`text` with every comment and the CONTENTS of every string and char
    literal blanked to spaces, same length and same newlines, so brace and
    paren counting sees only code. A doc comment naming `Error::Unsupported {
    method }`, or a `"{"` in a format string, would otherwise skew the depth.

    A `'` starts a char literal only when it closes one char (or one escape)
    later; otherwise it is a lifetime (`&'a str`, `'static`) and is kept.
    """
    out = list(text)
    n, i = len(text), 0

    def blank(a: int, b: int) -> None:
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c == "r" and RAW_OPEN.match(text, i) and not (
            i > 0 and (text[i - 1].isalnum() or text[i - 1] == "_")
        ):
            hashes = len(RAW_OPEN.match(text, i).group(1))
            open_end = i + 1 + hashes + 1
            close = text.find('"' + "#" * hashes, open_end)
            close = n if close < 0 else close
            blank(open_end, close)
            i = close + 1 + hashes
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            blank(i + 1, j)
            i = j + 1
        elif c == "'":
            m = CHAR_LIT.match(text, i)
            if m:
                blank(i + 1, m.end() - 1)
                i = m.end()
            else:
                i += 1  # a lifetime
        else:
            i += 1
    return "".join(out)


def matching(s: str, i: int, open_ch: str, close_ch: str) -> int:
    """Index of the `close_ch` matching the `open_ch` at `s[i]` (sanitized)."""
    depth = 0
    for k in range(i, len(s)):
        if s[k] == open_ch:
            depth += 1
        elif s[k] == close_ch:
            depth -= 1
            if depth == 0:
                return k
    sys.exit(f"unbalanced {open_ch!r} at offset {i}")


# A leaf's whole body: any `let _ = <args>;` statements, then the refusal.
LEAF_BODY = re.compile(
    r"(?:let_=(?:\([a-z0-9_,]*\)|[a-z0-9_]+);)*"
    r"Err\(Error::Unsupported\{[^{}]*\}\)"
)


def is_unsupported_leaf(sanitized_body: str) -> bool:
    """True iff a default body is exactly `Err(Error::Unsupported { .. })`,
    optionally after `let _ = x;` / `let _ = (x, y);` (the argument
    consumption that silences unused-variable lints). Such a body names no
    trait method, so it composes nothing through `self`: a leaf."""
    return LEAF_BODY.fullmatch("".join(sanitized_body.split())) is not None


def default_methods(body: str):
    """Yield (name, args_src, ret, is_unsupported_leaf) for every DEFAULTED
    trait method (a depth-0 `fn` whose signature ends in `{`, not `;`)."""
    s = sanitize(body)
    depth_at, depth = [0] * (len(s) + 1), 0
    for k, ch in enumerate(s):
        depth_at[k] = depth
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
    found = []
    for m in re.finditer(r"\bfn\s+([a-z0-9_]+)\s*\(", s):
        if depth_at[m.start()] != 0:
            continue
        p_open = m.end() - 1
        p_close = matching(s, p_open, "(", ")")
        # The signature ends at the first `{` or `;` outside brackets: a
        # return type may carry `[u8; 32]`, and `->` is not a closing `>`.
        k, nest = p_close + 1, 0
        while k < len(s):
            if s.startswith("->", k):
                k += 2
                continue
            if s[k] in "([<":
                nest += 1
            elif s[k] in ")]>":
                nest -= 1
            elif s[k] in "{;" and nest <= 0:
                break
            k += 1
        if k >= len(s) or s[k] == ";":
            continue  # required — `parse` emits it
        b_close = matching(s, k, "{", "}")
        args = " ".join(s[p_open + 1 : p_close].split())
        sig_tail = " ".join(s[p_close + 1 : k].split())
        ret = sig_tail[2:].strip() if sig_tail.startswith("->") else "()"
        found.append((m.group(1), args, ret, is_unsupported_leaf(s[k + 1 : b_close])))
    return found


def parse_defaults(body: str):
    """Yield (name, args_src, ret) for each defaulted method the double
    delegates: every `Unsupported` leaf (found), plus DELEGATED_DEFAULTS,
    minus NOT_DELEGATED. See the module docstring for the rule."""
    defaults = default_methods(body)
    by_name = {n: (n, a, r) for n, a, r, _ in defaults}
    leaves = {n for n, _, _, leaf in defaults if leaf}
    missing = set(DELEGATED_DEFAULTS) - set(by_name)
    if missing:
        sys.exit(
            f"DELEGATED_DEFAULTS names not found as defaulted trait methods: "
            f"{sorted(missing)} — the trait changed, or one became required "
            f"(in which case drop it from the list; it is generated anyway)"
        )
    redundant = set(DELEGATED_DEFAULTS) & leaves
    if redundant:
        sys.exit(
            f"DELEGATED_DEFAULTS names found automatically as Unsupported leaves: "
            f"{sorted(redundant)} — drop them from the list (it holds overrides only)"
        )
    stray = set(NOT_DELEGATED) - leaves
    if stray:
        sys.exit(
            f"NOT_DELEGATED names that are not Unsupported leaves: {sorted(stray)} "
            f"— a non-leaf default is not delegated anyway; drop it from the list"
        )
    chosen = (leaves | set(DELEGATED_DEFAULTS)) - set(NOT_DELEGATED)
    return [by_name[n] for n in sorted(chosen)]


def parse(body: str):
    """Yield (name, args_src, ret) for every REQUIRED (`;`-terminated) method."""
    methods = []
    # Only depth-0 items: nested impls/fns inside default bodies must not leak.
    depth, buf = 0, ""
    for line in body.split("\n"):
        if depth == 0:
            buf += line + "\n"
            if re.search(r"\bfn\s+[a-z0-9_]+", buf) and terminates(line) and "{" not in buf:
                one = " ".join(buf.split())
                m = re.match(
                    r".*?\bfn\s+([a-z0-9_]+)\s*\((.*?)\)\s*(?:->\s*(.+?))?\s*;$", one
                )
                if m:
                    methods.append((m.group(1), m.group(2), (m.group(3) or "()").strip()))
                buf = ""
            elif "{" in line:
                buf = ""
        depth += line.count("{") - line.count("}")
        if depth < 0:
            depth = 0
    return methods


def render(methods) -> str:
    L: list[str] = []
    A = L.append
    A('//! **A composable `FederationDirectory` double (CIRISPersist#603/#604).**')
    A('//!')
    A('//! GENERATED by `scripts/gen_directory_double.py`. Do not edit by hand —')
    A('//! edit the generator. `scripts/gen_directory_double.py --check` fails if this')
    A('//! file is stale.')
    A('//!')
    A('//! # The arm nobody could reach')
    A('//!')
    A('//! `resolve_mesh_config` folds per-root reads and carries `unreadable_roots`,')
    A('//! so *"this backend cannot answer for root R"* and *"root R said nothing"* stay')
    A('//! distinct. **No test in this repo could reach that arm**: all three shipped')
    A('//! backends implement every method, so none can return `Error::Unsupported`.')
    A('//! The only party exercising it was CIRISServer, through their own directory')
    A('//! impl — which is how the defect was found in the first place (#603).')
    A('//!')
    A('//! #604 recorded the pattern across five workstreams in one week:')
    A('//!')
    A('//! ```text')
    A('//! Ok(value)  -> a real answer')
    A('//! Ok(empty)  -> a real answer that happens to be empty')
    A('//! Err(_)     -> WE COULD NOT ASK')
    A('//! ```')
    A('//!')
    A('//! Collapsing that third arm is how a zero becomes evidence it has not earned.')
    A('//! The Constitution\'s own discipline: **a zero is not evidence unless the')
    A('//! instrument can fail.** This is the instrument that can fail.')
    A('//!')
    A('//! # Shape')
    A('//!')
    A('//! It WRAPS a real directory rather than stubbing 162 methods, so every')
    A('//! un-faulted call keeps real behaviour and a fixture only declares the')
    A('//! divergence it cares about.')
    A('//!')
    A('//! ```ignore')
    A('//! let dbl = FaultInjectingDirectory::new(backend)')
    A('//!     .unsupported("list_attestations_for");')
    A('//! // every other method behaves exactly as `backend` does')
    A('//! ```')
    A('//!')
    A('//! Test-only: `#[cfg(any(test, feature = "test-anchor"))]`, and `pub` because')
    A('//! CIRISServer/Edge/Agent need it (#664 was the same wall one module over).')
    A("")
    A("// A glob import on purpose: this file delegates EVERY trait signature, so it")
    A("// needs the trait\'s whole type scope. Naming them individually would be a")
    A("// second list to keep in sync with the first — the exact failure this")
    A("// generator exists to remove.")
    A("#[allow(unused_imports)]")
    A("use super::*;")
    A("use std::collections::BTreeSet;")
    A("use std::sync::Arc;")
    A("")
    A("/// A `FederationDirectory` that delegates to `inner`, except where a method")
    A("/// has been declared faulted — there it returns [`Error::Unsupported`].")
    A("///")
    A("/// Cloneable and `Send + Sync`, so it drops into any fixture that takes a")
    A("/// directory. The fault set is by METHOD NAME, matching the `method` field")
    A("/// `Error::Unsupported` already carries, so a refusal names the same thing the")
    A("/// fixture declared.")
    A("#[derive(Clone)]")
    A("pub struct FaultInjectingDirectory {")
    A("    inner: Arc<dyn FederationDirectory>,")
    A("    unsupported: BTreeSet<&'static str>,")
    A("    erroring: BTreeSet<&'static str>,")
    A("}")
    A("")
    A("impl std::fmt::Debug for FaultInjectingDirectory {")
    A("    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {")
    A('        f.debug_struct("FaultInjectingDirectory")')
    A('            .field("unsupported", &self.unsupported)')
    A('            .field("erroring", &self.erroring)')
    A("            .finish_non_exhaustive()")
    A("    }")
    A("}")
    A("")
    A("impl FaultInjectingDirectory {")
    A("    /// Wrap a real directory. With no faults declared it is behaviourally")
    A("    /// identical to `inner` — a fixture opts INTO each divergence.")
    A("    #[must_use]")
    A("    pub fn new(inner: Arc<dyn FederationDirectory>) -> Self {")
    A("        Self { inner, unsupported: BTreeSet::new(), erroring: BTreeSet::new() }")
    A("    }")
    A("")
    A("    /// Declare that `method` answers `Error::Unsupported { method }`.")
    A("    ///")
    A("    /// The name is NOT validated against the trait: an unknown name is inert")
    A("    /// rather than an error, because a fixture written against a newer persist")
    A("    /// should degrade to *\"that fault did not fire\"* and fail on its own")
    A("    /// assertion, not panic inside the double. Use [`Self::faults`] to assert")
    A("    /// what was actually declared.")
    A("    #[must_use]")
    A("    pub fn unsupported(mut self, method: &'static str) -> Self {")
    A("        self.unsupported.insert(method);")
    A("        self")
    A("    }")
    A("")
    A("    /// The declared fault set — so a fixture can assert its own setup.")
    A("    #[must_use]")
    A("    pub fn faults(&self) -> &BTreeSet<&'static str> {")
    A("        &self.unsupported")
    A("    }")
    A("")
    A("    /// v36.0.0 (CIRISPersist#624) — declare that `method` answers a")
    A("    /// GENERIC backend failure, not `Unsupported`.")
    A("    ///")
    A("    /// The two kinds are not interchangeable: `Unsupported` means *this")
    A("    /// directory cannot answer*, which several trait defaults treat as a")
    A("    /// sanctioned degrade-to-plan-free path. `Backend` means *the answer")
    A("    /// was attempted and FAILED*, which must propagate. Without this")
    A("    /// second kind a mutation collapsing a typed `Unsupported` arm into")
    A("    /// `Err(_)` survives every witness — measured on #624 (M6).")
    A("    #[must_use]")
    A("    pub fn erroring(mut self, method: &'static str) -> Self {")
    A("        self.erroring.insert(method);")
    A("        self")
    A("    }")
    A("")
    A("    /// The declared generic-failure set — so a fixture can assert setup.")
    A("    #[must_use]")
    A("    pub fn error_faults(&self) -> &BTreeSet<&'static str> {")
    A("        &self.erroring")
    A("    }")
    A("")
    A("    fn faulted(&self, method: &'static str) -> Option<Error> {")
    A("        if self.unsupported.contains(method) {")
    A("            return Some(Error::Unsupported { method });")
    A("        }")
    A("        self.erroring")
    A("            .contains(method)")
    A("            .then(|| Error::Backend(format!(\"injected backend failure: {method}\")))")
    A("    }")
    A("}")
    A("")
    A(f"// {len(methods)} delegations, generated. Every one: fault first, then delegate.")
    A("#[async_trait::async_trait]")
    A("impl FederationDirectory for FaultInjectingDirectory {")
    for name, args_src, ret in methods:
        args = split_args(args_src)
        # drop the receiver
        params = [a for a in args if a.strip() not in ("&self", "self", "&mut self")]
        names = []
        for p in params:
            nm = p.split(":")[0].strip()
            # `str.lstrip` takes a CHARACTER SET, not a prefix — `lstrip("mut ")`
            # eats the leading `m` of `member_identity_key_id`. Strip the real
            # `mut ` token instead.
            if nm.startswith("mut "):
                nm = nm[4:].strip()
            names.append(nm)
        arglist = ", ".join(["&self"] + params)
        call = ", ".join(names)
        is_result = ret.startswith("Result<")
        if name == "as_dyn_directory":
            # v48.0.0 (#905) — the one SYNC accessor: the double IS the trait
            # object it hands out, so faults injected here still apply to the
            # folds reached through it.
            A("    fn as_dyn_directory(&self) -> &dyn FederationDirectory {")
            A("        self")
            A("    }")
            continue
        if name == "trust_root_standing_cache":
            A(f"    fn {name}(&self) -> {ret} {{")
            A(f"        self.inner.{name}()")
            A("    }")
            continue
        if name == "execute_attestation_query":
            # v56.0.0 (CIRISPersist#1001) — the typed read serves every
            # attestation read, so a fixture also faults ONE query shape by
            # the read it replaced (`AttestationQuery::shape`, e.g.
            # "list_attestations_for_dimension_prefix").
            A(f"    async fn {name}({arglist}) -> {ret} {{")
            A(f'        if let Some(e) = self.faulted("{name}") {{')
            A("            return Err(e);")
            A("        }")
            A(f"        if let Some(e) = self.faulted({call}.shape()) {{")
            A("            return Err(e);")
            A("        }")
            A(f"        self.inner.{name}({call}).await")
            A("    }")
            continue
        A(f"    async fn {name}({arglist}) -> {ret} {{")
        if is_result:
            A(f'        if let Some(e) = self.faulted("{name}") {{')
            A("            return Err(e);")
            A("        }")
        A(f"        self.inner.{name}({call}).await")
        A("    }")
    A("}")
    return "\n".join(L) + "\n"


def rustfmt(text: str) -> str:
    """Run the emitted source through rustfmt.

    Without this, `cargo fmt --all` reformats the generated file and `--check`
    then reports STALE for a file nobody edited — the gate crying wolf at its own
    project's formatter. Generating already-formatted source makes "generated"
    and "formatted" the same string.
    """
    import subprocess

    try:
        r = subprocess.run(
            ["rustfmt", "--edition", "2021", "--emit", "stdout"],
            input=text,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        # No rustfmt (or it rejected the input): fall back to raw output rather
        # than failing. `cargo fmt --check` in CI is the real gate on formatting.
        return text
    out = r.stdout
    # rustfmt --emit stdout prefixes a `// rustfmt-...` banner line in some
    # versions; drop anything before our own module doc.
    i = out.find("//! ")
    return out[i:] if i > 0 else out


def main() -> None:
    body = trait_body(SRC.read_text())
    methods = parse(body)
    if not methods:
        sys.exit("parsed zero methods — the trait shape changed; fix the generator")
    # Defaulted leaves are delegated too, or the double answers with the trait
    # default while a bare backend answers with its override (PR #786).
    methods = sorted(methods + parse_defaults(body))
    text = rustfmt(render(methods))
    if "--check" in sys.argv:
        cur = OUT.read_text() if OUT.exists() else ""
        if cur != text:
            sys.exit(
                f"STALE: {OUT.relative_to(ROOT)} does not match the trait "
                f"({len(methods)} methods). Run: python3 scripts/gen_directory_double.py"
            )
        print(f"OK directory double is current ({len(methods)} delegations)")
        return
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(ROOT)} ({len(methods)} delegations)")


if __name__ == "__main__":
    main()
