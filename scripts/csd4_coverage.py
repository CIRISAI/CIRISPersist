#!/usr/bin/env python3
"""csd4_coverage.py — CC's CSD/4 chain joined to persist's evidence,
witnesses, mutation scopes and refusal tokens (docs/V60_TASK_PLAN.md §3b).

    scripts/csd4_coverage.py [--out <report.md>] [--cewpos-dir <dir>]

A REPORT, NOT A GATE (v60). The join is READ from CC's chain manifest,
tests/fixtures/csd4/csd4_chain.json (CIRISConstitution rc9
`manifests/csd4_chain.json`, vendored byte for byte; see the fixture
README), never guessed from `cc_ref` prefixes:

  atom -> chain atoms[a].claims[] (by_invariant | by_section)
       -> claims[].evidence[] where repo == CIRISPersist -> `path#symbol`
       -> the row in evidence/cc_impl.tsv
       -> the `*_invariants.rs` files under src/ that name the symbol (for a
          common name, only those that also name its module), and the
          scripts/mutants/scope-*.txt entries that cover the file (and, when
          the entry lists functions, the symbol).

Gap lists:
  (a) chain evidence refs to persist with no cc_impl.tsv row; and
      cc_impl.tsv rows no atom reaches;
  (b) atoms with persist claims but no witness file or no mutation scope;
  (c) persist refusal tokens (the resolved value of every `Error::kind()`
      arm) the text does not name (`refusal_tokens`; a `federation_<tok>`
      kind counts as named by `<tok>`), and text tokens persist never emits
      (no kind() returns it or its `federation_` form, no non-test string
      literal spells it, no non-test fn is named it), with the text's
      confidence (`bold` | `after_refusal`).

Also: the traces.json `refused` map (CIRISServer harness output, which CC
does not own: `_meta.not_here`) against persist's string literals, and the
CEWPOS "stops at rel[k]" relations with an owner guess. Atoms with no claim
BY DESIGN (`negatives.held`, `values.ready`: harness-level) are listed as
such, not as gaps.

Exit 0 whatever it finds; 2 when an input cannot be read or the chain's
vocabulary pin disagrees with the vendored vocabulary. Stdlib only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures" / "csd4"
CHAIN = FIX / "csd4_chain.json"
EVIDENCE = REPO / "evidence" / "cc_impl.tsv"
SCOPES = REPO / "scripts" / "mutants"
PERSIST = "CIRISPersist"
# Atoms the chain gives no claim on purpose: harness-level preconditions of a
# trace, not substrate state.
HARNESS_ATOMS = {"negatives.held", "values.ready"}
STOP = re.compile(r"stops at (rel\[\d+\]:([A-Za-z0-9_]+)):\s*(.*?)\)\s*\|\s*$")
LITERAL = re.compile(r'"([A-Za-z0-9_:.\-]{3,})"')
CONST = re.compile(r"\bconst\s+([A-Z0-9_]+)\s*:\s*&(?:'static\s+)?str\s*=\s*\"([^\"]+)\"")
KIND_FN = re.compile(r"pub fn kind\(&self\) -> &'static str \{")
ARM = re.compile(r"=>\s*(?:\{\s*)?(?:\"([^\"]+)\"|([A-Za-z_][A-Za-z0-9_:]*::)?([A-Z][A-Z0-9_]+)\b)")


def die(msg: str) -> None:
    print(f"csd4_coverage: {msg}", file=sys.stderr)
    sys.exit(2)


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as e:
        die(f"cannot read {path}: {e}")
        raise


def git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if r.returncode != 0:
        die(f"git -C {repo} {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout


def strip_comments(src: str) -> str:
    return re.sub(r"//[^\n]*", "", src)


def production(src: str) -> str:
    """The text before the file's first inline `#[cfg(test)] mod x {` (a
    `#[cfg(test)] mod x;` declaration is not a cut)."""
    m = re.search(r"^\s*#\[cfg\(test\)\]\s*\n\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{", src, re.M)
    return src[: m.start()] if m else src


# ── inputs ──────────────────────────────────────────────────────────────────


def load_chain() -> dict:
    try:
        chain = json.loads(read(CHAIN))
    except json.JSONDecodeError as e:
        die(f"{CHAIN}: {e}")
    for k in ("_meta", "atoms", "refusal_tokens"):
        if k not in chain:
            die(f"{CHAIN}: no `{k}`")
    vocab = hashlib.sha256((FIX / "topology_vocabulary.json").read_bytes()).hexdigest()
    pinned = chain["_meta"].get("pins", {}).get("vocabulary_sha256")
    if pinned != vocab:
        die(f"the chain pins vocabulary {pinned}, the vendored topology_vocabulary.json is {vocab}")
    return chain


def load_traces() -> dict:
    return json.loads(read(FIX / "traces.json"))["entries"]


def load_evidence() -> list[dict]:
    rows = []
    for line in read(EVIDENCE).splitlines():
        if line.startswith("#") or line.startswith("decimal_id\t") or not line.strip():
            continue
        cells = line.split("\t")
        if len(cells) < 4:
            continue
        path, _, sym = cells[3].partition("#")
        rows.append({"decimal": cells[0], "claim": cells[1], "repo": cells[2], "path": path, "symbol": sym})
    return rows


def load_scopes() -> list[tuple[str, str, list[str]]]:
    out = []
    for s in sorted(SCOPES.glob("scope-*.txt")):
        for raw in s.read_text().splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith(("tests:", "witnesses:", "features:")):
                continue
            file, *fns = line.split()
            out.append((s.name, file, fns))
    return out


def witness_files() -> dict[str, str]:
    return {str(p.relative_to(REPO)): read(p) for p in sorted((REPO / "src").rglob("*_invariants.rs"))}


def src_files() -> list[tuple[str, str]]:
    out = []
    for p in sorted((REPO / "src").rglob("*.rs")):
        if p.name.endswith("_invariants.rs") or p.name == "tests.rs" or "/tests/" in str(p):
            continue
        out.append((str(p.relative_to(REPO)), production(strip_comments(read(p)))))
    return out


def string_literals(files) -> dict[str, str]:
    """literal -> first non-test src file that spells it."""
    out: dict[str, str] = {}
    for f, text in files:
        for tok in LITERAL.findall(text):
            out.setdefault(tok, f)
    return out


def refusal_kinds(files) -> dict[str, str]:
    """Every value an `Error::kind()` arm returns -> the file of that kind().
    A const arm (`hard_case::refusal::REPLICATION_HELD`) resolves by its last
    segment against every `const NAME: &str = "…"` in src/; an unresolved one
    is reported as `?NAME`."""
    consts: dict[str, str] = {}
    for _, text in files:
        for name, val in CONST.findall(text):
            consts.setdefault(name, val)
    out: dict[str, str] = {}
    for f, text in files:
        for m in KIND_FN.finditer(text):
            depth, i = 1, m.end()
            while depth and i < len(text):
                depth += {"{": 1, "}": -1}.get(text[i], 0)
                i += 1
            for lit, _, const in ARM.findall(text[m.end():i]):
                tok = lit or consts.get(const, f"?{const}")
                out.setdefault(tok, f)
    return out


def cewpos_stops(cewpos_dir: Path) -> tuple[list[dict], str]:
    plan = cewpos_dir / "CSD4_CATALOGUE_AND_MIGRATION_PLAN.md"
    sha = git(cewpos_dir, "rev-parse", "HEAD").strip()
    rows = []
    for line in read(plan).splitlines():
        if "stops at rel[" not in line or not line.startswith("| `CSD-"):
            continue
        csd = re.match(r"\| `(CSD-\d+)`", line)[1]
        m = STOP.search(line)
        if not m:
            continue
        rows.append({"csd": csd, "rel": m[1], "relation": m[2], "reason": m[3]})
    return rows, sha


# ── the join ────────────────────────────────────────────────────────────────


def word(sym: str) -> re.Pattern:
    return re.compile(r"\b" + re.escape(sym) + r"\b")


def distinctive(sym: str) -> bool:
    """A symbol whose bare name is unlikely to collide: snake_case of two
    words or more, or a long CamelCase type."""
    return ("_" in sym and len(sym) >= 8) or (sym[:1].isupper() and len(sym) >= 10)


def witnesses_of(path: str, sym: str, witnesses: dict[str, str]) -> list[str]:
    pat, stem = word(sym), Path(path).stem
    return [f for f, t in witnesses.items() if pat.search(t) and (distinctive(sym) or stem in t)]


def persist_refs(atom: dict) -> list[tuple[str, str, str, str]]:
    """(claim_id, join, path, symbol) for every CIRISPersist evidence pointer."""
    out = []
    for c in atom.get("claims", []):
        for e in c.get("evidence", []):
            if e.get("repo") != PERSIST:
                continue
            for s in e.get("symbols") or [""]:
                out.append((c["claim_id"], c.get("join", ""), e.get("path", ""), s))
    return out


def join(atoms, evidence, scopes, witnesses):
    by_key = defaultdict(list)
    for e in evidence:
        by_key[(e["path"], e["symbol"])].append(e)
    sym_witness: dict[str, list[str]] = {}
    out, unresolved, reached = {}, [], set()
    for name, a in atoms.items():
        refs = persist_refs(a)
        rows, wit, sco = set(), set(), set()
        for claim, how, path, sym in refs:
            hits = by_key.get((path, sym), [])
            if not hits:
                unresolved.append({"atom": name, "claim": claim, "ref": f"{path}#{sym}", "why": "no row"})
                continue
            if not any(h["claim"] == claim for h in hits):
                unresolved.append({"atom": name, "claim": claim, "ref": f"{path}#{sym}",
                                   "why": "row under " + ", ".join(sorted({h["claim"] for h in hits}))})
            key = f"{path}#{sym}"
            reached.add((path, sym))
            rows.add(key)
            if path.startswith("src/") and sym:
                if key not in sym_witness:
                    sym_witness[key] = witnesses_of(path, sym, witnesses)
                wit.update(sym_witness[key])
            for scope, file, fns in scopes:
                if file == path and (not fns or sym in fns):
                    sco.add(scope)
        named = sorted(f for f, t in witnesses.items() if f"`{name}`" in t)
        out[name] = {"plane": a.get("plane", ""), "cc_ref": a.get("cc_ref", ""),
                     "predicate": a.get("state_predicate", ""),
                     "claims": sorted({c["claim_id"] for c in a.get("claims", [])}),
                     "persist_claims": sorted({r[0] for r in refs}),
                     "by_invariant": sorted({r[0] for r in refs if r[1] == "by_invariant"}),
                     "rows": sorted(rows), "witnesses": sorted(wit), "scopes": sorted(sco),
                     "named_by": named, "promised_by": a.get("promised_by", [])}
    unreached = sorted({f"{e['path']}#{e['symbol']}\t{e['claim']}\t{e['decimal']}"
                        for e in evidence if (e["path"], e["symbol"]) not in reached})
    return out, unresolved, unreached


def compound(tok: str) -> bool:
    return "_" in tok or ":" in tok


KIND_PREFIX = "federation_"


def kind_for(tok: str, kinds) -> str:
    """The persist kind() token that spells `tok`: itself, or with the
    `federation_` prefix persist's federation errors carry."""
    for k in (tok, KIND_PREFIX + tok):
        if k in kinds:
            return k
    return ""


def fn_names(files) -> dict[str, str]:
    out: dict[str, str] = {}
    for f, text in files:
        for name in re.findall(r"\bfn\s+([a-z_][a-z0-9_]*)", text):
            out.setdefault(name, f)
    return out


def text_tokens(chain, literals, kinds, fns):
    out = []
    for tok, secs in sorted(chain["refusal_tokens"].items()):
        conf = sorted(set(secs.values()))
        kind = kind_for(tok, kinds)
        near = sorted(k for k in kinds if k != kind and tok in k)[:3]
        out.append({"token": tok, "sections": sorted(secs), "confidence": "/".join(conf),
                    "kind": kind, "literal": literals.get(tok, ""), "fn": fns.get(tok, ""), "near": near})
    return out


def trace_refusals(traces, literals):
    out = []
    for tid, e in sorted(traces.items(), key=lambda kv: int(kv[0][1:])):
        for key, reason in sorted(e.get("refused", {}).items()):
            tok = key.split(":", 1)[1] if ":" in key else key
            # A one-word token (`agent`) spelled somewhere is an identity type
            # or a label, not evidence persist emits the refusal.
            exact = tok in literals and compound(tok)
            partial = sorted(t for t in literals if tok in t and t != tok and compound(t))[:3]
            named = sorted({t for t in re.findall(r"[A-Za-z0-9_:.\-]{4,}", reason)
                            if t in literals and compound(t)})
            out.append({"trace": tid, "key": key, "token": tok, "exact": exact,
                        "exact_file": literals.get(tok, ""), "partial": partial,
                        "reason_names": named})
    return out


def stops_by_relation(stops, literals):
    agg = defaultdict(lambda: {"csds": set(), "rels": set(), "reason": ""})
    for s in stops:
        a = agg[s["relation"]]
        a["csds"].add(s["csd"])
        a["rels"].add(s["rel"])
        a["reason"] = a["reason"] or s["reason"]
    out = []
    for rel, a in sorted(agg.items(), key=lambda kv: (-len(kv[1]["csds"]), kv[0])):
        hits = sorted(t for t in literals if re.search(r"(^|[_:.])" + re.escape(rel) + r"($|[_:.])", t)) \
            if compound(rel) else []
        why = []
        if re.search(r"\bpersist\b", a["reason"], re.IGNORECASE):
            why.append("the reason names persist")
        if hits:
            why.append("persist spells " + ", ".join(f"`{t}`" for t in hits[:3]))
        out.append({"relation": rel, "csds": sorted(a["csds"]), "owner": "persist" if why else "unknown",
                    "why": "; ".join(why), "reason": a["reason"]})
    return out


# ── the report ──────────────────────────────────────────────────────────────


def cell(items, limit=8) -> str:
    items = list(items)
    if not items:
        return "—"
    shown = ", ".join(f"`{i}`" for i in items[:limit])
    return shown + (f" … (+{len(items) - limit})" if len(items) > limit else "")


def esc(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def report(j, unresolved, unreached, texts, kinds, trace_refs, stops, meta) -> tuple[str, dict]:
    harness = [a for a in j if a in HARNESS_ATOMS]
    no_persist = [a for a, r in j.items() if not r["rows"] and a not in HARNESS_ATOMS]
    no_wit_or_scope = [a for a, r in j.items() if r["rows"] and (not r["witnesses"] or not r["scopes"])]
    text_names = {t["token"] for t in texts}
    kinds_unnamed = sorted(k for k in kinds if k not in text_names
                           and not (k.startswith(KIND_PREFIX) and k[len(KIND_PREFIX):] in text_names))
    never = [t for t in texts if not (t["kind"] or t["literal"] or t["fn"])]
    trace_never = [r for r in trace_refs if not r["exact"]]
    gaps = {
        "a1_chain_refs_without_row": len({(u["claim"], u["ref"]) for u in unresolved if u["why"] == "no row"}),
        "a1b_chain_refs_row_under_other_claim": len({(u["claim"], u["ref"]) for u in unresolved
                                                     if u["why"] != "no row"}),
        "a2_rows_no_atom_reaches": len(unreached),
        "b_atoms_with_persist_claims_no_witness_or_no_scope": len(no_wit_or_scope),
        "b0_atoms_without_persist_claim": len(no_persist),
        "c1_persist_kinds_text_does_not_name": len(kinds_unnamed),
        "c2_text_tokens_persist_never_spells": len(never),
        "trace_refused_keys_persist_never_spells": len(trace_never),
        "harness_atoms": len(harness),
    }
    L = []
    w = L.append
    w("# CSD/4 coverage — persist (v60 S0, report-only)")
    w("")
    w("Generated by `scripts/csd4_coverage.py` from CC's chain manifest "
      "(`tests/fixtures/csd4/csd4_chain.json`). Do not hand-edit; re-run it.")
    w("")
    w("| input | at |")
    w("|---|---|")
    for k, v in meta.items():
        w(f"| {k} | {v} |")
    w("")
    w("## Gap counts")
    w("")
    w("| gap | count |")
    w("|---|---:|")
    w(f"| (a) chain evidence refs to persist with no `cc_impl.tsv` row (distinct claim, ref) | {gaps['a1_chain_refs_without_row']} |")
    w(f"| (a) chain refs whose row sits under a different claim (distinct claim, ref) | {gaps['a1b_chain_refs_row_under_other_claim']} |")
    w(f"| (a) `cc_impl.tsv` rows no atom reaches | {gaps['a2_rows_no_atom_reaches']} |")
    w(f"| (b) atoms with persist claims but no witness or no mutation scope | {gaps['b_atoms_with_persist_claims_no_witness_or_no_scope']} |")
    w(f"| (b) atoms whose claims carry no persist evidence (harness atoms excluded) | {gaps['b0_atoms_without_persist_claim']} |")
    w(f"| (c) persist `kind()` tokens the text does not name | {gaps['c1_persist_kinds_text_does_not_name']} |")
    w(f"| (c) text tokens (`refusal_tokens`) persist never spells (no kind, literal or fn) | {gaps['c2_text_tokens_persist_never_spells']} |")
    w(f"| traces.json `refused` keys persist never spells | {gaps['trace_refused_keys_persist_never_spells']} |")
    w(f"| harness-level atoms (no claim by design; not a gap) | {gaps['harness_atoms']} |")
    w("")
    n = len(j)
    w(f"Of {n} atoms: {sum(1 for r in j.values() if r['claims'])} carry a CC claim, "
      f"{sum(1 for r in j.values() if r['rows'])} reach a persist evidence row "
      f"({sum(1 for r in j.values() if r['by_invariant'])} through a `by_invariant` claim), "
      f"{sum(1 for r in j.values() if r['witnesses'])} reach a witness file, "
      f"{sum(1 for r in j.values() if r['scopes'])} reach a mutation scope, and "
      f"{sum(1 for r in j.values() if r['named_by'])} are named (in backticks) by a witness file.")
    w("")
    w("A `by_section` claim sits under the atom's CC section without a formal link to its state; a "
      "`by_invariant` claim is the invariant over the atom's state variables. A witness file that names a "
      "symbol is not proof it asserts the atom's `state_predicate`.")
    w("")
    w("### (a) Chain evidence refs with no `cc_impl.tsv` row, or under another claim")
    w("")
    w("| atom | claim | ref | finding |")
    w("|---|---|---|---|")
    for u in unresolved:
        w(f"| `{u['atom']}` | `{u['claim']}` | `{u['ref']}` | {esc(u['why'])} |")
    if not unresolved:
        w("| — | — | — | none |")
    w("")
    w(f"### (a) `cc_impl.tsv` rows no atom reaches ({len(unreached)})")
    w("")
    w("The chain pins persist at `_meta.pins.evidence_pins.CIRISPersist`; rows added after it are "
      "unreached until CC re-pins.")
    w("")
    w("| path#symbol | claim | decimal |")
    w("|---|---|---|")
    for r in unreached:
        ref, claim, dec = r.split("\t")
        w(f"| `{ref}` | `{claim}` | {dec} |")
    w("")
    w("### (b) Atoms with persist claims but no witness or no scope")
    w("")
    w("| atom | cc_ref | persist rows | witness files | scopes |")
    w("|---|---|---:|---:|---|")
    for a in no_wit_or_scope:
        r = j[a]
        w(f"| `{a}` | {esc(r['cc_ref'])} | {len(r['rows'])} | {len(r['witnesses'])} | {cell(r['scopes'])} |")
    w("")
    w("### (b) Atoms whose claims carry no persist evidence")
    w("")
    w("| atom | plane | cc_ref | CC claims |")
    w("|---|---|---|---|")
    for a in no_persist:
        r = j[a]
        w(f"| `{a}` | {r['plane']} | {esc(r['cc_ref'])} | {cell(r['claims'], 4)} |")
    w("")
    w("### Harness-level atoms (no claim by design)")
    w("")
    for a in harness:
        w(f"- `{a}` ({j[a]['plane']}): {esc(j[a]['predicate'])}; promised by {cell(j[a]['promised_by'])}")
    w("")
    w("### (c) Persist `kind()` tokens the text does not name")
    w("")
    w("| token | kind() in |")
    w("|---|---|")
    for k in kinds_unnamed:
        w(f"| `{k}` | `{kinds[k]}` |")
    w("")
    w("### (c) Text tokens and persist")
    w("")
    w("Every token CC's text names (`refusal_tokens`), with the text's confidence: `bold` (named as a "
      "token) or `after_refusal` (the word after \"refusal\"). `kind()` = the persist error kind that returns "
      "it (or it with the `federation_` prefix); `literal` = the first non-test src file with it as a string "
      "literal; `fn` = a non-test src fn of that name (a predicate the text names). **never** = none of the "
      "three.")
    w("")
    w("| token | sections | confidence | persist kind() | literal | fn | near kind() |")
    w("|---|---|---|---|---|---|---|")
    for t in texts:
        miss = not (t["kind"] or t["literal"] or t["fn"])
        w(f"| `{t['token']}` | {' '.join(t['sections'])} | {t['confidence']} | "
          f"{('`' + t['kind'] + '`') if t['kind'] else ('**never**' if miss else '—')} | "
          f"{('`' + t['literal'] + '`') if t['literal'] else '—'} | {('`' + t['fn'] + '`') if t['fn'] else '—'} | "
          f"{cell(t['near'], 3)} |")
    w("")
    w("## traces.json `refused` keys persist never spells")
    w("")
    w("CIRISServer's harness output (CC does not own it: `_meta.not_here`). The keys are relation stops "
      "(`rel[k]:<relation>`); the join reads the relation.")
    w("")
    w("| trace | key | near persist strings | persist strings in the reason |")
    w("|---|---|---|---|")
    for r in trace_never:
        w(f"| {r['trace']} | `{r['key']}` | {cell(r['partial'], 3)} | {cell(r['reason_names'], 3)} |")
    w("")
    w("## \"Stops at rel[k]\" relations (CEWPOS catalogue), with an owner guess")
    w("")
    w("`persist` when the stated reason names persist, or the relation is a compound name a persist string "
      "spells; otherwise `unknown` (the chain names the card relations CEWPOS/CIRISClient data).")
    w("")
    w("| relation | CSD rows | CSDs | owner guess | why | reason (first) |")
    w("|---|---:|---|---|---|---|")
    for s in stops:
        w(f"| `{s['relation']}` | {len(s['csds'])} | {cell(s['csds'], 6)} | {s['owner']} | "
          f"{esc(s['why']) or '—'} | {esc(s['reason'])[:160]} |")
    w("")
    w("## Per atom")
    w("")
    w("| atom | plane | cc_ref | persist claims | persist rows | witness files | scopes | named by |")
    w("|---|---|---|---|---|---|---|---|")
    for a, r in j.items():
        w(f"| `{a}` | {r['plane']} | {esc(r['cc_ref'])} | {cell(r['persist_claims'], 4)} | {cell(r['rows'], 4)} | "
          f"{cell(r['witnesses'], 4)} | {cell(r['scopes'])} | {cell(r['named_by'], 3)} |")
    w("")
    return "\n".join(L), gaps


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out")
    ap.add_argument("--cewpos-dir", default=str(REPO.parent / "CEWPOS"))
    a = ap.parse_args(argv[1:])
    chain = load_chain()
    atoms, traces = chain["atoms"], load_traces()
    evidence = load_evidence()
    stops_raw, cew_sha = cewpos_stops(Path(a.cewpos_dir))
    files = src_files()
    literals, kinds, fns = string_literals(files), refusal_kinds(files), fn_names(files)
    j, unresolved, unreached = join(atoms, evidence, load_scopes(), witness_files())
    chain_sha = hashlib.sha256(CHAIN.read_bytes()).hexdigest()
    pins = chain["_meta"].get("pins", {})
    head = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
                          capture_output=True, text=True).stdout.strip() or "?"
    meta = {
        "CC chain": f"`tests/fixtures/csd4/csd4_chain.json` sha256 `{chain_sha[:16]}…` "
                    f"(`_meta.chain_sha256` `{chain['_meta'].get('chain_sha256', '?')[:16]}…`; "
                    f"{len(atoms)} atoms, {len(chain['refusal_tokens'])} text tokens; persist pinned at "
                    f"`{pins.get('evidence_pins', {}).get(PERSIST, '?')}`)",
        "traces": f"`tests/fixtures/csd4/traces.json` ({len(traces)} traces)",
        "persist evidence": f"`evidence/cc_impl.tsv` ({len(evidence)} rows) at persist `{head}`",
        "persist kind() tokens": f"{len(kinds)} distinct",
        "CEWPOS": f"`CSD4_CATALOGUE_AND_MIGRATION_PLAN.md` at `{cew_sha}` ({len(stops_raw)} stop rows)",
    }
    text, gaps = report(j, unresolved, unreached, text_tokens(chain, literals, kinds, fns), kinds,
                        trace_refusals(traces, literals), stops_by_relation(stops_raw, literals), meta)
    if a.out:
        Path(a.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    print("csd4_coverage gaps: " + ", ".join(f"{k}={v}" for k, v in gaps.items()), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
