#!/usr/bin/env python3
"""csd4_coverage.py — the CSD/4 catalogue joined to persist's evidence,
witnesses and mutation scopes (docs/V60_TASK_PLAN.md §3b, S0-csd).

    scripts/csd4_coverage.py [--out <report.md>] [--cc-dir <dir>] [--cc-ref <ref>]
                             [--cewpos-dir <dir>]

A REPORT, NOT A GATE (v60). It becomes a certify gate once CC publishes the
chain as joinable data (atom -> STATE_TABLE state -> formal transition ->
claim ids; the refusal tokens per trace step; the owning repo per "stops at
rel[k]" relation). Until then it joins what exists, from disk:

  (a) every atom of tests/fixtures/csd4/topology_vocabulary.json, by each
      decimal in its `cc_ref`, to the CC `constitution/claims.tsv` rows whose
      `decimal_id` equals it or lies under it (`3.2` takes `3.2` and
      `3.2.1.4`, never `3.20`); read with `git show <cc-ref>:...` from the
      Constitution checkout (default ../CIRISConstitution at origin/rc9);
  (b) those claim ids to persist's rows in evidence/cc_impl.tsv
      (`path#symbol`);
  (c) those symbols to the `*_invariants.rs` files under src/ that name them
      (a word match outside comments is not required: a witness that names
      the door in its doc comment counts, the S0-csd rule), and to every
      scripts/mutants/scope-*.txt entry that covers the file (and, when the
      entry names functions, the symbol); also every `*_invariants.rs` that
      names the ATOM itself in backticks (the rule going forward);
  (d) every key under `refused` in tests/fixtures/csd4/traces.json — the
      relation after `rel[k]:`, or the whole key — to persist's token strings
      (`const ..: &str = "…"` and `=> "…"` match arms in non-test src/);
  (e) the "stops at rel[k]:<relation>" rows of CEWPOS
      CSD4_CATALOGUE_AND_MIGRATION_PLAN.md (default ../CEWPOS), per
      relation, with a best-effort owner guess: `persist` when the relation
      or its stated reason names persist, or a compound relation name is a
      persist token's component, else `unknown`.

Output: a markdown report (stdout, or --out). Exit 0 whatever it finds; 2
when an input cannot be read (the fixtures, the evidence tsv, the CC claims,
the CEWPOS plan). Stdlib only.
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
EVIDENCE = REPO / "evidence" / "cc_impl.tsv"
SCOPES = REPO / "scripts" / "mutants"
DECIMAL = re.compile(r"^\d+(?:\.\d+)*$")
STOP = re.compile(r"stops at (rel\[\d+\]:([A-Za-z0-9_]+)):\s*(.*?)\)\s*\|\s*$")
TOKEN_LIT = re.compile(r'(?:\bconst\s+[A-Z0-9_]+\s*:\s*&(?:\'static\s+)?str\s*=\s*|=>\s*)"([A-Za-z0-9_:.\-]{3,})"')


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


# ── inputs ──────────────────────────────────────────────────────────────────


def load_atoms() -> dict:
    return json.loads(read(FIX / "topology_vocabulary.json"))["atoms"]


def load_traces() -> dict:
    return json.loads(read(FIX / "traces.json"))["entries"]


def load_claims(cc_dir: Path, ref: str) -> tuple[list[dict], str]:
    sha = git(cc_dir, "rev-parse", ref).strip()
    text = git(cc_dir, "show", f"{sha}:constitution/claims.tsv")
    rows = []
    lines = text.splitlines()
    head = lines[0].split("\t")
    for line in lines[1:]:
        if not line.strip() or line.startswith("#"):
            continue
        cells = dict(zip(head, line.split("\t")))
        if cells.get("claim_id") and cells.get("decimal_id"):
            rows.append(cells)
    return rows, sha


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


def persist_tokens() -> dict[str, str]:
    """token -> first file that spells it, from non-test src/."""
    out: dict[str, str] = {}
    for p in sorted((REPO / "src").rglob("*.rs")):
        if p.name.endswith("_invariants.rs") or p.name == "tests.rs":
            continue
        for tok in TOKEN_LIT.findall(strip_comments(read(p))):
            out.setdefault(tok, str(p.relative_to(REPO)))
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


def decimals(cc_ref: str) -> list[str]:
    return [t for t in cc_ref.split() if DECIMAL.match(t)]


def under(decimal: str, section: str) -> bool:
    return decimal == section or decimal.startswith(section + ".")


def word(sym: str) -> re.Pattern:
    return re.compile(r"\b" + re.escape(sym) + r"\b")


def distinctive(sym: str) -> bool:
    """A symbol whose bare name is unlikely to collide: snake_case of two
    words or more, or a long CamelCase type."""
    return ("_" in sym and len(sym) >= 8) or (sym[:1].isupper() and len(sym) >= 10)


def witnesses_of(path: str, sym: str, witnesses: dict[str, str]) -> list[str]:
    """The witness files that name `sym`; for a common name (`gate`, `plan`),
    only those that also name its module (`self_roster`)."""
    pat, stem = word(sym), Path(path).stem
    return [f for f, t in witnesses.items()
            if pat.search(t) and (distinctive(sym) or stem in t)]


def join(atoms, claims, evidence, scopes, witnesses):
    by_claim = defaultdict(list)
    for e in evidence:
        by_claim[e["claim"]].append(e)
    sym_witness: dict[str, list[str]] = {}
    out = {}
    for name, a in atoms.items():
        secs = decimals(a.get("cc_ref", ""))
        cl = sorted({c["claim_id"] for c in claims for s in secs if under(c["decimal_id"], s)})
        rows = [e for c in cl for e in by_claim.get(c, [])]
        syms = sorted({f"{e['path']}#{e['symbol']}" for e in rows})
        wit, sco = set(), set()
        for e in rows:
            if e["path"].startswith("src/") and e["symbol"]:
                key = f"{e['path']}#{e['symbol']}"
                if key not in sym_witness:
                    sym_witness[key] = witnesses_of(e["path"], e["symbol"], witnesses)
                wit.update(sym_witness[key])
            for scope, file, fns in scopes:
                if file == e["path"] and (not fns or e["symbol"] in fns):
                    sco.add(scope)
        named = sorted(f for f, t in witnesses.items() if f"`{name}`" in t)
        out[name] = {"plane": a.get("plane", ""), "cc_ref": a.get("cc_ref", ""), "decimals": secs,
                     "claims": cl, "symbols": syms, "witnesses": sorted(wit), "scopes": sorted(sco),
                     "named_by": named}
    return out


def compound(tok: str) -> bool:
    return "_" in tok or ":" in tok


def refusals(traces, tokens):
    out = []
    for tid, e in sorted(traces.items(), key=lambda kv: int(kv[0][1:])):
        for key, reason in sorted(e.get("refused", {}).items()):
            tok = key.split(":", 1)[1] if ":" in key else key
            # A one-word token (`agent`, `delegation`) spelled somewhere is an
            # identity type or a label, not evidence persist emits the
            # refusal: only a compound token's exact spelling counts.
            exact = tok in tokens and compound(tok)
            partial = sorted(t for t in tokens if tok in t and t != tok)[:4]
            named = sorted({t for t in re.findall(r"[A-Za-z0-9_:.\-]{4,}", reason) if t in tokens})
            if tok in tokens and not exact:
                partial = [f"{tok} (a plain word in {tokens[tok]})"] + partial[:3]
            out.append({"trace": tid, "key": key, "token": tok, "exact": exact,
                        "exact_file": tokens.get(tok, ""), "partial": partial,
                        "reason_names": named, "reason": reason})
    return out


def stops_by_relation(stops, tokens):
    agg = defaultdict(lambda: {"csds": set(), "rels": set(), "reason": ""})
    for s in stops:
        a = agg[s["relation"]]
        a["csds"].add(s["csd"])
        a["rels"].add(s["rel"])
        a["reason"] = a["reason"] or s["reason"]
    out = []
    for rel, a in sorted(agg.items(), key=lambda kv: (-len(kv[1]["csds"]), kv[0])):
        tok_hits = sorted(t for t in tokens if re.search(r"(^|[_:.])" + re.escape(rel) + r"($|[_:.])", t)) \
            if compound(rel) else []
        why = []
        if re.search(r"\bpersist\b", a["reason"], re.IGNORECASE):
            why.append("the reason names persist")
        if tok_hits:
            why.append("persist spells " + ", ".join(f"`{t}`" for t in tok_hits[:3]))
        out.append({"relation": rel, "csds": sorted(a["csds"]), "rels": sorted(a["rels"]),
                    "owner": "persist" if why else "unknown", "why": "; ".join(why), "reason": a["reason"]})
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


def report(j, refs, stops, meta) -> tuple[str, dict]:
    no_claim = [a for a, r in j.items() if not r["symbols"]]
    no_wit_or_scope = [a for a, r in j.items() if r["symbols"] and (not r["witnesses"] or not r["scopes"])]
    never = [r for r in refs if not r["exact"]]
    gaps = {"atoms_without_persist_claim": len(no_claim),
            "atoms_with_claims_but_no_witness_or_no_scope": len(no_wit_or_scope),
            "refusal_tokens_persist_never_emits": len(never)}
    L = []
    w = L.append
    w("# CSD/4 coverage — persist (v60 S0, report-only)")
    w("")
    w("Generated by `scripts/csd4_coverage.py` (docs/V60_TASK_PLAN.md §3b). Do not hand-edit; re-run it.")
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
    w(f"| atoms with no persist claim (no `cc_impl.tsv` row under any claim their `cc_ref` reaches) | {gaps['atoms_without_persist_claim']} |")
    w(f"| atoms with persist claims but no witness or no mutation scope | {gaps['atoms_with_claims_but_no_witness_or_no_scope']} |")
    w(f"| refusal tokens in `traces.json` persist never emits (no exact token string) | {gaps['refusal_tokens_persist_never_emits']} |")
    w("")
    n = len(j)
    w(f"Of {n} atoms: {sum(1 for r in j.values() if r['claims'])} reach a CC claim, "
      f"{sum(1 for r in j.values() if r['symbols'])} reach a persist evidence row, "
      f"{sum(1 for r in j.values() if r['witnesses'])} reach a witness file through those rows, "
      f"{sum(1 for r in j.values() if r['scopes'])} reach a mutation scope, and "
      f"{sum(1 for r in j.values() if r['named_by'])} are named (in backticks) by a witness file.")
    w("")
    w("Read the joins as UPPER bounds: a claim under an atom's section is not proof the claim realises the "
      "atom's `state_predicate`, and a witness file that names a symbol is not proof it asserts the atom. The "
      "chain becomes exact when CC publishes atom -> state -> transition -> claim ids.")
    w("")
    w("### 1. Atoms with no persist claim")
    w("")
    w("| atom | plane | cc_ref | CC claims under it |")
    w("|---|---|---|---|")
    for a in no_claim:
        r = j[a]
        w(f"| `{a}` | {r['plane']} | {esc(r['cc_ref'])} | {len(r['claims'])} |")
    w("")
    w("### 2. Atoms with claims but no witness or no scope")
    w("")
    w("| atom | cc_ref | persist rows | witness files | scopes |")
    w("|---|---|---:|---:|---|")
    for a in no_wit_or_scope:
        r = j[a]
        w(f"| `{a}` | {esc(r['cc_ref'])} | {len(r['symbols'])} | {len(r['witnesses'])} | {cell(r['scopes'])} |")
    w("")
    w("### 3. Refusal tokens persist never emits")
    w("")
    w("The `refused` keys are the builder's relation stops (`rel[k]:<relation>`), not persist refusal tokens; "
      "the join reads the relation. `persist strings in the reason` lists persist tokens the stated reason "
      "spells (a lead, not a match).")
    w("")
    w("| trace | key | token | near persist strings | persist strings in the reason |")
    w("|---|---|---|---|---|")
    for r in never:
        w(f"| {r['trace']} | `{r['key']}` | `{r['token']}` | {cell(r['partial'], 3)} | {cell(r['reason_names'], 3)} |")
    w("")
    w("## Refusal-map tokens persist spells (an exact compound token)")
    w("")
    w("| trace | key | token | spelled in |")
    w("|---|---|---|---|")
    for r in refs:
        if r["exact"]:
            w(f"| {r['trace']} | `{r['key']}` | `{r['token']}` | `{r['exact_file']}` |")
    if not any(r["exact"] for r in refs):
        w("| — | — | — | none |")
    w("")
    w("## \"Stops at rel[k]\" relations (CEWPOS catalogue), with an owner guess")
    w("")
    w("`persist` when the stated reason names persist, or the relation is a compound name a persist token "
      "spells; otherwise `unknown` (a one-word relation such as `agent` matches too much to guess from; CC "
      "has been asked for the owning repo per relation).")
    w("")
    w("| relation | CSD rows | CSDs | owner guess | why | reason (first) |")
    w("|---|---:|---|---|---|---|")
    for s in stops:
        w(f"| `{s['relation']}` | {len(s['csds'])} | {cell(s['csds'], 6)} | {s['owner']} | {esc(s['why']) or '—'} | {esc(s['reason'])[:160]} |")
    w("")
    w("## Per atom")
    w("")
    w("| atom | plane | cc_ref | CC claims | persist symbols | witness files | scopes | named by |")
    w("|---|---|---|---|---|---|---|---|")
    for a, r in j.items():
        w(f"| `{a}` | {r['plane']} | {esc(r['cc_ref'])} | {cell(r['claims'], 4)} | {cell(r['symbols'], 4)} | "
          f"{cell(r['witnesses'], 4)} | {cell(r['scopes'])} | {cell(r['named_by'], 3)} |")
    w("")
    return "\n".join(L), gaps


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out")
    ap.add_argument("--cc-dir", default=str(REPO.parent / "CIRISConstitution"))
    ap.add_argument("--cc-ref", default="origin/rc9")
    ap.add_argument("--cewpos-dir", default=str(REPO.parent / "CEWPOS"))
    a = ap.parse_args(argv[1:])
    atoms, traces = load_atoms(), load_traces()
    claims, cc_sha = load_claims(Path(a.cc_dir), a.cc_ref)
    evidence = load_evidence()
    stops_raw, cew_sha = cewpos_stops(Path(a.cewpos_dir))
    tokens = persist_tokens()
    j = join(atoms, claims, evidence, load_scopes(), witness_files())
    pin_sha = hashlib.sha256((FIX / "PIN.md").read_bytes()).hexdigest()
    head = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
                          capture_output=True, text=True).stdout.strip() or "?"
    meta = {
        "csd4 fixtures": f"`tests/fixtures/csd4/` (PIN.md sha256 `{pin_sha[:16]}…`; {len(atoms)} atoms, {len(traces)} traces)",
        "CC claims": f"CIRISConstitution `{a.cc_ref}` = `{cc_sha}` `constitution/claims.tsv` ({len(claims)} claims)",
        "persist evidence": f"`evidence/cc_impl.tsv` ({len(evidence)} rows) at persist `{head}`",
        "CEWPOS": f"`CSD4_CATALOGUE_AND_MIGRATION_PLAN.md` at `{cew_sha}` ({len(stops_raw)} stop rows)",
    }
    text, gaps = report(j, refusals(traces, tokens), stops_by_relation(stops_raw, tokens), meta)
    if a.out:
        Path(a.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    print("csd4_coverage gaps: " + ", ".join(f"{k}={v}" for k, v in gaps.items()), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
