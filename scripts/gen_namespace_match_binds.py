#!/usr/bin/env python3
"""gen_namespace_match_binds.py — the reference-output oracle for the matcher replay.

CIRISPersist#924 (CIRISConstitution#112). CC publishes
`manifests/namespace_match_vectors.json` with each dimension's expected
(family, refusal) but NOT the placeholder binds, and on a
`namespace_dimension_case_malformed` refusal its family is only best-effort
attribution (the reference itself may name a different one). Persist's replay
(`federation::namespace::matcher::tests::namespace_match_vectors_replay`)
compares binds too, and holds the port to the reference's EXACT family, so this script runs the CC REFERENCE matcher
(`tools/cc_namespace_match.py`, read from the pinned CIRISConstitution commit
with `git show`, never a checkout) over the VENDORED registry and vectors and
writes `src/federation/namespace/namespace_match_binds.json`.

Usage:
  python3 scripts/gen_namespace_match_binds.py <CIRISConstitution repo> <commit>
  python3 scripts/gen_namespace_match_binds.py <repo> <commit> --check
"""
import hashlib, importlib.util, json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
NS = os.path.join(HERE, "..", "src", "federation", "namespace")
REGISTRY = os.path.join(NS, "namespace_registry.json")
VECTORS = os.path.join(NS, "namespace_match_vectors.json")
OUT = os.path.join(NS, "namespace_match_binds.json")


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    repo, commit = argv[0], argv[1]
    full = subprocess.check_output(["git", "-C", repo, "rev-parse", commit], text=True).strip()
    for rel, local in (("manifests/namespace_registry.json", REGISTRY),
                       ("manifests/namespace_match_vectors.json", VECTORS)):
        upstream = subprocess.check_output(["git", "-C", repo, "show", "%s:%s" % (full, rel)])
        if upstream != open(local, "rb").read():
            sys.stderr.write("%s is not byte-identical to %s at %s\n" % (local, rel, full))
            return 1
    src = subprocess.check_output(["git", "-C", repo, "show", full + ":tools/cc_namespace_match.py"])
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "cc_namespace_match.py")
        open(path, "wb").write(src)
        spec = importlib.util.spec_from_file_location("cc_namespace_match", path)
        ref = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ref)
    rules = ref.Rules(json.load(open(REGISTRY, encoding="utf-8")))
    vectors_bytes = open(VECTORS, "rb").read()
    out = {
        "_meta": {
            "cc_commit": full,
            "generator": "scripts/gen_namespace_match_binds.py",
            "reference": "tools/cc_namespace_match.py",
            "vectors_sha256": hashlib.sha256(vectors_bytes).hexdigest(),
        },
        "binds": [],
    }
    for v in json.loads(vectors_bytes)["vectors"]:
        fam, binds, refusal = ref.match_family(rules, v["dimension"])
        # CC's contract (cc_namespace_match.self_test): on a case_malformed
        # refusal the family is best-effort attribution, so the vector's family
        # may differ from the reference's own; every other field is exact.
        family_ok = fam == v["family"] or (v["refusal"] == rules.tokens["case_malformed"]
                                           and fam is not None)
        if not family_ok or refusal != v["refusal"]:
            sys.stderr.write("reference disagrees with its own vector: %r\n" % v["dimension"])
            return 1
        out["binds"].append({"dimension": v["dimension"], "family": fam, "binds": binds,
                             "refusal": refusal})
    text = json.dumps(out, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    if argv[2:3] == ["--check"]:
        if open(OUT, encoding="utf-8").read() != text:
            sys.stderr.write("namespace_match_binds.json is stale\n")
            return 1
        print("binds oracle current (%d vectors)" % len(out["binds"]))
        return 0
    open(OUT, "w", encoding="utf-8").write(text)
    print("wrote %s (%d vectors)" % (os.path.relpath(OUT), len(out["binds"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
