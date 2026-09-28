#!/usr/bin/env python3
"""manifest_diff.py — the family diff between two vendored namespace registries.

CIRISPersist#924. A re-vendor of `src/federation/namespace/namespace_registry.json`
moves families, their segment grammar, their leaves and the `_meta` grammar
keys. Downstream adopters (CIRISEdge) need that diff stated, computed from the
bytes rather than estimated. Run it for every re-vendor:

  python3 scripts/manifest_diff.py <old git ref> [<new git ref>]   # default new: the working tree
  python3 scripts/manifest_diff.py --files OLD.json NEW.json

Reports: (a) families added, (b) families removed — each paired with an added
family on the same leading literal stem as a POSSIBLE rename (a heuristic; CC's
RETIRED_FAMILIES is the authority), (c) existing families whose segments,
`leaves` / `leaves_closed`, `segments[].values` / `open` / `multi` / `pattern` /
`variadic`, reserved rule or polarity changed, and (d) `_meta` / `_meta.case_rule`
keys that changed (including `reserved_stems` and `version_segment`).
Stdlib only. Exit 0 always — this is a report, not a gate.
"""
import json, subprocess, sys

REL = "src/federation/namespace/namespace_registry.json"
SEG_KEYS = ("class", "pattern", "values", "open", "multi", "variadic", "standard")
ROW_KEYS = ("leaves", "leaves_closed", "reserved", "reserved_rule", "polarity",
            "owning_component", "owning_repo", "cc_section")


def load(ref):
    if ref is None:
        return json.load(open(REL, encoding="utf-8"))
    return json.loads(subprocess.check_output(["git", "show", "%s:%s" % (ref, REL)]))


def stem(prefix):
    return prefix.split(":", 1)[0]


def seg_view(fam):
    return [{k: s.get(k) for k in ("segment",) + SEG_KEYS if k in s} for s in fam.get("segments", [])]


def main(argv):
    if argv[:1] == ["--files"]:
        old, new = (json.load(open(p, encoding="utf-8")) for p in argv[1:3])
        labels = argv[1:3]
    else:
        if not argv:
            sys.stderr.write(__doc__)
            return 2
        old, new = load(argv[0]), load(argv[1] if len(argv) > 1 else None)
        labels = [argv[0], argv[1] if len(argv) > 1 else "working tree"]
    A = {f["prefix"]: f for f in old["families"]}
    B = {f["prefix"]: f for f in new["families"]}
    om, nm = old["_meta"], new["_meta"]
    print("# namespace registry diff: %s -> %s" % tuple(labels))
    print("families: %d -> %d (net %+d)" % (len(A), len(B), len(B) - len(A)))
    for k in ("cc_version", "source_sha256", "registry_sha256"):
        print("_meta.%s: %s -> %s" % (k, om.get(k), nm.get(k)))
    added = sorted(set(B) - set(A))
    removed = sorted(set(A) - set(B))
    print("\n## (a) added (%d)" % len(added))
    for p in added:
        print("  + %s" % p)
    print("\n## (b) removed (%d)" % len(removed))
    for p in removed:
        cands = [q for q in added if stem(q) == stem(p)]
        print("  - %s%s" % (p, ("   possible rename -> " + ", ".join(cands)) if cands else ""))
    print("\n## (c) existing families that changed")
    n = 0
    for p in sorted(set(A) & set(B)):
        a, b = A[p], B[p]
        notes = []
        sa, sb = seg_view(a), seg_view(b)
        if sa != sb:
            for i in range(max(len(sa), len(sb))):
                x = sa[i] if i < len(sa) else None
                y = sb[i] if i < len(sb) else None
                if x != y:
                    notes.append("segments[%d]: %s -> %s" % (i, json.dumps(x, sort_keys=True),
                                                            json.dumps(y, sort_keys=True)))
        for k in ROW_KEYS:
            if a.get(k) != b.get(k):
                notes.append("%s: %s -> %s" % (k, json.dumps(a.get(k), sort_keys=True),
                                               json.dumps(b.get(k), sort_keys=True)))
        if a.get("description") != b.get("description"):
            notes.append("description (prose) changed")
        extra = sorted((set(a) | set(b)) - set(ROW_KEYS) - {"prefix", "segments", "description"})
        for k in extra:
            if a.get(k) != b.get(k):
                notes.append("%s: %s -> %s" % (k, json.dumps(a.get(k), sort_keys=True),
                                               json.dumps(b.get(k), sort_keys=True)))
        if notes:
            n += 1
            print("  ~ %s" % p)
            for x in notes:
                print("      %s" % x)
    if not n:
        print("  (none)")
    print("\n## (d) _meta / _meta.case_rule keys that changed")
    oc, nc = om.get("case_rule", {}), nm.get("case_rule", {})
    for k in sorted(set(om) | set(nm)):
        if k in ("case_rule", "source_sha256", "registry_sha256"):
            continue
        if om.get(k) != nm.get(k):
            print("  _meta.%s: %s -> %s" % (k, json.dumps(om.get(k), sort_keys=True),
                                            json.dumps(nm.get(k), sort_keys=True)))
    for k in sorted(set(oc) | set(nc)):
        if oc.get(k) != nc.get(k):
            state = "added" if k not in oc else "removed" if k not in nc else "changed"
            print("  _meta.case_rule.%s: %s" % (k, state))
            if k == "reserved_stems":
                for s in nc.get(k, []):
                    print("      stem %-28s kind=%-9s %s (%s)" % (s["stem"], s["kind"], s["rule"], s["cc_ref"]))
            if k == "version_segment":
                vs = nc.get(k, {})
                print("      pattern=%s position=%s required=%s exempt=%s"
                      % (vs.get("pattern"), vs.get("position"), vs.get("required"), vs.get("exempt")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
