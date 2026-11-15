#!/usr/bin/env python3
"""v62.0.0 (slice C) — fold a CIRIS_KERNEL_DIFF_LOG file into the
DIFFERENCES.md table: per function, the DISTINCT calls (by input key), how
many agree, and how many depart by each named class.

    python3 scripts/kernel_diff_counts.py <log.tsv> [<log.tsv> ...]

Exits 1 if any line is UNEXPLAINED (the I1838 witness panics on those too).
"""
import collections
import sys


def main(paths):
    seen = {}
    for path in paths:
        with open(path, encoding="utf-8") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 3:
                    continue
                fn, cls, key = parts[0], parts[1], parts[2]
                seen[(fn, key)] = cls
    table = collections.defaultdict(collections.Counter)
    for (fn, _), cls in seen.items():
        table[fn][cls] += 1
    bad = 0
    print("| function | distinct calls | agree | departs (class: n) |")
    print("|---|---|---|---|")
    for fn in sorted(table):
        c = table[fn]
        dep = ", ".join(f"{k}: {v}" for k, v in sorted(c.items()) if k != "agree")
        print(f"| {fn} | {sum(c.values())} | {c['agree']} | {dep or '0'} |")
        bad += c.get("UNEXPLAINED", 0)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
