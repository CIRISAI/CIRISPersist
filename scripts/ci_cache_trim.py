#!/usr/bin/env python3
"""ci_cache_trim.py — drop this crate's own build outputs from target/ before a
CIRISCache save (CIRISPersist#1022).

    scripts/ci_cache_trim.py <target-dir>            names from `cargo metadata`
    scripts/ci_cache_trim.py <target-dir> NAME...    names given (the self-test)

WHY. The save prunes target/ to its `max-size-mb` budget by deleting the
OLDEST-mtime files (CIRISCache `cc_prune_lru`). Cargo never touches a fresh
unit's files, so the oldest files are the dependencies this run did not need to
rebuild: exactly what the next run would reuse. The v54.0.0 tag run's core-1
target/ was 21.9 GB against a 12 GB budget; 7.7 GB of what survived the prune
was ciris-persist's own lib, test and bench binaries, which every run rebuilds
on a new commit and no downstream build can reuse (a path package here, a git
package there). The prune deleted dependency fingerprints instead: restoring
that blob, a core-1 build recompiled 27 crates (8 with no fingerprint left, 17
more behind them, pyo3, persist), where the blob before it had recompiled all
436. With these outputs gone first, target/ fits the budget and nothing a later
build reuses is pruned.

Deleted, under target/<profile>/ and target/<triple>/<profile>/ (a directory
holding `deps/` or `.fingerprint/`):
  deps/<name>-<16 hex>[.*] and deps/lib<name>-<16 hex>.*   (lib, test, bench, example)
  examples/<name>[-<16 hex>][.*]
  <name>, lib<name>.* (the uplifted copies)
  .fingerprint/<package>-<16 hex>/, build/<package>-<16 hex>/, incremental/<name>-*/
where <name> is each of the package's target names (dashes as underscores) and
<package> its package name. Nothing else is touched.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HASH = r"-[0-9a-f]{16}"


def names_from_cargo() -> tuple[set[str], set[str]]:
    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        check=True, capture_output=True, text=True).stdout)
    targets, packages = set(), set()
    for p in meta["packages"]:
        packages.add(p["name"])
        for t in p["targets"]:
            targets.add(t["name"].replace("-", "_"))
    return targets, packages


def size(p: Path) -> int:
    if p.is_symlink() or p.is_file():
        return p.lstat().st_size
    return sum(f.lstat().st_size for f in p.rglob("*") if f.is_file() or f.is_symlink())


def victims(target: Path, targets: set[str], packages: set[str]) -> list[Path]:
    t = "|".join(sorted(re.escape(n) for n in targets))
    pk = "|".join(sorted(re.escape(n) for n in packages))
    in_deps = re.compile(rf"^(lib)?({t}){HASH}(\..*)?$")
    in_examples = re.compile(rf"^({t})({HASH})?(\..*)?$")
    uplifted = re.compile(rf"^(lib)?({t})(\.[A-Za-z0-9.]+)?$")
    unit_dir = re.compile(rf"^({pk}){HASH}$")
    incr = re.compile(rf"^({t})-[0-9a-z]+$")
    out = []
    # target/<profile>/ and, for a cross build, target/<triple>/<profile>/.
    cands = [p for p in target.iterdir() if p.is_dir()]
    cands += [q for p in cands for q in p.iterdir() if q.is_dir()]
    profiles = [p for p in cands if (p / "deps").is_dir() or (p / ".fingerprint").is_dir()]
    for profile in sorted(profiles):
        for sub, rx in (("deps", in_deps), ("examples", in_examples),
                        (".fingerprint", unit_dir), ("build", unit_dir), ("incremental", incr)):
            d = profile / sub
            if d.is_dir():
                out += [e for e in sorted(d.iterdir()) if rx.match(e.name)]
        out += [e for e in sorted(profile.iterdir())
                if (e.is_file() or e.is_symlink()) and uplifted.match(e.name)]
    return out


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    target = Path(argv[1])
    if not target.is_dir():
        print(f"no target directory at {target}; nothing to trim")
        return 0
    if len(argv) > 2:
        targets = {n.replace("-", "_") for n in argv[2:]}
        packages = set(argv[2:])
    else:
        try:
            targets, packages = names_from_cargo()
        except (OSError, subprocess.CalledProcessError, ValueError, KeyError) as e:
            # An optimisation, not a gate: without names nothing is trimmed and
            # the save prunes as it did before. Say so where it is read.
            print(f"::warning::ci_cache_trim: cargo metadata failed ({e}); target/ not trimmed")
            return 0
    gone = victims(target, targets, packages)
    before = size(target)
    freed = 0
    for v in gone:
        freed += size(v)
        if v.is_dir() and not v.is_symlink():
            shutil.rmtree(v)
        else:
            v.unlink()
    print(f"ci_cache_trim: removed {len(gone)} own outputs ({freed / 2**30:.2f} GiB) of "
          f"{sorted(packages)}; target/ {before / 2**30:.2f} → {size(target) / 2**30:.2f} GiB")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
