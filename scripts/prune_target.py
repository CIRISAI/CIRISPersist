#!/usr/bin/env python3
"""prune_target.py — drop superseded build artifacts, keeping the newest per name.

`certify.sh` calls this when free disk falls below its per-leg floor
(CIRISPersist#1012). Every dependency re-pin and every feature set leaves a
complete generation of `<crate>-<hash>` artifacts in `target/<profile>/deps`,
and nothing ever removes the old ones: release worktree targets measured 62 GB
and 77 GB, and sibling repos' targets held 17–24 superseded copies of a crate.

A UNIT is every file sharing one `<crate>-<hash>` (its .rlib, .rmeta, .d, .so,
test executable). Units are grouped by crate name AND kind — a library unit
never competes with an executable of the same name, since `libfoo-A.rlib` and
the test binary `foo-B` are both current outputs of one build — ranked by
their newest mtime, and all but the newest `--keep` per group are deleted. The same rule
applies to `target/<profile>/incremental/<crate>-<hash>/` directories.

What is NOT touched: `.fingerprint/` and `build/`. A unit whose outputs are
gone is rebuilt by cargo on its next use (its fingerprint reports a missing
output), so the cost of pruning something still wanted is a recompile, never a
wrong result.

It is NOT safe while a build or a nextest run is using this target dir —
nextest re-execs its test binaries once per test. `certify.sh` drains its
in-flight legs before calling it.

    scripts/prune_target.py [--target DIR] [--profile debug] [--keep 1] [--dry-run]

The LAST line printed is the summary (certify.sh tails it).
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from collections import defaultdict
from pathlib import Path

#: `<name>-<16 hex>` with an optional extension. Library outputs carry a `lib`
#: prefix that is NOT part of the crate name (`liblibc-….rlib` is crate `libc`);
#: `.d` files and executables do not.
UNIT = re.compile(r"^(?P<stem>.+)-(?P<hash>[0-9a-f]{16})(?P<ext>\.[A-Za-z0-9.]+)?$")
LIB_EXTS = {".rlib", ".rmeta", ".so", ".a", ".dylib", ".dll", ".lib"}


def crate_name(stem: str, ext: str | None) -> str:
    if ext in LIB_EXTS and stem.startswith("lib"):
        return stem[3:]
    return stem


def size_of(p: Path) -> int:
    if p.is_symlink() or p.is_file():
        try:
            return p.lstat().st_size
        except OSError:
            return 0
    total = 0
    for root, _dirs, files in os.walk(p):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


def mtime_of(p: Path) -> float:
    try:
        return p.lstat().st_mtime
    except OSError:
        return 0.0


def plan(dirpath: Path, keep: int) -> list[Path]:
    """Every path in `dirpath` belonging to a superseded unit."""
    units: dict[tuple[str, str], list[Path]] = defaultdict(list)
    for entry in dirpath.iterdir():
        m = UNIT.match(entry.name)
        if not m:
            continue
        units[(crate_name(m["stem"], m["ext"]), m["hash"])].append(entry)
    by_group: dict[tuple[str, bool], list[tuple[float, str]]] = defaultdict(list)
    for (name, h), paths in units.items():
        is_lib = any(UNIT.match(p.name)["ext"] in LIB_EXTS for p in paths)
        by_group[(name, is_lib)].append((max(mtime_of(p) for p in paths), h))
    doomed: list[Path] = []
    for (name, _is_lib), gens in by_group.items():
        gens.sort(reverse=True)
        for _mt, h in gens[keep:]:
            doomed.extend(units[(name, h)])
    return doomed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--target", default=os.environ.get("CARGO_TARGET_DIR", "target"))
    ap.add_argument("--profile", action="append", help="profile dir(s) under target (default: debug)")
    ap.add_argument("--keep", type=int, default=1, help="generations kept per crate name (default 1)")
    ap.add_argument("--dry-run", action="store_true", help="report, delete nothing")
    args = ap.parse_args()
    if args.keep < 1:
        ap.error("--keep must be >= 1")

    target = Path(args.target)
    # Refuse anything that is not recognisably a cargo target dir: this script
    # deletes, and a mistyped --target must not be able to point it elsewhere.
    if not (target / "CACHEDIR.TAG").is_file():
        print(f"refusing: {target} has no CACHEDIR.TAG — not a cargo target directory", file=sys.stderr)
        return 2

    freed = files = 0
    for prof in args.profile or ["debug"]:
        for sub in ("deps", "incremental"):
            d = target / prof / sub
            if not d.is_dir():
                continue
            for p in plan(d, args.keep):
                n = size_of(p)
                if args.dry_run:
                    print(f"would remove {p} ({n / 2**20:.1f} MiB)")
                else:
                    try:
                        if p.is_dir() and not p.is_symlink():
                            shutil.rmtree(p)
                        else:
                            p.unlink()
                    except OSError as e:
                        print(f"could not remove {p}: {e}", file=sys.stderr)
                        continue
                freed += n
                files += 1
    verb = "would free" if args.dry_run else "freed"
    print(f"prune_target: {files} superseded artifacts, {verb} {freed / 2**30:.2f} GiB "
          f"in {target} (kept newest {args.keep} per crate name and kind)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
