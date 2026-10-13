#!/usr/bin/env python3
"""ci_cache_units.py — keep a CIRISCache target/ self-consistent at the cargo
UNIT level (v55.0.1).

    scripts/ci_cache_units.py seal   <target-dir>   before a CIRISCache save
    scripts/ci_cache_units.py repair <target-dir>   after a CIRISCache restore
    scripts/ci_cache_units.py --self-test

WHY. The CIRISCache save prunes target/ to its budget by deleting the
OLDEST-mtime FILES (`cc_prune_lru`), one file at a time. A build-script run's
outputs (`build/<pkg>-<hash>/out/...`) are written once and never touched
again, so they are among the oldest files and the prune can drop one while
keeping the unit's fingerprint. Cargo then reads the build-script run as fresh
and `include!`s a file that is not there: the v55.0.0 tag's Windows wheel job
failed twice on `libsqlite3-sys-…/out/bindgen.rs` that way, and every restore
of that blob fails the same.

SEAL (save side). For every build-script unit `build/<pkg>-<hash>/` (the
compiled script's dir and the run's dir alike), write `out.manifest`: every
file in the unit, relative, sorted, one per line. Then touch every file under
`build/*/out/` to now, so a file-by-file LRU prune drops them last.

REPAIR (restore side). For every build-script unit: a unit with no manifest,
or whose manifest lists a file that is absent, is removed WHOLE, its
`build/<pkg>-<hash>/` and its `.fingerprint/<pkg>-<hash>/`, so cargo reruns
that build script (and rebuilds what depends on it) instead of trusting a
half-pruned unit. A blob saved before v55.0.1 carries no manifests, so the
first restore reruns every build script once; the next save carries them.

A build-script unit is a directory under `<profile>/build/` named
`<pkg>-<16 hex>`. Profiles are `target/<profile>/` and, for a cross build,
`target/<triple>/<profile>/` (a directory holding `deps/` or `.fingerprint/`).
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

MANIFEST = "out.manifest"
UNIT = re.compile(r"^.+-[0-9a-f]{16}$")


def profiles(target: Path) -> list[Path]:
    cands = [p for p in target.iterdir() if p.is_dir()]
    cands += [q for p in cands for q in p.iterdir() if q.is_dir()]
    return sorted(p for p in cands if (p / "deps").is_dir() or (p / ".fingerprint").is_dir())


def units(target: Path) -> list[Path]:
    out = []
    for prof in profiles(target):
        b = prof / "build"
        if b.is_dir():
            out += [u for u in sorted(b.iterdir()) if u.is_dir() and UNIT.match(u.name)]
    return out


def files_of(unit: Path) -> list[str]:
    return sorted(
        f.relative_to(unit).as_posix()
        for f in unit.rglob("*")
        if (f.is_file() or f.is_symlink()) and f.name != MANIFEST
    )


def seal(target: Path) -> int:
    now = time.time()
    sealed = touched = 0
    for u in units(target):
        (u / MANIFEST).write_text("".join(f"{p}\n" for p in files_of(u)), encoding="utf-8")
        sealed += 1
        out = u / "out"
        if out.is_dir():
            for f in out.rglob("*"):
                if f.is_file() and not f.is_symlink():
                    os.utime(f, (now, now))
                    touched += 1
    print(f"ci_cache_units: sealed {sealed} build-script units, touched {touched} out files")
    return 0


def broken(unit: Path) -> str | None:
    m = unit / MANIFEST
    if not m.is_file():
        return "no manifest"
    for rel in m.read_text(encoding="utf-8").splitlines():
        if rel and not (unit / rel).exists():
            return f"missing {rel}"
    return None


def repair(target: Path) -> int:
    repaired = 0
    for u in units(target):
        why = broken(u)
        if why is None:
            continue
        fp = u.parent.parent / ".fingerprint" / u.name
        shutil.rmtree(u)
        if fp.is_dir():
            shutil.rmtree(fp)
        repaired += 1
        print(f"ci_cache_units: removed unit {u.parent.parent.name}/{u.name} ({why})")
    print(f"ci_cache_units: repaired {repaired} build-script units")
    return 0


def self_test() -> int:
    with tempfile.TemporaryDirectory() as d:
        t = Path(d) / "target"
        prof = t / "release"
        (prof / "deps").mkdir(parents=True)

        def unit(name: str, files: list[str]) -> Path:
            u = prof / "build" / name
            for f in files:
                p = u / f
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("x", encoding="utf-8")
            fp = prof / ".fingerprint" / name
            fp.mkdir(parents=True, exist_ok=True)
            (fp / "run-build-script-build_script_build").write_text("h", encoding="utf-8")
            return u

        good = unit("libsqlite3-sys-0123456789abcdef", ["output", "root-output", "out/bindgen.rs"])
        pruned = unit("ring-1111111111111111", ["output", "out/libring.a"])
        script = unit("libsqlite3-sys-2222222222222222", ["build-script-build"])
        seal(t)
        # The LRU prune drops one out file and keeps the fingerprint.
        (pruned / "out" / "libring.a").unlink()
        # A unit saved before manifests existed.
        legacy = unit("zstd-sys-3333333333333333", ["output", "out/zstd.h"])
        repair(t)
        fps = prof / ".fingerprint"
        checks = [
            (good.is_dir() and (fps / good.name).is_dir(), "a consistent unit is kept"),
            (script.is_dir() and (fps / script.name).is_dir(), "a sealed script unit is kept"),
            (not pruned.exists() and not (fps / pruned.name).exists(),
             "a unit with a missing out file goes, with its fingerprint"),
            (not legacy.exists() and not (fps / legacy.name).exists(),
             "a unit with no manifest goes, with its fingerprint"),
        ]
        # Sealing touches out files to now.
        old = time.time() - 10_000
        f = good / "out" / "bindgen.rs"
        os.utime(f, (old, old))
        seal(t)
        checks.append((f.stat().st_mtime > old + 5_000, "seal touches out files to now"))
        failed = [why for ok, why in checks if not ok]
        for why in failed:
            print(f"SELF-TEST FAILED: {why}")
        if failed:
            return 1
        print(f"ci_cache_units: self-test passed ({len(checks)} checks)")
        return 0


def main(argv: list[str]) -> int:
    # Every runner, Windows included (cp1252 stdout, v54.1.1).
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if len(argv) == 2 and argv[1] == "--self-test":
        return self_test()
    if len(argv) != 3 or argv[1] not in ("seal", "repair"):
        print(__doc__, file=sys.stderr)
        return 2
    target = Path(argv[2])
    if not target.is_dir():
        print(f"ci_cache_units: no target directory at {target}; nothing to {argv[1]}")
        return 0
    return seal(target) if argv[1] == "seal" else repair(target)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
