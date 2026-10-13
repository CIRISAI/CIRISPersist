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

REPAIR (restore side). A unit whose manifest lists a file that is absent is
removed WHOLE, its `build/<pkg>-<hash>/` and its `.fingerprint/<pkg>-<hash>/`,
so cargo reruns that build script (and rebuilds what depends on it) instead of
trusting a half-pruned unit.

A unit with NO manifest (a blob saved before v55.0.1) is judged by a bound,
not removed outright (removing all of them cost the v55.0.1 PR run's
`secrets` leg 15 compile minutes and its 50-minute budget):

- The prune is a file LRU by mtime, so every pruned file is no newer than
  every surviving one. `cutoff` = the OLDEST mtime of any file still under
  target/: a pruned file had mtime <= cutoff.
- A build-script RUN unit writes its `out/` files while the script runs and
  `output` when it ends, so each sibling's mtime >= `output`'s - R, R the
  script's runtime. R is bounded by the CI step limit: `R_MAX` = 2 h.
- So a pruned sibling implies `output` <= cutoff + R_MAX. Contrapositive: a
  manifest-less run unit whose `output` is NEWER than cutoff + R_MAX lost
  nothing, and is KEPT; one at or below it sits at the prune boundary and is
  REMOVED with its fingerprint. A run unit with no `output` at all (but
  `out/`, `root-output`, `stderr` or `invoked.timestamp`) is REMOVED.
- A script-compile unit (no run files) is judged the same way by its NEWEST
  file in place of `output`, so the exe is never trusted to cargo's check.
- The failure direction is safe: a restore that set every mtime to "now"
  makes cutoff ≈ now, every unit falls within R_MAX, and everything
  manifest-less is removed, which is the pre-bound behaviour.

It prints three counts: removed (manifest), removed (boundary), kept
(unverified: manifest-less and far from the cutoff).

The bound assumes ONE restored blob: one save pruned the whole tree in one
pass, so one cutoff covers every file. A caller that overlays SEVERAL blobs
(layers from different saves, each pruned at its own save; CIRISEdge
restores verify → persist → edge) has one cutoff PER LAYER, and a unit of a
later layer can sit hours above the oldest layer's cutoff with a pruned
sibling. Such a caller runs `repair` after EACH layer's restore, or passes
`--strict`, which removes every manifest-less unit (a one-time cold rebuild
of the build scripts; sealed blobs then carry manifests). CIRISEdge found
this (#1075).

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
# The longest a build script may run (a CI step limit bounds it): see REPAIR.
R_MAX = 2 * 60 * 60
RUN_FILES = ("out", "root-output", "stderr", "invoked.timestamp")


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


def oldest_mtime(target: Path) -> float | None:
    """The oldest mtime of any file under `target` (the LRU prune's cutoff)."""
    oldest = None
    for root, _dirs, files in os.walk(target):
        for f in files:
            try:
                m = os.lstat(os.path.join(root, f)).st_mtime
            except OSError:
                continue
            if oldest is None or m < oldest:
                oldest = m
    return oldest


def unverified_verdict(unit: Path, cutoff: float) -> str | None:
    """A manifest-less unit: `None` to keep it, else why it is removed."""
    out = unit / "output"
    if out.is_file():
        ref = out.stat().st_mtime
    elif any((unit / f).exists() for f in RUN_FILES):
        return "run unit with no output"
    else:
        times = [f.lstat().st_mtime for f in unit.rglob("*") if f.is_file() or f.is_symlink()]
        if not times:
            return "empty unit"
        ref = max(times)
    if ref <= cutoff + R_MAX:
        return "no manifest, at the prune boundary"
    return None


def broken(unit: Path) -> str | None:
    """A unit WITH a manifest: `None` when every file it lists is present."""
    m = unit / MANIFEST
    for rel in m.read_text(encoding="utf-8").splitlines():
        if rel and not (unit / rel).exists():
            return f"missing {rel}"
    return None


def repair(target: Path, strict: bool = False) -> int:
    """`strict`: every manifest-less unit goes (for layered restores, where
    the single-cutoff bound does not hold)."""
    cutoff = oldest_mtime(target)
    by_manifest = by_boundary = kept = 0
    for u in units(target):
        if (u / MANIFEST).is_file():
            why = broken(u)
            if why is None:
                continue
            by_manifest += 1
        elif strict:
            why = "no manifest (--strict: layered restore, no single cutoff)"
            by_boundary += 1
        else:
            why = unverified_verdict(u, cutoff if cutoff is not None else 0.0)
            if why is None:
                kept += 1
                continue
            by_boundary += 1
        fp = u.parent.parent / ".fingerprint" / u.name
        shutil.rmtree(u)
        if fp.is_dir():
            shutil.rmtree(fp)
        print(f"ci_cache_units: removed unit {u.parent.parent.name}/{u.name} ({why})")
    print(
        f"ci_cache_units: removed {by_manifest} (manifest), removed {by_boundary} (boundary), "
        f"kept {kept} (unverified, far from the cutoff)"
    )
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
        checks += bound_checks()
        failed = [why for ok, why in checks if not ok]
        for why in failed:
            print(f"SELF-TEST FAILED: {why}")
        if failed:
            return 1
        print(f"ci_cache_units: self-test passed ({len(checks)} checks)")
        return 0


def bound_checks() -> list[tuple[bool, str]]:
    """The manifest-less bound (see REPAIR), on fixtures with set mtimes."""
    out = []
    t0 = time.time() - 30 * 24 * 3600
    with tempfile.TemporaryDirectory() as d:
        t = Path(d) / "target"
        prof = t / "release"
        (prof / "deps").mkdir(parents=True)
        oldest = prof / "deps" / "libold-0000000000000000.rlib"
        oldest.write_text("x", encoding="utf-8")
        os.utime(oldest, (t0, t0))

        def unit(name: str, files: list[str], mtime: float) -> Path:
            u = prof / "build" / name
            for f in files:
                p = u / f
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("x", encoding="utf-8")
                os.utime(p, (mtime, mtime))
            fp = prof / ".fingerprint" / name
            fp.mkdir(parents=True, exist_ok=True)
            return u

        # Literal offsets (R_MAX is 2 h), so a mutated R_MAX moves the bound
        # and not the fixture.
        far = unit("far-4444444444444444", ["output", "out/a.rs"], t0 + 3 * 3600)
        near = unit("near-5555555555555555", ["output", "out/a.rs"], t0 + 2 * 3600 - 60)
        nout = unit("nout-6666666666666666", ["root-output", "out/a.rs"], t0 + 20 * 3600)
        sfar = unit("sfar-7777777777777777", ["build-script-build"], t0 + 20 * 3600)
        snear = unit("snear-8888888888888888", ["build-script-build"], t0 + 60)
        repair(t)
        fps = prof / ".fingerprint"
        gone = lambda u: not u.exists() and not (fps / u.name).exists()  # noqa: E731
        out += [
            (far.is_dir() and (fps / far.name).is_dir(),
             "a manifest-less run unit far above the cutoff is kept"),
            (gone(near), "a manifest-less run unit within R_MAX of the cutoff goes"),
            (gone(nout), "a run unit with no output goes"),
            (sfar.is_dir(), "a manifest-less script unit far above the cutoff is kept"),
            (gone(snear), "a manifest-less script unit near the cutoff goes"),
        ]
    # Clobbered: every mtime "now" puts every unit within R_MAX of the cutoff.
    with tempfile.TemporaryDirectory() as d:
        t = Path(d) / "target"
        prof = t / "release"
        (prof / "deps").mkdir(parents=True)
        made = []
        for n in ("a-9999999999999999", "b-aaaaaaaaaaaaaaaa"):
            u = prof / "build" / n
            (u / "out").mkdir(parents=True)
            (u / "output").write_text("x", encoding="utf-8")
            (u / "out" / "x.rs").write_text("x", encoding="utf-8")
            (prof / ".fingerprint" / n).mkdir(parents=True)
            made.append(u)
        repair(t)
        out.append((all(not u.exists() for u in made),
                    "clobbered mtimes remove every manifest-less unit"))
    # --strict (a layered restore, no single cutoff): a manifest-less unit the
    # bound would KEEP (far above the cutoff) goes; a sealed, consistent one stays.
    with tempfile.TemporaryDirectory() as d:
        t = Path(d) / "target"
        prof = t / "release"
        (prof / "deps").mkdir(parents=True)
        old = time.time() - 30 * 24 * 3600
        anchor = prof / "deps" / "libold.rlib"
        anchor.write_text("x", encoding="utf-8")
        os.utime(anchor, (old, old))
        far = prof / "build" / "far-1111111111111111"
        (far / "out").mkdir(parents=True)
        (far / "output").write_text("x", encoding="utf-8")
        (far / "out" / "g.rs").write_text("x", encoding="utf-8")
        (prof / ".fingerprint" / far.name).mkdir(parents=True)
        for f in (far / "output", far / "out" / "g.rs"):
            os.utime(f, (old + 10 * 3600, old + 10 * 3600))
        sealed = prof / "build" / "sealed-2222222222222222"
        (sealed / "out").mkdir(parents=True)
        (sealed / "output").write_text("x", encoding="utf-8")
        (sealed / "out" / "h.rs").write_text("x", encoding="utf-8")
        (prof / ".fingerprint" / sealed.name).mkdir(parents=True)
        seal(t)
        (far / MANIFEST).unlink()
        repair(t)
        out.append((far.exists(), "the bound keeps a manifest-less unit far above the cutoff"))
        repair(t, strict=True)
        out.append((not far.exists() and not (prof / ".fingerprint" / far.name).exists(),
                    "--strict removes it, with its fingerprint"))
        out.append((sealed.exists(), "--strict keeps a sealed, consistent unit"))
    return out


def main(argv: list[str]) -> int:
    # Every runner, Windows included (cp1252 stdout, v54.1.1).
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if len(argv) == 2 and argv[1] == "--self-test":
        return self_test()
    strict = argv[1:2] == ["repair"] and argv[3:] == ["--strict"]
    if not strict and (len(argv) != 3 or argv[1] not in ("seal", "repair")):
        print(__doc__, file=sys.stderr)
        return 2
    target = Path(argv[2])
    if not target.is_dir():
        print(f"ci_cache_units: no target directory at {target}; nothing to {argv[1]}")
        return 0
    return seal(target) if argv[1] == "seal" else repair(target, strict=strict)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
