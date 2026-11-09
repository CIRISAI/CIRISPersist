#!/usr/bin/env python3
"""split_wheel_debuginfo.py — split a linux wheel's native module into the
stripped .so the wheel ships and a `.debug` companion (CIRISPersist#1234).

    scripts/split_wheel_debuginfo.py <wheel> <debug-out-dir> --label <label>

WHY. Hosts profile persist inside their own process (Bridge's 61.0.4 harness
put 31% of peak CPU in the native module) and a stripped .so gives them one
opaque frame. The wheel must stay stripped, so the symbols ship beside it.

WHY ONE LINK. The debug file is only useful if it describes the SHIPPED code
exactly: the same build-id and the same loaded bytes. Two links (a stripped one
to ship and a debug one to keep) do not give that: the GNU build-id is a hash
over the linked file, so a link that keeps `.symtab` carries a different id,
and nothing promises the code is the same. So the linux wheel is built ONCE,
unstripped with line tables (ci.yml `maturin build`), and this script derives
both files from that one .so:

    objcopy --only-keep-debug  <so>  <debug>
    objcopy --strip-all --add-gnu-debuglink=<debug>  <so>  <shipped>

`--strip-all` is what the linker's `-s` (`strip = "symbols"`) does. The
`.note.gnu.build-id` note is a loaded section, so both files keep the link's
id, and `.gnu_debuglink` names the debug file (with its CRC32) for a debugger
that looks it up by name.

The wheel is rewritten in place: every member in its order and with its zip
metadata, the .so replaced and its RECORD line re-hashed. Run it BEFORE the
wheel is uploaded, signed or registered, so every later step sees the shipped
bytes.

REFUSES (exit 1, the wheel untouched) when the wheel does not hold exactly one
`*.abi3.so` and one RECORD; the .so carries no `.symtab` or no `.debug_line`
(it was built stripped: there is nothing to split); it has no GNU build-id;
or, after the split, the shipped .so still carries `.symtab` or a `.debug_*`
section, the three build-ids differ, or a loadable segment moved or changed
size. Exit 2 is usage.

The debug file is named `ciris_persist-<version>-<label>.abi3.so.debug`, the
version read from the wheel's file name, and that is the name the debuglink
records, so a host can drop the release asset next to the .so unrenamed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def fail(msg: str) -> "None":
    print(f"FAIL  {msg}", file=sys.stderr)
    sys.exit(1)


def run(*argv: str) -> str:
    p = subprocess.run(argv, capture_output=True, text=True)
    if p.returncode != 0:
        fail(f"{' '.join(argv)}: exit {p.returncode}: {p.stderr.strip()}")
    return p.stdout


def sections(path: Path) -> set[str]:
    """Section names, from `readelf -S -W`."""
    names = set()
    for line in run("readelf", "-S", "-W", str(path)).splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)", line)
        if m:
            names.add(m.group(1))
    return names


def build_id(path: Path) -> str:
    m = re.search(r"Build ID:\s*([0-9a-f]+)", run("readelf", "-n", "-W", str(path)))
    if not m:
        fail(f"{path.name}: no GNU build-id note")
    return m.group(1)


def load_segments(path: Path) -> list[str]:
    """The PT_LOAD rows of `readelf -l -W`: offset, vaddr, paddr, sizes, flags."""
    rows = [
        " ".join(line.split())
        for line in run("readelf", "-l", "-W", str(path)).splitlines()
        if line.strip().startswith("LOAD")
    ]
    if not rows:
        fail(f"{path.name}: no PT_LOAD segment")
    return rows


def record_hash(data: bytes) -> str:
    d = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("wheel", type=Path)
    ap.add_argument("out_dir", type=Path)
    ap.add_argument("--label", required=True, help="e.g. linux-x86_64")
    a = ap.parse_args()
    if not re.fullmatch(r"linux-[a-z0-9_]+", a.label):
        print(f"usage: --label {a.label!r} is not linux-<arch>", file=sys.stderr)
        sys.exit(2)
    m = re.match(r"ciris_persist-(\d+\.\d+\.\d+)-[^/]*\.whl$", a.wheel.name)
    if not m:
        print(f"usage: {a.wheel.name} is not a ciris_persist-<version>-*.whl", file=sys.stderr)
        sys.exit(2)
    version = m.group(1)
    debug_name = f"ciris_persist-{version}-{a.label}.abi3.so.debug"

    with zipfile.ZipFile(a.wheel) as z:
        infos = z.infolist()
        sos = [i for i in infos if i.filename.endswith(".abi3.so")]
        records = [i for i in infos if re.fullmatch(r"[^/]+\.dist-info/RECORD", i.filename)]
        if len(sos) != 1:
            fail(f"{a.wheel.name}: {len(sos)} *.abi3.so members, want 1: {[i.filename for i in sos]}")
        if len(records) != 1:
            fail(f"{a.wheel.name}: {len(records)} RECORD members, want 1")
        so_info, rec_info = sos[0], records[0]
        members = [(i, z.read(i)) for i in infos]

    a.out_dir.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="split-debuginfo-"))
    # Beside the wheel, so the replace is a rename on one filesystem.
    out = a.wheel.with_name(a.wheel.name + ".split-tmp")
    try:
        so = tmp / "unstripped.so"
        so.write_bytes(next(d for i, d in members if i is so_info))
        have = sections(so)
        for need in (".symtab", ".debug_line"):
            if need not in have:
                fail(
                    f"{so_info.filename} has no {need}: the wheel was built stripped "
                    f"or without line tables, so there is nothing to split"
                )
        bid = build_id(so)

        dbg = tmp / debug_name
        run("objcopy", "--only-keep-debug", str(so), str(dbg))
        shipped = tmp / "shipped.so"
        run("objcopy", "--strip-all", f"--add-gnu-debuglink={dbg}", str(so), str(shipped))

        left = sections(shipped)
        if ".symtab" in left or any(s.startswith(".debug_") for s in left):
            fail(f"the shipped .so is not stripped: {sorted(s for s in left if s == '.symtab' or s.startswith('.debug_'))}")
        if ".gnu_debuglink" not in left:
            fail("the shipped .so carries no .gnu_debuglink")
        dsec = sections(dbg)
        if ".debug_line" not in dsec or ".symtab" not in dsec:
            fail(f"the debug file lacks .debug_line or .symtab: {sorted(dsec)}")
        ids = {"unstripped": bid, "shipped": build_id(shipped), "debug": build_id(dbg)}
        if len(set(ids.values())) != 1:
            fail(f"build-ids differ: {ids}")
        if load_segments(shipped) != load_segments(so):
            fail("a loadable segment moved or changed size between the link and the shipped .so")

        new_so = shipped.read_bytes()
        rec = next(d for i, d in members if i is rec_info).decode()
        prefix = so_info.filename + ","
        hits = [ln for ln in rec.split("\n") if ln.startswith(prefix)]
        if len(hits) != 1:
            fail(f"RECORD has {len(hits)} lines for {so_info.filename}, want 1")
        rec = rec.replace(hits[0], f"{so_info.filename},{record_hash(new_so)},{len(new_so)}", 1)

        with zipfile.ZipFile(out, "w") as z:
            for info, data in members:
                if info is so_info:
                    data = new_so
                elif info is rec_info:
                    data = rec.encode()
                z.writestr(info, data, compress_type=info.compress_type)
        shutil.copyfile(dbg, a.out_dir / debug_name)
        os.replace(out, a.wheel)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        out.unlink(missing_ok=True)

    dbytes = (a.out_dir / debug_name).read_bytes()
    print(
        f"ok    {a.wheel.name}: shipped .so {len(new_so)} bytes (stripped, debuglink {debug_name}); "
        f"{debug_name} {len(dbytes)} bytes sha256 {hashlib.sha256(dbytes).hexdigest()}; build-id {bid}"
    )


if __name__ == "__main__":
    main()
