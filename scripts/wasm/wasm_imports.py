#!/usr/bin/env python3
"""v62.0.0 (slice D, P12) — print a core wasm module's imports.

One line per import: `<module> <field> <kind>` (kind: func, table, memory,
global, tag). Reads the binary's import section (id 2) directly: stdlib only,
so the gate needs no extra tool. Exits 2 on a file that is not a core module
(a component, or not wasm at all).
"""

import sys

KINDS = {0: "func", 1: "table", 2: "memory", 3: "global", 4: "tag"}


def leb_u(buf, i):
    result, shift = 0, 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7


def name(buf, i):
    n, i = leb_u(buf, i)
    return buf[i : i + n].decode("utf-8"), i + n


def skip_limits(buf, i):
    flags = buf[i]
    i += 1
    _, i = leb_u(buf, i)
    if flags & 0x01:
        _, i = leb_u(buf, i)
    return i


def imports(buf):
    if buf[:4] != b"\0asm":
        raise ValueError("not a wasm binary")
    if buf[4:8] != b"\x01\x00\x00\x00":
        raise ValueError("not a core module (version/layer %r)" % buf[4:8])
    i = 8
    out = []
    while i < len(buf):
        sid = buf[i]
        size, i = leb_u(buf, i + 1)
        end = i + size
        if sid == 2:
            count, j = leb_u(buf, i)
            for _ in range(count):
                mod, j = name(buf, j)
                field, j = name(buf, j)
                kind = buf[j]
                j += 1
                if kind == 0:
                    _, j = leb_u(buf, j)
                elif kind == 1:
                    j += 1
                    j = skip_limits(buf, j)
                elif kind == 2:
                    j = skip_limits(buf, j)
                elif kind == 3:
                    j += 2
                elif kind == 4:
                    j += 1
                    _, j = leb_u(buf, j)
                else:
                    raise ValueError("unknown import kind %d" % kind)
                out.append((mod, field, KINDS.get(kind, str(kind))))
        i = end
    return out


def main():
    if len(sys.argv) != 2:
        print("usage: wasm_imports.py MODULE.wasm", file=sys.stderr)
        return 2
    with open(sys.argv[1], "rb") as f:
        buf = f.read()
    try:
        for mod, field, kind in imports(buf):
            print(f"{mod} {field} {kind}")
    except (ValueError, IndexError) as e:
        print(f"wasm_imports: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
