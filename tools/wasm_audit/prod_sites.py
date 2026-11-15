#!/usr/bin/env python3
"""Count wasm/UEFI-hostile primitives in persist's PRODUCTION source.

Static only (no build). Strips comments, string literals, and every item
gated `#[cfg(test)]` / `#[cfg(all(test, ...))]` / `test-anchor` (inline `mod x { .. }`
blocks, fns, impls), and drops whole files declared as test-only modules
(`#[cfg(test)] mod x;`). Prints per-pattern totals and per-file hits,
split into node code, src/ffi/ (host binding) and src/bin/ (host tools).

Usage: prod_sites.py <persist>/src [--files PATTERN_NAME]
"""
import os
import re
import sys

PATTERNS = {
    "std_time_Instant": r"\bInstant::now\b|\bstd::time::Instant\b",
    "SystemTime": r"\bSystemTime\b",
    "block_on": r"\.block_on\(",
    "block_in_place": r"\bblock_in_place\b",
    "tokio_spawn": r"\btokio::spawn\b|\btokio::task::spawn\b|\btask::spawn\(",
    "spawn_blocking": r"\bspawn_blocking\b",
    "dispatch_blocking": r"\bdispatch_blocking\b",
    "thread_spawn": r"\bthread::spawn\b|\bthread::Builder\b",
    "Condvar": r"\bCondvar\b",
    "tokio_time": r"\btokio::time::|\btime::(sleep|interval|timeout)\(",
    "runtime_builder": r"\bRuntime::new\b|\bruntime::Builder\b|\bBuilder::new_(multi|current)_thread\b",
    "Handle_current": r"\bHandle::current\b|\bHandle::try_current\b",
    "std_fs": r"\bstd::fs\b|\bfs::(read|write|create_dir|create_dir_all|remove_file|remove_dir_all|rename|metadata|File|OpenOptions|read_dir|copy|canonicalize|read_to_string|set_permissions)\b|\bFile::(open|create)\b",
    "cfg_target": r"cfg\((?:[^()]|\([^()]*\))*\b(unix|windows|target_os|target_family|target_arch|target_env|target_vendor)\b",
    "fs4": r"\bfs4::",
    "redb": r"\bredb::",
    "tokio_signal": r"\btokio::signal\b",
    "libc": r"\blibc::",
    "chrono_Utc_now": r"\bUtc::now\(\)|\bLocal::now\(\)",
    "uuid_new_v4": r"\bUuid::new_v4\(\)",
    "env_var": r"\bstd::env::|\benv::var\b",
    "mode_0o600": r"\b0o6[04]0\b|PermissionsExt",
}

TEST_ATTR = re.compile(r"#\[cfg\(\s*(test\b|all\(\s*test\b|any\(\s*test\s*,\s*feature\s*=\s*\"test-anchor\"\s*\)|feature\s*=\s*\"test-anchor\")")


def strip_comments_and_strings(s):
    out = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if s.startswith("//", i):
            j = s.find("\n", i)
            j = n if j < 0 else j
            i = j
            continue
        if s.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if s.startswith("/*", i):
                    depth += 1
                    i += 2
                elif s.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    if s[i] == "\n":
                        out.append("\n")
                    i += 1
            continue
        m = re.match(r'r(#*)"', s[i:i + 10])
        if m and (i == 0 or not (s[i - 1].isalnum() or s[i - 1] == "_")):
            close = '"' + m.group(1)
            j = s.find(close, i + len(m.group(0)))
            j = n if j < 0 else j + len(close)
            out.append('""' + "\n" * s.count("\n", i, j))
            i = j
            continue
        if c == '"':
            j = i + 1
            while j < n and s[j] != '"':
                j += 2 if s[j] == "\\" else 1
            out.append('""' + "\n" * s.count("\n", i, j))
            i = j + 1
            continue
        if c == "'" and i + 2 < n and (s[i + 2] == "'" or (s[i + 1] == "\\" and "'" in s[i + 2:i + 12])):
            j = s.find("'", i + 2 if s[i + 1] != "\\" else i + 3)
            if j > 0 and j - i < 12:
                out.append("' '")
                i = j + 1
                continue
        out.append(c)
        i += 1
    return "".join(out)


def strip_test_items(s):
    """Remove the item after each test-only cfg attribute."""
    while True:
        m = TEST_ATTR.search(s)
        if not m:
            return s
        start = m.start()
        # find end of the attribute
        j = s.find("]", m.end())
        k = j + 1
        # skip further attributes / whitespace
        while True:
            mm = re.match(r"\s*#\[[^\]]*\]", s[k:])
            if not mm:
                break
            k += mm.end()
        # item: up to `;` (declaration) or a balanced `{}` block
        semi = s.find(";", k)
        brace = s.find("{", k)
        if brace < 0 or (0 <= semi < brace):
            end = semi + 1
        else:
            depth, p = 0, brace
            while p < len(s):
                if s[p] == "{":
                    depth += 1
                elif s[p] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                p += 1
            end = p + 1
        s = s[:start] + "\n" * s.count("\n", start, end) + s[end:]


def test_only_files(root):
    """Files declared `#[cfg(test)] mod x;` (or cfg(all(test..)))."""
    out = set()
    decl = re.compile(r"#\[cfg\(\s*(?:test\b|all\(\s*test\b|any\(\s*test\s*,\s*feature\s*=\s*\"test-anchor\"\s*\)|feature\s*=\s*\"test-anchor\")[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;")
    pathattr = re.compile(r'#\[path\s*=\s*"([^"]+)"\]')
    for dp, _, fs in os.walk(root):
        for f in fs:
            if not f.endswith(".rs"):
                continue
            p = os.path.join(dp, f)
            s = open(p, errors="ignore").read()
            base = dp if f in ("mod.rs", "lib.rs", "main.rs") else os.path.join(dp, f[:-3])
            for m in decl.finditer(s):
                seg = s[m.start():m.end()]
                pa = pathattr.search(seg)
                if pa:
                    cands = [os.path.normpath(os.path.join(dp, pa.group(1)))]
                else:
                    name = m.group(1)
                    cands = [os.path.join(base, name + ".rs"), os.path.join(base, name, "mod.rs")]
                for c in cands:
                    if os.path.exists(c):
                        out.add(os.path.normpath(c))
    # children of a test-only dir module are test-only
    grown = True
    while grown:
        grown = False
        for p in list(out):
            if p.endswith("mod.rs"):
                d = os.path.dirname(p)
                for dp, _, fs in os.walk(d):
                    for f in fs:
                        q = os.path.normpath(os.path.join(dp, f))
                        if f.endswith(".rs") and q not in out:
                            out.add(q)
                            grown = True
    return out


def main():
    root = os.path.normpath(sys.argv[1])
    want = sys.argv[3] if len(sys.argv) > 3 and sys.argv[2] == "--files" else None
    tests = test_only_files(root)
    totals = {k: {"node": [0, set()], "ffi": [0, set()], "bin": [0, set()]} for k in PATTERNS}
    perfile = {k: {} for k in PATTERNS}
    nfiles = 0
    for dp, _, fs in os.walk(root):
        for f in sorted(fs):
            if not f.endswith(".rs"):
                continue
            p = os.path.normpath(os.path.join(dp, f))
            if p in tests:
                continue
            nfiles += 1
            rel = os.path.relpath(p, root)
            area = "ffi" if rel.startswith("ffi/") else "bin" if rel.startswith("bin/") else "node"
            s = strip_test_items(strip_comments_and_strings(open(p, errors="ignore").read()))
            for k, pat in PATTERNS.items():
                n = len(re.findall(pat, s))
                if n:
                    totals[k][area][0] += n
                    totals[k][area][1].add(rel)
                    perfile[k][rel] = n
    print(f"# production files scanned: {nfiles}; test-only files dropped: {len(tests)}")
    print(f"{'pattern':<20} {'node hits/files':>16} {'ffi hits/files':>16} {'bin hits/files':>16}")
    for k in PATTERNS:
        t = totals[k]
        print(f"{k:<20} {t['node'][0]:>9}/{len(t['node'][1]):<6} {t['ffi'][0]:>9}/{len(t['ffi'][1]):<6} {t['bin'][0]:>9}/{len(t['bin'][1]):<6}")
    if want:
        print(f"\n## {want} per file")
        for rel, n in sorted(perfile[want].items(), key=lambda x: -x[1]):
            print(f"{n:>5}  src/{rel}")


if __name__ == "__main__":
    main()
