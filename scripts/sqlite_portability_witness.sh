#!/usr/bin/env bash
# sqlite_portability_witness.sh — CIRISPersist#845 (FSD/MIGRATION_IMMUTABILITY.md §6, I55).
#
# Runs the SHIPPED sqlite migrations through whatever libsqlite3 this host has,
# then the crate's portable-default repair, and proves the mechanism:
#   * on SQLite < 3.42 an INSERT that relies on a `datetime('now','subsec')`
#     default fails NOT NULL before the repair and succeeds after it;
#   * on any SQLite, after the repair no `subsec` remains and the stored
#     timestamp keeps the 23-character form.
# Meant to run in a `debian:bookworm-slim` container (libsqlite3 3.40.1) — the
# only place in the stack a pre-3.42 SQLite runs. Uses python3's stdlib sqlite3
# module because Debian's `sqlite3` CLI is built defensive and refuses
# `writable_schema` edits.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'PY'
import glob, re, sqlite3, sys, tempfile, os
ver = tuple(int(x) for x in sqlite3.sqlite_version.split("."))
old = ver < (3, 42, 0)
print(f"libsqlite3 {sqlite3.sqlite_version} — {'pre-3.42: subsec is NULL here' if old else '>= 3.42: subsec works here; only the repair half is proved'}")
SUBSEC   = "datetime('now', 'subsec')"
PORTABLE = "strftime('%Y-%m-%d %H:%M:%f', 'now')"
path = tempfile.mktemp(suffix=".db"); c = sqlite3.connect(path, isolation_level=None)
c.execute("PRAGMA foreign_keys = ON")
files = sorted(glob.glob("migrations/sqlite/lens/V*.sql"), key=lambda p: int(re.search(r"V(\d+)__", p).group(1)))
for f in files:
    c.executescript(open(f).read())
print(f"applied {len(files)} shipped sqlite migrations")
live = c.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND sql LIKE '%subsec%'").fetchone()[0]
assert live > 0, "expected shipped schema text to name subsec before the repair"
probe = "INSERT INTO federation_content_master (id, key_kind, master_key_b64, descriptor) VALUES (0, 'software', 'AAAA', '{}')"
if old:
    try:
        c.execute(probe); print("FAIL: pre-repair insert succeeded on a pre-3.42 SQLite"); sys.exit(1)
    except sqlite3.IntegrityError as e:
        assert "NOT NULL" in str(e) and "created_at" in str(e), e
        print(f"pre-repair insert refused as expected: {e}")
# the repair — the same procedure and literals as SqliteBackend::repair_portable_defaults
v = c.execute("PRAGMA schema_version").fetchone()[0]
c.execute("PRAGMA writable_schema = ON")
n = c.execute(f"UPDATE sqlite_master SET sql = replace(sql, \"{SUBSEC}\", \"{PORTABLE}\") WHERE type = 'table' AND sql LIKE '%subsec%'").rowcount
c.execute("PRAGMA writable_schema = OFF")
c.execute(f"PRAGMA schema_version = {v + 1}")
ok = c.execute("PRAGMA integrity_check").fetchone()[0]
assert ok == "ok", ok
left = c.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND sql LIKE '%subsec%'").fetchone()[0]
assert left == 0, f"{left} table(s) still name subsec"
print(f"repair rewrote {n} table(s); integrity ok; no subsec remains")
c.execute(probe)
length, text = c.execute("SELECT length(created_at), created_at FROM federation_content_master WHERE id = 0").fetchone()
assert length == 23, text
print(f"post-repair insert stored created_at={text!r} (23 chars)")
os.remove(path); print("SQLITE_PORTABILITY_WITNESS_OK")
PY
