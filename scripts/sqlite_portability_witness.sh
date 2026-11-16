#!/usr/bin/env bash
# sqlite_portability_witness.sh — CIRISPersist#845 (FSD/MIGRATION_IMMUTABILITY.md §6, I55),
# re-pointed at the edition-2 baseline in v62.0.0 (slice E2b).
#
# Applies the SHIPPED sqlite migrations (the V300 edition-2 baseline and
# whatever appends after it) through whatever libsqlite3 this host has, and
# proves the #845 property on it:
#   * no schema text names the `subsec` modifier (SQLite < 3.42 evaluates it
#     to NULL, and every insert relying on such a default fails NOT NULL);
#   * an insert relying on a defaulted timestamp succeeds and stores the
#     23-character `YYYY-MM-DD HH:MM:SS.SSS` form.
# Meant to run in a `debian:bookworm-slim` container (libsqlite3 3.40.1) — the
# only place in the stack a pre-3.42 SQLite runs. Uses python3's stdlib sqlite3
# module.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'PY'
import glob, re, sqlite3, tempfile, os
print(f"libsqlite3 {sqlite3.sqlite_version}")
SUBSEC = "datetime('now', 'subsec')"
path = tempfile.mktemp(suffix=".db"); c = sqlite3.connect(path, isolation_level=None)
c.execute("PRAGMA foreign_keys = ON")
files = sorted(glob.glob("migrations/sqlite/lens/V*.sql"), key=lambda p: int(re.search(r"V(\d+)__", p).group(1)))
assert files and re.search(r"V300__", files[0]), files[:1]
for f in files:
    c.executescript(open(f).read())
print(f"applied {len(files)} shipped sqlite migration(s), from {os.path.basename(files[0])}")
COUNT = "SELECT count(*) FROM sqlite_master WHERE instr(sql, ?) > 0"
left = c.execute(COUNT, (SUBSEC,)).fetchone()[0]
assert left == 0, f"{left} schema object(s) name subsec"
probe = "INSERT INTO federation_content_master (id, key_kind, master_key_b64, descriptor) VALUES (0, 'software', 'AAAA', '{}')"
c.execute(probe)
length, text = c.execute("SELECT length(created_at), created_at FROM federation_content_master WHERE id = 0").fetchone()
assert length == 23, text
print(f"defaulted insert stored created_at={text!r} (23 chars); no subsec in the schema")
os.remove(path); print("SQLITE_PORTABILITY_WITNESS_OK")
PY
