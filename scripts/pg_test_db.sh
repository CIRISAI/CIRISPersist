#!/usr/bin/env bash
# pg_test_db.sh — run a command against a FRESH, SINGLE-USE Postgres database,
# and refuse to run against one somebody else is already using.
#
# ── WHY ──────────────────────────────────────────────────────────────────
# Concurrent agents sharing one test database produce reds that belong to
# nobody's change. Two mechanisms, both measured in this repo:
#
#   * Row accumulation. Several tests assert on GLOBAL counts — e.g.
#     `tightening_supersedes_and_is_idempotent_postgres` asserts exactly 3
#     rows carry a value. A second suite's rows make it 6. It also means
#     these tests are not re-runnable against a database they already ran on.
#   * Destructive DDL. `av26_concurrent_boot_advisory_lock` does
#     `DROP SCHEMA cirislens CASCADE`; every other PG test on that database
#     then reports "relation cirislens.* does not exist" (CIRISPersist#128).
#
# Measured, two concurrent copies of the same 4-test suite, 6 iterations:
#     one shared database  -> 6/6 iterations RED
#     separate fresh DBs   -> 0/6 iterations RED
# Same tests, same load, same concurrency. The database is the whole variable.
#
# NOT the cause, though it is often blamed: the migration advisory lock.
# PostgreSQL advisory locks include MyDatabaseId in the lock tag, so they are
# PER-DATABASE, not cluster-wide. Two suites on two databases cannot contend
# on `pg_advisory_lock` no matter what key they use. Verified directly: with a
# holder on database A, a contender on A gets `f` and a contender on B gets
# `t`. Namespacing those lock keys would change nothing.
#
# ── USE ──────────────────────────────────────────────────────────────────
#   scripts/pg_test_db.sh -- cargo nextest run --features postgres,sqlite
#   scripts/pg_test_db.sh -- cargo nextest run --features postgres,sqlite \
#                              -E 'test(/_postgres$/)'
#   scripts/pg_test_db.sh --keep -- cargo nextest run ...   # leave DB for triage
#   scripts/pg_test_db.sh --check                           # just audit the server
#
# The command's exit code is propagated EXACTLY — this script never turns a
# failing test run into a passing one, and never reports its own success.
#
# Admin DSN comes from CIRIS_PERSIST_PG_ADMIN_URL, else the ciris-plainpg
# container's usual local shape.

set -uo pipefail

ADMIN_URL="${CIRIS_PERSIST_PG_ADMIN_URL:-postgres://ciris:pw@localhost:5435/ciris}"
KEEP=0
CHECK_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --keep)   KEEP=1; shift ;;
        --check)  CHECK_ONLY=1; shift ;;
        --admin)  ADMIN_URL="${2:-}"; shift 2 ;;
        --)       shift; break ;;
        -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1 (try --help)" >&2; exit 2 ;;
    esac
done

if ! command -v psql >/dev/null 2>&1; then
    PSQL() { docker exec -i ciris-plainpg psql "$@"; }
    if ! docker exec ciris-plainpg true >/dev/null 2>&1; then
        echo "need either psql on PATH or a running ciris-plainpg container" >&2
        exit 2
    fi
    ADMIN_ARGS=(-U ciris -d ciris)
else
    PSQL() { psql "$@"; }
    ADMIN_ARGS=("$ADMIN_URL")
fi

admin_q() { PSQL "${ADMIN_ARGS[@]}" -tAc "$1"; }

# ── audit: who is on which test database right now ───────────────────────
if [ "$CHECK_ONLY" -eq 1 ]; then
    echo "backends per database:"
    PSQL "${ADMIN_ARGS[@]}" -c \
      "SELECT datname, count(*) AS backends, min(backend_start) AS oldest
         FROM pg_stat_activity WHERE datname IS NOT NULL
        GROUP BY datname ORDER BY 2 DESC;"
    exit 0
fi

if [ $# -eq 0 ]; then
    echo "nothing to run. Usage: scripts/pg_test_db.sh -- <command...>" >&2
    exit 2
fi

# ── provision ────────────────────────────────────────────────────────────
# Lowercase by construction: PostgreSQL folds unquoted identifiers to lower
# case on CREATE, but a DSN path is case-sensitive, so a mixed-case name
# creates `foo_x` and then fails to connect to `fooX` with SQLSTATE 3D000.
DB="ciris_test_$(id -u)_$$_$(date +%s)"
DB="$(printf '%s' "$DB" | tr '[:upper:]' '[:lower:]')"

if [ -n "$(admin_q "SELECT 1 FROM pg_database WHERE datname='$DB'")" ]; then
    echo "refusing: database $DB already exists" >&2
    exit 2
fi

if ! admin_q "CREATE DATABASE $DB" >/dev/null; then
    echo "could not create $DB" >&2
    exit 2
fi
echo "pg_test_db: provisioned $DB"

cleanup() {
    if [ "$KEEP" -eq 1 ]; then
        echo "pg_test_db: KEEPING $DB (drop it yourself when done triaging)"
        return
    fi
    admin_q "DROP DATABASE IF EXISTS $DB WITH (FORCE)" >/dev/null 2>&1
    echo "pg_test_db: dropped $DB"
}
trap cleanup EXIT

# ── the sharing guard ────────────────────────────────────────────────────
# If the caller already had CIRIS_PERSIST_TEST_PG_URL pointing somewhere with
# live backends, they were one command away from the exact failure this script
# exists to prevent. Name it now, while it is still a warning rather than an
# assertion failure in somebody else's diff.
if [ -n "${CIRIS_PERSIST_TEST_PG_URL:-}" ]; then
    PRIOR_DB="${CIRIS_PERSIST_TEST_PG_URL##*/}"
    PRIOR_DB="${PRIOR_DB%%\?*}"
    OCCUPANTS="$(admin_q "SELECT count(*) FROM pg_stat_activity WHERE datname='$PRIOR_DB'")"
    if [ "${OCCUPANTS:-0}" -gt 0 ] 2>/dev/null; then
        echo "pg_test_db: NOTE — the inherited CIRIS_PERSIST_TEST_PG_URL pointed at" >&2
        echo "  '$PRIOR_DB', which has ${OCCUPANTS} live backend(s). Running the suite" >&2
        echo "  there would have shared a database with another occupant, which reds" >&2
        echo "  global-count assertions and breaks on av26's DROP SCHEMA. Overriding" >&2
        echo "  it with the fresh single-use database below." >&2
    fi
fi

HOST_PART="${ADMIN_URL%/*}"
export CIRIS_PERSIST_TEST_PG_URL="$HOST_PART/$DB"
echo "pg_test_db: CIRIS_PERSIST_TEST_PG_URL=$CIRIS_PERSIST_TEST_PG_URL"

"$@"
RC=$?

echo "pg_test_db: command exited $RC"
exit "$RC"
