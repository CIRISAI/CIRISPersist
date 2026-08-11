#!/usr/bin/env bash
# Tune the LOCAL TEST postgres cluster for throughput by trading away crash
# safety — which a test cluster does not need and pays for on every commit.
#
# ── WHY THIS EXISTS ──────────────────────────────────────────────────────
# On a STOCK cluster the local suite is not CPU-bound, and the proof is that
# lane tuning does nothing: 1443s at 8 lanes x 4 threads vs 1437s at 5 x 4 — one
# asks for 32 test threads, the other 20, on 32 cores. Work that is CPU-bound
# cannot tie like that. Two rounds of lane tuning bought 0.4%.
#
# The database was the constraint the whole time, and it was HIDING the CPU one.
# After this script runs, the same comparison is 731s vs 917s — the lanes become
# a real 20% lever, and --recreate-tmpfs takes it to 643s. Fix what binds first;
# tuning parallelism against a saturated dependency just measures the dependency.
#
#     stock 1443s  ->  tuned 731s  ->  tuned + tmpfs 643s   (24m03s -> 10m43s)
#
# What the suite actually does is hammer postgres: ~19,300 tests, most of them
# writing rows through the real admission path. The cluster was running every
# production durability default — fsync on, synchronous_commit on,
# full_page_writes on, jit on, 128MB shared_buffers — on databases that
# `pg_test_db.sh` creates from a template and drops when the run ends.
#
# Every database in this cluster is disposable. Paying for crash safety on it is
# pure cost with nothing bought.
#
# ── THE GUARD IS THE POINT ───────────────────────────────────────────────
# `fsync = off` means a crash can leave the cluster CORRUPT, not merely missing
# recent commits. On a test cluster that is free. On anything real it is a
# catastrophe, and the two are one typo apart. So this script refuses to touch
# anything it cannot positively identify as the disposable local test cluster,
# and refusing is the default — there is no flag that skips the identity check.
#
# ── REVERSING ────────────────────────────────────────────────────────────
#   scripts/pg_tune_test_cluster.sh --reset
#
# ── PGDATA IN RAM (largest lever, DESTRUCTIVE) ───────────────────────────
#   scripts/pg_tune_test_cluster.sh --recreate-tmpfs
#
# ── A TRAP WORTH KNOWING ─────────────────────────────────────────────────
# `docker exec` WITHOUT `-i` does not attach stdin. Feeding psql a heredoc
# through it silently delivers NOTHING; psql reads empty input and exits 0, so
# `set -e` sees success and every statement is skipped. That is exactly how the
# first attempt at this "succeeded" while postgresql.auto.conf stayed empty.
# The `-i` below is load-bearing, and the verification at the end exists because
# the failure mode is a silent no-op that reports green.
set -uo pipefail

CONTAINER="${CIRIS_PG_TEST_CONTAINER:-ciris-plainpg}"
PGUSER_="${CIRIS_PG_TEST_USER:-ciris}"
PGDB="${CIRIS_PG_TEST_DB:-ciris}"
MODE="${1:-apply}"

case "$MODE" in
    apply|--apply) MODE=apply ;;
    --reset|reset) MODE=reset ;;
    --recreate-tmpfs|recreate-tmpfs) MODE=recreate-tmpfs ;;
    -h|--help) sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "usage: $0 [--apply|--reset|--recreate-tmpfs]" >&2; exit 2 ;;
esac

command -v docker >/dev/null || { echo "REFUSING: docker not on PATH." >&2; exit 2; }

# ── identity check: is this the disposable local test cluster? ───────────
docker inspect "$CONTAINER" >/dev/null 2>&1 || {
    echo "REFUSING: no container named '$CONTAINER'." >&2
    echo "  This script only tunes the local test cluster. It will not reach a remote DSN." >&2
    exit 2; }

# Published only on loopback. A cluster reachable from the network is not a
# local test cluster no matter what it is called.
PORTS="$(docker inspect "$CONTAINER" --format '{{json .NetworkSettings.Ports}}')"
case "$PORTS" in
    *'"HostIp":"0.0.0.0"'*|*'"HostIp":"::"'*|*127.0.0.1*|*localhost*) ;;
    *) echo "REFUSING: '$CONTAINER' does not look like a locally-published test cluster." >&2
       echo "  ports: $PORTS" >&2; exit 2 ;;
esac

# ── the decisive check: an explicit, deliberately-placed marker ──────────
# The first version of this guard enumerated database names and refused anything
# not matching a pattern this repo creates. On the real cluster that refused
# immediately — it also hosts sibling repos' test databases (attr11, cc051_*,
# cc06_*), none of which match a CIRISPersist naming rule and all of which are
# just as disposable. A guard that refuses the one cluster it exists to serve
# gets deleted within a day, and then nothing guards anything.
#
# Name-matching was the wrong instrument regardless: it infers disposability
# from a string an operator never promised anything about. So the check is now a
# marker that somebody had to put there ON PURPOSE. It cannot false-positive
# into permanent refusal (there is a documented way through, printed below) and
# it cannot silently tune a cluster nobody declared disposable.
MARKER=/var/lib/postgresql/data/CIRIS_DISPOSABLE_TEST_CLUSTER
LABEL_OK=""
[ "$(docker inspect "$CONTAINER" --format '{{index .Config.Labels "ciris.disposable"}}' 2>/dev/null)" = "true" ] && LABEL_OK=1
FILE_OK=""
docker exec "$CONTAINER" test -f "$MARKER" 2>/dev/null && FILE_OK=1
# Two accepted markers, because the file cannot survive the tmpfs mode: PGDATA
# IS the tmpfs, so a marker inside it — like postgresql.auto.conf — is gone on
# every restart. The docker LABEL is container metadata and persists, which is
# why --recreate-tmpfs sets it and moves the tuning to `-c` flags.
if [ -z "$LABEL_OK$FILE_OK" ]; then
    echo "REFUSING: '$CONTAINER' is not marked as a disposable test cluster." >&2
    echo >&2
    echo "  fsync=off can leave a cluster CORRUPT after a crash — not merely missing" >&2
    echo "  recent commits. That is free on a cluster whose every database is recreated" >&2
    echo "  from a template, and unacceptable on any other. Nothing this script can read" >&2
    echo "  proves which one you have, so it requires you to say so:" >&2
    echo >&2
    echo "      docker exec $CONTAINER touch $MARKER" >&2
    echo >&2
    echo "  Only do that for a cluster you would be willing to delete outright." >&2
    exit 2
fi

# ── --recreate-tmpfs: PGDATA in RAM ──────────────────────────────────────
# DESTRUCTIVE. Drops the container and its volume and builds a fresh cluster
# whose data directory is a tmpfs. Everything in it goes: the template, and the
# accumulated per-run databases (92 of them when this was written, ~1.4G — the
# tmpfs mode incidentally ends that leak, since each restart starts empty).
#
# Two consequences that are easy to get wrong:
#   * `ALTER SYSTEM` writes postgresql.auto.conf INSIDE PGDATA, so under tmpfs
#     it does not survive a restart. The tuning therefore moves to `-c` flags on
#     the container command, which live in container config, not in the volume.
#   * The cluster is empty on every start. postgres' entrypoint re-runs initdb
#     and recreates the role/database from POSTGRES_* env; test_pg.rs rebuilds
#     the template on first use. Sibling repos rebuild theirs the same way.
if [ "$MODE" = "recreate-tmpfs" ]; then
    SIZE="${CIRIS_PG_TMPFS_SIZE:-8g}"
    IMAGE="$(docker inspect "$CONTAINER" --format '{{.Config.Image}}')"
    PORT="$(docker inspect "$CONTAINER" --format '{{range $p, $c := .HostConfig.PortBindings}}{{range $c}}{{.HostPort}}{{end}}{{end}}')"
    PW="$(docker inspect "$CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^POSTGRES_PASSWORD=//p')"
    VOL="$(docker inspect "$CONTAINER" --format '{{range .Mounts}}{{.Name}}{{end}}')"
    [ -n "$IMAGE" ] && [ -n "$PORT" ] && [ -n "$PW" ] || {
        echo "REFUSING: could not read image/port/password off '$CONTAINER'." >&2; exit 2; }
    if pgrep -x cargo >/dev/null || pgrep -x cargo-nextest >/dev/null; then
        echo "REFUSING: a cargo run is live. Destroying the cluster under it would" >&2
        echo "  produce failures belonging to this script, not to the tree." >&2
        exit 2
    fi
    echo "DESTROYING '$CONTAINER' (image=$IMAGE port=$PORT vol=${VOL:-none}) and rebuilding on tmpfs (${SIZE})..."
    docker rm -f "$CONTAINER" >/dev/null
    [ -n "$VOL" ] && docker volume rm "$VOL" >/dev/null 2>&1
    docker run -d --name "$CONTAINER" \
        --label ciris.disposable=true \
        -e POSTGRES_USER="$PGUSER_" -e POSTGRES_PASSWORD="$PW" -e POSTGRES_DB="$PGDB" \
        -p "127.0.0.1:${PORT}:5432" \
        --mount "type=tmpfs,destination=/var/lib/postgresql/data,tmpfs-size=${SIZE}" \
        "$IMAGE" \
        postgres \
          -c fsync=off -c synchronous_commit=off -c full_page_writes=off \
          -c jit=off -c bgwriter_lru_maxpages=0 -c checkpoint_timeout=60min \
          -c max_wal_size=8GB -c autovacuum=off \
          -c max_connections=400 -c shared_buffers=2GB -c work_mem=32MB >/dev/null || {
        echo "FAILED to start the replacement container." >&2; exit 1; }
    for _ in $(seq 1 90); do
        docker exec "$CONTAINER" pg_isready -U "$PGUSER_" -q 2>/dev/null && break
        sleep 1
    done
    docker exec "$CONTAINER" pg_isready -U "$PGUSER_" -q 2>/dev/null || {
        echo "FAILED: replacement cluster never became ready." >&2
        docker logs --tail 30 "$CONTAINER" >&2; exit 1; }
    echo "effective settings:"
    docker exec "$CONTAINER" psql -U "$PGUSER_" -d "$PGDB" -tAc \
     "select '  '||name||' = '||setting from pg_settings
       where name in ('fsync','synchronous_commit','full_page_writes','jit',
                      'shared_buffers','max_connections','autovacuum') order by name;"
    ON_TMPFS="$(docker exec "$CONTAINER" sh -c "df -T /var/lib/postgresql/data | tail -1 | awk '{print \$2}'")"
    echo "  PGDATA filesystem = $ON_TMPFS"
    [ "$ON_TMPFS" = "tmpfs" ] || { echo "FAILED: PGDATA is not tmpfs." >&2; exit 1; }
    FS="$(docker exec "$CONTAINER" psql -U "$PGUSER_" -d "$PGDB" -tAc 'show fsync')"
    [ "$FS" = "off" ] || { echo "FAILED: fsync is '$FS'." >&2; exit 1; }
    echo "OK (recreate-tmpfs). The cluster is EMPTY — the template rebuilds on first use."
    exit 0
fi

if [ "$MODE" = "reset" ]; then
    echo "Restoring stock durability settings on '$CONTAINER'..."
    docker exec -i "$CONTAINER" psql -U "$PGUSER_" -d "$PGDB" -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
ALTER SYSTEM RESET fsync;
ALTER SYSTEM RESET synchronous_commit;
ALTER SYSTEM RESET full_page_writes;
ALTER SYSTEM RESET jit;
ALTER SYSTEM RESET bgwriter_lru_maxpages;
ALTER SYSTEM RESET checkpoint_timeout;
ALTER SYSTEM RESET max_wal_size;
ALTER SYSTEM RESET autovacuum;
ALTER SYSTEM RESET max_connections;
ALTER SYSTEM RESET shared_buffers;
ALTER SYSTEM RESET work_mem;
SQL
    RC=$?
else
    echo "Tuning '$CONTAINER' for disposable test workloads..."
    # `-i` is load-bearing — see the header.
    docker exec -i "$CONTAINER" psql -U "$PGUSER_" -d "$PGDB" -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
-- Durability, traded away deliberately. Every database here is created from a
-- template by pg_test_db.sh and dropped when the run ends.
ALTER SYSTEM SET fsync = off;
ALTER SYSTEM SET synchronous_commit = off;
ALTER SYSTEM SET full_page_writes = off;
-- JIT compiles a plan before running it. Test queries are small and run once,
-- so compilation costs more than interpretation.
ALTER SYSTEM SET jit = off;
-- Stop dribbling pages to disk for a database that will be dropped.
ALTER SYSTEM SET bgwriter_lru_maxpages = 0;
ALTER SYSTEM SET checkpoint_timeout = '60min';
ALTER SYSTEM SET max_wal_size = '8GB';
-- Nothing here lives long enough to need vacuuming.
ALTER SYSTEM SET autovacuum = off;
-- Lanes x test-threads x (backend per connection) overruns the default 100, and
-- exhausting it surfaces as a connection error that reads exactly like a test
-- failure — a resource verdict wearing a correctness verdict's clothes.
ALTER SYSTEM SET max_connections = 400;
ALTER SYSTEM SET shared_buffers = '2GB';
ALTER SYSTEM SET work_mem = '32MB';
SQL
    RC=$?
fi
[ "$RC" -eq 0 ] || { echo "REFUSING to continue: psql exited $RC." >&2; exit 1; }

# shared_buffers and max_connections are postmaster-context: a reload will not
# move them.
docker restart "$CONTAINER" >/dev/null || { echo "restart failed" >&2; exit 1; }
for _ in $(seq 1 60); do
    docker exec "$CONTAINER" pg_isready -U "$PGUSER_" -q 2>/dev/null && break
    sleep 1
done
docker exec "$CONTAINER" pg_isready -U "$PGUSER_" -q 2>/dev/null || {
    echo "REFUSING to report success: '$CONTAINER' did not come back up." >&2; exit 1; }

# ── verify, because the failure mode is a silent no-op ───────────────────
echo "effective settings:"
docker exec "$CONTAINER" psql -U "$PGUSER_" -d "$PGDB" -tAc \
 "select '  '||name||' = '||setting from pg_settings
   where name in ('fsync','synchronous_commit','full_page_writes','jit',
                  'shared_buffers','max_connections','bgwriter_lru_maxpages','autovacuum')
   order by name;"

FSYNC="$(docker exec "$CONTAINER" psql -U "$PGUSER_" -d "$PGDB" -tAc "show fsync")"
if [ "$MODE" = "apply" ] && [ "$FSYNC" != "off" ]; then
    echo "FAILED: fsync is still '$FSYNC' — the settings did not take." >&2; exit 1
fi
if [ "$MODE" = "reset" ] && [ "$FSYNC" != "on" ]; then
    echo "FAILED: fsync is still '$FSYNC' — the reset did not take." >&2; exit 1
fi
echo "OK ($MODE)."
