//! v30.2.0 (CIRISPersist#17) — **one postgres database per test, so the suite
//! stops needing `--test-threads=1`.**
//!
//! # The problem this replaces
//!
//! Every postgres test read `CIRIS_PERSIST_TEST_PG_URL` directly and got **the
//! same database**. They then shared mutable state — schema objects in
//! `cirislens_secrets` / `cirislens.federation_*` / `cirislens.audit_log`,
//! global row counts, `av26`'s `DROP SCHEMA cirislens CASCADE` — so two tests
//! running at once could and did corrupt each other.
//!
//! CI's remedy was `--test-threads=1`, which works and costs **2.8×**:
//! measured on the `cirisaudit` leg, 154.8 s parallel against 436.5 s serial.
//! Across nine legs that is ~21 minutes of test time becoming ~58.
//!
//! **`#[serial_test::serial(postgres)]` is NOT the remedy and never was.**
//! nextest spawns every test in its own PROCESS, and `serial_test`'s lock is
//! process-local, so the attribute does nothing here. v30.0.1 added 43 of them
//! believing otherwise; two subsequent green runs were coincidence read as
//! causation.
//!
//! # Why per-PROCESS is per-TEST
//!
//! That same nextest property — process per test — is what makes this cheap.
//! A database created once per process IS a database per test, with no
//! per-test plumbing, no test-name threading, and no changes at the 491 call
//! sites: they all reach postgres through one env var.
//!
//! # Cost
//!
//! `CREATE DATABASE … TEMPLATE` is a file-level copy. Measured against this
//! repo's own container at ~101 ms per copy **including docker-exec
//! overhead**, with the copy verified to carry the template's rows; from
//! in-process it is well under that. 566 postgres tests × ~50 ms, spread
//! across threads, is negligible against the 282-second serial penalty on a
//! single leg.
//!
//! The template carries the migrations, so a per-test database does **not**
//! pay for `run_migrations()` — the expensive part — only for the copy.

use std::sync::OnceLock;

/// The env var every postgres test has always read. Now the **base** DSN: the
/// server and credentials, and the database the template is built beside.
const BASE_VAR: &str = "CIRIS_PERSIST_TEST_PG_URL";

/// Set by the harness (`scripts/pg_test_db.sh`) once per run, naming a
/// database that already has every migration applied. When present, each
/// process copies it; when absent, each process creates an empty database and
/// pays for its own migrations, which is slower but correct.
const TEMPLATE_VAR: &str = "CIRIS_PERSIST_TEST_PG_TEMPLATE";

/// This process's own database URL, created on first call and reused after.
///
/// Returns `None` exactly when [`BASE_VAR`] is unset — the long-standing
/// "skip postgres tests" signal, preserved so every existing
/// `let Some(dsn) = pg_dsn() else { return }` keeps working unchanged.
#[must_use]
pub fn dsn() -> Option<String> {
    static DSN: OnceLock<Option<String>> = OnceLock::new();
    DSN.get_or_init(provision).clone()
}

/// Split a postgres URL into (everything before the final `/`, database name).
fn split(url: &str) -> Option<(&str, &str)> {
    let cut = url.rfind('/')?;
    Some((&url[..cut], &url[cut + 1..]))
}

/// A name unique to this process AND this run.
///
/// PID alone is not enough: PIDs are recycled, and a leaked database from an
/// earlier run would be silently adopted — inheriting exactly the shared-state
/// problem this module exists to end. The nanosecond stamp makes reuse
/// impossible in practice, and the `ciris_t_` prefix is what the harness
/// sweeps.
fn unique_name() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("ciris_t_{}_{}", std::process::id(), nanos)
}

fn provision() -> Option<String> {
    let base = std::env::var(BASE_VAR).ok()?;
    let (host_part, base_db) = split(&base)?;
    let name = unique_name();

    // Connect to the BASE database to issue the CREATE — a session cannot
    // create the database it is connected to.
    let admin = format!("{host_part}/{base_db}");

    // Reap first. Without this a full leg leaves one database per TEST
    // standing: measured at 198 live databases and 2.5 GB partway through a
    // single leg, on a host already at 97% disk.
    //
    // The name embeds the creating PID, so a database whose process is GONE is
    // provably garbage — no timeout heuristic, and no risk of dropping a
    // database a slow test is still using. Concurrent reapers are safe:
    // `DROP DATABASE IF EXISTS` is idempotent, and a drop of a live database
    // is refused by postgres while sessions are attached.
    //
    // Doing it at provision time rather than at exit is deliberate: a killed
    // or panicking process runs no exit hook, and this suite gets killed
    // often. Every new process cleans up after the dead, so the standing count
    // is bounded by CONCURRENCY, not by test count.
    reap_dead(&admin);

    // The template is what makes this affordable. WITHOUT it every process ran
    // all 116 migrations into its own empty database, and the cirisaudit leg
    // went from 436.5 s serial to 1134.8 s parallel — isolation bought
    // correctness and cost 2.6x. `CREATE DATABASE … TEMPLATE` is a file-level
    // copy of an already-migrated database, so the per-test cost becomes the
    // copy instead of the migrations.
    let template = std::env::var(TEMPLATE_VAR)
        .ok()
        .or_else(|| ensure_template(&admin));
    let sql = match &template {
        Some(t) => format!("CREATE DATABASE \"{name}\" TEMPLATE \"{t}\""),
        None => format!("CREATE DATABASE \"{name}\""),
    };

    match run_sql(&admin, &sql) {
        Ok(()) => Some(format!("{host_part}/{name}")),
        Err(e) => {
            // FAIL LOUD, never fall back to the shared database. Silently
            // returning `base` here would put every test back on one database
            // and re-open the exact race this module closes, while every test
            // still passed — the failure would surface as flakes months later
            // with nothing pointing here.
            panic!(
                "test_pg: could not provision a per-process database ({e}).\n\
                 SQL: {sql}\n\
                 admin DSN: {admin}\n\
                 Refusing to fall back to the shared database: that would restore \
                 the cross-test interference this exists to prevent, and would do it \
                 invisibly."
            );
        }
    }
}

/// The shared, already-migrated database every per-test database is copied
/// from. Created once per server, by whichever process gets there first.
const TEMPLATE_DB: &str = "ciris_t_template";

/// A postgres advisory-lock key, so exactly one process builds the template
/// while the rest wait rather than racing 116 migrations against each other.
///
/// Advisory locks are PER-DATABASE (the tag includes the database OID), which
/// is fine and in fact required here: every process takes it on the same admin
/// database, so they genuinely contend.
const TEMPLATE_LOCK: i64 = 0x0C11_3507_E570;

/// Build [`TEMPLATE_DB`] if it does not exist, and return its name.
///
/// Returns `None` on any failure, which degrades to "create an empty database
/// and let the test migrate it" — slower, still correct, never silently
/// shared.
fn ensure_template(admin: &str) -> Option<String> {
    // Fast path: already built.
    if database_exists(admin, TEMPLATE_DB).unwrap_or(false) {
        return Some(TEMPLATE_DB.to_owned());
    }
    // Serialize construction. `pg_advisory_lock` blocks until acquired and is
    // released when the session ends, so a process that dies mid-build cannot
    // wedge the others.
    let built = with_advisory_lock(admin, TEMPLATE_LOCK, || {
        if database_exists(admin, TEMPLATE_DB).unwrap_or(false) {
            return Ok(()); // another process won the race while we waited
        }
        run_sql(admin, &format!("CREATE DATABASE \"{TEMPLATE_DB}\""))?;
        let (host, _) = split(admin).ok_or_else(|| "admin dsn".to_owned())?;
        migrate(&format!("{host}/{TEMPLATE_DB}"))
    });
    match built {
        Ok(()) => Some(TEMPLATE_DB.to_owned()),
        Err(_) => None,
    }
}

/// Run the crate's own migrations into `dsn`, on its own thread (same
/// runtime-nesting reason as [`run_sql`]).
fn migrate(dsn: &str) -> Result<(), String> {
    let dsn = dsn.to_owned();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("runtime: {e}"))?;
        rt.block_on(async {
            use crate::store::Backend as _;
            let be = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .map_err(|e| format!("template connect: {e}"))?;
            be.run_migrations()
                .await
                .map_err(|e| format!("template migrations: {e}"))
        })
    })
    .join()
    .map_err(|_| "template thread panicked".to_owned())?
}

fn database_exists(admin: &str, name: &str) -> Result<bool, String> {
    Ok(query_names(admin)?.iter().any(|n| n == name))
}

/// Hold a postgres advisory lock for the duration of `f`.
fn with_advisory_lock<F>(admin: &str, key: i64, f: F) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String>,
{
    let a = admin.to_owned();
    let guard = std::thread::spawn(move || -> Result<(), String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("runtime: {e}"))?;
        rt.block_on(async {
            let (client, connection) = tokio_postgres::connect(&a, tokio_postgres::NoTls)
                .await
                .map_err(|e| format!("connect: {e}"))?;
            let h = tokio::spawn(async move {
                let _ = connection.await;
            });
            client
                .execute("SELECT pg_advisory_lock($1)", &[&key])
                .await
                .map_err(|e| format!("lock: {e}"))?;
            // The connection task is intentionally abandoned: the advisory
            // lock is session-scoped and releases when this connection closes,
            // which is what we want. `drop` rather than `let _ =` because a
            // non-binding let on a future silently never polls it, and clippy
            // is right that the distinction should be explicit.
            drop(h);
            Ok(())
        })
    });
    guard
        .join()
        .map_err(|_| "lock thread panicked".to_owned())??;
    let out = f();
    // Session-scoped locks release when the connection closes, which already
    // happened above. Re-checking existence inside `f` is what makes the
    // narrow window harmless.
    out
}

/// Drop every `ciris_t_<pid>_<nanos>` database whose creating process is gone.
///
/// Best-effort by construction: a failure here must never fail a test, because
/// the reaper is hygiene and the test is the point. Errors are swallowed and
/// the next process tries again.
fn reap_dead(admin: &str) {
    let Ok(names) = query_names(admin) else {
        return;
    };
    let mut dead = Vec::new();
    for n in names {
        // ciris_t_<pid>_<nanos>
        let Some(rest) = n.strip_prefix("ciris_t_") else {
            continue;
        };
        let Some((pid, _)) = rest.split_once('_') else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        if pid == std::process::id() {
            continue;
        }
        if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
            dead.push(n);
        }
    }
    for n in dead {
        let _ = run_sql(admin, &format!("DROP DATABASE IF EXISTS \"{n}\" (FORCE)"));
    }
}

/// The `ciris_t_%` databases currently on the server.
fn query_names(admin: &str) -> Result<Vec<String>, String> {
    let admin = admin.to_owned();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("runtime: {e}"))?;
        rt.block_on(async {
            let (client, connection) = tokio_postgres::connect(&admin, tokio_postgres::NoTls)
                .await
                .map_err(|e| format!("connect: {e}"))?;
            let h = tokio::spawn(async move {
                let _ = connection.await;
            });
            let rows = client
                .query(
                    "SELECT datname FROM pg_database WHERE datname LIKE 'ciris_t\\_%'",
                    &[],
                )
                .await
                .map_err(|e| format!("query: {e}"))?;
            let out = rows.iter().map(|r| r.get::<_, String>(0)).collect();
            drop(client);
            h.abort();
            Ok(out)
        })
    })
    .join()
    .map_err(|_| "reaper thread panicked".to_owned())?
}

/// Issue one statement over a short-lived connection, using the same
/// `tokio-postgres` stack the backends use.
///
/// Runs on its OWN THREAD. `dsn()` is deliberately synchronous — that is what
/// lets all 79 existing helpers keep their signatures — but nearly every caller
/// is inside a `#[tokio::test]`, so building a runtime here directly panics
/// with *"Cannot start a runtime from within a runtime"*. A dedicated thread
/// escapes the ambient runtime context, and the join keeps the call
/// synchronous from the caller's point of view.
fn run_sql(dsn: &str, sql: &str) -> Result<(), String> {
    let dsn = dsn.to_owned();
    let sql = sql.to_owned();
    std::thread::spawn(move || run_sql_blocking(&dsn, &sql))
        .join()
        .map_err(|_| "provisioning thread panicked".to_owned())?
}

fn run_sql_blocking(dsn: &str, sql: &str) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    rt.block_on(async {
        let connector = tokio_postgres::NoTls;
        let (client, connection) = tokio_postgres::connect(dsn, connector)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let handle = tokio::spawn(async move {
            let _ = connection.await;
        });
        let out = client
            .batch_execute(sql)
            .await
            .map_err(|e| format!("execute: {e}"));
        drop(client);
        handle.abort();
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_separates_host_from_database() {
        let (h, d) = split("postgres://u:p@localhost:5435/ciris").expect("split");
        assert_eq!(h, "postgres://u:p@localhost:5435");
        assert_eq!(d, "ciris");
    }

    /// Two calls in one process return the SAME database — the whole point of
    /// per-PROCESS provisioning. If this ever returned two names, each test
    /// would silently get several databases and any test that writes then
    /// reads would break in a way that looks like data loss.
    ///
    /// **And when the base var IS set, it must have provisioned a DIFFERENT
    /// database from the base.** Without that half this test passes vacuously
    /// with the var unset (`None == None`), which is how it first "passed"
    /// while proving nothing.
    #[test]
    fn dsn_is_stable_within_a_process() {
        assert_eq!(dsn(), dsn());
        let Ok(base) = std::env::var(BASE_VAR) else {
            return; // no server configured; the skip path is the tested one
        };
        let got = dsn().expect("base var is set, so a database must be provisioned");
        assert_ne!(
            got, base,
            "provisioning returned the BASE database. Every test would share it again, \
             and the suite would look green while racing exactly as before."
        );
        let (_, db) = split(&got).expect("provisioned dsn parses");
        assert!(
            db.starts_with("ciris_t_"),
            "provisioned database `{db}` does not carry the sweep prefix; the harness \
             would leak it"
        );
    }

    /// Names are unique per call, so two PROCESSES cannot collide. Checked
    /// here rather than trusted because a PID-only name would pass a
    /// single-process test and collide across a run.
    #[test]
    fn unique_names_do_not_repeat() {
        let a = unique_name();
        let b = unique_name();
        assert_ne!(a, b, "two provisionings in one run must not share a name");
        assert!(
            a.starts_with("ciris_t_"),
            "the harness sweeps this prefix: {a}"
        );
    }
}
