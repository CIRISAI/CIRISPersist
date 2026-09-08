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
///
/// # The name carries the migration set's fingerprint, and that is load-bearing
///
/// v30.6.0 (CIRISPersist#622). A fixed name made the template STALE the moment
/// anyone added or edited a migration: every per-test database was cloned from
/// the OLD schema, so the suite ran green against a schema the tree no longer
/// describes. That is a silent-wrong-answer, not a slow one.
///
/// It bit twice while landing V121 — a dye test that removed the migration still
/// passed, because the template kept the applied column type, and then the
/// FIXED build failed because the template kept the unfixed one. Both directions
/// wrong, neither obvious.
///
/// Keying the name on a fingerprint of the embedded migration set means a schema
/// change automatically lands on a fresh template. Old ones become garbage
/// nobody reads; `reap_dead` and a human sweep them.
fn template_db() -> String {
    use std::sync::OnceLock;
    static NAME: OnceLock<String> = OnceLock::new();
    NAME.get_or_init(|| {
        let h = crate::store::postgres::embedded_migration_fingerprint();
        format!("ciris_t_template_{h:016x}")
    })
    .clone()
}

/// The name the template is BUILT under, before being renamed into place.
///
/// Shaped like a per-process database (`ciris_t_<pid>_…`) on purpose, so
/// [`reap_dead`] — which parses the segment after `ciris_t_` as a PID — sweeps
/// it if its builder dies. A finished template is `ciris_t_template_<hash>`,
/// whose second segment does not parse as a PID, so it correctly survives as
/// the cache it is. `scratch_and_template_names_sort_correctly_for_the_reaper`
/// pins both halves; getting it backwards either strands half-built databases
/// forever or reaps the live template out from under every running process.
fn scratch_template_name() -> String {
    format!(
        "ciris_t_{}_tpl_{:016x}",
        std::process::id(),
        crate::store::postgres::embedded_migration_fingerprint()
    )
}

/// A postgres advisory-lock key, so exactly one process builds the template
/// while the rest wait rather than racing 116 migrations against each other.
///
/// Advisory locks are PER-DATABASE (the tag includes the database OID), which
/// is fine and in fact required here: every process takes it on the same admin
/// database, so they genuinely contend.
const TEMPLATE_LOCK: i64 = 0x0C11_3507_E570;

/// Build [`template_db()`] if it does not exist, and return its name.
///
/// Returns `None` on any failure, which degrades to "create an empty database
/// and let the test migrate it" — slower, still correct, never silently
/// shared.
fn ensure_template(admin: &str) -> Option<String> {
    // Fast path: already built. Sound ONLY because the name appears at the end
    // of construction, never at the start — see the build below.
    if database_exists(admin, &template_db()).unwrap_or(false) {
        return Some(template_db());
    }
    // Serialize construction. `pg_advisory_lock` blocks until acquired and is
    // released when the session ends, so a process that dies mid-build cannot
    // wedge the others.
    let built = with_advisory_lock(admin, TEMPLATE_LOCK, || {
        if database_exists(admin, &template_db()).unwrap_or(false) {
            return Ok(()); // another process won the race while we waited
        }
        // v42.1.0 (CIRISPersist#821) — BUILD UNDER A SCRATCH NAME, THEN RENAME.
        //
        // The fast path above tests EXISTENCE. Creating the template under its
        // final name and migrating it afterwards made existence arrive BEFORE
        // readiness, and the window between them is the length of a full
        // migration run. In it, every other process took the fast path, skipped
        // this lock entirely, and issued
        // `CREATE DATABASE … TEMPLATE <half-built>`.
        //
        // What we SAW was postgres refusing that copy, because this process is
        // still connected to the source — a red CI leg, which is the lucky
        // outcome. The unlucky one is the copy succeeding against a partially
        // migrated template: every per-test database then carries a schema the
        // tree does not describe, and the suite goes green on it. That is the
        // exact silent-wrong-answer the fingerprinted name exists to stop
        // (V121 bit in both directions), reintroduced one level up in the
        // lifecycle rather than in the name.
        //
        // Renaming last makes the name mean "fully migrated", so the fast path
        // becomes true by construction instead of by timing.
        //
        // The scratch name is `ciris_t_<pid>_tpl_<hash>`, deliberately shaped
        // like a per-process database rather than like a template: `reap_dead`
        // strips `ciris_t_` and parses the next segment as a PID, so this form
        // is swept when its builder dies, while a finished
        // `ciris_t_template_<hash>` parses as "template", fails the PID parse,
        // and correctly survives as the cache it is. Getting this backwards
        // would either strand half-built databases forever or reap the template
        // out from under every running process.
        let scratch = scratch_template_name();
        let _ = run_sql(admin, &format!("DROP DATABASE IF EXISTS \"{scratch}\""));
        run_sql(admin, &format!("CREATE DATABASE \"{scratch}\""))?;
        let (host, _) = split(admin).ok_or_else(|| "admin dsn".to_owned())?;
        if let Err(e) = migrate(&format!("{host}/{scratch}")) {
            // Do not leave a half-migrated database standing under a name that
            // a future fingerprint might match.
            let _ = run_sql(admin, &format!("DROP DATABASE IF EXISTS \"{scratch}\""));
            return Err(e);
        }
        let renamed = run_sql(
            admin,
            &format!(
                "ALTER DATABASE \"{scratch}\" RENAME TO \"{}\"",
                template_db()
            ),
        );
        if renamed.is_err() {
            // Never leave a scratch standing. With the lock genuinely held this
            // should be unreachable, but an abandoned migrated database costs
            // real disk on a shared cluster and `reap_dead` only collects it
            // once this process exits.
            let _ = run_sql(admin, &format!("DROP DATABASE IF EXISTS \"{scratch}\""));
        }
        renamed
    });
    match built {
        Ok(()) => Some(template_db()),
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
    // v42.1.0 (CIRISPersist#821, Codex review P1) — HOLD THE LOCK ACROSS `f`.
    //
    // The previous shape took `pg_advisory_lock` on a connection owned by a
    // thread that then RETURNED, closing the session. Advisory locks are
    // session-scoped, so the lock was gone before the closure ran and this
    // function serialized nothing. Its own comment said so and argued the race
    // was harmless because `f` re-checks existence.
    //
    // That argument held only by accident. Every builder raced
    // `CREATE DATABASE "<final template name>"`, postgres let exactly one win,
    // and the losers took the slow-but-correct path. Giving each builder a
    // PID-unique scratch name (the fix for the readiness race) removed that
    // accidental serialization: every `CREATE DATABASE` now succeeds, so on a
    // cold parallel start EVERY process ran the full migration set at once —
    // precisely the load the shared template exists to avoid — and the losers
    // of the rename left their scratch databases standing.
    //
    // So the two fixes are coupled: build-then-rename is only safe if the lock
    // is real. The lock-holding connection now stays open, and its runtime keeps
    // polling it, until `f` has finished and the rename has landed.
    let a = admin.to_owned();
    let (acquired_tx, acquired_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();

    let guard = std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = acquired_tx.send(Err(format!("runtime: {e}")));
                return;
            }
        };
        rt.block_on(async move {
            let (client, connection) =
                match tokio_postgres::connect(&a, tokio_postgres::NoTls).await {
                    Ok(pair) => pair,
                    Err(e) => {
                        let _ = acquired_tx.send(Err(format!("connect: {e}")));
                        return;
                    }
                };
            let h = tokio::spawn(async move {
                let _ = connection.await;
            });
            if let Err(e) = client.execute("SELECT pg_advisory_lock($1)", &[&key]).await {
                let _ = acquired_tx.send(Err(format!("lock: {e}")));
                h.abort();
                return;
            }
            let _ = acquired_tx.send(Ok(()));
            // AWAIT, never block: the current-thread runtime must keep polling
            // `connection` or the client stops being driven while the caller
            // runs a full migration set on the other side of this channel.
            let _ = release_rx.await;
            // Closing the session releases the lock; the explicit unlock is
            // belt-and-braces for a pooled server that outlives the socket.
            let _ = client
                .execute("SELECT pg_advisory_unlock($1)", &[&key])
                .await;
            drop(client);
            h.abort();
        });
    });

    // Propagate an acquisition failure rather than running `f` unlocked.
    let acquired = acquired_rx
        .recv()
        .map_err(|_| "lock thread died before acquiring".to_owned())?;
    if let Err(e) = acquired {
        let _ = release_tx.send(());
        let _ = guard.join();
        return Err(e);
    }

    let out = f();

    let _ = release_tx.send(());
    guard
        .join()
        .map_err(|_| "lock thread panicked".to_owned())?;
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

/// v42.1.0 (CIRISPersist#821) — spell out WHY postgres refused.
///
/// `tokio_postgres::Error`'s `Display` is the string `"db error"` plus nothing
/// useful: the server's actual message, SQLSTATE, detail and hint all live on
/// the `DbError` behind `as_db_error()`. A provisioning failure in CI therefore
/// arrived as
///
/// ```text
/// could not provision a per-process database (execute: db error).
/// ```
///
/// which names the SQL that failed and not one word about the reason — so a red
/// leg could not be told apart from a dozen unrelated causes without a local
/// repro, and the repro is precisely what a load-dependent race denies you. The
/// panic below refuses to fall back silently, which is right; refusing to say
/// why is not.
fn describe_pg_error(e: &tokio_postgres::Error) -> String {
    match e.as_db_error() {
        Some(db) => {
            let mut out = format!("{} [SQLSTATE {}]", db.message(), db.code().code());
            if let Some(d) = db.detail() {
                out.push_str(&format!(" detail: {d}"));
            }
            if let Some(h) = db.hint() {
                out.push_str(&format!(" hint: {h}"));
            }
            out
        }
        None => e.to_string(),
    }
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
            .map_err(|e| format!("execute: {}", describe_pg_error(&e)));
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

#[cfg(test)]
mod template_naming_tests {
    use super::{scratch_template_name, template_db};

    /// `reap_dead`'s classifier, spelled out here rather than called, because
    /// the real one issues DROPs. The point is the NAMING CONTRACT the two
    /// functions must satisfy for that classifier to do the right thing.
    fn parses_as_pid_bearing(name: &str) -> bool {
        name.strip_prefix("ciris_t_")
            .and_then(|rest| rest.split_once('_'))
            .and_then(|(pid, _)| pid.parse::<u32>().ok())
            .is_some()
    }

    /// v42.1.0 (CIRISPersist#821) — the scratch database must look reapable and
    /// the finished template must not.
    ///
    /// I got this backwards on the first pass: the scratch was named
    /// `<template>_bld_<pid>`, whose segment after `ciris_t_` is the literal
    /// "template", so it failed the PID parse and would have been stranded on
    /// the server forever after any builder crash.
    #[test]
    fn scratch_and_template_names_sort_correctly_for_the_reaper() {
        let scratch = scratch_template_name();
        let finished = template_db();

        assert!(
            parses_as_pid_bearing(&scratch),
            "scratch {scratch:?} must parse as ciris_t_<pid>_… or reap_dead \
             will never sweep a half-built template"
        );
        assert!(
            !parses_as_pid_bearing(&finished),
            "finished template {finished:?} must NOT parse as a per-process \
             database, or reap_dead would drop the shared cache out from under \
             every live process"
        );
        // They must never collide — the rename would be a no-op and the fast
        // path would start returning a half-built database.
        assert_ne!(scratch, finished);
        // Postgres truncates identifiers at 63 bytes; a silent truncation could
        // make two builders collide on one scratch name.
        assert!(scratch.len() <= 63, "scratch name {} bytes", scratch.len());
        assert!(
            finished.len() <= 63,
            "template name {} bytes",
            finished.len()
        );
    }
}

#[cfg(test)]
mod pg_error_detail_tests {
    /// v42.1.0 (CIRISPersist#821) — a provisioning failure must name its cause.
    ///
    /// Drives a real refusal (creating a database that already exists) and
    /// asserts the rendered string carries the server's message and SQLSTATE,
    /// not the bare `"db error"` that `Display` gives. The CI failure this
    /// belongs to was undiagnosable for exactly that reason.
    #[test]
    fn a_refused_statement_names_its_reason_not_just_db_error() {
        let Some(dsn) = super::dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let (host, _) = super::split(&dsn).expect("dsn");
        let admin = format!("{host}/postgres");
        // `template1` always exists, so this is a guaranteed, harmless refusal.
        let err = super::run_sql(&admin, "CREATE DATABASE \"template1\"")
            .expect_err("creating an existing database must fail");
        assert!(
            err.contains("SQLSTATE"),
            "provisioning error must carry the SQLSTATE, got: {err}"
        );
        // v42.1.0 (Codex review P2) — assert the SQLSTATE, not English. A server
        // with a non-English `lc_messages` localizes "already exists" while
        // still returning 42P04, so an assertion on the prose is a portability
        // bug in the test rather than a property of the code.
        assert!(
            err.contains("42P04"),
            "provisioning error must carry the duplicate-database SQLSTATE, got: {err}"
        );
        // The server's own message must still be present — that is the whole
        // point of `describe_pg_error` — but its CONTENT is the server's to
        // choose, so assert only that something beyond the bare form arrived.
        assert!(
            err.len() > "execute: db error".len() + "[SQLSTATE 42P04]".len(),
            "rendered error carries no server message, got: {err}"
        );
        assert_ne!(
            err, "execute: db error",
            "this is the uninformative form the fix exists to replace"
        );
    }
}

#[cfg(test)]
mod advisory_lock_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// v42.1.0 (CIRISPersist#821, Codex review P1) — the lock must be held for
    /// the DURATION of the closure, not merely acquired before it.
    ///
    /// The previous implementation took `pg_advisory_lock` on a connection whose
    /// thread then returned, closing the session and releasing the lock before
    /// the closure ran. It serialized nothing, and its own comment said as much
    /// while arguing the window was harmless.
    ///
    /// Measured directly: N threads enter the same lock and each records the
    /// occupancy of its critical section. If the lock works, the peak is 1.
    ///
    /// Mutation check performed: restoring the release-early shape (drop the
    /// lock session before calling `f`) drives the peak to 4 and turns this red.
    #[test]
    fn the_lock_is_held_for_the_whole_closure_not_just_acquired() {
        let Some(dsn) = super::dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let (host, _) = super::split(&dsn).expect("dsn");
        let admin = format!("{host}/postgres");
        // A key of this test's own, so it cannot contend with the template lock
        // and cannot be satisfied by some unrelated holder.
        const TEST_KEY: i64 = 0x0C11_3507_7E57;

        let occupancy = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        std::thread::scope(|s| {
            for _ in 0..4 {
                let admin = admin.clone();
                let occupancy = Arc::clone(&occupancy);
                let peak = Arc::clone(&peak);
                s.spawn(move || {
                    let r = super::with_advisory_lock(&admin, TEST_KEY, || {
                        let now = occupancy.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        // Wide enough that an unheld lock reliably overlaps;
                        // short enough that four serialized turns stay quick.
                        std::thread::sleep(std::time::Duration::from_millis(150));
                        occupancy.fetch_sub(1, Ordering::SeqCst);
                        Ok(())
                    });
                    assert!(r.is_ok(), "lock body failed: {r:?}");
                });
            }
        });

        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "two closures were inside the same advisory lock at once — the lock \
             is being released before `f` runs, so template construction is not \
             serialized and every process migrates concurrently"
        );
        assert_eq!(occupancy.load(Ordering::SeqCst), 0);
    }
}
