//! v62.0.0 (WASM_UEFI_READINESS P6) — **persist applies its own migrations.**
//!
//! refinery's runner stamped each applied migration with
//! `OffsetDateTime::now_utc()` (`refinery-core-0.10.1/src/runner.rs:130`),
//! which panics on `wasm32-unknown-unknown`: the browser and UEFI node could
//! not migrate. This runner takes the instant from its caller (`now`, called
//! once per applied migration as refinery stamped each), and is otherwise
//! refinery's, decision for decision, so a store refinery migrated reads and
//! continues here, and a fresh store gets the rows refinery would have
//! written:
//!
//! - **the history table** is refinery's: the same `CREATE TABLE IF NOT
//!   EXISTS` text (so `sqlite_master.sql` is byte-identical), `version int4`
//!   (refinery without `int8-versions`), `name`, `applied_on` and `checksum`
//!   as `VARCHAR(255)`. SQLite keeps refinery's default name
//!   (`refinery_schema_history`), postgres persist's
//!   (`ciris_persist_schema_history`).
//! - **a row** is `(version, name, applied_on, checksum)`: `version` an
//!   integer, the rest text, as refinery's literal `INSERT` stored them.
//!   `name` is the file stem after `V{n}__`. `checksum` is refinery's
//!   SipHash-1-3 (keys 0, 0) over `name`, `version as i32`, then the file's
//!   text, each through `Hash` (so a `str` is its bytes plus `0xff`), as a
//!   decimal `u64`. `applied_on` is `time`'s RFC 3339 form in UTC:
//!   `YYYY-MM-DDTHH:MM:SS`, then `.` and the nanoseconds with trailing zeros
//!   cut when they are not zero, then `Z`.
//! - **the decision** is `refinery::traits::verify_migrations` with both
//!   aborts on (refinery's defaults, which persist never changed): every
//!   applied row must name a file of its version with the same name and
//!   checksum (else *divergent*) and every applied version must have a file
//!   (else *missing*); a file not applied whose version is at or below the
//!   highest applied one is *missing*; the rest apply in version order, up
//!   to the target.
//!
//! One difference, in the safe direction: refinery's SQLite driver committed
//! a migration's SQL and its history row in two transactions, so a crash
//! between them left a migration applied and unrecorded (postgres already
//! used one). Here both dialects commit the SQL and its row together.

use chrono::{DateTime, Datelike as _, Timelike as _, Utc};
use std::hash::{Hash as _, Hasher as _};

include!(concat!(env!("OUT_DIR"), "/embedded_migrations.rs"));

/// One embedded migration file.
#[derive(Debug, Clone)]
pub(crate) struct Migration {
    /// `V{version}__…`.
    pub(crate) version: i32,
    /// The stem after `V{version}__`.
    pub(crate) name: String,
    /// The file's text, as shipped.
    pub(crate) sql: &'static str,
    /// refinery's checksum of `(name, version, sql)`.
    pub(crate) checksum: u64,
}

/// One row of the history table, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Applied {
    pub(crate) version: i32,
    pub(crate) name: String,
    pub(crate) checksum: u64,
}

/// Why a run refused or failed. The divergence and missing texts are
/// refinery's, so an operator's runbook (and a log search) still matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MigrationError {
    /// An applied row whose file has the same version but another name or
    /// checksum: a shipped migration was edited (#840).
    Divergent {
        applied: (i32, String, u64),
        file: (i32, String, u64),
    },
    /// An applied version with no file, or a file below the applied head
    /// that was never applied.
    Missing { version: i32, name: String },
    /// Two files carry one version.
    Repeated { version: i32, name: String },
    /// v62.0.0 (slice E2b, I1951) — the store carries edition-1 history (a
    /// row below the edition-2 baseline, V300). The baseline never runs over
    /// it: an edition-1 store is deleted by
    /// [`crate::store::edition_upgrade`], never migrated.
    EditionOneHistory { head: i32 },
    /// A history row this runner cannot read (its checksum is not a `u64`).
    History(String),
    /// The instant `now` returned has no RFC 3339 form (a year outside
    /// 0..=9999).
    Instant(String),
    /// A migration's SQL, or its history row, failed; nothing of it committed.
    Apply {
        version: i32,
        name: String,
        detail: String,
        sqlstate: Option<String>,
    },
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Divergent { applied, file } => write!(
                f,
                "applied migration V{}__{} is different than filesystem one V{}__{}",
                applied.0, applied.1, file.0, file.1
            ),
            Self::Missing { version, name } => {
                write!(
                    f,
                    "migration V{version}__{name} is missing from the filesystem"
                )
            }
            Self::Repeated { version, name } => {
                write!(
                    f,
                    "migration V{version}__{name} is repeated, migration versions must be unique"
                )
            }
            Self::EditionOneHistory { head } => write!(
                f,
                "the store carries edition-1 migration history (head V{head}); the edition-2 \
                 baseline (V{}) never runs over it — an edition-1 store is deleted at open \
                 (store::edition_upgrade)",
                crate::store::edition_baseline::EDITION_TWO_BASELINE
            ),
            Self::History(d) => write!(f, "error reading the schema history: {d}"),
            Self::Instant(d) => write!(f, "the applied_on instant has no RFC 3339 form: {d}"),
            Self::Apply {
                version,
                name,
                detail,
                ..
            } => write!(f, "error applying migration V{version}__{name}: {detail}"),
        }
    }
}

impl std::error::Error for MigrationError {}

/// What a run applied, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) applied: Vec<(i32, String)>,
}

impl Report {
    /// The applied versions, in order.
    pub(crate) fn versions(&self) -> Vec<i32> {
        self.applied.iter().map(|(v, _)| *v).collect()
    }
}

#[cfg(feature = "postgres")]
impl MigrationError {
    /// The postgres SQLSTATE of a failed apply, when the server sent one.
    pub(crate) fn sqlstate(&self) -> Option<&str> {
        match self {
            Self::Apply { sqlstate, .. } => sqlstate.as_deref(),
            _ => None,
        }
    }
}

/// refinery's checksum (`Migration::unapplied`): SipHash-1-3, keys (0, 0),
/// over `name`, `version`, `sql` through `Hash`.
pub(crate) fn checksum(name: &str, version: i32, sql: &str) -> u64 {
    let mut h = siphasher::sip::SipHasher13::new();
    name.hash(&mut h);
    version.hash(&mut h);
    sql.hash(&mut h);
    h.finish()
}

/// Parse an embedded list (`(stem, text)`), checksum it, and order it by
/// version.
pub(crate) fn embedded(list: &'static [(&'static str, &'static str)]) -> Vec<Migration> {
    let mut out: Vec<Migration> = list
        .iter()
        .map(|(stem, sql)| {
            // build.rs admitted only `V{digits}__{word}`.
            let (v, name) = stem
                .strip_prefix('V')
                .and_then(|r| r.split_once("__"))
                .expect("build.rs admits V{n}__{name} only");
            let version: i32 = v.parse().expect("build.rs admits digits only");
            Migration {
                version,
                name: name.to_owned(),
                sql,
                checksum: checksum(name, version, sql),
            }
        })
        .collect();
    out.sort_by_key(|m| m.version);
    out
}

/// `now` in `time`'s RFC 3339 form, UTC: what refinery wrote into
/// `applied_on`.
pub(crate) fn format_applied_on(now: DateTime<Utc>) -> Result<String, MigrationError> {
    let year = now.year();
    if !(0..10_000).contains(&year) {
        return Err(MigrationError::Instant(format!("year {year}")));
    }
    let mut s = format!(
        "{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    // chrono carries a leap second as nanosecond >= 1e9; `time` has none.
    let nanos = now.nanosecond() % 1_000_000_000;
    if nanos != 0 {
        let digits = format!("{nanos:09}");
        s.push('.');
        s.push_str(digits.trim_end_matches('0'));
    }
    s.push('Z');
    Ok(s)
}

/// refinery's `ASSERT_MIGRATIONS_TABLE_QUERY` for `table`, byte for byte
/// (`int4`: refinery without `int8-versions`).
pub(crate) fn history_table_ddl(table: &str) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {table}(
             version int4 PRIMARY KEY,
             name VARCHAR(255),
             applied_on VARCHAR(255),
             checksum VARCHAR(255));"
    )
}

/// refinery's `GET_APPLIED_MIGRATIONS_QUERY` for `table`.
pub(crate) fn applied_query(table: &str) -> String {
    format!("SELECT version, name, applied_on, checksum FROM {table} ORDER BY version ASC;")
}

/// The history row insert: refinery's column order, bound.
pub(crate) fn insert_query(table: &str, dialect: Dialect) -> String {
    match dialect {
        #[cfg(feature = "sqlite")]
        Dialect::Sqlite => format!(
            "INSERT INTO {table} (version, name, applied_on, checksum) VALUES (?1, ?2, ?3, ?4)"
        ),
        #[cfg(feature = "postgres")]
        Dialect::Postgres => format!(
            "INSERT INTO {table} (version, name, applied_on, checksum) VALUES ($1, $2, $3, $4)"
        ),
    }
}

/// Which bind syntax [`insert_query`] speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dialect {
    #[cfg(feature = "sqlite")]
    Sqlite,
    #[cfg(feature = "postgres")]
    Postgres,
}

/// A history row's checksum column, which refinery wrote as a decimal `u64`.
pub(crate) fn parse_checksum(version: i32, raw: &str) -> Result<u64, MigrationError> {
    raw.parse::<u64>()
        .map_err(|_| MigrationError::History(format!("V{version}: checksum {raw:?} is not a u64")))
}

/// refinery's `verify_migrations(applied, migrations, abort_divergent =
/// true, abort_missing = true)`, then the target cut: the migrations to
/// apply, in version order.
pub(crate) fn plan<'m>(
    applied: &[Applied],
    migrations: &'m [Migration],
    target: Option<i32>,
) -> Result<Vec<&'m Migration>, MigrationError> {
    // v62.0.0 (I1951) — edition 2 never continues an edition-1 history.
    if applied
        .iter()
        .any(|a| a.version < crate::store::edition_baseline::EDITION_TWO_BASELINE)
    {
        return Err(MigrationError::EditionOneHistory {
            head: applied.iter().map(|a| a.version).max().unwrap_or(0),
        });
    }
    for app in applied {
        match migrations.iter().find(|m| m.version == app.version) {
            None => {
                return Err(MigrationError::Missing {
                    version: app.version,
                    name: app.name.clone(),
                })
            }
            Some(m) if m.name != app.name || m.checksum != app.checksum => {
                return Err(MigrationError::Divergent {
                    applied: (app.version, app.name.clone(), app.checksum),
                    file: (m.version, m.name.clone(), m.checksum),
                })
            }
            Some(_) => {}
        }
    }
    // refinery: the LAST row by version order, -1 when empty.
    let current = applied.iter().map(|a| a.version).max().unwrap_or(-1);
    let mut out: Vec<&Migration> = Vec::new();
    for m in migrations {
        if applied.iter().any(|a| a.version == m.version) {
            continue;
        }
        if out.iter().any(|o| o.version == m.version) {
            return Err(MigrationError::Repeated {
                version: m.version,
                name: m.name.clone(),
            });
        }
        if current >= m.version {
            return Err(MigrationError::Missing {
                version: m.version,
                name: m.name.clone(),
            });
        }
        out.push(m);
    }
    if let Some(t) = target {
        out.retain(|m| m.version <= t);
    }
    Ok(out)
}

// ── SQLite ────────────────────────────────────────────────────────────────

/// Migrate `conn` to `target` (every migration when `None`), stamping each
/// applied row with `now()`. Each migration's SQL and its history row commit
/// in one IMMEDIATE transaction (CIRISPersist#1238).
#[cfg(feature = "sqlite")]
pub(crate) fn run_sqlite(
    conn: &mut rusqlite::Connection,
    migrations: &[Migration],
    target: Option<i32>,
    now: &dyn Fn() -> DateTime<Utc>,
) -> Result<Report, MigrationError> {
    const TABLE: &str = "refinery_schema_history";
    let hist = |e: rusqlite::Error| MigrationError::History(e.to_string());
    conn.execute_batch(&history_table_ddl(TABLE))
        .map_err(hist)?;
    let applied: Vec<Applied> = {
        let mut st = conn.prepare(&applied_query(TABLE)).map_err(hist)?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, i32>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .map_err(hist)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(hist)?;
        rows.into_iter()
            .map(|(version, name, raw)| {
                Ok(Applied {
                    version,
                    checksum: parse_checksum(version, &raw)?,
                    name,
                })
            })
            .collect::<Result<_, MigrationError>>()?
    };
    let mut report = Report::default();
    for m in plan(&applied, migrations, target)? {
        let applied_on = format_applied_on(now())?;
        let fail = |e: rusqlite::Error| MigrationError::Apply {
            version: m.version,
            name: m.name.clone(),
            detail: e.to_string(),
            sqlstate: None,
        };
        let tx = crate::store::sqlite_conn_model::write_tx(conn).map_err(fail)?;
        tx.execute_batch(m.sql).map_err(fail)?;
        tx.execute(
            &insert_query(TABLE, Dialect::Sqlite),
            rusqlite::params![m.version, m.name, applied_on, m.checksum.to_string()],
        )
        .map_err(fail)?;
        tx.commit().map_err(fail)?;
        report.applied.push((m.version, m.name.clone()));
    }
    Ok(report)
}

/// The SQLite migrations, parsed once per call.
#[cfg(feature = "sqlite")]
pub(crate) fn sqlite_migrations() -> Vec<Migration> {
    embedded(SQLITE_MIGRATIONS)
}

// ── Postgres ──────────────────────────────────────────────────────────────

/// The postgres history table: persist's name, not refinery's default.
#[cfg(feature = "postgres")]
pub(crate) const POSTGRES_HISTORY_TABLE: &str = "ciris_persist_schema_history";

/// Migrate `client` to `target`, as [`run_sqlite`]; each migration's SQL
/// and its history row in one transaction (refinery's postgres shape).
#[cfg(feature = "postgres")]
pub(crate) async fn run_postgres(
    client: &mut tokio_postgres::Client,
    migrations: &[Migration],
    target: Option<i32>,
    now: &(dyn Fn() -> DateTime<Utc> + Sync),
) -> Result<Report, MigrationError> {
    let table = POSTGRES_HISTORY_TABLE;
    let hist = |e: tokio_postgres::Error| MigrationError::History(e.to_string());
    client
        .batch_execute(&history_table_ddl(table))
        .await
        .map_err(hist)?;
    let rows = client
        .query(&applied_query(table), &[])
        .await
        .map_err(hist)?;
    let applied = rows
        .iter()
        .map(|r| {
            let version: i32 = r.try_get(0).map_err(hist)?;
            let name: String = r.try_get(1).map_err(hist)?;
            let raw: String = r.try_get(3).map_err(hist)?;
            Ok(Applied {
                version,
                checksum: parse_checksum(version, &raw)?,
                name,
            })
        })
        .collect::<Result<Vec<_>, MigrationError>>()?;
    let mut report = Report::default();
    for m in plan(&applied, migrations, target)? {
        let applied_on = format_applied_on(now())?;
        let fail = |e: tokio_postgres::Error| MigrationError::Apply {
            version: m.version,
            name: m.name.clone(),
            sqlstate: e.code().map(|c| c.code().to_owned()),
            detail: match e.as_db_error() {
                Some(db) => db.to_string(),
                None => e.to_string(),
            },
        };
        let tx = client.transaction().await.map_err(fail)?;
        tx.batch_execute(m.sql).await.map_err(fail)?;
        tx.execute(
            &insert_query(table, Dialect::Postgres),
            &[&m.version, &m.name, &applied_on, &m.checksum.to_string()],
        )
        .await
        .map_err(fail)?;
        tx.commit().await.map_err(fail)?;
        report.applied.push((m.version, m.name.clone()));
    }
    Ok(report)
}

/// The postgres migrations, parsed once per call.
#[cfg(feature = "postgres")]
pub(crate) fn postgres_migrations() -> Vec<Migration> {
    embedded(POSTGRES_MIGRATIONS)
}

// ── witnesses: refinery (a dev-dependency) is the oracle ──────────────────

#[cfg(all(test, feature = "sqlite"))]
mod refinery_sqlite {
    refinery::embed_migrations!("migrations/sqlite/lens");
}

#[cfg(all(test, feature = "postgres"))]
mod refinery_postgres {
    refinery::embed_migrations!("migrations/postgres/lens");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Instants with every subsecond shape `time` distinguishes.
    fn instants() -> Vec<DateTime<Utc>> {
        let base = 1_790_000_000i64;
        [
            0u32,
            1,
            10,
            100,
            1_000,
            10_000,
            100_000,
            1_000_000,
            10_000_000,
            100_000_000,
            120_000_000,
            123_456_789,
            999_999_999,
            500_000_000,
            7,
        ]
        .iter()
        .enumerate()
        .map(|(i, n)| DateTime::from_timestamp(base + i as i64 * 3_601, *n).unwrap())
        .chain([
            DateTime::from_timestamp(0, 0).unwrap(),
            DateTime::from_timestamp(253_402_300_799, 999_999_999).unwrap(), // 9999-12-31
        ])
        .collect()
    }

    /// **I1818 — persist's runner computes refinery's checksums and writes
    /// refinery's instant.** For every migration file of each compiled
    /// dialect, `(version, name, checksum)` equals refinery's
    /// `Migration::unapplied` and the embedded list equals refinery's
    /// `embed_migrations!` list, element for element; `applied_on` equals
    /// `time`'s RFC 3339 form (what refinery wrote) at every subsecond shape,
    /// and a year outside 0..=9999 refuses instead of panicking.
    #[test]
    // One push per compiled dialect, each behind its own cfg.
    #[allow(clippy::vec_init_then_push)]
    fn i1818_checksums_names_and_the_instant_are_refinerys() {
        #[allow(unused_mut)]
        let mut lists: Vec<(&str, Vec<Migration>, Vec<refinery::Migration>)> = Vec::new();
        #[cfg(feature = "sqlite")]
        lists.push((
            "sqlite",
            sqlite_migrations(),
            refinery_sqlite::migrations::runner()
                .get_migrations()
                .clone(),
        ));
        #[cfg(feature = "postgres")]
        lists.push((
            "postgres",
            postgres_migrations(),
            refinery_postgres::migrations::runner()
                .get_migrations()
                .clone(),
        ));
        assert!(!lists.is_empty());
        for (dialect, ours, mut theirs) in lists {
            theirs.sort();
            assert_eq!(
                ours.first().map(|m| m.version),
                Some(crate::store::edition_baseline::EDITION_TWO_BASELINE),
                "I1818 {dialect}: the embed found the edition-2 baseline first"
            );
            assert_eq!(ours.len(), theirs.len(), "I1818 {dialect}: the same files");
            for (o, t) in ours.iter().zip(&theirs) {
                assert_eq!(
                    (o.version, o.name.as_str(), o.checksum),
                    (t.version(), t.name(), t.checksum()),
                    "I1818 {dialect}: V{} is refinery's",
                    o.version
                );
                assert_eq!(
                    Some(o.sql),
                    t.sql(),
                    "I1818 {dialect}: V{}'s text",
                    o.version
                );
            }
        }
        for t in instants() {
            let theirs = time::OffsetDateTime::from_unix_timestamp_nanos(
                i128::from(t.timestamp()) * 1_000_000_000 + i128::from(t.timestamp_subsec_nanos()),
            )
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
            assert_eq!(
                format_applied_on(t).unwrap(),
                theirs,
                "I1818: applied_on at {t:?}"
            );
        }
        let far = DateTime::from_timestamp(253_402_300_800, 0).unwrap(); // year 10000
        assert!(matches!(
            format_applied_on(far),
            Err(MigrationError::Instant(_))
        ));
    }

    /// `plan`'s refusals, decision for decision against
    /// `refinery::verify_migrations` (both aborts on), with no database.
    #[test]
    fn plan_refuses_as_refinery_does() {
        let m = |v: i32, n: &str| Migration {
            version: v,
            name: n.into(),
            sql: "",
            checksum: checksum(n, v, ""),
        };
        let a = |v: i32, n: &str| Applied {
            version: v,
            name: n.into(),
            checksum: checksum(n, v, ""),
        };
        let files = vec![m(300, "a"), m(301, "b"), m(302, "c"), m(304, "e")];
        let vs = |p: Vec<&Migration>| p.iter().map(|m| m.version).collect::<Vec<_>>();
        assert_eq!(vs(plan(&[], &files, None).unwrap()), [300, 301, 302, 304]);
        assert_eq!(
            vs(plan(&[a(300, "a")], &files, None).unwrap()),
            [301, 302, 304]
        );
        assert_eq!(
            vs(plan(&[a(300, "a")], &files, Some(302)).unwrap()),
            [301, 302]
        );
        assert!(plan(
            &files
                .iter()
                .map(|f| a(f.version, &f.name))
                .collect::<Vec<_>>(),
            &files,
            None
        )
        .unwrap()
        .is_empty());
        // divergent: same version, another name or checksum
        assert!(matches!(
            plan(&[a(300, "x")], &files, None),
            Err(MigrationError::Divergent { .. })
        ));
        let mut edited = a(301, "b");
        edited.checksum ^= 1;
        assert!(matches!(
            plan(&[a(300, "a"), edited], &files, None),
            Err(MigrationError::Divergent { .. })
        ));
        // missing: applied with no file; a file under the head never applied
        assert!(matches!(
            plan(&[a(303, "d")], &files, None),
            Err(MigrationError::Missing { version: 303, .. })
        ));
        assert!(matches!(
            plan(&[a(300, "a"), a(302, "c")], &files, None),
            Err(MigrationError::Missing { version: 301, .. })
        ));
        assert_eq!(
            MigrationError::Divergent {
                applied: (300, "x".into(), 0),
                file: (300, "a".into(), 0)
            }
            .to_string(),
            "applied migration V300__x is different than filesystem one V300__a"
        );
        // I1951 — any history row below the baseline refuses, before any
        // other decision: an edition-1 store is deleted, never continued.
        for applied in [
            vec![a(1, "trace_events")],
            vec![a(216, "attestation_dimension_asserted_seek")],
            vec![a(299, "x"), a(300, "a")],
        ] {
            let head = applied.iter().map(|x| x.version).max().unwrap();
            assert_eq!(
                plan(&applied, &files, None).map(|p| p.len()),
                Err(MigrationError::EditionOneHistory { head }),
                "I1951: {applied:?}"
            );
        }
    }
}

/// The edition-1 history every edition-1 store carries, as frozen in
/// `tests/fixtures/edition1_schema/{dialect}.history`: `(version, name,
/// checksum)`.
#[cfg(test)]
pub(crate) fn edition_one_history(dialect: &str) -> Vec<(i32, String, String)> {
    let text = std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(format!("tests/fixtures/edition1_schema/{dialect}.history")),
    )
    .expect("edition-1 history fixture");
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (
                f[0].parse().expect("version"),
                f[1].to_owned(),
                f[2].to_owned(),
            )
        })
        .collect()
}

/// A clock for the witnesses: distinct instants, each with a subsecond.
#[cfg(test)]
fn test_clock() -> (
    impl Fn() -> DateTime<Utc> + Sync,
    impl Fn(usize) -> DateTime<Utc>,
) {
    use std::sync::atomic::{AtomicI64, Ordering};
    let k = std::sync::Arc::new(AtomicI64::new(0));
    let at =
        |i: i64| DateTime::from_timestamp(1_790_000_000 + i * 3, 120_000_000 + i as u32).unwrap();
    let k2 = k.clone();
    (
        move || at(k2.fetch_add(1, Ordering::SeqCst)),
        move |i: usize| at(i as i64),
    )
}

#[cfg(all(test, feature = "sqlite"))]
mod sqlite_witnesses {
    use super::*;
    use rusqlite::Connection;

    type Row = (i64, String, String, String, String, String, String, String);

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        c
    }

    /// Every history row with each column's storage class.
    fn history(c: &Connection) -> Vec<Row> {
        let mut st = c
            .prepare(
                "SELECT version, typeof(version), name, typeof(name), applied_on, \
                 typeof(applied_on), checksum, typeof(checksum) \
                 FROM refinery_schema_history ORDER BY version",
            )
            .unwrap();
        st.query_map([], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
            ))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    /// Every schema object's DDL text.
    fn schema(c: &Connection) -> Vec<(String, String, Option<String>)> {
        let mut st = c
            .prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn rfc3339_roundtrips(s: &str) -> bool {
        let f = time::format_description::well_known::Rfc3339;
        time::OffsetDateTime::parse(s, &f)
            .map(|t| t.format(&f).unwrap() == s)
            .unwrap_or(false)
    }

    /// **I1819 (sqlite) — a fresh store gets refinery's history rows.**
    /// refinery and persist's runner each migrate a fresh database: the
    /// history table's DDL text, every row's version, name and checksum, and
    /// every column's storage class are identical; `applied_on` is the
    /// injected clock's instant in `time`'s RFC 3339 form (refinery's own
    /// rows round-trip through the same form); every schema object the
    /// migrations create is byte-identical.
    #[test]
    fn i1819_a_fresh_store_gets_refinerys_history_rows_sqlite() {
        let mut theirs = conn();
        refinery_sqlite::migrations::runner()
            .run(&mut theirs)
            .unwrap();
        let mut ours = conn();
        let migs = sqlite_migrations();
        let (now, at) = test_clock();
        let report = run_sqlite(&mut ours, &migs, None, &now).unwrap();
        assert_eq!(
            report.applied.len(),
            migs.len(),
            "I1819: every file applied"
        );
        let (h_t, h_o) = (history(&theirs), history(&ours));
        assert_eq!(h_t.len(), h_o.len());
        for (i, (t, o)) in h_t.iter().zip(&h_o).enumerate() {
            let strip = |r: &Row| {
                (
                    r.0,
                    r.1.clone(),
                    r.2.clone(),
                    r.3.clone(),
                    r.5.clone(),
                    r.6.clone(),
                    r.7.clone(),
                )
            };
            assert_eq!(strip(t), strip(o), "I1819: V{} row", t.0);
            assert_eq!(
                o.4,
                format_applied_on(at(i)).unwrap(),
                "I1819: V{} applied_on",
                o.0
            );
            assert!(rfc3339_roundtrips(&t.4), "I1819: refinery's {:?}", t.4);
            assert!(rfc3339_roundtrips(&o.4), "I1819: ours {:?}", o.4);
        }
        assert_eq!(
            schema(&theirs),
            schema(&ours),
            "I1819: the same schema, history DDL included"
        );
    }

    /// **I1951 (sqlite) — the baseline never runs over edition-1 history.**
    /// A store carrying edition 1's history rows (V001..V216, as every
    /// edition-1 store recorded them) refuses with `EditionOneHistory`
    /// naming V216, and nothing is applied or written.
    #[test]
    fn i1951_edition_one_history_refuses_sqlite() {
        let mut c = conn();
        c.execute_batch(&history_table_ddl("refinery_schema_history"))
            .unwrap();
        let rows = super::edition_one_history("sqlite");
        assert!(rows.len() > 190, "I1951: the fixture is edition 1's");
        for (v, n, sum) in &rows {
            c.execute(
                "INSERT INTO refinery_schema_history VALUES (?1, ?2, '2026-01-01T00:00:00Z', ?3)",
                rusqlite::params![v, n, sum],
            )
            .unwrap();
        }
        let (before, objects) = (history(&c), schema(&c));
        let (now, _) = test_clock();
        let err = run_sqlite(&mut c, &sqlite_migrations(), None, &now).unwrap_err();
        assert_eq!(
            err,
            MigrationError::EditionOneHistory { head: 216 },
            "I1951"
        );
        assert_eq!(history(&c), before, "I1951: no row written");
        assert_eq!(schema(&c), objects, "I1951: nothing applied");
    }

    /// **I1821 (sqlite) — an edited checksum, an edited name and a row with
    /// no file each refuse, as refinery does, and apply nothing.** A row
    /// whose checksum is not a `u64` refuses too (refinery panicked).
    #[test]
    fn i1821_divergence_and_missing_refuse_sqlite() {
        let migs = sqlite_migrations();
        let (now, _) = test_clock();
        let v = migs[0].version;
        for (tag, tamper) in [
            ("edited checksum", format!("UPDATE refinery_schema_history SET checksum = '1' WHERE version = {v}")),
            ("edited name", format!("UPDATE refinery_schema_history SET name = 'renamed' WHERE version = {v}")),
            ("row with no file", "INSERT INTO refinery_schema_history VALUES (9999, 'ghost', '2026-01-01T00:00:00Z', '1')".to_owned()),
            ("checksum not a u64", format!("UPDATE refinery_schema_history SET checksum = 'x' WHERE version = {v}")),
        ] {
            let mut c = conn();
            run_sqlite(&mut c, &migs, None, &now).unwrap();
            c.execute_batch(&tamper).unwrap();
            let (rows, objects) = (history(&c), schema(&c));
            let err = run_sqlite(&mut c, &migs, None, &now).unwrap_err();
            eprintln!("I1821 {tag}: {err}");
            let ok = match tag {
                "edited checksum" | "edited name" => {
                    matches!(&err, MigrationError::Divergent { applied, .. } if applied.0 == v)
                }
                "row with no file" => matches!(&err, MigrationError::Missing { version: 9999, .. }),
                _ => matches!(&err, MigrationError::History(_)),
            };
            assert!(ok, "I1821 {tag}: {err:?}");
            assert_eq!(history(&c), rows, "I1821 {tag}: no row written");
            assert_eq!(schema(&c), objects, "I1821 {tag}: nothing applied");
            if tag != "checksum not a u64" {
                let theirs = refinery_sqlite::migrations::runner().run(&mut c).unwrap_err();
                let same = match tag {
                    "edited checksum" | "edited name" => {
                        matches!(theirs.kind(), refinery::error::Kind::DivergentVersion(..))
                    }
                    _ => matches!(theirs.kind(), refinery::error::Kind::MissingVersion(..)),
                };
                assert!(same, "I1821 {tag}: refinery refuses alike: {theirs}");
                assert_eq!(err.to_string(), theirs.to_string(), "I1821 {tag}: refinery's text");
            }
        }
    }
}

#[cfg(all(test, feature = "postgres"))]
mod postgres_witnesses {
    use super::*;

    type Row = (i32, String, String, String);

    async fn history(c: &tokio_postgres::Client) -> Vec<Row> {
        c.query(
            "SELECT version, name, applied_on, checksum FROM ciris_persist_schema_history \
             ORDER BY version",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect()
    }

    async fn column_types(c: &tokio_postgres::Client) -> Vec<(String, String)> {
        c.query(
            "SELECT column_name::text, data_type::text FROM information_schema.columns \
             WHERE table_name = 'ciris_persist_schema_history' ORDER BY ordinal_position",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect()
    }

    /// **I1822 (postgres) — refinery's rows, and the refusals.** refinery
    /// and persist's runner each migrate an empty database: the same rows
    /// (version, name, checksum), the same column types, the injected
    /// instants. An edited checksum then refuses as divergent and a row with
    /// no file as missing, with refinery's text, writing nothing. **I1951
    /// (postgres):** a database carrying edition 1's history refuses with
    /// `EditionOneHistory`, applying nothing.
    #[tokio::test]
    async fn i1822_refinerys_rows_and_refusals_postgres() {
        let (Some(a), Some(b), Some(e1)) = (
            crate::test_pg::empty_dsn(),
            crate::test_pg::empty_dsn(),
            crate::test_pg::empty_dsn(),
        ) else {
            eprintln!("skipping: no test postgres");
            return;
        };
        let migs = postgres_migrations();
        let mut ca = crate::store::postgres::dedicated_connect_to(&a)
            .await
            .unwrap();
        let mut r = refinery_postgres::migrations::runner();
        r.set_migration_table_name(POSTGRES_HISTORY_TABLE);
        r.run_async(&mut ca).await.unwrap();
        let theirs = history(&ca).await;

        let mut cb = crate::store::postgres::dedicated_connect_to(&b)
            .await
            .unwrap();
        let (now_b, at_b) = test_clock();
        run_postgres(&mut cb, &migs, None, &now_b).await.unwrap();
        let ours = history(&cb).await;
        let key = |r: &Row| (r.0, r.1.clone(), r.3.clone());
        assert_eq!(
            ours.iter().map(key).collect::<Vec<_>>(),
            theirs.iter().map(key).collect::<Vec<_>>(),
            "I1822: refinery's version, name and checksum on every row"
        );
        for (i, r) in ours.iter().enumerate() {
            assert_eq!(
                r.2,
                format_applied_on(at_b(i)).unwrap(),
                "I1822: V{} applied_on",
                r.0
            );
        }
        assert_eq!(
            column_types(&cb).await,
            column_types(&ca).await,
            "I1822: column types"
        );
        assert!(run_postgres(&mut cb, &migs, None, &now_b)
            .await
            .unwrap()
            .applied
            .is_empty());

        let v = migs[0].version;
        for (tag, tamper, c) in [
            ("edited checksum", format!("UPDATE ciris_persist_schema_history SET checksum = '1' WHERE version = {v}"), &mut cb),
            ("row with no file", "INSERT INTO ciris_persist_schema_history VALUES (9999, 'ghost', '2026-01-01T00:00:00Z', '1')".to_owned(), &mut ca),
        ] {
            c.batch_execute(&tamper).await.unwrap();
            let rows = history(c).await;
            let err = run_postgres(c, &migs, None, &now_b).await.unwrap_err();
            let mut theirs = refinery_postgres::migrations::runner();
            theirs.set_migration_table_name(POSTGRES_HISTORY_TABLE);
            let theirs = theirs.run_async(c).await.unwrap_err();
            eprintln!("I1822 {tag}: ours {err}; refinery {theirs}");
            let ok = match tag {
                "edited checksum" => matches!(&err, MigrationError::Divergent { applied, .. } if applied.0 == v),
                _ => matches!(&err, MigrationError::Missing { version: 9999, .. }),
            };
            assert!(ok, "I1822 {tag}: {err:?}");
            assert_eq!(err.to_string(), theirs.to_string(), "I1822 {tag}: refinery's text");
            assert_eq!(history(c).await, rows, "I1822 {tag}: no row written");
        }

        let mut c1 = crate::store::postgres::dedicated_connect_to(&e1)
            .await
            .unwrap();
        c1.batch_execute(&history_table_ddl(POSTGRES_HISTORY_TABLE))
            .await
            .unwrap();
        for (ver, n, sum) in super::edition_one_history("postgres") {
            c1.execute(
                "INSERT INTO ciris_persist_schema_history VALUES ($1, $2, '2026-01-01T00:00:00Z', $3)",
                &[&ver, &n, &sum],
            )
            .await
            .unwrap();
        }
        let before = history(&c1).await;
        let err = run_postgres(&mut c1, &migs, None, &now_b)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            MigrationError::EditionOneHistory { head: 216 },
            "I1951 (postgres)"
        );
        assert_eq!(
            history(&c1).await,
            before,
            "I1951 (postgres): no row written"
        );
        let n: i64 = c1
            .query_one(
                "SELECT count(*) FROM pg_namespace WHERE nspname = 'cirislens'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, 0, "I1951 (postgres): nothing applied");
    }
}
