//! v62.0.0 (slice E2b) — **the upgrade deletes the earlier store.**
//!
//! CC 1.0-rc20, "nothing carries, clean mesh": a v62 node reads nothing from
//! an earlier store. On the earlier store (Eric): "No just delete it, we can
//! not store old data indefinitely and no holds exist." A node's storage
//! layout is its own (CC 2.7.9), so edition 2 starts from a fresh baseline
//! ([`crate::store::edition_baseline`]) and an edition-1 store is deleted,
//! never migrated, archived or held.
//!
//! # The flow (one entry point, [`delete_earlier_store`])
//!
//! 1. **Find** what the store is ([`StoreFinding`]): nothing yet (a fresh
//!    store), edition 2 (history at V300+), edition 1 (history 1..=216 that
//!    begins with persist's own V001), or **foreign** (anything persist cannot
//!    prove it created). A foreign store is refused, never touched.
//! 2. **Guard** (CC 4.5.3; C312 "law wins"): an edition-1 store that holds a
//!    live legal hold ([`LEGAL_HOLD_PLANES`]) is refused with
//!    [`EarlierStoreRefusal::LegalHold`] and nothing is deleted. Not expected
//!    to fire. A guard read that fails refuses too: a store is never deleted
//!    on a guard that did not run.
//! 3. **Count** the rows of every plane (table): counts only, never content.
//! 4. **Delete** the earlier store outright. SQLite: the file and its
//!    `-wal` / `-shm` / `-journal`, with no connection open. PostgreSQL: the
//!    five schemas persist owns, `cirislens_pseudonyms` and the history table
//!    in the connection's current schema, in one transaction that ROLLS BACK
//!    if any object outside them changed (a cascade into a host's objects).
//! 5. **Create** a fresh edition-2 store (the baseline) and write the
//!    local-tier record of the deletion (`store_edition_deletions`: the
//!    counts, the earlier head, the instant from the host clock).
//!
//! [`UpgradeMode::DryRun`] runs steps 1–3 and reports, deleting nothing.
//!
//! Every open reaches it: `SqliteBackend::open*` (file paths) before the
//! first connection opens, and `PostgresBackend::run_migrations` inside the
//! migration advisory lock, so the Engine, the PyO3 `Engine(...)` and a
//! consumer opening a backend directly all upgrade the same way.

use std::collections::BTreeMap;

use super::Error;

/// Whether [`delete_earlier_store`] deletes or only reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeMode {
    /// Find, guard and count; delete nothing, create nothing.
    DryRun,
    /// Find, guard, count, delete, create the fresh store, record.
    Delete,
}

/// What a store is, as the upgrade finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreFinding {
    /// Nothing of persist's (and nothing else) is there: a fresh store.
    Absent,
    /// An edition-2 store (history at V300 or above).
    EditionTwo {
        /// The highest applied version.
        head: i32,
    },
    /// An edition-1 store: what deleting it would delete.
    EditionOne(EarlierStore),
    /// Something persist cannot prove it created. Never touched.
    Foreign {
        /// Why.
        detail: String,
    },
}

/// An edition-1 store, counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EarlierStore {
    /// The highest applied edition-1 version.
    pub head: i32,
    /// How many history rows it carries.
    pub migrations: u64,
    /// Rows per plane (table), keyed by name (`schema.table` on PostgreSQL).
    pub plane_counts: BTreeMap<String, u64>,
    /// Every plane's rows, summed.
    pub rows: u64,
    /// Live legal holds per hold plane ([`LEGAL_HOLD_PLANES`]); empty when
    /// the guard passes.
    pub legal_holds: BTreeMap<String, u64>,
}

/// What [`delete_earlier_store`] found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeReport {
    /// The mode it ran in.
    pub mode: UpgradeMode,
    /// What it found.
    pub finding: StoreFinding,
    /// `true` only when an earlier store was deleted and replaced.
    pub deleted: bool,
    /// The instant of the deletion (the host clock), when there was one.
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Why an open refused to delete an earlier store.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EarlierStoreRefusal {
    /// The edition-1 store holds a live legal hold (CC 4.5.3, "law wins").
    #[error(
        "the earlier (edition-1) store holds a live legal hold ({holds}); a v62 node deletes \
         the earlier store at upgrade and will not delete one under a hold. Nothing was deleted. \
         Resolve the hold with counsel, then open again (CC 4.5.3)"
    )]
    LegalHold {
        /// `plane=rows`, comma-separated.
        holds: String,
    },
    /// The store is not one persist can prove it created.
    #[error(
        "refusing to upgrade a store persist did not create: {detail}. Nothing was deleted; \
         point the node at its own store"
    )]
    Foreign {
        /// Why.
        detail: String,
    },
    /// An edition-1 store on a host that cannot delete files (a
    /// `SingleProcess` host: no edition-1 node ran there).
    #[error(
        "an edition-1 store was found on a single-process host, which cannot delete it; \
         nothing was deleted. Remove the store with the host's own tools"
    )]
    SingleProcessHost,
}

impl EarlierStoreRefusal {
    /// The stable token.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::LegalHold { .. } => "store_earlier_store_legal_hold",
            Self::Foreign { .. } => "store_foreign_store",
            Self::SingleProcessHost => "store_earlier_store_single_process_host",
        }
    }
}

/// A plane whose rows are a live legal hold on an edition-1 store.
///
/// - `hard_case_events.kind = 'legal_hold…'` and an attestation subject of
///   dimension `hard_case:legal_hold…`: a recorded `hard_case:legal_hold`.
/// - a community record whose `policy_blob` declares the CC 4.4.3.2.8
///   `legal_hold` limb (carried verbatim in `AffiliationConfig::other`).
/// - a takedown under counter-notice (`counter_noticed`): the law may yet
///   require the content restored.
///
/// A plane whose table (or column) the store does not have holds nothing:
/// that edition-1 version never wrote it.
#[derive(Debug, Clone, Copy)]
pub struct HoldPlane {
    /// The name reported.
    pub name: &'static str,
    /// SQLite table, column, predicate.
    pub sqlite: (&'static str, &'static str, &'static str),
    /// PostgreSQL schema, table, column, predicate.
    pub postgres: (&'static str, &'static str, &'static str, &'static str),
}

/// The closed set of hold planes.
pub const LEGAL_HOLD_PLANES: &[HoldPlane] = &[
    HoldPlane {
        name: "hard_case:legal_hold",
        sqlite: (
            "hard_case_events",
            "kind",
            "substr(kind, 1, 10) = 'legal_hold'",
        ),
        postgres: (
            "cirislens",
            "hard_case_events",
            "kind",
            "left(kind, 10) = 'legal_hold'",
        ),
    },
    HoldPlane {
        name: "attestation:hard_case:legal_hold",
        sqlite: (
            "attestation_subjects",
            "dimension",
            "substr(dimension, 1, 20) = 'hard_case:legal_hold'",
        ),
        postgres: (
            "cirislens",
            "attestation_subjects",
            "dimension",
            "left(dimension, 20) = 'hard_case:legal_hold'",
        ),
    },
    HoldPlane {
        name: "community:legal_hold",
        sqlite: (
            "federation_communities",
            "policy_blob",
            "instr(policy_blob, '\"legal_hold\"') > 0",
        ),
        postgres: (
            "cirislens",
            "federation_communities",
            "policy_blob",
            "strpos(policy_blob::text, '\"legal_hold\"') > 0",
        ),
    },
    HoldPlane {
        name: "takedown:counter_noticed",
        sqlite: (
            "cirisnode_scheduled_takedown_actions",
            "status",
            "status = 'counter_noticed'",
        ),
        postgres: (
            "cirisnode",
            "scheduled_takedown_actions",
            "status",
            "status = 'counter_noticed'",
        ),
    },
];

/// Edition 1's V001, as persist shipped it: `(name, sqlite checksum,
/// postgres checksum)`. A history that does not begin with it is not
/// persist's.
pub(crate) const EDITION_ONE_V001: (&str, u64, u64) = (
    "trace_events",
    2_252_041_362_105_431_945,
    14_517_195_475_708_850_296,
);

/// The target of [`delete_earlier_store`].
#[derive(Debug, Clone, Copy)]
pub enum StoreTarget<'a> {
    /// A SQLite database file (a path, not a `sqlite://` DSN).
    #[cfg(feature = "sqlite")]
    Sqlite(&'a str),
    /// A PostgreSQL DSN.
    #[cfg(feature = "postgres")]
    Postgres(&'a str),
    #[doc(hidden)]
    #[cfg(not(any(feature = "sqlite", feature = "postgres")))]
    _None(std::marker::PhantomData<&'a ()>),
}

/// **The one entry point.** Find the store at `target`; on an edition-1
/// store, guard, count and (in [`UpgradeMode::Delete`]) delete it, create the
/// fresh edition-2 store and record the deletion. A foreign store, or an
/// edition-1 store under a live legal hold, refuses in `Delete` mode
/// ([`Error::EarlierStore`]) and is reported in `DryRun`.
///
/// The open paths call this themselves; a host calls it to dry-run.
pub async fn delete_earlier_store(
    target: StoreTarget<'_>,
    mode: UpgradeMode,
) -> Result<UpgradeReport, Error> {
    match target {
        #[cfg(feature = "sqlite")]
        StoreTarget::Sqlite(path) => {
            let path = path.to_owned();
            crate::host::rt::dispatch_blocking(move || sqlite::upgrade(&path, mode)).await
        }
        #[cfg(feature = "postgres")]
        StoreTarget::Postgres(dsn) => {
            let backend = crate::store::postgres::PostgresBackend::connect(dsn).await?;
            backend.edition_upgrade(mode).await
        }
        #[cfg(not(any(feature = "sqlite", feature = "postgres")))]
        StoreTarget::_None(_) => {
            let _ = mode;
            Err(Error::NotImplemented("delete_earlier_store: no backend"))
        }
    }
}

/// A DSN in the Engine's grammar (`sqlite:///path`, `postgres://…`) as a
/// [`StoreTarget`]; `None` for an in-memory store (never edition 1) or an
/// unknown scheme.
#[must_use]
pub fn target_of_dsn(dsn: &str) -> Option<StoreTarget<'_>> {
    if dsn.starts_with("postgresql://") || dsn.starts_with("postgres://") {
        #[cfg(feature = "postgres")]
        return Some(StoreTarget::Postgres(dsn));
    }
    #[cfg(feature = "sqlite")]
    if dsn.starts_with("sqlite://") {
        let path = dsn
            .strip_prefix("sqlite:///")
            .or_else(|| dsn.strip_prefix("sqlite://"))
            .unwrap_or(dsn);
        if path.is_empty() || path == ":memory:" {
            return None;
        }
        return Some(StoreTarget::Sqlite(path));
    }
    None
}

/// The guard and the foreign check, as `Delete` mode applies them.
pub(crate) fn refusal_of(finding: &StoreFinding) -> Option<EarlierStoreRefusal> {
    match finding {
        StoreFinding::Foreign { detail } => Some(EarlierStoreRefusal::Foreign {
            detail: detail.clone(),
        }),
        StoreFinding::EditionOne(e) if !e.legal_holds.is_empty() => {
            Some(EarlierStoreRefusal::LegalHold {
                holds: e
                    .legal_holds
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(","),
            })
        }
        _ => None,
    }
}

/// Decide a store from its history rows `(version, name, checksum)`;
/// `v001_checksum` is the dialect's pinned edition-1 V001 checksum.
pub(crate) fn classify_history(rows: &[(i32, String, u64)], v001_checksum: u64) -> Classified {
    if rows.is_empty() {
        return Classified::Empty;
    }
    let below = rows
        .iter()
        .filter(|r| r.0 < crate::store::edition_baseline::EDITION_TWO_BASELINE)
        .count();
    let head = rows.iter().map(|r| r.0).max().unwrap_or(0);
    if below == 0 {
        return Classified::EditionTwo { head };
    }
    if below != rows.len() {
        return Classified::Foreign(format!(
            "its history mixes edition-1 versions with edition-2 ones (head V{head})"
        ));
    }
    if head > crate::store::edition_baseline::EDITION_ONE_HEAD {
        return Classified::Foreign(format!(
            "its history reaches V{head}, which edition 1 never shipped"
        ));
    }
    let v001 = rows.iter().find(|r| r.0 == 1);
    match v001 {
        Some((_, name, sum)) if name == EDITION_ONE_V001.0 && *sum == v001_checksum => {
            Classified::EditionOne {
                head,
                migrations: rows.len() as u64,
            }
        }
        _ => Classified::Foreign(
            "its history does not begin with persist's edition-1 V001 (trace_events, its \
             shipped checksum)"
                .to_owned(),
        ),
    }
}

/// [`classify_history`]'s answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Classified {
    Empty,
    EditionTwo { head: i32 },
    EditionOne { head: i32, migrations: u64 },
    Foreign(String),
}

/// The record's `plane_counts` text: a JSON object, keys sorted.
pub(crate) fn plane_counts_json(counts: &BTreeMap<String, u64>) -> String {
    serde_json::to_string(counts).unwrap_or_else(|_| "{}".to_owned())
}

fn log_before_delete(dialect: &str, e: &EarlierStore) {
    tracing::warn!(
        dialect,
        earlier_head = e.head,
        earlier_migrations = e.migrations,
        rows = e.rows,
        planes = e.plane_counts.len(),
        plane_counts = %plane_counts_json(&e.plane_counts),
        "v62 edition upgrade: DELETING the earlier (edition-1) store; nothing carries (CC rc20)"
    );
}

// ── SQLite ────────────────────────────────────────────────────────────────

#[cfg(feature = "sqlite")]
pub(crate) mod sqlite {
    use super::*;
    use rusqlite::{Connection, OpenFlags};

    const HISTORY: &str = "refinery_schema_history";

    /// The sidecar files SQLite may leave beside `path`.
    pub(crate) fn sidecars(path: &str) -> [String; 3] {
        [
            format!("{path}-wal"),
            format!("{path}-shm"),
            format!("{path}-journal"),
        ]
    }

    /// Find what the database at `path` is, reading it (and closing it
    /// before returning). A missing or empty file is `Absent`.
    pub(crate) fn find(path: &str) -> Result<StoreFinding, Error> {
        match std::fs::metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(StoreFinding::Absent),
            Err(e) => return Err(Error::Backend(format!("edition upgrade: stat {path}: {e}"))),
            Ok(m) if m.len() == 0 && !sidecars(path).iter().any(|s| exists(s)) => {
                return Ok(StoreFinding::Absent)
            }
            Ok(_) => {}
        }
        // Read-write without CREATE, then `query_only`: a read-only
        // connection cannot create a WAL store's `-shm` on Apple's SQLite
        // (CIRISPersist#1261), and nothing here writes.
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| Error::Backend(format!("edition upgrade: open {path}: {e}")))?;
        conn.execute_batch("PRAGMA query_only = ON;").map_err(be)?;
        let r = find_on(&conn);
        drop(conn);
        r
    }

    fn exists(p: &str) -> bool {
        std::path::Path::new(p).exists()
    }

    fn be(e: rusqlite::Error) -> Error {
        Error::Backend(format!("edition upgrade (sqlite): {e}"))
    }

    fn tables(conn: &Connection) -> Result<Vec<String>, Error> {
        let mut st = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table' \
                 AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .map_err(be)?;
        let v = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(be)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(be)?;
        Ok(v)
    }

    fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool, Error> {
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM pragma_table_info(?1) WHERE name = ?2",
                rusqlite::params![table, column],
                |r| r.get(0),
            )
            .map_err(be)?;
        Ok(n > 0)
    }

    /// [`find`] on an open connection.
    pub(crate) fn find_on(conn: &Connection) -> Result<StoreFinding, Error> {
        let tables = tables(conn)?;
        if !tables.iter().any(|t| t == HISTORY) {
            return Ok(if tables.is_empty() {
                StoreFinding::Absent
            } else {
                StoreFinding::Foreign {
                    detail: format!(
                        "the database holds {} table(s) and no persist history ({HISTORY})",
                        tables.len()
                    ),
                }
            });
        }
        let rows: Vec<(i32, String, String)> = {
            let mut st = conn
                .prepare(&format!(
                    "SELECT version, name, checksum FROM {HISTORY} ORDER BY version"
                ))
                .map_err(be)?;
            let v = st
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .map_err(be)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(be)?;
            v
        };
        let mut parsed = Vec::with_capacity(rows.len());
        for (v, n, c) in rows {
            let Ok(sum) = c.parse::<u64>() else {
                return Ok(StoreFinding::Foreign {
                    detail: format!("history row V{v} carries no persist checksum"),
                });
            };
            parsed.push((v, n, sum));
        }
        match classify_history(&parsed, EDITION_ONE_V001.1) {
            Classified::Empty => Ok(if tables.len() == 1 {
                StoreFinding::Absent
            } else {
                StoreFinding::Foreign {
                    detail: "the history is empty but the database holds tables".to_owned(),
                }
            }),
            Classified::EditionTwo { head } => Ok(StoreFinding::EditionTwo { head }),
            Classified::Foreign(detail) => Ok(StoreFinding::Foreign { detail }),
            Classified::EditionOne { head, migrations } => {
                let mut plane_counts = BTreeMap::new();
                let mut rows = 0u64;
                for t in tables.iter().filter(|t| *t != HISTORY) {
                    let n: i64 = conn
                        .query_row(&format!("SELECT count(*) FROM \"{t}\""), [], |r| r.get(0))
                        .map_err(be)?;
                    let n = u64::try_from(n).unwrap_or(0);
                    rows += n;
                    plane_counts.insert(t.clone(), n);
                }
                let mut legal_holds = BTreeMap::new();
                for h in LEGAL_HOLD_PLANES {
                    let (table, column, pred) = h.sqlite;
                    if !tables.iter().any(|t| t == table) || !has_column(conn, table, column)? {
                        continue;
                    }
                    let n: i64 = conn
                        .query_row(
                            &format!("SELECT count(*) FROM \"{table}\" WHERE {pred}"),
                            [],
                            |r| r.get(0),
                        )
                        .map_err(be)?;
                    if n > 0 {
                        legal_holds.insert(h.name.to_owned(), u64::try_from(n).unwrap_or(0));
                    }
                }
                Ok(StoreFinding::EditionOne(EarlierStore {
                    head,
                    migrations,
                    plane_counts,
                    rows,
                    legal_holds,
                }))
            }
        }
    }

    /// The SQLite flow. Runs with no connection to `path` open.
    pub(crate) fn upgrade(path: &str, mode: UpgradeMode) -> Result<UpgradeReport, Error> {
        let finding = find(path)?;
        let report = |finding, deleted, deleted_at| UpgradeReport {
            mode,
            finding,
            deleted,
            deleted_at,
        };
        let StoreFinding::EditionOne(earlier) = &finding else {
            if mode == UpgradeMode::Delete {
                if let Some(r) = refusal_of(&finding) {
                    return Err(Error::EarlierStore(r));
                }
            }
            return Ok(report(finding, false, None));
        };
        if mode == UpgradeMode::DryRun {
            return Ok(report(finding, false, None));
        }
        if let Some(r) = refusal_of(&finding) {
            return Err(Error::EarlierStore(r));
        }
        let earlier = earlier.clone();
        log_before_delete("sqlite", &earlier);
        // Delete: the database file and every sidecar. No connection is
        // open (find closed its own), so nothing re-creates them.
        for f in std::iter::once(path.to_owned()).chain(sidecars(path)) {
            match std::fs::remove_file(&f) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(Error::Backend(format!(
                        "edition upgrade: delete {f}: {e} (the earlier store may be partly \
                         deleted; open again to finish)"
                    )))
                }
            }
        }
        let now = crate::host::clock::now();
        create_and_record(path, &earlier, now)?;
        Ok(report(finding, true, Some(now)))
    }

    /// Create the fresh edition-2 store at `path` and write the record.
    fn create_and_record(
        path: &str,
        earlier: &EarlierStore,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Error> {
        let conn = Connection::open(path).map_err(be)?;
        let mut conn = crate::store::sqlite::SqliteBackend::apply_connection_settings(conn)?;
        crate::store::migration_runner::run_sqlite(
            &mut conn,
            &crate::store::migration_runner::sqlite_migrations(),
            None,
            &crate::host::clock::now,
        )
        .map_err(|e| Error::Migration {
            sqlstate: None,
            detail: format!("edition upgrade: the fresh store: {e}"),
        })?;
        record(&conn, earlier, now)
    }

    /// Write the local-tier record of the deletion.
    pub(crate) fn record(
        conn: &Connection,
        earlier: &EarlierStore,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Error> {
        conn.execute(
            "INSERT INTO store_edition_deletions \
             (tier, deleted_at, earlier_edition, earlier_head, earlier_migrations, plane_counts, \
              rows_deleted) VALUES ('local', ?1, 1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                earlier.head,
                i64::try_from(earlier.migrations).unwrap_or(i64::MAX),
                plane_counts_json(&earlier.plane_counts),
                i64::try_from(earlier.rows).unwrap_or(i64::MAX),
            ],
        )
        .map_err(be)?;
        Ok(())
    }

    /// Whether `path` holds an edition-2 record table row count (tests).
    #[cfg(test)]
    pub(crate) fn records(path: &str) -> Vec<(String, i32, i64, String, i64)> {
        let c = Connection::open(path).unwrap();
        let mut st = c
            .prepare(
                "SELECT tier, earlier_head, earlier_migrations, plane_counts, rows_deleted \
                 FROM store_edition_deletions ORDER BY deletion_id",
            )
            .unwrap();
        let v = st
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        v
    }

    /// For the `SingleProcess` open: refuse an edition-1 (or foreign) store
    /// that host cannot delete, read on the open writer.
    pub(crate) fn refuse_on_single_process(conn: &Connection) -> Result<(), Error> {
        match find_on(conn)? {
            StoreFinding::EditionOne(_) => {
                Err(Error::EarlierStore(EarlierStoreRefusal::SingleProcessHost))
            }
            f => match refusal_of(&f) {
                Some(r) => Err(Error::EarlierStore(r)),
                None => Ok(()),
            },
        }
    }
}

// ── PostgreSQL ────────────────────────────────────────────────────────────

#[cfg(feature = "postgres")]
pub(crate) mod postgres {
    use super::*;
    use crate::retention::postgres::PERSIST_SCHEMAS;

    /// The history table (in the connection's current schema).
    const HISTORY: &str = crate::store::migration_runner::POSTGRES_HISTORY_TABLE;
    /// The one persist table edition 1 created unqualified (V010).
    const PSEUDONYMS: &str = "cirislens_pseudonyms";

    fn be(e: tokio_postgres::Error) -> Error {
        Error::Backend(format!(
            "edition upgrade (postgres): {}",
            e.as_db_error()
                .map_or_else(|| e.to_string(), |d| d.to_string())
        ))
    }

    fn schemas_list() -> String {
        PERSIST_SCHEMAS
            .iter()
            .map(|s| format!("'{s}'"))
            .collect::<Vec<_>>()
            .join(",")
    }

    async fn current_schema(c: &tokio_postgres::Client) -> Result<String, Error> {
        let r = c
            .query_one("SELECT current_schema()::text", &[])
            .await
            .map_err(be)?;
        r.try_get::<_, Option<String>>(0)
            .map_err(be)?
            .ok_or_else(|| {
                Error::Backend(
                    "edition upgrade (postgres): the connection has no current schema".into(),
                )
            })
    }

    async fn table_exists(
        c: &tokio_postgres::Client,
        schema: &str,
        table: &str,
    ) -> Result<bool, Error> {
        let r = c
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM pg_class k JOIN pg_namespace n \
                 ON n.oid = k.relnamespace WHERE n.nspname = $1 AND k.relname = $2 \
                 AND k.relkind IN ('r','p'))",
                &[&schema, &table],
            )
            .await
            .map_err(be)?;
        r.try_get(0).map_err(be)
    }

    async fn column_exists(
        c: &tokio_postgres::Client,
        schema: &str,
        table: &str,
        column: &str,
    ) -> Result<bool, Error> {
        let r = c
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
                 WHERE table_schema = $1 AND table_name = $2 AND column_name = $3)",
                &[&schema, &table, &column],
            )
            .await
            .map_err(be)?;
        r.try_get(0).map_err(be)
    }

    fn q(ident: &str) -> String {
        format!("\"{}\"", ident.replace('"', "\"\""))
    }

    /// Find what the database is, from `c` (the migration lock's connection
    /// on the open path).
    pub(crate) async fn find(c: &tokio_postgres::Client) -> Result<StoreFinding, Error> {
        let cs = current_schema(c).await?;
        let present: Vec<String> = c
            .query(
                &format!(
                    "SELECT nspname::text FROM pg_namespace WHERE nspname IN ({}) ORDER BY 1",
                    schemas_list()
                ),
                &[],
            )
            .await
            .map_err(be)?
            .iter()
            .map(|r| r.try_get::<_, String>(0))
            .collect::<Result<_, _>>()
            .map_err(be)?;
        let history = table_exists(c, &cs, HISTORY).await?;
        let pseudonyms = table_exists(c, &cs, PSEUDONYMS).await?;
        if !history {
            if present.is_empty() && !pseudonyms {
                return Ok(StoreFinding::Absent);
            }
            return Ok(StoreFinding::Foreign {
                detail: format!(
                    "persist's names exist here ({}) but this database holds no persist history \
                     ({cs}.{HISTORY}): persist did not create them",
                    present
                        .iter()
                        .cloned()
                        .chain(pseudonyms.then(|| format!("{cs}.{PSEUDONYMS}")))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
        let mut parsed = Vec::new();
        for r in c
            .query(
                &format!(
                    "SELECT version, name, checksum FROM {}.{} ORDER BY version",
                    q(&cs),
                    HISTORY
                ),
                &[],
            )
            .await
            .map_err(be)?
        {
            let v: i32 = r.try_get(0).map_err(be)?;
            let n: Option<String> = r.try_get(1).map_err(be)?;
            let s: Option<String> = r.try_get(2).map_err(be)?;
            let Some(sum) = s.and_then(|s| s.parse::<u64>().ok()) else {
                return Ok(StoreFinding::Foreign {
                    detail: format!("history row V{v} carries no persist checksum"),
                });
            };
            parsed.push((v, n.unwrap_or_default(), sum));
        }
        let (head, migrations) = match classify_history(&parsed, EDITION_ONE_V001.2) {
            Classified::Empty => {
                return Ok(if present.is_empty() && !pseudonyms {
                    StoreFinding::Absent
                } else {
                    StoreFinding::Foreign {
                        detail: "the history is empty but persist's schemas exist".to_owned(),
                    }
                })
            }
            Classified::EditionTwo { head } => return Ok(StoreFinding::EditionTwo { head }),
            Classified::Foreign(detail) => return Ok(StoreFinding::Foreign { detail }),
            Classified::EditionOne { head, migrations } => (head, migrations),
        };
        // Persist created these schemas, and nothing else lives in them.
        if let Some(detail) = foreign_inside(c, &present).await? {
            return Ok(StoreFinding::Foreign { detail });
        }
        let mut plane_counts = BTreeMap::new();
        let mut rows = 0u64;
        let mut planes: Vec<(String, String, String)> = c
            .query(
                &format!(
                    "SELECT n.nspname::text, k.relname::text FROM pg_class k \
                     JOIN pg_namespace n ON n.oid = k.relnamespace \
                     WHERE n.nspname IN ({}) AND k.relkind IN ('r','p') ORDER BY 1, 2",
                    schemas_list()
                ),
                &[],
            )
            .await
            .map_err(be)?
            .iter()
            .map(|r| {
                let (s, t): (String, String) = (r.try_get(0)?, r.try_get(1)?);
                Ok((format!("{s}.{t}"), s, t))
            })
            .collect::<Result<_, tokio_postgres::Error>>()
            .map_err(be)?;
        if pseudonyms {
            planes.push((PSEUDONYMS.to_owned(), cs.clone(), PSEUDONYMS.to_owned()));
        }
        for (key, s, t) in planes {
            let r = c
                .query_one(&format!("SELECT count(*) FROM {}.{}", q(&s), q(&t)), &[])
                .await
                .map_err(be)?;
            let n = u64::try_from(r.try_get::<_, i64>(0).map_err(be)?).unwrap_or(0);
            rows += n;
            plane_counts.insert(key, n);
        }
        let mut legal_holds = BTreeMap::new();
        for h in LEGAL_HOLD_PLANES {
            let (schema, table, column, pred) = h.postgres;
            if !table_exists(c, schema, table).await?
                || !column_exists(c, schema, table, column).await?
            {
                continue;
            }
            let r = c
                .query_one(
                    &format!(
                        "SELECT count(*) FROM {}.{} WHERE {pred}",
                        q(schema),
                        q(table)
                    ),
                    &[],
                )
                .await
                .map_err(be)?;
            let n: i64 = r.try_get(0).map_err(be)?;
            if n > 0 {
                legal_holds.insert(h.name.to_owned(), u64::try_from(n).unwrap_or(0));
            }
        }
        Ok(StoreFinding::EditionOne(EarlierStore {
            head,
            migrations,
            plane_counts,
            rows,
            legal_holds,
        }))
    }

    /// Something in persist's schemas persist did not create: a schema it
    /// does not own, a relation edition 1 never made, a sequence no table of
    /// its owns, a function or a standalone type.
    async fn foreign_inside(
        c: &tokio_postgres::Client,
        present: &[String],
    ) -> Result<Option<String>, Error> {
        if present.is_empty() {
            return Ok(None);
        }
        let not_owned: Vec<String> = c
            .query(
                &format!(
                    "SELECT nspname::text FROM pg_namespace WHERE nspname IN ({}) \
                     AND nspowner <> (SELECT oid FROM pg_roles WHERE rolname = current_user)",
                    schemas_list()
                ),
                &[],
            )
            .await
            .map_err(be)?
            .iter()
            .map(|r| r.try_get::<_, String>(0))
            .collect::<Result<_, _>>()
            .map_err(be)?;
        if !not_owned.is_empty() {
            return Ok(Some(format!(
                "schema(s) {} are not owned by this connection's role",
                not_owned.join(", ")
            )));
        }
        let rels: Vec<(String, String, String)> = c
            .query(
                &format!(
                    "SELECT n.nspname::text, k.relname::text, k.relkind::text FROM pg_class k \
                     JOIN pg_namespace n ON n.oid = k.relnamespace \
                     WHERE n.nspname IN ({}) AND k.relkind IN ('r','p','v','m','f','c')",
                    schemas_list()
                ),
                &[],
            )
            .await
            .map_err(be)?
            .iter()
            .map(|r| Ok((r.try_get(0)?, r.try_get(1)?, r.try_get(2)?)))
            .collect::<Result<_, tokio_postgres::Error>>()
            .map_err(be)?;
        for (s, t, k) in &rels {
            let ours = k == "r"
                && EDITION_ONE_PG_RELATIONS
                    .iter()
                    .any(|(es, et)| es == s && et == t);
            if !ours {
                return Ok(Some(format!(
                    "{s}.{t} (relkind {k}) is not a relation persist's edition 1 created"
                )));
            }
        }
        let loose_seq: Vec<String> = c
            .query(
                &format!(
                    "SELECT n.nspname::text || '.' || k.relname::text FROM pg_class k \
                     JOIN pg_namespace n ON n.oid = k.relnamespace \
                     WHERE n.nspname IN ({}) AND k.relkind = 'S' AND NOT EXISTS ( \
                       SELECT 1 FROM pg_depend d JOIN pg_class o ON o.oid = d.refobjid \
                       JOIN pg_namespace on2 ON on2.oid = o.relnamespace \
                       WHERE d.classid = 'pg_class'::regclass AND d.objid = k.oid \
                       AND d.refclassid = 'pg_class'::regclass AND d.deptype IN ('a','i') \
                       AND on2.nspname IN ({}))",
                    schemas_list(),
                    schemas_list()
                ),
                &[],
            )
            .await
            .map_err(be)?
            .iter()
            .map(|r| r.try_get::<_, String>(0))
            .collect::<Result<_, _>>()
            .map_err(be)?;
        if let Some(s) = loose_seq.first() {
            return Ok(Some(format!("sequence {s} belongs to no persist table")));
        }
        let r = c
            .query_one(
                &format!(
                    "SELECT (SELECT count(*) FROM pg_proc p JOIN pg_namespace n \
                       ON n.oid = p.pronamespace WHERE n.nspname IN ({0})) + \
                     (SELECT count(*) FROM pg_type t JOIN pg_namespace n \
                       ON n.oid = t.typnamespace WHERE n.nspname IN ({0}) \
                       AND t.typtype IN ('e','d','r','m'))",
                    schemas_list()
                ),
                &[],
            )
            .await
            .map_err(be)?;
        let n: i64 = r.try_get(0).map_err(be)?;
        if n > 0 {
            return Ok(Some(format!(
                "{n} function(s) or type(s) live in persist's schemas; edition 1 created none"
            )));
        }
        Ok(None)
    }

    /// Everything a cascade could reach outside persist's footprint, as one
    /// fingerprint: classes, constraints, triggers, rules and functions
    /// outside persist's schemas (and outside the two tables persist keeps in
    /// the current schema, with their indexes and constraints).
    const OUTSIDE_FINGERPRINT: &str = "WITH mine AS ( \
          SELECT k.oid FROM pg_class k JOIN pg_namespace n ON n.oid = k.relnamespace \
          WHERE n.nspname = current_schema() AND k.relname IN ($1, $2) \
          UNION SELECT i.indexrelid FROM pg_index i JOIN pg_class k ON k.oid = i.indrelid \
          JOIN pg_namespace n ON n.oid = k.relnamespace \
          WHERE n.nspname = current_schema() AND k.relname IN ($1, $2) \
          UNION SELECT k.reltoastrelid FROM pg_class k JOIN pg_namespace n \
          ON n.oid = k.relnamespace WHERE n.nspname = current_schema() \
          AND k.relname IN ($1, $2) AND k.reltoastrelid <> 0), \
        skip AS (SELECT oid FROM pg_namespace WHERE nspname = ANY($3) \
          OR nspname IN ('pg_toast','pg_catalog','information_schema') \
          OR nspname LIKE 'pg_temp_%' OR nspname LIKE 'pg_toast_temp_%') \
        SELECT md5(coalesce(( \
          SELECT string_agg(x, ',' ORDER BY x) FROM ( \
            SELECT 'c' || k.oid::text AS x FROM pg_class k WHERE k.relnamespace NOT IN \
              (SELECT oid FROM skip) AND k.oid NOT IN (SELECT oid FROM mine) \
            UNION ALL SELECT 'k' || o.oid::text FROM pg_constraint o \
              WHERE o.connamespace NOT IN (SELECT oid FROM skip) \
              AND o.conrelid NOT IN (SELECT oid FROM mine) \
            UNION ALL SELECT 't' || g.oid::text FROM pg_trigger g JOIN pg_class k \
              ON k.oid = g.tgrelid WHERE k.relnamespace NOT IN (SELECT oid FROM skip) \
              AND k.oid NOT IN (SELECT oid FROM mine) \
            UNION ALL SELECT 'r' || w.oid::text FROM pg_rewrite w JOIN pg_class k \
              ON k.oid = w.ev_class WHERE k.relnamespace NOT IN (SELECT oid FROM skip) \
            UNION ALL SELECT 'p' || p.oid::text FROM pg_proc p \
              WHERE p.pronamespace NOT IN (SELECT oid FROM skip) \
            UNION ALL SELECT 'y' || t.oid::text FROM pg_type t \
              WHERE t.typnamespace NOT IN (SELECT oid FROM skip) \
              AND t.typrelid NOT IN (SELECT oid FROM mine) \
              AND NOT EXISTS (SELECT 1 FROM pg_type e WHERE e.oid = t.typelem \
                AND e.typrelid IN (SELECT oid FROM mine)) \
          ) s), ''))";

    async fn fingerprint(
        tx: &tokio_postgres::Transaction<'_>,
        schemas: &[String],
    ) -> Result<String, Error> {
        let r = tx
            .query_one(OUTSIDE_FINGERPRINT, &[&PSEUDONYMS, &HISTORY, &schemas])
            .await
            .map_err(be)?;
        r.try_get::<_, String>(0).map_err(be)
    }

    /// Delete the earlier store: one transaction that drops persist's
    /// schemas, `cirislens_pseudonyms` and the history table, and ROLLS BACK
    /// when the fingerprint of everything outside them changed.
    pub(crate) async fn delete(c: &mut tokio_postgres::Client) -> Result<(), Error> {
        let schemas: Vec<String> = PERSIST_SCHEMAS.iter().map(|s| (*s).to_owned()).collect();
        let tx = c.transaction().await.map_err(be)?;
        let before = fingerprint(&tx, &schemas).await?;
        let present: Vec<String> = tx
            .query(
                "SELECT nspname::text FROM pg_namespace WHERE nspname = ANY($1) ORDER BY 1",
                &[&schemas],
            )
            .await
            .map_err(be)?
            .iter()
            .map(|r| r.try_get::<_, String>(0))
            .collect::<Result<_, _>>()
            .map_err(be)?;
        let cs = {
            let r = tx
                .query_one("SELECT current_schema()::text", &[])
                .await
                .map_err(be)?;
            r.try_get::<_, String>(0).map_err(be)?
        };
        let mut sql = String::new();
        if !present.is_empty() {
            sql.push_str(&format!(
                "DROP SCHEMA {} CASCADE; ",
                present.iter().map(|s| q(s)).collect::<Vec<_>>().join(", ")
            ));
        }
        sql.push_str(&format!(
            "DROP TABLE IF EXISTS {cs}.{PSEUDONYMS}; DROP TABLE {cs}.{HISTORY};",
            cs = q(&cs)
        ));
        tx.batch_execute(&sql).await.map_err(be)?;
        let after = fingerprint(&tx, &schemas).await?;
        if before != after {
            tx.rollback().await.map_err(be)?;
            return Err(Error::EarlierStore(EarlierStoreRefusal::Foreign {
                detail: "deleting persist's schemas would also change objects outside them (a \
                         host object depends on persist's); rolled back"
                    .to_owned(),
            }));
        }
        tx.commit().await.map_err(be)?;
        Ok(())
    }

    /// The PostgreSQL flow, on the migration lock's connection: find, then
    /// (in `Delete` mode) refuse or delete. Returns the report and, when a
    /// store was deleted, what to record once the baseline has run.
    pub(crate) async fn upgrade_locked(
        c: &mut tokio_postgres::Client,
        mode: UpgradeMode,
    ) -> Result<(UpgradeReport, Option<EarlierStore>), Error> {
        let finding = find(c).await?;
        let report = |finding, deleted, deleted_at| UpgradeReport {
            mode,
            finding,
            deleted,
            deleted_at,
        };
        if mode == UpgradeMode::DryRun {
            return Ok((report(finding, false, None), None));
        }
        if let Some(r) = refusal_of(&finding) {
            return Err(Error::EarlierStore(r));
        }
        let StoreFinding::EditionOne(earlier) = &finding else {
            return Ok((report(finding, false, None), None));
        };
        let earlier = earlier.clone();
        announce(&earlier);
        delete(c).await?;
        let now = crate::host::clock::now();
        Ok((report(finding, true, Some(now)), Some(earlier)))
    }

    /// Write the local-tier record of the deletion (after the baseline).
    pub(crate) async fn record(
        c: &tokio_postgres::Client,
        earlier: &EarlierStore,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Error> {
        c.execute(
            "INSERT INTO cirislens.store_edition_deletions \
             (tier, deleted_at, earlier_edition, earlier_head, earlier_migrations, plane_counts, \
              rows_deleted) VALUES ('local', $1, 1, $2, $3, $4, $5)",
            &[
                &now,
                &earlier.head,
                &i32::try_from(earlier.migrations).unwrap_or(i32::MAX),
                &plane_counts_json(&earlier.plane_counts),
                &i64::try_from(earlier.rows).unwrap_or(i64::MAX),
            ],
        )
        .await
        .map_err(be)?;
        Ok(())
    }

    /// Log the deletion about to happen.
    pub(crate) fn announce(e: &EarlierStore) {
        log_before_delete("postgres", e);
    }

    /// Every ordinary table persist's edition 1 ever created on PostgreSQL
    /// (at any version V001..V216, including those a later version dropped),
    /// by `(schema, table)`. Frozen: edition 1 is closed. Read from a stepwise
    /// V001..V216 run (one migration at a time, the relations after each).
    pub(crate) const EDITION_ONE_PG_RELATIONS: &[(&str, &str)] = &[
        ("cirisgraph", "consolidation_locks"),
        ("cirisgraph", "edges"),
        ("cirisgraph", "nodes"),
        ("cirisgraph", "telemetry_metrics"),
        ("cirislens", "accord_active_halt"),
        ("cirislens", "accord_decision"),
        ("cirislens", "accord_issued_nonce"),
        ("cirislens", "accord_participation"),
        ("cirislens", "accord_proposal"),
        ("cirislens", "accord_proposal_nonce_claim"),
        ("cirislens", "accord_public_keys"),
        ("cirislens", "announced_peers"),
        ("cirislens", "attestation_subjects"),
        ("cirislens", "audit_archives"),
        ("cirislens", "audit_log"),
        ("cirislens", "blackhole_rules"),
        ("cirislens", "blob_renditions"),
        ("cirislens", "canonical_role_withdrawal"),
        ("cirislens", "cirisnode_consent_sla_watch"),
        ("cirislens", "cirisnode_revocation_promotion_watch"),
        ("cirislens", "consent_peer_set"),
        ("cirislens", "consent_peer_set_for"),
        ("cirislens", "content_aggregation"),
        ("cirislens", "content_manifest"),
        ("cirislens", "content_symbols"),
        ("cirislens", "continuity_awareness"),
        ("cirislens", "creation_ceremonies"),
        ("cirislens", "dag_link_backfill_cursor"),
        ("cirislens", "deferral_reports"),
        ("cirislens", "edge_detection_events"),
        ("cirislens", "edge_outbound_queue"),
        ("cirislens", "federation_attestations"),
        ("cirislens", "federation_attestations_form_refused"),
        ("cirislens", "federation_blob_associations"),
        ("cirislens", "federation_blob_key_grants"),
        ("cirislens", "federation_blobs"),
        ("cirislens", "federation_communities"),
        ("cirislens", "federation_community_blob_epoch"),
        ("cirislens", "federation_community_dek"),
        ("cirislens", "federation_community_dek_epoch"),
        ("cirislens", "federation_community_dek_member_grants"),
        ("cirislens", "federation_community_membership_listings"),
        ("cirislens", "federation_community_membership_revocations"),
        ("cirislens", "federation_community_membership_widenings"),
        ("cirislens", "federation_content_kem_identity"),
        ("cirislens", "federation_content_master"),
        ("cirislens", "federation_cosign_aliases"),
        ("cirislens", "federation_cosign_pending"),
        ("cirislens", "federation_cosign_signatures"),
        ("cirislens", "federation_dag_chunks"),
        ("cirislens", "federation_families"),
        ("cirislens", "federation_family_membership_revocations"),
        ("cirislens", "federation_family_membership_widenings"),
        ("cirislens", "federation_group_versions"),
        ("cirislens", "federation_identity_occurrence_history"),
        ("cirislens", "federation_identity_occurrence_revocations"),
        ("cirislens", "federation_identity_occurrences"),
        ("cirislens", "federation_key_grant_pending"),
        ("cirislens", "federation_key_registration_history"),
        ("cirislens", "federation_keys"),
        ("cirislens", "federation_lineage_head_cosigns"),
        ("cirislens", "federation_location_proofs"),
        ("cirislens", "federation_manifest_children"),
        ("cirislens", "federation_org_memberships"),
        ("cirislens", "federation_organizations"),
        ("cirislens", "federation_partner_records"),
        ("cirislens", "federation_peer_metadata"),
        ("cirislens", "federation_revocation_quorum_state"),
        ("cirislens", "federation_revocations"),
        ("cirislens", "federation_role_withdrawals"),
        ("cirislens", "federation_scope_blobs"),
        ("cirislens", "federation_self_roster_proposals"),
        ("cirislens", "federation_stream_chunks"),
        ("cirislens", "federation_stream_dek_grants"),
        ("cirislens", "federation_stream_deks"),
        ("cirislens", "federation_stream_delivery_receipts"),
        ("cirislens", "federation_stream_epoch_counts"),
        ("cirislens", "federation_stream_sth"),
        ("cirislens", "federation_streams"),
        ("cirislens", "federation_trust_direction_held"),
        ("cirislens", "federation_trust_grants"),
        ("cirislens", "federation_vote_windows"),
        ("cirislens", "federation_withdraws_admission_depths"),
        ("cirislens", "feedback_mappings"),
        ("cirislens", "freshness_floor"),
        ("cirislens", "goals"),
        ("cirislens", "hard_case_events"),
        ("cirislens", "identity_canonical_binding"),
        ("cirislens", "identity_sequences"),
        ("cirislens", "incident_records"),
        ("cirislens", "key_escrows"),
        ("cirislens", "known_wire_hashes"),
        ("cirislens", "ledger_checkpoints"),
        ("cirislens", "ledger_entry_ranges"),
        ("cirislens", "ledger_fork_evidence"),
        ("cirislens", "ledger_heads"),
        ("cirislens", "maintenance_locks"),
        ("cirislens", "merkle_leaves"),
        ("cirislens", "merkle_sth_log"),
        ("cirislens", "occurrence_registry"),
        ("cirislens", "purge_executions"),
        ("cirislens", "purge_tombstones"),
        ("cirislens", "retention_policies"),
        ("cirislens", "revoked_service_tokens"),
        ("cirislens", "scheduled_tasks"),
        ("cirislens", "service_correlations"),
        ("cirislens", "shared_instance_leases"),
        ("cirislens", "signed_wire_index"),
        ("cirislens", "storage_budget_installed"),
        ("cirislens", "tasks"),
        ("cirislens", "thoughts"),
        ("cirislens", "tickets"),
        ("cirislens", "trace_events"),
        ("cirislens", "trace_events_factor_rollup_1h"),
        ("cirislens", "trace_events_factor_rollup_meta"),
        ("cirislens", "trace_llm_calls"),
        ("cirislens", "trace_thought_signatures"),
        ("cirislens", "transport_destinations"),
        ("cirislens", "wa_cert"),
        ("cirislens", "wholeness_witness_corpus"),
        ("cirislens_derived", "calibration_bundles"),
        ("cirislens_derived", "detection_events"),
        ("cirislens_secrets", "access_log"),
        ("cirislens_secrets", "filter_config"),
        ("cirislens_secrets", "master_key_meta"),
        ("cirislens_secrets", "secrets"),
        ("cirisnode", "contributions"),
        ("cirisnode", "credits_ledger"),
        ("cirisnode", "expertise_ledger"),
        ("cirisnode", "federation_delivery_attestations"),
        ("cirisnode", "moderation_events"),
        ("cirisnode", "promotion_attestations"),
        ("cirisnode", "reconsideration_attestations"),
        ("cirisnode", "reconsideration_requests"),
        ("cirisnode", "scheduled_takedown_actions"),
        ("cirisnode", "slashing_attestations"),
        ("cirisnode", "votes"),
    ];
}
