//! The edition-2 statement store: the shape the E2b baseline creates.
//!
//! The tables are E2b's, created in the edition-2 schema baseline
//! (`cirislens.` on postgres). This slice writes and reads against these
//! column names, which stay stable:
//!
//! - `ceg_statements`. One row per voice, keyed by `statement_id`, with an
//!   index on `row_id`. `row_id` is the row id or, for a signed object that
//!   is not a row, the object id. `row_type`, `family`, `sub` and
//!   `asserted_at_ms` are NULL exactly when `typ` is not `ceg-row/2`.
//!   `author` is the identity-ref text, NULL on a counted row. `bytes` is the
//!   statement as received.
//! - `ceg_row_names`. `(row_id, named_row_id, role)`: what each row names,
//!   from its signed `refs`. There is no FK, because a named row may not be
//!   held yet.
//!
//! [`SQLITE_DDL`] / [`POSTGRES_DDL`] are the shape, written here so this
//! slice's tests can stand it up before the baseline merges. I1906 checks
//! the columns against what the baseline creates, once it holds the tables.

use super::door::AdmittedRow;

/// The tables' shape on sqlite (test fixture until the E2b baseline).
pub const SQLITE_DDL: &str = "\
CREATE TABLE IF NOT EXISTS ceg_statements (\
  statement_id BLOB PRIMARY KEY CHECK (length(statement_id) = 32),\
  row_id BLOB NOT NULL CHECK (length(row_id) = 32),\
  typ TEXT NOT NULL,\
  row_type TEXT,\
  family TEXT,\
  kid BLOB NOT NULL CHECK (length(kid) = 32),\
  iss TEXT NOT NULL,\
  sub TEXT,\
  author TEXT,\
  asserted_at_ms INTEGER,\
  bytes BLOB NOT NULL,\
  CHECK ((typ = 'ceg-row/2') = (row_type IS NOT NULL AND family IS NOT NULL AND sub IS NOT \
  NULL AND asserted_at_ms IS NOT NULL))\
);\
CREATE INDEX IF NOT EXISTS ceg_statements_row_id ON ceg_statements (row_id);\
CREATE TABLE IF NOT EXISTS ceg_row_names (\
  row_id BLOB NOT NULL CHECK (length(row_id) = 32),\
  named_row_id BLOB NOT NULL CHECK (length(named_row_id) = 32),\
  role TEXT NOT NULL,\
  PRIMARY KEY (row_id, named_row_id, role)\
);\
CREATE INDEX IF NOT EXISTS ceg_row_names_named ON ceg_row_names (named_row_id, role, row_id);";

/// The tables' shape on postgres (test fixture until the E2b baseline).
pub const POSTGRES_DDL: &str = "\
CREATE TABLE IF NOT EXISTS cirislens.ceg_statements (\
  statement_id BYTEA PRIMARY KEY CHECK (octet_length(statement_id) = 32),\
  row_id BYTEA NOT NULL CHECK (octet_length(row_id) = 32),\
  typ TEXT NOT NULL,\
  row_type TEXT,\
  family TEXT,\
  kid BYTEA NOT NULL CHECK (octet_length(kid) = 32),\
  iss TEXT NOT NULL,\
  sub TEXT,\
  author TEXT,\
  asserted_at_ms BIGINT,\
  bytes BYTEA NOT NULL,\
  CHECK ((typ = 'ceg-row/2') = (row_type IS NOT NULL AND family IS NOT NULL AND sub IS NOT \
  NULL AND asserted_at_ms IS NOT NULL))\
);\
CREATE INDEX IF NOT EXISTS ceg_statements_row_id ON cirislens.ceg_statements (row_id);\
CREATE TABLE IF NOT EXISTS cirislens.ceg_row_names (\
  row_id BYTEA NOT NULL CHECK (octet_length(row_id) = 32),\
  named_row_id BYTEA NOT NULL CHECK (octet_length(named_row_id) = 32),\
  role TEXT NOT NULL,\
  PRIMARY KEY (row_id, named_row_id, role)\
);\
CREATE INDEX IF NOT EXISTS ceg_row_names_named ON cirislens.ceg_row_names (named_row_id, role, row_id);";

/// The `ceg_statements` columns, in [`SQLITE_DDL`]'s order.
pub const STATEMENT_COLUMNS: [&str; 11] = [
    "statement_id",
    "row_id",
    "typ",
    "row_type",
    "family",
    "kid",
    "iss",
    "sub",
    "author",
    "asserted_at_ms",
    "bytes",
];

/// The `ceg_row_names` columns.
pub const NAME_COLUMNS: [&str; 3] = ["row_id", "named_row_id", "role"];

/// The `typ` of a row statement.
pub const ROW_TYP: &str = ciris_verify_core::edition2::ROW_TYP;

/// `asserted_at_ms` as the BIGINT the columns hold. An instant above
/// `i64::MAX` ms is refused at the door rather than wrapped.
///
/// # Errors
/// `edition2_statement_invalid` (`malformed:asserted_at`).
pub fn asserted_at_column(row: &AdmittedRow) -> Result<i64, crate::federation::Error> {
    i64::try_from(row.asserted_at_ms).map_err(|_| {
        crate::federation::Error::malformed_row(
            super::door::PLANE,
            crate::federation::malformed_row::EDITION2_STATEMENT_INVALID,
            "malformed:asserted_at (above i64::MAX ms)",
        )
    })
}

/// sqlite: store an admitted row's statement and its names, idempotently, in
/// the caller's transaction. Returns whether the statement was new.
///
/// # Errors
/// sqlite errors; the door's `asserted_at` bound.
#[cfg(feature = "sqlite")]
pub fn put_row_sqlite(
    tx: &rusqlite::Connection,
    row: &AdmittedRow,
) -> Result<bool, crate::federation::Error> {
    let at = asserted_at_column(row)?;
    let be = |e: rusqlite::Error| crate::federation::Error::Backend(format!("ceg_statements: {e}"));
    let n = tx
        .execute(
            "INSERT OR IGNORE INTO ceg_statements (statement_id, row_id, typ, row_type, family, \
             kid, iss, sub, author, asserted_at_ms, bytes) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, \
             ?8, ?9, ?10, ?11)",
            rusqlite::params![
                &row.statement_id[..],
                &row.row_id.0[..],
                ROW_TYP,
                row.row_type,
                row.family,
                &row.kid[..],
                row.iss,
                row.sub,
                row.author,
                at,
                row.bytes,
            ],
        )
        .map_err(be)?;
    for name in &row.names {
        tx.execute(
            "INSERT OR IGNORE INTO ceg_row_names (row_id, named_row_id, role) VALUES (?1, ?2, ?3)",
            rusqlite::params![&row.row_id.0[..], &name.row.0[..], name.role],
        )
        .map_err(be)?;
    }
    Ok(n == 1)
}

/// sqlite: the held statements of `family` about `sub`, as received.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn statements_about_sqlite(
    conn: &rusqlite::Connection,
    family: &str,
    sub: &str,
) -> Result<Vec<Vec<u8>>, crate::federation::Error> {
    let be = |e: rusqlite::Error| crate::federation::Error::Backend(format!("ceg_statements: {e}"));
    let mut st = conn
        .prepare(
            "SELECT bytes FROM ceg_statements WHERE family = ?1 AND sub = ?2 ORDER BY \
             statement_id",
        )
        .map_err(be)?;
    let rows = st
        .query_map(rusqlite::params![family, sub], |r| r.get::<_, Vec<u8>>(0))
        .map_err(be)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(be)
}

/// sqlite: the rows that name `named` under `role`.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn rows_naming_sqlite(
    conn: &rusqlite::Connection,
    named: &super::names::RowId,
    role: &str,
) -> Result<Vec<super::names::RowId>, crate::federation::Error> {
    let be = |e: rusqlite::Error| crate::federation::Error::Backend(format!("ceg_row_names: {e}"));
    let mut st = conn
        .prepare(
            "SELECT row_id FROM ceg_row_names WHERE named_row_id = ?1 AND role = ?2 ORDER BY \
             row_id",
        )
        .map_err(be)?;
    let rows = st
        .query_map(rusqlite::params![&named.0[..], role], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .map_err(be)?;
    rows.map(|r| {
        let b = r.map_err(be)?;
        <[u8; 32]>::try_from(b.as_slice())
            .map(super::names::RowId)
            .map_err(|_| crate::federation::Error::Backend("ceg_row_names: row_id length".into()))
    })
    .collect()
}

/// postgres: store an admitted row's statement and its names, idempotently.
/// Returns whether the statement was new.
///
/// # Errors
/// postgres errors; the door's `asserted_at` bound.
#[cfg(feature = "postgres")]
pub async fn put_row_postgres<C>(
    client: &C,
    row: &AdmittedRow,
) -> Result<bool, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let at = asserted_at_column(row)?;
    let be = |e: tokio_postgres::Error| {
        crate::federation::Error::Backend(format!("ceg_statements: {e}"))
    };
    let n = client
        .execute(
            "INSERT INTO cirislens.ceg_statements (statement_id, row_id, typ, row_type, family, \
             kid, iss, sub, author, asserted_at_ms, bytes) VALUES ($1, $2, $3, $4, $5, $6, $7, \
             $8, $9, $10, $11) ON CONFLICT (statement_id) DO NOTHING",
            &[
                &&row.statement_id[..],
                &&row.row_id.0[..],
                &ROW_TYP,
                &row.row_type,
                &row.family,
                &&row.kid[..],
                &row.iss,
                &row.sub,
                &row.author,
                &at,
                &row.bytes,
            ],
        )
        .await
        .map_err(be)?;
    for name in &row.names {
        client
            .execute(
                "INSERT INTO cirislens.ceg_row_names (row_id, named_row_id, role) VALUES ($1, $2, \
                 $3) ON CONFLICT DO NOTHING",
                &[&&row.row_id.0[..], &&name.row.0[..], &name.role],
            )
            .await
            .map_err(be)?;
    }
    Ok(n == 1)
}

/// postgres: the held statements of `family` about `sub`, as received.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn statements_about_postgres<C>(
    client: &C,
    family: &str,
    sub: &str,
) -> Result<Vec<Vec<u8>>, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let rows = client
        .query(
            "SELECT bytes FROM cirislens.ceg_statements WHERE family = $1 AND sub = $2 ORDER BY \
             statement_id",
            &[&family, &sub],
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("ceg_statements: {e}")))?;
    Ok(rows.iter().map(|r| r.get::<_, Vec<u8>>(0)).collect())
}

/// postgres: the rows that name `named` under `role`.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn rows_naming_postgres<C>(
    client: &C,
    named: &super::names::RowId,
    role: &str,
) -> Result<Vec<super::names::RowId>, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let rows = client
        .query(
            "SELECT row_id FROM cirislens.ceg_row_names WHERE named_row_id = $1 AND role = $2 \
             ORDER BY row_id",
            &[&&named.0[..], &role],
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("ceg_row_names: {e}")))?;
    rows.iter()
        .map(|r| {
            let b: Vec<u8> = r.get(0);
            <[u8; 32]>::try_from(b.as_slice())
                .map(super::names::RowId)
                .map_err(|_| {
                    crate::federation::Error::Backend("ceg_row_names: row_id length".into())
                })
        })
        .collect()
}

/// sqlite: every held voice (statement) of one row id, as received.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn voices_of_sqlite(
    conn: &rusqlite::Connection,
    row_id: &super::names::RowId,
) -> Result<Vec<Vec<u8>>, crate::federation::Error> {
    let be = |e: rusqlite::Error| crate::federation::Error::Backend(format!("ceg_statements: {e}"));
    let mut st = conn
        .prepare("SELECT bytes FROM ceg_statements WHERE row_id = ?1 ORDER BY statement_id")
        .map_err(be)?;
    let rows = st
        .query_map(rusqlite::params![&row_id.0[..]], |r| r.get::<_, Vec<u8>>(0))
        .map_err(be)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(be)
}

/// postgres: every held voice (statement) of one row id, as received.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn voices_of_postgres<C>(
    client: &C,
    row_id: &super::names::RowId,
) -> Result<Vec<Vec<u8>>, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let rows = client
        .query(
            "SELECT bytes FROM cirislens.ceg_statements WHERE row_id = $1 ORDER BY statement_id",
            &[&&row_id.0[..]],
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("ceg_statements: {e}")))?;
    Ok(rows.iter().map(|r| r.get::<_, Vec<u8>>(0)).collect())
}

/// A verified voice of a signed object that is not a row (a
/// `ceg-genesis-bundle/2` voice), as `ceg_statements` holds it:
/// `row_type`, `family`, `sub` and `asserted_at_ms` NULL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldObject {
    /// The object id (in the `row_id` column).
    pub object_id: super::names::RowId,
    /// This voice's statement id.
    pub statement_id: [u8; 32],
    /// The `typ`.
    pub typ: String,
    /// The signer's kid.
    pub kid: [u8; 32],
    /// The CWT `iss`.
    pub iss: String,
    /// The statement as received.
    pub bytes: Vec<u8>,
}

/// sqlite: store an object voice, idempotently. Returns whether it was new.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn put_object_sqlite(
    conn: &rusqlite::Connection,
    o: &HeldObject,
) -> Result<bool, crate::federation::Error> {
    let n = conn
        .execute(
            "INSERT OR IGNORE INTO ceg_statements (statement_id, row_id, typ, kid, iss, bytes) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                &o.statement_id[..],
                &o.object_id.0[..],
                o.typ,
                &o.kid[..],
                o.iss,
                o.bytes
            ],
        )
        .map_err(|e| crate::federation::Error::Backend(format!("ceg_statements: {e}")))?;
    Ok(n == 1)
}

/// sqlite: every held voice of objects of `typ`, as received.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn objects_of_sqlite(
    conn: &rusqlite::Connection,
    typ: &str,
) -> Result<Vec<Vec<u8>>, crate::federation::Error> {
    let be = |e: rusqlite::Error| crate::federation::Error::Backend(format!("ceg_statements: {e}"));
    let mut st = conn
        .prepare("SELECT bytes FROM ceg_statements WHERE typ = ?1 ORDER BY statement_id")
        .map_err(be)?;
    let rows = st
        .query_map(rusqlite::params![typ], |r| r.get::<_, Vec<u8>>(0))
        .map_err(be)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(be)
}

/// postgres: store an object voice, idempotently. Returns whether it was new.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn put_object_postgres<C>(
    client: &C,
    o: &HeldObject,
) -> Result<bool, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let n = client
        .execute(
            "INSERT INTO cirislens.ceg_statements (statement_id, row_id, typ, kid, iss, bytes) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (statement_id) DO NOTHING",
            &[
                &&o.statement_id[..],
                &&o.object_id.0[..],
                &o.typ,
                &&o.kid[..],
                &o.iss,
                &o.bytes,
            ],
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("ceg_statements: {e}")))?;
    Ok(n == 1)
}

/// postgres: every held voice of objects of `typ`, as received.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn objects_of_postgres<C>(
    client: &C,
    typ: &str,
) -> Result<Vec<Vec<u8>>, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let rows = client
        .query(
            "SELECT bytes FROM cirislens.ceg_statements WHERE typ = $1 ORDER BY statement_id",
            &[&typ],
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("ceg_statements: {e}")))?;
    Ok(rows.iter().map(|r| r.get::<_, Vec<u8>>(0)).collect())
}
