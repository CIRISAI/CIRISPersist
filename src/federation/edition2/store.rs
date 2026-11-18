//! The edition-2 statement store: the shape the E2b baseline creates.
//!
//! The tables are E2b's, created in the edition-2 schema baseline
//! (`cirislens.` on postgres). This module writes and reads against these
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
//! The tables are created by `V300__edition2_baseline` on both dialects
//! (`store::edition_baseline::EDITION_TWO_ADDITIONS`); nothing here creates
//! them. I1906 checks the columns against what the baseline creates.

use super::door::AdmittedRow;

/// The `ceg_statements` columns, in the baseline's order.
pub const STATEMENT_COLUMNS: [&str; 12] = [
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
    "admitted_us",
];

/// The `ceg_row_names` columns.
pub const NAME_COLUMNS: [&str; 3] = ["row_id", "named_row_id", "role"];

/// The `typ` of a row statement.
pub const ROW_TYP: &str = ciris_verify_core::edition2::ROW_TYP;

/// THIS node's next admission position (POSIX µs): the host clock, or one
/// past the last position handed out when the clock is not ahead of it
/// (`monotonic_admission_instant`'s rule at µs). A backward clock step never
/// stamps a statement below one already served.
#[must_use]
pub fn next_admitted_us(now: chrono::DateTime<chrono::Utc>, last: Option<i64>) -> i64 {
    let now = now.timestamp_micros();
    match last {
        Some(l) if l >= now => l.saturating_add(1),
        _ => now,
    }
}

/// Where a reader of [`FederationDirectory::edition2_statements_since`]
/// resumes: the last served statement's admission position and id.
///
/// [`FederationDirectory::edition2_statements_since`]: crate::federation::FederationDirectory::edition2_statements_since
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct StatementCursor {
    /// The admission position, POSIX µs.
    pub admitted_us: i64,
    /// The statement id.
    pub statement_id: [u8; 32],
}

/// One held statement, served as received (CC 2.6.1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServedStatement {
    /// Its position: pass the last one served back as the cursor.
    pub cursor: StatementCursor,
    /// The statement's bytes as received.
    pub bytes: Vec<u8>,
}

/// The most statements one page serves.
pub const MAX_PAGE: u32 = 1000;

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

/// sqlite: the next admission position, read in the caller's write
/// transaction (BEGIN IMMEDIATE serialises it).
#[cfg(feature = "sqlite")]
fn next_admitted_us_sqlite(tx: &rusqlite::Connection) -> Result<i64, rusqlite::Error> {
    let last: Option<i64> =
        tx.query_row("SELECT MAX(admitted_us) FROM ceg_statements", [], |r| {
            r.get(0)
        })?;
    Ok(next_admitted_us(crate::host::clock::now(), last))
}

/// postgres: the next admission position, read in the caller's transaction.
#[cfg(feature = "postgres")]
async fn next_admitted_us_postgres<C>(client: &C) -> Result<i64, tokio_postgres::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let last: Option<i64> = client
        .query_one("SELECT MAX(admitted_us) FROM cirislens.ceg_statements", &[])
        .await?
        .try_get(0)?;
    Ok(next_admitted_us(crate::host::clock::now(), last))
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
    let admitted = next_admitted_us_sqlite(tx).map_err(be)?;
    let n = tx
        .execute(
            "INSERT OR IGNORE INTO ceg_statements (statement_id, row_id, typ, row_type, family, \
             kid, iss, sub, author, asserted_at_ms, bytes, admitted_us) VALUES (?1, ?2, ?3, ?4, \
             ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
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
                admitted,
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
    let admitted = next_admitted_us_postgres(client).await.map_err(be)?;
    let n = client
        .execute(
            "INSERT INTO cirislens.ceg_statements (statement_id, row_id, typ, row_type, family, \
             kid, iss, sub, author, asserted_at_ms, bytes, admitted_us) VALUES ($1, $2, $3, $4, \
             $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT (statement_id) DO NOTHING",
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
                &admitted,
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

/// sqlite: store an object voice, idempotently, in the caller's write
/// transaction. Returns whether it was new.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn put_object_sqlite(
    conn: &rusqlite::Connection,
    o: &HeldObject,
) -> Result<bool, crate::federation::Error> {
    let be = |e: rusqlite::Error| crate::federation::Error::Backend(format!("ceg_statements: {e}"));
    let admitted = next_admitted_us_sqlite(conn).map_err(be)?;
    let n = conn
        .execute(
            "INSERT OR IGNORE INTO ceg_statements (statement_id, row_id, typ, kid, iss, bytes, \
             admitted_us) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                &o.statement_id[..],
                &o.object_id.0[..],
                o.typ,
                &o.kid[..],
                o.iss,
                o.bytes,
                admitted,
            ],
        )
        .map_err(be)?;
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

/// postgres: store an object voice, idempotently, in the caller's
/// transaction. Returns whether it was new.
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
    let be = |e: tokio_postgres::Error| {
        crate::federation::Error::Backend(format!("ceg_statements: {e}"))
    };
    let admitted = next_admitted_us_postgres(client).await.map_err(be)?;
    let n = client
        .execute(
            "INSERT INTO cirislens.ceg_statements (statement_id, row_id, typ, kid, iss, bytes, \
             admitted_us) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (statement_id) DO \
             NOTHING",
            &[
                &&o.statement_id[..],
                &&o.object_id.0[..],
                &o.typ,
                &&o.kid[..],
                &o.iss,
                &o.bytes,
                &admitted,
            ],
        )
        .await
        .map_err(be)?;
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

fn served(
    admitted_us: i64,
    id: &[u8],
    bytes: Vec<u8>,
) -> Result<ServedStatement, crate::federation::Error> {
    let statement_id = <[u8; 32]>::try_from(id).map_err(|_| {
        crate::federation::Error::Backend("ceg_statements: statement_id length".into())
    })?;
    Ok(ServedStatement {
        cursor: StatementCursor {
            admitted_us,
            statement_id,
        },
        bytes,
    })
}

/// sqlite: the held statements after `cursor` (from the first with none), in
/// admission order, at most `limit` (clamped to [`MAX_PAGE`]).
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn statements_since_sqlite(
    conn: &rusqlite::Connection,
    cursor: Option<&StatementCursor>,
    limit: u32,
) -> Result<Vec<ServedStatement>, crate::federation::Error> {
    let be = |e: rusqlite::Error| crate::federation::Error::Backend(format!("ceg_statements: {e}"));
    let limit = i64::from(limit.min(MAX_PAGE));
    let (at, id) = cursor.map_or((i64::MIN, Vec::new()), |c| {
        (c.admitted_us, c.statement_id.to_vec())
    });
    let mut st = conn
        .prepare(
            "SELECT admitted_us, statement_id, bytes FROM ceg_statements \
             WHERE admitted_us > ?1 OR (admitted_us = ?1 AND statement_id > ?2) \
             ORDER BY admitted_us, statement_id LIMIT ?3",
        )
        .map_err(be)?;
    let rows = st
        .query_map(rusqlite::params![at, id, limit], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(be)?;
    rows.map(|r| {
        let (a, id, bytes) = r.map_err(be)?;
        served(a, &id, bytes)
    })
    .collect()
}

/// postgres: the held statements after `cursor` (from the first with none),
/// in admission order, at most `limit` (clamped to [`MAX_PAGE`]).
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn statements_since_postgres<C>(
    client: &C,
    cursor: Option<&StatementCursor>,
    limit: u32,
) -> Result<Vec<ServedStatement>, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let be = |e: tokio_postgres::Error| {
        crate::federation::Error::Backend(format!("ceg_statements: {e}"))
    };
    let limit = i64::from(limit.min(MAX_PAGE));
    let (at, id) = cursor.map_or((i64::MIN, Vec::new()), |c| {
        (c.admitted_us, c.statement_id.to_vec())
    });
    let rows = client
        .query(
            "SELECT admitted_us, statement_id, bytes FROM cirislens.ceg_statements \
             WHERE admitted_us > $1 OR (admitted_us = $1 AND statement_id > $2) \
             ORDER BY admitted_us, statement_id LIMIT $3",
            &[&at, &id, &limit],
        )
        .await
        .map_err(be)?;
    rows.iter()
        .map(|r| {
            let a: i64 = r.try_get(0).map_err(be)?;
            let id: Vec<u8> = r.try_get(1).map_err(be)?;
            let bytes: Vec<u8> = r.try_get(2).map_err(be)?;
            served(a, &id, bytes)
        })
        .collect()
}

// ─── v62.0.0 (JSON-cut slice B) — serving by statement id / row id ─────────

/// The wire-index kind of an edition-2 statement: its hash is the
/// statement id (lowercase hex). `lookup_signed_record_by_content_hash` and
/// `list_wire_hashes_since` serve this kind from `ceg_statements`, the bytes
/// as received (CC 2.6.1.2).
pub const STATEMENT_KIND: &str = "Statement";
/// The lookup kind of an edition-2 row: its hash is the row id (lowercase
/// hex), and the bytes served are the statement that admitted the row.
pub const ROW_KIND: &str = "Row";

/// A 64-hex id as 32 bytes.
#[must_use]
pub fn id_of_hex(hex_id: &str) -> Option<[u8; 32]> {
    if hex_id.len() != 64 || hex_id.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    <[u8; 32]>::try_from(hex::decode(hex_id).ok()?).ok()
}

/// **The edition-2 point read** behind `lookup_signed_record_by_content_hash`:
/// `None` when `kind` is not an edition-2 kind (the caller reads its earlier
/// index), `Some(None)` for an id that is malformed or not held, else the
/// statement's bytes as received.
///
/// # Errors
/// Directory read failures.
pub async fn lookup_by_id<F>(
    dir: &F,
    kind: &str,
    id_hex: &str,
) -> Result<Option<Option<Vec<u8>>>, crate::federation::Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    match kind {
        STATEMENT_KIND => {
            let Some(id) = id_of_hex(id_hex) else {
                return Ok(Some(None));
            };
            let held = dir.edition2_statement(&id).await?;
            Ok(Some(served_anonymously(dir, held).await?))
        }
        ROW_KIND => {
            let Some(id) = id_of_hex(id_hex) else {
                return Ok(Some(None));
            };
            // The statement that admitted the row (its mapped row carries
            // it); a key-plane row, which maps to no typed row, is served by
            // its first voice.
            let held = match dir.get_attestation(id_hex).await? {
                Some(row) => super::emit::carried_statement(&row),
                None => None,
            };
            let held = match held {
                Some(st) => Some(st),
                None => dir
                    .edition2_voices(&super::names::RowId(id))
                    .await?
                    .into_iter()
                    .next(),
            };
            Ok(Some(served_anonymously(dir, held).await?))
        }
        _ => Ok(None),
    }
}

/// The point read and the wire index are anonymous (no requester is named
/// at this surface): a statement is served only when an anonymous read may
/// be served it ([`super::serve::servable_to`] with no requester: the
/// commons, the key plane and signed objects).
async fn served_anonymously<F>(
    dir: &F,
    held: Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>, crate::federation::Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    match held {
        Some(st) if super::serve::servable_to(dir, &st, None).await? => Ok(Some(st)),
        _ => Ok(None),
    }
}

/// **The statement-id wire index, filtered**: [`FederationDirectory::edition2_statement_ids_since`]
/// with each id kept only when an anonymous read may be served its statement.
///
/// [`FederationDirectory::edition2_statement_ids_since`]: crate::federation::FederationDirectory::edition2_statement_ids_since
///
/// # Errors
/// Directory reads.
pub async fn served_statement_ids_since<F>(
    dir: &F,
    after: Option<&[u8; 32]>,
    limit: u32,
) -> Result<Vec<String>, crate::federation::Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    let mut out = Vec::new();
    for id in dir.edition2_statement_ids_since(after, limit).await? {
        let Some(raw) = id_of_hex(&id) else { continue };
        if served_anonymously(dir, dir.edition2_statement(&raw).await?)
            .await?
            .is_some()
        {
            out.push(id);
        }
    }
    Ok(out)
}

/// sqlite: one held statement by its statement id.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn statement_by_id_sqlite(
    conn: &rusqlite::Connection,
    statement_id: &[u8; 32],
) -> Result<Option<Vec<u8>>, crate::federation::Error> {
    use rusqlite::OptionalExtension as _;
    conn.query_row(
        "SELECT bytes FROM ceg_statements WHERE statement_id = ?1",
        rusqlite::params![&statement_id[..]],
        |r| r.get::<_, Vec<u8>>(0),
    )
    .optional()
    .map_err(|e| crate::federation::Error::Backend(format!("ceg_statements: {e}")))
}

/// postgres: one held statement by its statement id.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn statement_by_id_postgres<C>(
    client: &C,
    statement_id: &[u8; 32],
) -> Result<Option<Vec<u8>>, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let be = |e: tokio_postgres::Error| {
        crate::federation::Error::Backend(format!("ceg_statements: {e}"))
    };
    let row = client
        .query_opt(
            "SELECT bytes FROM cirislens.ceg_statements WHERE statement_id = $1",
            &[&&statement_id[..]],
        )
        .await
        .map_err(be)?;
    row.map(|r| r.try_get::<_, Vec<u8>>(0).map_err(be))
        .transpose()
}

/// sqlite: the held statement ids after `after` (lowercase hex, in id
/// order), at most `limit` (clamped to [`MAX_PAGE`]): the statement-id wire
/// index.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn statement_ids_since_sqlite(
    conn: &rusqlite::Connection,
    after: Option<&[u8; 32]>,
    limit: u32,
) -> Result<Vec<String>, crate::federation::Error> {
    let be = |e: rusqlite::Error| crate::federation::Error::Backend(format!("ceg_statements: {e}"));
    let after = after.map_or_else(Vec::new, |a| a.to_vec());
    let mut st = conn
        .prepare(
            "SELECT statement_id FROM ceg_statements WHERE statement_id > ?1 \
             ORDER BY statement_id LIMIT ?2",
        )
        .map_err(be)?;
    let rows = st
        .query_map(
            rusqlite::params![after, i64::from(limit.min(MAX_PAGE))],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .map_err(be)?;
    rows.map(|r| r.map(hex::encode).map_err(be)).collect()
}

/// postgres: [`statement_ids_since_sqlite`].
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn statement_ids_since_postgres<C>(
    client: &C,
    after: Option<&[u8; 32]>,
    limit: u32,
) -> Result<Vec<String>, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let be = |e: tokio_postgres::Error| {
        crate::federation::Error::Backend(format!("ceg_statements: {e}"))
    };
    let after = after.map_or_else(Vec::new, |a| a.to_vec());
    let rows = client
        .query(
            "SELECT statement_id FROM cirislens.ceg_statements WHERE statement_id > $1 \
             ORDER BY statement_id LIMIT $2",
            &[&after, &i64::from(limit.min(MAX_PAGE))],
        )
        .await
        .map_err(be)?;
    rows.iter()
        .map(|r| r.try_get::<_, Vec<u8>>(0).map(hex::encode).map_err(be))
        .collect()
}
