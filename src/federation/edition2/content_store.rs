//! v62.0.0 (CONTENT-A6; V300 per P/CONTENT-V300.rev3.sql) — **the stored
//! side of the room-content rule**, both dialects:
//!
//! - `ceg_content_ends` + `ceg_content_end_tips`: every held end of a seat
//!   (`removal`, `resignation`) and every `keeps` row, RETAINED with its
//!   head, class, cited end and tips. Written at the statement's admission
//!   ([`retain_sqlite`] / [`retain_postgres`], from `store::put_row_*`);
//!   insert-only; never deleted by a purge, a tombstone or a checkpoint
//!   (CC rc22 3.1.3.2: "a store keeps an end's tips through a purge").
//!   Whether a retained end COUNTS is read at use (the row's verdict), so a
//!   held, short removal is retained and never handed to the crate.
//! - `ceg_content_answers`: the CACHE of `ciris_kernel::content` answers per
//!   (room, member): replaced whole by each refresh (`content_cache`).

#![cfg_attr(
    not(any(feature = "sqlite", feature = "postgres")),
    allow(unused_imports, dead_code)
)]

use super::door::AdmittedRow;
use super::names::{single, RowId};
use ciris_verify_core::cde::Value;

/// One retained end or `keeps` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedEnd {
    /// The end's (or keeps row's) row id.
    pub source: RowId,
    /// `removal`, `resignation` or `keeps`.
    pub kind: String,
    /// A counted row (a removal; a counted keeps row).
    pub counted: bool,
    /// `refs.head`.
    pub head: RowId,
    /// A keeps row's cited end.
    pub extends: Option<RowId>,
    /// `refs.trusted_through`.
    pub tips: Vec<RowId>,
}

/// One cached answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedAnswer {
    /// The content row.
    pub row: RowId,
    /// Counted at its own head.
    pub counted: bool,
    /// In the room's content now.
    pub in_force: bool,
    /// The crate's rule name, or `undecided`.
    pub rule: String,
    /// The row the crate needs held to decide.
    pub undecided_on: Option<RowId>,
}

/// The retained record of an admitted end / keeps row: `(group_kind, group,
/// member, record)`, or `None`.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
fn retained_of(row: &AdmittedRow) -> Option<(String, String, String, RetainedEnd)> {
    use super::group::{KEEPS_LEAF, MEMBERSHIP_PREFIX, REMOVAL_LEAF, RESIGNATION_LEAF};
    if super::emit::names_a_target(&row.row_type)
        || row.family != ciris_verify_core::namespace_match::family_id(MEMBERSHIP_PREFIX)
    {
        return None;
    }
    let leaf = super::payloads::leaf_of(MEMBERSHIP_PREFIX, &row.payload)?;
    if leaf != REMOVAL_LEAF && leaf != RESIGNATION_LEAF && leaf != KEEPS_LEAF {
        return None;
    }
    let text = |k: &str| {
        row.payload
            .get_text(k)
            .and_then(Value::as_text)
            .map(str::to_owned)
    };
    let head = single(&row.names, "head")?;
    let extends = single(&row.names, "also:cites");
    if leaf == KEEPS_LEAF && extends.is_none() {
        return None;
    }
    let tips = row
        .names
        .iter()
        .filter(|n| n.role == "trusted_through")
        .map(|n| n.row)
        .collect();
    let counted = leaf == REMOVAL_LEAF || (leaf == KEEPS_LEAF && row.author.is_none());
    Some((
        text("group_kind")?,
        text("group")?,
        text("member")?,
        RetainedEnd {
            source: row.row_id,
            kind: leaf.to_owned(),
            counted,
            head,
            extends: if leaf == KEEPS_LEAF { extends } else { None },
            tips,
        },
    ))
}

/// sqlite: retain an admitted end / keeps row (insert-only).
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn retain_sqlite(tx: &rusqlite::Connection, row: &AdmittedRow) -> Result<(), rusqlite::Error> {
    let Some((kind, group, member, e)) = retained_of(row) else {
        return Ok(());
    };
    tx.execute(
        "INSERT OR IGNORE INTO ceg_content_ends (source_row_id, room_scope, room_target, member, \
         source_kind, counted, head_row_id, extends_row_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            &e.source.0[..],
            kind,
            group,
            member,
            e.kind,
            i64::from(e.counted),
            &e.head.0[..],
            e.extends.map(|x| x.0.to_vec()),
        ],
    )?;
    for t in &e.tips {
        tx.execute(
            "INSERT OR IGNORE INTO ceg_content_end_tips (source_row_id, tip_row_id) VALUES (?1, ?2)",
            rusqlite::params![&e.source.0[..], &t.0[..]],
        )?;
    }
    Ok(())
}

/// postgres: [`retain_sqlite`].
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn retain_postgres<C>(client: &C, row: &AdmittedRow) -> Result<(), tokio_postgres::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let Some((kind, group, member, e)) = retained_of(row) else {
        return Ok(());
    };
    let extends: Option<Vec<u8>> = e.extends.map(|x| x.0.to_vec());
    client
        .execute(
            "INSERT INTO cirislens.ceg_content_ends (source_row_id, room_scope, room_target, \
             member, source_kind, counted, head_row_id, extends_row_id) VALUES ($1, $2, $3, $4, \
             $5, $6, $7, $8) ON CONFLICT DO NOTHING",
            &[
                &&e.source.0[..],
                &kind,
                &group,
                &member,
                &e.kind,
                &e.counted,
                &&e.head.0[..],
                &extends,
            ],
        )
        .await?;
    for t in &e.tips {
        client
            .execute(
                "INSERT INTO cirislens.ceg_content_end_tips (source_row_id, tip_row_id) VALUES \
                 ($1, $2) ON CONFLICT DO NOTHING",
                &[&&e.source.0[..], &&t.0[..]],
            )
            .await?;
    }
    Ok(())
}

fn id_of(b: &[u8]) -> Result<RowId, crate::federation::Error> {
    <[u8; 32]>::try_from(b)
        .map(RowId)
        .map_err(|_| crate::federation::Error::Backend("ceg_content: row id length".into()))
}

/// sqlite: the retained ends and keeps rows of `member` in `group`.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn ends_sqlite(
    conn: &rusqlite::Connection,
    group_kind: &str,
    group: &str,
    member: &str,
) -> Result<Vec<RetainedEnd>, crate::federation::Error> {
    let be =
        |e: rusqlite::Error| crate::federation::Error::Backend(format!("ceg_content_ends: {e}"));
    let mut st = conn
        .prepare(
            "SELECT source_row_id, source_kind, counted, head_row_id, extends_row_id FROM \
             ceg_content_ends WHERE room_scope = ?1 AND room_target = ?2 AND member = ?3 ORDER BY \
             source_row_id",
        )
        .map_err(be)?;
    let rows = st
        .query_map(rusqlite::params![group_kind, group, member], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Option<Vec<u8>>>(4)?,
            ))
        })
        .map_err(be)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(be)?;
    let mut tips_q = conn
        .prepare("SELECT tip_row_id FROM ceg_content_end_tips WHERE source_row_id = ?1 ORDER BY tip_row_id")
        .map_err(be)?;
    let mut out = Vec::new();
    for (s, kind, counted, head, extends) in rows {
        let tips = tips_q
            .query_map(rusqlite::params![&s], |r| r.get::<_, Vec<u8>>(0))
            .map_err(be)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(be)?;
        out.push(RetainedEnd {
            source: id_of(&s)?,
            kind,
            counted: counted != 0,
            head: id_of(&head)?,
            extends: extends.as_deref().map(id_of).transpose()?,
            tips: tips.iter().map(|t| id_of(t)).collect::<Result<_, _>>()?,
        });
    }
    Ok(out)
}

/// postgres: [`ends_sqlite`].
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn ends_postgres<C>(
    client: &C,
    group_kind: &str,
    group: &str,
    member: &str,
) -> Result<Vec<RetainedEnd>, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let be = |e: tokio_postgres::Error| {
        crate::federation::Error::Backend(format!("ceg_content_ends: {e}"))
    };
    let rows = client
        .query(
            "SELECT source_row_id, source_kind, counted, head_row_id, extends_row_id FROM \
             cirislens.ceg_content_ends WHERE room_scope = $1 AND room_target = $2 AND member = \
             $3 ORDER BY source_row_id",
            &[&group_kind, &group, &member],
        )
        .await
        .map_err(be)?;
    let mut out = Vec::new();
    for r in rows {
        let s: Vec<u8> = r.get(0);
        let extends: Option<Vec<u8>> = r.get(4);
        let head: Vec<u8> = r.get(3);
        let tips = client
            .query(
                "SELECT tip_row_id FROM cirislens.ceg_content_end_tips WHERE source_row_id = $1 \
                 ORDER BY tip_row_id",
                &[&s],
            )
            .await
            .map_err(be)?;
        out.push(RetainedEnd {
            source: id_of(&s)?,
            kind: r.get(1),
            counted: r.get(2),
            head: id_of(&head)?,
            extends: extends.as_deref().map(id_of).transpose()?,
            tips: tips
                .iter()
                .map(|t| id_of(&t.get::<_, Vec<u8>>(0)))
                .collect::<Result<_, _>>()?,
        });
    }
    Ok(out)
}

/// sqlite: replace the cached answers of `member` in (`scope`, `target`).
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn put_answers_sqlite(
    conn: &mut rusqlite::Connection,
    scope: &str,
    target: &str,
    member: &str,
    answers: &[CachedAnswer],
) -> Result<(), crate::federation::Error> {
    let be =
        |e: rusqlite::Error| crate::federation::Error::Backend(format!("ceg_content_answers: {e}"));
    let tx = crate::store::sqlite_conn_model::write_tx(conn).map_err(be)?;
    tx.execute(
        "DELETE FROM ceg_content_answers WHERE room_scope = ?1 AND room_target = ?2 AND member = ?3",
        rusqlite::params![scope, target, member],
    )
    .map_err(be)?;
    for a in answers {
        tx.execute(
            "INSERT OR REPLACE INTO ceg_content_answers (row_id, room_scope, room_target, member, \
             counted, in_force, rule, undecided_on) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                &a.row.0[..],
                scope,
                target,
                member,
                i64::from(a.counted),
                i64::from(a.in_force),
                a.rule,
                a.undecided_on.map(|u| u.0.to_vec()),
            ],
        )
        .map_err(be)?;
    }
    tx.commit().map_err(be)
}

/// postgres: [`put_answers_sqlite`].
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn put_answers_postgres(
    client: &mut deadpool_postgres::Object,
    scope: &str,
    target: &str,
    member: &str,
    answers: &[CachedAnswer],
) -> Result<(), crate::federation::Error> {
    let be = |e: tokio_postgres::Error| {
        crate::federation::Error::Backend(format!("ceg_content_answers: {e}"))
    };
    let tx = client.transaction().await.map_err(be)?;
    tx.execute(
        "DELETE FROM cirislens.ceg_content_answers WHERE room_scope = $1 AND room_target = $2 AND \
         member = $3",
        &[&scope, &target, &member],
    )
    .await
    .map_err(be)?;
    for a in answers {
        let undecided: Option<Vec<u8>> = a.undecided_on.map(|u| u.0.to_vec());
        tx.execute(
            "INSERT INTO cirislens.ceg_content_answers (row_id, room_scope, room_target, member, \
             counted, in_force, rule, undecided_on) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON \
             CONFLICT (row_id) DO UPDATE SET room_scope = EXCLUDED.room_scope, room_target = \
             EXCLUDED.room_target, member = EXCLUDED.member, counted = EXCLUDED.counted, in_force \
             = EXCLUDED.in_force, rule = EXCLUDED.rule, undecided_on = EXCLUDED.undecided_on",
            &[
                &&a.row.0[..],
                &scope,
                &target,
                &member,
                &a.counted,
                &a.in_force,
                &a.rule,
                &undecided,
            ],
        )
        .await
        .map_err(be)?;
    }
    tx.commit().await.map_err(be)
}

/// sqlite: the cached answer of one content row.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn answer_sqlite(
    conn: &rusqlite::Connection,
    row: &RowId,
) -> Result<Option<CachedAnswer>, crate::federation::Error> {
    use rusqlite::OptionalExtension as _;
    let be =
        |e: rusqlite::Error| crate::federation::Error::Backend(format!("ceg_content_answers: {e}"));
    let got = conn
        .query_row(
            "SELECT counted, in_force, rule, undecided_on FROM ceg_content_answers WHERE row_id = ?1",
            rusqlite::params![&row.0[..]],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<Vec<u8>>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(be)?;
    got.map(|(c, f, rule, u)| {
        Ok(CachedAnswer {
            row: *row,
            counted: c != 0,
            in_force: f != 0,
            rule,
            undecided_on: u.as_deref().map(id_of).transpose()?,
        })
    })
    .transpose()
}

/// postgres: [`answer_sqlite`].
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn answer_postgres<C>(
    client: &C,
    row: &RowId,
) -> Result<Option<CachedAnswer>, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let r = client
        .query_opt(
            "SELECT counted, in_force, rule, undecided_on FROM cirislens.ceg_content_answers \
             WHERE row_id = $1",
            &[&&row.0[..]],
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("ceg_content_answers: {e}")))?;
    r.map(|r| {
        let u: Option<Vec<u8>> = r.get(3);
        Ok(CachedAnswer {
            row: *row,
            counted: r.get(0),
            in_force: r.get(1),
            rule: r.get(2),
            undecided_on: u.as_deref().map(id_of).transpose()?,
        })
    })
    .transpose()
}
