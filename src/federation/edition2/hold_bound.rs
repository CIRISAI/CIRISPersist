//! v62.0.0 (HOLD-1a; CC 2.7.3 as the Constitution ruled 11-23) — **this
//! node's own bound on the rows it holds for a writer's standing.**
//!
//! "A node may decline to keep or serve a row by its own configuration or
//! duty. That is its own act, never a verdict on the row, and the row is not
//! Invalid." So this is local housekeeping. It need not agree across nodes,
//! and a declined row's answer is "not held" (waiting).
//!
//! **What is bounded.** A row the door HOLDS on its writer's write scope:
//! - `write_scope_refused`;
//! - `link_unheld` for a room not held here.
//!
//! Only when the row does not [`takes_out`]. Concluded rows are never
//! touched. The ledger is `ceg_held_bound` (PRE4-V300-c). Rows are entered
//! when kept, removed when they conclude or are dropped.
//!
//! **The two buckets:**
//! - [`Bucket::Unseated`]: a writer with no end of a seat the node holds in
//!   that room (a joiner whose widening has not arrived; a stranger; a fresh
//!   key). Counted per room and per writer key. A dwell lands the legitimate
//!   race (a first post before its widening). Past the dwell the row is
//!   dropped; the sender's re-sweep re-offers it.
//! - [`Bucket::Ended`]: a member with a retained end in the room (a removed
//!   member's post-end rows). Counted per (room, member) across its keys.
//!   Under CONTENT-A7 these rows are ADMITTED and marked, and A7 enters them
//!   here too.
//!
//! **Over a ceiling, the NEW row is declined** ([`Error::NotKept`]; the
//! replicated door answers `Refused { NotKept }`, a local decline). Before
//! each check, at most [`EXPIRE_PER_CHECK`] rows of the bucket past their
//! dwell are dropped (`drop_held_row`).
//!
//! **One limit:** a row that TAKES SOMETHING OUT ([`takes_out`]) is never
//! declined or dropped here, whatever the bounds.

use ciris_verify_core::cde::Value;

use super::door::AdmittedRow;
use super::names::RowId;
use crate::federation::{Error, FederationDirectory};

/// A bound bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bucket {
    /// No end of the writer's seat is held in the room.
    Unseated,
    /// The writer's member has a retained end in the room.
    Ended,
}

impl Bucket {
    /// The stored spelling (`ceg_held_bound.bucket`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Bucket::Unseated => "unseated",
            Bucket::Ended => "ended",
        }
    }
}

/// This node's bounds (node configuration; [`HoldBounds::current`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HoldBounds {
    /// Unseated: rows per room.
    pub unseated_room_rows: u64,
    /// Unseated: bytes per room.
    pub unseated_room_bytes: u64,
    /// Unseated: rows per writer key in a room.
    pub unseated_writer_rows: u64,
    /// Unseated: bytes per writer key in a room.
    pub unseated_writer_bytes: u64,
    /// Unseated: the dwell, in microseconds.
    pub unseated_dwell_us: i64,
    /// Ended: rows per (room, member).
    pub ended_rows: u64,
    /// Ended: bytes per (room, member).
    pub ended_bytes: u64,
    /// Ended: the dwell, in microseconds.
    pub ended_dwell_us: i64,
}

const DAY_US: i64 = 86_400 * 1_000_000;

impl Default for HoldBounds {
    /// The defaults the lead accepted (P/HOLD-1-read.md):
    /// - unseated: a room 1,000 rows / 16 MB, a writer 50 rows / 1 MB,
    ///   dwell 7 days (beyond Edge's 6 h terminal re-offer);
    /// - ended: a (room, member) 500 rows / 8 MB, dwell 30 days.
    fn default() -> Self {
        Self {
            unseated_room_rows: 1_000,
            unseated_room_bytes: 16 * 1024 * 1024,
            unseated_writer_rows: 50,
            unseated_writer_bytes: 1024 * 1024,
            unseated_dwell_us: 7 * DAY_US,
            ended_rows: 500,
            ended_bytes: 8 * 1024 * 1024,
            ended_dwell_us: 30 * DAY_US,
        }
    }
}

tokio::task_local! {
    static BOUNDS_OVERRIDE: HoldBounds;
}

impl HoldBounds {
    /// The bounds in force: a task-scoped override ([`with_bounds`]), else
    /// the defaults with each `CIRIS_PERSIST_HOLD_<FIELD>` environment
    /// variable that parses (read once per process).
    #[must_use]
    pub fn current() -> Self {
        BOUNDS_OVERRIDE
            .try_with(|b| *b)
            .unwrap_or_else(|_| *configured())
    }
}

fn configured() -> &'static HoldBounds {
    static CONFIGURED: std::sync::OnceLock<HoldBounds> = std::sync::OnceLock::new();
    CONFIGURED.get_or_init(|| {
        let mut b = HoldBounds::default();
        let u = |name: &str, v: &mut u64| {
            if let Some(x) = std::env::var(format!("CIRIS_PERSIST_HOLD_{name}"))
                .ok()
                .and_then(|s| s.parse().ok())
            {
                *v = x;
            }
        };
        u("UNSEATED_ROOM_ROWS", &mut b.unseated_room_rows);
        u("UNSEATED_ROOM_BYTES", &mut b.unseated_room_bytes);
        u("UNSEATED_WRITER_ROWS", &mut b.unseated_writer_rows);
        u("UNSEATED_WRITER_BYTES", &mut b.unseated_writer_bytes);
        u("ENDED_ROWS", &mut b.ended_rows);
        u("ENDED_BYTES", &mut b.ended_bytes);
        let dwell = |name: &str, v: &mut i64| {
            if let Some(x) = std::env::var(format!("CIRIS_PERSIST_HOLD_{name}_SECS"))
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
            {
                *v = x.saturating_mul(1_000_000);
            }
        };
        dwell("UNSEATED_DWELL", &mut b.unseated_dwell_us);
        dwell("ENDED_DWELL", &mut b.ended_dwell_us);
        b
    })
}

/// Run `fut` with `bounds` in force (task-scoped: concurrent tests do not
/// see each other's).
pub async fn with_bounds<F: std::future::Future>(bounds: HoldBounds, fut: F) -> F::Output {
    BOUNDS_OVERRIDE.scope(bounds, fut).await
}

/// The most expired rows one bound check drops.
pub const EXPIRE_PER_CHECK: u32 = 64;

/// **THE one predicate: does this row TAKE SOMETHING OUT?** (CC 2.7.3's one
/// limit on declining.) Such a row is never declined or dropped by the
/// bound. Read from the row's own bytes:
/// - a retraction or withdrawal, a recant: `emit::carries_no_dimension`
///   (`withdraws`, `recants`);
/// - an end of a seat: `membership:{stage}` at leaf `removal` or
///   `resignation` (the leaf decides);
/// - a takedown or purge notice: `takedown_notice:{basis}` (`steward_purge`
///   is a basis);
/// - a key, occurrence or entity revocation: `key:revocation`,
///   `identity:occurrence_revocation`, `revocation:{entity_type}:{reason}`.
///
/// An edit (`supersedes`) and a `keeps` row ADD; they are not exempt.
#[must_use]
pub fn takes_out(row_type: &str, family_id: &str, payload: &Value) -> bool {
    use super::group::{MEMBERSHIP_PREFIX, REMOVAL_LEAF, RESIGNATION_LEAF};
    use ciris_verify_core::namespace_match::family_id as fid;
    if super::emit::carries_no_dimension(row_type) {
        return true;
    }
    if family_id == fid(MEMBERSHIP_PREFIX) {
        let leaf = super::payloads::leaf_of(MEMBERSHIP_PREFIX, payload);
        return !super::emit::names_a_target(row_type)
            && (leaf == Some(REMOVAL_LEAF) || leaf == Some(RESIGNATION_LEAF));
    }
    [
        "takedown_notice:{basis}",
        super::liveness::KEY_REVOCATION_FAMILY,
        super::occurrence::OCCURRENCE_REVOCATION_FAMILY,
        super::typed::REVOCATION_PREFIX,
    ]
    .iter()
    .any(|p| fid(p) == family_id)
}

/// One `ceg_held_bound` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldEntry {
    /// The held row.
    pub row: RowId,
    /// The room's placement.
    pub scope: String,
    /// The room's group.
    pub target: String,
    /// The writer key (`iss`) for an unseated row; the member for an ended
    /// one.
    pub writer: String,
    /// The bucket.
    pub bucket: Bucket,
    /// The statement's bytes.
    pub bytes: u64,
    /// This node's clock when it was held (µs).
    pub held_us: i64,
}

/// `Unsupported` (a backend without the ledger) is no bound.
fn supported<T>(r: Result<T, Error>) -> Result<Option<T>, Error> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(Error::Unsupported { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Does the hold `(reason, refusal)` the door just reached for `admitted`
/// come under the bound? The write scope's own holds only.
fn bounded_hold(reason: &str, refusal: &Error) -> bool {
    use super::fold::reason as r;
    matches!(refusal, Error::WriteScopeRefused(_))
        && (reason == r::WRITE_SCOPE_REFUSED || reason == r::LINK_UNHELD)
}

/// **Before the door keeps a write-scope hold of `admitted`:** the entry to
/// record once kept (`Ok(Some)`), no bound (`Ok(None)`: exempt, unplaced,
/// another hold, no ledger), or the decline ([`Error::NotKept`]). Expired
/// rows of the bucket are dropped first.
///
/// # Errors
/// [`Error::NotKept`] over a ceiling; directory reads and drops.
pub async fn admit<F>(
    dir: &F,
    admitted: &AdmittedRow,
    reason: &str,
    refusal: &Error,
) -> Result<Option<HeldEntry>, Error>
where
    F: FederationDirectory + ?Sized,
{
    if !bounded_hold(reason, refusal)
        || takes_out(&admitted.row_type, &admitted.family, &admitted.payload)
    {
        return Ok(None);
    }
    let text = |k: &str| admitted.payload.get_text(k).and_then(Value::as_text);
    let Some(scope) = text("cohort_scope") else {
        return Ok(None);
    };
    let Some(target) = crate::federation::admission::COHORT_TARGET_ENVELOPE_FIELDS
        .iter()
        .find_map(|f| text(f).filter(|t| !t.is_empty()))
    else {
        return Ok(None);
    };
    let member = admitted.author.as_deref().unwrap_or(admitted.iss.as_str());
    let kind = if scope == crate::federation::types::cohort_scope::FAMILY {
        "family"
    } else {
        "community"
    };
    let Some(ends) = supported(dir.edition2_content_ends(kind, target, member).await)? else {
        return Ok(None);
    };
    let b = HoldBounds::current();
    let (bucket, writer, dwell) = if ends.is_empty() {
        (Bucket::Unseated, admitted.iss.as_str(), b.unseated_dwell_us)
    } else {
        (Bucket::Ended, member, b.ended_dwell_us)
    };
    let now = crate::host::clock::now().timestamp_micros();
    // Expired rows first: at most EXPIRE_PER_CHECK, the oldest.
    let Some(expired) = supported(
        dir.edition2_held_bound_expired(
            scope,
            target,
            bucket.as_str(),
            now.saturating_sub(dwell),
            EXPIRE_PER_CHECK,
        )
        .await,
    )?
    else {
        return Ok(None);
    };
    for id in expired {
        dir.drop_held_row(&id).await?;
        dir.edition2_held_bound_remove(&id).await?;
    }
    let bytes = u64::try_from(admitted.bytes.len()).unwrap_or(u64::MAX);
    let decline = |detail: String| Error::NotKept {
        row_id: admitted.row_id.hex(),
        why: crate::federation::NotKeptWhy::Bound {
            bucket: bucket.as_str(),
        },
        detail,
    };
    let over = |(rows, used): (u64, u64), cap_rows: u64, cap_bytes: u64| {
        rows.saturating_add(1) > cap_rows || used.saturating_add(bytes) > cap_bytes
    };
    match bucket {
        Bucket::Unseated => {
            let room = dir
                .edition2_held_bound_usage(
                    scope,
                    target,
                    bucket.as_str(),
                    None,
                    b.unseated_room_rows,
                )
                .await?;
            if over(room, b.unseated_room_rows, b.unseated_room_bytes) {
                return Err(decline(format!(
                    "the room's unseated buffer is full ({} rows, {} bytes)",
                    room.0, room.1
                )));
            }
            let mine = dir
                .edition2_held_bound_usage(
                    scope,
                    target,
                    bucket.as_str(),
                    Some(writer),
                    b.unseated_writer_rows,
                )
                .await?;
            if over(mine, b.unseated_writer_rows, b.unseated_writer_bytes) {
                return Err(decline(format!(
                    "this writer's unseated buffer in the room is full ({} rows, {} bytes)",
                    mine.0, mine.1
                )));
            }
        }
        Bucket::Ended => {
            let mine = dir
                .edition2_held_bound_usage(
                    scope,
                    target,
                    bucket.as_str(),
                    Some(writer),
                    b.ended_rows,
                )
                .await?;
            if over(mine, b.ended_rows, b.ended_bytes) {
                return Err(decline(format!(
                    "the ended member's buffer in the room is full ({} rows, {} bytes)",
                    mine.0, mine.1
                )));
            }
        }
    }
    Ok(Some(HeldEntry {
        row: admitted.row_id,
        scope: scope.to_owned(),
        target: target.to_owned(),
        writer: writer.to_owned(),
        bucket,
        bytes,
        held_us: now,
    }))
}

/// sqlite: enter a held row.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn put_sqlite(conn: &rusqlite::Connection, e: &HeldEntry) -> Result<(), Error> {
    conn.execute(
        "INSERT OR IGNORE INTO ceg_held_bound (row_id, room_scope, room_target, writer, bucket, \
         bytes, held_us) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            &e.row.0[..],
            e.scope,
            e.target,
            e.writer,
            e.bucket.as_str(),
            i64::try_from(e.bytes).unwrap_or(i64::MAX),
            e.held_us
        ],
    )
    .map(|_| ())
    .map_err(|x| Error::Backend(format!("ceg_held_bound: {x}")))
}

/// sqlite: remove a row from the ledger.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn remove_sqlite(conn: &rusqlite::Connection, row: &RowId) -> Result<(), Error> {
    conn.execute(
        "DELETE FROM ceg_held_bound WHERE row_id = ?1",
        rusqlite::params![&row.0[..]],
    )
    .map(|_| ())
    .map_err(|x| Error::Backend(format!("ceg_held_bound: {x}")))
}

/// sqlite: `(rows, bytes)` of a bucket in a room (and of one writer), over
/// at most `cap + 1` rows.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn usage_sqlite(
    conn: &rusqlite::Connection,
    scope: &str,
    target: &str,
    bucket: &str,
    writer: Option<&str>,
    cap: u64,
) -> Result<(u64, u64), Error> {
    let lim = i64::try_from(cap.saturating_add(1)).unwrap_or(i64::MAX);
    let (sql, params): (&str, Vec<rusqlite::types::Value>) = match writer {
        None => (
            "SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM (SELECT bytes FROM ceg_held_bound \
             WHERE room_scope = ?1 AND room_target = ?2 AND bucket = ?3 LIMIT ?4)",
            vec![
                scope.to_owned().into(),
                target.to_owned().into(),
                bucket.to_owned().into(),
                lim.into(),
            ],
        ),
        Some(w) => (
            "SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM (SELECT bytes FROM ceg_held_bound \
             WHERE room_scope = ?1 AND room_target = ?2 AND writer = ?5 AND bucket = ?3 LIMIT ?4)",
            vec![
                scope.to_owned().into(),
                target.to_owned().into(),
                bucket.to_owned().into(),
                lim.into(),
                w.to_owned().into(),
            ],
        ),
    };
    conn.query_row(sql, rusqlite::params_from_iter(params.iter()), |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
    })
    .map(|(n, b)| {
        (
            u64::try_from(n).unwrap_or_default(),
            u64::try_from(b).unwrap_or_default(),
        )
    })
    .map_err(|x| Error::Backend(format!("ceg_held_bound: {x}")))
}

/// sqlite: at most `limit` rows of a bucket in a room held before
/// `before_us`, oldest first.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn expired_sqlite(
    conn: &rusqlite::Connection,
    scope: &str,
    target: &str,
    bucket: &str,
    before_us: i64,
    limit: u32,
) -> Result<Vec<RowId>, Error> {
    let be = |x: rusqlite::Error| Error::Backend(format!("ceg_held_bound: {x}"));
    let mut st = conn
        .prepare(
            "SELECT row_id FROM ceg_held_bound WHERE room_scope = ?1 AND room_target = ?2 AND \
             bucket = ?3 AND held_us < ?4 ORDER BY held_us, row_id LIMIT ?5",
        )
        .map_err(be)?;
    let rows = st
        .query_map(
            rusqlite::params![scope, target, bucket, before_us, i64::from(limit)],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .map_err(be)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(be)?;
    rows.iter()
        .map(|b| {
            <[u8; 32]>::try_from(b.as_slice())
                .map(RowId)
                .map_err(|_| Error::Backend("ceg_held_bound: row id length".into()))
        })
        .collect()
}

/// postgres: [`put_sqlite`].
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn put_postgres<C>(client: &C, e: &HeldEntry) -> Result<(), Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    client
        .execute(
            "INSERT INTO cirislens.ceg_held_bound (row_id, room_scope, room_target, writer, \
             bucket, bytes, held_us) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
            &[
                &&e.row.0[..],
                &e.scope,
                &e.target,
                &e.writer,
                &e.bucket.as_str(),
                &i64::try_from(e.bytes).unwrap_or(i64::MAX),
                &e.held_us,
            ],
        )
        .await
        .map(|_| ())
        .map_err(|x| Error::Backend(format!("ceg_held_bound: {x}")))
}

/// postgres: [`remove_sqlite`].
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn remove_postgres<C>(client: &C, row: &RowId) -> Result<(), Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    client
        .execute(
            "DELETE FROM cirislens.ceg_held_bound WHERE row_id = $1",
            &[&&row.0[..]],
        )
        .await
        .map(|_| ())
        .map_err(|x| Error::Backend(format!("ceg_held_bound: {x}")))
}

/// postgres: [`usage_sqlite`].
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn usage_postgres<C>(
    client: &C,
    scope: &str,
    target: &str,
    bucket: &str,
    writer: Option<&str>,
    cap: u64,
) -> Result<(u64, u64), Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let lim = i64::try_from(cap.saturating_add(1)).unwrap_or(i64::MAX);
    let row = client
        .query_one(
            "SELECT COUNT(*)::bigint, COALESCE(SUM(bytes), 0)::bigint FROM (SELECT bytes FROM \
             cirislens.ceg_held_bound WHERE room_scope = $1 AND room_target = $2 AND bucket = $3 \
             AND ($5::text IS NULL OR writer = $5) LIMIT $4) AS u",
            &[&scope, &target, &bucket, &lim, &writer],
        )
        .await
        .map_err(|x| Error::Backend(format!("ceg_held_bound: {x}")))?;
    let (n, b): (i64, i64) = (row.get(0), row.get(1));
    Ok((
        u64::try_from(n).unwrap_or_default(),
        u64::try_from(b).unwrap_or_default(),
    ))
}

/// postgres: [`expired_sqlite`].
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn expired_postgres<C>(
    client: &C,
    scope: &str,
    target: &str,
    bucket: &str,
    before_us: i64,
    limit: u32,
) -> Result<Vec<RowId>, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let rows = client
        .query(
            "SELECT row_id FROM cirislens.ceg_held_bound WHERE room_scope = $1 AND room_target = \
             $2 AND bucket = $3 AND held_us < $4 ORDER BY held_us, row_id LIMIT $5",
            &[&scope, &target, &bucket, &before_us, &i64::from(limit)],
        )
        .await
        .map_err(|x| Error::Backend(format!("ceg_held_bound: {x}")))?;
    rows.iter()
        .map(|r| {
            let b: Vec<u8> = r.get(0);
            <[u8; 32]>::try_from(b.as_slice())
                .map(RowId)
                .map_err(|_| Error::Backend("ceg_held_bound: row id length".into()))
        })
        .collect()
}
