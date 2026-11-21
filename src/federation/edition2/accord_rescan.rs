//! v62.0.0 (RL-fix1, lead ruling (B); CC 5.4 "Who carries what", CC 4.2.1.1)
//! — **a rootless node never wedges on an accord row, and never misses a
//! halt once it has a root.**
//!
//! An accord row (a halt invocation, a notify, a drill, a lifecycle row) is
//! judged against the holders of the genesis bundle in force. A node that
//! holds no bundle cannot verify one, and CC part_5 l.1129 says it "carries
//! none it cannot verify". The replicated door therefore answers such a row
//! [`AttestationRefusalReason::AccordRootNotHeld`](crate::federation::attestation_apply::AttestationRefusalReason::AccordRootNotHeld):
//! the store is untouched and the sender's cursor ADVANCES, where the
//! earlier answer (the retryable `federation_attester_key_unknown` naming the
//! bundle) held the cursor forever on a node that no replication can root (a
//! bundle arrives at the import door, under an anchor, never down a feed).
//!
//! What is skipped is not lost. The door called with the host's feed position
//! ([`apply_replicated_statement_at_feed`](super::ingest::apply_replicated_statement_at_feed))
//! records a node-local WATERMARK: no row bytes, only `(plane, peer,
//! from_position)`, the FIRST position skipped on that feed (a feed's cursor
//! only advances, so the first is the lowest). Once this node holds a
//! genesis bundle in force ([`rescan_needed`]), the host re-pulls each feed
//! from its watermark; the re-offered rows are judged under the roster now
//! held, and a halt latches. [`ack_rescan`] clears a watermark the host has
//! re-pulled past.
//!
//! The halt reaches an agent's act gate and an admitted unit's effect (CC 3.2
//! T4), and a rootless node runs no agent (T1): with no accord root there is
//! no accord to halt under, so nothing is owed before the root.

use serde::{Deserialize, Serialize};

use crate::federation::{Error, FederationDirectory};

/// The most watermarks one node keeps; a further feed's first skip is still
/// refused (nothing is stored either way) and logged.
pub const MAX_ACCORD_RESCAN_FEEDS: usize = 4096;

/// The most bytes of each watermark field (`plane`, `peer`, `position`).
pub const MAX_ACCORD_RESCAN_FIELD_BYTES: usize = 512;

/// **Where a host's feed stands**: the plane it pulls (`"statements"` for the
/// edition-2 statement feed), the peer it pulls from (its identity-ref, or
/// any stable feed name the host uses), and the position of the statement it
/// is offering, as the host spells its own cursor. Persist stores the
/// position opaquely and hands it back unchanged.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FeedPosition {
    /// The plane the feed carries.
    pub plane: String,
    /// The peer (or feed) the host pulls from.
    pub peer: String,
    /// The position of the offered statement, in the host's own spelling.
    pub position: String,
}

/// **One feed to re-pull**: the first position skipped on it while this node
/// held no accord root, and when (POSIX ms, this node's clock).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AccordRescan {
    /// The plane the feed carries.
    pub plane: String,
    /// The peer (or feed) the host pulls from.
    pub peer: String,
    /// Re-pull from here (inclusive).
    pub from_position: String,
    /// When the first skip was recorded (POSIX ms).
    pub skipped_at_ms: i64,
}

/// Is `statement` an accord row (an invocation of any family, or a
/// lifecycle row) that this node cannot judge because it holds no genesis
/// bundle at all? A node holding one judges every accord row as before.
///
/// # Errors
/// Directory reads.
pub async fn accord_root_not_held<F>(dir: &F, statement: &[u8]) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    if !(super::halt::is_invocation(statement) || super::halt::is_lifecycle(statement)) {
        return Ok(false);
    }
    Ok(!super::genesis::genesis_in_force(dir).await?.is_held())
}

fn check_field(what: &str, s: &str) -> Result<(), Error> {
    if s.is_empty() || s.len() > MAX_ACCORD_RESCAN_FIELD_BYTES {
        return Err(Error::InvalidArgument(format!(
            "accord_rescan: `{what}` must be 1..={MAX_ACCORD_RESCAN_FIELD_BYTES} bytes"
        )));
    }
    Ok(())
}

/// **Record a skip** on `feed`: the first one per `(plane, peer)` is kept,
/// a later one changes nothing.
///
/// # Errors
/// A field empty or over [`MAX_ACCORD_RESCAN_FIELD_BYTES`]; the store.
pub async fn note_skip<F>(dir: &F, feed: &FeedPosition) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    check_field("plane", &feed.plane)?;
    check_field("peer", &feed.peer)?;
    check_field("position", &feed.position)?;
    dir.note_accord_skip(feed, crate::host::clock::now().timestamp_millis())
        .await
}

/// **The feeds to re-pull**: every watermark, once this node holds a genesis
/// bundle in force (before that a re-pull would only be skipped again, so
/// the answer is empty, a STATE), in `(plane, peer)` order.
///
/// # Errors
/// Directory reads.
pub async fn rescan_needed<F>(dir: &F) -> Result<Vec<AccordRescan>, Error>
where
    F: FederationDirectory + ?Sized,
{
    if !super::genesis::genesis_in_force(dir).await?.is_held() {
        return Ok(Vec::new());
    }
    dir.accord_skips().await
}

/// **The host re-pulled `plane` from `peer` past `from_position`**: clear
/// that watermark. `false` when no watermark matches (it was cleared, or a
/// different first position is held: nothing is cleared then).
///
/// # Errors
/// The store.
pub async fn ack_rescan<F>(
    dir: &F,
    plane: &str,
    peer: &str,
    from_position: &str,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    dir.clear_accord_skip(plane, peer, from_position).await
}

/// sqlite: keep the first skip per `(plane, peer)`.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn note_skip_sqlite(
    conn: &mut rusqlite::Connection,
    feed: &FeedPosition,
    at_ms: i64,
) -> Result<(), Error> {
    let be = |e: rusqlite::Error| Error::Backend(format!("ceg_accord_rescan: {e}"));
    let held: i64 = conn
        .query_row("SELECT COUNT(*) FROM ceg_accord_rescan", [], |r| r.get(0))
        .map_err(be)?;
    if usize::try_from(held).unwrap_or(usize::MAX) >= MAX_ACCORD_RESCAN_FEEDS {
        tracing::warn!(
            plane = %feed.plane,
            peer = %feed.peer,
            "accord_rescan: the watermark table is full; this feed's skip is not recorded"
        );
        return Ok(());
    }
    conn.execute(
        "INSERT INTO ceg_accord_rescan (plane, peer, from_position, skipped_at_ms) \
         VALUES (?1, ?2, ?3, ?4) ON CONFLICT (plane, peer) DO NOTHING",
        rusqlite::params![feed.plane, feed.peer, feed.position, at_ms],
    )
    .map(|_| ())
    .map_err(be)
}

/// sqlite: every watermark, in `(plane, peer)` order.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn skips_sqlite(conn: &rusqlite::Connection) -> Result<Vec<AccordRescan>, Error> {
    let be = |e: rusqlite::Error| Error::Backend(format!("ceg_accord_rescan: {e}"));
    let mut st = conn
        .prepare(
            "SELECT plane, peer, from_position, skipped_at_ms FROM ceg_accord_rescan \
             ORDER BY plane, peer",
        )
        .map_err(be)?;
    let rows = st
        .query_map([], |r| {
            Ok(AccordRescan {
                plane: r.get(0)?,
                peer: r.get(1)?,
                from_position: r.get(2)?,
                skipped_at_ms: r.get(3)?,
            })
        })
        .map_err(be)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(be)
}

/// sqlite: clear one watermark when its first position matches.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn clear_skip_sqlite(
    conn: &mut rusqlite::Connection,
    plane: &str,
    peer: &str,
    from_position: &str,
) -> Result<bool, Error> {
    conn.execute(
        "DELETE FROM ceg_accord_rescan WHERE plane = ?1 AND peer = ?2 AND from_position = ?3",
        rusqlite::params![plane, peer, from_position],
    )
    .map(|n| n > 0)
    .map_err(|e| Error::Backend(format!("ceg_accord_rescan: {e}")))
}

/// postgres: keep the first skip per `(plane, peer)`.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn note_skip_postgres<C>(client: &C, feed: &FeedPosition, at_ms: i64) -> Result<(), Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let be = |e: tokio_postgres::Error| Error::Backend(format!("ceg_accord_rescan: {e}"));
    let held: i64 = client
        .query_one("SELECT COUNT(*) FROM cirislens.ceg_accord_rescan", &[])
        .await
        .map_err(be)?
        .get(0);
    if usize::try_from(held).unwrap_or(usize::MAX) >= MAX_ACCORD_RESCAN_FEEDS {
        tracing::warn!(
            plane = %feed.plane,
            peer = %feed.peer,
            "accord_rescan: the watermark table is full; this feed's skip is not recorded"
        );
        return Ok(());
    }
    client
        .execute(
            "INSERT INTO cirislens.ceg_accord_rescan (plane, peer, from_position, skipped_at_ms) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (plane, peer) DO NOTHING",
            &[&feed.plane, &feed.peer, &feed.position, &at_ms],
        )
        .await
        .map(|_| ())
        .map_err(be)
}

/// postgres: every watermark, in `(plane, peer)` order.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn skips_postgres<C>(client: &C) -> Result<Vec<AccordRescan>, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let rows = client
        .query(
            "SELECT plane, peer, from_position, skipped_at_ms FROM cirislens.ceg_accord_rescan \
             ORDER BY plane, peer",
            &[],
        )
        .await
        .map_err(|e| Error::Backend(format!("ceg_accord_rescan: {e}")))?;
    Ok(rows
        .iter()
        .map(|r| AccordRescan {
            plane: r.get(0),
            peer: r.get(1),
            from_position: r.get(2),
            skipped_at_ms: r.get(3),
        })
        .collect())
}

/// postgres: clear one watermark when its first position matches.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn clear_skip_postgres<C>(
    client: &C,
    plane: &str,
    peer: &str,
    from_position: &str,
) -> Result<bool, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    client
        .execute(
            "DELETE FROM cirislens.ceg_accord_rescan \
             WHERE plane = $1 AND peer = $2 AND from_position = $3",
            &[&plane, &peer, &from_position],
        )
        .await
        .map(|n| n > 0)
        .map_err(|e| Error::Backend(format!("ceg_accord_rescan: {e}")))
}
