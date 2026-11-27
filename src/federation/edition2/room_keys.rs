//! v62.0.0 (ROOMKEY-3; CC 3.1.3.2) — **the room keys this node's device holds,
//! and the bindings it holds**: two NODE-LOCAL tables (PRE4-V300-e).
//!
//! - `ceg_room_keys_local`: one row per room key this device holds. The text:
//!   "Erasure by person finds a person's rows in such a room only through that
//!   person's own devices, which keep the list of their room keys" (p3:375).
//!   "A room key MUST NOT be used in a second room" (p3:365), so the key is
//!   the primary key: one room per key, here as on the wire. `acts_for` is
//!   the identity the device holds the key for (a person's, an agent's, or
//!   this node's own for the node's room key).
//! - `ceg_room_bindings`: one row per binding made FOR this node ("a node
//!   accepts one only when it was made for that node", p3:367; "A removed
//!   member keeps the bindings it was given", p3:375). It is written only
//!   after the binding opened and its commitment checked (ROOMKEY-13), never
//!   here.
//!
//! **No secret is held here, and nothing here cares who holds one.** The room
//! keys' private halves stay with the host / keyring, which signs persist's
//! drafts (the custody ruling of 11-24). The rows are ids, a room, the
//! opening's nonce (the commitment's preimage, which the binding itself
//! carries to its addressee) and instants. Neither table is a row, neither
//! is replicated or served, no rule of standing reads either ("no rule of
//! standing reads a binding", p3:367), and no purge or tombstone path
//! reaches them (I7005).

/// The node-local room-key table.
pub const ROOM_KEYS_TABLE: &str = "ceg_room_keys_local";
/// The node-local binding table.
pub const ROOM_BINDINGS_TABLE: &str = "ceg_room_bindings";

/// One room key this device holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomKeyHeld {
    /// The room key's thumbprint (its kid).
    pub room_key_kid: [u8; 32],
    /// The one private room it is for (a group-ref).
    pub room_id: String,
    /// The identity the device holds it for (an identity-ref).
    pub acts_for: String,
    /// When this node recorded it (POSIX µs).
    pub created_at_us: i64,
    /// When its seat ended or a fresh key replaced it (POSIX µs); the row is
    /// kept.
    pub retired_at_us: Option<i64>,
}

/// One binding this node holds, made for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomBinding {
    /// The bound room key's thumbprint.
    pub room_key_kid: [u8; 32],
    /// The identity-ref the binding was made for (this node's room key).
    pub made_for: String,
    /// The room (a group-ref).
    pub room_id: String,
    /// The person the binding opened to (an identity-ref).
    pub person: String,
    /// The opening's nonce: the commitment's 32 random bytes.
    pub nonce: [u8; 32],
    /// When this node recorded it (POSIX µs).
    pub received_at_us: i64,
}

fn backend(table: &str, e: impl std::fmt::Display) -> crate::federation::Error {
    crate::federation::Error::Backend(format!("{table}: {e}"))
}

fn kid_of(v: Vec<u8>, table: &str) -> Result<[u8; 32], crate::federation::Error> {
    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| backend(table, "a kid is not 32 bytes"))
}

/// A room key already held for ANOTHER room: refused, one room per key
/// (p3:365 "A room key MUST NOT be used in a second room").
fn other_room(kid: &[u8; 32], held: &str, asked: &str) -> crate::federation::Error {
    crate::federation::Error::Conflict(format!(
        "{ROOM_KEYS_TABLE}: room key {} is held for {held}, not {asked} (one room per room key)",
        hex::encode(kid)
    ))
}

// ─────────────────────────────────────────────────────────────────────────
//  sqlite
// ─────────────────────────────────────────────────────────────────────────

/// sqlite: record a held room key. The same key for the same room again is a
/// no-op (`Ok(false)`); for another room, [`crate::federation::Error::Conflict`].
///
/// # Errors
/// sqlite errors; a key held for another room.
#[cfg(feature = "sqlite")]
pub fn put_room_key_local_sqlite(
    conn: &rusqlite::Connection,
    k: &RoomKeyHeld,
) -> Result<bool, crate::federation::Error> {
    use rusqlite::OptionalExtension as _;
    let be = |e: rusqlite::Error| backend(ROOM_KEYS_TABLE, e);
    let held: Option<String> = conn
        .query_row(
            "SELECT room_id FROM ceg_room_keys_local WHERE room_key_kid = ?1",
            rusqlite::params![k.room_key_kid.as_slice()],
            |r| r.get(0),
        )
        .optional()
        .map_err(be)?;
    match held {
        Some(room) if room == k.room_id => Ok(false),
        Some(room) => Err(other_room(&k.room_key_kid, &room, &k.room_id)),
        None => {
            conn.execute(
                "INSERT INTO ceg_room_keys_local \
                 (room_key_kid, room_id, acts_for, created_at_us, retired_at_us) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    k.room_key_kid.as_slice(),
                    k.room_id,
                    k.acts_for,
                    k.created_at_us,
                    k.retired_at_us
                ],
            )
            .map_err(be)?;
            Ok(true)
        }
    }
}

/// sqlite: mark a held room key retired at `at_us` (first time only).
/// `Ok(true)` when this call retired it.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn retire_room_key_local_sqlite(
    conn: &rusqlite::Connection,
    kid: &[u8; 32],
    at_us: i64,
) -> Result<bool, crate::federation::Error> {
    let n = conn
        .execute(
            "UPDATE ceg_room_keys_local SET retired_at_us = ?2 \
             WHERE room_key_kid = ?1 AND retired_at_us IS NULL AND created_at_us <= ?2",
            rusqlite::params![kid.as_slice(), at_us],
        )
        .map_err(|e| backend(ROOM_KEYS_TABLE, e))?;
    Ok(n == 1)
}

/// sqlite: the room keys held, for one room or (`None`) every room, in key
/// order.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn room_keys_held_sqlite(
    conn: &rusqlite::Connection,
    room: Option<&str>,
) -> Result<Vec<RoomKeyHeld>, crate::federation::Error> {
    let be = |e: rusqlite::Error| backend(ROOM_KEYS_TABLE, e);
    let mut st = conn
        .prepare(
            "SELECT room_key_kid, room_id, acts_for, created_at_us, retired_at_us \
             FROM ceg_room_keys_local WHERE (?1 IS NULL OR room_id = ?1) ORDER BY room_key_kid",
        )
        .map_err(be)?;
    let rows = st
        .query_map(rusqlite::params![room], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, Option<i64>>(4)?,
            ))
        })
        .map_err(be)?;
    let mut out = Vec::new();
    for row in rows {
        let (kid, room_id, acts_for, created_at_us, retired_at_us) = row.map_err(be)?;
        out.push(RoomKeyHeld {
            room_key_kid: kid_of(kid, ROOM_KEYS_TABLE)?,
            room_id,
            acts_for,
            created_at_us,
            retired_at_us,
        });
    }
    Ok(out)
}

/// sqlite: record a binding made for this node. A second one for the same
/// `(room_key_kid, made_for)` is a no-op (`Ok(false)`): the first is kept.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn put_room_binding_sqlite(
    conn: &rusqlite::Connection,
    b: &RoomBinding,
) -> Result<bool, crate::federation::Error> {
    let n = conn
        .execute(
            "INSERT INTO ceg_room_bindings \
             (room_key_kid, made_for, room_id, person, nonce, received_at_us) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT (room_key_kid, made_for) DO NOTHING",
            rusqlite::params![
                b.room_key_kid.as_slice(),
                b.made_for,
                b.room_id,
                b.person,
                b.nonce.as_slice(),
                b.received_at_us
            ],
        )
        .map_err(|e| backend(ROOM_BINDINGS_TABLE, e))?;
    Ok(n == 1)
}

/// sqlite: the bindings this node holds for `room`, in (key, made_for) order.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn room_bindings_sqlite(
    conn: &rusqlite::Connection,
    room: &str,
) -> Result<Vec<RoomBinding>, crate::federation::Error> {
    let be = |e: rusqlite::Error| backend(ROOM_BINDINGS_TABLE, e);
    let mut st = conn
        .prepare(
            "SELECT room_key_kid, made_for, room_id, person, nonce, received_at_us \
             FROM ceg_room_bindings WHERE room_id = ?1 ORDER BY room_key_kid, made_for",
        )
        .map_err(be)?;
    let rows = st
        .query_map(rusqlite::params![room], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })
        .map_err(be)?;
    let mut out = Vec::new();
    for row in rows {
        let (kid, made_for, room_id, person, nonce, received_at_us) = row.map_err(be)?;
        out.push(RoomBinding {
            room_key_kid: kid_of(kid, ROOM_BINDINGS_TABLE)?,
            made_for,
            room_id,
            person,
            nonce: kid_of(nonce, ROOM_BINDINGS_TABLE)?,
            received_at_us,
        });
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────
//  postgres
// ─────────────────────────────────────────────────────────────────────────

/// postgres: [`put_room_key_local_sqlite`].
///
/// # Errors
/// postgres errors; a key held for another room.
#[cfg(feature = "postgres")]
pub async fn put_room_key_local_postgres<C>(
    client: &C,
    k: &RoomKeyHeld,
) -> Result<bool, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let be = |e: tokio_postgres::Error| backend(ROOM_KEYS_TABLE, e);
    let kid: &[u8] = &k.room_key_kid;
    let n = client
        .execute(
            "INSERT INTO cirislens.ceg_room_keys_local \
             (room_key_kid, room_id, acts_for, created_at_us, retired_at_us) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (room_key_kid) DO NOTHING",
            &[
                &kid,
                &k.room_id,
                &k.acts_for,
                &k.created_at_us,
                &k.retired_at_us,
            ],
        )
        .await
        .map_err(be)?;
    if n == 1 {
        return Ok(true);
    }
    let row = client
        .query_one(
            "SELECT room_id FROM cirislens.ceg_room_keys_local WHERE room_key_kid = $1",
            &[&kid],
        )
        .await
        .map_err(be)?;
    let held: String = row.get(0);
    if held == k.room_id {
        Ok(false)
    } else {
        Err(other_room(&k.room_key_kid, &held, &k.room_id))
    }
}

/// postgres: [`retire_room_key_local_sqlite`].
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn retire_room_key_local_postgres<C>(
    client: &C,
    kid: &[u8; 32],
    at_us: i64,
) -> Result<bool, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let kid: &[u8] = kid;
    let n = client
        .execute(
            "UPDATE cirislens.ceg_room_keys_local SET retired_at_us = $2 \
             WHERE room_key_kid = $1 AND retired_at_us IS NULL AND created_at_us <= $2",
            &[&kid, &at_us],
        )
        .await
        .map_err(|e| backend(ROOM_KEYS_TABLE, e))?;
    Ok(n == 1)
}

/// postgres: [`room_keys_held_sqlite`].
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn room_keys_held_postgres<C>(
    client: &C,
    room: Option<&str>,
) -> Result<Vec<RoomKeyHeld>, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let rows = client
        .query(
            "SELECT room_key_kid, room_id, acts_for, created_at_us, retired_at_us \
             FROM cirislens.ceg_room_keys_local \
             WHERE ($1::text IS NULL OR room_id = $1) ORDER BY room_key_kid",
            &[&room],
        )
        .await
        .map_err(|e| backend(ROOM_KEYS_TABLE, e))?;
    rows.iter()
        .map(|r| {
            Ok(RoomKeyHeld {
                room_key_kid: kid_of(r.get::<_, Vec<u8>>(0), ROOM_KEYS_TABLE)?,
                room_id: r.get(1),
                acts_for: r.get(2),
                created_at_us: r.get(3),
                retired_at_us: r.get(4),
            })
        })
        .collect()
}

/// postgres: [`put_room_binding_sqlite`].
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn put_room_binding_postgres<C>(
    client: &C,
    b: &RoomBinding,
) -> Result<bool, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let kid: &[u8] = &b.room_key_kid;
    let nonce: &[u8] = &b.nonce;
    let n = client
        .execute(
            "INSERT INTO cirislens.ceg_room_bindings \
             (room_key_kid, made_for, room_id, person, nonce, received_at_us) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (room_key_kid, made_for) DO NOTHING",
            &[
                &kid,
                &b.made_for,
                &b.room_id,
                &b.person,
                &nonce,
                &b.received_at_us,
            ],
        )
        .await
        .map_err(|e| backend(ROOM_BINDINGS_TABLE, e))?;
    Ok(n == 1)
}

/// postgres: [`room_bindings_sqlite`].
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn room_bindings_postgres<C>(
    client: &C,
    room: &str,
) -> Result<Vec<RoomBinding>, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let rows = client
        .query(
            "SELECT room_key_kid, made_for, room_id, person, nonce, received_at_us \
             FROM cirislens.ceg_room_bindings WHERE room_id = $1 \
             ORDER BY room_key_kid, made_for",
            &[&room],
        )
        .await
        .map_err(|e| backend(ROOM_BINDINGS_TABLE, e))?;
    rows.iter()
        .map(|r| {
            Ok(RoomBinding {
                room_key_kid: kid_of(r.get::<_, Vec<u8>>(0), ROOM_BINDINGS_TABLE)?,
                made_for: r.get(1),
                room_id: r.get(2),
                person: r.get(3),
                nonce: kid_of(r.get::<_, Vec<u8>>(4), ROOM_BINDINGS_TABLE)?,
                received_at_us: r.get(5),
            })
        })
        .collect()
}
