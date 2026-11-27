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
/// The node-local binding-exchange table (PRE4-V300-g / -h).
pub const ROOM_EXCHANGES_TABLE: &str = "ceg_room_binding_exchanges";
/// The node-local sealed KEM-secret table (PRE4-V300-g).
pub const ROOM_KEM_SECRETS_TABLE: &str = "ceg_room_kem_secrets";

/// v62.0.0 (ROOMKEY-E1) — what one erasure removed, per node-local table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RoomErasure {
    /// Rows of `ceg_room_keys_local`.
    pub room_keys: u64,
    /// Rows of `ceg_room_kem_secrets`.
    pub kem_secrets: u64,
    /// Rows of `ceg_room_binding_exchanges`.
    pub exchanges: u64,
    /// Rows of `ceg_room_bindings`.
    pub bindings: u64,
}

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

// ─────────────────────────────────────────────────────────────────────────
//  ROOMKEY-3b — the voice <-> person tie, SEALED at rest (PRE4-V300-h)
// ─────────────────────────────────────────────────────────────────────────

/// The derivation label of the per-room person-tag key (persist-local; never
/// on a wire).
pub const PERSON_TAG_CONTEXT: &str = "ceg-room-person-tag-v1";
/// The label inside a sealed binding tie (binds the blob to its table).
pub const TIE_LABEL: &str = "ceg-room-binding-tie/1";

/// The content master a binding is sealed under, with its kind (the seal's
/// honest provenance, `tie_key_kind`). The key is scrubbed on drop.
pub struct TieSeal {
    /// The resolved 32-byte content master.
    pub master: zeroize::Zeroizing<[u8; 32]>,
    /// `software` | `hardware`, as `federation_content_master` records it.
    pub key_kind: String,
}

impl std::fmt::Debug for TieSeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TieSeal {{ key_kind: {:?}, .. }}", self.key_kind)
    }
}

/// **The node's tie seal**: the content-master row, resolved
/// (`at_rest_cascade::resolve_persisted_content_master_cached`). One path for
/// both kinds. A `hardware` master whose seed cannot be reached is a REFUSAL
/// (an `Err` naming the custody), never "no binding" (ROOMKEY-3b-read.md).
///
/// # Errors
/// The master cannot be resolved; directory reads.
pub async fn tie_seal<B>(store: &B) -> Result<TieSeal, crate::federation::Error>
where
    B: crate::federation::BlobStorage + ?Sized + Sync,
{
    let refuse = |e: String| {
        crate::federation::Error::Backend(format!(
            "{ROOM_BINDINGS_TABLE}: the content master the bindings are sealed under cannot be \
             resolved here; refusing to read them as absent: {e}"
        ))
    };
    let row = store
        .load_or_init_content_master_row()
        .await
        .map_err(|e| refuse(e.to_string()))?;
    let master = crate::federation::at_rest_cascade::resolve_persisted_content_master_cached(
        &row.key_kind,
        row.master_key_b64.as_ref().map(|b| b.as_str()),
    )
    .await
    .map_err(|e| refuse(e.to_string()))?;
    Ok(TieSeal {
        master: zeroize::Zeroizing::new(master),
        key_kind: row.key_kind,
    })
}

/// `person_tag = PRF(K_tag, CDE([room, person]))`. K_tag is HKDF-SHA-256 over
/// the content master under [`PERSON_TAG_CONTEXT`]. The PRF is HKDF-Expand-SHA-256
/// keyed by K_tag, which is HMAC-SHA-256 under a key derived from K_tag; through
/// `ciris_crypto::kdf`, the one primitive every build links, so no new crypto
/// feature is needed. Keyed per ROOM: one person's tag differs across rooms.
///
/// # Errors
/// The KDF refuses (never, at 32 bytes).
pub fn person_tag(
    master: &[u8; 32],
    room: &str,
    person: &str,
) -> Result<[u8; 32], crate::federation::Error> {
    use ciris_verify_core::cde::{encode, Value};
    let kdf = |ikm: &[u8], info: &[u8]| {
        ciris_crypto::kdf::hkdf_sha256(ikm, &[], info, 32)
            .map_err(|e| backend(ROOM_BINDINGS_TABLE, format!("person_tag: {e}")))
    };
    let k_tag = zeroize::Zeroizing::new(kdf(master, PERSON_TAG_CONTEXT.as_bytes())?);
    let input = encode(&Value::Array(vec![
        Value::Text(room.to_owned()),
        Value::Text(person.to_owned()),
    ]));
    let tag = kdf(&k_tag, &input)?;
    <[u8; 32]>::try_from(tag.as_slice()).map_err(|_| backend(ROOM_BINDINGS_TABLE, "a 32-byte tag"))
}

/// Seal `(person, nonce)` under the master: `CDE([TIE_LABEL, person, nonce])`,
/// in `seal_content_kem_private`'s format.
///
/// # Errors
/// The seal fails.
pub fn seal_tie(
    master: &[u8; 32],
    person: &str,
    nonce: &[u8; 32],
) -> Result<String, crate::federation::Error> {
    use ciris_verify_core::cde::{encode, Value};
    let plain = zeroize::Zeroizing::new(encode(&Value::Array(vec![
        Value::Text(TIE_LABEL.to_owned()),
        Value::Text(person.to_owned()),
        Value::Bytes(nonce.to_vec()),
    ])));
    crate::federation::identity_aggregate::seal_content_kem_private(master, &plain)
        .map_err(|e| backend(ROOM_BINDINGS_TABLE, format!("seal: {e}")))
}

/// Open a tie sealed by [`seal_tie`].
///
/// # Errors
/// It does not open under `master`, or it is not a tie (the label, the shape).
pub fn open_tie(
    master: &[u8; 32],
    sealed: &str,
) -> Result<(String, [u8; 32]), crate::federation::Error> {
    use ciris_verify_core::cde::{decode, Value};
    let refuse = |why: &str| {
        backend(
            ROOM_BINDINGS_TABLE,
            format!("a sealed tie does not open here ({why}); refusing to read it as absent"),
        )
    };
    let plain = crate::federation::identity_aggregate::unseal_content_kem_private(master, sealed)
        .map_err(|e| refuse(&e.to_string()))?;
    let v = decode(&plain).map_err(|_| refuse("not CDE"))?;
    match v.as_array() {
        Some([Value::Text(l), Value::Text(person), Value::Bytes(n)]) if l == TIE_LABEL => {
            let nonce = <[u8; 32]>::try_from(n.as_slice()).map_err(|_| refuse("nonce"))?;
            Ok((person.clone(), nonce))
        }
        _ => Err(refuse("not a binding tie")),
    }
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
fn open_binding_row(
    (kid, made_for, room_id, key_kind, sealed, received_at_us): SealedBindingRow,
    seal: &TieSeal,
) -> Result<RoomBinding, crate::federation::Error> {
    if key_kind != seal.key_kind {
        return Err(backend(
            ROOM_BINDINGS_TABLE,
            format!(
                "a binding sealed under a {key_kind} content master, which this node (now {}) \
                 does not hold; refusing to read it as absent",
                seal.key_kind
            ),
        ));
    }
    let (person, nonce) = open_tie(&seal.master, &sealed)?;
    Ok(RoomBinding {
        room_key_kid: kid_of(kid, ROOM_BINDINGS_TABLE)?,
        made_for,
        room_id,
        person,
        nonce,
        received_at_us,
    })
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

/// sqlite: record a binding made for this node, its tie SEALED
/// ([`TieSeal`]). A second one for the same `(room_key_kid, made_for)` is a
/// no-op (`Ok(false)`): the first is kept.
///
/// # Errors
/// sqlite errors; a seal that fails.
#[cfg(feature = "sqlite")]
pub fn put_room_binding_sqlite(
    conn: &rusqlite::Connection,
    b: &RoomBinding,
    seal: &TieSeal,
) -> Result<bool, crate::federation::Error> {
    let tag = person_tag(&seal.master, &b.room_id, &b.person)?;
    let tie = seal_tie(&seal.master, &b.person, &b.nonce)?;
    let n = conn
        .execute(
            "INSERT INTO ceg_room_bindings \
             (room_key_kid, made_for, room_id, person_tag, tie_key_kind, tie_sealed_b64, \
              received_at_us) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
             ON CONFLICT (room_key_kid, made_for) DO NOTHING",
            rusqlite::params![
                b.room_key_kid.as_slice(),
                b.made_for,
                b.room_id,
                tag.as_slice(),
                seal.key_kind,
                tie,
                b.received_at_us
            ],
        )
        .map_err(|e| backend(ROOM_BINDINGS_TABLE, e))?;
    Ok(n == 1)
}

/// The columns a binding row is read back from.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
type SealedBindingRow = (Vec<u8>, String, String, String, String, i64);

#[cfg(feature = "sqlite")]
fn sealed_binding_rows_sqlite(
    conn: &rusqlite::Connection,
    sql: &str,
    params: &[&dyn rusqlite::ToSql],
) -> Result<Vec<SealedBindingRow>, crate::federation::Error> {
    let be = |e: rusqlite::Error| backend(ROOM_BINDINGS_TABLE, e);
    let mut st = conn.prepare(sql).map_err(be)?;
    let rows = st
        .query_map(params, |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })
        .map_err(be)?;
    rows.map(|r| r.map_err(be)).collect()
}

/// sqlite: the bindings this node holds for `room`, in (key, made_for) order,
/// each tie OPENED under `seal`. A row that does not open is a REFUSAL to read
/// (an `Err`), never a row left out.
///
/// # Errors
/// sqlite errors; a row sealed under another master, or that does not open.
#[cfg(feature = "sqlite")]
pub fn room_bindings_sqlite(
    conn: &rusqlite::Connection,
    room: &str,
    seal: &TieSeal,
) -> Result<Vec<RoomBinding>, crate::federation::Error> {
    let rows = sealed_binding_rows_sqlite(conn, SELECT_BINDINGS_OF_ROOM_SQLITE, &[&room])?;
    rows.into_iter()
        .map(|r| open_binding_row(r, seal))
        .collect()
}

/// sqlite: the bindings this node holds in `room` whose person is `person`,
/// found by [`person_tag`] through the index; only those rows are opened
/// (never a scan that unseals every row).
///
/// # Errors
/// As [`room_bindings_sqlite`].
#[cfg(feature = "sqlite")]
pub fn room_bindings_of_person_sqlite(
    conn: &rusqlite::Connection,
    room: &str,
    person: &str,
    seal: &TieSeal,
) -> Result<Vec<RoomBinding>, crate::federation::Error> {
    let tag = person_tag(&seal.master, room, person)?;
    let rows = sealed_binding_rows_sqlite(
        conn,
        SELECT_BINDINGS_OF_PERSON_SQLITE,
        &[&room, &tag.as_slice()],
    )?;
    rows.into_iter()
        .map(|r| open_binding_row(r, seal))
        .collect()
}

#[cfg(feature = "sqlite")]
const SELECT_BINDINGS_OF_ROOM_SQLITE: &str =
    "SELECT room_key_kid, made_for, room_id, tie_key_kind, tie_sealed_b64, received_at_us \
     FROM ceg_room_bindings WHERE room_id = ?1 ORDER BY room_key_kid, made_for";
#[cfg(feature = "sqlite")]
const SELECT_BINDINGS_OF_PERSON_SQLITE: &str =
    "SELECT room_key_kid, made_for, room_id, tie_key_kind, tie_sealed_b64, received_at_us \
     FROM ceg_room_bindings WHERE room_id = ?1 AND person_tag = ?2 \
     ORDER BY room_key_kid, made_for";

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
/// postgres errors; a seal that fails.
#[cfg(feature = "postgres")]
pub async fn put_room_binding_postgres<C>(
    client: &C,
    b: &RoomBinding,
    seal: &TieSeal,
) -> Result<bool, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let tag = person_tag(&seal.master, &b.room_id, &b.person)?;
    let tie = seal_tie(&seal.master, &b.person, &b.nonce)?;
    let kid: &[u8] = &b.room_key_kid;
    let tag: &[u8] = &tag;
    let n = client
        .execute(
            "INSERT INTO cirislens.ceg_room_bindings \
             (room_key_kid, made_for, room_id, person_tag, tie_key_kind, tie_sealed_b64, \
              received_at_us) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (room_key_kid, made_for) DO NOTHING",
            &[
                &kid,
                &b.made_for,
                &b.room_id,
                &tag,
                &seal.key_kind,
                &tie,
                &b.received_at_us,
            ],
        )
        .await
        .map_err(|e| backend(ROOM_BINDINGS_TABLE, e))?;
    Ok(n == 1)
}

#[cfg(feature = "postgres")]
async fn sealed_binding_rows_postgres<C>(
    client: &C,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
) -> Result<Vec<SealedBindingRow>, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let rows = client
        .query(sql, params)
        .await
        .map_err(|e| backend(ROOM_BINDINGS_TABLE, e))?;
    Ok(rows
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4), r.get(5)))
        .collect())
}

/// postgres: [`room_bindings_sqlite`].
///
/// # Errors
/// As [`room_bindings_sqlite`].
#[cfg(feature = "postgres")]
pub async fn room_bindings_postgres<C>(
    client: &C,
    room: &str,
    seal: &TieSeal,
) -> Result<Vec<RoomBinding>, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let rows =
        sealed_binding_rows_postgres(client, SELECT_BINDINGS_OF_ROOM_POSTGRES, &[&room]).await?;
    rows.into_iter()
        .map(|r| open_binding_row(r, seal))
        .collect()
}

/// postgres: [`room_bindings_of_person_sqlite`].
///
/// # Errors
/// As [`room_bindings_sqlite`].
#[cfg(feature = "postgres")]
pub async fn room_bindings_of_person_postgres<C>(
    client: &C,
    room: &str,
    person: &str,
    seal: &TieSeal,
) -> Result<Vec<RoomBinding>, crate::federation::Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let tag = person_tag(&seal.master, room, person)?;
    let tag: &[u8] = &tag;
    let rows =
        sealed_binding_rows_postgres(client, SELECT_BINDINGS_OF_PERSON_POSTGRES, &[&room, &tag])
            .await?;
    rows.into_iter()
        .map(|r| open_binding_row(r, seal))
        .collect()
}

#[cfg(feature = "postgres")]
const SELECT_BINDINGS_OF_ROOM_POSTGRES: &str =
    "SELECT room_key_kid, made_for, room_id, tie_key_kind, tie_sealed_b64, received_at_us \
     FROM cirislens.ceg_room_bindings WHERE room_id = $1 ORDER BY room_key_kid, made_for";
#[cfg(feature = "postgres")]
const SELECT_BINDINGS_OF_PERSON_POSTGRES: &str =
    "SELECT room_key_kid, made_for, room_id, tie_key_kind, tie_sealed_b64, received_at_us \
     FROM cirislens.ceg_room_bindings WHERE room_id = $1 AND person_tag = $2 \
     ORDER BY room_key_kid, made_for";

// ─────────────────────────────────────────────────────────────────────────
//  ROOMKEY-E1 — erasure (the lead's item 12; CC 3.1.3.2 "What a private
//  room does not give"). One function per case; none reaches another device.
// ─────────────────────────────────────────────────────────────────────────

fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// sqlite, case (a): THIS device drops `room`'s rows, and with them the
/// bindings it holds in that room and its pending exchanges there. "The
/// remaining members' devices keep the removed voice's binding for as long as
/// they keep that voice's rows". Room keys and KEM secrets are untouched.
///
/// # Errors
/// sqlite errors (nothing is removed: one transaction).
#[cfg(feature = "sqlite")]
pub fn drop_room_bindings_sqlite(
    conn: &mut rusqlite::Connection,
    room: &str,
) -> Result<RoomErasure, crate::federation::Error> {
    let be = |e: rusqlite::Error| backend(ROOM_BINDINGS_TABLE, e);
    let tx = conn.transaction().map_err(be)?;
    let exchanges = tx
        .execute(
            "DELETE FROM ceg_room_binding_exchanges WHERE room_id = ?1",
            [room],
        )
        .map_err(be)?;
    let bindings = tx
        .execute("DELETE FROM ceg_room_bindings WHERE room_id = ?1", [room])
        .map_err(be)?;
    tx.commit().map_err(be)?;
    Ok(RoomErasure {
        exchanges: count(exchanges),
        bindings: count(bindings),
        ..RoomErasure::default()
    })
}

/// sqlite, case (b): a PERSON's erasure on one of the person's OWN devices.
/// It deletes the room keys this device holds for `person` (`acts_for`),
/// each one's sealed KEM secret, the exchanges addressed to those keys, and
/// the person's own room-binding KEM secret(s). The voice's withdrawals of
/// its rows are the host's signed acts, made BEFORE this (from
/// `edition2_room_keys_held`). Nothing here names the person to another
/// device, and the bindings this device holds OF OTHERS are kept (case (c)
/// takes those).
///
/// # Errors
/// sqlite errors (nothing is removed: one transaction).
#[cfg(feature = "sqlite")]
pub fn erase_person_room_keys_sqlite(
    conn: &mut rusqlite::Connection,
    person: &str,
) -> Result<RoomErasure, crate::federation::Error> {
    let be = |e: rusqlite::Error| backend(ROOM_KEYS_TABLE, e);
    let tx = conn.transaction().map_err(be)?;
    let kids: Vec<Vec<u8>> = {
        let mut st = tx
            .prepare("SELECT room_key_kid FROM ceg_room_keys_local WHERE acts_for = ?1")
            .map_err(be)?;
        let rows = st.query_map([person], |r| r.get(0)).map_err(be)?;
        rows.collect::<Result<_, _>>().map_err(be)?
    };
    let mut out = RoomErasure::default();
    for kid in &kids {
        let addressee =
            ciris_verify_core::edition2::identity_ref(&kid_of(kid.clone(), ROOM_KEYS_TABLE)?);
        out.kem_secrets += count(
            tx.execute(
                "DELETE FROM ceg_room_kem_secrets WHERE room_key_kid = ?1",
                [kid.as_slice()],
            )
            .map_err(be)?,
        );
        out.exchanges += count(
            tx.execute(
                "DELETE FROM ceg_room_binding_exchanges WHERE made_for = ?1",
                [&addressee],
            )
            .map_err(be)?,
        );
        out.room_keys += count(
            tx.execute(
                "DELETE FROM ceg_room_keys_local WHERE room_key_kid = ?1",
                [kid.as_slice()],
            )
            .map_err(be)?,
        );
    }
    out.kem_secrets += count(
        tx.execute(
            "DELETE FROM ceg_room_kem_secrets WHERE identity_ref = ?1",
            [person],
        )
        .map_err(be)?,
    );
    tx.commit().map_err(be)?;
    Ok(out)
}

/// sqlite, case (c): the owner erases their account or retires THIS device.
/// Every node-local room table is emptied, in one transaction: the device's
/// own room keys (their signing halves are the host's), their sealed KEM
/// secrets, its pending exchanges, and the bindings it holds of others.
///
/// # Errors
/// sqlite errors (nothing is removed: one transaction).
#[cfg(feature = "sqlite")]
pub fn erase_room_device_state_sqlite(
    conn: &mut rusqlite::Connection,
) -> Result<RoomErasure, crate::federation::Error> {
    let be = |e: rusqlite::Error| backend(ROOM_KEYS_TABLE, e);
    let tx = conn.transaction().map_err(be)?;
    let out = RoomErasure {
        exchanges: count(
            tx.execute("DELETE FROM ceg_room_binding_exchanges", [])
                .map_err(be)?,
        ),
        bindings: count(
            tx.execute("DELETE FROM ceg_room_bindings", [])
                .map_err(be)?,
        ),
        kem_secrets: count(
            tx.execute("DELETE FROM ceg_room_kem_secrets", [])
                .map_err(be)?,
        ),
        room_keys: count(
            tx.execute("DELETE FROM ceg_room_keys_local", [])
                .map_err(be)?,
        ),
    };
    tx.commit().map_err(be)?;
    Ok(out)
}

/// postgres: [`drop_room_bindings_sqlite`].
///
/// # Errors
/// postgres errors (nothing is removed: one transaction).
#[cfg(feature = "postgres")]
pub async fn drop_room_bindings_postgres(
    client: &mut deadpool_postgres::Object,
    room: &str,
) -> Result<RoomErasure, crate::federation::Error> {
    let be = |e: tokio_postgres::Error| backend(ROOM_BINDINGS_TABLE, e);
    let tx = client.transaction().await.map_err(be)?;
    let exchanges = tx
        .execute(
            "DELETE FROM cirislens.ceg_room_binding_exchanges WHERE room_id = $1",
            &[&room],
        )
        .await
        .map_err(be)?;
    let bindings = tx
        .execute(
            "DELETE FROM cirislens.ceg_room_bindings WHERE room_id = $1",
            &[&room],
        )
        .await
        .map_err(be)?;
    tx.commit().await.map_err(be)?;
    Ok(RoomErasure {
        exchanges,
        bindings,
        ..RoomErasure::default()
    })
}

/// postgres: [`erase_person_room_keys_sqlite`].
///
/// # Errors
/// postgres errors (nothing is removed: one transaction).
#[cfg(feature = "postgres")]
pub async fn erase_person_room_keys_postgres(
    client: &mut deadpool_postgres::Object,
    person: &str,
) -> Result<RoomErasure, crate::federation::Error> {
    let be = |e: tokio_postgres::Error| backend(ROOM_KEYS_TABLE, e);
    let tx = client.transaction().await.map_err(be)?;
    let kids: Vec<Vec<u8>> = tx
        .query(
            "SELECT room_key_kid FROM cirislens.ceg_room_keys_local WHERE acts_for = $1",
            &[&person],
        )
        .await
        .map_err(be)?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let mut out = RoomErasure::default();
    for kid in &kids {
        let addressee =
            ciris_verify_core::edition2::identity_ref(&kid_of(kid.clone(), ROOM_KEYS_TABLE)?);
        let k: &[u8] = kid;
        out.kem_secrets += tx
            .execute(
                "DELETE FROM cirislens.ceg_room_kem_secrets WHERE room_key_kid = $1",
                &[&k],
            )
            .await
            .map_err(be)?;
        out.exchanges += tx
            .execute(
                "DELETE FROM cirislens.ceg_room_binding_exchanges WHERE made_for = $1",
                &[&addressee],
            )
            .await
            .map_err(be)?;
        out.room_keys += tx
            .execute(
                "DELETE FROM cirislens.ceg_room_keys_local WHERE room_key_kid = $1",
                &[&k],
            )
            .await
            .map_err(be)?;
    }
    out.kem_secrets += tx
        .execute(
            "DELETE FROM cirislens.ceg_room_kem_secrets WHERE identity_ref = $1",
            &[&person],
        )
        .await
        .map_err(be)?;
    tx.commit().await.map_err(be)?;
    Ok(out)
}

/// postgres: [`erase_room_device_state_sqlite`].
///
/// # Errors
/// postgres errors (nothing is removed: one transaction).
#[cfg(feature = "postgres")]
pub async fn erase_room_device_state_postgres(
    client: &mut deadpool_postgres::Object,
) -> Result<RoomErasure, crate::federation::Error> {
    let be = |e: tokio_postgres::Error| backend(ROOM_KEYS_TABLE, e);
    let tx = client.transaction().await.map_err(be)?;
    let exchanges = tx
        .execute("DELETE FROM cirislens.ceg_room_binding_exchanges", &[])
        .await
        .map_err(be)?;
    let bindings = tx
        .execute("DELETE FROM cirislens.ceg_room_bindings", &[])
        .await
        .map_err(be)?;
    let kem_secrets = tx
        .execute("DELETE FROM cirislens.ceg_room_kem_secrets", &[])
        .await
        .map_err(be)?;
    let room_keys = tx
        .execute("DELETE FROM cirislens.ceg_room_keys_local", &[])
        .await
        .map_err(be)?;
    let out = RoomErasure {
        room_keys,
        kem_secrets,
        exchanges,
        bindings,
    };
    tx.commit().await.map_err(be)?;
    Ok(out)
}
