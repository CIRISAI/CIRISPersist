//! v62.0.0 (ROOMKEY-5; CC 3.1.3.2) — **the room-key members of a key
//! record**, read from the key's own held `key:record` rows (the key plane,
//! [`super::liveness`]).
//!
//! Constitution's answers of 11-24 (Q-C1, Q-C2, Q-C5; FREEZE "CONSTITUTION
//! ANSWERED THE ROOM-KEY QUESTIONS"):
//! - [`ROOM`] (`group-ref`) is THE marker: a key record carrying it is a room
//!   key, of that one room; a record without it is no room key. "A room key is
//!   a hybrid key pair that one device makes for this room only" and "MUST
//!   NOT be used in a second room" (p3:365). The end rule reads the record
//!   alone (p2:401).
//! - [`KEM_XWING_PUBKEY`] (`bstr .size 1216`, `pk_M ‖ pk_X`): the room key's
//!   KEM half, which "a wrap for a member is made to" (p3:377). It changes
//!   only by a renewal of the record.
//! - [`SEAT_COMMITMENT`] (`[-16, bstr .size 32]`): the room key's own record
//!   is its seat row and carries its commitment (Q-C5).
//!
//! **What this reads and what it does not.** Only records that verify and
//! keep the end rule ([`HeldKeys::valid_records`]) are read; a record only
//! other keys signed is none. Every valid record of the key must agree on
//! `room` (renewals of one room key name one room): records that disagree,
//! or that mark the key a room key in some records and not in others, are
//! [`RoomKeyReading::Conflicting`] and conclude no room. An ill-typed member
//! is [`RoomKeyReading::Malformed`], never "absent" (a malformed member is a
//! refusal, not an absence). The KEM half and the commitment are the LATEST
//! valid record's (by `asserted_at`, then row id), among those covering
//! the instant asked when one is asked. No refusal token is emitted here:
//! the readings are for the doors that name them (ROOMKEY-9, behind
//! `roomkey_names`), and for the audience and the wraps.
//!
//! v62.0.0 (ROOMKEY-5b; Constitution 11-24, ruling (3)) — the three members
//! come TOGETHER: `kem_xwing_pubkey` and `seat_commitment` are present IFF
//! `room` is, and a record with `room` carries both. A record breaking that is
//! MALFORMED, refused on the row alone (`edition2_payload_invalid`) by the
//! statement door ([`super::door`], the key record's step), through
//! [`members_of_payload`]. So a held record is well formed, and the reader's
//! [`RoomKeyReading::Malformed`] answers only for a record this node did not
//! take through its door.

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::Digest32;

use super::liveness::{statement_parts, HeldKeys, Liveness, ValidRecord};
use crate::federation::self_at_login::XWingPublicKey;
use crate::federation::{Error, FederationDirectory};

/// The key-record member naming the room key's one room (a `group-ref`).
pub const ROOM: &str = "room";
/// The key-record member carrying the room key's X-Wing KEM public key.
pub const KEM_XWING_PUBKEY: &str = "kem_xwing_pubkey";
/// The key-record member carrying the room key's seat commitment.
pub const SEAT_COMMITMENT: &str = "seat_commitment";

/// The room-key members of a room key's record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomKeyMembers {
    /// The one room (a `group-ref`).
    pub room: String,
    /// The KEM half.
    pub kem_xwing_pubkey: XWingPublicKey,
    /// The seat commitment's 32 bytes.
    pub seat_commitment: [u8; 32],
}

/// What a key's held records say of it as a room key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoomKeyReading {
    /// No valid record of the key carries [`ROOM`]: it is no room key.
    NotARoomKey,
    /// A room key of this room.
    Room(RoomKeyMembers),
    /// A valid record carries one of the three members ill-typed.
    Malformed {
        /// The member.
        member: &'static str,
    },
    /// Valid records of the key disagree on [`ROOM`] (two rooms, or marked in
    /// some and not in others): no room is concluded.
    Conflicting,
    /// No valid record of the key is held, or (an instant asked) the key is
    /// not live then: nothing is concluded.
    Unresolved,
}

/// One record's members: `Ok(None)` when it carries none of the three.
///
/// # Errors
/// The first member that breaks the rule, by name:
/// - `room` present and not a `group-ref`;
/// - `kem_xwing_pubkey` missing beside `room`, present without it, or not 1216
///   bytes;
/// - `seat_commitment` missing beside `room`, present without it, or not a
///   hash digest.
pub fn members_of_payload(payload: &Value) -> Result<Option<RoomKeyMembers>, &'static str> {
    let kem = payload.get_text(KEM_XWING_PUBKEY);
    let seat = payload.get_text(SEAT_COMMITMENT);
    let Some(room) = payload.get_text(ROOM) else {
        return match (kem, seat) {
            (None, None) => Ok(None),
            (Some(_), _) => Err(KEM_XWING_PUBKEY),
            (None, Some(_)) => Err(SEAT_COMMITMENT),
        };
    };
    let room = room
        .as_text()
        .filter(|s| super::group_id::is_group_ref(s))
        .ok_or(ROOM)?
        .to_owned();
    let kem_xwing_pubkey = kem
        .and_then(Value::as_bytes)
        .and_then(XWingPublicKey::from_bytes)
        .ok_or(KEM_XWING_PUBKEY)?;
    let seat_commitment = seat.and_then(digest_bytes).ok_or(SEAT_COMMITMENT)?;
    Ok(Some(RoomKeyMembers {
        room,
        kem_xwing_pubkey,
        seat_commitment,
    }))
}

/// `[-16, bstr .size 32]`.
fn digest_bytes(v: &Value) -> Option<[u8; 32]> {
    match v.as_array()? {
        [alg, d] if alg.as_i64() == Some(-16) => {
            d.as_bytes().and_then(|b| <[u8; 32]>::try_from(b).ok())
        }
        _ => None,
    }
}

fn payload_of(v: &ValidRecord) -> Option<Value> {
    statement_parts(&v.statement).map(|(_, p)| p)
}

/// **The reading over held records** (pure): `kid`'s valid records, every
/// one agreeing on [`ROOM`]; the KEM half and the commitment from the latest
/// valid record (covering `at_ms`, when given). With `at_ms` the key must
/// be live then ([`HeldKeys::liveness`]), else [`RoomKeyReading::Unresolved`].
#[must_use]
pub fn room_key_reading(held: &HeldKeys, kid: &Digest32, at_ms: Option<u64>) -> RoomKeyReading {
    if let Some(at) = at_ms {
        if !matches!(held.liveness(kid, at), Liveness::Live(_)) {
            return RoomKeyReading::Unresolved;
        }
    }
    let Ok(valid) = held.valid_records(kid) else {
        return RoomKeyReading::Unresolved;
    };
    let mut read: Vec<(&ValidRecord, Option<RoomKeyMembers>)> = Vec::new();
    for v in &valid {
        let Some(payload) = payload_of(v) else {
            return RoomKeyReading::Unresolved;
        };
        match members_of_payload(&payload) {
            Ok(m) => read.push((v, m)),
            Err(member) => return RoomKeyReading::Malformed { member },
        }
    }
    let rooms: std::collections::BTreeSet<Option<&str>> = read
        .iter()
        .map(|(_, m)| m.as_ref().map(|m| m.room.as_str()))
        .collect();
    match rooms.len() {
        0 => return RoomKeyReading::Unresolved,
        1 if rooms.contains(&None) => return RoomKeyReading::NotARoomKey,
        1 => {}
        _ => return RoomKeyReading::Conflicting,
    }
    read.into_iter()
        .filter(|(v, _)| {
            at_ms.is_none_or(|at| {
                crate::kernel::key_end::within_record(
                    at,
                    v.record.asserted_at,
                    v.record.valid_until,
                )
            })
        })
        .max_by(|(a, _), (b, _)| {
            a.record
                .asserted_at
                .cmp(&b.record.asserted_at)
                .then(a.row_id.cmp(&b.row_id))
        })
        .and_then(|(_, m)| m)
        .map_or(RoomKeyReading::Unresolved, RoomKeyReading::Room)
}

/// [`room_key_reading`] over `dir`'s key plane of `kid`
/// ([`super::ingest::held_keys_for_kid`]).
///
/// # Errors
/// Directory reads.
pub async fn room_key_of<F>(
    dir: &F,
    kid: &Digest32,
    at_ms: Option<u64>,
) -> Result<RoomKeyReading, Error>
where
    F: FederationDirectory + ?Sized,
{
    let held = super::ingest::held_keys_for_kid(dir, kid).await?;
    Ok(room_key_reading(&held, kid, at_ms))
}

/// **Is `kid` a room key, and of which room?** `Some(room)` only on a
/// consistent, well-typed reading ([`RoomKeyReading::Room`]); every other
/// reading is `None` (no room is concluded).
///
/// # Errors
/// Directory reads.
pub async fn is_room_key<F>(dir: &F, kid: &Digest32) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(match room_key_of(dir, kid, None).await? {
        RoomKeyReading::Room(m) => Some(m.room),
        _ => None,
    })
}
