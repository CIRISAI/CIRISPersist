//! v62.0.0 (ROOMKEY-7, the parts that touch no door; CC 3.1.3.2, Constitution
//! 11-24 Q-C6 and "AN AGENT'S VOICE IS ONE ROOM KEY") — **a voice of a private
//! room**.
//!
//! - A VOICE is named by the identity reference of its FIRST room key. That
//!   name keeps naming the voice after the key is evicted.
//! - A person's voice seats further room keys by the self-roster machinery
//!   applied to room keys: an `identity:occurrence` bind placed in the room,
//!   counted by the voice's live keys, cosigned by the new key; eviction is
//!   an `identity:occurrence_revocation` in the voice.
//! - An AGENT's voice is ONE room key and seats no further key by its own
//!   count. A NODE's room key is an owned key and no voice.
//! - On every row of a private room: `iss` = the voice, `kid` = the room key
//!   that signed, and `refs.also.voice` names the head of the voice's key
//!   roster (exactly one row,
//!   [`roomkey_names::VOICE_ROLE`](super::roomkey_names::VOICE_ROLE)).
//!
//! **Kernel's collapse is persist's adapter** (FREEZE "KERNEL on voices"):
//! before a room row counts, the room key that signed it must be a live key
//! of its voice at the head of the voice's own roster that the ROW names.
//! The row then counts as the voice's, once ([`voice_of_room_row`]).
//! Otherwise it concludes nothing.
//!
//! What is here: [`voice_keys_at_head`] (the voice's keys at a named head,
//! over held rows) and the adapter's decision ([`voice_of_room_row`], pure).
//! The door arms that read `refs.also.voice` are NOT here: Verify 23.6.0's
//! reader refuses `voice` at every door. They are cut at the Verify 23.7.0
//! pin (ROOMKEY-7.md, "at the 23.7.0 pin").

use std::collections::BTreeSet;

use super::names::RowId;
use super::room_key_record::{room_key_of, RoomKeyReading};
use crate::federation::{Error, FederationDirectory};

/// A voice's keys at one head of its key roster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceKeys {
    /// The one room the voice speaks in (its first key's record's `room`).
    pub room: String,
    /// The room keys (identity-refs) that speak for the voice at the head.
    pub keys: BTreeSet<String>,
}

/// What the held rows say of `voice` as a voice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoiceRoster {
    /// A voice; its keys at the head.
    Keys(VoiceKeys),
    /// The voice's first key is no (well-formed, consistent) room key, so it
    /// names no voice.
    NotAVoice,
}

/// **The keys of `voice` at `head`** (the head of the voice's key roster a
/// room row names in `refs.also.voice`), read from held rows.
/// - The first key (`voice` itself) must be a room key by its own record
///   ([`room_key_of`]).
/// - An AGENT's voice is that one key (it seats no further key by its own
///   count).
/// - A person's voice is the self roster at `head`
///   ([`crate::federation::self_roster::roster_at_heads`]), keeping only the
///   keys whose own record names the SAME room. A key of another room is no
///   key of this voice in this room.
///
/// # Errors
/// The retryable unknown signer while a row the head reaches is not held or
/// has not landed here (as `roster_at_heads`); directory reads.
pub async fn voice_keys_at_head<F>(dir: &F, voice: &str, head: &RowId) -> Result<VoiceRoster, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(first) = super::ingest::kid_of_identity_ref(voice) else {
        return Ok(VoiceRoster::NotAVoice);
    };
    let RoomKeyReading::Room(m) = room_key_of(dir, &first, None).await? else {
        return Ok(VoiceRoster::NotAVoice);
    };
    let agent = super::ingest::machine_kind_at(dir, &first, None)
        .await?
        .is_some_and(|r| r.holds(crate::federation::types::identity_type::AGENT));
    if agent {
        return Ok(VoiceRoster::Keys(VoiceKeys {
            room: m.room,
            keys: BTreeSet::from([voice.to_owned()]),
        }));
    }
    let roster =
        crate::federation::self_roster::roster_at_heads(dir, voice, std::slice::from_ref(head))
            .await?;
    let mut keys = BTreeSet::new();
    for k in roster {
        if k == voice {
            keys.insert(k);
            continue;
        }
        let Some(kid) = super::ingest::kid_of_identity_ref(&k) else {
            continue;
        };
        if let RoomKeyReading::Room(km) = room_key_of(dir, &kid, None).await? {
            if km.room == m.room {
                keys.insert(k);
            }
        }
    }
    Ok(VoiceRoster::Keys(VoiceKeys { room: m.room, keys }))
}

/// The adapter's answer for one room row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoiceOfRow {
    /// The row counts as this voice's (presented with `signer()` = the voice).
    Voice(String),
    /// The row names no head of a voice's key roster: it concludes nothing.
    NoVoiceHead,
    /// The row's `iss` names no voice.
    NotAVoice,
    /// The voice speaks in another room than the row's.
    OtherRoom,
    /// The signing room key is not a key of the voice at the head the row
    /// names: the row concludes nothing (never counted twice, never counted
    /// as the key).
    NotAKeyOfTheVoice,
}

/// **The adapter's decision, pure**. A row of `room`, `iss` = `voice`, signed
/// by the room key `signer` (identity-ref), naming (`named_head`) a head of
/// the voice's key roster, whose keys at that head are `roster`, counts as
/// the voice's, or concludes nothing.
#[must_use]
pub fn voice_of_room_row(
    room: &str,
    voice: &str,
    signer: &str,
    named_head: bool,
    roster: &VoiceRoster,
) -> VoiceOfRow {
    if !named_head {
        return VoiceOfRow::NoVoiceHead;
    }
    let VoiceRoster::Keys(k) = roster else {
        return VoiceOfRow::NotAVoice;
    };
    if k.room != room {
        return VoiceOfRow::OtherRoom;
    }
    if !k.keys.contains(signer) {
        return VoiceOfRow::NotAKeyOfTheVoice;
    }
    VoiceOfRow::Voice(voice.to_owned())
}
