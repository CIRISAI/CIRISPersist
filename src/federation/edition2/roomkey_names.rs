//! v62.0.0 (ROOMKEY-6; CC 3.1.3.2) — **the names the private-room commit owes,
//! held until it comes.**
//!
//! Constitution's answers (11-24, Q-C7 / A3, Q-R4) give two spellings as
//! FINAL. Every other token, role and family of the room-key form comes with
//! the commit. Persist invents none. A name not yet given is `None` here:
//! - a PRODUCER arm that would write it returns `Unsupported` ("awaiting the
//!   CC commit") and sends no bytes;
//! - a DOOR arm that would refuse by it is reached only through [`typed`].
//!   While `None`, the row takes the path it takes without the arm.
//!
//! The pin step flips a constant to `Some(..)` from the commit's text alone,
//! and the arm's witness then tests the named behaviour. Every use of this
//! module is listed in the ROOMKEY-* notes.

/// FINAL (Q-R4): a room key's `identity:occurrence` placed outside the room
/// its key record's `room` names (p3:365).
pub const ROOM_KEY_OCCURRENCE_OUTSIDE_ROOM: &str = "room_key_occurrence_outside_room";
/// FINAL (Q-R4): a room key's owner binding placed outside the room its key
/// record's `room` names (p3:365, p3:1097).
pub const ROOM_KEY_BINDING_OUTSIDE_ROOM: &str = "room_key_binding_outside_room";
/// FINAL (Constitution 11-24, "AN AGENT'S VOICE IS ONE ROOM KEY"): the fifth
/// `refs.also` role. It is exactly one row-ref, the head of the voice's key
/// roster, on every row of a private room. As it sits inside `refs.also` it is
/// `voice`; [`super::names::names_of`] spells it [`VOICE_NAMES_ROLE`]. The
/// interim role lists (payloads.rs `ALSO_ROLES`, produce.rs `check_refs`) are
/// v62-head's HEAD-fix7. No producer states it before the Verify 23.7.0 pin,
/// because 23.6.0's reader refuses it at every door.
pub const VOICE_ROLE: &str = "voice";
/// [`VOICE_ROLE`] as `names_of` spells a role inside `refs.also`.
pub const VOICE_NAMES_ROLE: &str = "also:voice";

/// T9, the ML-KEM-768 half of `room_binding_xwing_pubkey` reused on its row
/// (the `onion_hop_*_reuse` pattern). Not yet named.
pub const ROOM_BINDING_ML_KEM_768_REUSE: Option<&str> = None;
/// T9, the X25519 half of `room_binding_xwing_pubkey` reused on its row. Not
/// yet named.
pub const ROOM_BINDING_X25519_REUSE: Option<&str> = None;

/// A held name, once given: `Some(token)` arms the door, `None` leaves it
/// unreached.
#[must_use]
pub const fn typed(name: Option<&'static str>) -> Option<&'static str> {
    name
}
