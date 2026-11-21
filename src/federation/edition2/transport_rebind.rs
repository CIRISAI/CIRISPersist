//! v62.0.0 (wave W1; CC 3.1.3 `transport:canonical_rebind`, CC 3.3.6.2 "A
//! seat's transit key", CC 3.4.7, CC 5.3.4) — **the counted re-bind of a
//! seat's transit key, in edition 2.**
//!
//! A seat of the genesis bundle in force takes its X-Wing transit key first
//! from its binding in the bundle. The key moves only by a
//! `transport:canonical_rebind` row about the seat, counted by the accord's
//! holders, or by a later bundle that re-seats the seat on new keys. A
//! binding the seat publishes itself that carries another key is not
//! honoured (CC 3.3.6.2: "a node of this form takes a seat's
//! `transit_xwing_pubkey` from the bundle or from such a re-bind, and a
//! seat's own binding that carries another key is not honoured").
//!
//! # The row
//!
//! Family `transport:canonical_rebind` (counted: no `author`; Verify's family
//! model `"counted"`), row type `scores`, `sub` = the seat's identity-ref.
//! Payload (`edition2::payloads`): `transit_xwing_pubkey` (bstr, 1216 bytes,
//! required), `onion_hop_xwing_pubkey` and `transport_destination`
//! (optional), and `refs.head` (required) naming the genesis bundle in force
//! the re-bind is counted over (its object id). Every voice is one holder's
//! statement over the same payload (CC 2.6.1.9).
//!
//! # The count (CC ruling, 2026-11-18)
//!
//! A STRICT MAJORITY (⌊n/2⌋ + 1) of the holders of the bundle in force, over
//! the `refs.head` naming that bundle. A later bundle that re-seats the node
//! with new X-Wing keys is the other path; both stand.
//!
//! # The door ([`put_rebind_voice`])
//!
//! - No genesis bundle held, or `refs.head` names a bundle this node does not
//!   hold: the voice WAITS (the retryable unknown-signer error naming
//!   `ceg-genesis-bundle/2:<hex>`), as the genesis door waits.
//! - `refs.head` names a held bundle that is not in force (a predecessor of
//!   the head): judged against THAT bundle (v62.0.0, KR-fix2 rev 3;
//!   Constitution's ruling, CC rc22 7b4a55e). Its voices count only when
//!   their own `asserted_at` is before the `asserted_at` of the next bundle
//!   of the lineage this node holds; a voice dated at or after it is kept and
//!   counts nothing. (Before: held `rebind_head_not_in_force`, which made the
//!   outcome depend on which arrived first.)
//! - `sub` is not a seat of the bundle the re-bind names, or the signer is not
//!   a holder of it at its placed key: refused `reserved_family_unseated`
//!   (CC 3.4.7). A seat signing its own re-bind is refused by this rule.
//! - A transit key that is not 1216 bytes: `xwing_pubkey_wrong_length`.
//! - Otherwise the voice is kept. The row is `Row` once its distinct holder
//!   voices reach the count ([`accord_threshold`](crate::federation::admission::accord_threshold), the one spelling), `Pending` before.
//!
//! # The read ([`seat_transit_key`], [`rebind_held_for`])
//!
//! The seat's binding was seeded by the earliest bundle of the unbroken run
//! (back from the newest Valid bundle) that seats it with its current
//! transit key. A re-bind applies when its `refs.head` names a bundle of that
//! run and its voices reach a strict majority of THAT bundle's holders. The
//! live key is the latest such re-bind's (by `asserted_at`, then row id), or
//! else the binding's. A later bundle that re-seats the seat on new keys
//! starts a new run, so the re-binds over older bundles no longer apply and
//! the new binding's key is live.

use std::collections::{BTreeMap, BTreeSet};

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::genesis::{
    GenesisPlacement, PlacedHolder, PlacedSeat, XWING_PUBKEY_LEN,
};
use ciris_verify_core::edition2::Digest32;

use super::door::{AdmittedRow, PLANE};
use super::genesis::{genesis_in_force, GenesisInForce, GENESIS_BUNDLE_TYP};
use super::ingest::StatementOutcome;
use super::liveness::statement_parts;
use super::names::{names_of, single, RowId};
use crate::federation::{malformed_row, Error, FederationDirectory};

/// The family id (header -70002) of a re-bind row.
pub const REBIND_FAMILY: &str = "transport:canonical_rebind";

/// The row type a re-bind is signed under (an attestation row about the
/// seat, CC 3.1.3).
pub const REBIND_ROW_TYPE: &str = "scores";

/// The payload member carrying the new transit key.
pub const TRANSIT_MEMBER: &str = "transit_xwing_pubkey";

/// The `refs` role naming the bundle a re-bind is counted over.
pub const HEAD_ROLE: &str = "head";

fn unseated(detail: impl Into<String>) -> Error {
    Error::malformed_row(PLANE, malformed_row::RESERVED_FAMILY_UNSEATED, detail)
}

fn invalid(detail: impl Into<String>) -> Error {
    Error::malformed_row(PLANE, malformed_row::EDITION2_PAYLOAD_INVALID, detail)
}

/// The signer of a voice, if it is one of `holders` at its placed key: its
/// identity-ref.
fn holder_of(holders: &[PlacedHolder], iss: &str, kid: &Digest32) -> Option<String> {
    holders
        .iter()
        .find(|h| h.identity_ref == iss && h.kid == *kid)
        .map(|h| h.identity_ref.clone())
}

/// A voice's `iss` and `kid`, read from its protected header.
fn signer_of(statement: &[u8]) -> Option<(String, Digest32)> {
    let (protected, _) = statement_parts(statement)?;
    let iss = protected
        .get_int(15)?
        .get_int(1)?
        .as_text()
        .map(str::to_owned)?;
    let kid = <[u8; 32]>::try_from(protected.get_int(4)?.as_bytes()?).ok()?;
    Some((iss, kid))
}

/// The distinct `holders` among `voices`.
fn counted_holders(holders: &[PlacedHolder], voices: &[Vec<u8>]) -> BTreeSet<String> {
    voices
        .iter()
        .filter_map(|v| signer_of(v.as_slice()))
        .filter_map(|(iss, kid)| holder_of(holders, &iss, &kid))
        .collect()
}

/// v62.0.0 (KR-fix2 rev 3; CC rc22 7b4a55e) — the voices of a re-bind over
/// the bundle `named` that still count: those dated before the next bundle
/// of the lineage this node holds
/// ([`trust_root_group::voices_before_successor`](super::trust_root_group::voices_before_successor),
/// the one function a counted grant from the root uses too). The door and
/// the read ([`latest_counted_rebind`]) both count through it.
fn counting_voices(
    in_force: &GenesisInForce,
    named: &Digest32,
    voices: Vec<Vec<u8>>,
) -> Vec<Vec<u8>> {
    super::trust_root_group::voices_before_successor(in_force, named, voices, |v| {
        statement_parts(v.as_slice())
            .and_then(|(_, p)| p.get_text("asserted_at").and_then(Value::as_u64))
    })
}

/// v62.0.0 (KR-fix2 rev 5) — **does a re-bind over the bundle `named` reach
/// its count on `voices`?** The distinct holders of `named`, at the key each
/// signed with, among the voices that still count ([`counting_voices`]),
/// against the one threshold. THE count of a re-bind: the door
/// ([`put_rebind_voice`]), the verdict readers ([`latest_counted_rebind`],
/// behind [`seat_transit_key`] and [`rebind_held_for`]) and the host listings
/// ([`rebind_counted`]) all ask it, so none of them can disagree with
/// another.
fn counts(in_force: &GenesisInForce, named: &GenesisPlacement, voices: Vec<Vec<u8>>) -> bool {
    let voices = counting_voices(in_force, &named.object_id, voices);
    counted_holders(&named.holders, &voices).len()
        >= crate::federation::admission::accord_threshold(named.holders.len())
}

/// v62.0.0 (KR-fix2 rev 5) — **is the held row `row_id` a re-bind, and does
/// it reach its count NOW?** `None`: no re-bind voice is held under the id.
/// `Some(true)`: counted ([`counts`]). `Some(false)`: held and short (its
/// bundle is not held, or too few of its holders' voices are in time).
///
/// The host listings read this in place of the fold's stored state
/// (`fold::why_held_listed`, `second_signer_voice::row_status`). The re-bind
/// plane is FINAL, so the stored state is whatever the door answered when
/// the last voice arrived: a node that held the voices before a later bundle
/// stores "concluded", a node that held the bundle first stores "held", for
/// one and the same row. This reading has no arrival order in it.
///
/// # Errors
/// Directory read failures.
pub async fn rebind_counted<F>(dir: &F, row_id: &RowId) -> Result<Option<bool>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let voices = dir.edition2_voices(row_id).await?;
    let Some(first) = voices.first() else {
        return Ok(None);
    };
    if super::emit::family_of_statement(first).is_none_or(|(family, _)| family != REBIND_FAMILY) {
        return Ok(None);
    }
    let Some(head) = statement_parts(first.as_slice()).and_then(|(_, p)| head_of(&p)) else {
        return Ok(Some(false));
    };
    let in_force = genesis_in_force(dir).await?;
    let Some(named) = in_force.valid.iter().find(|p| p.object_id == head.0) else {
        return Ok(Some(false));
    };
    Ok(Some(counts(&in_force, named, voices)))
}

/// v62.0.0 (KR-fix2 rev 8) — **who may still voice the held re-bind
/// `row_id`**: the holders of the bundle it names
/// ([`trust_root_group::bundle_holders`](super::trust_root_group::bundle_holders)),
/// when the row is a re-bind that does NOT count now ([`counts`]) and a
/// further voice could still make it count (its `asserted_at`, which every
/// voice shares, is before the next held bundle of the lineage). `None`: not
/// a re-bind held here, its bundle not held, already counted, or dated out.
///
/// What `second_signer_voice::held_rows_for` lists a re-bind by, in the role
/// `root_holder`. Recomputed from the held lineage and the voices' signed
/// instants, never the fold's stored state, so two nodes that hold the same
/// rows list the same re-binds.
///
/// # Errors
/// Directory read failures.
pub async fn rebind_voice_parties<F>(dir: &F, row_id: &RowId) -> Result<Option<Vec<String>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let voices = dir.edition2_voices(row_id).await?;
    let Some(first) = voices.first() else {
        return Ok(None);
    };
    if super::emit::family_of_statement(first).is_none_or(|(family, _)| family != REBIND_FAMILY) {
        return Ok(None);
    }
    let Some((_, payload)) = statement_parts(first.as_slice()) else {
        return Ok(None);
    };
    let Some(head) = head_of(&payload) else {
        return Ok(None);
    };
    let in_force = genesis_in_force(dir).await?;
    let Some(named) = in_force.valid.iter().find(|p| p.object_id == head.0) else {
        return Ok(None);
    };
    let at = payload.get_text("asserted_at").and_then(Value::as_u64);
    if in_force
        .successor_instant(&named.object_id)
        .is_some_and(|next| at.is_none_or(|a| a >= next))
    {
        return Ok(None);
    }
    if counts(&in_force, named, voices) {
        return Ok(None);
    }
    Ok(super::trust_root_group::bundle_holders(
        &in_force,
        &named.object_id,
    ))
}

/// The transit key a re-bind payload carries, when it is exactly 1216 bytes.
fn transit_of(payload: &Value) -> Option<[u8; XWING_PUBKEY_LEN]> {
    payload
        .get_text(TRANSIT_MEMBER)
        .and_then(Value::as_bytes)
        .and_then(|b| <[u8; XWING_PUBKEY_LEN]>::try_from(b).ok())
}

/// The bundle a re-bind payload's `refs.head` names.
fn head_of(payload: &Value) -> Option<RowId> {
    names_of(payload)
        .ok()
        .and_then(|names| single(&names, HEAD_ROLE))
}

fn waiting_on_bundle(head: &RowId) -> Error {
    Error::unknown_signer(&format!("{GENESIS_BUNDLE_TYP}:{}", head.hex()), PLANE)
}

/// **The re-bind door**: one voice of a `transport:canonical_rebind` row
/// (see the module doc).
///
/// # Errors
/// `reserved_family_unseated`, `edition2_payload_invalid`,
/// `xwing_pubkey_wrong_length`; the retryable unknown-signer wait for a
/// bundle not held; storage failures.
pub async fn put_rebind_voice<F>(dir: &F, row: &AdmittedRow) -> Result<StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(head) = single(&row.names, HEAD_ROLE) else {
        return Err(invalid(format!(
            "{REBIND_FAMILY}: `refs.head` names the genesis bundle in force the re-bind is \
             counted over"
        )));
    };
    // v62.0.0 (wave GC5; CC 2.7.3) — the bundle it names is an input (the
    // re-bind plane is FINAL: it reads the row's NAMED past only).
    super::fold::reads(super::fold::Dep::Row(head));
    let in_force = genesis_in_force(dir).await?;
    // v62.0.0 (KR-fix2 rev 3; Constitution's ruling, CC rc22 7b4a55e) — a
    // re-bind is judged against the bundle it NAMES, in force or not: the
    // named bundle must be in this node's held Valid lineage (else the voice
    // waits on it). A later bundle no longer HOLDS the voice
    // (`rebind_head_not_in_force` is retired from this door): what a later
    // bundle changes is which voices COUNT, by their own signed instant
    // (`voices_before_successor` below), so the verdict does not depend on
    // which arrived first.
    let Some(named) = in_force.valid.iter().find(|p| p.object_id == head.0) else {
        return Err(waiting_on_bundle(&head));
    };
    if !named.seats.iter().any(|s| s.identity_ref == row.sub) {
        return Err(unseated(format!(
            "{REBIND_FAMILY}: {} is not a seat of the genesis bundle the re-bind names",
            row.sub
        )));
    }
    if holder_of(&named.holders, &row.iss, &row.kid).is_none() {
        return Err(unseated(format!(
            "{REBIND_FAMILY}: {} is not a holder of the genesis bundle the re-bind names, at the \
             key it signed with; only the accord's holders re-bind a seat (CC 3.4.7)",
            row.iss
        )));
    }
    // v62.0.0 (KR-fix2 rev 8) — each holder of the named bundle is a party
    // whose voice this row may wait for: declared as a read (as a counted
    // grant from the root declares them), so the row is indexed under every
    // holder's key and `held_rows_for(holder, "root_holder")` finds it
    // ([`rebind_voice_parties`]). A monotone trigger on this FINAL plane
    // (`fold::enforce_final_plane`): it only re-runs a held row.
    for h in &named.holders {
        super::fold::reads(super::fold::Dep::key(&h.identity_ref));
    }
    if transit_of(&row.payload).is_none() {
        return Err(Error::malformed_row(
            PLANE,
            malformed_row::XWING_PUBKEY_WRONG_LENGTH,
            format!("{REBIND_FAMILY}: `{TRANSIT_MEMBER}` is not {XWING_PUBKEY_LEN} bytes"),
        ));
    }
    let new = dir.put_edition2_statement(row).await?;
    Ok(
        if counts(&in_force, named, dir.edition2_voices(&row.row_id).await?) {
            StatementOutcome::Row {
                row_id: row.row_id,
                new,
            }
        } else {
            StatementOutcome::Pending {
                row_id: row.row_id,
                new,
            }
        },
    )
}

/// The bundles of the run that seeded the seat's current binding: back from
/// the newest Valid bundle, every bundle that seats it with its current
/// transit key, until the first that does not.
fn seeding_run<'a>(in_force: &'a GenesisInForce, seat: &PlacedSeat) -> Vec<&'a GenesisPlacement> {
    let mut run = Vec::new();
    for p in in_force.valid.iter().rev() {
        match p.seats.iter().find(|s| s.identity_ref == seat.identity_ref) {
            Some(s) if s.transit_xwing_pubkey == seat.transit_xwing_pubkey => run.push(p),
            _ => break,
        }
    }
    run
}

/// A counted re-bind of a seat's transit key that applies now
/// ([`rebind_held_for`], [`seat_transit_key`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldRebind {
    /// The re-bind row's id (node-computed).
    pub row_id: RowId,
    /// The transit key it carries (`transit_xwing_pubkey`, 1216 bytes).
    pub transit_xwing_pubkey: [u8; XWING_PUBKEY_LEN],
    /// The bundle it is counted over (`refs.head`): a bundle of the seat's
    /// seeding run.
    pub head: RowId,
}

/// The latest re-bind about `seat` counted over a bundle of its seeding run
/// (by `asserted_at`, then row id), or `None`.
async fn latest_counted_rebind<F>(
    dir: &F,
    in_force: &GenesisInForce,
    seat: &PlacedSeat,
) -> Result<Option<HeldRebind>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let run = seeding_run(in_force, seat);
    let mut rows: BTreeMap<RowId, Vec<Vec<u8>>> = BTreeMap::new();
    for st in dir
        .edition2_statements_about(REBIND_FAMILY, &seat.identity_ref)
        .await?
    {
        if let Some(id) = RowId::of_statement(&st) {
            rows.entry(id).or_default().push(st);
        }
    }
    let mut best: Option<(u64, HeldRebind)> = None;
    for (id, voices) in rows {
        let Some((_, payload)) = voices.first().and_then(|v| statement_parts(v.as_slice())) else {
            continue;
        };
        let Some(head) = head_of(&payload) else {
            continue;
        };
        let Some(over) = run.iter().find(|p| p.object_id == head.0) else {
            continue;
        };
        // Only voices dated before the next held bundle of the lineage
        // count (KR-fix2 rev 3; the door's own filter).
        if !counts(in_force, over, voices) {
            continue;
        }
        let Some(at) = payload.get_text("asserted_at").and_then(Value::as_u64) else {
            continue;
        };
        let Some(key) = transit_of(&payload) else {
            continue;
        };
        if best
            .as_ref()
            .is_none_or(|(b_at, b)| (at, id) > (*b_at, b.row_id))
        {
            best = Some((
                at,
                HeldRebind {
                    row_id: id,
                    transit_xwing_pubkey: key,
                    head,
                },
            ));
        }
    }
    Ok(best.map(|(_, r)| r))
}

/// **The live transit key of a seat of the bundle in force**: the latest
/// re-bind counted over a bundle of the seeding run, else the binding's key
/// (module doc).
///
/// # Errors
/// Directory read failures.
pub async fn seat_transit_key<F>(
    dir: &F,
    in_force: &GenesisInForce,
    seat: &PlacedSeat,
) -> Result<[u8; XWING_PUBKEY_LEN], Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(latest_counted_rebind(dir, in_force, seat)
        .await?
        .map_or(seat.transit_xwing_pubkey, |r| r.transit_xwing_pubkey))
}

/// v62.0.0 (ceremony gap 2; CC 3.3.6.2, CC 3.4.7) — **is a counted re-bind
/// held for this seat, and live?** The edition-2 answer to Server's
/// pre-roll gate: for `seat_identity_ref`, a seat of the genesis bundle in
/// force, the re-bind whose key is live now (the latest counted over a
/// bundle of the seat's seeding run, as [`seat_transit_key`] reads it).
///
/// `None` when no genesis bundle is held, when `seat_identity_ref` is not a
/// seat of the bundle in force, when no re-bind about it reaches its count,
/// or when every counted re-bind is over a bundle a later re-seat has left
/// behind (the seat's key is then its binding's, and no re-bind is live).
///
/// # Errors
/// Directory read failures.
pub async fn rebind_held_for<F>(
    dir: &F,
    seat_identity_ref: &str,
) -> Result<Option<HeldRebind>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let in_force = genesis_in_force(dir).await?;
    let Some(seat) = in_force.seat(seat_identity_ref) else {
        return Ok(None);
    };
    latest_counted_rebind(dir, &in_force, seat).await
}
