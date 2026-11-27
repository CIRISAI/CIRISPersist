//! v62.0.0 (wave W1; CC 3.2 T2/T7, CC 2.6.1.11, CC 2.7.5) — **a trust-root
//! community counted over the genesis bundle in force.**
//!
//! The trust-root door (`canonical_community`) counted a trust-root
//! community's birth against the accord FAMILY record (`humanity-accord`)
//! and seated founders by that family's roster. A v62 node never holds that
//! record: the accord is the genesis bundle in force (bundle/2 names key
//! records and seat bindings only, and a `group:roster` group is an
//! identity-ref). So every trust-root birth was short and the T7 stalled /
//! restored legs could not be reached. This module re-points the three reads
//! the door makes:
//!
//! - **the holder arm of a founder** ([`is_bundle_holder`]): an identity-ref
//!   that is a holder of the bundle in force (common to every tip);
//! - the birth's accord count (`bundle_quorum_over`) is DELETED (v62.0.0
//!   R2-rooms-b; Constitution 11-24 "CONSTITUTION RULED ROOM ROOTING": "the
//!   holders' birth count … go"): a room's birth is its founders' act;
//! - **a version's voices** ([`version_signers`]): the signers of the held
//!   `group:roster` statements whose typed record is that version (each was
//!   verified at the edition-2 door when it arrived), plus, while the
//!   version's last voice is at its door, the vouched voices
//!   (`group::vouched_signers_for`).
//!
//! A version no held statement maps to (an earlier-form record) answers
//! `None`, and the door keeps its earlier reading.

use std::collections::BTreeSet;

use ciris_verify_core::namespace_match;

use super::genesis::genesis_in_force;
use super::group::{
    prev_head_digest, record_of_roster, roster_view_of_statement, GROUP_ROSTER_PREFIX,
};
use super::liveness::statement_parts;
use super::names::RowId;
use crate::federation::trust_root::SignerCount;
use crate::federation::types::Community;
use crate::federation::{Error, FederationDirectory};

/// Is `key_id` (an identity-ref) a holder of the genesis bundle in force,
/// seated alike by every tip?
///
/// # Errors
/// Directory read failures.
pub async fn is_bundle_holder<F>(dir: &F, key_id: &str) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(holders_in_force(&genesis_in_force(dir).await?)
        .iter()
        .any(|h| h == key_id))
}

/// v62.0.0 (TR-fix2; CC rc21 3.2 T7 "The active founder set", conditions
/// three and four) — **does the holder `key_id` count as an active founder at
/// `when_ms`** beyond being a holder of the bundle in force? Read from
/// signer-stamped rows only, no clock:
///
/// - **`revoked_after`**: no honoured revocation of the holder's placed key is
///   in effect at `when_ms` (a bound at or before it, or a revocation with no
///   bound). "t < the effective revoked_after of f's key".
/// - **not `node`-bearing**: no valid record of that key whose
///   `identity_type` includes `node` is asserted at or before `when_ms`. That
///   covers "a later key record that adds `node` is a resignation at that
///   record's `asserted_at`". At seating the record cannot be node-bearing:
///   Verify's bundle reader requires `accord_holder` on a holder record
///   (`holder_not_accord_holder`), and a set holding `accord_holder` with
///   `node` is refused at the key door (CC 2.4.1.1; I1870). This check is
///   kept for every record of the key anyway (no reliance on door order).
///
/// Returns `(counts, next)`, where `next` is the earliest such instant after
/// `when_ms` (a bound for a cached verdict). A key that is not a holder of
/// the bundle in force answers `(false, None)`.
///
/// # Errors
/// Directory read failures.
pub async fn holder_founder_counts_at<F>(
    dir: &F,
    key_id: &str,
    when_ms: u64,
) -> Result<(bool, Option<u64>), Error>
where
    F: FederationDirectory + ?Sized,
{
    let in_force = genesis_in_force(dir).await?;
    let Some(kid) = in_force
        .holders()
        .iter()
        .find(|h| h.identity_ref == key_id)
        .map(|h| h.kid)
    else {
        return Ok((false, None));
    };
    let held = super::ingest::held_keys_for_kid(dir, &kid).await?;
    let mut next: Option<u64> = None;
    let mut later = |t: u64| {
        if t > when_ms {
            next = Some(next.map_or(t, |n: u64| n.min(t)));
        }
    };
    for r in held.honoured_revocations(&kid) {
        match r.revoked_after {
            None => return Ok((false, None)),
            Some(b) if b <= when_ms => return Ok((false, None)),
            Some(b) => later(b),
        }
    }
    if let Ok(records) = held.valid_records(&kid) {
        for v in records {
            if v.record.identity_type.iter().any(|t| t == "node") {
                if v.record.asserted_at <= when_ms {
                    return Ok((false, None));
                }
                later(v.record.asserted_at);
            }
        }
    }
    Ok((true, next))
}

/// v62.0.0 (KR-fix2; CC 3.2 as ruled 2026-11-21) — **the ONE count over a
/// bundle's holders**: the distinct `holders` (identity-refs) among `signers`,
/// against [`accord_threshold`](crate::federation::admission::accord_threshold)
/// of their number (the strict majority, through the one seam). Shared by the
/// counted grant from the root ([`holders_count_at`]: the holders of the
/// bundle the grant NAMES) and the steward purge. No holder, never met.
#[must_use]
pub fn holders_count(holders: &[String], signers: &BTreeSet<String>) -> SignerCount {
    SignerCount {
        distinct_holders: holders.iter().filter(|h| signers.contains(*h)).count(),
        // TR-fix1 — the ONE spelling of the holders' strict majority.
        required: crate::federation::admission::accord_threshold(holders.len()),
        roster_size: holders.len(),
    }
}

/// v62.0.0 (KR-fix2 rev 3; Constitution's ruling, CC rc22 7b4a55e: "A
/// verdict reads only held rows and signer-stamped instants") — **the voices
/// of a row counted over the bundle `named` that still count**: those whose
/// OWN `asserted_at` is BEFORE the `asserted_at` of the next bundle of the
/// lineage this node holds after `named`
/// ([`GenesisInForce::successor_instant`](super::genesis::GenesisInForce::successor_instant)).
/// With no successor held, every voice counts. A voice with no readable
/// instant never counts once a successor is held.
///
/// The ONE function behind a counted grant from the root
/// (`admission::root_grant_reading`) and a seat re-bind
/// (`transport_rebind`), at the door and at every read. It reads the held
/// lineage and the voices' signed instants only, never which arrived first:
/// a row that concluded on voices dated at or after a successor this node did
/// not yet hold stops counting when that successor lands, so two nodes that
/// receive the row and the successor in opposite orders hold one verdict.
/// NOT applied to halts (`edition2::halt` is unchanged).
#[must_use]
pub fn voices_before_successor<V>(
    state: &super::genesis::GenesisInForce,
    named: &ciris_verify_core::edition2::Digest32,
    voices: Vec<V>,
    asserted_at_ms: impl Fn(&V) -> Option<u64>,
) -> Vec<V> {
    match state.successor_instant(named) {
        None => voices,
        Some(next) => voices
            .into_iter()
            .filter(|v| asserted_at_ms(v).is_some_and(|at| at < next))
            .collect(),
    }
}

/// v62.0.0 (KR-fix2 rev 5; CC 3.2 as ruled 2026-11-21: "the root is the
/// bundle") — **THE holder reader: the holders of one bundle of the held
/// lineage**, as identity-refs in the bundle's own order. `bundle` is a
/// bundle object id (what a counted row's `refs.head` names). `None`: `bundle`
/// is not a Valid placement of the lineage this node holds (not held, or
/// held and not Valid).
///
/// Every reader of "who holds the root" goes through this function: a row
/// counted over the bundle it NAMES ([`holders_count_at`],
/// `admission::root_grant_voice_parties`) reads it directly; "the holders in
/// force" ([`holders_in_force`]) reads it once per tip.
#[must_use]
pub fn bundle_holders(
    state: &super::genesis::GenesisInForce,
    bundle: &ciris_verify_core::edition2::Digest32,
) -> Option<Vec<String>> {
    state
        .valid
        .iter()
        .find(|p| p.object_id == *bundle)
        .map(|p| p.holders.iter().map(|h| h.identity_ref.clone()).collect())
}

/// v62.0.0 (KR-fix2 rev 5) — **the holders in force**: [`bundle_holders`] of
/// each tip of the held lineage, keeping the holders COMMON to every tip.
/// With one head that is the head's holders; with no bundle held, empty.
///
/// On a fork of successors this is the reading the halt path already uses
/// (`GenesisInForce::holders`, `GenesisInForce::halt_roster`): a holder
/// counts while EVERY tip seats it, under the same key. A holder two tips
/// seat under different keys is not common (the retain below), so this is
/// never wider than the halt path's roster.
///
/// It sits beside the fork rule of a row that NAMES a bundle (ruled,
/// Constitution, CC rc22 7b4a55e: the EARLIEST successor's instant is the
/// cutoff, [`voices_before_successor`]) without meeting it: a row that names
/// a bundle is counted over [`bundle_holders`] of THAT bundle, whatever the
/// tips are, and the fork only decides which of its voices are in time; a
/// reader with no named bundle (a halt, the birth's count, standing) has only
/// "in force" to read, and on a fork that is what every tip agrees on.
#[must_use]
pub fn holders_in_force(state: &super::genesis::GenesisInForce) -> Vec<String> {
    let mut tips = state.tips().into_iter();
    let Some(first) = tips.next() else {
        return Vec::new();
    };
    let mut common = bundle_holders(state, &first.object_id).unwrap_or_default();
    for tip in tips {
        let theirs = bundle_holders(state, &tip.object_id).unwrap_or_default();
        common.retain(|h| theirs.contains(h));
    }
    // "Under the same key" (the halt path's `TipsInCommon.holders`).
    let same_key: BTreeSet<&str> = state
        .holders()
        .iter()
        .map(|h| h.identity_ref.as_str())
        .collect();
    common.retain(|h| same_key.contains(h.as_str()));
    common
}

/// v62.0.0 (KR-fix2) — [`holders_count`] over the holders of the bundle a
/// row names in `refs.head` ([`bundle_holders`]), never the holders in force
/// now. `None`: the named bundle is not a held Valid placement.
#[must_use]
pub fn holders_count_at(
    state: &super::genesis::GenesisInForce,
    bundle: &ciris_verify_core::edition2::Digest32,
    signers: &BTreeSet<String>,
) -> Option<SignerCount> {
    bundle_holders(state, bundle).map(|holders| holders_count(&holders, signers))
}

/// A held statement's `iss`.
fn iss_of(statement: &[u8]) -> Option<String> {
    let (protected, _) = statement_parts(statement)?;
    protected
        .get_int(15)?
        .get_int(1)?
        .as_text()
        .map(str::to_owned)
}

/// The held `group:roster` statements of `group`, as received.
///
/// # Errors
/// Directory read failures.
pub async fn roster_statements<F>(dir: &F, group: &str) -> Result<Vec<Vec<u8>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    dir.edition2_statements_about(&namespace_match::family_id(GROUP_ROSTER_PREFIX), group)
        .await
}

/// **The voices of one version of a community**: the signers of every held
/// `group:roster` statement whose typed record hashes to `community`'s
/// `persist_row_hash` (re-derived from the record), plus the vouched voices
/// of the record at its door. `None` when neither exists (an earlier-form
/// record: the door's earlier reading applies).
///
/// # Errors
/// Directory read failures.
pub async fn version_signers<F>(
    dir: &F,
    community: &Community,
) -> Result<Option<BTreeSet<String>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let target = crate::federation::types::compute_persist_row_hash(community)?;
    let mut found: Option<BTreeSet<String>> = None;
    for st in roster_statements(dir, &community.community_key_id).await? {
        let Ok(view) = roster_view_of_statement(&st) else {
            continue;
        };
        let Some(id) = RowId::of_statement(&st) else {
            continue;
        };
        let Ok(prev) = prev_head_digest(dir, &view, &id).await else {
            continue;
        };
        let Ok(hash) = record_of_roster(&view, prev).and_then(|r| r.persist_row_hash()) else {
            continue;
        };
        if hash != target {
            continue;
        }
        let set = found.get_or_insert_with(BTreeSet::new);
        if let Some(iss) = iss_of(&st) {
            set.insert(iss);
        }
    }
    if let Some(vouched) = super::group::vouched_signers_for(&community.signing_envelope()) {
        found.get_or_insert_with(BTreeSet::new).extend(vouched);
    }
    Ok(found)
}
