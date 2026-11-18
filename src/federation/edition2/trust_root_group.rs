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
//! - **the birth's accord count** ([`bundle_quorum_over`]): the distinct
//!   holders among the version's voices, against a strict majority of the
//!   holders (CC 3.2, citing CC 2.7.5: "a co-signature by a strict majority of the standing
//!   accord roster"; CC 2.6.1.11, the bundle's own count for the holders'
//!   acts);
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
use crate::federation::trust_root::CharterQuorum;
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
    Ok(genesis_in_force(dir)
        .await?
        .holders()
        .iter()
        .any(|h| h.identity_ref == key_id))
}

/// The identity-refs of the holders of the bundle in force (empty: none
/// held). An input of the standing cache's key.
///
/// # Errors
/// Directory read failures.
pub async fn bundle_holder_refs<F>(dir: &F) -> Result<Vec<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(genesis_in_force(dir)
        .await?
        .holders()
        .iter()
        .map(|h| h.identity_ref.clone())
        .collect())
}

/// The count a holders' act needs over `holders` holders: a strict majority.
#[must_use]
pub const fn holders_required(holders: usize) -> usize {
    holders / 2 + 1
}

/// **The birth's accord count**: the distinct holders of the bundle in force
/// among `signers`, against [`holders_required`]. With no bundle held the
/// roster is empty and the count is never met.
///
/// # Errors
/// Directory read failures.
pub async fn bundle_quorum_over<F>(
    dir: &F,
    signers: &BTreeSet<String>,
) -> Result<CharterQuorum, Error>
where
    F: FederationDirectory + ?Sized,
{
    let holders = bundle_holder_refs(dir).await?;
    let distinct_holders = holders.iter().filter(|h| signers.contains(*h)).count();
    Ok(CharterQuorum {
        distinct_holders,
        required: holders_required(holders.len()),
        roster_size: holders.len(),
    })
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
