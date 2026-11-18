//! v62.0.0 (JSON-cut slice B) — **what an edition-2 serve path may hand a
//! requester**: the JSON-era serve rule, applied to statements.
//!
//! The statement store (`ceg_statements`) holds every statement this node
//! admitted, as received. Reading it directly would serve what the JSON
//! listing withheld. Every edition-2 serve path therefore asks
//! [`servable_to`] of each statement, which applies the SAME rule the JSON
//! listing (`list_attestations_since`, `read_plan::serve_rule_parts`) applies
//! to the row the statement maps to, and adds the requester's audience:
//!
//! - **tier**: a `local`-tier row never reaches the serve surface (E5);
//! - **row type**: under enforcement an unregistered type is not served
//!   (CC 2.4, #975), and a retired carrier never is;
//! - **purge plane**: a row an `attestation` purge tombstone names is not
//!   served. (Stricter than the JSON read: the tombstone's
//!   accountability-record and person-subject voids are not granted here; a
//!   withheld void is a row a peer re-fetches from a node that grants it.)
//! - **the delivered key** (v62.0.0, wave T1; CC 2.1): the audience is the
//!   members at the head plus the key the family delivers the row to (a
//!   membership proposal's invitee, a key grant's recipient, the owner's own
//!   node on an owner-binding), so an invitee is served its invitation. No
//!   blanket rule serves a row to every key it names;
//! - **audience** ("never serve what the requester is not party to"): a
//!   commons row (`federation` / `species` / `biosphere`) is served to
//!   anyone; a `self` / `family` / room (`community`, `affiliations`) row
//!   only to a requester party to it, asked of THIS node's rosters
//!   ([`replication::hold::is_audience`], the receiver-side test, with the
//!   requester as the party). An anonymous read (no requester) serves the
//!   commons only.
//!
//! Key-plane statements (`key:record`, `key:revocation`) and signed objects
//! (genesis bundle voices) are public and always served. A voice of a row
//! follows its row. v62.0.0 (wave T1) — a statement that maps to NO
//! attestation row (a group voice, which lands in its typed table; a counted
//! row still gathering voices; another statement-only family) is judged from
//! the statement itself ([`super::group_serve::servable_without_row`]): a
//! group voice by the group's members at the head it names, the member it
//! names and the founders; any other by the scope its payload states, an
//! absent scope reading as `federation` (the attestation default). The purge plane applies to it
//! as to a row.
//!
//! The serve paths: [`statements_served_to`] (the listing, behind
//! `Engine::edition2_statements_served_to`), [`super::store::lookup_by_id`]
//! (the point read, anonymous) and the statement-id wire index
//! (`list_wire_hashes_since("Statement")`, anonymous).
//!
//! [`replication::hold::is_audience`]: crate::federation::replication::hold::is_audience

use ciris_verify_core::cde::Value;

use super::liveness::{statement_parts, KEY_REVOCATION_FAMILY};
use super::store::{ServedStatement, StatementCursor};
use crate::federation::types::cohort_scope as cs;
use crate::federation::{Error, FederationDirectory};

/// One page of a filtered serve listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServedPage {
    /// The statements this requester is served, as received.
    pub statements: Vec<ServedStatement>,
    /// Where the next page resumes: the last statement SCANNED (served or
    /// withheld), so a page of withheld statements still advances. `None`
    /// when the store had nothing after the cursor.
    pub next: Option<StatementCursor>,
}

/// Is `attestation_type` served under the row-type rule in force?
fn row_type_served(attestation_type: &str) -> bool {
    use crate::federation::row_type::{
        enforcement, is_registered, retired_carrier, RowTypeEnforcement,
    };
    retired_carrier(attestation_type).is_none()
        && (enforcement() != RowTypeEnforcement::Enforce || is_registered(attestation_type))
}

/// **May `requester` be served `statement`?** See the module doc for the
/// rule. `requester` is the identity the transport authenticated, never a
/// claim the statement makes; `None` is an anonymous read.
///
/// # Errors
/// Directory reads.
pub async fn servable_to<F>(
    dir: &F,
    statement: &[u8],
    requester: Option<&str>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some((protected, _)) = statement_parts(statement) else {
        return Ok(false);
    };
    // A signed object (a genesis bundle voice) is public.
    if protected
        .get_int(16)
        .and_then(Value::as_text)
        .is_some_and(|t| ciris_verify_core::edition2::OBJECT_TYPS.contains(&t))
    {
        return Ok(true);
    }
    let Some(family) = protected.get_int(-70002).and_then(Value::as_text) else {
        return Ok(false);
    };
    if family == ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY
        || family == KEY_REVOCATION_FAMILY
    {
        return Ok(true);
    }
    let Some(rid) = super::names::RowId::of_statement(statement) else {
        return Ok(false);
    };
    let rid = rid.hex();
    let Some(row) = dir.get_attestation(&rid).await? else {
        // v62.0.0 (wave T1) — no attestation row: judged from the statement.
        if dir
            .purge_tombstoned("attestation", &rid)
            .await
            .unwrap_or(None)
            .is_some()
        {
            return Ok(false);
        }
        return Box::pin(super::group_serve::servable_without_row(
            dir, statement, requester,
        ))
        .await;
    };
    if row.tier != crate::federation::types::attestation_tier::FEDERATION
        || !row_type_served(&row.attestation_type)
    {
        return Ok(false);
    }
    if dir
        .purge_tombstoned("attestation", &rid)
        .await
        .unwrap_or(None)
        .is_some()
    {
        return Ok(false);
    }
    // v62.0.0 (wave T1; CC 2.1, "whom a targeted row may name") — the
    // audience is the members at the head PLUS the key the family delivers
    // the row to: a membership proposal's invitee, a key grant's recipient,
    // the owner's own node on an owner-binding. An invitation delivered to
    // the invitee's key reaches the invitee before it joins. A row merely
    // ABOUT a key gets no such reach: a named subject is within the audience
    // by the admission rule (`subject_outside_audience`), so the audience
    // rule below serves it.
    if let Some(peer) = requester {
        if super::group_serve::delivered_to_requester(dir, &row, peer).await? {
            return Ok(true);
        }
    }
    let placement = cs::Scope::parse(&row.cohort_scope).map(cs::Scope::placement);
    match (placement, requester) {
        (Some(cs::Placement::Commons), _) => Ok(true),
        (None, _) | (Some(_), None) => Ok(false),
        (Some(_), Some(peer)) => {
            let target =
                crate::federation::admission::envelope_cohort_target(&row.attestation_envelope)
                    .unwrap_or(None);
            crate::federation::replication::hold::is_audience(
                dir,
                &row.cohort_scope,
                target,
                &row.attesting_key_id,
                |author| author == peer,
                peer,
            )
            .await
        }
    }
}

/// **The filtered serve listing**: the statements after `cursor`, in this
/// node's admission order, that `requester` may be served
/// ([`servable_to`]). Scans at most `limit` held statements.
///
/// # Errors
/// Directory reads.
pub async fn statements_served_to<F>(
    dir: &F,
    cursor: Option<&StatementCursor>,
    limit: u32,
    requester: Option<&str>,
) -> Result<ServedPage, Error>
where
    F: FederationDirectory + ?Sized,
{
    let scanned = dir.edition2_statements_since(cursor, limit).await?;
    let next = scanned.last().map(|s| s.cursor);
    let mut statements = Vec::with_capacity(scanned.len());
    for s in scanned {
        if servable_to(dir, &s.bytes, requester).await? {
            statements.push(s);
        }
    }
    Ok(ServedPage { statements, next })
}
