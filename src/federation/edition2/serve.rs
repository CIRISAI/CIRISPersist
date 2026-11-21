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
/// v62.0.0 (T1-fix3; CC 2.7.5, "missing, and what is copied") — a statement
/// its own rule ([`servable_by_own_rule`]) withholds is still served where a
/// row naming it carries its audience to it
/// ([`super::group_serve::carried_by_a_naming_row`]): "A row carries its
/// audience to the rows it names when it is concluded, sits in the same
/// room, and its signer is already in the named row's audience." So an
/// eviction's cited proof (CC 2.6.1.7 way (d), rc21 7f94be1) travels with
/// it, and an invitation's cited roster head reaches its invitee.
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
    if servable_by_own_rule(dir, statement, requester).await? {
        return Ok(true);
    }
    Box::pin(super::group_serve::carried_by_a_naming_row(
        dir, statement, requester,
    ))
    .await
}

/// **The statement's own serve rule**, before any row naming it carries
/// its audience to it (the body [`servable_to`] had before T1-fix3).
///
/// # Errors
/// Directory reads.
pub async fn servable_by_own_rule<F>(
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
        // v62.0.0 (K2-fix6; CC 2.6.1.9, CC 2.7.3) — an authored row whose
        // family names second signers and that has no typed row is HELD for
        // a second signer's voice: kept, not served. The second signer gets
        // the payload from the producer's draft, never from the serve feed;
        // once the row lands its voices follow the row.
        if !super::door::second_signer_roles(statement).is_empty() {
            return Ok(false);
        }
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
        (Some(placement), Some(peer)) => {
            let target =
                crate::federation::admission::envelope_cohort_target(&row.attestation_envelope)
                    .unwrap_or(None);
            if crate::federation::replication::hold::is_audience(
                dir,
                &row.cohort_scope,
                target,
                &row.attesting_key_id,
                |author| author == peer,
                peer,
            )
            .await?
            {
                return Ok(true);
            }
            // v62.0.0 (LF-fix1; CC 5.4.6 / 3.2, CIRISEdge#761,
            // CIRISPersist#1063) — a PUBLIC group's rows fan out to everyone
            // ([`public_group_serves`]). Asked last, so a requester already
            // in the audience pays no further read.
            public_group_serves(dir, &row, placement, target, peer).await
        }
    }
}

/// v62.0.0 (LF-fix1; CC 5.4.6 / 3.2, CIRISEdge#761, CIRISPersist#1063) —
/// **a typed row targeted at a PUBLIC group, and a requester outside its
/// roster.** A public group's rows fan out to everyone: an authorized
/// `infrastructure` community, a held `public` room, the accord family, a
/// conferring family
/// ([`is_public_group`](crate::federation::replication_audience::is_public_group),
/// the ONE predicate the tier decisions ask). The send-set rule has this arm
/// (`replication_audience::audience_nodes`: `Targeted(_) if is_public_group`
/// is `Everyone`); the filtered serve asked only `hold::is_audience`, which
/// is the requester's own MEMBERSHIPS. So a public room's rows were served to
/// its members alone, and the row a non-member needs in order to join — the
/// founder's subjectless standing proposal (`open:self_admit`,
/// CIRISPersist#1063) — never left the member's node: `may_receive` said yes
/// and the serve feed said no.
///
/// Decided by the send-set rule itself
/// ([`may_receive`](crate::federation::replication_audience::may_receive)),
/// so its carve-outs hold here as they do there: a cosign row reaches the
/// group's active members only, a key-grant row its one recipient, an
/// owner's grant FOR a node that node. A self, commons or untargeted row, and
/// a group that is not public, is `false` (the audience rule above was the
/// whole answer).
///
/// # Errors
/// Directory reads.
async fn public_group_serves<F>(
    dir: &F,
    row: &crate::federation::types::Attestation,
    placement: cs::Placement,
    target: Option<&str>,
    peer: &str,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let (cs::Placement::Targeted(_), Some(group)) = (placement, target.filter(|t| !t.is_empty()))
    else {
        return Ok(false);
    };
    if !crate::federation::replication_audience::is_public_group(dir, group).await? {
        return Ok(false);
    }
    Ok(
        Box::pin(crate::federation::replication_audience::may_receive(
            dir, peer, row,
        ))
        .await?
        .allowed(),
    )
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
    let mut statements: Vec<ServedStatement> = Vec::with_capacity(scanned.len());
    for s in scanned {
        if servable_to(dir, &s.bytes, requester).await? {
            // v62.0.0 (T2-fix4; CC 2.7.5, rc21 7f94be1) — the rows an
            // eviction cites (its voices' key records and bindings) are its
            // ancestors and TRAVEL with it: served just before it, at its
            // position, so the page's resume point is unchanged, each one
            // gated by `servable_to` (T1-fix3's copy rule).
            for ancestor in super::typed::travelling_ancestors(dir, &s.bytes).await? {
                // Within the row's audience (CC 2.7.5): the ONE serve rule
                // decides each ancestor (T1's carry admits a cited row to
                // whoever the concluded eviction is served to).
                if !servable_to(dir, &ancestor, requester).await? {
                    continue;
                }
                if !statements.iter().any(|x| x.bytes == ancestor) {
                    statements.push(ServedStatement {
                        cursor: s.cursor,
                        bytes: ancestor,
                    });
                }
            }
            if !statements.iter().any(|x| x.bytes == s.bytes) {
                statements.push(s);
            }
        }
    }
    Ok(ServedPage { statements, next })
}
