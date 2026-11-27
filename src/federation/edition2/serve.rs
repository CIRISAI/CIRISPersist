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
    /// v62.0.0 (RL-fix1; CC 5.3.4) — how many scanned statements were
    /// withheld because they WAIT for this node to reach a root
    /// ([`SERVE_WAITS_FOR_ROOTED`]): federation-tier rows a rootless node
    /// does not serve to a third party. A count a host can read and render;
    /// zero on a node whose own standing chain reaches a root.
    pub waiting_for_rooted: u32,
}

/// v62.0.0 (RL-fix1; CC 5.3.4 "What crosses before Rooted") — the reason a
/// serve path withholds a federation-tier (commons) row on a node whose own
/// standing chain reaches no root: "What waits for `Rooted` (CC 3.2 T8) is
/// what the node serves to a third party: a federation-tier row, and any
/// self-authored row about someone other than the peer." A wait, never a
/// refusal: the row is held as it was, and is served once a root is reached.
pub const SERVE_WAITS_FOR_ROOTED: &str = "serve_waits_for_rooted";

/// Per serve call: this node's rooting, read once, and the waits counted.
#[derive(Default)]
struct ServeCtx {
    rooted: std::sync::OnceLock<bool>,
    waiting: std::sync::atomic::AtomicU32,
}

tokio::task_local! {
    /// v62.0.0 (RL-fix1) — set while [`statements_served_to`] scans a page.
    static SERVE_CTX: std::sync::Arc<ServeCtx>;
}

/// v62.0.0 (RL-fix1; CC 5.3.4, CC 5.4 "Who carries what") — **the
/// bootstrap kinds and the allegiance facts**, by the statement's own
/// family: what crosses to any peer before either side is Rooted. CC part_5
/// l.1129: "the public self-authenticating rows, which are key records and
/// revocations, occurrences, a sender's own allegiance rows and the routes
/// of unowned nodes"; "the accord's rows and tombstones" (the halt, the
/// notify, the drill, the lifecycle). So:
///
/// - `key:record`, `key:revocation` (served before this is asked);
/// - `identity:occurrence` (an occurrence and its bind, which carries the
///   route and the transit key: CC 5.3.4 l.730, "that identity's own
///   hybrid-signed `transport_destination` row … from any source"),
///   `identity:occurrence_revocation` and `revocation:{entity_type}:{reason}`;
/// - `transport:canonical_rebind` (a seat's route);
/// - an agent's owner binding (`ownership:{relation}:{target_kind}:{version}`);
///   a person's owner binding (a `self:delegates_to` owner-binding row) is
///   recognised by its row ([`commons_servable`]'s `allegiance`);
/// - the accord's invocation and lifecycle rows (`edition2::halt`).
///
/// Signed objects (genesis bundle voices) are public and served before this
/// is asked. The pairing plane's sealed asks (an invitation, a key grant, a
/// device join) are rows ADDRESSED to the requester, served by
/// `group_serve::delivered_to_requester`.
#[must_use]
pub fn is_bootstrap_kind(statement: &[u8]) -> bool {
    use ciris_verify_core::namespace_match::family_id;
    if super::halt::is_invocation(statement) || super::halt::is_lifecycle(statement) {
        return true;
    }
    let Some((protected, _)) = statement_parts(statement) else {
        return false;
    };
    let Some(family) = protected.get_int(-70002).and_then(Value::as_text) else {
        return false;
    };
    let is = |f: &str| family == f || family == family_id(f);
    is(ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY)
        || is(KEY_REVOCATION_FAMILY)
        || is(super::occurrence::OCCURRENCE_FAMILY)
        || is(super::occurrence::OCCURRENCE_REVOCATION_FAMILY)
        || is(super::typed::OCCURRENCE_REVOCATION_PREFIX)
        || is(super::typed::REVOCATION_PREFIX)
        || is(super::transport_rebind::REBIND_FAMILY)
        || is("ownership:{relation}:{target_kind}:{version}")
}

/// v62.0.0 (RL-fix2; CC 3.2 T8 reader-relative, for ITSELF; lead ruling
/// (A)(i)) — **THE SEAM: is `node`'s own standing chain rooted at
/// `at_ms`?** True when some trust root that a live acceptance edge of the
/// node, or of its owner, names ([`transit_candidate_roots`](crate::federation::trust_root))
/// reads `Rooted` or `Stalled` (valid but non-admitting, CC 3.2 T7) by the
/// ONE standing primitive,
/// [`stored_standing_at`](crate::federation::canonical_community::stored_standing_at):
/// the root's chain from an accord birth, its live `trust:charter:v1`, and
/// THIS node's own T3 chain to it ([`own_chain_to`](crate::federation::trust_root::own_chain_to):
/// the owner's acceptance edge governs once the owner signed one). A genesis
/// bundle held with no acceptance edge is no root this node reaches (CC 3.2
/// T3). `node` is this directory's own node key (`node_key_id`), which
/// `stored_standing_at` reads its own chain from.
///
/// v62.0.0 (TR-fix2) — **re-pointed at the peer verdict's own pieces**, for
/// the reader's own node: the roots `node`'s governing acceptor names
/// (`trust_root::accepted_roots_of`) judged FOR `node` by the trust root's
/// read verdict (`canonical_community::reader_standing`: the chain from an
/// accord birth, the charter, `node`'s own T3 legs, T7's margin), the same
/// call `edition2::peer_rooting` makes. Rooted or Stalled crosses (CC 3.2
/// T7 l.1240). No wall clock: `at_ms` is the caller's instant. It now reads
/// `node`'s chain, not this directory's node key's.
///
/// # Errors
/// Directory reads.
pub async fn node_is_rooted<F>(dir: &F, node: &str, at_ms: u64) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(Box::pin(rooted_under(dir, node, at_ms)).await?.is_some())
}

/// v62.0.0 (KB-fix4) — [`node_is_rooted`], naming the root: the first root
/// `node`'s governing acceptor names that roots it (the bundle lineage's
/// `family_key_id`, or a keyed root's id while that arm stands). `None`:
/// not rooted. The ONE body `node_is_rooted` and the host's read
/// (`Engine::root_standing`) share.
///
/// # Errors
/// Directory reads.
pub async fn rooted_under<F>(dir: &F, node: &str, at_ms: u64) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::canonical_community::{reader_standing, StoredStanding};
    let Some(now) = chrono::TimeZone::timestamp_millis_opt(
        &chrono::Utc,
        i64::try_from(at_ms).unwrap_or(i64::MAX),
    )
    .single() else {
        return Ok(None);
    };
    for root in crate::federation::trust_root::accepted_roots_of(dir, node).await? {
        // v62.0.0 (KB-fix1; CC 3.2 at rc22 `87abd2d`) — the root a node
        // accepts is the bundle's lineage: a live acceptance of the
        // `family_key_id` of the bundle in force roots the node
        // (`bundle_root_accepted`). No room chain is read for it.
        if Box::pin(crate::federation::trust_root::bundle_root_accepted(
            dir, node, &root, now,
        ))
        .await?
        {
            return Ok(Some(root));
        }
        let (standing, _) = Box::pin(reader_standing(dir, Some(node), &root, now)).await?;
        if matches!(
            standing,
            StoredStanding::Rooted(_) | StoredStanding::Stalled { .. }
        ) {
            return Ok(Some(root));
        }
    }
    Ok(None)
}

/// This directory's node, rooted now ([`node_is_rooted`]). Every serve path
/// computes it ONCE per call and passes it on (the SQL serve rule takes it
/// as a parameter, `read_plan::serve_rule_parts`).
///
/// v62.0.0 (RL-fix2b/2c, lead ruling) — **no node identity: not rooted, the
/// wait APPLIES, in every build** (fail closed). No host-reachable path can
/// be proved to always set a node key: the `Engine` constructors set it only
/// when the signer derives an id (`if let Ok(id) =
/// engine.local_derived_key_id()`), `Engine::from_shared` only through
/// `node_key_to_tell`, and the wheel only when `federation_key_id_of`
/// answers. A store with no node key withholds federation-tier rows from
/// third parties (I2254).
///
/// # Errors
/// Directory reads.
pub(crate) async fn this_node_is_rooted<F>(dir: &F) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(node) = dir.node_key_id() else {
        return Ok(false);
    };
    let now = u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap_or(0);
    Box::pin(node_is_rooted(dir, &node, now)).await
}

/// v62.0.0 (RL-fix2) — **the JSON attestation serve plane's wait**: the rows
/// of a page a node that is not rooted ([`node_is_rooted`]) withholds, by
/// the same rule as [`commons_servable`] (the page carries no requester, so
/// no party exemption). A commons row waits unless it is an allegiance fact
/// (an owner binding) or a bootstrap kind by its dimension (`identity:occurrence*`,
/// `revocation:*`, `ownership:*`). Rows at any other placement pass
/// untouched (their audience rule is the serve path's own).
///
/// # Errors
/// Directory reads.
pub async fn withhold_waiting_rows<F>(
    dir: &F,
    rows: Vec<crate::federation::Attestation>,
) -> Result<Vec<crate::federation::Attestation>, Error>
where
    F: FederationDirectory + ?Sized,
{
    if !rows.iter().any(row_waits_unrooted) || Box::pin(rooted_for_serve(dir)).await? {
        return Ok(rows);
    }
    let before = rows.len();
    let kept: Vec<_> = rows
        .into_iter()
        .filter(|a| !row_waits_unrooted(a))
        .collect();
    tracing::debug!(
        reason = SERVE_WAITS_FOR_ROOTED,
        withheld = before - kept.len(),
        "federation-tier rows wait: this node's own standing chain reaches no root"
    );
    Ok(kept)
}

tokio::task_local! {
    /// v62.0.0 (RL-fix2b) — set while persist reads its OWN store through a
    /// listing that is also a serve surface (a sweep, the key plane's own
    /// walk, the replication apply's held check): no peer is served, so no
    /// row waits.
    static INTERNAL_READ: ();
}

/// v62.0.0 (RL-fix2b) — run `fut` as one of persist's own reads of its
/// store ([`rooted_for_serve`] then reads `true`): the serve wait applies to
/// what a node hands a peer, never to what it reads for itself.
pub(crate) async fn as_internal_read<T>(fut: impl std::future::Future<Output = T>) -> T {
    INTERNAL_READ.scope((), fut).await
}

/// v62.0.0 (RL-fix2b) — **what the SQL serve rule takes as `rooted`**: `true`
/// for persist's own reads ([`as_internal_read`]), else this node's standing
/// ([`this_node_is_rooted`]), asked once per call.
///
/// # Errors
/// Directory reads.
pub(crate) async fn rooted_for_serve<F>(dir: &F) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    if INTERNAL_READ.try_with(|()| ()).is_ok() {
        return Ok(true);
    }
    Box::pin(this_node_is_rooted(dir)).await
}

/// v62.0.0 (RL-fix2c) — **what this store will serve a third party**: the
/// read a host calls at startup instead of inferring it from side effects.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServeStanding {
    /// The store's node key (`FederationDirectory::node_key_id`). `None`
    /// when no constructor could derive one (a classical-only signer, a P-256
    /// keystore fallback, a hardware public-key read that failed at boot).
    pub node_key_id: Option<String>,
    /// Does this node's own standing chain reach a root
    /// ([`node_is_rooted`]; always `false` with no node key)?
    pub rooted: bool,
    /// `!rooted`: federation-tier rows are WITHHELD from third parties
    /// ([`SERVE_WAITS_FOR_ROOTED`]). A host warns loudly when this is true
    /// AND `node_key_id` is `None` (a misconfiguration, not a pre-genesis
    /// state).
    pub withholds_federation_tier: bool,
}

/// v62.0.0 (RL-fix2c) — **[`ServeStanding`] of this store, now** (read only).
///
/// # Errors
/// Directory reads.
pub async fn serve_standing<F>(dir: &F) -> Result<ServeStanding, Error>
where
    F: FederationDirectory + ?Sized,
{
    let rooted = Box::pin(this_node_is_rooted(dir)).await?;
    Ok(ServeStanding {
        node_key_id: dir.node_key_id(),
        rooted,
        withholds_federation_tier: !rooted,
    })
}

/// v62.0.0 (RL-fix2b) — the dimension prefixes of the attestation-plane
/// bootstrap kinds (CC part_5 l.1129: occurrences, revocations, a sender's
/// own allegiance rows): ONE list, read by the Rust row test
/// ([`row_waits_unrooted`]) and by the SQL serve rule
/// (`read_plan::served_while_unrooted_sql`).
pub(crate) const BOOTSTRAP_DIMENSION_PREFIXES: [&str; 3] =
    ["identity:occurrence", "revocation:", "ownership:"];

/// v62.0.0 (RL-fix2b) — **does an attestation row WAIT on a node that is not
/// rooted?** A commons-scope row that is neither an owner binding
/// (`admission::is_owner_binding_envelope`) nor a bootstrap kind by its
/// dimension ([`BOOTSTRAP_DIMENSION_PREFIXES`]). The SQL form is
/// `read_plan::served_while_unrooted_sql`; the two are the same decision.
#[must_use]
pub(crate) fn row_waits_unrooted(a: &crate::federation::Attestation) -> bool {
    let commons =
        cs::Scope::parse(&a.cohort_scope).map(cs::Scope::placement) == Some(cs::Placement::Commons);
    if !commons || crate::federation::admission::is_owner_binding_envelope(&a.attestation_envelope)
    {
        return false;
    }
    let dim =
        crate::federation::admission::envelope_dimension(&a.attestation_envelope).unwrap_or("");
    !BOOTSTRAP_DIMENSION_PREFIXES
        .iter()
        .any(|p| dim.starts_with(p))
}

/// v62.0.0 (RL-fix2b) — **the wire-index point read's wait**: `bytes`, read
/// for an `"Attestation"` entry, is a row that waits
/// ([`row_waits_unrooted`]) on a node that is not rooted
/// ([`this_node_is_rooted`]). Any other kind, or bytes that do not parse as
/// a row, never wait here (their own serve rules decide them).
///
/// # Errors
/// Directory reads.
pub(crate) async fn point_read_waits<F>(dir: &F, kind: &str, bytes: &[u8]) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    if kind != "Attestation" {
        return Ok(false);
    }
    let Ok(row) = serde_json::from_slice::<crate::federation::Attestation>(bytes) else {
        return Ok(false);
    };
    if !row_waits_unrooted(&row) {
        return Ok(false);
    }
    Ok(!Box::pin(rooted_for_serve(dir)).await?)
}

/// v62.0.0 (RL-fix1; CC 5.3.4) — **may a federation-tier (commons) row be
/// served to `requester`?** Yes when it is a bootstrap kind or an
/// allegiance fact ([`is_bootstrap_kind`]; `allegiance` for an owner-binding
/// row), when the requester is one of `parties` (its author, or its
/// subject: a row about the peer, never "about someone other than the
/// peer"), or when this node's own standing chain reaches a root
/// ([`node_is_rooted`]). Otherwise it WAITS
/// ([`SERVE_WAITS_FOR_ROOTED`], counted on the page).
///
/// # Errors
/// Directory reads.
pub(crate) async fn commons_servable<F>(
    dir: &F,
    statement: &[u8],
    requester: Option<&str>,
    parties: &[&str],
    allegiance: bool,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    if allegiance || is_bootstrap_kind(statement) {
        return Ok(true);
    }
    if let Some(peer) = requester.filter(|p| !p.is_empty()) {
        if Box::pin(is_party_to_row(dir, statement, peer, parties)).await? {
            return Ok(true);
        }
    }
    let ctx = SERVE_CTX.try_with(std::sync::Arc::clone).ok();
    let rooted = match ctx.as_ref().and_then(|c| c.rooted.get().copied()) {
        Some(r) => r,
        None => {
            let r = Box::pin(this_node_is_rooted(dir)).await?;
            if let Some(c) = &ctx {
                let _ = c.rooted.set(r);
            }
            r
        }
    };
    if !rooted {
        if let Some(c) = &ctx {
            c.waiting.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        tracing::debug!(
            reason = SERVE_WAITS_FOR_ROOTED,
            requester = requester.unwrap_or(""),
            "a federation-tier row waits: this node's own standing chain reaches no root"
        );
    }
    Ok(rooted)
}

/// v62.0.0 (RL-fix11; lead ruling 2026-11-21, CC 5.3.4) — **is `peer` a
/// PARTY to the row `statement` is a voice of?** The ONE answer the rootless
/// serve wait asks, on the pending path (a statement with no typed row yet,
/// `group_serve::scope_servable`) and the concluded one
/// ([`servable_by_own_rule`]) alike. The parties are:
///
/// - the row's subject and its attester (`parties`, as the caller names them:
///   the attester of an authored row is the one-voice case);
/// - EVERY key that signed a verifying voice of the row: the voices this node
///   holds for its row id (each verified at the door), and the signer of the
///   statement asked about. A signer always may see the row it signed and
///   its outcome;
/// - whoever the row's own family designates: the holders of the bundle a
///   counted root row names, when the statement is a holder's own voice
///   (KR-fix2 rev 7's arm, folded in here from
///   `group_serve::servable_without_row`); and (v62.0.0, PT-fix1; CC
///   4.4.3.12 as ruled 11-21) the designated officials of the one-seat
///   affiliation a counted act against a member is taken in
///   ([`super::group_serve::served_to_floor_official`], the ONE
///   implementation). The same function is also asked directly by
///   [`servable_by_own_rule`] and by `group_serve::servable_without_row`,
///   so the official's reach holds at every placement and on rooted and
///   rootless nodes alike; this arm makes the rootless wait's own answer
///   complete.
///
/// # Errors
/// Directory reads.
pub(crate) async fn is_party_to_row<F>(
    dir: &F,
    statement: &[u8],
    peer: &str,
    parties: &[&str],
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    if parties.contains(&peer) {
        return Ok(true);
    }
    let Some((protected, _)) = statement_parts(statement) else {
        return Ok(false);
    };
    let iss = protected
        .get_int(15)
        .and_then(|c| c.get_int(1))
        .and_then(Value::as_text)
        .unwrap_or("");
    if iss == peer {
        return Ok(true);
    }
    if let Some(rid) = super::names::RowId::of_statement(statement) {
        if super::voices::voices_of_row(dir, &rid)
            .await?
            .iter()
            .any(|v| v.iss == peer)
        {
            return Ok(true);
        }
    }
    // v62.0.0 (PT-fix1) — the floor-act officials, by the one function.
    if Box::pin(super::group_serve::served_to_floor_official(
        dir, statement, peer,
    ))
    .await?
    {
        return Ok(true);
    }
    if let Some(holders) =
        crate::federation::admission::root_grant_voice_parties(dir.as_dyn_directory(), statement)
            .await?
    {
        if holders.iter().any(|h| h == iss) {
            if holders.iter().any(|h| h == peer) {
                return Ok(true);
            }
            let principals = crate::federation::self_collective::principals_of(dir, peer).await?;
            if principals.iter().any(|p| holders.contains(p)) {
                return Ok(true);
            }
        }
    }
    Ok(false)
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

/// v62.0.0 (RL-fix23) — **is this bootstrap bind CONCLUDED?** An
/// `identity:occurrence` bind is concluded when the occurrence it states
/// (`identity_key_id`, `occurrence_key_id`, at its own `asserted_at`) is held
/// in the occurrence read model, which the bind's door writes only when every
/// voice is counted. Every other family: `false` (a second-signer row with no
/// typed row is never inferred concluded from the absence of a hold).
///
/// VD-step1 — the conclusion is the one verdict's
/// ([`super::verdict::row_state`]); this keeps RL-fix23's family scope.
///
/// # Errors
/// Directory reads.
pub(crate) async fn bootstrap_bind_concluded<F>(dir: &F, statement: &[u8]) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    use ciris_verify_core::namespace_match::family_id;
    let Some((protected, _)) = statement_parts(statement) else {
        return Ok(false);
    };
    let family = protected.get_int(-70002).and_then(Value::as_text);
    let occ_family = super::occurrence::OCCURRENCE_FAMILY;
    if family != Some(occ_family) && family != Some(family_id(occ_family).as_str()) {
        return Ok(false);
    }
    let Some(rid) = super::names::RowId::of_statement(statement) else {
        return Ok(false);
    };
    Ok(super::verdict::row_state(dir, &rid).await?.is_concluded())
}

/// v62.0.0 (WD-fix14; CC 5.4.6 "An occurrence follows its bindings", Eric's
/// ruling via Constitution, 11-22) — **the audience of a concluded
/// `identity:occurrence` bind**, by the identity's kind:
///
/// - a NODE's own self pair (author = identity = occurrence; its transport
///   destination binding): `None`, the statement's scope rule as before
///   (public, a bootstrap kind before Rooted; the Constitution's standing
///   answer for a node, unchanged);
/// - any other MACHINE occurrence (an AGENT identity's; a key bound under a
///   NODE identity): `Some`: served to a requester in the audience of
///   `self` (the identity's own) or of a placement of one of the identity's
///   owner bindings in force now (`cohort_scope` + `community_id` /
///   `family_id`, [`envelope_cohort_target`]: the same members the binding
///   gate reads), and to no one else; a commons placement (the owner
///   announced it at `federation`) is the public one, the only one an
///   anonymous read is served;
/// - a PERSON's occurrence (Constitution, 11-23): `Some`, by the same rule
///   over the UNION of the placements of the owner bindings of EVERY node
///   the person owns (`admission::nodes_owned_by`), plus `self`. Placement
///   is per person at a group, never per device; a seat in a room places
///   nothing. A person who placed no node's binding at a room has no
///   occurrence held by that room's co-members (they wrap nothing to the
///   person there) until one is placed.
///
/// Not an occurrence bind: `None`.
///
/// [`envelope_cohort_target`]: crate::federation::admission::envelope_cohort_target
///
/// # Errors
/// Directory reads; a binding with two cohort targets.
pub(crate) async fn occurrence_follows_its_bindings<F>(
    dir: &F,
    statement: &[u8],
    requester: Option<&str>,
) -> Result<Option<bool>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::types::identity_type::{set_contains, AGENT, NODE};
    use ciris_verify_core::namespace_match::family_id;
    let Some((protected, payload)) = statement_parts(statement) else {
        return Ok(None);
    };
    let occ_family = super::occurrence::OCCURRENCE_FAMILY;
    let family = protected.get_int(-70002).and_then(Value::as_text);
    if family != Some(occ_family) && family != Some(family_id(occ_family).as_str()) {
        return Ok(None);
    }
    let text = |m: &str| payload.get_text(m).and_then(Value::as_text);
    let (Some(identity), Some(occurrence)) = (text("identity_key_id"), text("occurrence_key_id"))
    else {
        return Ok(None);
    };
    let types = dir
        .lookup_public_key(identity)
        .await?
        .map(|r| r.identity_type)
        .unwrap_or_default();
    let (node, agent) = (set_contains(&types, NODE), set_contains(&types, AGENT));
    // A node's own self pair: public (unchanged).
    if node && identity == occurrence {
        return Ok(None);
    }
    // The bindings whose placements are the occurrence's audience: a
    // machine's own owner bindings; for a PERSON, the owner bindings of
    // EVERY node the person owns (Constitution, 11-23: "each of a person's
    // devices is held wherever one of them is placed"; a seat in a room
    // places nothing: membership alone is no placement). A key of neither
    // kind (no person, no machine record held): the scope rule as before.
    let now = crate::host::clock::now();
    let bindings = if node || agent {
        crate::federation::admission::owner_bindings_in_force_at(dir, identity, now).await?
    } else if super::occurrence::is_person_key(dir, identity).await? {
        let mut all = Vec::new();
        for owned in crate::federation::admission::nodes_owned_by(dir, identity).await? {
            all.extend(
                crate::federation::admission::owner_bindings_in_force_at(dir, &owned, now).await?,
            );
        }
        all
    } else {
        return Ok(None);
    };
    let Some(peer) = requester.filter(|p| !p.is_empty()) else {
        // An anonymous read: the commons placement only.
        return Ok(Some(bindings.iter().any(|b| {
            cs::Scope::parse(&b.cohort_scope).map(cs::Scope::placement)
                == Some(cs::Placement::Commons)
        })));
    };
    if crate::federation::replication::hold::is_audience(
        dir,
        cs::SELF,
        None,
        identity,
        |author| author == peer,
        peer,
    )
    .await?
    {
        return Ok(Some(true));
    }
    for b in &bindings {
        if cs::Scope::parse(&b.cohort_scope).map(cs::Scope::placement)
            == Some(cs::Placement::Commons)
        {
            return Ok(Some(true));
        }
        let target = crate::federation::admission::envelope_cohort_target(&b.attestation_envelope)?;
        if crate::federation::replication::hold::is_audience(
            dir,
            &b.cohort_scope,
            target,
            &b.attesting_key_id,
            |author| author == peer,
            peer,
        )
        .await?
        {
            return Ok(Some(true));
        }
    }
    Ok(Some(false))
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
        // v62.0.0 (wave T1) — no attestation row: judged from the statement.
        // A purged row is never served.
        if dir
            .purge_tombstoned("attestation", &rid)
            .await
            .unwrap_or(None)
            .is_some()
        {
            return Ok(false);
        }
        // v62.0.0 (K2-fix6; CC 2.6.1.9, CC 2.7.3) — an authored row whose
        // family names second signers and that has no typed row is HELD for
        // a second signer's voice: kept, not served. The second signer gets
        // the payload from the producer's draft, never from the serve feed;
        // once the row lands its voices follow the row.
        //
        // v62.0.0 (RL-fix12; CC 5.3.4, CC 3.3.6.2) — a BOOTSTRAP kind with
        // second signers (an `identity:occurrence` bind: the device's voice
        // and its identity's) never gets an attestation row: its typed row
        // is the occurrence row. So "no attestation row" is not "not yet a
        // fact" for it; the fold is. A bind whose second voice is still
        // missing is HELD (`fold_held`): not a fact, withheld from every
        // reader, as before. A CONCLUDED one is the fact the pre-seal route
        // fetch needs, served before Rooted (the 4q run's I2245: 2 of 4).
        // A concluded bind then takes the same scope rule as any statement
        // with no typed row (`servable_without_row`).
        //
        // v62.0.0 (RL-fix23; CC 5.3.4, CC 2.7.3) — "concluded" is NEVER "no
        // fold hold": a device's lone bind voice is KEPT as a voice with no
        // hold recorded, and was served to an anonymous reader (its
        // `transport_destination` and transit key) before its identity had
        // voiced it (I2415). A bind is concluded when the occurrence it
        // states is HELD in the occurrence read model
        // ([`bootstrap_bind_concluded`]); any other second-signer row with no
        // typed row waits for it. Until then nobody is served it: the second
        // signer (the identity, from its other devices) voices it from the
        // producer's draft, never from the feed (K2-fix6).
        if !super::door::second_signer_roles(statement).is_empty()
            && !(is_bootstrap_kind(statement)
                && Box::pin(bootstrap_bind_concluded(dir, statement)).await?)
        {
            return Ok(false);
        }
        // v62.0.0 (WD-fix14; CC 5.4.6 "An occurrence follows its bindings")
        // — an occurrence (other than a node's own self pair) is served only to
        // the audiences its identity's owner bindings are placed at (a
        // person's: every owned node's), and `self`.
        if let Some(decision) =
            Box::pin(occurrence_follows_its_bindings(dir, statement, requester)).await?
        {
            return Ok(decision);
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
        // v62.0.0 (SL-fix4; CC 4.4.3.12 as ruled 11-21) — a CONCLUDED
        // countersigned act reaches the designated officials of its room as
        // a party, as it did while it gathered voices (`group_serve`): the
        // commons wait's parties (its attester and subject) left them out,
        // so a rootless node that concluded the act withheld it from the
        // official (I4164).
        if Box::pin(super::group_serve::served_to_floor_official(
            dir, statement, peer,
        ))
        .await?
        {
            return Ok(true);
        }
    }
    let placement = cs::Scope::parse(&row.cohort_scope).map(cs::Scope::placement);
    match (placement, requester) {
        // v62.0.0 (RL-fix1; CC 5.3.4) — a federation-tier row waits for a
        // root on a node that reaches none, unless the text lets it cross.
        (Some(cs::Placement::Commons), _) => {
            Box::pin(commons_servable(
                dir,
                statement,
                requester,
                &[row.attesting_key_id.as_str(), row.attested_key_id.as_str()],
                crate::federation::admission::is_owner_binding_envelope(&row.attestation_envelope),
            ))
            .await
        }
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
    let ctx = std::sync::Arc::new(ServeCtx::default());
    SERVE_CTX
        .scope(
            ctx.clone(),
            statements_served_to_scoped(dir, cursor, limit, requester, ctx),
        )
        .await
}

/// [`statements_served_to`]'s body, run inside its [`ServeCtx`].
async fn statements_served_to_scoped<F>(
    dir: &F,
    cursor: Option<&StatementCursor>,
    limit: u32,
    requester: Option<&str>,
    ctx: std::sync::Arc<ServeCtx>,
) -> Result<ServedPage, Error>
where
    F: FederationDirectory + ?Sized,
{
    use std::sync::atomic::Ordering;
    let scanned = dir.edition2_statements_since(cursor, limit).await?;
    let next = scanned.last().map(|s| s.cursor);
    let mut statements: Vec<ServedStatement> = Vec::with_capacity(scanned.len());
    let mut waiting_for_rooted = 0u32;
    for s in scanned {
        let waits_before = ctx.waiting.load(Ordering::Relaxed);
        let served = servable_to(dir, &s.bytes, requester).await?;
        if !served && ctx.waiting.load(Ordering::Relaxed) > waits_before {
            waiting_for_rooted = waiting_for_rooted.saturating_add(1);
        }
        if served {
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
    Ok(ServedPage {
        statements,
        next,
        waiting_for_rooted,
    })
}
