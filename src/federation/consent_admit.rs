//! v60.0.0 (CIRISPersist#934 step 4) — **the consent doors, decided once.**
//!
//! # What was here before
//!
//! Seven doors were written three times, once in each of
//! `store/{memory,sqlite,postgres}.rs`:
//!
//! - two writes: `set_consent_role` (the admissibility gate, the wire→stored
//!   mapping, the no-row refusal) and `grant_trust` (the #721 authority gate,
//!   the shape validation, the no-row refusal; `trusted_at` read from each
//!   backend's own clock, `NOW()` on postgres);
//! - five reads over the consent projections: `list_consent_peers` /
//!   `list_consent_peers_for` (sort + dedup), `list_live_consent_grants_by` /
//!   `_for` (the `consent:replication:v1` dimension filter, newest first, the
//!   per-door read counter) and `list_consent_revocations` (the subject-side
//!   predicate: a `withdraws` admitted under rule 2/3/4, or a
//!   `consent:state:revoked` stance).
//!
//! The reads' decisions were three copies of one predicate in two languages
//! (SQL `WHERE`, a Rust filter on memory) — the shape `AttestationQuery`
//! retired for the attestation reads in v56.
//!
//! # The shape
//!
//! Each door is one shared function here (`*_planned`). The writes plan
//! ([`plan_set_consent_role`], [`plan_grant_trust`]) and hand the executor a
//! row; the reads are one fold each ([`consent_peers_planned`],
//! [`live_consent_grants_planned`], [`consent_revocations_planned`]) over a
//! typed read ([`ConsentRead`]) the executor answers with the raw projection
//! rows or a candidate superset. The fold decides membership, order and
//! dedup; the executor's SQL is the key pin and a coarse pushdown, never the
//! predicate. [`ConsentStore`] is what a backend implements: the SQL, the
//! row mapping, the transaction, the serve position and the wire index. It
//! decides nothing.
//!
//! # Which instant each plan reads
//!
//! `grant_trust` stamps `trusted_at` with the door's one clock read
//! (`received_at`); before v60 postgres stamped `NOW()` (the database clock)
//! and the other two `Utc::now()`. Nothing else here reads an instant.

use chrono::{DateTime, Utc};

use super::attestation_query::QueryRows;
use super::types::{self, Attestation, SignedTrustGrant, TrustRow};
use super::{Error, FederationDirectory};

/// Which consent projection a read walks, and the key it pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsentRead<'a> {
    /// `consent_peer_set` (V109): the grants a node authored about itself,
    /// pinned on `node_key_id`.
    Node(&'a str),
    /// `consent_peer_set_for` (V147): the grants naming a machine as the one
    /// they are FOR, pinned on `for_key_id`.
    For(&'a str),
}

impl ConsentRead<'_> {
    /// The pinned key.
    #[must_use]
    pub(crate) fn key(&self) -> &str {
        match self {
            Self::Node(k) | Self::For(k) => k,
        }
    }
}

/// One projection row as stored: `(author, peer)`. For [`ConsentRead::Node`]
/// the author is the pinned node itself.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ConsentPeerRow {
    /// `node_key_id` (V109) or `author_key_id` (V147).
    pub(crate) author_key_id: String,
    /// `peer_key_id`.
    pub(crate) peer_key_id: String,
}

/// A planned consent-role overwrite: the key and the role in WIRE form
/// (`None` = the stored `'unregistered'` default).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlannedConsentRole {
    /// The `federation_keys` row to overwrite.
    pub(crate) key_id: String,
    /// The admitted role, wire form.
    pub(crate) role: Option<String>,
}

#[cfg_attr(not(any(feature = "postgres", feature = "sqlite")), allow(dead_code))]
impl PlannedConsentRole {
    /// The stored form of [`Self::role`] (the V020 column is NOT NULL).
    #[must_use]
    pub(crate) fn stored(&self) -> &str {
        types::consent_role::stored_from_wire(self.role.as_deref())
    }
}

/// The consent plane's executor: what a backend does for the shared plans.
/// Storage only — every refusal and every membership decision is the plan's.
#[async_trait::async_trait]
pub(crate) trait ConsentStore: Send + Sync {
    /// Overwrite `federation_keys.consent_role` for the planned key, moving
    /// its serve position (the role is in the served bytes, #707), then
    /// re-index the stored row (#640). `false` when the key has no row.
    async fn store_planned_consent_role(&self, planned: PlannedConsentRole) -> Result<bool, Error>;

    /// Write the trust columns of `row.key`'s `federation_keys` row (or the
    /// memory backend's trust map). `false` when the key has no row.
    async fn store_planned_trust_grant(&self, row: TrustRow) -> Result<bool, Error>;

    /// Every projection row the read pins, as stored: unordered, duplicates
    /// kept (the fold sorts and dedups).
    async fn read_consent_peer_rows(
        &self,
        read: ConsentRead<'_>,
    ) -> Result<Vec<ConsentPeerRow>, Error>;

    /// The attestation rows that still source a row of the read's
    /// projection (the revocation fold already ran at write time): for
    /// [`ConsentRead::Node`] the ones the node authored, for
    /// [`ConsentRead::For`] the ones whose `consent_peer_set_for` row names
    /// the machine. Unordered; the fold filters and orders.
    async fn read_live_consent_grant_candidates(
        &self,
        read: ConsentRead<'_>,
    ) -> Result<QueryRows, Error>;

    /// Every row that MAY be a subject-side revocation: any `withdraws`, and
    /// any row whose envelope dimension starts with
    /// [`consent_dimension::STATE_REVOKED_PREFIX`](super::consent::consent_dimension::STATE_REVOKED_PREFIX),
    /// at or after `since`, every tier. Unordered; the fold applies the rule.
    async fn read_consent_revocation_candidates(
        &self,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<Attestation>, Error>;
}

// ── writes ─────────────────────────────────────────────────────────────

/// **The consent-role overwrite's decision**: the CC 3.4.7.2 token gate
/// (an unrecognized token refused on every backend, keeping postgres's CHECK
/// and CHECK-less sqlite symmetric), then the wire normal form (the
/// `'unregistered'` default and the empty token read as no role).
pub(crate) fn plan_set_consent_role(
    key_id: &str,
    consent_role: Option<&str>,
) -> Result<PlannedConsentRole, Error> {
    types::consent_role::check_admissible(consent_role)?;
    Ok(PlannedConsentRole {
        key_id: key_id.to_owned(),
        role: consent_role
            .and_then(types::consent_role::wire_from_stored)
            .map(str::to_owned),
    })
}

/// The `set_consent_role` door every backend runs: the plan, the executor,
/// and the no-row refusal.
pub(crate) async fn set_consent_role_planned<D>(
    dir: &D,
    key_id: &str,
    consent_role: Option<&str>,
) -> Result<(), Error>
where
    D: ConsentStore + ?Sized,
{
    let planned = plan_set_consent_role(key_id, consent_role)?;
    if dir.store_planned_consent_role(planned).await? {
        Ok(())
    } else {
        Err(no_key_row("set_consent_role", key_id))
    }
}

fn no_key_row(door: &str, key_id: &str) -> Error {
    Error::InvalidArgument(format!("{door}: no federation_keys row for {key_id}"))
}

/// The trust grant's SHAPE (v1.3.0): both keys named, no self-trust, a
/// `Registry` grant names its domains and a `Direct` grant names none.
/// Shape, not authority — [`admission::check_trust_grant_authority`](super::admission::check_trust_grant_authority)
/// is the authority gate, and runs first.
pub(crate) fn validate_trust_grant(grant: &types::TrustGrant) -> Result<(), Error> {
    if grant.key.is_empty() {
        return Err(Error::InvalidArgument("grant.key must be non-empty".into()));
    }
    if grant.trusted_by.is_empty() {
        return Err(Error::InvalidArgument(
            "grant.trusted_by must be non-empty".into(),
        ));
    }
    if grant.trusted_by == grant.key {
        return Err(Error::InvalidArgument(format!(
            "grant.trusted_by must differ from grant.key (no self-trust); got {}",
            grant.key
        )));
    }
    match grant.trust_relationship {
        types::TrustRelationship::Registry => {
            if grant.trust_domains.as_ref().is_none_or(Vec::is_empty) {
                return Err(Error::InvalidArgument(
                    "Registry-relationship grants require a non-empty trust_domains list".into(),
                ));
            }
        }
        // `Direct` grants: `trust_domains` MUST be `None` (NodeCore's shape
        // contract). The resolver ignores domains there, so a `Some` is a
        // caller's misuse, refused at the boundary rather than stored.
        types::TrustRelationship::Direct => {
            if grant.trust_domains.is_some() {
                return Err(Error::InvalidArgument(
                    "Direct-relationship grants must have trust_domains=None".into(),
                ));
            }
        }
    }
    Ok(())
}

/// **The trust grant's decision** (v38.0.0, CIRISPersist#721): the granter
/// proves it is `trusted_by` (Strict hybrid over the pinned signing bytes,
/// verified against this directory's keys) BEFORE the shape is read; then
/// the shape; then the row, stamped `received_at`.
pub(crate) async fn plan_grant_trust(
    dir: &dyn FederationDirectory,
    signed: SignedTrustGrant,
    received_at: DateTime<Utc>,
) -> Result<TrustRow, Error> {
    super::admission::check_trust_grant_authority(dir, &signed).await?;
    let grant = signed.grant;
    validate_trust_grant(&grant)?;
    Ok(TrustRow {
        key: grant.key,
        trust_type: grant.trust_type,
        trust_relationship: grant.trust_relationship,
        trust_domains: grant.trust_domains,
        trusted_by: grant.trusted_by,
        trusted_at: received_at,
        expires_at: grant.expires_at,
    })
}

/// The `grant_trust` door every backend runs: one clock read, the plan, the
/// executor, and the no-row refusal (a trust row rides an existing key row:
/// there is nothing to preserve when the key was never put).
pub(crate) async fn grant_trust_planned<D>(dir: &D, signed: SignedTrustGrant) -> Result<(), Error>
where
    D: ConsentStore + FederationDirectory,
{
    let row = plan_grant_trust(dir, signed, Utc::now()).await?;
    let key = row.key.clone();
    if dir.store_planned_trust_grant(row).await? {
        Ok(())
    } else {
        Err(Error::InvalidArgument(format!(
            "federation_keys row {key} does not exist — call put_public_key first"
        )))
    }
}

// ── reads ──────────────────────────────────────────────────────────────

/// **The consent-peer fold**: the projection rows the read pins, sorted by
/// `(author, peer)` and deduplicated (a peer two live grants both name is
/// one peer).
pub(crate) async fn consent_peers_planned<D>(
    dir: &D,
    read: ConsentRead<'_>,
) -> Result<Vec<ConsentPeerRow>, Error>
where
    D: ConsentStore + ?Sized,
{
    let mut rows = dir.read_consent_peer_rows(read).await?;
    rows.sort();
    rows.dedup();
    Ok(rows)
}

/// `list_consent_peers`: the node's live peers, sorted, deduplicated.
pub(crate) async fn list_consent_peers_planned<D>(
    dir: &D,
    node_key_id: &str,
) -> Result<Vec<String>, Error>
where
    D: ConsentStore + ?Sized,
{
    let rows = consent_peers_planned(dir, ConsentRead::Node(node_key_id)).await?;
    let mut peers: Vec<String> = rows.into_iter().map(|r| r.peer_key_id).collect();
    // One node's rows sort by peer already; the dedup is per peer, not per
    // (author, peer), because every row here has the same author.
    peers.dedup();
    Ok(peers)
}

/// `list_consent_peers_for`: every `(author, peer)` naming the machine.
pub(crate) async fn list_consent_peers_for_planned<D>(
    dir: &D,
    for_key_id: &str,
) -> Result<Vec<(String, String)>, Error>
where
    D: ConsentStore + ?Sized,
{
    let rows = consent_peers_planned(dir, ConsentRead::For(for_key_id)).await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.author_key_id, r.peer_key_id))
        .collect())
}

/// Newest first by the SIGNED instant, ties by id (the `AttestationQuery`
/// order), so every backend returns the same sequence.
fn newest_first(rows: &mut [Attestation]) {
    rows.sort_by(|a, b| {
        (b.asserted_at, b.attestation_id.as_str()).cmp(&(a.asserted_at, a.attestation_id.as_str()))
    });
}

/// **The live-grant fold** (`list_live_consent_grants_by` / `_for`): the
/// candidates whose envelope dimension is `consent:replication:v1`, newest
/// first, counted on the read's door.
pub(crate) async fn live_consent_grants_planned<D>(
    dir: &D,
    read: ConsentRead<'_>,
) -> Result<Vec<Attestation>, Error>
where
    D: ConsentStore + ?Sized,
{
    let QueryRows {
        rows,
        bytes,
        backend,
    } = dir.read_live_consent_grant_candidates(read).await?;
    let mut rows: Vec<Attestation> = rows
        .into_iter()
        .filter(|a| {
            super::admission::envelope_dimension(&a.attestation_envelope)
                == Some(super::consent_peer_set::DIMENSION)
        })
        .collect();
    newest_first(&mut rows);
    let door = match read {
        ConsentRead::Node(_) => crate::observe::Door::ListLiveConsentGrantsBy,
        ConsentRead::For(_) => crate::observe::Door::ListLiveConsentGrantsFor,
    };
    crate::observe::record_read(backend, door, read.key(), &rows, bytes);
    Ok(rows)
}

/// Is `a` a SUBJECT-side consent revocation (§8.1.11.3 / §10.1.3)? A
/// `withdraws` admitted under rule 2, 3 or 4 (rule 1 is the producer's own
/// revoke, not a consent event), or a `consent:state:revoked*` stance.
#[must_use]
pub(crate) fn is_subject_side_revocation(a: &Attestation) -> bool {
    let subject_withdraws = a.attestation_type == types::attestation_type::WITHDRAWS
        && matches!(a.withdraws_admission_rule, Some(2..=4));
    let revoked_stance = super::admission::envelope_dimension(&a.attestation_envelope)
        .is_some_and(|d| d.starts_with(super::consent::consent_dimension::STATE_REVOKED_PREFIX));
    subject_withdraws || revoked_stance
}

/// **The consent-revocation fold** (`list_consent_revocations`): the
/// candidates [`is_subject_side_revocation`] keeps, newest first. Every tier
/// (the §10.1.3 promotion-overdue check needs the local rows).
pub(crate) async fn consent_revocations_planned<D>(
    dir: &D,
    since: Option<DateTime<Utc>>,
) -> Result<Vec<Attestation>, Error>
where
    D: ConsentStore + ?Sized,
{
    let mut rows: Vec<Attestation> = dir
        .read_consent_revocation_candidates(since)
        .await?
        .into_iter()
        .filter(is_subject_side_revocation)
        .collect();
    newest_first(&mut rows);
    Ok(rows)
}
