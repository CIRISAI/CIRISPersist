//! `NodeCoreService` trait — what the cirisnode track still stores itself
//! (v0.7.0+; FSD Appendix A.2 + A.3; narrowed in v60.0.0).
//!
//! v60.0.0 (CIRISPersist#988 item 1, #803, #854) — every cirisnode CLASS is a
//! signed `scores` row on the attestation plane (`super::rows`): a
//! Contribution, a vote, a moderation event, a slashing, a reconsideration,
//! a takedown notice, a credits or expertise balance. Their typed writes and
//! the tables behind them are gone (V203). What stays here is what is not a
//! claim:
//!
//! - the credits / expertise **ledger reads** — the ledgers are PROJECTIONS
//!   of this node's `credits:` / `expertise:` rows
//!   ([`crate::federation::ledger_projection`]), read here;
//! - the **promotion records** (local bookkeeping: which held rows the
//!   consensus pass promoted);
//! - the **delivery attestations** (a local receipt);
//! - the pre-V203 ledger rows still waiting to be re-emitted as rows
//!   ([`NodeCoreService::legacy_ledger_rows`]).
//!
//! Same `impl Future<...> + Send` GAT pattern as `crate::read::ReadEngine` /
//! `crate::secrets::SecretsService` — no `async_trait` dep.

use std::future::Future;

use super::federation_announcement::DeliveryAttestation;
use super::types::{
    CreditsLedgerEntry, CreditsUpdate, ExpertiseLedgerEntry, ExpertiseUpdate, PromotionAttestation,
    RoutableContributor, VoteWeight,
};
use super::Error;

/// v62.0.0 (P1-fix8; CC 2.6.1.5) — a ledger decimal as stored: the
/// canonical decimal text sqlite holds as `TEXT` and postgres returns as
/// `numeric::text`. Anything else is a store that was written around the
/// projection — refused, never coerced.
///
/// # Errors
/// [`Error::Backend`] naming the column.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn stored_decimal(
    column: &str,
    text: &str,
) -> Result<crate::federation::ledger_projection::Decimal, Error> {
    crate::federation::ledger_projection::Decimal::parse_canonical(text).ok_or_else(|| {
        Error::Backend(format!(
            "{column} {text:?} is not a canonical decimal (the ledger stores exact decimals)"
        ))
    })
}

/// v62.0.0 (P1-fix8) — **routing order, exactly**: `(contributor_id,
/// expertise)` of a cell's ACTIVE rows, kept where the expertise is above
/// zero and ranked by it, greatest first, ties by contributor id. Done here,
/// on the exact decimal, for both backends: sqlite's `TEXT` cannot order a
/// decimal, and one rule keeps the two backends' answers equal.
///
/// # Errors
/// [`stored_decimal`]'s.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn rank_routable(
    rows: Vec<(String, String)>,
) -> Result<Vec<RoutableContributor>, Error> {
    let mut ranked = Vec::with_capacity(rows.len());
    for (contributor_id, text) in rows {
        let d = stored_decimal("expertise", &text)?;
        if !d.is_zero() && !d.is_negative() {
            ranked.push((d, contributor_id));
        }
    }
    ranked.sort_by(|(da, ca), (db, cb)| db.cmp(da).then_with(|| ca.cmp(cb)));
    Ok(ranked
        .into_iter()
        .map(|(d, contributor_id)| RoutableContributor {
            contributor_id,
            expertise: d.canonical(),
        })
        .collect())
}

/// v62.0.0 (P1-fix8) — **the vote weight from the two projections,
/// exactly** (`SCHEMA.md` §5.2,
/// [`crate::federation::ledger_projection::decimal::vote_weight`]): `None`
/// when neither ledger says anything (no credits, no expertise, not active),
/// as before. A missing ledger row is zero / inactive.
///
/// # Errors
/// [`stored_decimal`]'s.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) fn vote_weight_of(
    key: (&str, &str, &str, &str),
    credits: Option<String>,
    expertise: Option<(String, bool)>,
) -> Result<Option<VoteWeight>, Error> {
    use crate::federation::ledger_projection::{decimal, Decimal};
    let credits = match credits {
        Some(t) => stored_decimal("balance", &t)?,
        None => Decimal::zero(),
    };
    let (expertise, is_active) = match expertise {
        Some((t, a)) => (stored_decimal("expertise", &t)?, a),
        None => (Decimal::zero(), false),
    };
    if credits.is_zero() && expertise.is_zero() && !is_active {
        return Ok(None);
    }
    let (expertise_multiplier, active_tier_multiplier, weight) =
        decimal::vote_weight(&credits, &expertise, is_active);
    let (contributor_id, domain, language, subject) = key;
    Ok(Some(VoteWeight {
        contributor_id: contributor_id.to_owned(),
        domain: domain.to_owned(),
        language: language.to_owned(),
        subject: subject.to_owned(),
        credits: credits.canonical(),
        expertise_multiplier: expertise_multiplier.canonical(),
        active_tier_multiplier: active_tier_multiplier.canonical(),
        weight: weight.canonical(),
    }))
}

/// v60.0.0 — a pre-V203 ledger row with no backing row (`attestation_id`
/// NULL): what the rehome re-emits as this node's `credits:` /
/// `expertise:` row.
#[derive(Debug, Clone, PartialEq)]
pub enum LegacyLedgerRow {
    /// A credits balance.
    Credits(CreditsUpdate),
    /// An expertise balance.
    Expertise(ExpertiseUpdate),
}

/// The cirisnode track's own storage: ledger reads, promotion records,
/// delivery attestations. Every claim is a row (`super::rows`).
pub trait NodeCoreService: Send + Sync {
    /// v0.7.2 (CIRISPersist#32) → v60.0.0 — verify-and-insert a
    /// [`PromotionAttestation`] (local bookkeeping). Every named target must
    /// be a row THIS node holds on the target kind's family
    /// ([`super::rows::promotion_target_family`]); a target not held, or held
    /// on another family, refuses the whole record with
    /// [`Error::InvalidArgument`] and nothing is written. The pre-v60
    /// `is_canonical` flip is gone with the typed tables: a row is promoted
    /// when a promotion record names it.
    fn put_promotion_attestation(
        &self,
        att: PromotionAttestation,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// List contributors with non-zero Expertise in `(domain, language)`,
    /// filtered to Active tier, from the expertise projection.
    fn routable_contributors(
        &self,
        domain: &str,
        language: &str,
    ) -> impl Future<Output = Result<Vec<RoutableContributor>, Error>> + Send;

    /// `Credits(domain, language, subject) × expertise_multiplier ×
    /// active_tier_multiplier` per `SCHEMA.md` §5.2, from the projections.
    fn read_vote_weight(
        &self,
        contributor_id: &str,
        domain: &str,
        language: &str,
        subject: &str,
    ) -> impl Future<Output = Result<Option<VoteWeight>, Error>> + Send;

    /// Point-lookup one credits-ledger row (the projection).
    fn get_credits_ledger(
        &self,
        contributor_id: &str,
        domain: &str,
        language: &str,
        subject: &str,
    ) -> impl Future<Output = Result<Option<CreditsLedgerEntry>, Error>> + Send;

    /// Point-lookup one expertise-ledger row (the projection).
    fn get_expertise_ledger(
        &self,
        contributor_id: &str,
        domain: &str,
        language: &str,
    ) -> impl Future<Output = Result<Option<ExpertiseLedgerEntry>, Error>> + Send;

    /// v60.0.0 — every pre-V203 ledger row with no backing row, for the
    /// rehome. Empty once every legacy balance has been re-emitted.
    fn legacy_ledger_rows(
        &self,
    ) -> impl Future<Output = Result<Vec<LegacyLedgerRow>, Error>> + Send;

    // ── Federation delivery attestations (v2.1, CIRISPersist#101) ──

    /// Verify-and-insert a [`DeliveryAttestation`]. INSERTs idempotently on
    /// `(announcement_id, peer_key_id)` — a duplicate write returns `Ok(())`
    /// (replay-safe per FSD §3.2.1).
    ///
    /// Pre-insert verification:
    /// 1. shape: a 32-byte canonical hash ([`Error::InvalidArgument`]);
    /// 2. v60.0.0 — the announcement is a `contribution:federation_announcement`
    ///    row THIS node holds (the V046 foreign key's rule, now that the
    ///    announcement is a row; [`Error::InvalidArgument`]);
    /// 3. v62.0.0 (F0-cp5) — ONE composite signature over
    ///    [`DeliveryAttestation::canonical_bytes`] under `peer_key_id`'s LIVE
    ///    edition-2 key ([`super::verify::verify_delivery_attestation`];
    ///    [`Error::Signature`] led by the refusal's token).
    fn put_delivery_attestation(
        &self,
        attestation: DeliveryAttestation,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// All attestations for `announcement_id`, `received_at DESC`.
    fn list_delivery_attestations(
        &self,
        announcement_id: &str,
    ) -> impl Future<Output = Result<Vec<DeliveryAttestation>, Error>> + Send;

    /// Count attestations for `announcement_id`.
    fn count_delivery_attestations(
        &self,
        announcement_id: &str,
    ) -> impl Future<Output = Result<u64, Error>> + Send;
}
