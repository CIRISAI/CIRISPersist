//! `NodeCoreService` trait — federation-consensus surface
//! (v0.7.0+; FSD Appendix A.2 + A.3).
//!
//! 8 typed-write methods + 5 read clusters that CIRISNodeCore
//! consumes. Same `impl Future<...> + Send` GAT pattern as
//! `crate::read::ReadEngine` / `crate::secrets::SecretsService` —
//! no `async_trait` dep.

use std::future::Future;

use super::types::{
    ContributionEnvelope, ContributionListPage, ContributionsFilter, CreditsLedgerEntry,
    CreditsUpdate, ExpertiseLedgerEntry, ExpertiseUpdate, ListCursor, ModerationEvent,
    PromotionAttestation, ReconsiderationAttestation, ReconsiderationRequest, RoutableContributor,
    SlashingAttestation, VoteEnvelope, VoteListPage, VoteWeight, VotesFilter,
};
use super::Error;

/// Federation-consensus substrate trait. 8 typed-write methods + 5
/// read clusters per FSD Appendix A.2 / A.3.
///
/// # Audit envelope invariant
///
/// Every typed-write method MUST verify the row's hybrid signature
/// against the federation directory before INSERT, and reject with
/// [`Error::Signature`] on mismatch. The PG impl threads this
/// through `verify_hybrid_via_directory` (v0.4.1 surface). Persist
/// refuses to store unverified rows.
///
/// # Conflict semantics
///
/// Duplicate writes (same `contribution_id`, same `vote_id`, etc.)
/// surface as [`Error::Conflict`]. Caller decides whether to treat
/// as a 409 or a no-op (typically idempotent at the consumer side
/// because the wire shape is content-addressed via the signature).
///
/// # Pending vs canonical
///
/// Per `CIRISNodeCore/SCHEMA.md` §13.2, every audit-chain row has
/// an `is_canonical` flag. Typed-writes INSERT with
/// `is_canonical=false` (pending); the canonical-promotion pass
/// (CIRISNodeCore-side) flips the flag when the row clears the
/// canonical audit-chain gate. List reads can filter on either tier
/// via [`ContributionsFilter::is_canonical`] / [`VotesFilter::is_canonical`].
pub trait NodeCoreService: Send + Sync {
    // ── Typed writes (FSD Appendix A.2) ─────────────────────────────

    /// Verify-and-insert a Contribution envelope. INSERTs as pending
    /// (`is_canonical=false`); canonical-promotion is a separate pass.
    fn put_contribution(
        &self,
        env: ContributionEnvelope,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Verify-and-insert a Vote envelope. Same shape as
    /// [`put_contribution`].
    fn cast_vote(&self, env: VoteEnvelope) -> impl Future<Output = Result<(), Error>> + Send;

    /// Upsert one row in `cirisnode.credits_ledger`. Idempotent on
    /// `(contributor_id, domain, language, subject)`.
    fn update_credits_ledger(
        &self,
        update: CreditsUpdate,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Upsert one row in `cirisnode.expertise_ledger`. Idempotent on
    /// `(contributor_id, domain, language)`.
    fn update_expertise_ledger(
        &self,
        update: ExpertiseUpdate,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Verify-and-insert a ModerationEvent.
    fn put_moderation_event(
        &self,
        event: ModerationEvent,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Verify-and-insert a SlashingAttestation. Caller must have
    /// already inserted the referenced `moderation_id`; the PG impl
    /// enforces the FK.
    fn put_slashing_attestation(
        &self,
        att: SlashingAttestation,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Verify-and-insert a ReconsiderationRequest.
    fn put_reconsideration_request(
        &self,
        req: ReconsiderationRequest,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Verify-and-insert a ReconsiderationAttestation.
    fn put_reconsideration_attestation(
        &self,
        att: ReconsiderationAttestation,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// v0.7.2 (CIRISPersist#32) — verify-and-insert a
    /// [`PromotionAttestation`], AND transactionally flip the named
    /// target rows from `is_canonical=FALSE` to `is_canonical=TRUE`
    /// (with `canonicalized_at = NOW()`).
    ///
    /// The transaction asserts that every named target_id exists in
    /// the table corresponding to `att.target_kind` — if the
    /// affected-row count does not equal `att.target_ids.len()`,
    /// the entire transaction rolls back with
    /// [`Error::InvalidArgument`] and no rows are mutated.
    ///
    /// Idempotency: targets already in canonical state (TRUE) still
    /// match the affected-row count (the UPDATE no-ops on them);
    /// callers retrying after a partial network failure get the
    /// same Conflict on `attestation_id` if the attestation row
    /// already INSERTed.
    fn put_promotion_attestation(
        &self,
        att: PromotionAttestation,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    // ── Read cluster 1: routing-eligibility (FSD A.3) ───────────────

    /// List contributors with non-zero Expertise in `(domain,
    /// language)`, filtered to Active tier. Used by
    /// `MISSION.md` §3.3 deferral routing (steps 1-2).
    fn routable_contributors(
        &self,
        domain: &str,
        language: &str,
    ) -> impl Future<Output = Result<Vec<RoutableContributor>, Error>> + Send;

    // ── Read cluster 2: vote-weighting ──────────────────────────────

    /// Compute `Credits(domain, language, subject) ×
    /// expertise_multiplier × active_tier_multiplier` for vote
    /// weighting per `SCHEMA.md` §5.2.
    fn read_vote_weight(
        &self,
        contributor_id: &str,
        domain: &str,
        language: &str,
        subject: &str,
    ) -> impl Future<Output = Result<Option<VoteWeight>, Error>> + Send;

    // ── Read cluster 3: bulk-list (cursor-paged newest-first) ───────

    /// Page through `cirisnode.contributions`. Mirrors v0.5.5 §I
    /// cursor shape: `(submitted_at, contribution_id)` tuple,
    /// newest-first.
    fn list_contributions(
        &self,
        filter: ContributionsFilter,
        cursor: Option<ListCursor>,
        limit: i64,
    ) -> impl Future<Output = Result<ContributionListPage, Error>> + Send;

    /// Page through `cirisnode.votes`.
    fn list_votes(
        &self,
        filter: VotesFilter,
        cursor: Option<ListCursor>,
        limit: i64,
    ) -> impl Future<Output = Result<VoteListPage, Error>> + Send;

    // ── Read cluster 4: ledger point-lookups ────────────────────────

    /// Point-lookup one Credits ledger row.
    fn get_credits_ledger(
        &self,
        contributor_id: &str,
        domain: &str,
        language: &str,
        subject: &str,
    ) -> impl Future<Output = Result<Option<CreditsLedgerEntry>, Error>> + Send;

    /// Point-lookup one Expertise ledger row.
    fn get_expertise_ledger(
        &self,
        contributor_id: &str,
        domain: &str,
        language: &str,
    ) -> impl Future<Output = Result<Option<ExpertiseLedgerEntry>, Error>> + Send;

    // (Read cluster 5 — pending-vs-canonical split — is folded into
    // list_contributions + list_votes via their `is_canonical` filter
    // field. No separate methods.)
}
