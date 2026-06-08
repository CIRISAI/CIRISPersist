//! `NodeCoreService` trait — federation-consensus surface
//! (v0.7.0+; FSD Appendix A.2 + A.3).
//!
//! 8 typed-write methods + 5 read clusters that CIRISNodeCore
//! consumes. Same `impl Future<...> + Send` GAT pattern as
//! `crate::read::ReadEngine` / `crate::secrets::SecretsService` —
//! no `async_trait` dep.

use std::future::Future;

use super::federation_announcement::DeliveryAttestation;
use super::types::{
    ContributionEnvelope, ContributionListPage, ContributionsFilter, CreditsLedgerEntry,
    CreditsUpdate, ExpertiseLedgerEntry, ExpertiseUpdate, ListCursor, ModerationEvent,
    PromotionAttestation, ReconsiderationAttestation, ReconsiderationRequest, RoutableContributor,
    SlashingAttestation, VoteEnvelope, VoteListPage, VoteWeight, VotesFilter,
};
use super::Error;

/// v3.6.0 (CIRISPersist#134) — report from [`NodeCoreService::retire_key_grants`].
/// Counts the prior `key_grant` Contributions the caller's
/// `actor_key_id` issued, and how many supersession-grant Contributions
/// the method emitted against them.
///
/// CEG 0.3 §5.6.8.4 — rotation_chain supersession (option b from
/// CIRISRegistry#38): each prior grant is retired by issuing a FRESH
/// `key_grant` Contribution whose `rotation_chain` is extended by the
/// prior `contribution_id`. The fresh grant's `wrapped_dek_base64` is
/// an empty/zero marker (revocation sentinel: recipient sees zero-length
/// DEK and knows the prior grant is retired).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RetireKeyGrantsReport {
    /// Number of prior `key_grant` Contributions found for the actor.
    pub grants_seen: usize,
    /// Number of supersession-grant Contributions successfully emitted.
    pub supersedes_emitted: usize,
    /// Number of supersession-grant emissions that failed (signer / FK).
    pub supersedes_failed: usize,
}

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

    // ── Federation delivery attestations (v2.1, CIRISPersist#101) ──
    //
    // Per-peer attestation that the federation_announcement reached
    // the application layer. Persist stores the FSD §3.2.1 wire shape
    // one-to-one, gates the row's hybrid signature against
    // federation_keys[peer_key_id], and surfaces reach-verification
    // reads. Surface mirrors the cirisnode write/list pattern —
    // not `FederationDirectory` even though they share the
    // `peer_key_id → federation_keys` lookup, because the row's
    // canonical-chain FK targets `cirisnode.contributions` and the
    // surface belongs alongside the announcement that owns it.

    /// Verify-and-insert a [`DeliveryAttestation`]. INSERTs idempotently
    /// on `(announcement_id, peer_key_id)` — a duplicate write returns
    /// `Ok(())` (replay-safe per FSD §3.2.1 "AV: replayed attestation").
    ///
    /// Pre-insert verification:
    /// 1. `enforce` shape: 32-byte canonical hash, 64-byte Ed25519
    ///    signature, optional 3309-byte PQC signature (admission
    ///    error → [`Error::InvalidArgument`]).
    /// 2. Directory lookup: `peer_key_id` MUST exist in
    ///    `federation_keys`; absence → [`Error::Signature`].
    /// 3. Hybrid signature verify via
    ///    [`crate::verify::verify_hybrid_via_directory`] over
    ///    [`DeliveryAttestation::canonical_bytes`]; mismatch →
    ///    [`Error::Signature`].
    fn put_delivery_attestation(
        &self,
        attestation: DeliveryAttestation,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// List all attestations for `announcement_id`, ordered by
    /// `received_at DESC`. The primary reach-verification read path
    /// per FSD §3.2 — RATCHET / steward dashboards consume this to
    /// detect delivery gaps.
    fn list_delivery_attestations(
        &self,
        announcement_id: &str,
    ) -> impl Future<Output = Result<Vec<DeliveryAttestation>, Error>> + Send;

    /// Count attestations for `announcement_id`. Cheap convenience
    /// for reach-aggregate queries (returns `u64`; non-empty
    /// announcements with >2^63 attestations are not a real-world
    /// concern).
    fn count_delivery_attestations(
        &self,
        announcement_id: &str,
    ) -> impl Future<Output = Result<u64, Error>> + Send;

    // ── Media-sharing reads (v3.6.0, CIRISPersist#134) ─────────────
    //
    // Three indexed reads over the V054 media_sharing columns. Each
    // returns the underlying ContributionEnvelope rows newest-first
    // (`ORDER BY submitted_at DESC`).

    /// List every `takedown_notice` Contribution whose payload pins
    /// `content_sha256`. Indexed via V054 partial index on
    /// `media_content_sha256`.
    fn list_takedowns_for(
        &self,
        content_sha256: &str,
    ) -> impl Future<Output = Result<Vec<ContributionEnvelope>, Error>> + Send;

    /// List every `key_grant` Contribution whose payload pins
    /// `recipient_key_id`. Indexed via V054 partial index on
    /// `key_grant_recipient_key_id`.
    fn list_key_grants_for(
        &self,
        recipient_key_id: &str,
    ) -> impl Future<Output = Result<Vec<ContributionEnvelope>, Error>> + Send;

    /// List every `key_grant` Contribution that matches BOTH
    /// `content_sha256` AND `recipient_key_id`. Uses both V054 partial
    /// indexes (the planner picks the more selective one).
    fn list_key_grants_for_content(
        &self,
        content_sha256: &str,
        recipient_key_id: &str,
    ) -> impl Future<Output = Result<Vec<ContributionEnvelope>, Error>> + Send;

    /// v4.x (CIRISPersist#142 Cut C3b, CEG §10.5.3) — list every
    /// **stream/epoch-addressed** `key_grant` Contribution for
    /// `(stream_id, epoch)`, newest-first. This is the catch-up /
    /// delivery read the epoch-DEK cascade serves; persist returns the
    /// grants and the consumer (LensCore) applies its own P4 catch-up
    /// depth cap (the cap is a LensCore knob, NOT a substrate constant —
    /// §10.5.3). Indexed via the V064 partial index
    /// `contributions_key_grant_stream_epoch`.
    fn list_key_grants_for_stream_epoch(
        &self,
        stream_id: &str,
        epoch: u64,
    ) -> impl Future<Output = Result<Vec<ContributionEnvelope>, Error>> + Send;

    /// v3.6.0 (CIRISPersist#134) — emit a supersession `key_grant`
    /// Contribution against every prior `key_grant` Contribution
    /// issued by `actor_key_id`. Used when an actor's keying material
    /// is rotated out and prior grants must be retracted.
    ///
    /// # Emission shape
    ///
    /// CEG 0.3 §5.6.8.4 (option b from CIRISRegistry#38): each prior
    /// grant is retired by issuing a FRESH `key_grant` Contribution
    /// with:
    ///
    ///   - Same `recipient_key_id` + `content_sha256` as the prior
    ///     grant.
    ///   - `wrapped_dek_base64` set to an empty/zero marker
    ///     (revocation sentinel; recipient sees zero-length DEK and
    ///     knows the grant is retired).
    ///   - `wrap_algorithm = HpkeRfc9180BaseX25519AesGcm` (CEG 0.3
    ///     §5.6.8.4).
    ///   - `rotation_chain` extended with the prior grant's
    ///     `contribution_id`.
    ///
    /// `actor_key_id` is the `author_id` of the prior grants. `signer`
    /// produces the canonical Ed25519 signature for the new
    /// Contribution envelope. `now` pins the wall-clock for the new
    /// rows.
    fn retire_key_grants(
        &self,
        actor_key_id: &str,
        signer: &dyn ciris_keyring::HardwareSigner,
        now: chrono::DateTime<chrono::Utc>,
    ) -> impl Future<Output = Result<RetireKeyGrantsReport, Error>> + Send;
}
