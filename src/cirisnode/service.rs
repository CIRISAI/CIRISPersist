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

/// v36.0.0 (CIRISPersist#711) — **which step of retiring ONE grant
/// failed**, for a [`RetireGrantFailure`].
///
/// Closed, and every variant corresponds to exactly ONE branch in the
/// backends' `retire_key_grants` loop — no `Other` catch-all, per the
/// #565 `KeyRefusalReason` discipline: a catch-all reintroduces the
/// disjunction one name deeper. Serde tokens are snake_case and
/// [`Self::as_str`] returns the SAME token, so a consumer keys on a
/// program constant and never on a message string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetireFailureStage {
    /// The prior grant's stored `payload` did not decode as a
    /// `KeyGrantPayload`, so no supersession sentinel could even be
    /// composed against it.
    PriorPayloadDecode,
    /// Composing/emitting the supersession sentinel failed — signer
    /// error, or the sentinel refused by persist's own `key_grant`
    /// validator (the #704 shape: a legacy transit grant with no
    /// `ifac_size` yields a sentinel the v34.0.0 rule refuses).
    SupersessionEmission,
}

impl RetireFailureStage {
    /// The **stable program token** for this stage — identical to the
    /// serde token (bound together by a test), so a consumer that reads
    /// the FFI JSON and a consumer that holds the typed value key on
    /// the same constant. Append-only; never re-spell a token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PriorPayloadDecode => "prior_payload_decode",
            Self::SupersessionEmission => "supersession_emission",
        }
    }

    /// Every variant, in declaration order — the closed set.
    pub const ALL: &'static [Self] = &[Self::PriorPayloadDecode, Self::SupersessionEmission];
}

/// v36.0.0 (CIRISPersist#711) — one prior grant that
/// [`NodeCoreService::retire_key_grants`] could **not** retire: WHICH
/// grant (so an operator can act on the row that is still live) and WHY
/// (stage + the underlying error text, the same facts the warn log
/// carries — but in the type, where a caller cannot miss them).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RetireGrantFailure {
    /// `contribution_id` of the prior grant whose material is STILL
    /// LIVE — on a transit grant, a passphrase revocation that did not
    /// happen.
    pub contribution_id: String,
    /// Which step failed. See [`RetireFailureStage`].
    pub stage: RetireFailureStage,
    /// Rendered error from the failing step. Diagnostic text — key on
    /// [`Self::stage`], never on this string.
    pub error: String,
}

/// v36.0.0 (CIRISPersist#711) — outcome of
/// [`NodeCoreService::retire_key_grants`]. **Replaces
/// `RetireKeyGrantsReport`**, whose `supersedes_failed` counter let a
/// `?`-style caller read a retirement that retired nothing as success
/// (the passphrase-stays-live shape: revocation reported `Ok`, red
/// signal nowhere).
///
/// The two cases are distinct VARIANTS, so partial failure is
/// unrepresentable-as-success: there is no count to forget to check —
/// extracting anything from the value forces the caller to have chosen
/// what `Partial` means for it. Counts, not row echoes, in `Complete`:
/// the sentinels are ordinary contributions and readable back through
/// the list surfaces.
///
/// CEG 0.3 §5.6.8.4 — rotation_chain supersession (option b from
/// CIRISRegistry#38): each prior grant is retired by issuing a FRESH
/// `key_grant` Contribution whose `rotation_chain` is extended by the
/// prior `contribution_id`. The fresh grant's `wrapped_dek_base64` is
/// an empty/zero marker (revocation sentinel: recipient sees zero-length
/// DEK and knows the prior grant is retired).
///
/// Serde shape (the FFI JSON contract) is internally tagged on
/// `outcome`: `{"outcome":"complete","retired":N}` or
/// `{"outcome":"partial","retired":N,"failed":[{"contribution_id":…,
/// "stage":…,"error":…}]}`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
#[must_use = "a Partial outcome means prior grants are STILL LIVE — match on the variant \
              before treating the retirement as done"]
pub enum RetireKeyGrantsOutcome {
    /// EVERY prior grant seen was retired — a supersession sentinel was
    /// emitted against each of the `retired` grants found for the
    /// actor. Vacuously complete when the actor had no grants
    /// (`retired == 0`).
    Complete {
        /// Prior grants found AND superseded.
        retired: usize,
    },
    /// At least one prior grant was NOT retired — its material is
    /// still live. `failed` is non-empty by construction
    /// ([`Self::from_batch`] is the only builder the backends use) and
    /// names every unretired grant.
    Partial {
        /// Prior grants that WERE superseded in this call.
        retired: usize,
        /// The grants that were not, each with stage + error.
        failed: Vec<RetireGrantFailure>,
    },
}

impl RetireKeyGrantsOutcome {
    /// Fold a batch tally into the outcome: `Complete` iff `failed` is
    /// empty. The single build point both backends use, so
    /// `Partial { failed: vec![] }` — a partial outcome asserting no
    /// failures — is never constructed.
    pub fn from_batch(retired: usize, failed: Vec<RetireGrantFailure>) -> Self {
        if failed.is_empty() {
            Self::Complete { retired }
        } else {
            Self::Partial { retired, failed }
        }
    }

    /// Number of prior grants retired (superseded) by this call,
    /// whichever variant. NOT a success test — `Partial` also retires
    /// grants; match on the variant for that.
    #[must_use]
    pub const fn retired(&self) -> usize {
        match self {
            Self::Complete { retired } | Self::Partial { retired, .. } => *retired,
        }
    }
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

    /// v4.x (CIRISPersist#142 Cut C3b, CEG §10.5.3) → v34.0.0
    /// (CIRISPersist#704, CIRISEdge#492) — list every
    /// **scope-epoch-addressed** `key_grant` Contribution for
    /// `(scope_kind, scope_id, epoch)`, newest-first.
    ///
    /// `scope_kind` is the
    /// [`KeyGrantScope::as_str`](super::KeyGrantScope::as_str) token of the scope
    /// being resolved — the same string the write path projects onto
    /// `key_grant_scope_kind`. Every epoch-addressed scope reads through
    /// this ONE function:
    ///
    ///   - `"stream_epoch"` — the streaming epoch-DEK cascade
    ///     (CEG 0.15 §10.5.3). `scope_id` is the `stream_id`. This is
    ///     the catch-up / delivery read the cascade serves; persist
    ///     returns the grants and the consumer (LensCore) applies its
    ///     own P4 catch-up depth cap (the cap is a LensCore knob, NOT a
    ///     substrate constant — §10.5.3).
    ///   - `"transit_membership"` — the IFAC transit passphrase for
    ///     scoped transit (CIRISEdge#492). `scope_id` is the `netname`.
    ///
    /// # Why one function and not two
    ///
    /// The two scopes are the same OBJECT: an `(id, epoch)` pair with
    /// exactly one grant set per epoch, rotated by superseding the set
    /// and converged by reading it. A dedicated
    /// `list_key_grants_for_transit_epoch` beside a
    /// `…_for_stream_epoch` would be a second copy of one invariant —
    /// N implementations that agree only because someone diffed them,
    /// and that diverge the first time one is fixed alone. This repo
    /// tracks that failure mode as CIRISPersist#663. There is one
    /// predicate here because there is one thing to say.
    ///
    /// # `scope_kind` is load-bearing, not decoration
    ///
    /// `scope_id` is an id WITHIN `scope_kind`, so it is namespaced by
    /// it and by nothing else: a transit `netname` and a `stream_id`
    /// are drawn from different vocabularies and may collide as
    /// strings. Omitting the `scope_kind` predicate would let a transit
    /// grant whose netname equals some stream id, at the same epoch,
    /// land in a STREAMING reader's result set — two scopes' wrapped
    /// DEKs fused into one authorization list. The predicate is also
    /// what makes the V129 partial index
    /// `contributions_key_grant_scope_epoch` — leading on
    /// `(key_grant_scope_kind, key_grant_scope_id, key_grant_epoch)` —
    /// usable as a prefix rather than a scan.
    fn list_key_grants_for_scope_epoch(
        &self,
        scope_kind: &str,
        scope_id: &str,
        epoch: u64,
    ) -> impl Future<Output = Result<Vec<ContributionEnvelope>, Error>> + Send;

    /// v16 (CIRISPersist#432, CC 5.1 `CLM-epoch-keying`) — the
    /// dedicated `key_grant` WRITER. Verifies the envelope IS a
    /// well-formed `key_grant` Contribution
    /// ([`super::media_sharing::require_key_grant_envelope`]:
    /// `contribution_type=proposal`, `subject_kind=key_grant`, payload
    /// valid in exactly one addressing mode), then runs the FULL
    /// [`put_contribution`](Self::put_contribution) admission — trust
    /// gate + hybrid signature verification + payload re-validation +
    /// V054/V129 column projection. A scope-epoch-addressed grant
    /// written here for `(scope_kind, scope_id, epoch)` is served by
    /// [`list_key_grants_for_scope_epoch`](Self::list_key_grants_for_scope_epoch);
    /// a content-addressed grant is served by the
    /// [`list_key_grants_for`](Self::list_key_grants_for) /
    /// [`list_key_grants_for_content`](Self::list_key_grants_for_content)
    /// axes.
    ///
    /// # Conflict semantics
    ///
    /// The table PK is `contribution_id` — NOT `(stream_id, epoch,
    /// recipient)`. A duplicate `contribution_id` surfaces as
    /// [`Error::Conflict`]; re-granting the SAME `(stream_id, epoch,
    /// recipient_key_id)` under a fresh `contribution_id` appends a
    /// new grant row (reads are newest-first; supersession is
    /// expressed via `rotation_chain` /
    /// [`retire_key_grants`](Self::retire_key_grants), never by
    /// mutating a prior grant — grants are immutable audit rows).
    fn put_key_grant(
        &self,
        env: ContributionEnvelope,
    ) -> impl Future<Output = Result<(), Error>> + Send;

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
    ///   - The prior grant's ADDRESSING and description carried
    ///     verbatim: `recipient_key_id`, `content_sha256`, `epoch`,
    ///     `scope`, `scope_id`, `wrap_algorithm`, `ratchet_version`
    ///     and — v34.0.0 (#704) — `ifac_size`. The sentinel names the
    ///     same grant; a field copied by halves would describe a
    ///     different one.
    ///   - `wrapped_dek_base64` set to an empty/zero marker
    ///     (revocation sentinel; recipient sees zero-length DEK and
    ///     knows the grant is retired).
    ///   - `rotation_chain` extended with the prior grant's
    ///     `contribution_id`.
    ///
    /// v34.0.0 (#704) — the `wrap_algorithm =
    /// HpkeRfc9180BaseX25519AesGcm` line this block carried is gone with
    /// the variant: the emitter has always copied the prior grant's
    /// algorithm, and the classical wrap no longer exists to name.
    ///
    /// `actor_key_id` is the `author_id` of the prior grants. `signer`
    /// produces the canonical Ed25519 signature for the new
    /// Contribution envelope. `now` pins the wall-clock for the new
    /// rows.
    ///
    /// # Partial failure is a variant, not an error — and not success
    ///
    /// v36.0.0 (#711): a per-grant failure (payload decode, signer,
    /// sentinel refused by the validator) does NOT abort the batch —
    /// the remaining grants are still attempted, because retiring nine
    /// of ten is strictly safer than retiring four and stopping. But
    /// it is not representable as success either: the call returns
    /// [`RetireKeyGrantsOutcome::Partial`] naming every unretired
    /// grant. `Err(_)` is reserved for failures BEFORE the batch (the
    /// listing query). A `?`-style caller therefore holds an outcome it
    /// must match — the previous shape (a `supersedes_failed` counter
    /// inside an `Ok` report) read as a successful retirement that
    /// retired nothing, which on a transit grant leaves the IFAC
    /// passphrase live with no red signal anywhere.
    fn retire_key_grants(
        &self,
        actor_key_id: &str,
        signer: &dyn ciris_keyring::HardwareSigner,
        now: chrono::DateTime<chrono::Utc>,
    ) -> impl Future<Output = Result<RetireKeyGrantsOutcome, Error>> + Send;
}

#[cfg(test)]
mod tests {
    use super::{RetireFailureStage, RetireGrantFailure, RetireKeyGrantsOutcome};

    /// #565 discipline — the typed constant and the serde token are the
    /// SAME spelling, so a consumer keying on `as_str()` and a consumer
    /// reading the FFI JSON cannot drift apart.
    #[test]
    fn retire_failure_stage_tokens_match_serde() {
        for stage in RetireFailureStage::ALL {
            let wire = serde_json::to_value(stage).unwrap();
            assert_eq!(
                wire,
                serde_json::Value::String(stage.as_str().to_owned()),
                "serde token and as_str() diverged for {stage:?}"
            );
        }
    }

    /// [`RetireKeyGrantsOutcome::from_batch`] is the single build point:
    /// empty failures fold to `Complete`, any failure folds to
    /// `Partial` — so a `Partial` with an empty `failed` is never built.
    #[test]
    fn from_batch_folds_on_the_failure_set_711() {
        assert_eq!(
            RetireKeyGrantsOutcome::from_batch(2, vec![]),
            RetireKeyGrantsOutcome::Complete { retired: 2 }
        );
        let failure = RetireGrantFailure {
            contribution_id: "cid-1".into(),
            stage: RetireFailureStage::SupersessionEmission,
            error: "refused".into(),
        };
        let outcome = RetireKeyGrantsOutcome::from_batch(1, vec![failure.clone()]);
        assert_eq!(
            outcome,
            RetireKeyGrantsOutcome::Partial {
                retired: 1,
                failed: vec![failure],
            }
        );
        assert_eq!(outcome.retired(), 1);
    }

    /// The FFI JSON contract, pinned byte-for-byte on the tag + field
    /// names: `cirisnode_retire_key_grants_json`'s docstring promises
    /// this exact shape to Python consumers.
    #[test]
    fn outcome_wire_shape_is_the_documented_contract_711() {
        let complete = RetireKeyGrantsOutcome::Complete { retired: 2 };
        assert_eq!(
            serde_json::to_value(&complete).unwrap(),
            serde_json::json!({"outcome": "complete", "retired": 2})
        );
        let partial = RetireKeyGrantsOutcome::Partial {
            retired: 1,
            failed: vec![RetireGrantFailure {
                contribution_id: "cid-9".into(),
                stage: RetireFailureStage::PriorPayloadDecode,
                error: "bad json".into(),
            }],
        };
        assert_eq!(
            serde_json::to_value(&partial).unwrap(),
            serde_json::json!({
                "outcome": "partial",
                "retired": 1,
                "failed": [{
                    "contribution_id": "cid-9",
                    "stage": "prior_payload_decode",
                    "error": "bad json",
                }],
            })
        );
    }
}
