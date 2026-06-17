//! CIRISNodeCore federation-consensus substrate (v0.7.0+).
//!
//! Implementation of [`FSD/CIRIS_PERSIST.md`](../../../FSD/CIRIS_PERSIST.md)
//! Appendix A. Persist hosts the federation-consensus row classes
//! (Contribution / Vote / Ledger / Moderation / Slashing /
//! Reconsideration) that `CIRISNodeCore` produces. This is a
//! **distinct track** from the v0.6.x lens/agent/bridge substrate
//! — different consumer ecosystem, different Cargo feature
//! (`cirisnode`), different PostgreSQL schema (`cirisnode.*` vs
//! `cirislens.*` / `cirislens_secrets.*`).
//!
//! # Why a separate substrate
//!
//! Per FSD Appendix A.1, the federation-consensus row classes are
//! structurally distinct from the agent-local runtime state that
//! Phase 3 of the main FSD subsumes (`tasks`, `thoughts`,
//! `agent_deferrals_*`, etc.). The agent-local tables hold one
//! agent's runtime state; the federation-consensus tables hold the
//! federation's consensus output across N agents + N witnesses.
//! Same persist crate, different write paths, different audit
//! semantics.
//!
//! # Surface (FSD Appendix A.2 + A.3)
//!
//! - **8 typed-write methods** on the [`NodeCoreService`] trait
//!   (v0.7.0-α3): `put_contribution`, `cast_vote`,
//!   `update_credits_ledger`, `update_expertise_ledger`,
//!   `put_moderation_event`, `put_slashing_attestation`,
//!   `put_reconsideration_request`, `put_reconsideration_attestation`.
//! - **5 read-surface clusters** (v0.7.0-α3): routing-eligibility,
//!   vote-weighting, bulk-list (newest-first cursor pagination,
//!   matching the v0.5.5 §I shape), pending-vs-canonical split,
//!   ledger point-lookups.
//!
//! # Audit envelope discipline
//!
//! Every row carries the standard CIRISPersist audit columns
//! (`signature`, `signing_key_id`, `signature_verified`,
//! `original_content_hash`, `scrub_signature_classical`,
//! `scrub_signature_pqc`, `scrub_key_id`, `scrub_timestamp`,
//! `pqc_completed_at`, `persist_row_hash`). The ingest path
//! verifies the hybrid Ed25519 + ML-DSA-65 signature before INSERT
//! (matches federation_directory discipline from V004).
//!
//! # Scope per release
//!
//! - **v0.7.0-α1** (this commit): Cargo feature + V011 migration
//!   + module skeleton + [`Error`] type with stable `kind()` tokens.
//! - **v0.7.0-α2**: wire types (`ContributionEnvelope`,
//!   `VoteEnvelope`, payload variants per `CIRISNodeCore/SCHEMA.md`
//!   §3–§10).
//! - **v0.7.0-α3**: `NodeCoreService` trait surface (8 writes + 5
//!   reads, `impl Future + Send` GAT pattern).
//! - **v0.7.0-α4**: `PostgresBackend` impl.
//! - **v0.7.0-α5**: Engine PyO3 wraps.
//! - **v0.7.0**: release tag.

pub mod federation_announcement;
pub mod media_sharing;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub mod takedown_handler;
pub mod types;
pub mod verify;

pub use federation_announcement::{
    encode_canonical_hash_base64, encode_signature_base64, enforce_constitutional_asymmetry,
    extract_announcement_payload, AccordCarrier, AnnouncementKind, AnnouncementPriority,
    AuthorityClass, DeliveryAttestation, FederationAnnouncementPayload, TransportMedium,
    DELIVERY_ATTESTATION_DOMAIN, SUBJECT_KIND,
};
pub use media_sharing::{
    extract_key_grant_payload, extract_takedown_notice_payload, KeyGrantPayload, KeyGrantScope,
    KeyValidityWindow, LegalBasis, MultimediaConfig, MultimediaConfigWire, TakedownNoticePayload,
    WrapAlgorithm, KEY_GRANT_SUBJECT_KIND, TAKEDOWN_NOTICE_SUBJECT_KIND,
};
pub use service::{NodeCoreService, RetireKeyGrantsReport};
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub use takedown_handler::{
    process_takedown_admission, process_takedown_admission_with_config, TakedownReport,
};
// v1.3.0 (CIRISPersist#47): convenience re-export of the
// FederationDirectory trait so NodeCore consumers can use either
// `ciris_persist::federation::FederationDirectory` (canonical) or
// `ciris_persist::cirisnode::FederationDirectory` (sibling-pattern
// matches the v0.7.0 NodeCoreService import path). This unblocks
// NodeCore's `pub use ciris_persist::cirisnode::{FederationDirectory,
// TrustGrant, TrustRow, TrustFilter}` replacement of its local
// placeholder trait definition in `src/trust.rs`.
pub use crate::federation::{
    FederationDirectory, TrustFilter, TrustGrant, TrustRelationship, TrustRow, TrustType,
};
pub use types::{
    Cell, ContributionEnvelope, ContributionListPage, ContributionType, ContributionsFilter,
    CreditsLedgerEntry, CreditsUpdate, DiversityProof, ExpertiseLedgerEntry, ExpertiseUpdate,
    HybridSignature, KeyGrantFilter, KeyGrantListPage, ListCursor, ModerationEvent,
    PromotionAttestation, ReconsiderationAttestation, ReconsiderationRequest, RoutableContributor,
    SlashingAttestation, TakedownFilter, TakedownListPage, TargetRowKind, VoteEnvelope,
    VoteListPage, VoteWeight, VotesFilter, Witness, WitnessSet,
};

/// Federation-consensus-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens for HTTP / PyO3
/// sanitization. Verbose `Display` messages stay in tracing only.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments (malformed envelope,
    /// unknown contribution_type, missing required field, etc.).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Authorization layer rejected the operation (e.g. cast_vote
    /// from a voter whose Expertise ledger entry is below the
    /// minimum required by the cell's voting policy).
    #[error("not authorized: {0}")]
    NotAuthorized(String),

    /// Signature verification failed on a typed-write envelope.
    /// Persist refuses to insert; caller must re-sign and retry.
    #[error("signature: {0}")]
    Signature(String),

    /// Conflict on a uniqueness constraint — duplicate
    /// contribution_id, voter casting twice on the same subject,
    /// etc. Caller decides whether to surface as a 409 or no-op.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Row not found (read-side path) — recall, ledger point-lookup,
    /// etc. Distinct from `NotAuthorized` (which implies the row
    /// EXISTS but caller can't access it).
    #[error("not found: {0}")]
    NotFound(String),

    /// Backend-level error (DB connection, JSONB serialization).
    /// String-typed because each backend has its own error tree.
    #[error("backend: {0}")]
    Backend(String),

    /// Surface declared on the trait but the backend doesn't
    /// implement it. Memory backend returns this for the typed
    /// write paths; sqlite backend (when added) likewise.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),

    /// Internal serialization / type-conversion bug. Indicates a
    /// persist bug; operators should file an issue.
    #[error("internal: {0}")]
    Internal(String),

    /// v8.7.1 (CIRISPersist#233, CEG RC24/RC25/RC26 §11.10 / §11.11 /
    /// §5.6.8.10) — a moderation / takedown primitive
    /// (`ModerationEvent` / `takedown_notice`) emission was refused: the
    /// signer neither holds the duty as-self (it is NOT a subject of the
    /// target content nor a named moderator of the target community) NOR is
    /// reached by an owner-bound duty-holder via a live `delegates_to`
    /// chain bearing the governing scope (`moderate` / `takedown`). The row
    /// is not stored. This is the cirisnode-surface
    /// image of [`crate::federation::Error::DelegatedScopeUnauthorized`] —
    /// the §11.10 child-safety / "takedown isn't a coup" gate. Distinct
    /// from [`Error::NotAuthorized`] so consumers can pattern-match the
    /// delegated-duty rejection deterministically (stable `kind()` token
    /// `cirisnode_delegated_scope_unauthorized`).
    #[error("delegated-duty emission not admitted: {0}")]
    DelegatedScopeUnauthorized(String),

    /// v2.1 (CIRISPersist#101) — the constitutional asymmetry
    /// (FSD §4.5) was violated: either `AccordCarrier` priority was
    /// claimed under a non-HumanityAccord authority class, or a
    /// HumanityAccord authority signed something other than
    /// `AccordCarrier`, or `AccordCarrier` priority and kind were
    /// mismatched. Wire-isolation between the humanity-accord
    /// hierarchy and the federation-governance hierarchy is enforced
    /// at admission; the schema's CHECK / trigger is the same rule
    /// applied at storage. Distinguished from `InvalidArgument` so
    /// callers can detect the constitutional violation specifically
    /// (audit-chain framing, telemetry per-kind counters).
    #[error("federation announcement authority mismatch: {0}")]
    FederationAnnouncementAuthorityMismatch(String),
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    /// Mirrors the kind() convention from `crate::secrets::SecretsError`
    /// / `crate::read::Error` / `crate::pipeline::Error`.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "cirisnode_invalid_argument",
            Error::NotAuthorized(_) => "cirisnode_not_authorized",
            Error::Signature(_) => "cirisnode_signature",
            Error::Conflict(_) => "cirisnode_conflict",
            Error::NotFound(_) => "cirisnode_not_found",
            Error::Backend(_) => "cirisnode_backend",
            Error::NotImplemented(_) => "cirisnode_not_implemented",
            Error::Internal(_) => "cirisnode_internal",
            Error::DelegatedScopeUnauthorized(_) => "cirisnode_delegated_scope_unauthorized",
            Error::FederationAnnouncementAuthorityMismatch(_) => {
                "cirisnode_federation_announcement_authority_mismatch"
            }
        }
    }
}

/// v8.7.1 (CIRISPersist#233, CEG RC24/RC25/RC26 §11.10) — run the FULL
/// §11.10 moderation admit-iff gate for a cirisnode primitive
/// (`ModerationEvent` / `takedown_notice`) and translate a federation
/// rejection into the cirisnode-surface
/// [`Error::DelegatedScopeUnauthorized`].
///
/// `signer` is the emission's verified author (`accuser_id` for a
/// `ModerationEvent`, `author_id` for a `takedown_notice` Contribution).
/// `subjects` + `community_id` are the producer-declared target descriptor
/// (the content's subjects + the target community); this resolves the
/// `duty_holders` (subjects ∪ the community's named moderators) and runs
/// the gate. `duty` is `moderate` / `takedown` / `review`.
/// `target_descriptor` is an audit string naming the target. Admit IFF the
/// signer is a duty-holder (as-self) or an owner-bound holder reaches the
/// signer via a live `duty`-scoped chain; the v8.7.0 absent-⇒-admit bypass
/// is GONE (no duty-holder ⇒ REJECT). Delegates to
/// [`crate::federation::admission::check_moderation_admission`] so the
/// scope-isolation + attenuation + sub_delegation + depth-cap + owner-bound
/// properties are identical to the report-`scores` path.
///
/// A federation [`Backend`](crate::federation::Error::Backend) error from
/// the directory walk maps to [`Error::Backend`]; the authority rejection
/// maps to [`Error::DelegatedScopeUnauthorized`]; any other federation
/// error is surfaced as [`Error::Internal`] (none are expected here).
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub async fn check_moderation_or_reject(
    directory: &dyn crate::federation::FederationDirectory,
    signer: &str,
    subjects: &[String],
    community_id: &str,
    duty: &str,
    target_descriptor: &str,
) -> Result<(), Error> {
    let duty_holders = match crate::federation::admission::duty_holders_for_content(
        directory,
        subjects,
        community_id,
        duty,
    )
    .await
    {
        Ok(h) => h,
        Err(crate::federation::Error::Backend(e)) => return Err(Error::Backend(e)),
        Err(e) => {
            return Err(Error::Internal(format!(
                "moderation duty-holder resolution unexpected federation error: {e}"
            )))
        }
    };
    match crate::federation::admission::check_moderation_admission(
        directory,
        signer,
        &duty_holders,
        duty,
        target_descriptor,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(crate::federation::Error::DelegatedScopeUnauthorized {
            signer,
            on_behalf_of: target,
            scope,
        }) => Err(Error::DelegatedScopeUnauthorized(format!(
            "signer {signer} holds neither the {scope} duty as-self over {target} nor a live \
             {scope}-scoped delegates_to chain from an owner-bound duty-holder (CEG §11.10)"
        ))),
        Err(crate::federation::Error::Backend(e)) => Err(Error::Backend(e)),
        Err(e) => Err(Error::Internal(format!(
            "moderation gate unexpected federation error: {e}"
        ))),
    }
}

/// v8.7.1 (CIRISPersist#233, CEG §11.10) — extract the producer-declared
/// **target descriptor** from a cirisnode moderation/takedown payload: the
/// target content's `subject_key_ids` (the people the content is ABOUT — a
/// subject may take down content about themselves) and the target
/// `community_id` (whose named moderators hold the duty). Both default to
/// empty/absent.
///
/// **Honesty note (flagged, CIRISPersist#233).** The cirisnode payload
/// surface (`TakedownNoticePayload` / `ModerationEvent.payload`) carries
/// `content_sha256` / `target_contributor`, NOT a content→subjects index;
/// persist has no `content_sha256 → subject_key_ids` lookup (the
/// `subject_key_ids` live on the federation `scores`/content attestation,
/// not on the cirisnode Contribution row). So the cirisnode gate resolves
/// authority over the **producer-declared** `subject_key_ids` +
/// `community_id` in the payload — exactly as the report→`scores` path uses
/// the row's own `subject_key_ids` + envelope `community_id`. Persist
/// enforces authority over the declared target; it does not re-derive the
/// content's true subject set from the hash (no such index exists).
pub fn payload_target_descriptor(payload: &serde_json::Value) -> (Vec<String>, String) {
    let subjects = payload
        .get("subject_key_ids")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let community_id = payload
        .get("community_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    (subjects, community_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kind_tokens_stable() {
        assert_eq!(
            Error::InvalidArgument("x".into()).kind(),
            "cirisnode_invalid_argument"
        );
        assert_eq!(
            Error::NotAuthorized("x".into()).kind(),
            "cirisnode_not_authorized"
        );
        assert_eq!(Error::Signature("x".into()).kind(), "cirisnode_signature");
        assert_eq!(Error::Conflict("x".into()).kind(), "cirisnode_conflict");
        assert_eq!(Error::NotFound("x".into()).kind(), "cirisnode_not_found");
        assert_eq!(Error::Backend("x".into()).kind(), "cirisnode_backend");
        assert_eq!(
            Error::NotImplemented("x").kind(),
            "cirisnode_not_implemented"
        );
        assert_eq!(Error::Internal("x".into()).kind(), "cirisnode_internal");
    }
}
