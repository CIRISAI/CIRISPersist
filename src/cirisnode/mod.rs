//! CIRISNodeCore federation-consensus substrate (v0.7.0+; v60.0.0 rows).
//!
//! Implementation of [`FSD/CIRIS_PERSIST.md`](../../../FSD/CIRIS_PERSIST.md)
//! Appendix A. The federation-consensus classes — Contribution, Vote,
//! Credits / Expertise, Moderation, Slashing, Reconsideration, takedown
//! notice — are CC 3.1.9 dimensions.
//!
//! # v60.0.0 (CIRISPersist#988 item 1, #803, #854) — the classes are rows
//!
//! Signed attestations are the only state (CEWPOS). Every class is a
//! hybrid-signed `scores` row on the attestation plane ([`rows`]), admitted
//! by the plane's door and replicated like any row. The `cirisnode.*` typed
//! tables that held self-signed Ed25519-only copies are gone (V203); what
//! stays is what is not a claim ([`NodeCoreService`]): the credits and
//! expertise ledgers as PROJECTIONS of this node's balance rows
//! ([`crate::federation::ledger_projection`]), the promotion records and the
//! delivery attestations (local bookkeeping), and the scheduled takedown
//! actions table. The `key_grant` Contribution is retired (the key-grant
//! plane is the one door for a wrapped key), and a v59 typed envelope
//! offered at a door is refused by name ([`rows::refusal`]).
//!
//! The Python surface keeps its method names; each is a thin wrapper that
//! plans the row and signs it with the engine's own key (CHANGELOG
//! `## [60.0.0]` lists every signature change).

pub mod federation_announcement;
pub mod media_sharing;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod rows;
#[cfg(test)]
mod rows_invariants;
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
    extract_takedown_notice_payload, LegalBasis, TakedownNoticePayload, KEY_GRANT_SUBJECT_KIND,
    TAKEDOWN_NOTICE_SUBJECT_KIND,
};
pub use rows::{
    ContributionInput, ContributionsFilter, ModerationInput, ReconsiderationRequestInput,
    ReconsiderationRulingInput, RowPage, SlashingInput, VoteInput,
};
pub use service::{LegacyLedgerRow, NodeCoreService};
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub use takedown_handler::process_takedown_admission;
// v1.3.0 (CIRISPersist#47): convenience re-export of the
// FederationDirectory trait so NodeCore consumers can use either
// `ciris_persist::federation::FederationDirectory` (canonical) or
// `ciris_persist::cirisnode::FederationDirectory`.
pub use crate::federation::{
    FederationDirectory, TrustFilter, TrustGrant, TrustRelationship, TrustRow, TrustType,
};
pub use types::{
    Cell, ContributionType, CreditsLedgerEntry, CreditsUpdate, DiversityProof,
    ExpertiseLedgerEntry, ExpertiseUpdate, HybridSignature, PromotionAttestation,
    RoutableContributor, TargetRowKind, VoteWeight, Witness, WitnessSet,
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
    /// reached by an steward-bound duty-holder via a live `delegates_to`
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

    /// v60.0.0 (CIRISPersist#988 item 1) — a RETIRED cirisnode object was
    /// offered: a `key_grant` Contribution, or a v59 typed envelope at a
    /// door that now takes a row's body. `kind()` is the token
    /// ([`rows::refusal`]), so a consumer matches the retirement by name.
    #[error("{token}: {detail}")]
    Retired {
        /// The stable refusal token.
        token: &'static str,
        /// What was retired and what replaces it.
        detail: String,
    },

    /// v60.0.0 — the attestation plane refused (or failed) a cirisnode row.
    /// `kind()` is the plane's own token, so a moderation gate refusal reads
    /// `federation_delegated_scope_unauthorized` here exactly as at
    /// `put_attestation`.
    #[error("{0}")]
    Federation(Box<crate::federation::Error>),
}

impl From<crate::federation::Error> for Error {
    fn from(e: crate::federation::Error) -> Self {
        Error::Federation(Box::new(e))
    }
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
            Error::Retired { token, .. } => token,
            Error::Federation(e) => e.kind(),
        }
    }
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
