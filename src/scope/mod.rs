//! CallerScope — the v4.0 scope substrate (CIRISPersist#150, FSD §4).
//!
//! This module lands the read-side cohort_scope admission primitive:
//!
//! - [`CallerScope`] (`caller.rs`) — the two-variant enum expressing
//!   *who is asking* (`Unauthenticated` / `Authenticated`). The CEG
//!   cohort vocabulary `{self, family, community, affiliations,
//!   species, biosphere, federation}` lives on *rows*, not callers —
//!   so there is deliberately no third variant (FSD §2.2, §4.1).
//! - [`CallerAdmission`] (`admission.rs`) — the substrate-resolved
//!   admission set carried by `Authenticated`. Its constructor is
//!   crate-private; the only public path to one is
//!   [`build_caller_admission`]. This is the AV-44 forge-resistance
//!   mitigation (FSD §13): a caller cannot fabricate an admission by
//!   struct-literal construction because there is no public ctor.
//! - [`cohort_scope_sql_predicate`] (`sql.rs`) — the WHERE-fragment +
//!   bind-param emitter that AND-composes the §4.3 cohort_scope gate
//!   into a read query, for both backends.
//!
//! Per the cut sequence (FSD §15 Commit B) these types land additive —
//! they are NOT yet wired into the `ReadEngine` trait methods (that is
//! Commit E) and the read `Error` enum is NOT rewritten here. This
//! module only *defines* [`ScopeRefusalReason`] so Commit E can wire
//! `Error::ScopeRefused(#[from] ScopeRefusalReason)`.
//!
//! # `KeyId`
//!
//! The federation substrate refers to keys as plain `String` /
//! `&str` `federation_keys.key_id` values throughout
//! (`IdentityOccurrence::identity_key_id`, `FamilyMember::key_id`,
//! etc.). v4.0 introduces [`KeyId`] as a *type alias* over `String`
//! so the FSD §4.1 struct shapes read literally; it is intentionally
//! a transparent alias (not a newtype) so it composes with every
//! existing `&str`-keyed `FederationDirectory` method without
//! conversion. A future cut may promote it to a newtype; that is a
//! separate change with its own break budget.

pub mod admission;
pub mod caller;
pub mod sql;

/// A `federation_keys.key_id` — the substrate's identity for a key.
///
/// Transparent alias over `String` (see module docs). Used for the
/// `occurrence_key_id` / `identity_key_id` / family / community key
/// fields on [`CallerAdmission`].
pub type KeyId = String;

pub use admission::{build_caller_admission, AdmissionError, CallerAdmission};
pub use caller::CallerScope;
pub use sql::{cohort_scope_sql_predicate, BackendKind, ScopeParam};

/// Structured reason a read (or, post-Commit-F, a write) was refused
/// by the cohort_scope admission gate (FSD §8.2).
///
/// `&'static str` was insufficient: consumers (lens UI, audit
/// dashboards, automated policy enforcement) need to distinguish
/// *why* the scope refused — wrong identity vs no family membership
/// vs no community membership vs boundary-auth failure are different
/// conditions with different remediations.
///
/// AV-15 stable-token discipline (FSD §8.2): the single token crossing
/// the PyO3 / HTTP boundary is `read_scope_refused`; the per-variant
/// tag below is a separate closed-set `&'static str` available via
/// [`ScopeRefusalReason::kind`] for callers needing machine-distinguishable
/// detail. The `Display` form goes to tracing only.
///
/// Commit E folds this into the read `Error` enum as
/// `Error::ScopeRefused(#[from] ScopeRefusalReason)`; Commit F reuses
/// the same enum on the write side (`check_write_cohort_scope`,
/// FSD §4.6). The `InvalidCohortScope` arm exists for the write-side
/// dispatch's closed-set fall-through (§4.6) — it carries the
/// offending label.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeRefusalReason {
    /// Caller's identity ≠ emitter's identity for a `cohort_scope: self`
    /// row.
    #[error("caller identity does not match emitter identity for self-scoped row")]
    WrongIdentity,

    /// Caller's identity is not a member of any family containing the
    /// emitter's identity, for a `cohort_scope: family` row.
    #[error("caller's identity is not a member of any family containing the emitter's identity")]
    NoFamilyMembership,

    /// Caller's identity is not a member of any community containing
    /// the emitter's identity, for a `cohort_scope: community` row.
    #[error(
        "caller's identity is not a member of any community containing the emitter's identity"
    )]
    NoCommunityMembership,

    /// Caller's `occurrence_key_id` could not be resolved through any
    /// substrate primitive — neither bound as an occurrence nor present
    /// as an identity in any family/community. Boundary auth held that
    /// the key is real; substrate can't admit any cohort beyond the
    /// non-suppressed tiers. Treated as Unauthenticated visibility plus
    /// the singleton-identity fallback (FSD §4.4).
    #[error("occurrence_key_id could not be resolved to an admission")]
    BoundaryAuthFailed,

    /// Unauthenticated caller attempted to read self/family-scoped
    /// content. The §8.1.13.3 structural-invisibility rule applies even
    /// at the SQL layer.
    #[error("unauthenticated caller cannot read structurally-invisible cohort scopes")]
    UnauthenticatedSuppressedCohort,

    /// A write (Commit F, FSD §4.6) claimed a `cohort_scope` label that
    /// is not in the closed CEG cohort vocabulary. Carries the
    /// offending label for diagnostics. Read-side admission never
    /// produces this (the predicate only ever emits known labels); it
    /// exists so the write-side dispatch's closed-set match has a typed
    /// fall-through reusing this enum.
    #[error("cohort_scope label is not in the closed CEG vocabulary: {0}")]
    InvalidCohortScope(String),
}

impl ScopeRefusalReason {
    /// Closed-set machine token for this refusal reason. Distinct from
    /// the boundary-crossing `read_scope_refused` token (FSD §8.2 /
    /// AV-15) — this is the *detail* tag consumers branch on.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::WrongIdentity => "scope_wrong_identity",
            Self::NoFamilyMembership => "scope_no_family_membership",
            Self::NoCommunityMembership => "scope_no_community_membership",
            Self::BoundaryAuthFailed => "scope_boundary_auth_failed",
            Self::UnauthenticatedSuppressedCohort => "scope_unauthenticated_suppressed_cohort",
            Self::InvalidCohortScope(_) => "scope_invalid_cohort_scope",
        }
    }
}
