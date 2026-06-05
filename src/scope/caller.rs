//! [`CallerScope`] — *who is asking* (FSD §4.1).
//!
//! Two variants, by design. The CEG cohort vocabulary
//! `{self, family, community, affiliations, species, biosphere,
//! federation}` lives on *rows*, not on callers. A sovereign-mode
//! agent is an `Authenticated` caller whose admission resolves to its
//! own identity with empty family/community sets (the §4.4 singleton
//! fallback) — not a distinct enum variant. Internal scope-bypassed
//! reads plumb through per-primitive `pub(crate)` `*_internal`
//! siblings (FSD §8.1), NOT a third `Internal` variant.

use super::admission::CallerAdmission;

/// The scope of a read caller (FSD §4.1).
///
/// Exactly two variants:
///
/// - [`CallerScope::Unauthenticated`] admits rows tagged
///   `cohort_scope ∈ {community, affiliations, species, biosphere,
///   federation}` — the non-suppressed tiers per §8.1.13.3. It refuses
///   `self` + `family` (for which
///   `cohort_scope::suppresses_holds_bytes` is true).
/// - [`CallerScope::Authenticated`] additionally admits `self` /
///   `family` / `community` rows, but only by *admission resolution*
///   on the caller's identity — never by caller assertion. The
///   admission set is substrate-built (see
///   [`build_caller_admission`](super::build_caller_admission)).
#[derive(Clone, Debug)]
pub enum CallerScope {
    /// Unauthenticated reader. Admits rows tagged cohort_scope ∈
    /// {community, affiliations, species, biosphere, federation} —
    /// the non-suppressed tiers per §8.1.13.3. Refuses self + family
    /// (cohort_scope::suppresses_holds_bytes returns true for those).
    Unauthenticated,

    /// Authenticated caller. Admission is *substrate-built* from the
    /// caller's occurrence key — never caller-asserted (FSD §4.2,
    /// THREAT_MODEL AV-44). Self/family/community are NOT enum
    /// variants; they are admission *resolutions* on the caller's
    /// identity.
    Authenticated {
        /// The substrate-resolved admission set. Constructed only via
        /// [`build_caller_admission`](super::build_caller_admission);
        /// [`CallerAdmission`] has no public constructor.
        admission: CallerAdmission,
    },
}

impl CallerScope {
    /// `true` for [`CallerScope::Authenticated`].
    pub fn is_authenticated(&self) -> bool {
        matches!(self, CallerScope::Authenticated { .. })
    }

    /// The resolved admission, when authenticated.
    pub fn admission(&self) -> Option<&CallerAdmission> {
        match self {
            CallerScope::Authenticated { admission } => Some(admission),
            CallerScope::Unauthenticated => None,
        }
    }
}
