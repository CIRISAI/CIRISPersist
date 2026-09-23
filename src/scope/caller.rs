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

    /// v17.4.0 — the Rust-side twin of
    /// [`cohort_scope_sql_predicate`](super::cohort_scope_sql_predicate)
    /// (FSD §4.3), for the memory backend's `scores` reads (which have no SQL
    /// to push the gate into). Returns `true` iff a row tagged `cohort_scope`
    /// with membership `target` (the row's `attested_key_id`) is admitted for
    /// this caller. Byte-for-byte the same semantics: broad tiers always
    /// admit; `self`/`family`/`community` admit only on target-membership;
    /// the unauthenticated reader sees only the broad tiers.
    ///
    /// `dimension` is the row's dimension (`envelope_dimension`), consulted
    /// on the `self` arm only: a SENSITIVE `config:*` leaf (CC 3.4.5.1,
    /// `CONFIG_SENSITIVE_LEAVES`) is node-local by the write floor and is
    /// admitted only when the caller IS the target — the collective widening
    /// of v46.3.1 (#888) must not carry it to the owner's other keys on a
    /// shared node (PR #889 review). `None` = a row with no dimension.
    /// `cohort_target` is the ROW's room, as its signed envelope states it
    /// (v46.5.0, CIRISPersist#893). The arms take DIFFERENT targets and that
    /// is the point: `self` compares `target` (the row's `attested_key_id`)
    /// against the caller's self-collective by principal (#888), while
    /// `family` / `community` compare the ROOM against the caller's admitted
    /// rooms — the predicate the hold path and edge's serve gate already use.
    /// Passing the attested key to the targeted arms is what #893 was: AV-84
    /// pins that column to the PRODUCER, so the intersection with a room set
    /// is empty by construction and no member could read their own room.
    pub fn admits(
        &self,
        cohort_scope: &str,
        target: &str,
        cohort_target: Option<&str>,
        dimension: Option<&str>,
    ) -> bool {
        const BROAD: &[&str] = &["affiliations", "species", "biosphere", "federation"];
        if BROAD.contains(&cohort_scope) {
            return true;
        }
        match self {
            CallerScope::Unauthenticated => false,
            CallerScope::Authenticated { admission } => match cohort_scope {
                // v46.3.1 (#888): the target is one of the caller's own keys
                // — resolved on BOTH sides (FSD/OCCURRENCE_PRINCIPAL.md §6).
                "self" => {
                    admission.self_key_ids.contains(target)
                        && (target == admission.occurrence_key_id
                            || !dimension.is_some_and(
                                crate::federation::admission::is_sensitive_config_leaf,
                            ))
                }
                // The ROW's room, never the producer's rooms — and a row
                // that names none is nobody's (fail closed).
                "family" => cohort_target.is_some_and(|r| admission.family_key_ids.contains(r)),
                "community" => {
                    cohort_target.is_some_and(|r| admission.community_key_ids.contains(r))
                }
                _ => false,
            },
        }
    }

    /// v46.3.1 (PR #889 review, round three) — **the local-tier gate**,
    /// `FSD/V4_4_SHARED_ATTESTATION_SURFACE.md` §3: a `local`-tier row is
    /// producer-only authority (signature deferred) and is visible ONLY to
    /// the occurrence that produced it — never to the rest of the
    /// self-collective the `self` arm of [`Self::admits`] now admits. The
    /// SQL twin is [`local_tier_sql_predicate`](super::local_tier_sql_predicate).
    pub fn admits_local_tier(&self, tier: &str, attesting_key_id: &str) -> bool {
        if tier != crate::federation::types::attestation_tier::LOCAL {
            return true;
        }
        match self {
            CallerScope::Unauthenticated => false,
            CallerScope::Authenticated { admission } => {
                admission.occurrence_key_id == attesting_key_id
            }
        }
    }
}
