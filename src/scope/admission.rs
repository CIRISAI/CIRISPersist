//! [`CallerAdmission`] + [`build_caller_admission`] — the substrate-built
//! admission set (FSD §4.1, §4.2, §4.4, §11.2) and AV-44 mitigation
//! (FSD §13).
//!
//! # AV-44 forge resistance
//!
//! `CallerAdmission`'s fields are `pub` so the §4.3 SQL helper can read
//! them, but the struct carries a private zero-sized seal field
//! ([`AdmissionSeal`]). An external crate cannot name that field, so it
//! cannot construct a `CallerAdmission` by struct literal, and there is
//! no public `new`. The SOLE public path to a `CallerAdmission` is
//! [`build_caller_admission`], which resolves identity / families /
//! communities deterministically from the federation chain. A Python
//! caller (or any external Rust caller) therefore cannot fabricate
//! `Authenticated { admission: { identity: <victim>, families: <all>,
//! communities: <all> } }` — the type system refuses the literal
//! (FSD §13 `forged_admission_refused_at_compile_time`).
//!
//! `CallerAdmission` is deliberately NOT `Deserialize` — a serde
//! construction path would be a second forge surface (FSD §13 test
//! note "deserialization paths are blocked by serde-skip on the
//! struct").

use std::collections::BTreeSet;

use super::KeyId;
use crate::engine::Engine;

/// Private seal — prevents external struct-literal construction of
/// [`CallerAdmission`]. Zero-sized; only `super`-module code (the
/// builder) can name it. This is the type-system half of the AV-44
/// mitigation (FSD §13).
#[derive(Clone, Debug)]
struct AdmissionSeal;

/// The substrate-resolved admission set for an authenticated caller
/// (FSD §4.1).
///
/// Every field except `occurrence_key_id` is resolved by the substrate
/// from the federation chain — never caller-asserted. The struct has
/// no public constructor (see module docs / [`build_caller_admission`]);
/// its fields are `pub` only so the §4.3 SQL helper can read them.
#[derive(Clone, Debug)]
pub struct CallerAdmission {
    /// The caller's occurrence key — the literal signing key they
    /// presented at the boundary. The only field the caller has any
    /// agency over; everything else below is substrate-resolved.
    pub occurrence_key_id: KeyId,

    /// The caller's IDENTITY — resolved via
    /// `federation_identity_occurrences` (V059 §5.6.8.8):
    /// "lookup occurrence_key_id → identity_key_id."
    ///
    /// Singleton fallback (FSD §4.4): when the occurrence key is not
    /// bound (not yet declared as an occurrence of any identity), the
    /// caller IS its own identity (`identity_key_id == occurrence_key_id`).
    pub identity_key_id: KeyId,

    /// Every family the caller's IDENTITY is a member of — resolved via
    /// `list_families_for_member(identity_key_id)` against
    /// `federation_families` (V059 §5.6.8.9). Members are IDENTITY
    /// keys, NOT occurrence keys.
    pub family_key_ids: BTreeSet<KeyId>,

    /// Every community the caller's IDENTITY is a member of — resolved
    /// via `list_communities_for_member(identity_key_id)` against
    /// `federation_communities` (V060, Commit D). Same
    /// identity-keys-as-members shape as families.
    pub community_key_ids: BTreeSet<KeyId>,

    /// Construction seal — see [`AdmissionSeal`]. Not `pub`; blocks
    /// external struct-literal construction (AV-44).
    _seal: AdmissionSeal,
}

/// Failure building a [`CallerAdmission`] (FSD §11.2).
///
/// Resolution backend errors surface here. The §4.4 singleton fallback
/// is NOT an error — an unbound occurrence key resolves to itself; this
/// enum fires only when a substrate read genuinely fails.
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    /// A `FederationDirectory` read (identity-occurrence lookup, family
    /// fan-out, or community fan-out) failed at the backend.
    #[error("admission resolution failed: {0}")]
    Resolution(#[from] crate::federation::Error),
}

/// Build the admission set for a caller from their occurrence key
/// (FSD §4.1, §11.2). Substrate-side helper — the SOLE way to construct
/// a [`CallerAdmission`] (AV-44, FSD §13).
///
/// Resolution (FSD §11.2):
///
/// 1. `occurrence_key_id → identity_key_id` via
///    [`lookup_identity_for_occurrence`](crate::federation::FederationDirectory::lookup_identity_for_occurrence)
///    (V059 §5.6.8.8). On no binding, the §4.4 singleton fallback
///    applies: `identity == occurrence`, empty family/community sets.
/// 2. `identity_key_id → family_key_ids` via
///    [`list_families_for_member`](crate::federation::FederationDirectory::list_families_for_member)
///    (V059 §5.6.8.9).
/// 3. `identity_key_id → community_key_ids` via
///    `list_communities_for_member` (V060, Commit D).
///
/// # Cross-dependency (Commit B note)
///
/// Step 3 calls `list_communities_for_member`, added to
/// `FederationDirectory` by Commit D (not yet merged into this
/// worktree). Until Commit D lands, this function will not compile
/// standalone — that is the single expected residual build error for
/// Commit B.
pub async fn build_caller_admission(
    engine: &Engine,
    occurrence_key_id: &KeyId,
) -> Result<CallerAdmission, AdmissionError> {
    let directory = engine.federation_directory();

    // Step 1 — occurrence → identity. §4.4 singleton fallback when the
    // occurrence key is not bound as an occurrence of any identity:
    // the caller IS its own identity.
    let identity_key_id = match directory
        .lookup_identity_for_occurrence(occurrence_key_id)
        .await?
    {
        Some(occurrence) => occurrence.identity_key_id,
        None => occurrence_key_id.clone(),
    };

    // Step 2 — identity → families. Members are identity keys; the
    // family's own key_id is the admission token.
    let family_key_ids: BTreeSet<KeyId> = directory
        .list_families_for_member(&identity_key_id)
        .await?
        .into_iter()
        .map(|family| family.family_key_id)
        .collect();

    // Step 3 — identity → communities. Provided by Commit D; symmetric
    // to families. Each community's `community_key_id` is the admission
    // token.
    let community_key_ids: BTreeSet<KeyId> = directory
        .list_communities_for_member(&identity_key_id)
        .await?
        .into_iter()
        .map(|community| community.community_key_id)
        .collect();

    Ok(CallerAdmission {
        occurrence_key_id: occurrence_key_id.clone(),
        identity_key_id,
        family_key_ids,
        community_key_ids,
        _seal: AdmissionSeal,
    })
}

impl CallerAdmission {
    /// v4.0 (CIRISPersist#160 comment 4, FSD §4.6) — crate-internal
    /// constructor from already-resolved admission parts.
    ///
    /// [`build_caller_admission`] is the `Engine`-based resolution path
    /// used on the read side. The trace-ingest write path
    /// (`IngestPipeline`) holds only a `Backend` (no `Engine`), so it
    /// resolves the writer's identity / family / community sets through
    /// the `Backend` admission fan-out methods and assembles the
    /// `CallerAdmission` here. The constructor stays `pub(crate)` so the
    /// AV-44 forge-resistance seal is intact — no external crate can
    /// reach this path (FSD §13). Membership semantics are identical to
    /// the read-side builder; only the resolution plumbing differs.
    pub(crate) fn from_resolved(
        occurrence_key_id: impl Into<KeyId>,
        identity_key_id: impl Into<KeyId>,
        family_key_ids: impl IntoIterator<Item = KeyId>,
        community_key_ids: impl IntoIterator<Item = KeyId>,
    ) -> Self {
        Self {
            occurrence_key_id: occurrence_key_id.into(),
            identity_key_id: identity_key_id.into(),
            family_key_ids: family_key_ids.into_iter().collect(),
            community_key_ids: community_key_ids.into_iter().collect(),
            _seal: AdmissionSeal,
        }
    }
}

#[cfg(test)]
impl CallerAdmission {
    /// Test-only direct constructor. The seal blocks *external*
    /// construction (AV-44); within-crate tests for the §4.3 SQL
    /// predicate need to fabricate admissions without standing up an
    /// `Engine` + backend. Gated `#[cfg(test)]` so it never appears in
    /// the public API surface.
    pub(crate) fn for_test(
        occurrence_key_id: impl Into<KeyId>,
        identity_key_id: impl Into<KeyId>,
        family_key_ids: impl IntoIterator<Item = KeyId>,
        community_key_ids: impl IntoIterator<Item = KeyId>,
    ) -> Self {
        Self {
            occurrence_key_id: occurrence_key_id.into(),
            identity_key_id: identity_key_id.into(),
            family_key_ids: family_key_ids.into_iter().collect(),
            community_key_ids: community_key_ids.into_iter().collect(),
            _seal: AdmissionSeal,
        }
    }
}
