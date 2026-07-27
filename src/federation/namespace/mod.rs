//! **CIRISPersist#425 — the namespace registry + replication-policy resolution
//! surface.**
//!
//! Replication is not a plane per object type; it is a pure function of what a
//! signed `scores` [`Attestation`](crate::federation::Attestation) envelope
//! (CC 2.1) already carries — its **namespace** (`dimension` → AUTHORITY), its
//! **cohort_scope** (→ PROJECTION + VISIBILITY), and its lifecycle relation
//! (`attestation_type` → tombstone/anti-rollback). Persist owns the CEG-state
//! inputs an edge replication engine resolves against, so a new CEG object type
//! becomes a [`registry`] row rather than a hand-wired `list_* + selector +
//! apply-arm` on every consumer (the `key_selector`/`occurrence_selector`
//! whack-a-mole this replaces).
//!
//! This module supplies the resolver INPUTS; the combining engine
//! (`replication_policy(obj, ceg) -> Policy`) lives on the transport consumer
//! (CIRISEdge). The split: persist owns the data + the pure classifiers
//! ([`authority_for`](registry::authority_for), [`projection_for`],
//! [`visibility_for`], [`is_trust_root`], [`lifetime_class`]) and the roster
//! reads ([`active_members`](crate::federation::FederationDirectory::active_members)
//! — the `roster_of`); edge owns the fan-out.
//!
//! The [`registry`] is **generated from CC 3.1** (`part_3_the_namespace.md`) and
//! vendored (`namespace_registry.json`); CC is the single source of truth. See
//! [`registry`] for the drift-control (the vendored-copy content hash gate).

pub mod registry;
pub mod supersets;

use crate::federation::types::{attestation_type, cohort_scope};

/// **Who may emit under a namespace** — the authority class a `dimension`'s
/// reserved-prefix rule (CC 3.4) demands. Resolved from the vendored CC-3.1
/// registry by [`registry::authority_for`]; the four classes the whole
/// federation composes against. The CC 3.4 specifics (e.g. the required
/// `identity_type`) ride alongside in [`Authority::reserved`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityClass {
    /// The subject signs its own state — key records, identity occurrences,
    /// transport bindings (the `SELF`-projected identity plane). No third party
    /// may emit on the subject's behalf.
    SelfIdentity,
    /// Conferred only by an **m-of-n accord co-scrub** — the founding/canonical
    /// trust root and the `infra:attest` build-signing pipelines
    /// (`provenance:build_manifest:*`, `canonical`). The property that closes
    /// the chicken/egg: a build manifest is valid only once accord-co-scrubbed,
    /// exactly like a canonical seed. See
    /// [`check_infra_attest_role_admission`](crate::federation::admission::check_infra_attest_role_admission)
    /// / [`check_canonical_role_admission`](crate::federation::admission::check_canonical_role_admission).
    AccordCoScrub,
    /// **Substrate-self-report** — emittable only by the running substrate
    /// instance the dimension is about (`system:*`, `persist:*`, `transport:*`,
    /// `audit_chain:*`, …; CC 3.4.3). What makes the claim honest: the substrate
    /// cannot be made to lie about its own health by a third party.
    SubstrateSelf,
    /// A third-party **producer / steward** — the signing party vouches for a
    /// claim about something else (gossip attestations, community content,
    /// partner records). Authority is the producer key itself; a reserved
    /// producer (e.g. `accord:*` → `accord_holder`-only, a witness-emitter, a
    /// detector-only prefix) carries its CC 3.4 constraint in
    /// [`Authority::reserved`].
    ProducerSteward,
}

impl AuthorityClass {
    /// `true` iff this authority is a **trust root** — an accord-co-scrubbed
    /// canonical / infra pipeline whose public records gossip GLOBAL (commons /
    /// discovery). The load-bearing predicate in [`projection_for`]: a public
    /// record from a trust root reaches the whole federation; the same scope
    /// from a plain producer relays over its cohort.
    pub fn is_trust_root(self) -> bool {
        matches!(self, AuthorityClass::AccordCoScrub)
    }
}

/// A CC 3.4 reserved-emit constraint attached to a namespace family — the
/// specific rule beyond the coarse [`AuthorityClass`] (e.g. `accord:*` requires
/// `identity_type = accord_holder`; `capacity:*` forbids self-emission).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReservedRule {
    /// The rule token as catalogued in CC 3.4 (e.g. `"substrate-self-report"`,
    /// `"accord_holder-only"`, `"detector-only"`, `"no-self-emit"`).
    pub rule: String,
    /// The CC clause the rule is normatively defined in (e.g. `"CC 3.4.1"`).
    pub cc_ref: String,
}

/// The resolved authority for a `dimension`: its coarse [`AuthorityClass`] plus
/// any CC 3.4 [`ReservedRule`]. Returned by [`registry::authority_for`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Authority {
    /// The coarse emit-authority class.
    pub class: AuthorityClass,
    /// The CC 3.4 reserved-emit constraint, if the family is reserved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved: Option<ReservedRule>,
}

/// **Who advertises / propagates** a record — the projection its `cohort_scope`
/// (and, for the commons tiers, its authority) resolves to. Computed by
/// [`projection_for`]. Distinct from at-rest [`visibility_for`] (VISIBILITY is
/// what a holder may decrypt; PROJECTION is how far the record travels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Projection {
    /// **Publish-own (KERI)** — only the subject node advertises the record
    /// (`self` / `family`; the structurally-invisible identity plane). This is
    /// the policy the `key_selector` (#257) and `occurrence_selector` (#305)
    /// hand-wired separately — one projection, re-implemented per plane.
    SelfOwn,
    /// **Hold-and-forward over a cohort roster** — the record relays to the
    /// members of its `community` / `affiliations` roster (resolved via
    /// [`active_members`](crate::federation::FederationDirectory::active_members)),
    /// and to the cohort for non-trust-root commons content.
    Cohort,
    /// **Commons / tombstone gossip** — the record reaches the whole federation:
    /// trust-root commons records (canonical seeds, build manifests) AND every
    /// withdraw/revocation (anti-rollback — a tombstone that only relayed over
    /// the cohort would starve peers outside it, silently un-revoking).
    Global,
}

/// **The lifetime class of a lifecycle relation** — whether an envelope is a
/// live claim, a monotonic supersede, or a revocation tombstone. Drives the
/// anti-rollback projection: [`Tombstone`](LifetimeClass::Tombstone) and
/// [`MonotonicSupersede`](LifetimeClass::MonotonicSupersede) both force
/// [`Projection::Global`] regardless of scope, so a revocation can never be
/// out-run by the stale record it retracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifetimeClass {
    /// A standing claim (`scores`) — projects per its `cohort_scope`.
    Live,
    /// A monotonic replace-in-place (`supersedes`) — anti-rollback: gossips
    /// GLOBAL so the newest version reaches every holder of an older one.
    MonotonicSupersede,
    /// A revocation / retraction (`withdraws` / `recants`) — a durable tombstone
    /// that gossips GLOBAL, monotonic.
    Tombstone,
}

/// CC 2.1 `attestation_type` → its [`LifetimeClass`]. `withdraws`/`recants` are
/// tombstones; `supersedes` is a monotonic replace; everything else
/// (`scores`, the retired `delegates_to`) is a live claim.
pub fn lifetime_class(attestation_type: &str) -> LifetimeClass {
    match attestation_type {
        attestation_type::WITHDRAWS | attestation_type::RECANTS => LifetimeClass::Tombstone,
        attestation_type::SUPERSEDES => LifetimeClass::MonotonicSupersede,
        _ => LifetimeClass::Live,
    }
}

/// `true` iff the `attestation_type` is a tombstone or a monotonic supersede —
/// i.e. it must project [`Projection::Global`] for anti-rollback, regardless of
/// its `cohort_scope`. The single predicate that fixes the latent RELAY-
/// starvation the revocation kinds otherwise mis-project into.
pub fn is_withdraw_or_revocation(attestation_type: &str) -> bool {
    !matches!(lifetime_class(attestation_type), LifetimeClass::Live)
}

/// **The projection resolver** — `f(cohort_scope, authority, is_tombstone)`.
///
/// Persist owns this so the anti-rollback rule and the trust-root commons rule
/// live in exactly ONE tested place; an edge engine calls it rather than
/// re-deriving projection per object plane. Faithful to the CC replication
/// contract:
///
/// - **`self` / `family`** → [`SelfOwn`](Projection::SelfOwn) (publish-own; the
///   structurally-invisible identity plane).
/// - **`community` / `affiliations`** → [`Cohort`](Projection::Cohort)
///   (hold-and-forward over the roster).
/// - **commons tiers (`species` / `biosphere` / `federation`)** →
///   [`Global`](Projection::Global) iff the authority
///   [`is_trust_root`](AuthorityClass::is_trust_root) (canonical / infra
///   discovery), else [`Cohort`](Projection::Cohort).
/// - **any unrecognized scope** → [`Cohort`](Projection::Cohort) — conservative
///   RELAY; a future scope never silently GLOBAL-gossips.
/// - **`is_tombstone`** (see [`is_withdraw_or_revocation`]) overrides ALL of the
///   above to [`Global`](Projection::Global) — anti-rollback.
///
/// NOTE (design surface for the edge engine): substrate-self-report health
/// (`system:*` / `transport:*`) is [`AuthorityClass::SubstrateSelf`], NOT a
/// trust root, so a commons-scoped health report resolves to
/// [`Cohort`](Projection::Cohort) here. If the federation wants substrate
/// health to gossip GLOBAL, that is a one-line policy addition (treat
/// `SubstrateSelf` like a trust root for commons scopes) — surfaced as an
/// explicit decision rather than buried.
pub fn projection_for(
    cohort_scope: &str,
    authority: AuthorityClass,
    is_tombstone: bool,
) -> Projection {
    // Anti-rollback: a withdraw/revocation/supersede always gossips GLOBAL,
    // monotonic — it can never be out-run by the stale record it retracts.
    if is_tombstone {
        return Projection::Global;
    }
    match cohort_scope {
        cohort_scope::SELF | cohort_scope::FAMILY => Projection::SelfOwn,
        cohort_scope::COMMUNITY | cohort_scope::AFFILIATIONS => Projection::Cohort,
        cohort_scope::SPECIES | cohort_scope::BIOSPHERE | cohort_scope::FEDERATION => {
            if authority.is_trust_root() {
                Projection::Global
            } else {
                Projection::Cohort
            }
        }
        // Negative default: an unrecognized/future scope relays over its cohort,
        // never silently GLOBAL — mirrors the `crypto_tier` negative default.
        _ => Projection::Cohort,
    }
}

/// **The closed set of replicated CEG object kinds** an edge engine fetches for
/// a subject. Each maps to a byte-exact signed read via
/// [`list_signed_records`](crate::federation::FederationDirectory::list_signed_records)
/// — the generalization of #418's `list_signed_identity_occurrences_for` so the
/// one engine fetches every kind uniformly instead of a bespoke selector per
/// plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReplicatedKind {
    /// The subject's own `federation_keys` row (`SignedKeyRecord`; the scrub
    /// signature is embedded — the bare read is already byte-exact).
    KeyRecord,
    /// The subject's identity occurrences (`SignedIdentityOccurrence`; the
    /// detached signature container reconstructed per #418).
    IdentityOccurrence,
    /// The subject's authenticated transport routes (`SignedTransportDestination`
    /// since #443 — the detached signature container reconstructed like the
    /// occurrence plane; a bare unsigned `TransportDestination` no longer
    /// rides replication).
    TransportDestination,
    /// Attestations **about** the subject (`SignedAttestation`; envelope sig).
    Attestation,
    /// Occurrence revocation tombstones for the subject (anti-rollback GLOBAL).
    IdentityOccurrenceRevocation,
}

impl ReplicatedKind {
    /// The wire token (`"key_record"`, `"identity_occurrence"`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            ReplicatedKind::KeyRecord => "key_record",
            ReplicatedKind::IdentityOccurrence => "identity_occurrence",
            ReplicatedKind::TransportDestination => "transport_destination",
            ReplicatedKind::Attestation => "attestation",
            ReplicatedKind::IdentityOccurrenceRevocation => "identity_occurrence_revocation",
        }
    }

    /// Every replicated kind, for an engine that sweeps a subject across all of
    /// them.
    pub fn all() -> &'static [ReplicatedKind] {
        &[
            ReplicatedKind::KeyRecord,
            ReplicatedKind::IdentityOccurrence,
            ReplicatedKind::TransportDestination,
            ReplicatedKind::Attestation,
            ReplicatedKind::IdentityOccurrenceRevocation,
        ]
    }
}

/// A uniform signed record for the replication engine — the object's kind plus
/// its canonical JSON (byte-exact producer form; the receiver's put gate
/// re-canonicalizes via JCS, so serde round-tripping preserves verifiability).
/// The uniform shape [`list_signed_records`](crate::federation::FederationDirectory::list_signed_records)
/// returns so one engine handles every kind.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignedReplicatedRecord {
    /// Which CEG object kind this record is.
    pub kind: ReplicatedKind,
    /// The record serialized to its canonical JSON form.
    pub canonical_json: serde_json::Value,
}

/// **The at-rest visibility resolver** — a re-export of the substrate's existing
/// [`crypto_tier`](crate::federation::types::cohort_scope::crypto_tier)
/// dispatch, named for the replication contract. `self`/`family` →
/// `InvisibleEncrypted` (structurally invisible), `community`/`affiliations` →
/// `CommunityDek` (per-community DEK + cleartext provenance), commons /
/// infrastructure / unknown → `Plaintext` (inspectable). Orthogonal to
/// [`projection_for`]: VISIBILITY is decryptability, PROJECTION is reach.
pub fn visibility_for(
    cohort_scope: &str,
    cohort_subkind: Option<&str>,
) -> cohort_scope::CryptoTier {
    cohort_scope::crypto_tier(cohort_scope, cohort_subkind)
}

/// **Is `key_id` a federation trust root?** `true` iff it is an accord-blessed
/// canonical server ([`is_canonical`](crate::federation::admission::is_canonical))
/// OR an accord-blessed build-signing pipeline
/// ([`is_infra_attest`](crate::federation::admission::is_infra_attest)) — the
/// two [`AuthorityClass::AccordCoScrub`] roles. The `is_trust_root` the edge
/// engine consults to promote a commons record to [`Projection::Global`].
pub async fn is_trust_root(
    directory: &dyn crate::federation::FederationDirectory,
    key_id: &str,
) -> Result<bool, crate::federation::Error> {
    Ok(
        crate::federation::admission::is_canonical(directory, key_id).await?
            || crate::federation::admission::is_infra_attest(directory, key_id).await?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_self_and_family_are_publish_own() {
        for s in ["self", "family"] {
            assert_eq!(
                projection_for(s, AuthorityClass::SelfIdentity, false),
                Projection::SelfOwn
            );
        }
    }

    #[test]
    fn projection_community_and_affiliations_relay_over_cohort() {
        for s in ["community", "affiliations"] {
            assert_eq!(
                projection_for(s, AuthorityClass::ProducerSteward, false),
                Projection::Cohort
            );
        }
    }

    #[test]
    fn projection_commons_is_global_only_for_trust_root() {
        // build manifest / canonical (accord co-scrub, trust root) → GLOBAL.
        assert_eq!(
            projection_for("federation", AuthorityClass::AccordCoScrub, false),
            Projection::Global
        );
        // a plain producer's commons content relays over the cohort.
        assert_eq!(
            projection_for("federation", AuthorityClass::ProducerSteward, false),
            Projection::Cohort
        );
        // substrate-self health is NOT a trust root → cohort (documented surface).
        assert_eq!(
            projection_for("federation", AuthorityClass::SubstrateSelf, false),
            Projection::Cohort
        );
    }

    #[test]
    fn tombstone_always_global_regardless_of_scope() {
        // the anti-rollback rule: even a self-scoped withdraw gossips GLOBAL.
        for s in [
            "self",
            "family",
            "community",
            "federation",
            "totally-unknown",
        ] {
            assert_eq!(
                projection_for(s, AuthorityClass::SelfIdentity, true),
                Projection::Global,
                "scope {s} tombstone must be GLOBAL"
            );
        }
    }

    #[test]
    fn unknown_scope_is_conservative_relay_never_global() {
        assert_eq!(
            projection_for("some-future-scope", AuthorityClass::AccordCoScrub, false),
            Projection::Cohort
        );
    }

    #[test]
    fn lifetime_class_maps_the_lifecycle_primitives() {
        assert_eq!(lifetime_class("withdraws"), LifetimeClass::Tombstone);
        assert_eq!(lifetime_class("recants"), LifetimeClass::Tombstone);
        assert_eq!(
            lifetime_class("supersedes"),
            LifetimeClass::MonotonicSupersede
        );
        assert_eq!(lifetime_class("scores"), LifetimeClass::Live);
        assert!(is_withdraw_or_revocation("withdraws"));
        assert!(is_withdraw_or_revocation("supersedes"));
        assert!(!is_withdraw_or_revocation("scores"));
    }

    #[test]
    fn trust_root_authority_predicate() {
        assert!(AuthorityClass::AccordCoScrub.is_trust_root());
        assert!(!AuthorityClass::SelfIdentity.is_trust_root());
        assert!(!AuthorityClass::SubstrateSelf.is_trust_root());
        assert!(!AuthorityClass::ProducerSteward.is_trust_root());
    }
}
