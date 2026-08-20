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

pub mod conformance;
pub mod registry;
pub mod supersets;

use crate::federation::types::{attestation_type, cohort_scope};

/// The object-CLASS axis (v35.0.0, CIRISPersist#713) — re-exported from
/// [`load_bearing`](crate::federation::load_bearing) so the predicate surface
/// ([`is_load_bearing`](crate::federation::load_bearing::is_load_bearing)) and
/// the projection surface share one closed five-class vocabulary. Since
/// v36.0.0 the projection surface ([`projection_for`] /
/// [`tombstone_ceiling`]) dispatches over [`Plane`] — this same class set,
/// with the Attestation class additionally carrying its envelope `dimension`
/// (the #713 decomposition's information-type parameter). [`Plane::class`]
/// bridges back; `tests::every_object_class_has_a_projection_plane` holds the
/// two enums 1:1 at compile time.
pub use crate::federation::load_bearing::ObjectClass;

/// **The projection plane parameter** (v36.0.0, CIRISPersist#713 second half)
/// — [`ObjectClass`], with the Attestation class carrying its envelope
/// `dimension`.
///
/// Under contextual integrity the information-type parameter of the
/// Attestation plane IS the `dimension` (consent_grammar.rs, v21.2.0 #509): a
/// single Attestation row would be one selector serving many
/// information-types — the CIRISEdge#311 collapse repeated a level down. So
/// the plane parameter carries the dimension FOR THAT PLANE ONLY, and the
/// type refuses the two misuse shapes outright (house doctrine: contradictions
/// are refused — here at COMPILE time):
///
/// - a `dimension` supplied with a non-Attestation plane is UNREPRESENTABLE
///   (no other variant has the field), and
/// - an Attestation projection query WITHOUT its dimension is equally
///   unrepresentable (the field is mandatory) — the "forget the call, silently
///   over-advertise" drift class (#663/#710) closed by type rather than by
///   convention, exactly as edge's #713 shape answer asked.
///
/// Non-Attestation planes therefore pay nothing: no `Option` check, no
/// dimension read, no allocation — [`projection_for`] stays pure O(1) on
/// every arm. The dimension is an envelope field like `cohort_scope`, already
/// extracted at edge's dispatch site for
/// [`registry::authority_for`], so passing it costs nothing on the hot path.
///
/// Deliberately NO `From<ObjectClass>` impl: it could not be total (the
/// Attestation arm has no dimension to invent), and a partial bridge is the
/// misuse door this type exists to close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Plane<'a> {
    /// [`ObjectClass::KeyRecord`] — the identity plane.
    KeyRecord,
    /// [`ObjectClass::TransportDestination`] — the reachability plane.
    TransportDestination,
    /// [`ObjectClass::FountainContent`] — the bytes plane.
    FountainContent,
    /// [`ObjectClass::HardCaseEvent`] — the adverse-evidence plane.
    HardCaseEvent,
    /// [`ObjectClass::Attestation`], value-keyed by its envelope `dimension`
    /// — the #713 decomposition's per-family registry input.
    Attestation {
        /// The envelope `dimension` (CC 2.1) the registry resolves the
        /// audience from. Family-classified internally; an unrecognized
        /// dimension resolves the conservative default row.
        dimension: &'a str,
    },
}

impl Plane<'_> {
    /// The [`ObjectClass`] this plane projects — the bridge back to the
    /// predicate axis. Exhaustive over [`Plane`]; the reverse direction is
    /// held by `tests::every_object_class_has_a_projection_plane`.
    #[must_use]
    pub const fn class(self) -> ObjectClass {
        match self {
            Plane::KeyRecord => ObjectClass::KeyRecord,
            Plane::TransportDestination => ObjectClass::TransportDestination,
            Plane::FountainContent => ObjectClass::FountainContent,
            Plane::HardCaseEvent => ObjectClass::HardCaseEvent,
            Plane::Attestation { .. } => ObjectClass::Attestation,
        }
    }
}

/// **The const-typed capability token a [`Projection::Capability`] audience
/// carries** (v36.0.0, CIRISPersist#713 second half).
///
/// A closed enum rather than a string ON PURPOSE: edge shipped the
/// bare-string version of this bug once (CIRISEdge#379's `"observer"`, which
/// was not a capability token anywhere in the stack, corrected in CIRISEdge
/// v13.11.0 to the conferral const) — carrying the authority's const inside the variant
/// makes that failure unrepresentable. Each variant resolves to an EXISTING
/// delegation-scope constant via [`Self::as_scope`]; this type never mints a
/// second spelling of a token
/// ([`delegation_scope`](crate::federation::types::delegation_scope) stays
/// the single source), and the serde form is pinned to the same spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum CapabilityToken {
    /// [`delegation_scope::INFRA_SERVE`](crate::federation::types::delegation_scope::INFRA_SERVE)
    /// — the E3 trace-serve audience: `trace:*` serves to holders of
    /// `infra:serve` ONLY (CIRISEdge#386 / CC 4.4.3.4.3, the
    /// `SERVE_ADVERTISE_POLICY_HASH`-pinned policy; edge's
    /// `peer_has_serve_capability` overlay folds onto this variant).
    #[serde(rename = "infra:serve")]
    InfraServe,
}

impl CapabilityToken {
    /// The delegation-scope token this capability audience is gated on — BY
    /// CONST, never respelled.
    #[must_use]
    pub const fn as_scope(self) -> &'static str {
        match self {
            CapabilityToken::InfraServe => crate::federation::types::delegation_scope::INFRA_SERVE,
        }
    }
}

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
    /// withdraw/revocation whose plane's [`tombstone_ceiling`] is Global
    /// (anti-rollback — a tombstone that relayed narrower than any copy could
    /// have traveled would starve holders, silently un-revoking. Since #713 the
    /// ceiling is per-plane: Global exactly where copies could have gone Global).
    Global,
    /// **Capability-gated serve** (v36.0.0, #713 decomposition) — the record's
    /// audience is the holders of the carried [`CapabilityToken`], selected by
    /// ROLE rather than by cohort, and it never widens with scope. The E3
    /// `trace:*` cell: serves to `infra:serve` holders only. Not comparable to
    /// [`Cohort`](Projection::Cohort) (role-keyed vs roster-keyed); the
    /// ceiling-domination test uses an explicit partial order.
    Capability(CapabilityToken),
    /// **Subject-gated** (v36.0.0, #713 decomposition) — the record's audience
    /// past the subject node itself is its DATA-SUBJECT's grant, at every
    /// scope. The CC#46 `scores:*` cell: admission is cheap (self-signed
    /// hybrid PoP), so the authority is the subject's — "a node can be fully
    /// consented for replication and still have no right to score you."
    Subject,
}

/// **The lifetime class of a lifecycle relation** — whether an envelope is a
/// live claim, a monotonic supersede, or a revocation tombstone. Drives the
/// anti-rollback projection: [`Tombstone`](LifetimeClass::Tombstone) and
/// [`MonotonicSupersede`](LifetimeClass::MonotonicSupersede) both project at
/// their plane's [`tombstone_ceiling`] regardless of scope, so a revocation
/// can never be out-run by the stale record it retracts — anywhere a copy of
/// that record can exist (#713: the ceiling is the plane's row-max, no longer
/// an unconditional Global).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifetimeClass {
    /// A standing claim (`scores`) — projects per its `cohort_scope`.
    Live,
    /// A monotonic replace-in-place (`supersedes`) — anti-rollback: gossips at
    /// the plane's [`tombstone_ceiling`] so the newest version reaches every
    /// holder of an older one.
    MonotonicSupersede,
    /// A revocation / retraction (`withdraws` / `recants`) — a durable tombstone
    /// that gossips at the plane's [`tombstone_ceiling`], monotonic.
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
/// i.e. it must project at its plane's [`tombstone_ceiling`] for anti-rollback,
/// regardless of its `cohort_scope`. The single predicate that fixes the latent
/// RELAY-starvation the revocation kinds otherwise mis-project into.
pub fn is_withdraw_or_revocation(attestation_type: &str) -> bool {
    !matches!(lifetime_class(attestation_type), LifetimeClass::Live)
}

/// **The per-plane projection resolver** —
/// `f(plane, cohort_scope, authority, is_tombstone)`, with the Attestation
/// plane value-keyed by its `dimension` (v35.0.0 #713; decomposed v36.0.0,
/// #713 second half).
///
/// Persist owns this so the anti-rollback rule and the trust-root commons rule
/// live in exactly ONE tested place; an edge engine calls it rather than
/// re-deriving projection per object plane. Under contextual integrity each
/// plane is its own CONTEXT with its own transmission norm — *who may learn a
/// subject's reachability* is not the same norm as *who may learn about their
/// key* — so `cohort_scope` resolves PER-FLOW. Before #713 this function took
/// no plane: a `self`-scoped `KeyRecord` and a `self`-scoped
/// `TransportDestination` projected identically, one subject set drove every
/// plane, and a subject's reachability was published as a side effect of a
/// decision about their key (the CIRISEdge#311 collapse). The predicate side
/// ([`is_load_bearing`](crate::federation::load_bearing::is_load_bearing))
/// already dispatched per [`ObjectClass`]; the projection side now does too —
/// and on the Attestation plane, per DIMENSION FAMILY, because the
/// information-type parameter of that plane is the `dimension` and one row
/// would repeat the #311 collapse a level down (#713 server relay).
///
/// # The decided norm table (#713: edge answer + server relay + operator arbitration)
///
/// ✱ = [`Global`](Projection::Global) if the authority
/// [`is_trust_root`](AuthorityClass::is_trust_root), else
/// [`Cohort`](Projection::Cohort).
///
/// | plane | self | family | community | affiliations | species | biosphere | federation |
/// |---|---|---|---|---|---|---|---|
/// | `KeyRecord` | SelfOwn | SelfOwn | Cohort | Cohort | ✱ | ✱ | ✱ |
/// | `TransportDestination` | SelfOwn | SelfOwn | Cohort | Cohort | **Cohort** | **Cohort** | ✱ |
/// | `FountainContent` | SelfOwn | SelfOwn | Cohort | Cohort | Cohort | Cohort | ✱ |
/// | `HardCaseEvent` | SelfOwn | SelfOwn | Cohort | Cohort | Cohort | Cohort | **Cohort** |
/// | `Attestation` | *per dimension FAMILY — the table below* |
///
/// The cut that decides the narrowed cells: **content may travel wider than
/// the reachability of its author.** A key's audience is everyone who must
/// VERIFY artifacts it signed — and signatures travel with the artifacts,
/// globally — so `KeyRecord` keeps ✱ at every commons tier. A route's audience
/// is everyone who may DELIVER to the subject — a bounded, relationship-shaped
/// set — so `TransportDestination` species/biosphere stay Cohort even for a
/// trust root: Global gossip of non-infra reachability is a PRESENCE
/// DIRECTORY, the surveillance surface #713 exists to close. `federation`
/// keeps ✱ because a relay/serve node's ROLE is to be reachable.
/// `FountainContent` mirrors the route row at the bytes layer (advertisement ≠
/// availability; discovery rides the manifest/attestation plane, the bytes are
/// pulled by the swarm). `HardCaseEvent` rows carry `subject_key_id` and the
/// kinds are adverse (quarantine, de-admission, …): Global gossip of those is
/// a REPUTATION DIRECTORY, so no live cell ever widens past Cohort — the
/// infra-role de-admission reach rides the TOMBSTONE ceiling
/// ([`tombstone_ceiling`]) BY ROLE, not a live cell.
///
/// # The `Attestation` decomposition (v36.0.0 — #713's second half, decided)
///
/// [`Plane::Attestation`] resolves per dimension FAMILY, value-keyed by the
/// envelope `dimension` the plane parameter carries. Two families need
/// audience kinds the scope axis cannot express — [`Projection::Capability`]
/// (role-keyed) and [`Projection::Subject`] (subject-keyed) — which is why
/// the row could never be *a* row:
///
/// | family | self / family | community / affiliations | species / biosphere | federation | ceiling |
/// |---|---|---|---|---|---|
/// | `consent:*` | SelfOwn | Cohort | Cohort | ✱ | **Global** |
/// | `trace:*` | SelfOwn | **SelfOwn** | Capability(`infra:serve`) | Capability(`infra:serve`) | Capability(`infra:serve`) |
/// | `scores:*` | SelfOwn | **Subject** | Subject | Subject | Subject |
/// | `capacity:*` | SelfOwn | Cohort | Cohort | ✱ | row-max (✱) |
/// | `content_class:*` | SelfOwn | Cohort | Cohort | ✱ | row-max (✱) |
/// | `transport:*` † | SelfOwn | Cohort | Global if SubstrateSelf, else Cohort | Global if SubstrateSelf, else ✱ | row-max |
/// | *unknown* | SelfOwn | Cohort | Cohort | **Cohort** | Cohort |
///
/// † and the EXACT dimension `system:audit_chain:hash_continuity` — the VALUE,
/// never the open `system:*` prefix. A future subject-carrying dimension must
/// never inherit Global from a namespace; a new member has to EARN Global,
/// not inherit it (#713 server relay, declining the open prefix). Every other
/// `system:*` dimension resolves the unknown-family conservative row.
///
/// The family reasoning, from the thread: `consent:*` is the routing editor —
/// it must reach any holder who might rely on it, so its CEILING is Global
/// (KeyRecord's anti-rollback logic) while its live commons cells stay
/// bounded. `trace:*` is capability-gated, NOT scope-gated (E3, pinned by
/// `SERVE_ADVERTISE_POLICY_HASH`): recipient selection is by ROLE and never
/// widens by cohort — its community/affiliations cells stay SelfOwn, and no
/// authority (not even a trust root) widens it past the `infra:serve` set.
/// `scores:*` is subject-gated (CC#46): admission is cheap, so past `family`
/// the authority is the SUBJECT's grant at every scope — for every emitter
/// authority. `capacity:*` / `content_class:*` are commons-health shapes
/// (self-report about own substrate / flags whose subject is the content).
/// `transport:*` + the exact audit-chain dimension are substrate self-reports
/// with no third-party subject and federation-wide consumers (mesh healing,
/// ALM capacity), so [`AuthorityClass::SubstrateSelf`] at commons scopes
/// projects Global — decided on the thread, landed here as registry rows with
/// no resolver special-casing.
///
/// An UNKNOWN dimension family resolves the conservative default (negative
/// default doctrine): SelfOwn at the structurally-invisible tier, Cohort
/// everywhere else, for EVERY authority — never Global, so a new family
/// earns its commons reach by landing a decided row rather than inheriting
/// one. Note the consequence, chosen not discovered: families the thread did
/// not decide (`provenance:*`, `accord:*`, `moderation:*`,
/// `trace_manifest:*`, …) resolve this row on the ATTESTATION REPLICATION
/// plane until a row is decided on #713 — including their tombstones
/// (Cohort ceiling), and including trust-root-authored records.
///
/// An unrecognized SCOPE within a known family resolves that family's
/// community-tier cell — the bounded relay answer, never wider (`trace:*` →
/// SelfOwn, `scores:*` → Subject, everything else → Cohort): a future scope
/// never silently widens, on any axis.
///
/// # Structure
///
/// - **Total registry, compiler-checked** (#636's lesson — the gate sees the
///   table itself, not a copy): the body is an exhaustive `match` on
///   [`Plane`], and the dimension axis an exhaustive `match` on the family
///   classifier, so a new plane variant or family variant is a COMPILE ERROR
///   until its row exists. `tests::every_object_class_has_a_projection_plane`
///   holds [`ObjectClass`] ↔ [`Plane`] 1:1.
/// - **Pure and O(1)**: no directory read, no allocation, no O(members)
///   anything — the dimension is classified by a fixed set of prefix
///   comparisons; `benches/projection.rs` holds the number against the
///   `pre-713` baseline.
/// - **`is_tombstone`** (see [`is_withdraw_or_revocation`]) projects at
///   [`tombstone_ceiling`]`(plane, authority)` — per-plane AND per-family;
///   see there for the invariant and the rows.
#[inline]
pub fn projection_for(
    plane: Plane<'_>,
    cohort_scope: &str,
    authority: AuthorityClass,
    is_tombstone: bool,
) -> Projection {
    // Anti-rollback, per-plane: a withdraw/revocation/supersede projects at
    // the widest projection any live version of its plane could ever have had
    // (the row max across ALL scopes), so it reaches every holder of a copy
    // it retracts — and nobody beyond the set that could know it existed.
    if is_tombstone {
        return tombstone_ceiling(plane, authority);
    }
    match plane {
        // KeyRecord — unchanged, reaffirmed by #713: keys must resolve
        // wherever their signatures travel, so every commons tier stays ✱.
        Plane::KeyRecord => match cohort_scope {
            cohort_scope::SELF | cohort_scope::FAMILY => Projection::SelfOwn,
            cohort_scope::COMMUNITY | cohort_scope::AFFILIATIONS => Projection::Cohort,
            cohort_scope::SPECIES | cohort_scope::BIOSPHERE | cohort_scope::FEDERATION => {
                if authority.is_trust_root() {
                    Projection::Global
                } else {
                    Projection::Cohort
                }
            }
            _ => Projection::Cohort,
        },
        // TransportDestination — THE #713 divergence: species/biosphere stay
        // Cohort even for a trust root (routes need only reach those with a
        // delivery relationship; Global non-infra reachability is a presence
        // directory). federation keeps ✱ — infra's role is to be reachable.
        Plane::TransportDestination => match cohort_scope {
            cohort_scope::SELF | cohort_scope::FAMILY => Projection::SelfOwn,
            cohort_scope::COMMUNITY | cohort_scope::AFFILIATIONS => Projection::Cohort,
            cohort_scope::SPECIES | cohort_scope::BIOSPHERE => Projection::Cohort,
            cohort_scope::FEDERATION => {
                if authority.is_trust_root() {
                    Projection::Global
                } else {
                    Projection::Cohort
                }
            }
            _ => Projection::Cohort,
        },
        // FountainContent — the route row's logic at the bytes layer:
        // advertisement ≠ availability; ✱ only on federation so a canonical
        // corpus (trust-root build artifacts) is widely advertised.
        Plane::FountainContent => match cohort_scope {
            cohort_scope::SELF | cohort_scope::FAMILY => Projection::SelfOwn,
            cohort_scope::COMMUNITY | cohort_scope::AFFILIATIONS => Projection::Cohort,
            cohort_scope::SPECIES | cohort_scope::BIOSPHERE => Projection::Cohort,
            cohort_scope::FEDERATION => {
                if authority.is_trust_root() {
                    Projection::Global
                } else {
                    Projection::Cohort
                }
            }
            _ => Projection::Cohort,
        },
        // HardCaseEvent — adverse statements ABOUT a party (every row carries
        // subject_key_id): Global gossip is a reputation directory, so even
        // federation scope stays Cohort ON THE LIVE PATH regardless of
        // authority. The infra-role de-admission Global reach is the
        // tombstone ceiling's, BY ROLE.
        Plane::HardCaseEvent => match cohort_scope {
            cohort_scope::SELF | cohort_scope::FAMILY => Projection::SelfOwn,
            cohort_scope::COMMUNITY | cohort_scope::AFFILIATIONS => Projection::Cohort,
            cohort_scope::SPECIES | cohort_scope::BIOSPHERE | cohort_scope::FEDERATION => {
                Projection::Cohort
            }
            _ => Projection::Cohort,
        },
        // Attestation — per dimension FAMILY (v36.0.0, #713 second half).
        // The information-type parameter of this plane IS the dimension; one
        // row would repeat the #311 collapse a level down.
        Plane::Attestation { dimension } => match attestation_family(dimension) {
            // consent:* / capacity:* / content_class:* share the LIVE shape
            // (SelfOwn | Cohort | Cohort | ✱ at federation only) — they
            // split at the CEILING: consent's is Global (the routing editor
            // must reach any holder who might rely on it — KeyRecord's
            // anti-rollback logic), the other two take the row-max. See
            // `tombstone_ceiling`.
            AttestationFamily::Consent
            | AttestationFamily::Capacity
            | AttestationFamily::ContentClass => match cohort_scope {
                cohort_scope::SELF | cohort_scope::FAMILY => Projection::SelfOwn,
                cohort_scope::COMMUNITY
                | cohort_scope::AFFILIATIONS
                | cohort_scope::SPECIES
                | cohort_scope::BIOSPHERE => Projection::Cohort,
                cohort_scope::FEDERATION => {
                    if authority.is_trust_root() {
                        Projection::Global
                    } else {
                        Projection::Cohort
                    }
                }
                _ => Projection::Cohort,
            },
            // trace:* — capability-gated, NOT scope-gated (E3): recipient
            // selection is by ROLE and never widens by cohort. Community and
            // affiliations stay SelfOwn; the commons tiers serve to the
            // `infra:serve` set for EVERY authority — a trust root's trace
            // does not widen past the capability audience either. An
            // unrecognized scope resolves the family's community-tier cell
            // (SelfOwn) — never wider.
            AttestationFamily::Trace => match cohort_scope {
                cohort_scope::SELF
                | cohort_scope::FAMILY
                | cohort_scope::COMMUNITY
                | cohort_scope::AFFILIATIONS => Projection::SelfOwn,
                cohort_scope::SPECIES | cohort_scope::BIOSPHERE | cohort_scope::FEDERATION => {
                    Projection::Capability(CapabilityToken::InfraServe)
                }
                _ => Projection::SelfOwn,
            },
            // scores:* — subject-gated (CC#46): past `family` the audience is
            // the SUBJECT's grant at every scope, for every emitter
            // authority. An unrecognized scope resolves the community-tier
            // cell (Subject) — bounded to the one party with a standing
            // right, never a roster.
            AttestationFamily::Scores => match cohort_scope {
                cohort_scope::SELF | cohort_scope::FAMILY => Projection::SelfOwn,
                _ => Projection::Subject,
            },
            // accord:* — co-scrub ASSEMBLY (v36.2.0, decided by server).
            // Global UNCONDITIONALLY at the commons tiers, not ✱: a partial
            // quorum object is emitted pre-authority and becomes the root's
            // act only by aggregating, so ✱ would be a bootstrap paradox.
            //
            // GLOBAL HERE IS CARRIAGE, NOT REACH, and that distinction is what
            // reconciles this row with CC 4.2.1's "reach is consent-scoped":
            // *"a node that never trusted the accord, or has already cut the
            // edge, is simply not reached."* Projection answers who may HOLD
            // the bytes so the quorum can assemble across an unknown cohort
            // span; whether a given node may CARRY a particular object is a
            // per-node relational question no cohort value can express, and it
            // is answered by `trust_root::may_relay_accord_object` — seated
            // signer AND a live `delegates_to(self -> root)`. Without that
            // predicate this row WOULD over-deliver and the clause would be
            // violated; with it, Global is the widest the substrate offers and
            // the relay gate is what narrows it to those who granted the root.
            // Sub-commons keeps the standard shape.
            AttestationFamily::Accord => match cohort_scope {
                cohort_scope::SELF | cohort_scope::FAMILY => Projection::SelfOwn,
                cohort_scope::COMMUNITY | cohort_scope::AFFILIATIONS => Projection::Cohort,
                cohort_scope::SPECIES | cohort_scope::BIOSPHERE | cohort_scope::FEDERATION => {
                    Projection::Global
                }
                _ => Projection::Cohort,
            },
            // moderation:* — adverse allegations about a party (v36.2.0,
            // decided by server). The HardCaseEvent shape EXACTLY: no live
            // cell widens past Cohort, because Global gossip of allegations is
            // a reputation directory.
            //
            // v37.0.1 (CIRISPersist#741) — THE COMMONS TIERS ARE ENUMERATED
            // EXPLICITLY, and the enumeration is the point.
            //
            // Until this cut the ceiling was correct but INHERITED FROM THE
            // WILDCARD: `SELF | FAMILY => SelfOwn`, everything else to `_`.
            // That made this the ONLY family in the registry whose commons
            // tiers are not spelled out — `Accord`, `ProvenanceBuildManifest`
            // and `SubstrateHealth` each enumerate
            // `SPECIES | BIOSPHERE | FEDERATION`. A consistency sweep (this
            // repo ran four during v37) that "finished" Moderation to match
            // its three neighbours would have written `=> Global` and lifted
            // the allegation ceiling SILENTLY, because no test looked at that
            // cell.
            //
            // Enumerated, the arms now say Cohort in the same breath as the
            // families that say Global, so symmetry is no longer a reason to
            // edit this. `moderation_holds_its_cohort_ceiling_at_every_commons_tier`
            // and its tombstone twin red if anyone does anyway — the mechanism,
            // where the comment above is only the reason.
            AttestationFamily::Moderation => match cohort_scope {
                cohort_scope::SELF | cohort_scope::FAMILY => Projection::SelfOwn,
                cohort_scope::COMMUNITY
                | cohort_scope::AFFILIATIONS
                | cohort_scope::SPECIES
                | cohort_scope::BIOSPHERE
                | cohort_scope::FEDERATION => Projection::Cohort,
                _ => Projection::Cohort,
            },
            // provenance:build_manifest:* — the binary-verification surface
            // (v36.1.0, #713, decided by edge). The KeyRecord shape, ✱ at
            // EVERY commons tier: a trust-root-blessed manifest must be
            // resolvable wherever a peer's build attestation travels, exactly
            // as a key must be resolvable wherever its signatures travel.
            // Non-root emitters stay Cohort — the ✱ is the trust root's
            // reach, not the family's.
            AttestationFamily::ProvenanceBuildManifest => match cohort_scope {
                cohort_scope::SELF | cohort_scope::FAMILY => Projection::SelfOwn,
                cohort_scope::COMMUNITY | cohort_scope::AFFILIATIONS => Projection::Cohort,
                cohort_scope::SPECIES | cohort_scope::BIOSPHERE | cohort_scope::FEDERATION => {
                    if authority.is_trust_root() {
                        Projection::Global
                    } else {
                        Projection::Cohort
                    }
                }
                _ => Projection::Cohort,
            },
            // transport:* + the EXACT system:audit_chain:hash_continuity —
            // substrate self-reports with no third-party subject and
            // federation-wide consumers: SubstrateSelf at commons scopes
            // projects Global (#713 question 3, decided). Other authorities
            // follow the commons-health shape (✱ at federation only).
            AttestationFamily::SubstrateHealth => match cohort_scope {
                cohort_scope::SELF | cohort_scope::FAMILY => Projection::SelfOwn,
                cohort_scope::COMMUNITY | cohort_scope::AFFILIATIONS => Projection::Cohort,
                cohort_scope::SPECIES | cohort_scope::BIOSPHERE => {
                    if matches!(authority, AuthorityClass::SubstrateSelf) {
                        Projection::Global
                    } else {
                        Projection::Cohort
                    }
                }
                cohort_scope::FEDERATION => {
                    if matches!(authority, AuthorityClass::SubstrateSelf)
                        || authority.is_trust_root()
                    {
                        Projection::Global
                    } else {
                        Projection::Cohort
                    }
                }
                _ => Projection::Cohort,
            },
            // Unknown family — the conservative default (negative default
            // doctrine): never Global, for ANY authority. A new family earns
            // its commons reach by landing a decided row on #713.
            AttestationFamily::Unknown => match cohort_scope {
                cohort_scope::SELF | cohort_scope::FAMILY => Projection::SelfOwn,
                _ => Projection::Cohort,
            },
        },
    }
}

/// The EXACT `system:*` member the #713 thread co-signed for the
/// substrate-health Global cells — the VALUE, never the namespace. Every
/// other `system:*` dimension resolves [`AttestationFamily::Unknown`]: the
/// open prefix at Global would be a standing invitation for a future
/// subject-carrying dimension to inherit a scope nobody chose for it (#713
/// server relay, declining the open prefix).
const SYSTEM_AUDIT_CHAIN_HASH_CONTINUITY: &str = "system:audit_chain:hash_continuity";

/// The dimension-FAMILY axis of the Attestation plane (#713 decomposition) —
/// the decided rows plus the conservative default.
///
/// # v36.1.0 — this was private, and the reason it gave was wrong
///
/// It read *"consumers ask [`projection_for`]; the family is a resolver
/// internal, so the registry cannot be consulted half-way."* CIRISEdge
/// disproved that while adopting v36.0.0, and the v36.0.0 adopt map's
/// instruction to fold a capability overlay onto
/// [`Projection::Capability`] was UNSAFE because of it.
///
/// **A capability gate is a FAMILY question; a projection is a
/// FAMILY-AND-SCOPE answer.** `trace:*` resolves
/// [`Capability`](Projection::Capability) only at the commons tiers — at
/// `community` / `affiliations` the same family resolves
/// [`SelfOwn`](Projection::SelfOwn). So a consumer replacing
/// `dimension.starts_with("trace:")` with `matches!(p, Projection::Capability(_))`
/// stops gating below the commons, and on a DIRECT-FETCH path that is a hole
/// rather than a narrower advertisement: E3 requires `infra:serve` even for a
/// subject pulling its own `trace:*` row. The same coupling applies to
/// `scores:*` → [`Subject`](Projection::Subject).
///
/// Keeping this private did not prevent half-consulting the registry — it
/// forced consumers to re-spell the prefix rule instead, which is the
/// second-spelling shape this repo removes everywhere else. Public, so the
/// classification has exactly one owner.
///
/// `#[non_exhaustive]` deliberately: the decided set GROWS as policy lands
/// (`accord:*` and `moderation:*` are open with CIRISServer as of this
/// release), and a new decided family is additive policy, not a contract
/// change — it must not break a consumer's build. Consumers match the
/// variants they gate on and let the rest fall through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttestationFamily {
    /// `consent:*` — the routing editor (Global ceiling).
    Consent,
    /// `trace:*` — capability-gated (E3), never widens by cohort.
    Trace,
    /// `scores:*` — subject-gated (CC#46).
    Scores,
    /// `capacity:*` — substrate self-report, commons-health shape.
    Capacity,
    /// `content_class:*` — flags whose subject is the content.
    ContentClass,
    /// `transport:*` and the EXACT
    /// [`SYSTEM_AUDIT_CHAIN_HASH_CONTINUITY`] — substrate self-reports whose
    /// SubstrateSelf commons cells are Global.
    SubstrateHealth,
    /// v36.2.0 (CIRISPersist#713) — `accord:*`, decided by CIRISServer.
    /// **`Global` UNCONDITIONALLY at every commons tier — not ✱.**
    ///
    /// The operative reason is co-scrub ASSEMBLY, not artifact-vs-subject. An
    /// accord act is not a single emission: it is m-of-n over the live active
    /// roster, and it comes into being by **partial quorum objects replicating
    /// until they assemble**. The co-scrubbers are independent holders by
    /// construction — that independence IS the security property of an m-of-n
    /// kill switch — so they are deliberately not co-located in one cohort,
    /// and the roster is dynamic: which cohorts it spans is **not knowable at
    /// emit time** by the node emitting a partial. Cap this family at `Cohort`
    /// and partials from different cohorts never meet: the quorum cannot
    /// assemble and the kill switch is inoperable BY CONSTRUCTION, silently.
    ///
    /// **Why ✱ is the wrong shape, and this is the subtle part.** ✱ suits a
    /// family whose rows are ALREADY the trust root's act when emitted
    /// (`KeyRecord`, `provenance:build_manifest:*`). A partial quorum object
    /// is emitted PRE-AUTHORITY and becomes authoritative by aggregation, so
    /// ✱ is a bootstrap paradox — the object would need quorum to project
    /// widely, and need to project widely to reach quorum. As far as anyone
    /// has found, this is the only decided family of that second kind.
    ///
    /// Forgery is closed at the correct layer and does not need projection's
    /// help: admission requires `identity_type = accord_holder`, which is
    /// `HardwareAttested` — established by registration-time ceremony. A
    /// narrower projection would be a weaker second forgery gate that breaks
    /// assembly.
    ///
    /// **Confidentiality is answered elsewhere, deliberately.** An in-flight
    /// partial does disclose that an accord act is being considered, possibly
    /// against a named node, before any quorum exists. Projection is the wrong
    /// lever: it decides who may HOLD the bytes, never who may READ them. The
    /// partial must reach a roster whose cohort span is unknowable, so its
    /// projection must be Global; legibility is limited by keeping a partial
    /// ENCRYPTED UNTIL QUORUM. Narrowing here would buy weaker confidentiality
    /// AND break assembly.
    ///
    /// Stem is `accord:` — the whole reserved prefix the co-scrub argument
    /// covers. It does NOT extend to its `RESERVED_CLASS_DIMENSION_PREFIXES`
    /// sibling `objection:`, which stays conservative until argued (the
    /// `provenance:build_manifest:` / `provenance:` precedent).
    Accord,
    /// v36.2.0 (CIRISPersist#713) — `moderation:*`, decided by CIRISServer.
    /// **`Cohort` — the same value the conservative default gave, but now
    /// ARGUED rather than inherited**, so the row stops reading as "nobody has
    /// looked."
    ///
    /// Every live dimension (`moderation:rogue_action:v1`, `:harassment:v1`,
    /// `:conduct:v1`, `:tone:v1`, `:report`) is an **adverse allegation about
    /// a party** — precisely the [`Plane::HardCaseEvent`] shape, which v35
    /// already decided: Global gossip of adverse statements is a REPUTATION
    /// DIRECTORY, so no live cell widens past `Cohort`. The Attestation-plane
    /// family carrying allegations must not project wider than the
    /// object-plane row carrying them.
    ///
    /// Contextual integrity gives the same answer directly: the information
    /// type is an allegation about a person, and what makes its transmission
    /// appropriate is the community adjudicating conduct that occurred within
    /// it. Global gossip re-purposes it into a portable reputation record —
    /// the surveillance surface #713 exists to close.
    Moderation,
    /// v36.1.0 (CIRISPersist#713) — `provenance:build_manifest:*`, the
    /// BINARY-VERIFICATION surface, decided by edge after v36.0.0 shipped it
    /// under the conservative default.
    ///
    /// **Why it is not `Unknown`.** Edge's bundle gate (CIRISEdge#436/#437)
    /// admits a peer at `Rooted` only if its build attestation verifies
    /// against a trust-root-blessed manifest. Capping this family at `Cohort`
    /// silently degrades cross-cohort FIRST CONTACT to `Advisory` — the
    /// safe-mesh path — and contextual integrity does not argue for the
    /// narrowing: **a build manifest is a statement about an ARTIFACT, not
    /// about a subject**, so the presence-directory reasoning that narrowed
    /// reachability has no purchase here.
    ///
    /// **Why it had to be decided rather than defaulted.** Edge's advertise
    /// gate maps `Global | Cohort => true`, so the v36.0.0 narrowing was
    /// compiler-green AND test-green downstream — invisible exactly where it
    /// mattered. A default that cannot be observed by the consumer it harms
    /// is the reason this row exists.
    ProvenanceBuildManifest,
    /// Any dimension outside the decided families — the conservative row.
    Unknown,
}

/// `true` iff `dimension` sits UNDER `stem` — the stem plus a non-empty tail,
/// mirroring the manifest's own prefix grammar (`consent:*` describes
/// `consent:replication:v1`, not a bare `consent` or an empty-tailed
/// `consent:`). Pure byte comparison; no allocation.
#[inline]
fn under(dimension: &str, stem: &str) -> bool {
    dimension.len() > stem.len() && dimension.starts_with(stem)
}

/// Classify a `dimension` into its decided [`AttestationFamily`] — a fixed
/// set of prefix comparisons plus ONE exact-value gate, so the resolver stays
/// pure O(1) on the hot path (the general
/// [`family_for_dimension`](crate::federation::load_bearing::family_for_dimension)
/// walks the whole manifest and allocates — deliberately NOT used here).
///
/// # v36.1.0 — public (CIRISPersist#713, CIRISEdge adoption)
///
/// This is the surface a capability or subject overlay is 1:1 with. A
/// consumer gating on "does this dimension require `infra:serve`?" asks
/// `matches!(attestation_family(d), AttestationFamily::Trace)` — NOT
/// `matches!(projection_for(..), Projection::Capability(_))`, which is only
/// true at the commons tiers and silently stops gating below them. See
/// [`AttestationFamily`] for why the private-by-default rationale was wrong.
#[inline]
pub fn attestation_family(dimension: &str) -> AttestationFamily {
    // The exact-value gate FIRST — the value earns the row, the `system:*`
    // namespace never does.
    if dimension == SYSTEM_AUDIT_CHAIN_HASH_CONTINUITY {
        return AttestationFamily::SubstrateHealth;
    }
    if under(dimension, "consent:") {
        return AttestationFamily::Consent;
    }
    if under(dimension, "trace:") {
        return AttestationFamily::Trace;
    }
    if under(dimension, "scores:") {
        return AttestationFamily::Scores;
    }
    if under(dimension, "capacity:") {
        return AttestationFamily::Capacity;
    }
    if under(dimension, "content_class:") {
        return AttestationFamily::ContentClass;
    }
    if under(dimension, "transport:") {
        return AttestationFamily::SubstrateHealth;
    }
    // v36.1.0 (#713) — the DEEPER stem is decided; the rest of `provenance:*`
    // stays `Unknown` until someone decides it. Checked after the shallower
    // stems above cannot match it, and deliberately NOT widened to
    // `provenance:` — edge's argument is about build manifests specifically,
    // and a family earns its row by being argued for, not by sharing a
    // namespace with one that was.
    if under(dimension, "provenance:build_manifest:") {
        return AttestationFamily::ProvenanceBuildManifest;
    }
    // v36.2.0 (#713, decided by CIRISServer). `accord:` is the WHOLE reserved
    // prefix the co-scrub-assembly argument covers; its
    // RESERVED_CLASS_DIMENSION_PREFIXES sibling `objection:` is deliberately
    // NOT matched here and stays conservative until argued.
    if under(dimension, "accord:") {
        return AttestationFamily::Accord;
    }
    if under(dimension, "moderation:") {
        return AttestationFamily::Moderation;
    }
    AttestationFamily::Unknown
}

/// **The per-plane tombstone ceiling** — the projection a withdraw / recant /
/// supersede takes, replacing the pre-#713 unconditional
/// [`Global`](Projection::Global).
///
/// The invariant: **anti-rollback holds within the record's maximal disclosure
/// set; beyond it there is no copy to roll back.** The ceiling is the row-max
/// across ALL scopes for this `(plane, authority)` — the widest projection any
/// LIVE version of the record could ever have had, whatever scope it carried
/// at any point in its history. The row max dominates every scope, so
/// rescope-narrowing attacks are covered WITHOUT reading the record's scope
/// history — which is what keeps this pure: two inputs, no state.
/// `tests::tombstone_ceiling_dominates_every_live_cell` asserts the
/// row-max property against the registry itself.
///
/// And the reason narrowing is a duty, not an economy: **WIDENING A TOMBSTONE
/// DISCLOSES MORE THAN THE ORIGINAL FACT.** A Global withdrawal of a
/// Cohort-scoped route tells parties who never knew the route existed that it
/// DID exist — the erasure machinery manufacturing the very disclosure it was
/// performed to prevent. A tombstone ceiling above its row's max is not
/// wasteful; it is a contextual-integrity violation created by the privacy
/// machinery itself (#713 server relay, accepted without override).
///
/// The rows:
///
/// - [`KeyRecord`](ObjectClass::KeyRecord) → `Global`, unconditional — today's
///   rule KEPT, because the row's semantics demand it: signatures by a revoked
///   key may ride records that traveled Global, so the revocation's
///   verify-relevance is unbounded.
/// - [`TransportDestination`](ObjectClass::TransportDestination) /
///   [`FountainContent`](ObjectClass::FountainContent) → `Global` if
///   trust-root, else `Cohort`. A non-root route/corpus never projected beyond
///   Cohort under ANY scope, so a Cohort tombstone reaches every
///   replication-plane holder that can exist — anti-rollback preserved exactly
///   where copies can exist, and "this route was withdrawn" is disclosed only
///   to the set that could already know the route existed.
/// - [`HardCaseEvent`](ObjectClass::HardCaseEvent) → `Global` if the authority
///   carries an infra role, else `Cohort` — the de-admission of a node holding
///   an infra role stays Global BY ROLE (#713: "a revoked relay must be
///   globally unlearnable for the same reason it was globally discoverable").
///   APPROXIMATION, stated: [`AuthorityClass`] cannot express "carries an
///   infra role" more precisely than
///   [`is_trust_root`](AuthorityClass::is_trust_root) —
///   [`AccordCoScrub`](AuthorityClass::AccordCoScrub) IS the accord-blessed
///   canonical/infra class — so that predicate stands in for the thread's
///   "by role" language until an infra-role-precise authority input exists.
/// - [`Attestation`](Plane::Attestation) → per dimension FAMILY (v36.0.0,
///   #713 second half):
///   - `consent:*` → `Global`, unconditional — the thread's decided
///     exception: the routing editor must reach any holder who might rely on
///     it ("same anti-rollback logic as KeyRecord"), so this family alone
///     keeps a ceiling ABOVE its live row-max.
///   - `trace:*` → [`Capability`](Projection::Capability)(`infra:serve`) —
///     the row-max: copies only ever existed at the serve set (or on the
///     subject itself), so the retraction goes exactly there. A trace
///     retraction gossiped wider would disclose that a trace existed to
///     parties the trace itself never reached.
///   - `scores:*` → [`Subject`](Projection::Subject) — the row-max: past
///     self, only the subject's grant ever held a copy.
///   - `capacity:*` / `content_class:*` → `Global` if trust-root, else
///     `Cohort` (the ✱-at-federation row-max).
///   - `transport:*` and the EXACT `system:audit_chain:hash_continuity` →
///     `Global` for [`SubstrateSelf`](AuthorityClass::SubstrateSelf) or a
///     trust root, else `Cohort` (the row-max of the substrate-health row).
///   - *unknown family* → `Cohort` for EVERY authority — the conservative
///     row's max. An undecided family's retraction cannot gossip wider than
///     any copy of it could ever have traveled.
///
/// # Residuals (chosen on the thread, not discovered later)
///
/// 1. Trust-root reachability tombstones stay Global — infra reachability is
///    public by role, and its withdrawal is operationally load-bearing for the
///    whole mesh.
/// 2. The ceiling governs the REPLICATION plane only. Routes learned via the
///    announce plane are superseded by the announce/epoch machinery (the #337
///    verified-only route table), not by replication tombstones; a route
///    quoted INSIDE a Global record of another plane is the embedding record's
///    plane. Neither reopens a rollback window here.
#[inline]
pub fn tombstone_ceiling(plane: Plane<'_>, authority: AuthorityClass) -> Projection {
    match plane {
        // Verify-relevance is unbounded: signatures by a revoked key may ride
        // records that traveled Global.
        Plane::KeyRecord => Projection::Global,
        // Row max: a non-root route/corpus never projected beyond Cohort
        // under any scope.
        Plane::TransportDestination | Plane::FountainContent => {
            if authority.is_trust_root() {
                Projection::Global
            } else {
                Projection::Cohort
            }
        }
        // Global BY ROLE (infra de-admission); is_trust_root is the closest
        // AuthorityClass approximation of "carries an infra role" — see doc.
        Plane::HardCaseEvent => {
            if authority.is_trust_root() {
                Projection::Global
            } else {
                Projection::Cohort
            }
        }
        // Per dimension FAMILY (v36.0.0) — consent is the decided
        // above-row-max exception; every other family takes its row-max.
        Plane::Attestation { dimension } => match attestation_family(dimension) {
            AttestationFamily::Consent => Projection::Global,
            AttestationFamily::Trace => Projection::Capability(CapabilityToken::InfraServe),
            AttestationFamily::Scores => Projection::Subject,
            // Row-max for all three: ✱ at their widest live cell. The
            // provenance row reaches ✱ at three commons tiers rather than one,
            // but the MAX is the same value, so the ceiling arm is shared.
            AttestationFamily::Capacity
            | AttestationFamily::ContentClass
            | AttestationFamily::ProvenanceBuildManifest => {
                if authority.is_trust_root() {
                    Projection::Global
                } else {
                    Projection::Cohort
                }
            }
            AttestationFamily::SubstrateHealth => {
                if matches!(authority, AuthorityClass::SubstrateSelf) || authority.is_trust_root() {
                    Projection::Global
                } else {
                    Projection::Cohort
                }
            }
            // Row-max, and UNCONDITIONAL for accord: its live commons cells
            // are Global for every authority, so a tombstone that retracts a
            // partial must reach everywhere the partial could have assembled.
            AttestationFamily::Accord => Projection::Global,
            // Row-max: moderation never widens past Cohort live, so its
            // retraction does not either. A withdrawal of an allegation must
            // not travel further than the allegation did — widening it would
            // republish the allegation to parties who never held it, which is
            // the tombstone principle this cut already recorded.
            AttestationFamily::Moderation => Projection::Cohort,
            AttestationFamily::Unknown => Projection::Cohort,
        },
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

    /// The [`ObjectClass`] plane this replicated kind projects under — the
    /// explicit #713 mapping from the fetch-kind enum onto the five-plane
    /// projection registry. The two enums are NOT 1:1: this enum has no
    /// `FountainContent` / `HardCaseEvent` fetch kinds, and the projection
    /// registry has no occurrence planes — so the bridge is spelled here,
    /// once, instead of being re-derived per consumer. For
    /// [`ObjectClass::Attestation`] the projection call additionally needs
    /// the envelope `dimension` the consumer already holds
    /// ([`Plane::Attestation`]) — the v36.0.0 decomposition's
    /// information-type axis.
    ///
    /// The occurrence kinds ride the KeyRecord row DELIBERATELY: an identity
    /// occurrence is the same structurally-invisible identity plane as the
    /// key record (the #257 `key_selector` / #305 `occurrence_selector`
    /// [`Projection::SelfOwn`] already documents as ONE projection), and the
    /// KeyRecord row is exactly the pre-#713 behavior — so this mapping is
    /// behavior-preserving for the two kinds #713's thread did not
    /// re-decide. An [`IdentityOccurrenceRevocation`](ReplicatedKind::IdentityOccurrenceRevocation)
    /// under KeyRecord's ceiling keeps today's unconditional-Global
    /// anti-rollback.
    #[must_use]
    pub const fn projection_plane(self) -> ObjectClass {
        match self {
            ReplicatedKind::KeyRecord
            | ReplicatedKind::IdentityOccurrence
            | ReplicatedKind::IdentityOccurrenceRevocation => ObjectClass::KeyRecord,
            ReplicatedKind::TransportDestination => ObjectClass::TransportDestination,
            ReplicatedKind::Attestation => ObjectClass::Attestation,
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
/// canonical server OR an accord-blessed build-signing pipeline — the two
/// [`AuthorityClass::AccordCoScrub`] roles — **and neither role has been
/// withdrawn.** The `is_trust_root` the edge engine consults to promote a
/// commons record to [`Projection::Global`].
///
/// # It asks the EFFECTIVE question (v31.5.0, CIRISPersist#685)
///
/// This called the bare
/// [`is_canonical`](crate::federation::admission::is_canonical) /
/// [`is_infra_attest`](crate::federation::admission::is_infra_attest), which
/// answer *"does the row carry this role"* and say nothing about whether a
/// quorum has since withdrawn it. `is_infra_attest`'s own doc says a consumer
/// deciding whether to **trust** must call the `_effective` variant; this one
/// decides trust and did not.
///
/// The consequence was not subtle. This predicate is the load-bearing test in
/// [`projection_for`]: a public record from a trust root reaches the **whole
/// federation**, the same scope from a plain producer relays over its cohort.
/// So a key whose trust-root role had been withdrawn by quorum **kept gossiping
/// globally**. The withdrawal was stored, verifiable, and unread on this path —
/// the edge existed and the reader skipped it, which is the same shape as #659
/// (a co-scrub conferring `canonical` on any key_id) and #608 (a sanction not
/// covering the sanctioning dimension).
///
/// The `_effective` variants consult
/// [`lookup_role_withdrawal`](crate::federation::FederationDirectory::lookup_role_withdrawal)
/// — the V095/V104 tombstone — and treat a withdrawal as disqualifying unless it
/// is a rotate-in (`superseded_by == key_id`).
pub async fn is_trust_root(
    directory: &dyn crate::federation::FederationDirectory,
    key_id: &str,
) -> Result<bool, crate::federation::Error> {
    Ok(
        crate::federation::admission::is_canonical_effective(directory, key_id).await?
            || crate::federation::admission::is_infra_attest_effective(directory, key_id).await?,
    )
}

// ─────────────────────────────────────────────────────────────────────────
// v37.1.0 (CIRISPersist#744) — THE RECIPIENT-SET AXIS
//
// CIRISEdge closed a real leak: its swarm publisher broadcast every held
// `content_id` AND its `symbol_ids`, on a timer, to every peer, with no
// entitlement filter — so a `family`- or `community`-scoped holding was
// announced to peers with no business knowing it existed. The fix routes
// through `projection_for(Plane::FountainContent, …)`, and that surfaced the
// gap this section closes.
//
// **THE RULE IS PERSIST'S, AND IT IS A PROJECTION QUESTION.** CIRISServer drew
// the line that settles it (the `accord:*` row above states it): *projection
// decides who may HOLD the bytes; whether a given node may CARRY a particular
// object is the per-node relational question.* Advertising a holding
// DISCLOSES THAT YOU HOLD IT. That disclosure is itself a fact about who may
// hold what, so it is projection's to answer, not a relay overlay's. Were it
// the consumer's business, every consumer would derive its own recipient set
// from the same projection cell — the two-owners-for-one-wire-fact shape #731
// and #733 spent two releases removing.
// ─────────────────────────────────────────────────────────────────────────

/// v37.1.0 (CIRISPersist#744) — **how the recipient set was arrived at, or why
/// it could not be.** Reported alongside the two booleans of
/// [`RecipientVerdict`] because *"I cannot judge"* has more than one cause and
/// each is a different thing for an operator to go fix — the same reason
/// [`RelayVerdict`](crate::federation::trust_root::RelayVerdict) is three
/// fields rather than a bool.
///
/// `#[non_exhaustive]`: a future audience axis (a scope-address table, an
/// infra-role set) adds a basis without breaking a consumer's build. Consumers
/// match what they report on and let the rest fall through — the refusal is
/// carried by [`RecipientVerdict::may_advertise`], never by this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// # The forced wildcard arm (downstream guidance, v38.0.0 / #746)
///
/// `#[non_exhaustive]` forces external matches to carry a wildcard arm.
/// Map that arm to **"I cannot judge"** — withhold, never a seated/
/// not-seated answer. A wildcard that defaults to "not in the set" turns
/// every future variant into a silent refusal of legitimate peers, and one
/// that defaults to "in the set" turns it into an open door; only
/// cannot-judge fails closed without lying about why.
#[non_exhaustive]
pub enum RecipientBasis {
    /// [`Projection::SelfOwn`] — **the record's OWN roster bounds the set.**
    /// This is the reading CIRISEdge shipped as an inference and #744 asked
    /// persist to own: `SelfOwn` is not only *"advertise iff this node
    /// produced it"*, it also bounds WHO the advertisement may reach.
    OwnRoster,
    /// [`Projection::Cohort`] — the active roster of the named group bounds
    /// the set (`community` / `affiliations` / `family`, revocation-folded).
    CohortRoster,
    /// [`Projection::Global`] — the record reaches the whole federation, so no
    /// roster bounds it and every peer is in the set. The ONE resolvable
    /// audience with no roster read behind it.
    Unbounded,
    /// **Cannot judge** — the record's `cohort_scope` names no rostered tier
    /// (`species` / `biosphere` / `federation`, or a scope this build has
    /// never heard of). Persist holds roster tables for `self` / `family` /
    /// `community` / `affiliations` and NOTHING ELSE; the commons tiers are
    /// audience scopes whose address table does not exist yet (gated on
    /// CIRISVerify#259). With no table, the honest answer is that the set is
    /// unresolved — and the fail-closed answer is to advertise to nobody.
    NoRosterForScope,
    /// **Cannot judge** — the scope names a rostered tier, but this node
    /// cannot see that group's roster: the group is unknown here, or the read
    /// failed. Distinct from [`NoRosterForScope`](Self::NoRosterForScope)
    /// (the scope has no roster AT ALL) and, critically, distinct from a
    /// RESOLVED roster the peer is simply not on.
    GroupUnresolvable,
    /// **Wrong id space** (v38.0.0, CIRISPersist#746) — the caller handed a
    /// SCOPE-ADDRESS-TABLE id (edge's `ContentScope::Group` mints
    /// `cohort:{community_id}` / `av-stream:{hex}`) where this verb's
    /// contract is a FEDERATION DIRECTORY key id (`family_key_id` /
    /// `community_key_id` / `key_id`). Persist holds no mapping between the
    /// two spaces, and answering through the roster read would have reported
    /// a confident [`GroupUnresolvable`](Self::GroupUnresolvable) about a
    /// group that was never asked about — the false-authoritative "I cannot
    /// judge" this verb's signature exists to prevent (#731). The prefix
    /// check is a TYPED REFUSAL ONLY, never a resolution path — sniffing a
    /// prefix to pick a table would be one parameter meaning two things,
    /// the axis fusion this repo removes elsewhere. The handover itself is
    /// edge's: `ContentScope` must carry (or translate to) the federation
    /// group key id it already knows at scope-address mint time.
    GroupIdNotFederationKeyed,
    /// **Cannot judge, by construction** — the projection's audience is keyed
    /// on an axis that is not a roster: [`Projection::Capability`] selects by
    /// ROLE and [`Projection::Subject`] by the data subject's grant. Neither
    /// is a question a `(scope, group)` pair can answer, and answering it with
    /// a roster would be the axis fusion this repo removes elsewhere. NOT a
    /// licence to advertise: [`RecipientVerdict::may_advertise`] is `false`
    /// here, and a consumer serving those planes gates them on their own axis
    /// ([`attestation_family`] → `Trace` / `Scores`, per the v36.1.0 note on
    /// [`AttestationFamily`]).
    NotRosterKeyed,
}

/// v37.1.0 (CIRISPersist#744) — the typed verdict of
/// [`resolve_projection_recipients`]. Deliberately the shape of
/// [`RelayVerdict`](crate::federation::trust_root::RelayVerdict) — edge named
/// [`resolve_transit_eligibility`](crate::federation::trust_root::resolve_transit_eligibility)
/// as the model and the two verbs answer sibling questions, so a reader
/// comparing them should not have to learn a second idiom.
///
/// **The distinction that must never collapse.** `set_resolvable: false` means
/// *"I cannot judge"*; `set_resolvable: true, peer_in_set: false` means
/// *"I judged, and this peer is not seated"*. Both refuse — but an operator
/// debugging a withheld advertisement needs to know which, and a substrate
/// that reports the second when it means the first is claiming knowledge it
/// does not have. [`RelayVerdict`](crate::federation::trust_root::RelayVerdict)
/// carries the same distinction for the same reason (`roster_resolvable`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientVerdict {
    /// The recipient set for this `(plane, scope, group)` was resolvable at
    /// all. `false` means *"I cannot judge"* — NOT *"the peer is not in the
    /// set"*. See [`RecipientBasis`] for which cause fired.
    pub set_resolvable: bool,
    /// The peer is in the resolved recipient set. Meaningless unless
    /// `set_resolvable`; a caller must go through
    /// [`may_advertise`](Self::may_advertise) rather than read this alone.
    pub peer_in_set: bool,
    /// How the set was arrived at, or why it could not be.
    pub basis: RecipientBasis,
}

impl RecipientVerdict {
    /// **May this record's holding be advertised to this peer?** Only when the
    /// set resolved AND the peer is in it. Fail-closed in every other
    /// combination, including both *"cannot judge"* cases — a directory read
    /// that failed tells us nothing about the peer, and nothing is not a
    /// reason to disclose what we hold.
    #[must_use]
    pub fn may_advertise(self) -> bool {
        self.set_resolvable && self.peer_in_set
    }
}

/// v37.1.0 (CIRISPersist#744) — **may `peer_key_id` be told that we hold this
/// record?** The recipient-set verb CIRISEdge asked for, shaped after
/// [`resolve_transit_eligibility`](crate::federation::trust_root::resolve_transit_eligibility)
/// as edge proposed.
///
/// # Why `SelfOwn` needed this, and why the edge-local reading was vacuous
///
/// [`Projection::SelfOwn`] is documented as structural invisibility — no
/// directory advertisement — and edge's replication bridge implements that as
/// **"advertise iff this node produced it"**, which is exactly right on the
/// attestation plane.
///
/// It is **VACUOUS on the holdings plane**: the swarm publisher is *always*
/// the producer of its own holdings, so that predicate admits a family-scoped
/// holding to every peer and closes nothing — the leak survives the gate. A
/// projection value that means one thing on one plane and nothing on another
/// is not a projection value; it is a coincidence. So `SelfOwn` also **bounds
/// the recipient set to the record's own roster**, which is the reading edge
/// shipped as an inference and #744 asked persist to own.
///
/// The producer predicate is NOT subsumed here and must not be dropped: the
/// two are conjunctive. *Who may advertise* stays edge's relay question; *who
/// may be advertised to* is this. Fusing them would put one name on two axes.
///
/// # The parameters, and why they are not edge's four
///
/// Edge proposed `(plane, scope, group, peer) -> bool`. Two deviations, both
/// load-bearing:
///
/// - `authority` and `is_tombstone` are taken so this verb resolves the
///   projection ITSELF through [`projection_for`], rather than accepting a
///   caller-nominated [`Projection`]. A caller that nominates the wrong cell
///   gets a confidently wrong answer in the permissive direction — the exact
///   shape #731 removed one plane over
///   ([`may_relay_accord_object`](crate::federation::trust_root::may_relay_accord_object)
///   taking a caller-supplied `root_ref`). The caller already holds both
///   values, because it already had to call [`projection_for`].
/// - the verdict is [`RecipientVerdict`], not `bool`, so *"I cannot judge"*
///   stays distinguishable from *"resolved, not a member"*.
///
/// # What it does with no scope-address table — the fail-closed answer
///
/// Persist holds roster tables for exactly four tiers (`self` / `family` /
/// `community` / `affiliations`, via
/// [`active_members`](crate::federation::FederationDirectory::active_members),
/// revocation-folded). The commons tiers — `species` / `biosphere` /
/// `federation` — are audience scopes with no roster table, and the
/// scope-address table that would give them one does not exist yet (gated on
/// CIRISVerify#259). So a [`Cohort`](Projection::Cohort) projection at a
/// commons tier resolves [`RecipientBasis::NoRosterForScope`],
/// `set_resolvable: false`, `may_advertise() == false`. **Not "every peer".**
/// The verb is answerable TODAY at the four rostered tiers, which is where the
/// leak #744 reports actually lived; it becomes answerable at the commons
/// tiers when the table lands, and until then it withholds.
///
/// # Fail-closed, always
///
/// Any directory error, an unknown group, an unresolvable read — every one
/// returns a `set_resolvable: false` verdict rather than an `Err`, exactly as
/// [`resolve_transit_eligibility`](crate::federation::trust_root::resolve_transit_eligibility)
/// does. The `Result` is retained for API stability and because a future leg
/// may need to distinguish an infrastructure fault from a refusal; today every
/// resolution path returns `Ok`.
pub async fn resolve_projection_recipients(
    directory: &dyn crate::federation::FederationDirectory,
    plane: Plane<'_>,
    cohort_scope: &str,
    authority: AuthorityClass,
    is_tombstone: bool,
    group_key_id: &str,
    peer_key_id: &str,
) -> Result<RecipientVerdict, crate::federation::Error> {
    const fn cannot_judge(basis: RecipientBasis) -> RecipientVerdict {
        RecipientVerdict {
            set_resolvable: false,
            peer_in_set: false,
            basis,
        }
    }

    // The projection is resolved HERE, from the record's own axes — never
    // nominated by the caller (#731's lesson, one plane over).
    let basis = match projection_for(plane, cohort_scope, authority, is_tombstone) {
        // The one audience with no roster behind it: the record reaches the
        // whole federation, so the set resolved and every peer is in it.
        Projection::Global => {
            return Ok(RecipientVerdict {
                set_resolvable: true,
                peer_in_set: true,
                basis: RecipientBasis::Unbounded,
            })
        }
        // Role-keyed / subject-keyed audiences are not this verb's question.
        // Fail closed and SAY SO, so a consumer cannot read the refusal as
        // "not seated" and go looking for a roster that was never the answer.
        Projection::Capability(_) | Projection::Subject => {
            return Ok(cannot_judge(RecipientBasis::NotRosterKeyed))
        }
        // THE #744 CELL. `SelfOwn` is roster-bounded on every plane — it is
        // not the producer predicate wearing a projection's name.
        Projection::SelfOwn => RecipientBasis::OwnRoster,
        Projection::Cohort => RecipientBasis::CohortRoster,
    };

    // Roster-keyed from here. The scope must name a tier persist holds a
    // roster table for; the commons tiers do not, and no scope-address table
    // exists to give them one (CIRISVerify#259).
    let Ok(cohort) = crate::federation::cohort::Cohort::from_token(cohort_scope) else {
        return Ok(cannot_judge(RecipientBasis::NoRosterForScope));
    };

    // The `self` tier's roster is the subject's identity OCCURRENCES, and an
    // unknown identity resolves `Ok(vec![])` there rather than an error — the
    // one place "cannot judge" would silently become "resolved, empty" if this
    // existence check were dropped.
    // [`active_roster_of`](crate::federation::trust_root::active_roster_of)
    // draws the same line (`Ok(None)` vs `Ok(Some(vec![]))`) for the same
    // reason.
    // v38.0.0 (CIRISPersist#746) — a scope-address-table id is the WRONG ID
    // SPACE for this verb, and it is refused BY NAME before any roster read:
    // feeding it through active_members would yield a confident
    // GroupUnresolvable about a group that was never asked about. The two
    // prefixes are the ones edge's scope-address table mints; the check
    // refuses, it never routes — routing on a sniffed prefix would be the
    // axis fusion this parameter exists to remove.
    if group_key_id.starts_with("cohort:") || group_key_id.starts_with("av-stream:") {
        tracing::warn!(
            cohort_scope,
            group_key_id,
            peer_key_id,
            "resolve_projection_recipients: scope-address-table id in the \
             federation-key parameter (#746) — WITHHOLDING with the typed \
             refusal; the caller must hand over the federation group key id"
        );
        return Ok(cannot_judge(RecipientBasis::GroupIdNotFederationKeyed));
    }

    if matches!(cohort, crate::federation::cohort::Cohort::SelfId)
        && !matches!(directory.lookup_public_key(group_key_id).await, Ok(Some(_)))
    {
        return Ok(cannot_judge(RecipientBasis::GroupUnresolvable));
    }

    match directory.active_members(cohort, group_key_id).await {
        Ok(members) => Ok(RecipientVerdict {
            set_resolvable: true,
            peer_in_set: members.iter().any(|m| m.key_id == peer_key_id),
            basis,
        }),
        Err(e) => {
            // The fail-closed clause, and the only place it fires. A read that
            // failed tells us nothing about the group, and "nothing" is not a
            // reason to disclose what this node holds.
            tracing::warn!(
                cohort_scope,
                group_key_id,
                peer_key_id,
                error = %e,
                "resolve_projection_recipients: roster read failed — WITHHOLDING \
                 (an advertisement gate never fails open)"
            );
            Ok(cannot_judge(RecipientBasis::GroupUnresolvable))
        }
    }
}

/// v37.1.0 (CIRISPersist#744 item 2) — **the declared authority of a held
/// fountain corpus**, resolved from its PUBLISHER.
///
/// # The gap this closes
///
/// [`Plane::FountainContent`] resolves [`Projection::Global`] at `federation`
/// scope only when the authority
/// [`is_trust_root`](AuthorityClass::is_trust_root). But a held corpus carries
/// `content_id`, `corpus_kind` and `symbol_ids` — nothing that says whether it
/// is accord-co-scrubbed — so CIRISEdge passed
/// [`AuthorityClass::ProducerSteward`], the negative default, and **a genuine
/// trust-root canonical corpus was under-advertised.** It cost nothing at the
/// tiers in play (`Global` and `Cohort` both admit the broadcast there), but
/// it was a wrong answer to a right question.
///
/// # Why this is a SEAM and not a column
///
/// Edge's constraint is correct and load-bearing: **a consumer must not infer
/// an authority class from a corpus kind.** That leaves two shapes, and only
/// one of them is available:
///
/// - **Carrying authority on the fountain row is refused.** The producer's
///   hybrid signature covers
///   [`FountainManifestV1::canonical_value`](crate::fountain::FountainManifestV1::canonical_value)
///   in a LOCKED field order, and `V1` is frozen the moment the V084 migration
///   shipped (shipped migrations are immutable). A field added to those signed
///   bytes invalidates every stored manifest signature mesh-wide — the failure
///   `types::signing_preimage_pin_tests` exists to make impossible by accident
///   on the planes it covers.
/// - **A producer-declared authority key in the signed `envelope` is refused
///   too, and this is the subtler one.** The envelope is opaque JSON, so a new
///   key inside it moves no preimage for already-stored rows — it is
///   *mechanically* safe and *substantively* wrong.
///   [`AuthorityClass::AccordCoScrub`] is precisely the class a producer must
///   never self-declare: a corpus whose envelope said
///   `"authority": "accord_co_scrub"` would confer trust-root reach on itself.
///   That is the shape #543 enumerated (privilege a peer writes into its own
///   registration) and the shape #659 hit (a gate reading the subject rather
///   than the signer).
///
/// So the authority is DECLARED AT THE SEAM and re-derived from persist's own
/// verified state on every call — never stored, never signed by the party it
/// benefits, never inferred from `corpus_kind`. Note the signature: the only
/// input is the publisher key. `corpus_kind` is not a parameter, so the
/// inference edge was told not to make is not expressible here.
///
/// # What it resolves
///
/// [`is_trust_root`] — *is the publisher an accord-blessed canonical server or
/// an accord-blessed build-signing pipeline, with neither role withdrawn* —
/// which is already the exact predicate [`projection_for`]'s ✱ cells consult,
/// so this seam introduces no second definition of "trust root". Withdrawal
/// therefore wins here for free (v31.5.0 / #685): a quorum-withdrawn canonical
/// publisher demotes to [`ProducerSteward`](AuthorityClass::ProducerSteward)
/// and its corpus stops gossiping globally on the very next resolution.
///
/// Anything else — an unregistered publisher, a plain producer, a read that
/// came back empty — is [`ProducerSteward`](AuthorityClass::ProducerSteward),
/// the negative default. That IS the fail-closed answer on this plane:
/// `ProducerSteward` never widens a cell in [`projection_for`], on any plane,
/// so an unknown publisher can only ever narrow the audience.
///
/// [`SubstrateSelf`](AuthorityClass::SubstrateSelf) is deliberately
/// unreachable: it is the substrate-self-report class (`transport:*`,
/// `system:*`), and a fountain corpus is content — a claim about bytes, not a
/// substrate reporting on itself.
pub async fn holdings_authority(
    directory: &dyn crate::federation::FederationDirectory,
    publisher_key_id: &str,
) -> Result<AuthorityClass, crate::federation::Error> {
    if is_trust_root(directory, publisher_key_id).await? {
        Ok(AuthorityClass::AccordCoScrub)
    } else {
        Ok(AuthorityClass::ProducerSteward)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every authority class, for sweeps whose expected cell is the same
    /// LITERAL for all of them. Never used to derive an expectation.
    const AUTHORITIES: [AuthorityClass; 4] = [
        AuthorityClass::SelfIdentity,
        AuthorityClass::AccordCoScrub,
        AuthorityClass::SubstrateSelf,
        AuthorityClass::ProducerSteward,
    ];

    /// The seven closed scopes plus one unrecognized, for the row-max sweep.
    const SCOPES: [&str; 8] = [
        "self",
        "family",
        "community",
        "affiliations",
        "species",
        "biosphere",
        "federation",
        "some-future-scope",
    ];

    /// One representative dimension per decided Attestation family, plus one
    /// resolving the conservative default — LITERALS, never derived from the
    /// classifier under test.
    const FAMILY_DIMS: [&str; 11] = [
        "consent:replication:v1",
        "trace:complete:v1",
        "scores:medical",
        "capacity:integrity",
        "content_class:violence",
        "transport:reticulum",
        "system:audit_chain:hash_continuity",
        // v37.0.1 (CIRISPersist#741) — THE THREE FAMILIES #713 DECIDED, ADDED
        // THREE CUTS LATE.
        //
        // This list's doc says "one representative dimension per decided
        // Attestation family", and for three releases it was not: `accord:*`
        // (v36.2.0), `moderation:*` (v36.2.0) and `provenance:build_manifest:*`
        // (v36.1.0) each got an explicit arm in `projection_for` and none was
        // added here. So every property sweep built on `all_planes()` — the
        // anti-rollback dominance invariant among them — silently never looked
        // at the newest and least settled families in the registry.
        //
        // That is worse than a thin corpus: the doc CLAIMS one per decided
        // family, so the sweep reads as total. Verified by mutation — lifting
        // moderation's live commons cells to Global left
        // `tombstone_ceiling_dominates_every_live_cell` GREEN, because the
        // family it had just broken was not in its corpus.
        //
        // Adding a family's arm to `projection_for` and forgetting this list is
        // the easy mistake, and nothing catches it. `every_decided_family_has_a_
        // representative_dimension` below now does.
        "accord:lifecycle:v1",
        "moderation:rogue_action:v1",
        "provenance:build_manifest:v1",
        "ratchet:flag:out_of_distribution_voting", // no decided row — the conservative default
    ];

    /// The four dimension-less planes — for sweeps whose expected cell is the
    /// same LITERAL across them.
    const DIMLESS_PLANES: [Plane<'static>; 4] = [
        Plane::KeyRecord,
        Plane::TransportDestination,
        Plane::FountainContent,
        Plane::HardCaseEvent,
    ];

    /// Every plane, with the Attestation plane fanned across [`FAMILY_DIMS`]
    /// — the projection registry's full extent, for property sweeps.
    fn all_planes() -> Vec<Plane<'static>> {
        let mut v = DIMLESS_PLANES.to_vec();
        v.extend(
            FAMILY_DIMS
                .iter()
                .map(|&d| Plane::Attestation { dimension: d }),
        );
        v
    }

    /// v37.0.1 (CIRISPersist#741) — **THE MECHANISM THAT KEEPS
    /// [`FAMILY_DIMS`] HONEST.**
    ///
    /// `FAMILY_DIMS` is the corpus for every property sweep built on
    /// [`all_planes`], including the anti-rollback dominance invariant. Its doc
    /// claims one representative per decided family. For three releases that
    /// was false — `accord:*`, `moderation:*` and `provenance:build_manifest:*`
    /// each had an explicit arm in [`projection_for`] and no representative
    /// here, so the sweeps never looked at them while reading as total.
    ///
    /// A doc claim is not a mechanism. This is the mechanism, and it works in
    /// two directions at once:
    ///
    /// - The match below is **EXHAUSTIVE with no wildcard**. `AttestationFamily`
    ///   is `#[non_exhaustive]`, which constrains downstream crates but not this
    ///   one — so adding a variant **fails this build** until someone names its
    ///   representative. That is a compile error, not a test failure: it cannot
    ///   be skipped, filtered out, or lost in a feature set that does not run.
    /// - Each named representative is then checked to be present in
    ///   `FAMILY_DIMS` **and** to actually resolve to that family via
    ///   [`attestation_family`] — so a typo'd or re-prefixed dimension cannot
    ///   satisfy the gate while classifying as `Unknown`.
    #[test]
    fn every_decided_family_has_a_representative_dimension() {
        // No wildcard arm. This is load-bearing — see the doc above.
        fn representative(f: AttestationFamily) -> Option<&'static str> {
            match f {
                AttestationFamily::Consent => Some("consent:replication:v1"),
                AttestationFamily::Trace => Some("trace:complete:v1"),
                AttestationFamily::Scores => Some("scores:medical"),
                AttestationFamily::Capacity => Some("capacity:integrity"),
                AttestationFamily::ContentClass => Some("content_class:violence"),
                AttestationFamily::SubstrateHealth => Some("transport:reticulum"),
                AttestationFamily::Accord => Some("accord:lifecycle:v1"),
                AttestationFamily::Moderation => Some("moderation:rogue_action:v1"),
                AttestationFamily::ProvenanceBuildManifest => Some("provenance:build_manifest:v1"),
                // The conservative default is not a decided family; its
                // representative rides FAMILY_DIMS separately so the sweeps
                // still exercise the fall-through.
                AttestationFamily::Unknown => None,
            }
        }

        for family in [
            AttestationFamily::Consent,
            AttestationFamily::Trace,
            AttestationFamily::Scores,
            AttestationFamily::Capacity,
            AttestationFamily::ContentClass,
            AttestationFamily::SubstrateHealth,
            AttestationFamily::Accord,
            AttestationFamily::Moderation,
            AttestationFamily::ProvenanceBuildManifest,
        ] {
            let dim = representative(family).unwrap_or_else(|| {
                panic!("{family:?} is a decided family and needs a representative dimension")
            });
            assert!(
                FAMILY_DIMS.contains(&dim),
                "{family:?}'s representative {dim:?} is not in FAMILY_DIMS, so every \
                 property sweep over all_planes() is blind to that family while its \
                 doc claims otherwise (CIRISPersist#741)"
            );
            assert_eq!(
                attestation_family(dim),
                family,
                "{dim:?} is listed as {family:?}'s representative but classifies \
                 differently — a representative that does not resolve to its own \
                 family exercises the wrong arm"
            );
        }
    }

    #[test]
    fn projection_self_and_family_are_publish_own() {
        // Every plane's self/family cells are SelfOwn — the structurally-
        // invisible identity tier is publish-own on every plane, and on every
        // Attestation dimension family including the conservative default.
        for plane in all_planes() {
            for s in ["self", "family"] {
                assert_eq!(
                    projection_for(plane, s, AuthorityClass::SelfIdentity, false),
                    Projection::SelfOwn,
                    "{plane:?}/{s}"
                );
            }
        }
    }

    /// The five commons tiers, spelled out rather than derived from any list
    /// the code under test also reads.
    const COMMONS_TIERS: [&str; 5] = [
        "community",
        "affiliations",
        "species",
        "biosphere",
        "federation",
    ];

    /// Every live `moderation:*` dimension. Hand-written: deriving this from
    /// the registry would make the witness agree with whatever the registry
    /// happens to say.
    const MODERATION_DIMS: [&str; 5] = [
        "moderation:rogue_action:v1",
        "moderation:harassment:v1",
        "moderation:conduct:v1",
        "moderation:tone:v1",
        "moderation:report:v1",
    ];

    const ALL_AUTHORITIES: [AuthorityClass; 4] = [
        AuthorityClass::SelfIdentity,
        AuthorityClass::AccordCoScrub,
        AuthorityClass::SubstrateSelf,
        AuthorityClass::ProducerSteward,
    ];

    /// v37.0.1 (CIRISPersist#741) — THE ALLEGATION CEILING, asserted rather
    /// than inherited.
    ///
    /// Every live `moderation:*` dimension is an **adverse allegation about a
    /// party** (`rogue_action`, `harassment`, `conduct`, `tone`, `report`), so
    /// Global gossip of them is a reputation directory. The ceiling held
    /// before this test, but only because the match arm fell through to `_` —
    /// making Moderation the one family in the registry whose commons tiers
    /// were not enumerated, while `Accord`, `ProvenanceBuildManifest` and
    /// `SubstrateHealth` each spell out `SPECIES | BIOSPHERE | FEDERATION`.
    ///
    /// A consistency sweep that "finished" Moderation to match its neighbours
    /// would have written `=> Global` and lifted the ceiling with every test
    /// still green, because none looked at this cell.
    ///
    /// **No authority widens it**, which is the second half: a trust root can
    /// carry a key record or a build manifest to the whole federation, and it
    /// still may not carry an allegation past the cohort.
    #[test]
    fn moderation_holds_its_cohort_ceiling_at_every_commons_tier() {
        for dim in MODERATION_DIMS {
            let plane = Plane::Attestation { dimension: dim };
            for tier in COMMONS_TIERS {
                for authority in ALL_AUTHORITIES {
                    assert_eq!(
                        projection_for(plane, tier, authority, false),
                        Projection::Cohort,
                        "LIVE allegation ceiling breached: {dim} at {tier} under \
                         {authority:?} projected past Cohort. Every moderation:* \
                         dimension is an adverse allegation about a party; Global \
                         gossip of allegations is a reputation directory \
                         (CIRISPersist#741, decided v36.2.0 by CIRISServer)."
                    );
                }
            }
        }
    }

    /// The tombstone half, and the sharper one: **a withdrawal must not
    /// republish the allegation to parties who never held it.**
    ///
    /// Note the deliberate asymmetry with `Accord` directly above it in
    /// [`projection_for`], whose row-max IS unconditionally Global precisely
    /// because its live commons cells are Global — a tombstone retracting a
    /// partial must reach everywhere the partial could have assembled. Two
    /// families, opposite tombstone rules, one principle: the retraction
    /// travels exactly as far as the thing it retracts, never further.
    #[test]
    fn moderation_tombstone_never_travels_further_than_the_allegation() {
        for dim in MODERATION_DIMS {
            let plane = Plane::Attestation { dimension: dim };
            for tier in COMMONS_TIERS {
                for authority in ALL_AUTHORITIES {
                    assert_eq!(
                        projection_for(plane, tier, authority, true),
                        Projection::Cohort,
                        "TOMBSTONE ceiling breached: a withdrawal of {dim} at {tier} \
                         under {authority:?} projected past Cohort, republishing the \
                         allegation to parties who never held it (CIRISPersist#741)."
                    );
                }
            }
        }
    }

    /// ANTI-VACUITY. The two ceiling witnesses above assert `== Cohort`
    /// everywhere they look, so a `projection_for` that had rotted into
    /// returning `Cohort` unconditionally would satisfy both and prove
    /// nothing.
    ///
    /// This pins that the same harness — same tiers, same call shape — does
    /// observe `Global` on a family that is supposed to reach it. If this
    /// fails, the ceiling tests above are no longer evidence of anything.
    #[test]
    fn the_ceiling_harness_can_actually_observe_global() {
        let accord = Plane::Attestation {
            dimension: "accord:lifecycle:v1",
        };
        for tier in ["species", "biosphere", "federation"] {
            assert_eq!(
                projection_for(accord, tier, AuthorityClass::ProducerSteward, false),
                Projection::Global,
                "anti-vacuity: accord:* must project Global at {tier}; if it does \
                 not, the moderation ceiling assertions are vacuous"
            );
        }
    }

    #[test]
    fn projection_community_and_affiliations_relay_over_cohort() {
        // The four dimension-less planes relay community/affiliations over
        // the cohort roster. The Attestation plane's cells moved to the
        // per-family row tests below: trace:* stays SelfOwn there and
        // scores:* is Subject — the #713 decomposition's whole point.
        for plane in DIMLESS_PLANES {
            for s in ["community", "affiliations"] {
                assert_eq!(
                    projection_for(plane, s, AuthorityClass::ProducerSteward, false),
                    Projection::Cohort,
                    "{plane:?}/{s}"
                );
            }
        }
    }

    #[test]
    fn key_record_commons_is_global_only_for_trust_root() {
        // build manifest / canonical (accord co-scrub, trust root) → GLOBAL —
        // on the KEY plane: keys must resolve wherever their signatures travel.
        for s in ["species", "biosphere", "federation"] {
            assert_eq!(
                projection_for(Plane::KeyRecord, s, AuthorityClass::AccordCoScrub, false),
                Projection::Global,
                "trust-root {s} key record"
            );
            // a plain producer's commons record relays over the cohort.
            assert_eq!(
                projection_for(Plane::KeyRecord, s, AuthorityClass::ProducerSteward, false),
                Projection::Cohort,
                "producer {s} key record"
            );
            // substrate-self is NOT a trust root → cohort (documented surface).
            assert_eq!(
                projection_for(Plane::KeyRecord, s, AuthorityClass::SubstrateSelf, false),
                Projection::Cohort,
                "substrate-self {s} key record"
            );
        }
    }

    /// THE cell the whole #713 thread argued about: a trust root's
    /// species/biosphere-scoped ROUTE stays Cohort (pre-#713 these cells were
    /// ✱ → Global for a trust root). Routes need only reach those with a
    /// delivery relationship; Global non-infra reachability is a presence
    /// directory.
    #[test]
    fn transport_destination_species_biosphere_stay_cohort_even_for_trust_root() {
        for s in ["species", "biosphere"] {
            assert_eq!(
                projection_for(
                    Plane::TransportDestination,
                    s,
                    AuthorityClass::AccordCoScrub,
                    false
                ),
                Projection::Cohort,
                "a trust root's {s}-scoped route must NOT gossip Global"
            );
        }
    }

    /// The full TransportDestination row, cell by cell — LITERALS, never
    /// derived from the registry under test.
    #[test]
    fn transport_destination_row_matches_the_decided_table() {
        use AuthorityClass::{AccordCoScrub, ProducerSteward};
        use Projection::{Cohort, Global, SelfOwn};
        const TD: Plane<'static> = Plane::TransportDestination;
        assert_eq!(projection_for(TD, "self", ProducerSteward, false), SelfOwn);
        assert_eq!(
            projection_for(TD, "family", ProducerSteward, false),
            SelfOwn
        );
        assert_eq!(
            projection_for(TD, "community", ProducerSteward, false),
            Cohort
        );
        assert_eq!(
            projection_for(TD, "affiliations", ProducerSteward, false),
            Cohort
        );
        assert_eq!(
            projection_for(TD, "species", ProducerSteward, false),
            Cohort
        );
        assert_eq!(projection_for(TD, "species", AccordCoScrub, false), Cohort);
        assert_eq!(
            projection_for(TD, "biosphere", ProducerSteward, false),
            Cohort
        );
        assert_eq!(
            projection_for(TD, "biosphere", AccordCoScrub, false),
            Cohort
        );
        // federation keeps ✱ — infra's role is to be reachable.
        assert_eq!(
            projection_for(TD, "federation", AccordCoScrub, false),
            Global
        );
        assert_eq!(
            projection_for(TD, "federation", ProducerSteward, false),
            Cohort
        );
    }

    /// The full FountainContent row — the route row's logic at the bytes
    /// layer (advertisement ≠ availability). LITERALS.
    #[test]
    fn fountain_content_row_matches_the_decided_table() {
        use AuthorityClass::{AccordCoScrub, ProducerSteward};
        use Projection::{Cohort, Global, SelfOwn};
        const FC: Plane<'static> = Plane::FountainContent;
        assert_eq!(projection_for(FC, "self", ProducerSteward, false), SelfOwn);
        assert_eq!(
            projection_for(FC, "family", ProducerSteward, false),
            SelfOwn
        );
        assert_eq!(
            projection_for(FC, "community", ProducerSteward, false),
            Cohort
        );
        assert_eq!(
            projection_for(FC, "affiliations", ProducerSteward, false),
            Cohort
        );
        assert_eq!(projection_for(FC, "species", AccordCoScrub, false), Cohort);
        assert_eq!(
            projection_for(FC, "biosphere", AccordCoScrub, false),
            Cohort
        );
        // ✱ on federation so a canonical corpus is widely advertised.
        assert_eq!(
            projection_for(FC, "federation", AccordCoScrub, false),
            Global
        );
        assert_eq!(
            projection_for(FC, "federation", ProducerSteward, false),
            Cohort
        );
    }

    /// HardCaseEvent federation-scope is Cohort EVEN FOR A TRUST ROOT — the
    /// live row never widens past Cohort (a reputation directory is the
    /// analog of the presence directory, and arguably worse). The infra
    /// de-admission reach is the TOMBSTONE ceiling's, by role.
    #[test]
    fn hard_case_event_federation_is_cohort_even_for_trust_root() {
        assert_eq!(
            projection_for(
                Plane::HardCaseEvent,
                "federation",
                AuthorityClass::AccordCoScrub,
                false
            ),
            Projection::Cohort,
            "a live hard-case row must never gossip Global — not even trust-root-authored"
        );
    }

    /// The full HardCaseEvent row — LITERALS.
    #[test]
    fn hard_case_event_row_matches_the_decided_table() {
        use AuthorityClass::{AccordCoScrub, ProducerSteward};
        use Projection::{Cohort, SelfOwn};
        const HCE: Plane<'static> = Plane::HardCaseEvent;
        assert_eq!(projection_for(HCE, "self", ProducerSteward, false), SelfOwn);
        assert_eq!(
            projection_for(HCE, "family", ProducerSteward, false),
            SelfOwn
        );
        assert_eq!(
            projection_for(HCE, "community", ProducerSteward, false),
            Cohort
        );
        assert_eq!(
            projection_for(HCE, "affiliations", ProducerSteward, false),
            Cohort
        );
        assert_eq!(projection_for(HCE, "species", AccordCoScrub, false), Cohort);
        assert_eq!(
            projection_for(HCE, "biosphere", AccordCoScrub, false),
            Cohort
        );
        assert_eq!(
            projection_for(HCE, "federation", AccordCoScrub, false),
            Cohort
        );
        assert_eq!(
            projection_for(HCE, "federation", ProducerSteward, false),
            Cohort
        );
    }

    /// The consent:* row — the routing editor. LITERALS: live shape is
    /// SelfOwn | Cohort | Cohort | ✱-at-federation; its Global CEILING is
    /// witnessed separately.
    #[test]
    fn attestation_consent_row_matches_the_decided_table() {
        use AuthorityClass::{AccordCoScrub, ProducerSteward};
        use Projection::{Cohort, Global, SelfOwn};
        const CONSENT: Plane<'static> = Plane::Attestation {
            dimension: "consent:replication:v1",
        };
        assert_eq!(
            projection_for(CONSENT, "self", ProducerSteward, false),
            SelfOwn
        );
        assert_eq!(
            projection_for(CONSENT, "family", ProducerSteward, false),
            SelfOwn
        );
        assert_eq!(
            projection_for(CONSENT, "community", ProducerSteward, false),
            Cohort
        );
        assert_eq!(
            projection_for(CONSENT, "affiliations", ProducerSteward, false),
            Cohort
        );
        // species/biosphere stay Cohort even for a trust root — federation
        // is the ONLY ✱ cell.
        assert_eq!(
            projection_for(CONSENT, "species", AccordCoScrub, false),
            Cohort
        );
        assert_eq!(
            projection_for(CONSENT, "biosphere", AccordCoScrub, false),
            Cohort
        );
        assert_eq!(
            projection_for(CONSENT, "federation", AccordCoScrub, false),
            Global
        );
        assert_eq!(
            projection_for(CONSENT, "federation", ProducerSteward, false),
            Cohort
        );
    }

    /// THE capability cell (#713 server relay, E3): trace:* is
    /// capability-gated, NOT scope-gated. Community/affiliations stay
    /// SelfOwn (never widens by cohort), the commons tiers serve to the
    /// `infra:serve` set — for EVERY authority, a trust root included.
    /// LITERALS.
    #[test]
    fn attestation_trace_row_is_capability_gated_not_scope_gated() {
        use Projection::{Capability, SelfOwn};
        const TRACE: Plane<'static> = Plane::Attestation {
            dimension: "trace:complete:v1",
        };
        for a in AUTHORITIES {
            for s in ["self", "family", "community", "affiliations"] {
                assert_eq!(
                    projection_for(TRACE, s, a, false),
                    SelfOwn,
                    "trace {s}/{a:?} must stay SelfOwn — trace never widens by cohort"
                );
            }
            for s in ["species", "biosphere", "federation"] {
                assert_eq!(
                    projection_for(TRACE, s, a, false),
                    Capability(CapabilityToken::InfraServe),
                    "trace {s}/{a:?} serves to the infra:serve set ONLY — by role, not cohort"
                );
            }
            // An unrecognized scope resolves the community-tier cell.
            assert_eq!(
                projection_for(TRACE, "some-future-scope", a, false),
                SelfOwn,
                "{a:?}"
            );
        }
    }

    /// THE subject cell (CC#46): scores:* past `family` is the SUBJECT's
    /// grant at every scope, for every emitter authority — "a node can be
    /// fully consented for replication and still have no right to score
    /// you." LITERALS.
    #[test]
    fn attestation_scores_row_is_subject_gated_past_self() {
        use Projection::{SelfOwn, Subject};
        const SCORES: Plane<'static> = Plane::Attestation {
            dimension: "scores:medical",
        };
        for a in AUTHORITIES {
            assert_eq!(projection_for(SCORES, "self", a, false), SelfOwn, "{a:?}");
            assert_eq!(projection_for(SCORES, "family", a, false), SelfOwn, "{a:?}");
            for s in [
                "community",
                "affiliations",
                "species",
                "biosphere",
                "federation",
                "some-future-scope",
            ] {
                assert_eq!(
                    projection_for(SCORES, s, a, false),
                    Subject,
                    "scores {s}/{a:?} must be Subject — never a roster, never Global"
                );
            }
        }
    }

    /// v36.1.0 (#713, CIRISEdge adoption) — **the capability overlay is a
    /// FAMILY question and the projection is a FAMILY-AND-SCOPE answer; they
    /// are NOT interchangeable.**
    ///
    /// v36.0.0's adopt map told consumers to delete their
    /// `starts_with("trace:")` overlay and gate on
    /// `matches!(projection, Projection::Capability(_))`. That is unsafe:
    /// below the commons tiers the same family resolves `SelfOwn`, so the
    /// folded gate stops firing — and on a direct-fetch path E3 still
    /// requires `infra:serve`, so it is a hole, not a narrower advertisement.
    ///
    /// This pins the trap in both directions so nobody performs that fold
    /// later without a red in front of them, and pins that
    /// [`attestation_family`] IS scope-independent — the surface an overlay
    /// should actually key on.
    #[test]
    fn a_capability_overlay_keys_on_family_not_on_projection_713() {
        use AuthorityClass::{AccordCoScrub, ProducerSteward};
        let dim = "trace:reasoning:v1";
        let plane = Plane::Attestation { dimension: dim };

        // The family answer is scope-free — every scope, every authority.
        assert_eq!(attestation_family(dim), AttestationFamily::Trace);

        // The projection answer is NOT. This is the whole finding.
        for scope in ["self", "family", "community", "affiliations"] {
            assert_eq!(
                projection_for(plane, scope, ProducerSteward, false),
                Projection::SelfOwn,
                "trace:* below the commons is SelfOwn at {scope} — a gate folded \
                 onto Projection::Capability would STOP FIRING here, and E3 \
                 requires infra:serve even for a subject's own row"
            );
        }
        for scope in ["species", "biosphere", "federation"] {
            assert!(
                matches!(
                    projection_for(plane, scope, AccordCoScrub, false),
                    Projection::Capability(_)
                ),
                "trace:* is Capability only at the commons tiers ({scope})"
            );
        }

        // scores:* carries the identical coupling for a Subject overlay.
        let s = "scores:capacity:v1";
        assert_eq!(attestation_family(s), AttestationFamily::Scores);
        let splane = Plane::Attestation { dimension: s };
        assert_eq!(
            projection_for(splane, "family", ProducerSteward, false),
            Projection::SelfOwn,
            "scores:* at family is SelfOwn, not Subject — same trap"
        );
        assert_eq!(
            projection_for(splane, "community", ProducerSteward, false),
            Projection::Subject
        );
    }

    /// v36.2.0 (#713) — `accord:*` is `Global` UNCONDITIONALLY at the commons
    /// tiers, and specifically **not ✱**. LITERALS.
    ///
    /// The ✱ distinction is the whole point and the easy thing to get wrong
    /// by analogy with `KeyRecord` / `provenance:build_manifest:*`. A partial
    /// quorum object is emitted PRE-AUTHORITY and becomes the trust root's act
    /// only by aggregating, so ✱ would be a bootstrap paradox: it would need
    /// quorum to project widely and need to project widely to reach quorum.
    /// The non-trust-root assertions below are therefore the load-bearing
    /// ones — under ✱ they would read `Cohort` and the kill switch would be
    /// inoperable by construction, silently.
    #[test]
    fn accord_is_global_unconditionally_not_star_713() {
        use AuthorityClass::{AccordCoScrub, ProducerSteward};
        use Projection::{Cohort, Global, SelfOwn};
        let plane = Plane::Attestation {
            dimension: "accord:halt:v1",
        };
        assert_eq!(
            projection_for(plane, "self", ProducerSteward, false),
            SelfOwn
        );
        assert_eq!(
            projection_for(plane, "community", ProducerSteward, false),
            Cohort
        );
        for scope in ["species", "biosphere", "federation"] {
            for authority in [AccordCoScrub, ProducerSteward] {
                assert_eq!(
                    projection_for(plane, scope, authority, false),
                    Global,
                    "a partial from {authority:?} at {scope} must reach a roster whose cohort \
                     span is unknowable at emit time — under ✱ this reads Cohort for a \
                     non-root emitter and the quorum never assembles"
                );
            }
        }
        // The ceiling is unconditional too: a tombstone retracting a partial
        // must reach everywhere the partial could have assembled.
        assert_eq!(tombstone_ceiling(plane, ProducerSteward), Global);

        // The stem is `accord:` ONLY. Its reserved-prefix sibling stays
        // conservative until argued.
        let sibling = Plane::Attestation {
            dimension: "objection:tier5:v1",
        };
        assert_eq!(
            projection_for(sibling, "federation", ProducerSteward, false),
            Cohort,
            "objection:* is the undecided half of RESERVED_CLASS_DIMENSION_PREFIXES"
        );
    }

    /// v36.2.0 (#713) — `moderation:*` never widens past `Cohort`: the
    /// `HardCaseEvent` shape, because every live dimension is an adverse
    /// allegation about a party and Global gossip of those is a reputation
    /// directory. LITERALS.
    ///
    /// Same VALUE the conservative default gave, different STATUS — this row
    /// is argued. The assertions are identical either way, which is exactly
    /// why the distinction has to live in the doc and the CHANGELOG rather
    /// than in a test: no witness can tell "decided Cohort" from "defaulted
    /// Cohort".
    #[test]
    fn moderation_never_widens_past_cohort_713() {
        use AuthorityClass::{AccordCoScrub, ProducerSteward};
        use Projection::{Cohort, SelfOwn};
        for dim in [
            "moderation:rogue_action:v1",
            "moderation:harassment:v1",
            "moderation:conduct:v1",
            "moderation:tone:v1",
        ] {
            let plane = Plane::Attestation { dimension: dim };
            assert_eq!(
                projection_for(plane, "self", ProducerSteward, false),
                SelfOwn,
                "{dim}"
            );
            assert_eq!(
                projection_for(plane, "family", ProducerSteward, false),
                SelfOwn,
                "{dim}"
            );
            for scope in [
                "community",
                "affiliations",
                "species",
                "biosphere",
                "federation",
            ] {
                for authority in [AccordCoScrub, ProducerSteward] {
                    assert_eq!(
                        projection_for(plane, scope, authority, false),
                        Cohort,
                        "{dim} at {scope}/{authority:?}: an allegation about a party must not \
                         become a portable reputation record"
                    );
                }
            }
            // And the retraction does not travel further than the allegation
            // did — widening it would republish the allegation to parties who
            // never held it.
            assert_eq!(tombstone_ceiling(plane, AccordCoScrub), Cohort, "{dim}");
        }
    }

    /// v36.1.0 (#713) — `provenance:build_manifest:*` is ✱ at EVERY commons
    /// tier, not just federation. LITERALS.
    ///
    /// This is the row that v36.0.0 shipped under the conservative default,
    /// capping it at Cohort. Edge decided it back: its bundle gate
    /// (CIRISEdge#436/#437) admits a peer at `Rooted` only against a
    /// trust-root-blessed manifest, so a Cohort cap silently degrades
    /// cross-cohort first contact to `Advisory`.
    ///
    /// The species/biosphere cells are the whole point — they are what
    /// distinguish this row from the commons-health shape below, and they are
    /// where the narrowing bit. A witness that only checked `federation`
    /// would pass against the defaulted row and prove nothing.
    #[test]
    fn provenance_build_manifest_is_star_at_every_commons_tier_713() {
        use AuthorityClass::{AccordCoScrub, ProducerSteward};
        use Projection::{Cohort, Global, SelfOwn};
        let plane = Plane::Attestation {
            dimension: "provenance:build_manifest:v1",
        };
        assert_eq!(
            projection_for(plane, "self", ProducerSteward, false),
            SelfOwn
        );
        assert_eq!(
            projection_for(plane, "family", ProducerSteward, false),
            SelfOwn
        );
        assert_eq!(
            projection_for(plane, "community", AccordCoScrub, false),
            Cohort
        );
        // The three cells the default got wrong.
        for scope in ["species", "biosphere", "federation"] {
            assert_eq!(
                projection_for(plane, scope, AccordCoScrub, false),
                Global,
                "trust-root build manifest must reach the commons at {scope}"
            );
            assert_eq!(
                projection_for(plane, scope, ProducerSteward, false),
                Cohort,
                "the ✱ is the trust root's reach, not the family's, at {scope}"
            );
        }
        // The DEEPER stem earns the row; `provenance:*` broadly does not.
        // A family earns its row by being argued for, not by sharing a
        // namespace with one that was.
        let sibling = Plane::Attestation {
            dimension: "provenance:signature_chain:v1",
        };
        assert_eq!(
            projection_for(sibling, "species", AccordCoScrub, false),
            Cohort,
            "undecided provenance siblings stay on the conservative row"
        );
        // Ceiling is the row-max, not above it.
        assert_eq!(tombstone_ceiling(plane, AccordCoScrub), Global);
        assert_eq!(tombstone_ceiling(plane, ProducerSteward), Cohort);
    }

    /// capacity:* / content_class:* — the commons-health shape (self-report
    /// about own substrate / flags whose subject is the content): ✱ at
    /// federation only. LITERALS.
    #[test]
    fn attestation_capacity_and_content_class_rows_match_commons_health() {
        use AuthorityClass::{AccordCoScrub, ProducerSteward};
        use Projection::{Cohort, Global, SelfOwn};
        for dim in ["capacity:integrity", "content_class:violence"] {
            let plane = Plane::Attestation { dimension: dim };
            assert_eq!(
                projection_for(plane, "self", ProducerSteward, false),
                SelfOwn
            );
            assert_eq!(
                projection_for(plane, "family", ProducerSteward, false),
                SelfOwn
            );
            assert_eq!(
                projection_for(plane, "community", ProducerSteward, false),
                Cohort
            );
            assert_eq!(
                projection_for(plane, "affiliations", ProducerSteward, false),
                Cohort
            );
            assert_eq!(
                projection_for(plane, "species", AccordCoScrub, false),
                Cohort
            );
            assert_eq!(
                projection_for(plane, "biosphere", AccordCoScrub, false),
                Cohort
            );
            assert_eq!(
                projection_for(plane, "federation", AccordCoScrub, false),
                Global,
                "{dim}"
            );
            assert_eq!(
                projection_for(plane, "federation", ProducerSteward, false),
                Cohort,
                "{dim}"
            );
        }
    }

    /// The decided SubstrateSelf commons cells (#713 question 3): transport:*
    /// and the EXACT system:audit_chain:hash_continuity project Global at
    /// commons scopes for SubstrateSelf — real registry rows, no resolver
    /// special-casing. Other authorities keep the commons-health shape.
    /// LITERALS.
    #[test]
    fn attestation_substrate_self_commons_cells_are_global() {
        use AuthorityClass::{AccordCoScrub, ProducerSteward, SubstrateSelf};
        use Projection::{Cohort, Global, SelfOwn};
        for dim in ["transport:reticulum", "system:audit_chain:hash_continuity"] {
            let plane = Plane::Attestation { dimension: dim };
            assert_eq!(projection_for(plane, "self", SubstrateSelf, false), SelfOwn);
            assert_eq!(
                projection_for(plane, "community", SubstrateSelf, false),
                Cohort,
                "{dim}: commons means species+, not community"
            );
            for s in ["species", "biosphere", "federation"] {
                assert_eq!(
                    projection_for(plane, s, SubstrateSelf, false),
                    Global,
                    "{dim} {s}: the substrate's self-report about itself is federation-consumed"
                );
            }
            // Non-substrate authorities: the commons-health shape.
            assert_eq!(
                projection_for(plane, "species", ProducerSteward, false),
                Cohort
            );
            assert_eq!(
                projection_for(plane, "federation", ProducerSteward, false),
                Cohort
            );
            assert_eq!(
                projection_for(plane, "federation", AccordCoScrub, false),
                Global,
                "{dim}"
            );
        }
    }

    /// THE open-prefix refusal (#713 server relay): Global is earned by the
    /// VALUE `system:audit_chain:hash_continuity`, never by the `system:*`
    /// namespace. Any other system:* dimension — including a suffixed
    /// spelling of the blessed value — resolves the conservative default.
    #[test]
    fn system_prefix_never_inherits_global_only_the_exact_value_does() {
        use AuthorityClass::SubstrateSelf;
        use Projection::{Cohort, Global};
        assert_eq!(
            projection_for(
                Plane::Attestation {
                    dimension: "system:audit_chain:hash_continuity"
                },
                "federation",
                SubstrateSelf,
                false
            ),
            Global,
            "the exact co-signed dimension IS Global"
        );
        for dim in [
            "system:some_future:subject_carrying",
            "system:audit_chain:hash_continuity:v2",
            "system:audit_chain",
            "system:health",
        ] {
            for s in ["species", "biosphere", "federation"] {
                assert_eq!(
                    projection_for(
                        Plane::Attestation { dimension: dim },
                        s,
                        SubstrateSelf,
                        false
                    ),
                    Cohort,
                    "{dim} {s}: a system:* member must EARN Global, not inherit it"
                );
            }
        }
    }

    /// The conservative default: a dimension with no decided row — including
    /// families that EXIST but were not decided on #713 (provenance:*,
    /// moderation:*, trace_manifest:*, …) — never projects past Cohort, for
    /// ANY authority. The negative-default doctrine: a new family earns its
    /// commons reach by landing a decided row, and until then even a
    /// trust-root-authored record relays over its cohort.
    #[test]
    fn attestation_unknown_dimension_is_the_conservative_default() {
        use Projection::{Cohort, SelfOwn};
        for dim in [
            "ratchet:flag:out_of_distribution_voting",
            // v36.1.0 (#713) — `provenance:build_manifest:*` was HERE as an
            // undecided example until edge decided it back to ✱ (see
            // `provenance_build_manifest_is_star_at_every_commons_tier_713`).
            // Its undecided SIBLING replaces it, which is the stronger case
            // anyway: it pins that the DEEPER stem earned the row and the
            // namespace did not inherit it.
            "provenance:signature_chain:v1",
            // v36.2.0 (#713) — `moderation:harassment` was HERE until server
            // decided it: Cohort, ARGUED (same value, different status). Its
            // replacement is `objection:*`, the genuinely-undecided member of
            // the reserved-prefix pair — the co-scrub argument covers
            // `accord:` only.
            "objection:tier5:v1",
            "trace_manifest:v1", // trace-ADJACENT but not trace:* — undecided
            "capacity_assurance:rung_3", // capacity-ADJACENT but not capacity:*
            "brand_new_scoring_family:leaf",
        ] {
            let plane = Plane::Attestation { dimension: dim };
            for a in AUTHORITIES {
                assert_eq!(projection_for(plane, "self", a, false), SelfOwn, "{dim}");
                assert_eq!(projection_for(plane, "family", a, false), SelfOwn, "{dim}");
                for s in [
                    "community",
                    "affiliations",
                    "species",
                    "biosphere",
                    "federation",
                    "some-future-scope",
                ] {
                    assert_eq!(
                        projection_for(plane, s, a, false),
                        Cohort,
                        "{dim} {s}/{a:?}: an undecided family must never gossip past Cohort"
                    );
                }
            }
        }
    }

    /// The anti-rollback rule the OLD unconditional-Global tombstone was an
    /// over-approximation of, kept exactly on the plane whose row demands it:
    /// even a self-scoped KEY withdraw gossips GLOBAL, from any authority.
    #[test]
    fn key_record_tombstone_is_global_regardless() {
        for s in SCOPES {
            for a in AUTHORITIES {
                assert_eq!(
                    projection_for(Plane::KeyRecord, s, a, true),
                    Projection::Global,
                    "key tombstone {s}/{a:?} must be GLOBAL — verify-relevance is unbounded"
                );
            }
        }
    }

    /// THE narrowed ceiling cell (#713's single arbitrated trade): a NON-ROOT
    /// route tombstone projects Cohort, not Global — a Global withdrawal of a
    /// Cohort-scoped route would tell parties who never knew the route
    /// existed that it did.
    #[test]
    fn non_root_transport_destination_tombstone_is_cohort() {
        for s in SCOPES {
            for a in [
                AuthorityClass::SelfIdentity,
                AuthorityClass::SubstrateSelf,
                AuthorityClass::ProducerSteward,
            ] {
                assert_eq!(
                    projection_for(Plane::TransportDestination, s, a, true),
                    Projection::Cohort,
                    "non-root route tombstone {s}/{a:?} must stay Cohort"
                );
            }
        }
    }

    /// Residual 1, chosen on the thread: trust-root reachability tombstones
    /// stay Global — infra reachability is public by role and its withdrawal
    /// is operationally load-bearing for the whole mesh.
    #[test]
    fn trust_root_transport_destination_tombstone_is_global() {
        for s in ["self", "federation", "some-future-scope"] {
            assert_eq!(
                projection_for(
                    Plane::TransportDestination,
                    s,
                    AuthorityClass::AccordCoScrub,
                    true
                ),
                Projection::Global,
                "trust-root route tombstone at {s}"
            );
        }
    }

    /// FountainContent shares the route plane's ceiling: non-root Cohort,
    /// trust-root Global.
    #[test]
    fn fountain_content_tombstone_ceiling_follows_trust_root() {
        assert_eq!(
            projection_for(
                Plane::FountainContent,
                "self",
                AuthorityClass::ProducerSteward,
                true
            ),
            Projection::Cohort
        );
        assert_eq!(
            projection_for(
                Plane::FountainContent,
                "self",
                AuthorityClass::AccordCoScrub,
                true
            ),
            Projection::Global
        );
    }

    /// HardCaseEvent tombstones: Cohort for a non-infra authority (nobody who
    /// could not act on the case is told it existed), Global BY ROLE for the
    /// infra de-admission case — expressed via `is_trust_root`, the stated
    /// AuthorityClass approximation of "carries an infra role".
    #[test]
    fn hard_case_event_tombstone_is_global_only_for_infra_role() {
        for a in [
            AuthorityClass::SelfIdentity,
            AuthorityClass::SubstrateSelf,
            AuthorityClass::ProducerSteward,
        ] {
            assert_eq!(
                projection_for(Plane::HardCaseEvent, "federation", a, true),
                Projection::Cohort,
                "non-infra hard-case tombstone {a:?} must stay Cohort"
            );
        }
        assert_eq!(
            projection_for(
                Plane::HardCaseEvent,
                "federation",
                AuthorityClass::AccordCoScrub,
                true
            ),
            Projection::Global,
            "infra-role de-admission must be globally unlearnable"
        );
    }

    /// The consent:* ceiling — Global for every authority at every scope,
    /// the thread's decided above-row-max exception ("same anti-rollback
    /// logic as KeyRecord": the routing editor must reach any holder who
    /// might rely on it).
    #[test]
    fn consent_tombstone_is_global_regardless() {
        const CONSENT: Plane<'static> = Plane::Attestation {
            dimension: "consent:replication:v1",
        };
        for s in SCOPES {
            for a in AUTHORITIES {
                assert_eq!(
                    projection_for(CONSENT, s, a, true),
                    Projection::Global,
                    "consent tombstone {s}/{a:?}"
                );
            }
        }
    }

    /// The trace:* ceiling is the CAPABILITY set, not Global and not Cohort:
    /// copies only ever existed at the serve set, and a retraction gossiped
    /// wider would disclose that a trace existed to parties the trace never
    /// reached — the widening-discloses-more principle on the role axis.
    #[test]
    fn trace_tombstone_projects_to_the_serve_capability_set() {
        const TRACE: Plane<'static> = Plane::Attestation {
            dimension: "trace:complete:v1",
        };
        for s in SCOPES {
            for a in AUTHORITIES {
                assert_eq!(
                    projection_for(TRACE, s, a, true),
                    Projection::Capability(CapabilityToken::InfraServe),
                    "trace tombstone {s}/{a:?}"
                );
            }
        }
    }

    /// The scores:* ceiling is the SUBJECT: past self, only the subject's
    /// grant ever held a copy.
    #[test]
    fn scores_tombstone_projects_to_the_subject() {
        const SCORES: Plane<'static> = Plane::Attestation {
            dimension: "scores:medical",
        };
        for s in SCOPES {
            for a in AUTHORITIES {
                assert_eq!(
                    projection_for(SCORES, s, a, true),
                    Projection::Subject,
                    "scores tombstone {s}/{a:?}"
                );
            }
        }
    }

    /// capacity:* / content_class:* ceilings take the row-max (✱ at
    /// federation): Global for a trust root, Cohort otherwise.
    #[test]
    fn capacity_and_content_class_tombstones_follow_trust_root() {
        for dim in ["capacity:integrity", "content_class:violence"] {
            let plane = Plane::Attestation { dimension: dim };
            assert_eq!(
                projection_for(plane, "self", AuthorityClass::ProducerSteward, true),
                Projection::Cohort,
                "{dim}"
            );
            assert_eq!(
                projection_for(plane, "self", AuthorityClass::AccordCoScrub, true),
                Projection::Global,
                "{dim}"
            );
        }
    }

    /// The substrate-health ceiling: Global for SubstrateSelf (whose live
    /// commons cells are Global) and for a trust root (✱ at federation);
    /// Cohort for everyone else.
    #[test]
    fn substrate_health_tombstone_is_global_for_substrate_self_and_infra() {
        for dim in ["transport:reticulum", "system:audit_chain:hash_continuity"] {
            let plane = Plane::Attestation { dimension: dim };
            assert_eq!(
                projection_for(plane, "self", AuthorityClass::SubstrateSelf, true),
                Projection::Global,
                "{dim}"
            );
            assert_eq!(
                projection_for(plane, "self", AuthorityClass::AccordCoScrub, true),
                Projection::Global,
                "{dim}"
            );
            for a in [
                AuthorityClass::SelfIdentity,
                AuthorityClass::ProducerSteward,
            ] {
                assert_eq!(
                    projection_for(plane, "self", a, true),
                    Projection::Cohort,
                    "{dim}/{a:?}"
                );
            }
        }
    }

    /// An undecided family's ceiling stays Cohort for EVERY authority — a
    /// trust root included: no copy of it could ever have traveled wider, and
    /// a wider retraction would disclose more than the original fact.
    #[test]
    fn unknown_dimension_tombstone_stays_cohort_even_for_trust_root() {
        const UNKNOWN: Plane<'static> = Plane::Attestation {
            dimension: "ratchet:flag:out_of_distribution_voting",
        };
        for s in SCOPES {
            for a in AUTHORITIES {
                assert_eq!(
                    projection_for(UNKNOWN, s, a, true),
                    Projection::Cohort,
                    "unknown-family tombstone {s}/{a:?}"
                );
            }
        }
    }

    /// THE CEILING DOMINATES THE ROW (#713's stated invariant: "anti-rollback
    /// holds within the record's maximal disclosure set; beyond it there is
    /// no copy to roll back"). For every (plane, authority) — the Attestation
    /// plane fanned across every decided dimension family AND the
    /// conservative default — the tombstone ceiling must dominate every LIVE
    /// cell in that row, over the seven closed scopes and the
    /// unrecognized-scope default, or a tombstone could fail to reach a
    /// holder a live version legitimately reached.
    ///
    /// Domination is a PARTIAL order on purpose: `Global` reaches everyone
    /// and everything reaches the record's own node (`SelfOwn`), but
    /// `Capability` (role-keyed), `Subject` (subject-keyed) and `Cohort`
    /// (roster-keyed) select by different axes and are deliberately
    /// incomparable — a row whose ceiling and live cells sat on different
    /// axes would be a registry bug this test should refuse, not reconcile
    /// with an invented total order.
    ///
    /// This test reads the registry ON PURPOSE: it is a property OVER the
    /// table, not a per-cell expectation derived FROM it (those are the
    /// literal row tests above).
    #[test]
    fn tombstone_ceiling_dominates_every_live_cell() {
        fn dominates(ceiling: Projection, live: Projection) -> bool {
            ceiling == live
                || matches!(ceiling, Projection::Global)
                || matches!(live, Projection::SelfOwn)
        }
        for plane in all_planes() {
            for authority in AUTHORITIES {
                let ceiling = tombstone_ceiling(plane, authority);
                for s in SCOPES {
                    let live = projection_for(plane, s, authority, false);
                    assert!(
                        dominates(ceiling, live),
                        "{plane:?}/{authority:?}: ceiling {ceiling:?} does not dominate the live \
                         cell {live:?} at scope {s:?} — a tombstone would starve a holder a live \
                         version reached (anti-rollback broken); stop and re-read #713 rather \
                         than reconciling silently"
                    );
                }
                // And the resolver's tombstone arm IS the ceiling — the two
                // functions cannot drift apart.
                assert_eq!(
                    projection_for(plane, "self", authority, true),
                    ceiling,
                    "{plane:?}/{authority:?}: projection_for(is_tombstone) must BE the ceiling"
                );
            }
        }
    }

    /// The explicit fetch-kind → projection-plane bridge: LITERAL cells. The
    /// occurrence kinds ride the KeyRecord row (behavior-preserving; the
    /// thread did not re-decide them).
    #[test]
    fn replicated_kind_maps_onto_the_projection_planes() {
        assert_eq!(
            ReplicatedKind::KeyRecord.projection_plane(),
            ObjectClass::KeyRecord
        );
        assert_eq!(
            ReplicatedKind::IdentityOccurrence.projection_plane(),
            ObjectClass::KeyRecord
        );
        assert_eq!(
            ReplicatedKind::IdentityOccurrenceRevocation.projection_plane(),
            ObjectClass::KeyRecord
        );
        assert_eq!(
            ReplicatedKind::TransportDestination.projection_plane(),
            ObjectClass::TransportDestination
        );
        assert_eq!(
            ReplicatedKind::Attestation.projection_plane(),
            ObjectClass::Attestation
        );
    }

    #[test]
    fn unknown_scope_is_conservative_relay_never_global() {
        // On EVERY plane, even for a trust root, an unrecognized scope
        // resolves the family's bounded community-tier cell — a future scope
        // never silently GLOBAL-gossips, on any dimension family. LITERAL
        // expectations per plane: Cohort everywhere except the two families
        // whose community tier is narrower than a roster (trace:* → SelfOwn,
        // scores:* → Subject).
        for plane in all_planes() {
            let expected = match plane {
                Plane::Attestation {
                    dimension: "trace:complete:v1",
                } => Projection::SelfOwn,
                Plane::Attestation {
                    dimension: "scores:medical",
                } => Projection::Subject,
                _ => Projection::Cohort,
            };
            assert_eq!(
                projection_for(
                    plane,
                    "some-future-scope",
                    AuthorityClass::AccordCoScrub,
                    false
                ),
                expected,
                "{plane:?}"
            );
        }
    }

    /// The [`ObjectClass`] ↔ [`Plane`] coupling, held by the COMPILER in the
    /// direction [`Plane::class`] cannot: this match is exhaustive over
    /// `ObjectClass`, so a new object class fails to compile HERE until its
    /// projection plane is named — the #713 "a new plane is a registry row,
    /// not a silently-inherited default" property, preserved across the
    /// v36.0.0 split of the two enums.
    #[test]
    fn every_object_class_has_a_projection_plane() {
        for class in ObjectClass::ALL {
            let plane = match class {
                ObjectClass::KeyRecord => Plane::KeyRecord,
                ObjectClass::TransportDestination => Plane::TransportDestination,
                ObjectClass::FountainContent => Plane::FountainContent,
                ObjectClass::HardCaseEvent => Plane::HardCaseEvent,
                ObjectClass::Attestation => Plane::Attestation {
                    dimension: "consent:replication:v1",
                },
            };
            assert_eq!(plane.class(), class);
        }
    }

    /// The capability token is the EXISTING delegation-scope constant — by
    /// value here (the literal, per witness discipline) and by const identity
    /// (no second spelling minted anywhere between the variant and the
    /// token).
    #[test]
    fn capability_token_is_the_existing_delegation_scope_constant() {
        assert_eq!(CapabilityToken::InfraServe.as_scope(), "infra:serve");
        assert_eq!(
            CapabilityToken::InfraServe.as_scope(),
            crate::federation::types::delegation_scope::INFRA_SERVE
        );
    }

    /// The wire form of the new audience kinds pins the SAME spelling — a
    /// serialized `Capability` carries the delegation-scope token verbatim,
    /// not a re-cased enum name (the CIRISEdge#379 bare-"observer" class,
    /// closed at the serde layer too).
    #[test]
    fn projection_wire_form_pins_the_token_spelling() {
        assert_eq!(
            serde_json::to_value(Projection::Capability(CapabilityToken::InfraServe)).unwrap(),
            serde_json::json!({ "capability": "infra:serve" })
        );
        assert_eq!(
            serde_json::to_value(Projection::Subject).unwrap(),
            serde_json::json!("subject")
        );
        assert_eq!(
            serde_json::to_value(Projection::SelfOwn).unwrap(),
            serde_json::json!("self_own")
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

/// v30.12.0 (CIRISPersist#635) — **may the DATA-SUBJECT of a row carrying this
/// `dimension` retain a copy on its own node?**
///
/// `true` only for families where the subject is NECESSARILY the author.
/// Everything else — including every dimension this build has never heard of —
/// is `false`.
///
/// # The hole this closes
///
/// CIRISEdge#462's subject-scoped RECEIVE-axis pull lets a fedID pull its own
/// testimony onto a fresh node. Serving a peer-authored score *about* the
/// subject onto the node where that subject is the **sole writer** conflates a
/// read-copy with write-authority — the shape that produced the **G2
/// self-revocation hole**. Edge carved it out with a local prefix denylist
/// (`capacity:` / `capacity_assurance:` / `moderation:`), which silently
/// re-opens G2 the moment a scoring family lands persist-side and not
/// edge-side. The taxonomy is persist's, so the predicate is persist's.
///
/// # Why an ALLOWLIST, and why the manifest does not decide this at runtime
///
/// A denylist defaults a NEW family to retainable — which is the very drift
/// this replaces, just relocated into persist. So the runtime answer comes
/// from [`SUBJECT_RETAINABLE_FAMILIES`] and nothing else: an unclassified
/// family, a renamed family and an unknown dimension all read `false`. That is
/// the same fail-secure posture
/// [`LoadBearing::treated_as_load_bearing`](crate::federation::load_bearing::LoadBearing::treated_as_load_bearing)
/// takes — only a proven `No` is a `No`.
///
/// The manifest DOES record the authorship fact, in `emit_authority`, but as
/// prose: *"self-emission MANDATORY (attesting_key_id in subject_key_ids)"*,
/// *"scored-by-canonical (reserved: attesting_key_id != attested…)"*,
/// *"witness-reserved; attester not in {subject, …}"*. Deriving a security
/// predicate by string-matching English would be an inference dressed as a
/// rule. So prose is read by a TEST — `manifest_self_emission_families_are_all_retainable`
/// — which fails the build when the manifest gains a self-emission family this
/// list does not name. The runtime decision stays explicit; the manifest is
/// the alarm, not the authority.
///
/// # Orthogonal to the sender axis
///
/// A score I AUTHORED is mine to recover. This predicate is consulted only on
/// the data-subject axis.
#[must_use]
pub fn is_subject_retainable(dimension: &str) -> bool {
    crate::federation::load_bearing::family_for_dimension(dimension).is_some_and(|family| {
        SUBJECT_RETAINABLE_FAMILIES
            .iter()
            .any(|(f, _)| *f == family)
    })
}

/// The families a data-subject may retain about itself, with the manifest
/// `emit_authority` clause that justifies each. Every entry is a family whose
/// author is necessarily the subject, so a retained copy conveys no authority
/// the subject did not already hold.
///
/// Adding an entry is a security decision: it says "a node where this subject
/// is the sole writer may hold this row." Removing one is always safe.
pub const SUBJECT_RETAINABLE_FAMILIES: &[(&str, &str)] = &[
    (
        "trace:*",
        "emit_authority: self-emission MANDATORY (attesting_key_id in subject_key_ids)",
    ),
    (
        "trace_manifest:*",
        "emit_authority: self-emission MANDATORY (inherited from trace:*)",
    ),
    (
        "identity_continuity:relational_anchor",
        "emit_authority: substrate-self-report (the substrate instance itself)",
    ),
    (
        "transport:{kind}",
        "emit_authority: substrate-self-report (the transport-delivery component)",
    ),
    // The drift alarm found these three on its first run — which is the
    // argument for having it. All three are CC 3.4.3 substrate-self-reports:
    // the node is the author, so a retained copy conveys no authority it did
    // not already hold. They are node-plane rather than fedID-plane, so a
    // subject-scoped pull will rarely match them; that is a reason they were
    // easy to miss, not a reason to withhold them.
    (
        "audit_chain:hash_continuity",
        "emit_authority: canonical (substrate-self-report per CC 3.4.3)",
    ),
    (
        "corpus_health:n_eff_measurable",
        "emit_authority: substrate-self-report (CIRISPersist only; reserved per CC 3.4.3)",
    ),
    (
        "federation_directory:replication_lag",
        "emit_authority: substrate-self-report (the reporting node/replica itself, per CC 3.4.3)",
    ),
];

#[cfg(test)]
mod subject_retainability_tests {
    use super::*;

    /// The three prefixes CIRISEdge#462 currently denies locally must all be
    /// refused here, or persist has not actually taken ownership of the carve.
    #[test]
    fn edges_denylist_is_covered() {
        for dim in [
            "capacity:composite",
            "capacity:integrity",
            "capacity_assurance:rung_3",
            "moderation:harassment",
        ] {
            assert!(
                !is_subject_retainable(dim),
                "{dim} is peer-authored about the subject; retaining it on the subject's own \
                 node is the G2 shape"
            );
        }
    }

    /// Self-authored testimony IS retainable — otherwise the predicate is
    /// vacuously safe and edge's pull returns nothing.
    #[test]
    fn self_emitted_testimony_is_retainable() {
        for dim in [
            "trace:complete:v1",
            "trace_manifest:v1",
            "identity_continuity:relational_anchor",
        ] {
            assert!(
                is_subject_retainable(dim),
                "{dim} is self-emitted; refusing it would empty the RECEIVE-axis pull"
            );
        }
    }

    /// Fail-CLOSED: a dimension this build has never heard of is NOT
    /// retainable. The issue asks for this explicitly, and it is what makes an
    /// allowlist an allowlist.
    #[test]
    fn unknown_dimensions_are_not_retainable() {
        for dim in [
            "capacity:some_future_metric_we_have_not_seen",
            "brand_new_scoring_family:leaf",
            "",
            "::",
            "trace",
        ] {
            assert!(
                !is_subject_retainable(dim),
                "{dim:?} resolved to retainable — an allowlist that admits the unknown is a \
                 denylist wearing a costume"
            );
        }
    }

    /// THE DRIFT ALARM. The manifest records authorship in `emit_authority`
    /// prose; this test reads that prose so the runtime predicate never has to.
    /// A manifest family that MANDATES self-emission and is missing from
    /// `SUBJECT_RETAINABLE_FAMILIES` fails the build — that is the "new family
    /// lands persist-side" case #635 was filed about, caught at the taxonomy
    /// rather than at a consumer.
    ///
    /// Note the direction: this can only ever ask for a family to be ADDED.
    /// It cannot silently make something retainable, because the runtime
    /// answer is the const list and nothing else.
    #[test]
    fn manifest_self_emission_families_are_all_retainable() {
        let listed: Vec<&str> = SUBJECT_RETAINABLE_FAMILIES
            .iter()
            .map(|(f, _)| *f)
            .collect();
        let mut missing = Vec::new();
        for (family, emit) in supersets::family_emit_authorities() {
            let lower = emit.to_ascii_lowercase();
            let self_emitted = lower.contains("self-emission mandatory")
                || lower.contains("substrate-self-report");
            if self_emitted && !listed.contains(&family) {
                missing.push(format!("{family}  ({emit})"));
            }
        }
        assert!(
            missing.is_empty(),
            "manifest families mandate self-emission but are absent from \
             SUBJECT_RETAINABLE_FAMILIES: {missing:#?}\n\
             Either add them (the subject is necessarily the author, so a retained copy conveys \
             no new authority) or record why they are still withheld."
        );
        assert!(
            !listed.is_empty(),
            "the allowlist is empty — every pull would return nothing"
        );
    }

    /// Every allowlisted family must actually exist in the vendored manifest.
    /// A typo would silently withhold rows forever, and a fail-CLOSED default
    /// makes that invisible — nothing errors, the pull just quietly shrinks.
    #[test]
    fn allowlisted_families_exist_in_the_manifest() {
        let declared = supersets::family_prefixes();
        for (family, _) in SUBJECT_RETAINABLE_FAMILIES {
            assert!(
                declared.contains(family),
                "SUBJECT_RETAINABLE_FAMILIES names {family:?}, which the manifest does not \
                 declare — a typo here withholds rows silently, because unknown is refused"
            );
        }
    }
}

/// v37.1.0 (CIRISPersist#744) — **the recipient-set axis**, both directions
/// and both ways of failing to know.
///
/// Every expectation below is a HAND-WRITTEN LITERAL. Nothing here derives an
/// expected verdict from [`resolve_projection_recipients`],
/// [`projection_for`] or [`holdings_authority`]; a list computed from the code
/// it checks asserts nothing about that code.
#[cfg(test)]
mod recipient_set_tests {
    use super::*;
    use crate::federation::FederationDirectory;
    use crate::store::memory::MemoryBackend;

    /// Register `key_id` as a plain `node` with its deterministic hybrid
    /// pubkeys — the ordinary, unprivileged publisher/peer of these witnesses.
    /// Nothing here confers a role: a `node` is descriptive and unlocks
    /// nothing (`AUTHORITY_CONFERRING_IDENTITY_TYPES` deliberately omits it).
    async fn register_node(dir: &dyn FederationDirectory, key_id: &str) {
        let (ed_pk, mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(key_id);
        let now = chrono::Utc::now();
        let rec = crate::federation::types::KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: crate::federation::types::identity_type::NODE.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": key_id }),
            original_content_hash: "deadbeef".to_owned(),
            scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        dir.put_public_key(crate::federation::types::SignedKeyRecord { record: rec })
            .await
            .expect("a plain node registration is admissible");
    }

    /// The #744 fixture: a family whose roster seats exactly `PUBLISHER` and
    /// `SEATED`, plus a registered `STRANGER` who is on no roster. Returns the
    /// backend.
    async fn holdings_fixture() -> MemoryBackend {
        let backend = MemoryBackend::new();
        for who in [PUBLISHER, SEATED, STRANGER] {
            register_node(&backend, who).await;
        }
        crate::federation::operational::test_support::seed_test_family(
            &backend,
            FAMILY,
            &[PUBLISHER.to_owned(), SEATED.to_owned()],
            "quorum:2/3",
        )
        .await
        .expect("seed the holding's own family");
        backend
    }

    const FAMILY: &str = "recipients-744-family";
    const PUBLISHER: &str = "recipients-744-publisher";
    const SEATED: &str = "recipients-744-seated";
    const STRANGER: &str = "recipients-744-stranger";

    /// **Direction 1** — a peer IN the resolved set is eligible.
    ///
    /// `family` scope on the holdings plane resolves [`Projection::SelfOwn`],
    /// and `SelfOwn`'s recipient set is the record's own roster. A seated
    /// member is on it.
    #[tokio::test]
    async fn a_roster_peer_is_an_eligible_recipient_of_a_family_scoped_holding() {
        let backend = holdings_fixture().await;
        let v = resolve_projection_recipients(
            &backend,
            Plane::FountainContent,
            "family",
            AuthorityClass::ProducerSteward,
            false,
            FAMILY,
            SEATED,
        )
        .await
        .expect("the verb never returns Err today");
        assert_eq!(
            v.basis,
            RecipientBasis::OwnRoster,
            "SelfOwn is roster-bounded"
        );
        assert!(
            v.set_resolvable,
            "this node holds the family, so it can judge"
        );
        assert!(
            v.peer_in_set,
            "a seated member is in the record's own roster"
        );
        assert!(v.may_advertise(), "a roster peer may be told we hold it");
    }

    /// **Direction 2, AND THE PLANE-SPECIFIC POINT.** A `SelfOwn` holdings
    /// record must NOT be advertisable to a non-roster peer **even though this
    /// node produced it**.
    ///
    /// This is the exact vacuity CIRISEdge hit: the swarm publisher is always
    /// the producer of its own holdings, so *"advertise iff this node produced
    /// it"* — the correct reading of `SelfOwn` on the ATTESTATION plane —
    /// admits a family-scoped holding to every peer and closes nothing. A
    /// witness that only tested the attestation-plane reading would PASS
    /// against the broken behaviour, so this one deliberately makes the
    /// publisher the record's own producer and still requires a refusal.
    #[tokio::test]
    async fn a_self_own_holding_is_withheld_from_a_non_roster_peer_even_though_this_node_produced_it(
    ) {
        let backend = holdings_fixture().await;
        // PUBLISHER is on the roster: it is unambiguously the producer of its
        // own holdings, which is what makes the producer predicate vacuous.
        let producer_is_seated = resolve_projection_recipients(
            &backend,
            Plane::FountainContent,
            "family",
            AuthorityClass::ProducerSteward,
            false,
            FAMILY,
            PUBLISHER,
        )
        .await
        .expect("no Err");
        assert!(
            producer_is_seated.may_advertise(),
            "the trap must be reachable — if nothing were advertisable here, the \
             refusal below would prove nothing"
        );

        let v = resolve_projection_recipients(
            &backend,
            Plane::FountainContent,
            "family",
            AuthorityClass::ProducerSteward,
            false,
            FAMILY,
            STRANGER,
        )
        .await
        .expect("no Err");
        assert_eq!(v.basis, RecipientBasis::OwnRoster);
        assert!(
            v.set_resolvable,
            "the roster resolved — this is a JUDGED refusal, not an unknown"
        );
        assert!(
            !v.peer_in_set,
            "a stranger is not on the record's own roster"
        );
        assert!(
            !v.may_advertise(),
            "SelfOwn bounds the RECIPIENT SET, not only the advertiser — a \
             family-scoped holding must not be announced to a peer with no \
             business knowing it exists, however produced it"
        );
    }

    /// **The third answer.** An unresolvable group fails closed AND stays
    /// distinguishable from *"resolved, and this peer is not a member"*.
    ///
    /// Both refuse. An operator debugging a withheld advertisement needs to
    /// know which, and a substrate reporting the second when it means the
    /// first is claiming knowledge it does not have.
    #[tokio::test]
    async fn an_unresolvable_group_fails_closed_and_is_distinguishable_from_not_a_member() {
        let backend = holdings_fixture().await;

        let unknown_group = resolve_projection_recipients(
            &backend,
            Plane::FountainContent,
            "family",
            AuthorityClass::ProducerSteward,
            false,
            "recipients-744-family-this-node-never-heard-of",
            SEATED,
        )
        .await
        .expect("no Err");
        assert!(
            !unknown_group.set_resolvable,
            "a family this node holds no roster for is I-CANNOT-JUDGE"
        );
        assert_eq!(unknown_group.basis, RecipientBasis::GroupUnresolvable);
        assert!(!unknown_group.may_advertise(), "fail closed");

        let not_a_member = resolve_projection_recipients(
            &backend,
            Plane::FountainContent,
            "family",
            AuthorityClass::ProducerSteward,
            false,
            FAMILY,
            STRANGER,
        )
        .await
        .expect("no Err");
        assert!(
            not_a_member.set_resolvable,
            "the roster resolved — this refusal is JUDGED"
        );
        assert_eq!(not_a_member.basis, RecipientBasis::OwnRoster);
        assert!(!not_a_member.may_advertise(), "fail closed");

        assert_ne!(
            unknown_group, not_a_member,
            "COLLAPSING these two is the defect this test exists for: \
             `cannot judge` and `judged, not seated` are different facts and \
             must not be reported with the same verdict"
        );
    }

    /// The `self` tier's roster is the subject's identity OCCURRENCES, and an
    /// unregistered identity has none — `Ok(vec![])`, not an error. Without
    /// the existence pre-check that reads as *"resolved, and the roster is
    /// empty"*, which is the same collapse one tier down.
    #[tokio::test]
    async fn a_self_scoped_holding_for_an_unregistered_subject_cannot_be_judged() {
        let backend = holdings_fixture().await;
        let v = resolve_projection_recipients(
            &backend,
            Plane::FountainContent,
            "self",
            AuthorityClass::ProducerSteward,
            false,
            "recipients-744-never-registered",
            SEATED,
        )
        .await
        .expect("no Err");
        assert!(
            !v.set_resolvable,
            "an unregistered subject is I-CANNOT-JUDGE, never an empty roster"
        );
        assert_eq!(v.basis, RecipientBasis::GroupUnresolvable);
        assert!(!v.may_advertise(), "fail closed");
    }

    /// **No scope-address table ⇒ withhold.** `species` / `biosphere` /
    /// `federation` (and any scope this build has never heard of) project
    /// `Cohort` for a plain producer, but persist holds no roster table for
    /// them and the scope-address table is gated on CIRISVerify#259. The
    /// answer with no table is *"I cannot judge"*, and the fail-closed
    /// consequence is that nobody is told.
    #[tokio::test]
    async fn a_commons_scope_has_no_roster_table_and_withholds() {
        let backend = holdings_fixture().await;
        for scope in ["species", "biosphere", "federation", "some-future-scope"] {
            let v = resolve_projection_recipients(
                &backend,
                Plane::FountainContent,
                scope,
                AuthorityClass::ProducerSteward,
                false,
                FAMILY,
                SEATED,
            )
            .await
            .expect("no Err");
            assert_eq!(
                v.basis,
                RecipientBasis::NoRosterForScope,
                "{scope}: persist holds roster tables for self/family/community/\
                 affiliations and nothing else"
            );
            assert!(
                !v.set_resolvable,
                "{scope}: unresolved is unresolved — NOT 'every peer'"
            );
            assert!(!v.may_advertise(), "{scope}: fail closed");
        }
    }

    /// A [`Projection::Global`] record reaches the whole federation, so the
    /// set IS resolved and every peer is in it — including one on no roster.
    /// If this cell withheld, a trust root's canonical corpus would stop
    /// advertising, which is the opposite failure.
    #[tokio::test]
    async fn a_global_projection_admits_every_peer_unbounded() {
        let backend = holdings_fixture().await;
        let v = resolve_projection_recipients(
            &backend,
            Plane::FountainContent,
            "federation",
            AuthorityClass::AccordCoScrub,
            false,
            FAMILY,
            STRANGER,
        )
        .await
        .expect("no Err");
        assert_eq!(v.basis, RecipientBasis::Unbounded);
        assert!(v.set_resolvable && v.peer_in_set);
        assert!(v.may_advertise(), "Global bounds nobody out");
    }

    /// v38.0.0 (CIRISPersist#746) — **a scope-address-table id is refused BY
    /// NAME, never answered as an unknown group.** Edge's
    /// `ContentScope::Group` carries `cohort:{community_id}` /
    /// `av-stream:{hex}` — a different id space than the federation
    /// directory key this verb's contract names. Before this cut, feeding
    /// one through yielded a confident `GroupUnresolvable` for a peer that
    /// may well be SEATED on the real roster — the false-authoritative
    /// wildcard the verb's signature exists to prevent. Now the refusal
    /// names the actual problem, and the roster is never consulted (a
    /// prefix that ROUTED to a table would be axis fusion; a prefix that
    /// refuses is a typed error).
    #[tokio::test]
    async fn a_table_id_is_refused_by_name_not_answered_as_unknown_746() {
        let backend = holdings_fixture().await;
        for table_id in [format!("cohort:{FAMILY}"), "av-stream:deadbeef".to_owned()] {
            let v = resolve_projection_recipients(
                &backend,
                Plane::FountainContent,
                "community",
                AuthorityClass::ProducerSteward,
                false,
                &table_id,
                SEATED,
            )
            .await
            .expect("no Err");
            assert_eq!(
                v.basis,
                RecipientBasis::GroupIdNotFederationKeyed,
                "{table_id}: the wrong id space must be named, not shrugged at"
            );
            assert!(
                !v.set_resolvable,
                "{table_id}: cannot judge is not resolved"
            );
            assert!(!v.may_advertise(), "{table_id}: and it still fails closed");
        }
        // The control: the REAL federation key resolves exactly as before —
        // the refusal is about the id space, not about the group.
        let v = resolve_projection_recipients(
            &backend,
            Plane::FountainContent,
            "federation",
            AuthorityClass::AccordCoScrub,
            false,
            FAMILY,
            STRANGER,
        )
        .await
        .expect("no Err");
        assert_ne!(v.basis, RecipientBasis::GroupIdNotFederationKeyed);
    }

    /// Role-keyed and subject-keyed audiences are NOT roster questions. The
    /// verb says so explicitly rather than answering with a roster — and it
    /// still refuses, so a consumer that ignores the basis cannot over-share.
    #[tokio::test]
    async fn capability_and_subject_audiences_are_not_roster_keyed() {
        let backend = holdings_fixture().await;
        for (dimension, scope) in [
            ("trace:complete:v1", "species"),
            ("scores:medical", "community"),
        ] {
            let v = resolve_projection_recipients(
                &backend,
                Plane::Attestation { dimension },
                scope,
                AuthorityClass::ProducerSteward,
                false,
                FAMILY,
                SEATED,
            )
            .await
            .expect("no Err");
            assert_eq!(
                v.basis,
                RecipientBasis::NotRosterKeyed,
                "{dimension} @ {scope}: the audience is a role / a subject grant"
            );
            assert!(
                !v.may_advertise(),
                "{dimension} @ {scope}: not-this-verb's-question still refuses"
            );
        }
    }
}

/// v37.1.0 (CIRISPersist#744 item 2) — **the holdings seam's declared
/// authority.** A trust-root corpus and a producer corpus must reach
/// DIFFERENT projections, or the input is decorative.
#[cfg(test)]
mod holdings_authority_tests {
    use super::*;
    use crate::federation::FederationDirectory;
    use crate::store::memory::MemoryBackend;

    /// The baked genesis canonical — an accord-co-scrubbed trust root that
    /// admits through the ordinary `check_canonical_role_admission` gate, so
    /// nothing here fabricates conferral.
    async fn seeded_canonical() -> (MemoryBackend, String) {
        let backend = MemoryBackend::new();
        backend
            .seed_genesis_accord_holders(crate::federation::genesis::accord_holder_genesis_records())
            .await
            .expect("holders seed");
        crate::federation::genesis::seed_family_and_canonical(&backend)
            .await
            .expect("a fresh node seeds the baked plane");
        let canonical = crate::federation::genesis::canonical_genesis_bundle().serve_nodes[0]
            .record
            .key_id
            .clone();
        (backend, canonical)
    }

    /// THE ITEM-2 WITNESS. Same plane, same scope, same corpus — two
    /// publishers, two projections. If these matched, the authority input
    /// would be decorative and edge's `ProducerSteward` default would cost
    /// nothing to keep.
    #[tokio::test]
    async fn a_trust_root_corpus_and_a_producer_corpus_reach_different_projections() {
        let (backend, canonical) = seeded_canonical().await;

        let root = holdings_authority(&backend, &canonical)
            .await
            .expect("resolve the seam");
        assert_eq!(
            root,
            AuthorityClass::AccordCoScrub,
            "the baked canonical publisher IS accord-co-scrubbed"
        );

        let plain = holdings_authority(&backend, "holdings-744-plain-producer")
            .await
            .expect("resolve the seam");
        assert_eq!(
            plain,
            AuthorityClass::ProducerSteward,
            "an unregistered publisher takes the negative default — which never \
             widens a cell, so it is the fail-closed answer"
        );

        // The point of the seam: the two reach different projections.
        assert_eq!(
            projection_for(Plane::FountainContent, "federation", root, false),
            Projection::Global,
            "a trust root's federation-scoped corpus gossips to the commons"
        );
        assert_eq!(
            projection_for(Plane::FountainContent, "federation", plain, false),
            Projection::Cohort,
            "a plain producer's does not"
        );
    }

    /// Withdrawal wins, inherited from `is_trust_root`'s `_effective` reads
    /// (#685). A quorum-withdrawn canonical publisher demotes on the very next
    /// resolution — its corpus stops gossiping globally with no cache to
    /// invalidate.
    #[tokio::test]
    async fn a_withdrawn_canonical_publisher_stops_being_a_trust_root_corpus() {
        let (backend, canonical) = seeded_canonical().await;
        assert_eq!(
            holdings_authority(&backend, &canonical)
                .await
                .expect("seam"),
            AuthorityClass::AccordCoScrub,
            "the trap must be reachable — if it were already ProducerSteward, the \
             demotion below would prove nothing"
        );

        backend
            .record_canonical_withdrawal(&canonical, None, &"11".repeat(32))
            .await
            .expect("record the quorum withdrawal");

        // THE DISJUNCTION IS REAL, and this leg records it rather than
        // discovering it later. `is_trust_root` is `canonical OR infra:attest`,
        // and the baked canonical carries BOTH (`roles` includes `infra:attest`
        // — it is a build-signing pipeline as well as a bootstrap server). So a
        // canonical withdrawal alone does NOT demote the corpus, and a
        // consumer-side gate that consulted only the canonical tombstone would
        // be the #441 one-surface shape a plane over.
        assert_eq!(
            holdings_authority(&backend, &canonical)
                .await
                .expect("seam"),
            AuthorityClass::AccordCoScrub,
            "the canonical role is withdrawn, but this publisher is ALSO an \
             accord-blessed `infra:attest` pipeline — one tombstone does not \
             retire a two-role trust root"
        );

        backend
            .record_role_withdrawal(
                crate::federation::types::roles::INFRA_ATTEST,
                &canonical,
                None,
                &"22".repeat(32),
            )
            .await
            .expect("record the infra:attest withdrawal");

        assert_eq!(
            holdings_authority(&backend, &canonical)
                .await
                .expect("seam"),
            AuthorityClass::ProducerSteward,
            "a withdrawn trust root does not keep gossiping its corpus globally"
        );
        assert_eq!(
            projection_for(
                Plane::FountainContent,
                "federation",
                holdings_authority(&backend, &canonical)
                    .await
                    .expect("seam"),
                false
            ),
            Projection::Cohort,
            "and the projection narrows with it"
        );
    }

    /// End-to-end through the recipient verb: the authority the seam declares
    /// is the difference between "every peer" and "withhold" on the same
    /// record. This is the composition edge will actually run.
    #[tokio::test]
    async fn the_seam_decides_whether_a_federation_scoped_corpus_reaches_a_stranger() {
        let (backend, canonical) = seeded_canonical().await;
        let stranger = "holdings-744-stranger";

        let as_root = resolve_projection_recipients(
            &backend,
            Plane::FountainContent,
            "federation",
            holdings_authority(&backend, &canonical)
                .await
                .expect("seam"),
            false,
            "holdings-744-no-such-group",
            stranger,
        )
        .await
        .expect("no Err");
        assert!(
            as_root.may_advertise(),
            "a trust root's federation corpus is Global — unbounded, no roster read"
        );

        let as_producer = resolve_projection_recipients(
            &backend,
            Plane::FountainContent,
            "federation",
            holdings_authority(&backend, "holdings-744-plain-producer")
                .await
                .expect("seam"),
            false,
            "holdings-744-no-such-group",
            stranger,
        )
        .await
        .expect("no Err");
        assert!(
            !as_producer.may_advertise(),
            "a plain producer's federation corpus is Cohort, and no scope-address \
             table exists for that tier — so it withholds"
        );
        assert_eq!(as_producer.basis, RecipientBasis::NoRosterForScope);
    }
}
