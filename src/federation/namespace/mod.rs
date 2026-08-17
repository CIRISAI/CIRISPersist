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

/// The projection PLANE parameter (v35.0.0, CIRISPersist#713) — re-exported
/// from [`load_bearing`](crate::federation::load_bearing) so the projection
/// surface ([`projection_for`] / [`tombstone_ceiling`]) and the predicate
/// surface ([`is_load_bearing`](crate::federation::load_bearing::is_load_bearing))
/// dispatch over the SAME closed five-plane enum. One enum, two axes: the
/// predicate answers *may this copy be released*, the projection answers *how
/// far does this record travel* — both per plane.
pub use crate::federation::load_bearing::ObjectClass;

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
/// `f(plane, cohort_scope, authority, is_tombstone)` (v35.0.0, CIRISPersist#713).
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
/// already dispatched per [`ObjectClass`]; the projection side now does too.
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
/// | `Attestation` | *DEFERRED — the pre-#713 scope-only behavior, held; see below* |
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
/// # The deferred `Attestation` row (NOT a silent default)
///
/// [`ObjectClass::Attestation`] holds today's scope-only behavior — the exact
/// pre-#713 rule — because #713's server relay showed the row cannot be *a*
/// row: the contextual-integrity information-type parameter is the
/// `dimension`, and at minimum `trace:*` is capability-gated (serves to
/// `capability:infra:serve` only; never widens with scope) while `scores:*`
/// is subject-gated (CC#46), which need audience kinds (`Capability`,
/// `Subject`) the four inputs cannot express. The per-dimension-family
/// decomposition is #713's open half; CIRISEdge owes the shape answer. Until
/// it lands, this arm is the old behavior, documented as DEFERRED — awaiting
/// a decision, not making one.
///
/// Two cells of that decomposition ARE already decided on the thread and are
/// recorded here because this signature cannot yet resolve them (they need
/// the `dimension`, which the four inputs deliberately do not carry — the
/// decomposition will bring it properly, not as a bolt-on parameter):
/// [`AuthorityClass::SubstrateSelf`] at commons scopes projects
/// [`Global`](Projection::Global) on the Attestation plane for `transport:*`
/// dimensions and for the EXACT dimension `system:audit_chain:hash_continuity`
/// — NOT the open `system:*` prefix. A future subject-carrying dimension must
/// never inherit Global from a namespace; a new member has to EARN Global,
/// not inherit it (#713 server relay, declining the open prefix).
///
/// # Structure
///
/// - **Total registry, compiler-checked** (#636's lesson — the gate sees the
///   table itself, not a copy): the body is an exhaustive `match` on
///   [`ObjectClass`], so a new plane variant is a COMPILE ERROR until its row
///   exists.
/// - **Pure and O(1)**: no directory read, no allocation, no O(members)
///   anything; `benches/projection.rs` holds the number against the `pre-713`
///   baseline.
/// - **Any unrecognized scope** → [`Cohort`](Projection::Cohort) on every
///   plane — the conservative negative default, unchanged; a future scope
///   never silently GLOBAL-gossips.
/// - **`is_tombstone`** (see [`is_withdraw_or_revocation`]) projects at
///   [`tombstone_ceiling`]`(plane, authority)` — no longer an unconditional
///   Global; see there for the invariant and the rows.
#[inline]
pub fn projection_for(
    plane: ObjectClass,
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
        ObjectClass::KeyRecord => match cohort_scope {
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
        ObjectClass::TransportDestination => match cohort_scope {
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
        ObjectClass::FountainContent => match cohort_scope {
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
        ObjectClass::HardCaseEvent => match cohort_scope {
            cohort_scope::SELF | cohort_scope::FAMILY => Projection::SelfOwn,
            cohort_scope::COMMUNITY | cohort_scope::AFFILIATIONS => Projection::Cohort,
            cohort_scope::SPECIES | cohort_scope::BIOSPHERE | cohort_scope::FEDERATION => {
                Projection::Cohort
            }
            _ => Projection::Cohort,
        },
        // Attestation — DEFERRED (#713): the pre-#713 scope-only behavior,
        // held verbatim pending the per-dimension-family decomposition (needs
        // Capability + Subject audience kinds; CIRISEdge owes the shape
        // answer). See the function doc for the two already-decided
        // SubstrateSelf commons cells this signature cannot yet resolve.
        ObjectClass::Attestation => match cohort_scope {
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
    }
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
/// - [`Attestation`](ObjectClass::Attestation) → `Global`, unconditional —
///   today's behavior HELD under the same deferral as the live row: the
///   per-dimension decomposition will assign per-family ceilings (#713's
///   server relay already names `consent:*` ceiling Global, "same
///   anti-rollback logic as KeyRecord").
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
pub fn tombstone_ceiling(plane: ObjectClass, authority: AuthorityClass) -> Projection {
    match plane {
        // Verify-relevance is unbounded: signatures by a revoked key may ride
        // records that traveled Global.
        ObjectClass::KeyRecord => Projection::Global,
        // Row max: a non-root route/corpus never projected beyond Cohort
        // under any scope.
        ObjectClass::TransportDestination | ObjectClass::FountainContent => {
            if authority.is_trust_root() {
                Projection::Global
            } else {
                Projection::Cohort
            }
        }
        // Global BY ROLE (infra de-admission); is_trust_root is the closest
        // AuthorityClass approximation of "carries an infra role" — see doc.
        ObjectClass::HardCaseEvent => {
            if authority.is_trust_root() {
                Projection::Global
            } else {
                Projection::Cohort
            }
        }
        // DEFERRED with the live row — today's unconditional Global, held.
        ObjectClass::Attestation => Projection::Global,
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
    /// once, instead of being re-derived per consumer.
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

    #[test]
    fn projection_self_and_family_are_publish_own() {
        // Every plane's self/family cells are SelfOwn — the structurally-
        // invisible identity tier is publish-own on every plane.
        for plane in ObjectClass::ALL {
            for s in ["self", "family"] {
                assert_eq!(
                    projection_for(plane, s, AuthorityClass::SelfIdentity, false),
                    Projection::SelfOwn,
                    "{plane:?}/{s}"
                );
            }
        }
    }

    #[test]
    fn projection_community_and_affiliations_relay_over_cohort() {
        for plane in ObjectClass::ALL {
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
                projection_for(
                    ObjectClass::KeyRecord,
                    s,
                    AuthorityClass::AccordCoScrub,
                    false
                ),
                Projection::Global,
                "trust-root {s} key record"
            );
            // a plain producer's commons record relays over the cohort.
            assert_eq!(
                projection_for(
                    ObjectClass::KeyRecord,
                    s,
                    AuthorityClass::ProducerSteward,
                    false
                ),
                Projection::Cohort,
                "producer {s} key record"
            );
            // substrate-self is NOT a trust root → cohort (documented surface).
            assert_eq!(
                projection_for(
                    ObjectClass::KeyRecord,
                    s,
                    AuthorityClass::SubstrateSelf,
                    false
                ),
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
                    ObjectClass::TransportDestination,
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
        use ObjectClass::TransportDestination as TD;
        use Projection::{Cohort, Global, SelfOwn};
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
        use ObjectClass::FountainContent as FC;
        use Projection::{Cohort, Global, SelfOwn};
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
                ObjectClass::HardCaseEvent,
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
        use ObjectClass::HardCaseEvent as HCE;
        use Projection::{Cohort, SelfOwn};
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

    /// The Attestation row is DEFERRED: it must hold the exact pre-#713
    /// scope-only behavior until the per-dimension-family decomposition
    /// lands (#713's open half). LITERALS of the old rule.
    #[test]
    fn attestation_row_holds_the_pre_713_scope_only_behavior() {
        use AuthorityClass::{AccordCoScrub, ProducerSteward, SubstrateSelf};
        use ObjectClass::Attestation as AT;
        use Projection::{Cohort, Global, SelfOwn};
        assert_eq!(projection_for(AT, "self", ProducerSteward, false), SelfOwn);
        assert_eq!(
            projection_for(AT, "family", ProducerSteward, false),
            SelfOwn
        );
        assert_eq!(
            projection_for(AT, "community", ProducerSteward, false),
            Cohort
        );
        assert_eq!(
            projection_for(AT, "affiliations", ProducerSteward, false),
            Cohort
        );
        for s in ["species", "biosphere", "federation"] {
            assert_eq!(projection_for(AT, s, AccordCoScrub, false), Global, "{s}");
            assert_eq!(projection_for(AT, s, ProducerSteward, false), Cohort, "{s}");
            // The SubstrateSelf commons cells the thread DID decide (Global
            // for transport:* + system:audit_chain:hash_continuity) need the
            // dimension, which this signature cannot see — so the held
            // behavior is still Cohort here, per the deferral note.
            assert_eq!(projection_for(AT, s, SubstrateSelf, false), Cohort, "{s}");
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
                    projection_for(ObjectClass::KeyRecord, s, a, true),
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
                    projection_for(ObjectClass::TransportDestination, s, a, true),
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
                    ObjectClass::TransportDestination,
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
                ObjectClass::FountainContent,
                "self",
                AuthorityClass::ProducerSteward,
                true
            ),
            Projection::Cohort
        );
        assert_eq!(
            projection_for(
                ObjectClass::FountainContent,
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
                projection_for(ObjectClass::HardCaseEvent, "federation", a, true),
                Projection::Cohort,
                "non-infra hard-case tombstone {a:?} must stay Cohort"
            );
        }
        assert_eq!(
            projection_for(
                ObjectClass::HardCaseEvent,
                "federation",
                AuthorityClass::AccordCoScrub,
                true
            ),
            Projection::Global,
            "infra-role de-admission must be globally unlearnable"
        );
    }

    /// The Attestation ceiling holds today's unconditional Global, under the
    /// same deferral as its live row.
    #[test]
    fn attestation_tombstone_stays_global_pending_decomposition() {
        for a in AUTHORITIES {
            assert_eq!(
                projection_for(ObjectClass::Attestation, "self", a, true),
                Projection::Global,
                "{a:?}"
            );
        }
    }

    /// THE CEILING IS THE ROW MAX (#713's stated invariant: "anti-rollback
    /// holds within the record's maximal disclosure set; beyond it there is
    /// no copy to roll back"). For every (plane, authority) the tombstone
    /// ceiling must dominate every LIVE cell in that row — over the seven
    /// closed scopes AND the unrecognized-scope default — or a tombstone
    /// could fail to reach a holder a live version legitimately reached.
    ///
    /// This test reads the registry ON PURPOSE: it is a property OVER the
    /// table, not a per-cell expectation derived FROM it (those are the
    /// literal row tests above).
    #[test]
    fn tombstone_ceiling_dominates_every_live_cell() {
        fn rank(p: Projection) -> u8 {
            match p {
                Projection::SelfOwn => 0,
                Projection::Cohort => 1,
                Projection::Global => 2,
            }
        }
        for plane in ObjectClass::ALL {
            for authority in AUTHORITIES {
                let ceiling = tombstone_ceiling(plane, authority);
                for s in SCOPES {
                    let live = projection_for(plane, s, authority, false);
                    assert!(
                        rank(ceiling) >= rank(live),
                        "{plane:?}/{authority:?}: ceiling {ceiling:?} is BELOW the live cell \
                         {live:?} at scope {s:?} — a tombstone would starve a holder a live \
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
        // On EVERY plane, even for a trust root, an unrecognized scope relays
        // over the cohort — a future scope never silently GLOBAL-gossips.
        for plane in ObjectClass::ALL {
            assert_eq!(
                projection_for(
                    plane,
                    "some-future-scope",
                    AuthorityClass::AccordCoScrub,
                    false
                ),
                Projection::Cohort,
                "{plane:?}"
            );
        }
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
