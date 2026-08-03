//! v24.2.0 (CIRISPersist#564 stage 1) — **`is_load_bearing(X)`**: the
//! reachability primitive, read-only and fail-secure.
//!
//! # The question
//!
//! > **Is this CEG object load-bearing on THIS node?**
//!
//! An object is load-bearing iff removing our copy would change an answer this
//! node can give or an action it may take. A `consent:replication` grant
//! authorizes *our holding of something*; hold nothing that needs it and it
//! does no work here — independent of its age or its author's fate.
//!
//! #563 found 234 inert `consent:replication` grants that nothing reduces and
//! proposed decay. The operator's reframe replaced the mechanism: **not decay,
//! not liveness — reference counting with a rigorous definition of
//! reachability.** Three of this project's paid lessons argue against the
//! decay design and are recorded so it is not re-proposed: clock-based
//! validity was removed on purpose (#551/#557 — `valid until revoked`);
//! a principal-liveness band is a score about a principal (#552, CC#49-A1) and
//! punishes the quiet-but-honest; and two decay mechanisms with different
//! schedules is the two-lists-that-disagree class. Load-bearing is
//! **structural** — about the graph, about no one.
//!
//! # What this stage does, and what it deliberately does not
//!
//! Stage 1 is the predicate + the manifest axis + the gate. It **releases,
//! evicts and mutates NOTHING**: every function here is a read. It makes the
//! 234 legible as `No` and every gap legible as `Unknown`.
//!
//! `may_release_copy` (with its `anti_entropy_satisfied` conjunct) is stage 2
//! and is deliberately absent — a `No` from this module is NOT a licence to
//! drop anything, because dropping a copy that has nowhere else to live is
//! data loss wearing a GC costume. Compaction is stage 4 and may prove
//! unnecessary entirely.
//!
//! # Never a bare bool
//!
//! [`LoadBearing`] carries a derivation trace: `Yes` names WHICH dependency,
//! `Unknown` names WHICH family and WHY. That is the `TrustRootVerdict` /
//! `TrustedGrant` discipline — a verdict whose evidence the consumer can read
//! without coming back to this layer to ask.
//!
//! # Fail-secure
//!
//! [`LoadBearing::Unknown`] is **treated as load-bearing**. It is the DEFAULT
//! for any family without a declared predicate — never `No` by omission. An
//! undeclared family is a manifest gap, never a licence to collect; the
//! coverage gate in [`super::namespace::supersets`] is what turns that gap
//! from silent into loud.

use crate::federation::{Attestation, Error, FederationDirectory};
use serde::{Deserialize, Serialize};

/// The persist-owned pseudo-family for a `federation_keys` row.
///
/// Key records are directory rows, not CC claim families, so they have no
/// prefix in the namespace manifest. They still need a family NAME to report
/// in an [`LoadBearing::Unknown`], and inventing one silently would be worse
/// than naming it here.
pub const FEDERATION_KEY_FAMILY: &str = "federation_key";

/// What the object under test is. Extended APPEND-ONLY; stage 2 (#564) added
/// the three classes the issue's dependency-kind sweep names and stage 1 could
/// not yet address — routes, fountain units and hard-case evidence.
///
/// Every arm MUST map to an [`ObjectClass`], and every `ObjectClass` MUST have
/// an [`object_class_policy`]. Both are exhaustive matches, so **adding an arm
/// without declaring its predicate is a compile failure** — the
/// [`super::replication_policy::policy_for`] discipline, applied to the
/// reachability axis. That is what makes the sweep exhaustive by construction
/// rather than by anyone remembering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectRef {
    /// A CEG attestation, by `attestation_id`. Its family is resolved from the
    /// envelope `dimension`.
    Attestation {
        /// The row's `attestation_id`.
        attestation_id: String,
    },
    /// A `federation_keys` row, by `key_id`.
    KeyRecord {
        /// The row's `key_id`.
        key_id: String,
    },
    /// v27 (#564 stage 2) — a `federation_transport_destinations` row: one
    /// route, keyed as the table keys it. The issue's "transport routes →
    /// reachability to peers we may serve (#561's hop eligibility)".
    TransportDestination {
        /// The occurrence the route reaches.
        occurrence_key_id: String,
        /// The route's transport kind (`reticulum` / `websocket` / …).
        transport_kind: String,
    },
    /// v27 (#564 stage 2) — a fountain-coded content unit, by its
    /// `(content_id, corpus_kind)` manifest key. The issue's "blobs / fountain
    /// units → the existing eviction plane already answers this; reuse rather
    /// than duplicate".
    FountainContent {
        /// The manifest's `content_id`.
        content_id: String,
        /// The manifest's `corpus_kind`.
        corpus_kind: String,
    },
    /// v27 (#564 stage 2) — a `hard_case_events` row, by `event_id`. The
    /// issue's "breach/hard_case evidence → load-bearing while any verdict
    /// process may cite it".
    HardCaseEvent {
        /// The row's `event_id`.
        event_id: String,
    },
}

impl ObjectRef {
    /// The identifier, whichever arm this is — for logging and for the
    /// `object_id` a consumer echoes back. Composite-keyed arms report their
    /// leading key; [`Self::class`] disambiguates.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Attestation { attestation_id } => attestation_id,
            Self::KeyRecord { key_id } => key_id,
            Self::TransportDestination {
                occurrence_key_id, ..
            } => occurrence_key_id,
            Self::FountainContent { content_id, .. } => content_id,
            Self::HardCaseEvent { event_id } => event_id,
        }
    }

    /// The [`ObjectClass`] this ref belongs to. Exhaustive — a new arm must
    /// name its class here, and the class must then carry a policy.
    #[must_use]
    pub const fn class(&self) -> ObjectClass {
        match self {
            Self::Attestation { .. } => ObjectClass::Attestation,
            Self::KeyRecord { .. } => ObjectClass::KeyRecord,
            Self::TransportDestination { .. } => ObjectClass::TransportDestination,
            Self::FountainContent { .. } => ObjectClass::FountainContent,
            Self::HardCaseEvent { .. } => ObjectClass::HardCaseEvent,
        }
    }

    /// **The ONE parse door** from an FFI/host-shaped `(kind, id, id2)` triple
    /// to a typed ref.
    ///
    /// Every host entry point funnels through here rather than matching the
    /// kind token itself, so the two FFI surfaces cannot drift into supporting
    /// different subsets of the classes — the failure that gave #564 stage 1 a
    /// predicate reachable for two classes and unreachable for the rest.
    /// Exhaustive over [`ObjectClass::ALL`]; a class with no arm is a test
    /// failure ([`tests::every_class_is_constructible_from_host_parts`]).
    ///
    /// `id2` is REQUIRED for the composite-keyed classes and rejected loudly
    /// when absent — a silently-defaulted `transport_kind` would answer about a
    /// different route than the caller asked about.
    pub fn from_parts(kind: &str, id: &str, id2: Option<&str>) -> Result<Self, String> {
        let need2 = |what: &str| -> Result<String, String> {
            id2.map(str::to_owned).ok_or_else(|| {
                format!("object_kind {kind:?} is keyed on (id, {what}) — {what} is required")
            })
        };
        match kind {
            "attestation" => Ok(Self::Attestation {
                attestation_id: id.to_owned(),
            }),
            "key_record" => Ok(Self::KeyRecord {
                key_id: id.to_owned(),
            }),
            "transport_destination" => Ok(Self::TransportDestination {
                occurrence_key_id: id.to_owned(),
                transport_kind: need2("transport_kind")?,
            }),
            "fountain_content" => Ok(Self::FountainContent {
                content_id: id.to_owned(),
                corpus_kind: need2("corpus_kind")?,
            }),
            "hard_case_event" => Ok(Self::HardCaseEvent {
                event_id: id.to_owned(),
            }),
            other => Err(format!(
                "unknown object_kind {other:?} — expected one of {:?}",
                ObjectClass::ALL.map(|c| c.as_str())
            )),
        }
    }
}

/// The closed set of object classes the reachability sweep covers — the
/// storage-keyed counterpart to the per-family predicate axis.
///
/// A family declares what a *claim* implies; a class declares how an *object*
/// is reference-counted at all. The two are orthogonal: `Attestation` resolves
/// through the family axis, while a route has no family and is answered
/// structurally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectClass {
    /// `federation_attestations` — resolved through the per-family axis.
    Attestation,
    /// `federation_keys`.
    KeyRecord,
    /// `federation_transport_destinations`.
    TransportDestination,
    /// `content_manifest` + `content_symbols`.
    FountainContent,
    /// `hard_case_events`.
    HardCaseEvent,
}

impl ObjectClass {
    /// Every class, in declaration order. The gate iterates this.
    pub const ALL: [ObjectClass; 5] = [
        ObjectClass::Attestation,
        ObjectClass::KeyRecord,
        ObjectClass::TransportDestination,
        ObjectClass::FountainContent,
        ObjectClass::HardCaseEvent,
    ];

    /// The stable program token — identical to the serde token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Attestation => "attestation",
            Self::KeyRecord => "key_record",
            Self::TransportDestination => "transport_destination",
            Self::FountainContent => "fountain_content",
            Self::HardCaseEvent => "hard_case_event",
        }
    }
}

/// How a class is reference-counted, and — when it cannot be — why. Closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassResolution {
    /// Resolved through the per-family declared predicate axis
    /// ([`super::namespace::supersets::load_bearing_predicate`]).
    PerFamilyPredicate,
    /// Answered structurally from targeted reads on this class's own table.
    StructuralReads,
    /// DEFERRED to a plane that already owns this object's retention. Resolves
    /// [`LoadBearing::Unknown`] here on purpose: two mechanisms deciding one
    /// object's fate is the two-lists-that-disagree class #564 exists to avoid.
    DeferredToOwningPlane,
    /// Persist holds no reverse index that could prove the object unreferenced,
    /// so NOT-load-bearing is unprovable. Fail-secure [`LoadBearing::Unknown`].
    NoReverseIndex,
}

/// The per-class policy: how it resolves, and the rationale a consumer reads
/// instead of coming back here to ask.
#[derive(Debug, Clone, Copy)]
pub struct ObjectClassPolicy {
    /// The class this governs.
    pub class: ObjectClass,
    /// How it is reference-counted.
    pub resolution: ClassResolution,
    /// Why — including, for the deferring/unprovable arms, WHICH read persist
    /// would need. A gap that names its missing read is actionable; a shrug
    /// is not.
    pub rationale: &'static str,
}

/// The ONE policy per class. Exhaustive `match`: adding an [`ObjectClass`]
/// without a policy is a **compile failure**.
#[must_use]
pub const fn object_class_policy(class: ObjectClass) -> ObjectClassPolicy {
    let (resolution, rationale) = match class {
        ObjectClass::Attestation => (
            ClassResolution::PerFamilyPredicate,
            "a claim's dependents are whatever its FAMILY implies, so the manifest's declared \
             per-family predicate is the authority; an undeclared family resolves Unknown",
        ),
        ObjectClass::KeyRecord => (
            ClassResolution::StructuralReads,
            "a key is load-bearing while any held row names it. `list_attestations_by` / \
             `list_attestations_for` prove YES; no index answers \"which rows name it as scrub \
             or co-scrub\", so NO stays unproven and resolves Unknown",
        ),
        ObjectClass::TransportDestination => (
            ClassResolution::StructuralReads,
            "a LIVE route is what makes an occurrence reachable, and a RETIRED route is a \
             tombstone the route plane deliberately keeps gossiping \
             (`list_signed_transport_destinations_for` includes retired rows on purpose). Both \
             are dependents this node can read directly, so both prove YES; a route absent from \
             both reads is not held here at all",
        ),
        ObjectClass::FountainContent => (
            ClassResolution::DeferredToOwningPlane,
            "the eviction plane ALREADY decides fountain retention — tier eviction, \
             consent-driven hard delete, the §Q pin reserve. #564 says reuse rather than \
             duplicate, and a second mechanism with its own reasoning is exactly the \
             two-lists-that-disagree shape. Reference counting therefore declines to answer \
             here and defers; deferring resolves Unknown, which is fail-secure",
        ),
        ObjectClass::HardCaseEvent => (
            ClassResolution::NoReverseIndex,
            "breach evidence is load-bearing while any verdict process may cite it. Persist \
             emits and lists hard-case rows but stores no index of OPEN verdict processes, and \
             the WA quorum that turns evidence into sentences runs elsewhere — so nothing here \
             can prove a given row uncited. Same shape as the declared-undeclared `accord:*` \
             and `bond_posted:{currency}` families",
        ),
    };
    ObjectClassPolicy {
        class,
        resolution,
        rationale,
    }
}

/// The KIND of dependency a [`Dependency`] records — closed, so a consumer can
/// branch on the shape of the thing that would break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    /// A row this node RETAINS that exists here because of the object under
    /// test — the object authorizes our holding of it.
    RetainedAttestation,
    /// A held row that NAMES the object under test (as attester, subject,
    /// scrub or co-scrub), so removing the object would leave that row
    /// dangling.
    NamingRow,
    /// The manifest DECLARES this family always load-bearing. Not an inference
    /// from the corpus — a declaration, which is the point: `trust:accepts:v1`
    /// must be load-bearing on a node that holds nothing else at all.
    DeclaredAlways,
    /// v27 (#564 stage 2) — a LIVE route: removing it removes an address this
    /// node can be reached on, which is an action it may take.
    ReachabilityRoute,
    /// v27 (#564 stage 2) — a RETIRED route kept deliberately so the tombstone
    /// gossips. Removing it would let a peer's stale route resurrect, so the
    /// tombstone is doing work precisely BECAUSE the route is dead.
    GossipTombstone,
}

impl DependencyKind {
    /// The stable program token — identical to the serde token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RetainedAttestation => "retained_attestation",
            Self::NamingRow => "naming_row",
            Self::DeclaredAlways => "declared_always",
            Self::ReachabilityRoute => "reachability_route",
            Self::GossipTombstone => "gossip_tombstone",
        }
    }
}

/// ONE reason an object is load-bearing: which row depends on it, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    /// The shape of the dependency.
    pub kind: DependencyKind,
    /// The identifier of the depending row (an `attestation_id`, a `key_id`,
    /// or — for [`DependencyKind::DeclaredAlways`] — the declaring family).
    pub object_id: String,
    /// Human-readable derivation: what would stop working.
    pub detail: String,
}

/// The verdict. **Never a bare bool** — the consumer sees WHICH dependency and
/// WHY (the `TrustRootVerdict` / `TrustedGrant` discipline).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBearing {
    /// Something here depends on this object. `because` is the enumerated
    /// derivation, capped at [`MAX_DEPENDENCIES_REPORTED`] — the verdict is
    /// the same at one dependent or a thousand, and an unbounded list would
    /// make a cheap read expensive.
    Yes {
        /// The enumerated dependents.
        because: Vec<Dependency>,
    },
    /// Provably nothing on this node depends on it. Still not a licence to
    /// release: that needs stage 2's `anti_entropy_satisfied` conjunct too.
    No,
    /// **FAIL-SECURE: treated as load-bearing.** The family declares no
    /// predicate persist can evaluate, so the honest answer is "we do not
    /// know" — and not knowing means not collecting.
    Unknown {
        /// The manifest family (or [`FEDERATION_KEY_FAMILY`]) the object
        /// resolved to, or `"<unresolved>"` when the dimension matched none.
        family: String,
        /// Why the predicate could not answer — which read persist would need.
        reason: String,
    },
}

impl LoadBearing {
    /// The fail-secure reading: `Yes` AND `Unknown` are both treated as load
    /// bearing. Only a proven `No` is not.
    ///
    /// Named for what it MEANS rather than what it returns, so a caller cannot
    /// read it as "may release" — it is not. Release needs stage 2's
    /// anti-entropy conjunct as well.
    #[must_use]
    pub const fn treated_as_load_bearing(&self) -> bool {
        !matches!(self, Self::No)
    }
}

/// The cap on enumerated dependents in a [`LoadBearing::Yes`]. One dependent
/// already settles the verdict; the rest are evidence, and evidence is worth
/// bounding.
pub const MAX_DEPENDENCIES_REPORTED: usize = 16;

/// The manifest family prefix a claim `dimension` belongs to, or `None` if it
/// matches no declared family.
///
/// Matching mirrors the manifest's own prefix grammar: a literal segment must
/// match exactly, a `{placeholder}` segment matches any ONE segment, and a
/// trailing `*` matches the remaining segments. The MOST SPECIFIC match wins
/// (most literal segments, then longest), the same longest-prefix discipline
/// [`crate::federation::namespace::registry::lookup`] uses — so
/// `dma:pdma:principled_evaluation` resolves to `dma:pdma:*` rather than to a
/// broader `dma:*` if both were declared.
#[must_use]
pub fn family_for_dimension(dimension: &str) -> Option<&'static str> {
    let mut best: Option<(usize, usize, &'static str)> = None;
    for family in super::namespace::supersets::family_prefixes() {
        let Some(literals) = prefix_match_score(family, dimension) else {
            continue;
        };
        let key = (literals, family.len(), family);
        if best.is_none_or(|b| key > b) {
            best = Some(key);
        }
    }
    best.map(|(_, _, f)| f)
}

/// `Some(number_of_literal_segments_matched)` iff `family` matches
/// `dimension`; `None` otherwise. The literal count is the specificity score.
fn prefix_match_score(family: &str, dimension: &str) -> Option<usize> {
    let fam: Vec<&str> = family.split(':').collect();
    let dim: Vec<&str> = dimension.split(':').collect();
    let mut literals = 0usize;
    for (i, seg) in fam.iter().enumerate() {
        if *seg == "*" {
            // A trailing `*` consumes the remainder — but only if there IS a
            // remainder (`consent:*` describes `consent:replication:v1`, not a
            // bare `consent`).
            return if dim.len() > i { Some(literals) } else { None };
        }
        let d = dim.get(i)?;
        if seg.starts_with('{') && seg.ends_with('}') {
            continue; // a placeholder matches exactly one segment
        }
        if seg != d {
            return None;
        }
        literals += 1;
    }
    // No wildcard consumed the tail: the arities must match exactly.
    (fam.len() == dim.len()).then_some(literals)
}

/// v24.2.0 (CIRISPersist#564 stage 1) — **is `object` load-bearing on this
/// node?**
///
/// Resolves the object's family, looks up the family's declared predicate in
/// the Registry-of-Record ([`super::namespace::supersets::load_bearing_predicate`]),
/// and evaluates it against reads that exist today. A family with no declared
/// predicate — or one declared `undeclared` — resolves
/// [`LoadBearing::Unknown`], which is fail-secure.
///
/// `Err` is reserved for a real backend failure: an object that cannot be
/// found is not an error, it is [`LoadBearing::No`] with nothing to depend on
/// it. (An absent object is trivially not load-bearing; the caller asked about
/// a copy this node does not hold.)
///
/// Backend-agnostic by construction — it composes trait methods over
/// `&dyn FederationDirectory`, so memory / sqlite / postgres get identical
/// behaviour with no per-backend code.
pub async fn is_load_bearing(
    directory: &dyn FederationDirectory,
    object: ObjectRef,
) -> Result<LoadBearing, Error> {
    match object {
        ObjectRef::Attestation { attestation_id } => {
            let Some(row) = directory.get_attestation(&attestation_id).await? else {
                // Nothing here to be load-bearing. Not an error and not
                // Unknown: the absence is itself the complete answer.
                return Ok(LoadBearing::No);
            };
            attestation_load_bearing(directory, &row).await
        }
        ObjectRef::KeyRecord { key_id } => key_record_load_bearing(directory, &key_id).await,
        ObjectRef::TransportDestination {
            occurrence_key_id,
            transport_kind,
        } => {
            transport_destination_load_bearing(directory, &occurrence_key_id, &transport_kind).await
        }
        ObjectRef::FountainContent {
            content_id,
            corpus_kind,
        } => Ok(deferred_or_unindexed(
            ObjectClass::FountainContent,
            &format!("{content_id}/{corpus_kind}"),
        )),
        ObjectRef::HardCaseEvent { event_id } => {
            Ok(deferred_or_unindexed(ObjectClass::HardCaseEvent, &event_id))
        }
    }
}

/// The shared fail-secure resolution for a class whose policy says persist
/// either DEFERS to an owning plane or holds no reverse index.
///
/// Both are the same runtime fact — persist cannot prove this object
/// unreferenced — and both are therefore [`LoadBearing::Unknown`]. They differ
/// only in WHY, and the policy's rationale carries that, so the caller learns
/// which of the two it hit without a second call.
///
/// The `family` slot reports the CLASS token rather than a manifest family,
/// because these objects have no `dimension` and inventing one would be a lie
/// the consumer could not detect.
fn deferred_or_unindexed(class: ObjectClass, object_id: &str) -> LoadBearing {
    let policy = object_class_policy(class);
    debug_assert!(
        matches!(
            policy.resolution,
            ClassResolution::DeferredToOwningPlane | ClassResolution::NoReverseIndex
        ),
        "deferred_or_unindexed called for a class that claims it can answer structurally"
    );
    LoadBearing::Unknown {
        family: class.as_str().to_string(),
        reason: format!("{object_id}: {}", policy.rationale),
    }
}

/// The route arm. A route is load-bearing while this node holds it in either
/// of the two route reads, and the two mean different things:
///
/// - present in [`FederationDirectory::list_transport_destinations_for`] — a
///   LIVE address; removing it removes a way this node can be reached.
/// - present only in the SIGNED read (which includes retired rows on purpose,
///   "tombstones must gossip") — a RETIRED route whose tombstone is the work.
///
/// Absent from both, the route is not held here, and nothing here can depend on
/// a copy that is not here — the same absence rule the attestation arm uses.
async fn transport_destination_load_bearing(
    directory: &dyn FederationDirectory,
    occurrence_key_id: &str,
    transport_kind: &str,
) -> Result<LoadBearing, Error> {
    let mut because: Vec<Dependency> = Vec::new();
    let object_id = format!("{occurrence_key_id}/{transport_kind}");

    for route in directory
        .list_transport_destinations_for(occurrence_key_id)
        .await?
    {
        if route.transport_kind == transport_kind {
            because.push(Dependency {
                kind: DependencyKind::ReachabilityRoute,
                object_id: object_id.clone(),
                detail: format!(
                    "a LIVE {transport_kind} route reaches occurrence {occurrence_key_id} at \
                     {}; dropping it drops that reachability",
                    route.destination
                ),
            });
        }
    }

    // Retired rows appear ONLY in the signed read. Consult it whenever the
    // live read found nothing — that is exactly the tombstone case.
    if because.is_empty() {
        for signed in directory
            .list_signed_transport_destinations_for(occurrence_key_id)
            .await?
        {
            if signed.transport_destination.transport_kind == transport_kind {
                because.push(Dependency {
                    kind: DependencyKind::GossipTombstone,
                    object_id: object_id.clone(),
                    detail: format!(
                        "a RETIRED {transport_kind} route for occurrence {occurrence_key_id} — \
                         the route plane keeps retired rows in the signed read so the tombstone \
                         gossips; dropping it would let a peer's stale route resurrect"
                    ),
                });
            }
        }
    }

    if because.is_empty() {
        Ok(LoadBearing::No)
    } else {
        because.truncate(MAX_DEPENDENCIES_REPORTED);
        Ok(LoadBearing::Yes { because })
    }
}

/// The attestation arm: resolve family → declared predicate → evaluate.
async fn attestation_load_bearing(
    directory: &dyn FederationDirectory,
    row: &Attestation,
) -> Result<LoadBearing, Error> {
    let Some(dimension) = super::admission::envelope_dimension(&row.attestation_envelope) else {
        return Ok(LoadBearing::Unknown {
            family: "<unresolved>".to_string(),
            reason: "the envelope carries no `dimension`, so no family — and therefore no \
                     declared predicate — can be resolved for it"
                .to_string(),
        });
    };
    let Some(family) = family_for_dimension(dimension) else {
        return Ok(LoadBearing::Unknown {
            family: "<unresolved>".to_string(),
            reason: format!(
                "dimension {dimension:?} matches no family in the vendored namespace manifest, so \
                 it has no declared load-bearing predicate"
            ),
        });
    };
    let Some((kind, rationale)) = super::namespace::supersets::load_bearing_predicate(family)
    else {
        return Ok(LoadBearing::Unknown {
            family: family.to_string(),
            reason: format!(
                "family {family} declares no load-bearing predicate — a manifest gap, never a \
                 licence to collect"
            ),
        });
    };
    match kind {
        "always" => Ok(LoadBearing::Yes {
            because: vec![Dependency {
                kind: DependencyKind::DeclaredAlways,
                object_id: family.to_string(),
                detail: format!(
                    "{family} is DECLARED always load-bearing (dimension {dimension}): {rationale}"
                ),
            }],
        }),
        "retained_replication" => retained_replication(directory, row, family, dimension).await,
        // `undeclared`, and any kind a future manifest cut adds that this
        // resolver has no arm for. Both are the same fact — persist cannot
        // evaluate it — and both are fail-secure.
        _ => Ok(LoadBearing::Unknown {
            family: family.to_string(),
            reason: rationale.to_string(),
        }),
    }
}

/// The `retained_replication` predicate: a `consent:replication:v1` grant is
/// load-bearing iff this node still holds at least one row authored by a peer
/// the grant names.
///
/// The grant's peers ride `subject_key_ids` (the shape
/// [`super::consent_peer_set`] projects), and what the grant authorizes is our
/// holding of what those peers replicate to us — so `list_attestations_by(peer)`
/// is exactly the dependent set. Hold nothing from any named peer and the
/// grant does no work here.
///
/// A `consent:*` row that is NOT the replication dimension resolves
/// `Unknown`: its subject binding is not the peer-set shape, and guessing that
/// it is would be a wrong `No` on a live authorization.
async fn retained_replication(
    directory: &dyn FederationDirectory,
    row: &Attestation,
    family: &'static str,
    dimension: &str,
) -> Result<LoadBearing, Error> {
    if dimension != super::consent_peer_set::DIMENSION {
        return Ok(LoadBearing::Unknown {
            family: family.to_string(),
            reason: format!(
                "the `retained_replication` predicate is defined for {} only; dimension \
                 {dimension:?} binds its subjects differently and has no evaluable predicate yet",
                super::consent_peer_set::DIMENSION
            ),
        });
    }
    let mut because: Vec<Dependency> = Vec::new();
    for peer in &row.subject_key_ids {
        for held in directory.list_attestations_by(peer).await? {
            // The grant itself is not evidence of its own necessity.
            if held.attestation_id == row.attestation_id {
                continue;
            }
            because.push(Dependency {
                kind: DependencyKind::RetainedAttestation,
                object_id: held.attestation_id.clone(),
                detail: format!(
                    "retained under this grant: a row authored by consented peer {peer}"
                ),
            });
            if because.len() >= MAX_DEPENDENCIES_REPORTED {
                return Ok(LoadBearing::Yes { because });
            }
        }
    }
    if because.is_empty() {
        // The #563 case: a grant that reduces to nothing here.
        Ok(LoadBearing::No)
    } else {
        Ok(LoadBearing::Yes { because })
    }
}

/// The key-record arm: a `federation_keys` row is load-bearing while any held
/// row names it.
///
/// Persist can prove YES from targeted reads — `list_attestations_by` (the key
/// as attester) and `list_attestations_for` (the key as subject). It cannot yet
/// prove NO: "which rows name this key as `scrub_key_id` or co-scrub" has no
/// index, and answering it would need a full corpus scan whose cost is not
/// stage 1's to spend. So a key with no attestation dependency resolves
/// `Unknown`, not `No` — the fail-secure direction, and the honest one.
async fn key_record_load_bearing(
    directory: &dyn FederationDirectory,
    key_id: &str,
) -> Result<LoadBearing, Error> {
    let mut because: Vec<Dependency> = Vec::new();
    for (rows, role) in [
        (directory.list_attestations_by(key_id).await?, "attester"),
        (directory.list_attestations_for(key_id).await?, "subject"),
    ] {
        for held in rows {
            because.push(Dependency {
                kind: DependencyKind::NamingRow,
                object_id: held.attestation_id.clone(),
                detail: format!("a held attestation names {key_id} as its {role}"),
            });
            if because.len() >= MAX_DEPENDENCIES_REPORTED {
                return Ok(LoadBearing::Yes { because });
            }
        }
    }
    if because.is_empty() {
        Ok(LoadBearing::Unknown {
            family: FEDERATION_KEY_FAMILY.to_string(),
            reason: format!(
                "no held attestation names {key_id} as attester or subject, but persist has no \
                 index answering \"which rows name it as scrub or co-scrub\" — so NOT-load-bearing \
                 is unproven, and unproven is treated as load-bearing"
            ),
        })
    } else {
        Ok(LoadBearing::Yes { because })
    }
}

// ─────────────────────────────────────────────────────────────────────────
// v27 (CIRISPersist#564 stage 2) — `may_release_copy`, and the ANTI-ENTROPY
// CONJUNCT that is the whole point of it.
//
//     may_release_copy(X) ⇔ is_load_bearing(X) == No ∧ anti_entropy_satisfied(X)
//
// Both halves, never one. #564: "Dropping a copy that has nowhere else to live
// is data loss wearing a GC costume." Stage 2 still releases NOTHING — it is
// the predicate that stage 3 would have to satisfy, built now so that a stage-3
// author cannot forget the second half. Making the conjunct structural is the
// deliverable; a helper that returned only the first half would be worse than
// nothing, because it would look complete.
// ─────────────────────────────────────────────────────────────────────────

/// Whether the object verifiably resides where it is **relative to** — the
/// second conjunct.
///
/// # Persist cannot currently produce [`Self::Satisfied`], and that is a finding
///
/// The check requires knowing that some OTHER node holds the object (for a
/// consent about peer `P`: that `P` holds it, or that it was offered and
/// acknowledged). Persist cannot know that:
///
/// - It has **no peer transport**. The crate's only outbound HTTP client is the
///   feature-gated federated-secrets client; there is no peer-to-peer send
///   path anywhere in `src/`.
/// - Its replication surface is **inbound-apply and outbound-PULL only**
///   (`apply_replicated_key_record`, `list_signed_*_since`). A pull surface
///   does not learn who pulled, nor whether they kept it.
/// - There is **no stored acknowledgment or offer receipt** — no table, no
///   column, no trait method records "peer `P` acknowledged holding `X`".
///
/// So the honest value today is always [`Self::Unverifiable`], which is
/// fail-secure: the conjunct is never satisfied, so nothing is ever releasable.
/// This is a *structural* block, not a stub — closing it needs an
/// acknowledgment plane written by the layer that actually talks to peers, and
/// [`Self::Satisfied`] is the shape that plane would have to produce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntiEntropy {
    /// The object verifiably resides elsewhere. **Nothing in persist produces
    /// this today** — see the type-level note, and
    /// [`tests::nothing_yields_anti_entropy_satisfied_today`], which is the
    /// regression gate on that claim.
    Satisfied {
        /// Where it was verified to reside.
        because: Vec<Dependency>,
    },
    /// It provably does NOT reside elsewhere — this copy is the only one.
    NotSatisfied {
        /// Why residence is disproven.
        reason: String,
    },
    /// Residence cannot be verified from this node's own state. **Fail-secure**
    /// and the only value persist returns today.
    Unverifiable {
        /// What persist would need in order to answer.
        reason: String,
    },
}

impl AntiEntropy {
    /// The fail-secure reading: only a proven [`Self::Satisfied`] counts.
    ///
    /// Named for the conjunct it stands for, so a caller cannot read
    /// `!not_satisfied` as "fine" — `Unverifiable` is not fine.
    #[must_use]
    pub const fn is_satisfied(&self) -> bool {
        matches!(self, Self::Satisfied { .. })
    }
}

/// The stage-2 verdict: may this node release its copy?
///
/// **Deliberately a distinct type from the erasure plane's verdict (#573).**
/// The two questions have OPPOSITE failure directions — reachability fails
/// SECURE (an undeclared family is never released), erasure fails OPEN (an
/// unenumerated container is silently never erased). One shared "is this
/// covered?" verdict would be wrong for one of them, so the enumeration is
/// shared and the verdicts are not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MayRelease {
    /// BOTH conjuncts proven. Constructible only via [`may_release_copy`], and
    /// only when nothing depends on the object AND it verifiably lives
    /// elsewhere.
    Yes,
    /// Blocked — and the verdict names WHICH half blocked it, so a caller
    /// never has to guess whether it was reachability or residence.
    No {
        /// The reachability half.
        load_bearing: LoadBearing,
        /// The residence half.
        anti_entropy: AntiEntropy,
    },
}

impl MayRelease {
    /// `true` only for [`Self::Yes`]. The single place a caller should branch.
    #[must_use]
    pub const fn is_releasable(&self) -> bool {
        matches!(self, Self::Yes)
    }
}

/// v27 (CIRISPersist#564 stage 2) — **may this node release its copy of
/// `object`?**
///
/// `is_load_bearing(X) == No ∧ anti_entropy_satisfied(X)`. Evaluates both
/// halves and reports both, always — a `No` that named only the half that
/// happened to be checked first would send a caller to fix the wrong thing.
///
/// **This releases nothing.** It is a read, like everything else in this
/// module; stage 3 is the release, and it does not exist. Given
/// [`anti_entropy_satisfied`] cannot return [`AntiEntropy::Satisfied`] on this
/// substrate, the honest present-day answer is that **`Yes` is unreachable** —
/// which is the correct fail-secure posture and is asserted by
/// [`tests::may_release_is_unreachable_without_an_acknowledgment_plane`].
pub async fn may_release_copy(
    directory: &dyn FederationDirectory,
    object: ObjectRef,
) -> Result<MayRelease, Error> {
    let load_bearing = is_load_bearing(directory, object.clone()).await?;
    let anti_entropy = anti_entropy_satisfied(directory, &object).await?;
    if matches!(load_bearing, LoadBearing::No) && anti_entropy.is_satisfied() {
        return Ok(MayRelease::Yes);
    }
    Ok(MayRelease::No {
        load_bearing,
        anti_entropy,
    })
}

/// v27 (CIRISPersist#564 stage 2) — the second conjunct: does `object`
/// verifiably reside where it is relative to?
///
/// Returns [`AntiEntropy::Unverifiable`] for every object, naming the missing
/// plane. See [`AntiEntropy`] for why that is structural rather than a stub.
/// `directory` is taken so the signature does not change when an
/// acknowledgment plane lands — the reads it will need are directory reads.
#[allow(clippy::unused_async)] // the signature is the contract; see the doc.
pub async fn anti_entropy_satisfied(
    directory: &dyn FederationDirectory,
    object: &ObjectRef,
) -> Result<AntiEntropy, Error> {
    let _ = directory;
    Ok(AntiEntropy::Unverifiable {
        reason: format!(
            "persist cannot verify that {} {} resides anywhere else: it has no peer transport, \
             its replication surface is inbound-apply plus outbound-pull (a pull never learns \
             who kept what), and no table records a peer acknowledging a holding. Closing this \
             needs an acknowledgment plane written by the layer that talks to peers; until then \
             residence is unproven, and unproven blocks release",
            object.class().as_str(),
            object.id()
        ),
    })
}

/// v24.2.0 (CIRISPersist#564 stage 1) — the shared, backend-agnostic
/// behavioural witness, run by the sqlite / postgres / memory suites against
/// `&dyn FederationDirectory` so the three backends cannot silently diverge on
/// the predicate (the same discipline
/// [`super::consent_peer_set::test_support::exercise_consent_peer_set_fold`]
/// runs for the E7 projection). `suffix` scopes every fixture key so a run
/// against a shared postgres test DB does not collide with a prior one.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod test_support {
    use super::{
        is_load_bearing, may_release_copy, AntiEntropy, DependencyKind, LoadBearing, MayRelease,
        ObjectRef,
    };
    use crate::federation::types::{attestation_tier, attestation_type};
    use crate::federation::{Attestation, FederationDirectory, SignedAttestation};

    /// A federation-tier row carrying `dimension`, authored by `author` about
    /// `subject`. One fixture for every family the witness exercises: the
    /// thing under test is which FAMILY a dimension resolves to and what its
    /// declared predicate then does, so varying anything else would only make
    /// the witness harder to read.
    fn row(
        id: &str,
        author: &str,
        subject: &str,
        att_type: &str,
        dimension: &str,
        subject_key_ids: Vec<String>,
        extra: serde_json::Value,
    ) -> Attestation {
        let mut envelope = serde_json::json!({
            "dimension": dimension,
            "payload": {"grants": "replication", "attestation_prefixes": ["lb-fixture:"]},
        });
        // Family-specific envelope requirements (e.g. `trace:*` demands a
        // `trace_id`) ride here rather than forcing a second fixture builder.
        if let (Some(obj), Some(add)) = (envelope.as_object_mut(), extra.as_object()) {
            for (k, v) in add {
                obj.insert(k.clone(), v.clone());
            }
        }
        let (och, ed_sig, pqc_sig) =
            crate::federation::tier_ingest::test_support::sign_envelope(author, &envelope);
        let now = chrono::Utc::now();
        Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: author.to_owned(),
            attested_key_id: subject.to_owned(),
            attestation_type: att_type.to_owned(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: author.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids,
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    async fn verdict(dir: &dyn FederationDirectory, attestation_id: &str) -> LoadBearing {
        is_load_bearing(
            dir,
            ObjectRef::Attestation {
                attestation_id: attestation_id.to_owned(),
            },
        )
        .await
        .expect("is_load_bearing")
    }

    /// How many inert grants the witness plants. #563 counted 234 of them in
    /// production; the property under test is that the verdict does not depend
    /// on HOW MANY there are — an inert grant is inert one at a time.
    const INERT_GRANTS: usize = 5;

    /// The #564 stage-1 witness:
    ///
    /// - N inert `consent:replication` grants with no dependent data read `No`
    ///   (the 234-row case, made legible);
    /// - a grant naming a peer whose trace we DO retain reads `Yes` and NAMES
    ///   that trace;
    /// - `trust:accepts:v1` reads `Yes` with nothing else present at all — the
    ///   un-trust lever, declared, never inferred;
    /// - a declared-`undeclared` family reads `Unknown` naming the family;
    /// - a dimension outside the manifest reads `Unknown` too — fail-secure,
    ///   never `No` by omission.
    pub(crate) async fn exercise_load_bearing_predicate(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        use crate::federation::consent_peer_set::DIMENSION as CONSENT_REPLICATION;
        use crate::federation::tier_ingest::test_support::register_hybrid_key;

        let node = format!("lb-node-{suffix}");
        let inert_peer = format!("lb-inert-{suffix}");
        let live_peer = format!("lb-live-{suffix}");
        let root = format!("lb-root-{suffix}");
        register_hybrid_key(dir, &node).await;
        register_hybrid_key(dir, &live_peer).await;
        register_hybrid_key(dir, &root).await;

        // ── (1) THE 234-ROW CASE. Grants naming a peer this node holds
        //    nothing from: they authorize a holding that does not exist here,
        //    so they do no work here — regardless of age or author.
        let mut inert = Vec::new();
        for _ in 0..INERT_GRANTS {
            let id = uuid::Uuid::new_v4().to_string();
            dir.put_attestation(SignedAttestation {
                attestation: row(
                    &id,
                    &node,
                    &node,
                    attestation_type::SCORES,
                    CONSENT_REPLICATION,
                    vec![inert_peer.clone()],
                    serde_json::Value::Null,
                ),
            })
            .await
            .expect("inert grant admits");
            inert.push(id);
        }
        for id in &inert {
            assert_eq!(
                verdict(dir, id).await,
                LoadBearing::No,
                "an inert consent:replication grant ({id}) reduces to nothing here"
            );
        }

        // ── (2) The SAME grant shape, naming a peer whose trace we retain.
        let live_grant = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(SignedAttestation {
            attestation: row(
                &live_grant,
                &node,
                &node,
                attestation_type::SCORES,
                CONSENT_REPLICATION,
                vec![live_peer.clone()],
                serde_json::Value::Null,
            ),
        })
        .await
        .expect("live grant admits");
        assert_eq!(
            verdict(dir, &live_grant).await,
            LoadBearing::No,
            "no data retained under it yet — inert until something depends on it"
        );

        let retained_trace = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(SignedAttestation {
            attestation: row(
                &retained_trace,
                &live_peer,
                &live_peer,
                attestation_type::SCORES,
                "trace:complete:v1",
                // `trace:*` is self-emitted: the producer must appear in its
                // own `subject_key_ids` (a trace records its own reasoning).
                vec![live_peer.clone()],
                // The `trace:*` admission gate's required shape (self-emitted
                // above, identity fields + exactly one of inline/manifest
                // here) — a REAL trace, so the witness proves the predicate
                // over the row a producer actually writes.
                serde_json::json!({
                    "trace_id": format!("lb-trace-{suffix}"),
                    "agent_id_hash": "sha256:lb-fixture-agent",
                    "trace": {"step": "load-bearing witness"},
                }),
            ),
        })
        .await
        .expect("retained trace admits");

        match verdict(dir, &live_grant).await {
            LoadBearing::Yes { because } => {
                assert!(
                    because.iter().any(|d| d.object_id == retained_trace
                        && d.kind == DependencyKind::RetainedAttestation),
                    "the verdict must NAME the retained trace, not merely say yes: {because:?}"
                );
            }
            other => panic!("a grant with a retained trace under it must be Yes, got {other:?}"),
        }

        // The live data must not have changed the inert grants' verdicts —
        // load-bearing is per-object and structural, never a corpus-wide mood.
        for id in &inert {
            assert_eq!(
                verdict(dir, id).await,
                LoadBearing::No,
                "an unrelated peer's data must not make grant {id} load-bearing"
            );
        }

        // ── (3) `trust:accepts:v1` — the un-trust lever. Yes with NOTHING
        //    else present, because it is DECLARED, never inferred.
        let accepts = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(SignedAttestation {
            attestation: row(
                &accepts,
                &node,
                &root,
                attestation_type::DELEGATES_TO,
                "trust:accepts:v1",
                Vec::new(),
                serde_json::Value::Null,
            ),
        })
        .await
        .expect("trust:accepts:v1 admits");
        match verdict(dir, &accepts).await {
            LoadBearing::Yes { because } => assert!(
                because
                    .iter()
                    .any(|d| d.kind == DependencyKind::DeclaredAlways),
                "trust:accepts:v1 must be load-bearing BY DECLARATION: {because:?}"
            ),
            other => panic!("the un-trust lever must never read collectable, got {other:?}"),
        }

        // ── (4) A declared-`undeclared` family: Unknown, naming the family.
        match verdict(dir, &retained_trace).await {
            LoadBearing::Unknown { family, reason } => {
                assert_eq!(family, "trace:*");
                assert!(!reason.is_empty(), "an Unknown must carry its reason");
            }
            other => panic!("a declared-`undeclared` family must read Unknown, got {other:?}"),
        }

        // ── (5) A dimension outside the manifest: still Unknown, never `No`.
        //    `No` by omission is the one answer this primitive may not give.
        let alien = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(SignedAttestation {
            attestation: row(
                &alien,
                &node,
                &node,
                attestation_type::SCORES,
                "definitely_not_a_ciris_family:xyzzy:v1",
                Vec::new(),
                serde_json::Value::Null,
            ),
        })
        .await
        .expect("alien-dimension row admits");
        assert!(
            matches!(verdict(dir, &alien).await, LoadBearing::Unknown { .. }),
            "an unresolvable family is fail-secure Unknown, never No"
        );

        // ── (6) The key-record arm: a key NAMED by held rows is load-bearing.
        match is_load_bearing(
            dir,
            ObjectRef::KeyRecord {
                key_id: live_peer.clone(),
            },
        )
        .await
        .expect("key record verdict")
        {
            LoadBearing::Yes { because } => assert!(
                because
                    .iter()
                    .any(|d| d.kind == DependencyKind::NamingRow && d.object_id == retained_trace),
                "the key that authored a held row is load-bearing, and the row is named: \
                 {because:?}"
            ),
            other => panic!("a key naming held rows must be Yes, got {other:?}"),
        }

        // ── (7) An object this node does not hold: nothing here can depend on
        //    a copy that is not here.
        assert_eq!(
            verdict(dir, &uuid::Uuid::new_v4().to_string()).await,
            LoadBearing::No,
            "an absent object is trivially not load-bearing HERE"
        );

        // ── (8) #564 stage 2 — the ROUTE class. Absent → No; live → Yes and
        //    NAMED as reachability.
        let route_kind = "websocket";
        assert_eq!(
            is_load_bearing(
                dir,
                ObjectRef::TransportDestination {
                    occurrence_key_id: live_peer.clone(),
                    transport_kind: route_kind.to_owned(),
                },
            )
            .await
            .expect("route verdict"),
            LoadBearing::No,
            "a route this node does not hold cannot be depended on here"
        );

        dir.put_transport_destination(&crate::federation::self_at_login::TransportDestination {
            occurrence_key_id: live_peer.clone(),
            transport_kind: route_kind.to_owned(),
            destination: format!("wss://lb-fixture-{suffix}.invalid/ws"),
            asserted_at: chrono::Utc::now(),
            last_seen_at: None,
            transport_ed25519_pubkey_base64: None,
            transport_x25519_pubkey_base64: None,
            binding_provenance: crate::federation::self_at_login::BindingProvenance::default(),
            epoch: 0,
            retired_at: None,
        })
        .await
        .expect("route admits");

        match is_load_bearing(
            dir,
            ObjectRef::TransportDestination {
                occurrence_key_id: live_peer.clone(),
                transport_kind: route_kind.to_owned(),
            },
        )
        .await
        .expect("route verdict")
        {
            LoadBearing::Yes { because } => assert!(
                because
                    .iter()
                    .any(|d| d.kind == DependencyKind::ReachabilityRoute),
                "a live route IS the reachability it provides: {because:?}"
            ),
            other => panic!("a held live route must be Yes, got {other:?}"),
        }

        // A DIFFERENT transport_kind on the same occurrence is a different
        // route — the composite key must not smear across kinds.
        assert_eq!(
            is_load_bearing(
                dir,
                ObjectRef::TransportDestination {
                    occurrence_key_id: live_peer.clone(),
                    transport_kind: "reticulum".to_owned(),
                },
            )
            .await
            .expect("route verdict"),
            LoadBearing::No,
            "the verdict is per-route, not per-occurrence"
        );

        // ── (9) The DEFERRING and UNINDEXED classes read Unknown and NAME
        //    themselves — never `No`, which would be a licence to collect an
        //    object whose retention another plane owns.
        for object in [
            ObjectRef::FountainContent {
                content_id: format!("lb-content-{suffix}"),
                corpus_kind: "trace".to_owned(),
            },
            ObjectRef::HardCaseEvent {
                event_id: format!("lb-hc-{suffix}"),
            },
        ] {
            let class = object.class();
            match is_load_bearing(dir, object).await.expect("class verdict") {
                LoadBearing::Unknown { family, reason } => {
                    assert_eq!(family, class.as_str());
                    assert!(!reason.is_empty(), "an Unknown must carry its reason");
                }
                other => panic!(
                    "{} must be fail-secure Unknown, got {other:?}",
                    class.as_str()
                ),
            }
        }

        // ── (10) **THE STAGE-2 PROPERTY.** The inert grants are the ONLY
        //    objects here that read `No` — and they STILL may not be released,
        //    because persist cannot verify the copy lives anywhere else. If
        //    this ever passes, #564's second conjunct has become decorative
        //    and the 234-row case turns into 234 deletions.
        for id in &inert {
            let object = ObjectRef::Attestation {
                attestation_id: id.clone(),
            };
            assert_eq!(
                is_load_bearing(dir, object.clone())
                    .await
                    .expect("reachability half"),
                LoadBearing::No,
                "precondition: this grant is the provably-inert case"
            );
            match may_release_copy(dir, object)
                .await
                .expect("release verdict")
            {
                MayRelease::No {
                    load_bearing,
                    anti_entropy,
                } => {
                    assert_eq!(
                        load_bearing,
                        LoadBearing::No,
                        "the verdict must report the reachability half it actually computed"
                    );
                    assert!(
                        matches!(anti_entropy, AntiEntropy::Unverifiable { .. }),
                        "residence is unverifiable on this substrate, got {anti_entropy:?}"
                    );
                }
                MayRelease::Yes => panic!(
                    "grant {id} was released with NO acknowledgment plane — a copy with nowhere \
                     else to live was just declared collectable"
                ),
            }
        }

        // …and the same holds for a load-bearing object, blocked by BOTH
        // halves rather than one.
        match may_release_copy(
            dir,
            ObjectRef::Attestation {
                attestation_id: accepts.clone(),
            },
        )
        .await
        .expect("release verdict")
        {
            MayRelease::No { load_bearing, .. } => assert!(
                load_bearing.treated_as_load_bearing(),
                "trust:accepts:v1 must block on the reachability half too"
            ),
            MayRelease::Yes => panic!("the un-trust lever must never be releasable"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The family resolver honours the manifest's prefix grammar: literal,
    /// `{placeholder}`, and trailing `*`.
    #[test]
    fn dimension_resolves_to_its_manifest_family() {
        assert_eq!(
            family_for_dimension(super::super::consent_peer_set::DIMENSION),
            Some("consent:*")
        );
        assert_eq!(family_for_dimension("trust:accepts:v1"), Some("trust:*"));
        assert_eq!(family_for_dimension("trace:complete:v1"), Some("trace:*"));
        assert_eq!(
            family_for_dimension("capacity:composite"),
            Some("capacity:composite"),
            "an exact literal family matches with no wildcard"
        );
        // A `{placeholder}` consumes exactly one segment.
        assert_eq!(
            family_for_dimension("bond_posted:usd"),
            Some("bond_posted:{currency}")
        );
        // A bare prefix with nothing after it is NOT the wildcard family.
        assert_eq!(family_for_dimension("consent"), None);
        assert_eq!(
            family_for_dimension("definitely:not:a:real:family:xyzzy"),
            None
        );
    }

    /// The tokens are program constants, not prose.
    #[test]
    fn dependency_kind_tokens_match_serde() {
        for kind in [
            DependencyKind::RetainedAttestation,
            DependencyKind::NamingRow,
            DependencyKind::DeclaredAlways,
        ] {
            assert_eq!(
                serde_json::to_string(&kind).expect("serialize"),
                format!("\"{}\"", kind.as_str())
            );
        }
    }

    /// The class gate: every [`ObjectClass`] carries a policy, every policy
    /// carries a non-empty rationale, and `ALL` is complete.
    ///
    /// `object_class_policy` is an exhaustive match, so a class with no policy
    /// cannot compile; what this adds is that `ALL` did not fall behind the
    /// enum, which is the way a "complete" list actually rots.
    #[test]
    fn every_object_class_declares_a_policy() {
        for class in ObjectClass::ALL {
            let policy = object_class_policy(class);
            assert_eq!(policy.class, class, "policy must name its own class");
            assert!(
                policy.rationale.len() > 40,
                "{}: a rationale that does not explain itself is a shrug with punctuation",
                class.as_str()
            );
        }
        // ALL is complete: every arm the mapping can produce is in it.
        for object in [
            ObjectRef::Attestation {
                attestation_id: String::new(),
            },
            ObjectRef::KeyRecord {
                key_id: String::new(),
            },
            ObjectRef::TransportDestination {
                occurrence_key_id: String::new(),
                transport_kind: String::new(),
            },
            ObjectRef::FountainContent {
                content_id: String::new(),
                corpus_kind: String::new(),
            },
            ObjectRef::HardCaseEvent {
                event_id: String::new(),
            },
        ] {
            assert!(
                ObjectClass::ALL.contains(&object.class()),
                "{:?} maps to a class missing from ObjectClass::ALL",
                object.class()
            );
        }
    }

    /// **Host reachability, at the parse door.** Every declared class must be
    /// constructible from the `(kind, id, id2)` triple the FFI hands over, and
    /// the token it is constructible under must be the class's OWN token.
    ///
    /// This is the gate on the AV-77 failure: a class the predicate handles
    /// but no host can name is not shipped. Iterating `ObjectClass::ALL` means
    /// adding a class without an FFI door goes red here rather than shipping
    /// unreachable.
    #[test]
    fn every_class_is_constructible_from_host_parts() {
        for class in ObjectClass::ALL {
            // Composite-keyed classes need id2; try with, which must always work.
            let built =
                ObjectRef::from_parts(class.as_str(), "id-1", Some("id-2")).unwrap_or_else(|e| {
                    panic!("{} is not reachable from the FFI: {e}", class.as_str())
                });
            assert_eq!(
                built.class(),
                class,
                "the {:?} token built a {:?}",
                class.as_str(),
                built.class()
            );
        }
        assert!(ObjectRef::from_parts("not_a_class", "x", None).is_err());
    }

    /// A composite-keyed class REFUSES a missing second key rather than
    /// defaulting it. A defaulted `transport_kind` would answer confidently
    /// about a route the caller never asked about.
    #[test]
    fn composite_keyed_classes_refuse_a_missing_second_key() {
        for (kind, missing) in [
            ("transport_destination", "transport_kind"),
            ("fountain_content", "corpus_kind"),
        ] {
            let err = ObjectRef::from_parts(kind, "id-1", None)
                .expect_err("a composite-keyed class must refuse a missing second key");
            assert!(
                err.contains(missing),
                "the refusal must NAME the missing key, got {err:?}"
            );
        }
        // The single-keyed classes are unaffected by id2 being absent.
        for kind in ["attestation", "key_record", "hard_case_event"] {
            assert!(ObjectRef::from_parts(kind, "id-1", None).is_ok());
        }
    }

    /// The class tokens are program constants, not prose.
    #[test]
    fn object_class_tokens_match_serde() {
        for class in ObjectClass::ALL {
            assert_eq!(
                serde_json::to_string(&class).expect("serialize"),
                format!("\"{}\"", class.as_str())
            );
        }
    }

    /// **The stage-2 safety property.** Nothing on this substrate may produce
    /// [`AntiEntropy::Satisfied`], because persist cannot verify that any
    /// object resides anywhere else — no transport, no acknowledgment record.
    ///
    /// A SOURCE SCAN, not a call-site check: the failure this guards is
    /// somebody adding a `Satisfied` producer to make a stage-3 release path
    /// go green, and a behavioural test over today's call graph would not see
    /// that. Same discipline `family_rules.rs` uses to close its own loop —
    /// over-reporting is the safe direction here.
    #[test]
    fn nothing_yields_anti_entropy_satisfied_today() {
        // The needles are ASSEMBLED at runtime, never written contiguously, so
        // this scanner does not match its own source. A scan that trips on
        // itself is a scan nobody can keep green, and it would be silenced.
        let qualified = ["AntiEntropy", "Satisfied"].join("::");
        let via_self = ["Self", "Satisfied"].join("::");

        let mut sources: Vec<(String, String)> = Vec::new();
        fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
            let Ok(rd) = std::fs::read_dir(dir) else {
                return;
            };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    if let Ok(t) = std::fs::read_to_string(&p) {
                        out.push((p.display().to_string(), t));
                    }
                }
            }
        }
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut sources,
        );
        assert!(
            sources.len() > 20,
            "the source walk collapsed ({} files) — this gate would pass vacuously",
            sources.len()
        );

        let mut producers: Vec<String> = Vec::new();
        for (path, text) in &sources {
            for (i, line) in text.lines().enumerate() {
                let t = line.trim_start();
                if t.starts_with("//") {
                    continue;
                }
                if !(t.contains(&qualified) || t.contains(&via_self)) {
                    continue;
                }
                // `matches!(self, Self::Satisfied { .. })` in `is_satisfied`
                // READS the variant; it does not construct one.
                if t.contains("matches!") {
                    continue;
                }
                producers.push(format!("  {}:{}: {}", path, i + 1, t));
            }
        }
        assert!(
            producers.is_empty(),
            "the `{qualified}` variant is constructed somewhere in src/. It must not be, until \
             an acknowledgment plane exists that can PROVE a peer holds the object — otherwise \
             `may_release_copy` starts returning Yes and #564's second conjunct becomes \
             decorative, which turns the 234-row case into 234 deletions. Found:\n{}",
            producers.join("\n")
        );
        // And the honest value is the fail-secure one.
        assert!(!AntiEntropy::Unverifiable {
            reason: String::new()
        }
        .is_satisfied());
        assert!(!AntiEntropy::NotSatisfied {
            reason: String::new()
        }
        .is_satisfied());
    }

    /// **Fail-secure, end to end**: with no acknowledgment plane, `Yes` is
    /// unreachable REGARDLESS of the reachability half. Even a proven `No`
    /// from `is_load_bearing` must not release, because the copy may have
    /// nowhere else to live.
    ///
    /// Constructed directly rather than through a backend so the property is
    /// asserted over the whole verdict space, not one fixture's corner of it.
    #[test]
    fn may_release_is_unreachable_without_an_acknowledgment_plane() {
        let unverifiable = AntiEntropy::Unverifiable {
            reason: "no acknowledgment plane".into(),
        };
        for load_bearing in [
            LoadBearing::No,
            LoadBearing::Yes {
                because: Vec::new(),
            },
            LoadBearing::Unknown {
                family: "whatever".into(),
                reason: "no predicate".into(),
            },
        ] {
            // This mirrors `may_release_copy`'s conjunct exactly.
            let releasable = matches!(load_bearing, LoadBearing::No) && unverifiable.is_satisfied();
            assert!(
                !releasable,
                "no verdict may release while residence is unverifiable, got a release for \
                 {load_bearing:?}"
            );
        }
        assert!(!MayRelease::No {
            load_bearing: LoadBearing::No,
            anti_entropy: unverifiable,
        }
        .is_releasable());
        assert!(MayRelease::Yes.is_releasable());
    }

    /// The deferring / unindexed classes resolve `Unknown` and NAME themselves
    /// — never `No`. A `No` here would be a licence to collect an object whose
    /// retention another plane owns.
    #[test]
    fn deferred_and_unindexed_classes_are_fail_secure_unknown() {
        for class in [ObjectClass::FountainContent, ObjectClass::HardCaseEvent] {
            match deferred_or_unindexed(class, "obj-1") {
                LoadBearing::Unknown { family, reason } => {
                    assert_eq!(family, class.as_str(), "an Unknown must name its class");
                    assert!(
                        reason.contains("obj-1"),
                        "the reason must name the object it is about: {reason}"
                    );
                }
                other => panic!(
                    "{} must be fail-secure Unknown, got {other:?}",
                    class.as_str()
                ),
            }
            assert!(deferred_or_unindexed(class, "obj-1").treated_as_load_bearing());
        }
    }

    /// **Fail-secure**: `Unknown` is treated as load-bearing. Only a proven
    /// `No` is not. If this ever inverted, an undeclared family would become a
    /// licence to collect — the exact failure the whole axis exists to prevent.
    #[test]
    fn unknown_is_treated_as_load_bearing() {
        assert!(LoadBearing::Yes { because: vec![] }.treated_as_load_bearing());
        assert!(LoadBearing::Unknown {
            family: "whatever".into(),
            reason: "no predicate".into(),
        }
        .treated_as_load_bearing());
        assert!(!LoadBearing::No.treated_as_load_bearing());
    }
}
