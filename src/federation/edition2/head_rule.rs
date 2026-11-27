//! v62.0.0 (HEAD-1; CC 2.4.1.1 "The end of a standing", CC 2.7.8) — **the
//! head rule**: which head (`refs.head`) a row names, and the one resolver
//! that finds it.
//!
//! *An act names its head.* A row signed in exercise of a standing names the
//! head it is at: for a seat in a room or a family, the roster version; for a
//! grant from a root (and an accord holder's act), the bundle in force; for an
//! owner binding, the binding row; for a delegation outside a room, the
//! `delegates_to` row. A row exercising no standing names none (CC 2.4.1.1).
//!
//! Three layers, each one function:
//!
//! - [`names_head`] — the family model's `names_head` column (Constitution
//!   rc22 commit [`NAMES_HEAD_SOURCE_COMMIT`], 76c4550), one value per family
//!   in [`NAMES_HEAD_TABLE`]. **When the one family table carries the column
//!   (`namespace::family_table`, FS-step1), this body becomes one line:**
//!   `FamilyTable::get().names_head(family_id, leaf).map(..)`, and the table
//!   constant here is deleted. Nothing else reads the constant.
//! - [`head_kind`] — pure: the column, the row's placement and the signer's
//!   capacity give the KIND of head ([`HeadKind`]). The producer and the door
//!   both ask it, so they cannot disagree on whether a row names a head.
//! - [`resolve`] — the producer's read of the actual row for a kind: the
//!   roster version the node holds for the room or family, the bundle in
//!   force, the counted owner's binding row, the signer's live `delegates_to`
//!   (the lowest row id when several). [`state_head`] joins it into a
//!   payload's `refs`, never replacing a head the payload already names.
//!
//! Kernel's cautions (FREEZE, "KERNEL: NO pin move"): nothing here routes
//! through `head::View` `counts_at` / `carried`, nor `seat::exercised_stands`.
//! No instant decides anything here.

use std::collections::HashMap;
use std::sync::OnceLock;

use ciris_verify_core::cde::Value;
use ciris_verify_core::namespace_match;

use super::names::{names_of, single, RowId};
use crate::federation::types::{attestation_type, cohort_scope, identity_type};
use crate::federation::{Error, FederationDirectory};

/// The Constitution commit whose `manifests/family_model.json` `names_head`
/// column [`NAMES_HEAD_TABLE`] copies (rc22, "The family model says which
/// head a row of each family names"; file sha256 `c501487e…74705805`).
pub const NAMES_HEAD_SOURCE_COMMIT: &str = "76c45508774855571ae384a02f794bc878d0e142";

/// The family model's `names_head` vocabulary (CC 2.4.1.1, CC 2.7.8). The
/// variant names are FS-step1's (`namespace::family_table::NamesHead`), so the
/// swap to the table read is a rename of the import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamesHead {
    /// Placed only at a room's or a family's scope: names that roster's
    /// version.
    Roster,
    /// Signed under a seat, a grant or a binding outside any roster: names
    /// the record that seats the signer.
    Standing,
    /// A row of its signer's own, exercising no conferred standing.
    NoHead,
    /// Placed at several scopes: the roster's version at a room or family;
    /// at self none, unless its signer signs as someone's node, agent or
    /// delegate, and then that binding or delegation.
    ByPlacement,
}

use self::NamesHead::{ByPlacement, NoHead, Roster, Standing};

/// Constitution 76c4550's `names_head` column, one row per family (190), by
/// the family's prefix as the model spells it. `None` is the model's `null`:
/// "the placement cell is unread" (eleven families, open: Constitution has
/// them to rule). Generated from the column, not typed by hand.
pub const NAMES_HEAD_TABLE: &[(&str, Option<NamesHead>)] = &[
    ("accord:*", Some(ByPlacement)),
    ("accord:human_dignity", Some(ByPlacement)),
    ("accord:invoke:constitutional:{halt_id}", Some(ByPlacement)),
    ("accord:invoke:drill:{drill_id}", Some(ByPlacement)),
    ("accord:invoke:notify:{notify_id}", Some(ByPlacement)),
    ("accord:lifecycle", Some(ByPlacement)),
    ("accord:lifecycle:{kind}", Some(ByPlacement)),
    ("act:ack", None),
    ("activity_tier:{period}", Some(ByPlacement)),
    ("admission:unit", None),
    ("age_assurance:{level}:{band}:{version}", Some(ByPlacement)),
    ("age_self_declared:band:{band}:{version}", Some(ByPlacement)),
    ("agent_files:{kind}:{platform_or_target}", Some(ByPlacement)),
    ("approach:{goal_id}", Some(ByPlacement)),
    ("archive_release:{basis}", None),
    ("attestation:agent_integrity", Some(ByPlacement)),
    ("attestation:hardware_rooted", Some(ByPlacement)),
    ("attestation:license_validity", Some(ByPlacement)),
    ("attestation:registry_consensus", Some(NoHead)),
    ("attestation:self_verify", Some(ByPlacement)),
    ("audio:*", Some(ByPlacement)),
    ("audit_chain:hash_continuity", Some(ByPlacement)),
    ("autonomy:{aspect}", Some(ByPlacement)),
    ("ballot:moderator", Some(Roster)),
    ("ballot:moderator_acceptance", Some(Roster)),
    ("ballot:tally:{poll_id}", Some(Roster)),
    ("benchmark:he300:{category}:{version}", Some(ByPlacement)),
    ("beneficence:{aspect}", Some(ByPlacement)),
    ("blog:*", Some(ByPlacement)),
    ("bond_posted:{currency}", Some(ByPlacement)),
    ("build:registered:{target}", Some(ByPlacement)),
    ("capacity:composite", Some(ByPlacement)),
    ("capacity:relay_delivery", Some(ByPlacement)),
    ("capacity:{factor}", Some(ByPlacement)),
    (
        "capacity_assurance:reversible_excluded:{domain}:{version}",
        Some(ByPlacement),
    ),
    (
        "capacity_assurance:reversible_pending:{domain}:{version}",
        Some(ByPlacement),
    ),
    (
        "capacity_assurance:{level}:{domain}:{band}:{version}",
        Some(ByPlacement),
    ),
    ("census:composite:{class}", Some(Standing)),
    ("census:expected_active", Some(Roster)),
    ("census:member:partial", Some(Roster)),
    ("census:member:share", Some(Standing)),
    ("census:partial:{class}", Some(Standing)),
    ("census:share:{class}", Some(NoHead)),
    ("cert_validity:{authority}", Some(ByPlacement)),
    ("chat:*", Some(ByPlacement)),
    ("coherence_standing:{cohort}", Some(ByPlacement)),
    ("collection:{kind}", Some(ByPlacement)),
    (
        "commitment_fulfillment:{prior_contribution_id}",
        Some(ByPlacement),
    ),
    ("community:listing", Some(Standing)),
    ("config:{scope}", Some(ByPlacement)),
    ("conscience:coherence", Some(ByPlacement)),
    ("conscience:entropy", Some(ByPlacement)),
    ("conscience:epistemic_humility", Some(ByPlacement)),
    ("conscience:optimization_veto", Some(ByPlacement)),
    ("consent:community_trust", Some(ByPlacement)),
    ("consent:decay:{stage}", Some(ByPlacement)),
    ("consent:deletion_complete", Some(ByPlacement)),
    ("consent:deletion_sla:{days}", Some(ByPlacement)),
    ("consent:partnership_accept", Some(ByPlacement)),
    ("consent:partnership_grant", Some(ByPlacement)),
    ("consent:replication:{version}", Some(ByPlacement)),
    ("consent:scope:{kind}", Some(ByPlacement)),
    ("consent:state:{stance}", Some(ByPlacement)),
    ("consent:stream:{kind}", Some(ByPlacement)),
    ("consent:{kind}", Some(ByPlacement)),
    ("content_class:{class}", Some(ByPlacement)),
    ("content_rating:{scheme}:{rating}", Some(ByPlacement)),
    ("contribution:{subject_kind}", None),
    ("corpus_health:n_eff_measurable", Some(ByPlacement)),
    ("cosign:{state}", Some(Roster)),
    ("credits:{domain}:{language}:{subject}", Some(ByPlacement)),
    ("custody:{kind}", Some(NoHead)),
    ("cw_class:{class}", Some(ByPlacement)),
    ("deferral:request", Some(ByPlacement)),
    ("deferral:response:{outcome}", Some(ByPlacement)),
    ("delivery:{class}", Some(ByPlacement)),
    ("delivery_receipt:{stream_id}", Some(ByPlacement)),
    ("detection:correlated_action:{axis}", Some(ByPlacement)),
    (
        "detection:distributive:access:{resource_type}",
        Some(ByPlacement),
    ),
    ("detection:hash_chain_integrity", Some(ByPlacement)),
    ("detection:intra_agent_consistency", Some(ByPlacement)),
    ("detection:{detector}", Some(ByPlacement)),
    ("device:label", Some(Standing)),
    ("dma:csdma:*", Some(ByPlacement)),
    ("dma:dsdma:{domain}:*", Some(ByPlacement)),
    ("dma:idma:*", Some(ByPlacement)),
    ("dma:pdma:*", Some(ByPlacement)),
    ("duty:{kind}", Some(NoHead)),
    ("encyclopedia:*", Some(ByPlacement)),
    ("event:attendance", Some(ByPlacement)),
    ("event:lifecycle:{state}", Some(ByPlacement)),
    ("event:rsvp_count", Some(ByPlacement)),
    ("evidence:{suite}:{kind}:{cell}:{prefix}", Some(Standing)),
    ("expertise:{domain}:{language}", Some(ByPlacement)),
    ("federation_directory:replication_lag", Some(ByPlacement)),
    ("fidelity:explainability_sla:{tier}", Some(ByPlacement)),
    ("fidelity:{aspect}", Some(ByPlacement)),
    ("file:{version}", Some(ByPlacement)),
    ("film:*", Some(ByPlacement)),
    ("goal:{scale}", Some(ByPlacement)),
    ("group:roster", Some(Roster)),
    ("hard_case:{kind}", Some(ByPlacement)),
    ("hardware_custody:{platform}", Some(ByPlacement)),
    ("health:liveness:{version}", Some(ByPlacement)),
    (
        "identity:canonical_binding:{canonical_hash}",
        Some(ByPlacement),
    ),
    ("identity:occurrence", Some(NoHead)),
    ("identity:occurrence_revocation", Some(NoHead)),
    ("identity_amendment", Some(ByPlacement)),
    ("identity_continuity:relational_anchor", Some(ByPlacement)),
    ("image:*", Some(ByPlacement)),
    ("integrity:{aspect}", Some(ByPlacement)),
    ("judge_model:verdict:{model_id}", Some(ByPlacement)),
    ("justice:{aspect}", Some(ByPlacement)),
    ("key:record", Some(NoHead)),
    ("key:revocation", Some(NoHead)),
    ("key_boundary:{scope}", Some(ByPlacement)),
    ("key_grant:{axis}", Some(Standing)),
    ("lawful_order:release", None),
    ("ledger:checkpoint:{unit}:{version}", Some(ByPlacement)),
    ("ledger:head:{unit}:{version}", Some(ByPlacement)),
    ("ledger:promotion:{version}", Some(ByPlacement)),
    ("licensure:{authority_id}", Some(ByPlacement)),
    ("lineage_witness:{stage}", Some(ByPlacement)),
    ("locality:decision:{scale}", Some(ByPlacement)),
    ("location_proof:{version}", None),
    ("manifold_conformity:{cohort}", Some(ByPlacement)),
    ("membership:{stage}", Some(Roster)),
    ("mesh_config:{key}", Some(ByPlacement)),
    ("method:{approach_id}:{substrate_rung}", Some(ByPlacement)),
    ("model_3d:*", Some(ByPlacement)),
    ("moderation:{allegation_type}", Some(ByPlacement)),
    (
        "moderation_track_record:{community_key_id}",
        Some(ByPlacement),
    ),
    (
        "multilateral_participation:{forum}:{kind}",
        Some(ByPlacement),
    ),
    ("need:{domain}:{kind}", Some(NoHead)),
    ("news:*", Some(ByPlacement)),
    ("non_maleficence:{aspect}", Some(ByPlacement)),
    ("objection:{state}", Some(ByPlacement)),
    ("observation:access_assumption", Some(ByPlacement)),
    ("observation:reachability", Some(ByPlacement)),
    (
        "ownership:{relation}:{target_kind}:{version}",
        Some(Standing),
    ),
    ("partner_role:{role}", Some(ByPlacement)),
    ("peer_reachability:{network}", Some(ByPlacement)),
    ("preserve_request", None),
    ("preserve_response", None),
    ("progress_measure:{method_id}", Some(ByPlacement)),
    ("prohibited:{category}", Some(ByPlacement)),
    ("provenance:build_manifest:{target}", Some(NoHead)),
    (
        "provenance:build_manifest:{target}:locale:{lang_code}",
        Some(ByPlacement),
    ),
    ("provenance:skill_import:{source}", Some(ByPlacement)),
    ("provenance:slsa:{level}", Some(ByPlacement)),
    ("quarantine:{state}", Some(ByPlacement)),
    ("ratchet:flag:coordinated_voting_cluster", Some(ByPlacement)),
    ("ratchet:flag:counter_rii:{layer}", Some(ByPlacement)),
    ("ratchet:flag:density_anomaly", Some(ByPlacement)),
    (
        "ratchet:flag:expertise_attestation_anomaly",
        Some(ByPlacement),
    ),
    ("ratchet:flag:harassment_pattern", Some(ByPlacement)),
    ("ratchet:flag:out_of_distribution_voting", Some(ByPlacement)),
    ("reconsideration:{grounds}", Some(ByPlacement)),
    ("regime:{artifact}:{version}", Some(ByPlacement)),
    ("rendezvous:route", Some(NoHead)),
    ("retirement:{state}", None),
    ("revocation:{entity_type}:{reason}", Some(ByPlacement)),
    ("rollback_detected:{revision_field}", Some(ByPlacement)),
    ("seed_holder_voting_alignment:{cell}", Some(ByPlacement)),
    ("self:delegates_to", Some(ByPlacement)),
    ("self:delegates_to:agent_occurrence", Some(ByPlacement)),
    ("session:{kind}", Some(ByPlacement)),
    ("settlement:*", Some(ByPlacement)),
    ("slashing:{outcome}", Some(ByPlacement)),
    ("stream:head", None),
    ("system:*", Some(ByPlacement)),
    ("takedown_notice:{basis}", Some(ByPlacement)),
    ("testimonial_witness:{kind}", Some(NoHead)),
    ("topical_relation:{kind}", Some(ByPlacement)),
    ("trace:{form}:{version}", Some(ByPlacement)),
    ("trace_summary:{kind}", Some(ByPlacement)),
    ("transparency_log:consistency", Some(ByPlacement)),
    ("transparency_log:cosigned:{tree_size}", Some(ByPlacement)),
    ("transparency_log:inclusion", Some(ByPlacement)),
    ("transport:canonical_rebind", Some(ByPlacement)),
    ("transport:{kind}", Some(ByPlacement)),
    ("trust:blessing", None),
    ("trust:{job}:{version}", Some(ByPlacement)),
    ("truth_grounding:{subject}", Some(ByPlacement)),
    ("video:*", Some(ByPlacement)),
    ("vote:{contribution_id}", Some(ByPlacement)),
    ("wa_adjudication:{state}", Some(ByPlacement)),
    ("watchlist:{id}", Some(Roster)),
    ("weighted_aggregate:{contribution_id}", Some(ByPlacement)),
    ("witness_diversity:{contribution_id}", Some(ByPlacement)),
];

/// v62.0.0 (HEAD-4) — **the cells Constitution ruled by hand on 2026-11-22**
/// (P/FREEZE.md, "CONSTITUTION RULED names_head CELLS", into the next pre
/// tag), over [`NAMES_HEAD_TABLE`]: the cells it had doubted or left open.
/// They win over the 76c4550 column, and both go when the one family table
/// carries the tag's column. The two cells a leaf or the authorship selects
/// are read in [`head_kind`]: `trust:{job}:{version}` (accepts none, a
/// counted confers the bundle, charter none) and `admission:unit` (its own
/// payload rule, `payloads::check_admission_unit`). `ownership:*` is none
/// here; a binding naming an affiliation names that roster's version, which
/// its own door already requires (`admission::check_owner_binding_counted`).
/// The held-shut families stay open.
pub const RULED_CELLS: &[(&str, Option<NamesHead>)] = &[
    ("custody:{kind}", Some(Standing)),
    ("contribution:{subject_kind}", Some(Standing)),
    ("census:share:{class}", Some(Standing)),
    ("census:member:share", Some(Standing)),
    ("census:composite:{class}", Some(Standing)),
    ("census:partial:{class}", Some(Standing)),
    ("device:label", Some(NoHead)),
    ("ownership:{relation}:{target_kind}:{version}", Some(NoHead)),
    ("location_proof:{version}", Some(NoHead)),
    ("trust:{job}:{version}", Some(Standing)),
    ("trust:blessing", Some(Standing)),
    ("attestation:registry_consensus", Some(Roster)),
    ("community:listing", Some(Roster)),
    ("duty:{kind}", Some(ByPlacement)),
    ("act:ack", Some(ByPlacement)),
    ("stream:head", Some(ByPlacement)),
    ("key_grant:{axis}", Some(Standing)),
    ("admission:unit", Some(Roster)),
    // v62.0.0 (HEAD-6a; Constitution's ruling on the halt, relayed by
    // Verify, into CC 4.2.1.1) — a halt INVOCATION names no head: it has no
    // place in causal order by design (it fires on receipt, is pre-signable,
    // and its holder's standing is read at the roster the receiving node
    // holds in force when it arrives). Verify's invocation payload stays
    // closed. The lifecycle rows keep `refs.head` = the bundle.
    ("accord:invoke:constitutional:{halt_id}", Some(NoHead)),
    ("accord:invoke:notify:{notify_id}", Some(NoHead)),
    ("accord:invoke:drill:{drill_id}", Some(NoHead)),
];

/// The column by family id (header -70002), built once.
fn column() -> &'static HashMap<String, Option<NamesHead>> {
    static COLUMN: OnceLock<HashMap<String, Option<NamesHead>>> = OnceLock::new();
    COLUMN.get_or_init(|| {
        NAMES_HEAD_TABLE
            .iter()
            .chain(RULED_CELLS)
            .map(|(prefix, v)| (namespace_match::family_id(prefix), *v))
            .collect()
    })
}

/// **The family model's `names_head` for `family_id`** (header -70002) at
/// `leaf`. `None`: an open family (the model's `null`) or a family the model
/// does not list. 76c4550 states no per-leaf cell, so `leaf` is not read yet;
/// it is in the signature because the table's accessor takes it.
///
/// THE SWAP: when `namespace::family_table` carries the column, this body is
/// `crate::federation::namespace::family_table::FamilyTable::get().names_head(family_id, leaf)`
/// (with [`NamesHead`] re-exported from there) and [`NAMES_HEAD_TABLE`] goes.
#[must_use]
pub fn names_head(family_id: &str, leaf: Option<&str>) -> Option<NamesHead> {
    let _ = leaf;
    column().get(family_id).copied().flatten()
}

/// Where a row is placed, read from its `cohort_scope` (CC 2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// `community`: a room.
    Room,
    /// `family`.
    Family,
    /// `self`.
    Own,
    /// Every other cohort (`affiliations`, `species`, `biosphere`,
    /// `federation`, the commons), and an absent `cohort_scope` (the earlier
    /// default, `federation`).
    Elsewhere,
}

impl Placement {
    /// The placement a `cohort_scope` value names.
    #[must_use]
    pub fn of_scope(scope: Option<&str>) -> Self {
        match scope {
            Some(cohort_scope::COMMUNITY) => Self::Room,
            Some(cohort_scope::FAMILY) => Self::Family,
            Some(cohort_scope::SELF) => Self::Own,
            _ => Self::Elsewhere,
        }
    }

    /// A payload's placement.
    #[must_use]
    pub fn of_payload(payload: &Value) -> Self {
        Self::of_scope(payload.get_text("cohort_scope").and_then(Value::as_text))
    }

    /// At a room's or a family's scope?
    #[must_use]
    pub fn in_a_roster(self) -> bool {
        matches!(self, Self::Room | Self::Family)
    }
}

/// In what capacity the signer signs the row: which of its standings, if
/// any, the row exercises (CC 2.4.1.1's five: a seat, a root grant, an
/// accord holder's act, an owner binding, a delegation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerCapacity {
    /// A person in its own right: no conferred standing.
    Person,
    /// A seat holder acting for a room or family outside its scope (a
    /// founder's or moderator's listing).
    Seat,
    /// A node acting for its owner (its key's `identity_type` holds `node`).
    Node,
    /// An agent acting for its owner (`agent`).
    Agent,
    /// A delegate under a `delegates_to` (a reserved duty: `infra:detect`,
    /// `infra:attest:*`).
    Delegate,
    /// An accord holder, a voice of the root's count over the bundle in
    /// force.
    RootHolder,
    /// v62.0.0 (HEAD-4.rev2; Constitution, head cases (1) and the lead's
    /// relay of case 2) — a signer acting under a grant from the root: a
    /// reserved family whose rule names a delegation scope, conferred by a
    /// `trust:confers` edge. Its act names the bundle in force, not the
    /// grant row.
    RootGrantee,
}

/// The kind of head a row names: what [`resolve`] reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadKind {
    /// The roster version of the room or family the row is placed at (or
    /// the seat's room).
    Roster,
    /// The bundle in force (its object id, as halt lifecycle rows name it).
    Bundle,
    /// The signer's owner binding row.
    OwnerBinding,
    /// The signer's `delegates_to` row.
    Delegation,
    /// No head: the row exercises no standing.
    NoHead,
    /// The model leaves the family open (`null`): persist states what the
    /// producer gives and the door requires nothing (back to Constitution).
    Open,
}

impl HeadKind {
    /// Must a row of this kind name a head?
    #[must_use]
    pub fn requires_a_head(self) -> bool {
        matches!(
            self,
            Self::Roster | Self::Bundle | Self::OwnerBinding | Self::Delegation
        )
    }
}

/// The conferral records themselves: a row of these IS the record a
/// standing is read from, and its own head rule is its family's, not this
/// one. A `group:roster` version names the version it extends (CC 2.6.1.9;
/// version 1 names none, `payloads::check_prose`); an owner binding names
/// none (Constitution, 11-22 answer (3): "an owner binding their own node
/// names none"), so the bound node's second voice on it is no act at its
/// binding either.
const CONFERRAL_RECORDS: &[&str] = &[
    "group:roster",
    "ownership:{relation}:{target_kind}:{version}",
];

/// Families whose head Constitution ruled directly (FREEZE, "CONSTITUTION
/// RULED THE CONFERRAL END", *THE HEAD by standing*): "key grant → the
/// room's roster version if the asset is in a room, else none", whoever
/// seals it (the minter, the owner, a moderator, a node for its owner).
const ROSTER_IN_A_ROOM_ELSE_NONE: &[&str] = &["key_grant:{axis}"];

/// Acceptances (Constitution, 11-22 answer (3): "an ACCEPTANCE needs no
/// head"): `(family prefix, leaf)`, a `None` leaf for every leaf.
const ACCEPTANCES: &[(&str, Option<&str>)] = &[
    ("trust:{job}:{version}", Some("accepts")),
    ("consent:partnership_accept", None),
    ("ballot:moderator_acceptance", None),
    ("membership:{stage}", Some("acceptance")),
    ("membership:{stage}", Some("decline")),
];

/// Families whose signer acts as a seat holder of the room it names when
/// the row is placed outside that room (`community:listing`: a founder or a
/// named `moderate`-holder, `public_room::check_community_listing_admission`).
const SEATED_OUTSIDE_THE_ROOM: &[&str] = &["community:listing"];

fn listed(prefixes: &[&str], family_id: &str) -> bool {
    prefixes
        .iter()
        .any(|p| namespace_match::family_id(p) == family_id)
}

/// Is a row of `family_id` at `leaf` an acceptance ([`ACCEPTANCES`])?
#[must_use]
pub fn is_acceptance(family_id: &str, leaf: Option<&str>) -> bool {
    ACCEPTANCES
        .iter()
        .any(|(p, l)| namespace_match::family_id(p) == family_id && (l.is_none() || *l == leaf))
}

/// Is a row of `family_id` a conferral record ([`CONFERRAL_RECORDS`])?
#[must_use]
pub fn is_conferral_record(family_id: &str) -> bool {
    listed(CONFERRAL_RECORDS, family_id)
}

/// The standing a capacity exercises outside any roster.
fn standing_of(capacity: SignerCapacity) -> HeadKind {
    match capacity {
        SignerCapacity::Person => HeadKind::NoHead,
        SignerCapacity::Seat => HeadKind::Roster,
        SignerCapacity::Node | SignerCapacity::Agent => HeadKind::OwnerBinding,
        SignerCapacity::Delegate => HeadKind::Delegation,
        SignerCapacity::RootHolder | SignerCapacity::RootGrantee => HeadKind::Bundle,
    }
}

/// **THE head rule** (CC 2.4.1.1, CC 2.7.8; the `names_head` column): the
/// kind of head a row of `family_id` at `leaf`, placed at `placement` and
/// signed in `capacity`, names. Pure; the producer ([`state_head`]) and the
/// door ask this one function.
///
/// - an open family ([`names_head`] `None`) is [`HeadKind::Open`];
/// - a conferral record, an acceptance and a row over another row's
///   payload name none; a key grant names the roster in a room, else none;
/// - `none`: none; `roster`: the roster version;
/// - `standing`: the roster version when placed in a room or family (a key
///   grant over an asset in a room: Constitution's ruling), else the record
///   that seats the signer, by capacity;
/// - `by_placement`: at a room or family, the roster version; at self, the
///   binding or delegation of a node, agent or delegate, else none;
///   elsewhere (the commons, which the column's note does not name) the
///   record that seats the signer, by capacity.
///
/// "Two live standings, prefer the roster": a row placed in a room names the
/// roster whatever its signer's capacity.
#[must_use]
pub fn head_kind(
    family_id: &str,
    leaf: Option<&str>,
    placement: Placement,
    capacity: SignerCapacity,
) -> HeadKind {
    let Some(column) = names_head(family_id, leaf) else {
        return HeadKind::Open;
    };
    if is_conferral_record(family_id) || is_acceptance(family_id, leaf) {
        return HeadKind::NoHead;
    }
    // A row over another row's payload (`cosign:{state}`) signs the EVENT's
    // payload: the event names its head, and nothing is added here.
    if listed(super::payloads::OVER_THE_EVENT, family_id) {
        return HeadKind::NoHead;
    }
    // v62.0.0 (HEAD-4; Constitution's ruling) — the trust family by leaf:
    // `accepts` none (its `attached_head_digest` stays an envelope member),
    // a COUNTED `confers` the bundle's object id, `charter` none.
    if super::typed::is_trust_family(family_id) {
        return match (leaf, capacity) {
            (Some("confers"), SignerCapacity::RootHolder) => HeadKind::Bundle,
            _ => HeadKind::NoHead,
        };
    }
    // `admission:unit`: counted (no `author`) names its roster head, authored
    // at self none; whether a row is counted is its `author`, read by its own
    // payload rule (`payloads::check_admission_unit`), not here.
    if family_id == super::payloads::ADMISSION_UNIT_FAMILY {
        return HeadKind::NoHead;
    }
    if listed(ROSTER_IN_A_ROOM_ELSE_NONE, family_id) {
        return if placement.in_a_roster() {
            HeadKind::Roster
        } else {
            HeadKind::NoHead
        };
    }
    match column {
        NoHead => HeadKind::NoHead,
        Roster => HeadKind::Roster,
        // v62.0.0 (HEAD-4; Constitution's ruling) — `standing` names the
        // record that seats the signer WHEREVER the row is placed (a custody
        // report: "the node's owner-binding row wherever the blob is
        // placed"); the key grant's room rule is above.
        Standing => standing_of(capacity),
        // v62.0.0 (HEAD-4.rev2; Constitution, head cases (1)) — the commons
        // has no roster, so `by_placement` there reads exactly as at self: a
        // node's or agent's row names its binding, a root-grant act the
        // bundle, a delegate's the delegation, a person's own row none.
        ByPlacement => match placement {
            Placement::Room | Placement::Family => HeadKind::Roster,
            Placement::Own | Placement::Elsewhere => standing_of(capacity),
        },
    }
}

/// **The signer's capacity** for a row of `family_id`, read from what the
/// row and the signer's key record state (no directory read):
///
/// - a `node` / `agent` key acts for its owner;
/// - an `accord_holder` voicing a COUNTED row (no `author`) of the trust
///   family, a seat re-bind or an accord family is a voice of the root's
///   count;
/// - a person on a reserved family whose rule names a delegation scope
///   (`admission::default_reserved_prefix_rules`) acts as a delegate;
/// - a person on a family seated outside its room ([`SEATED_OUTSIDE_THE_ROOM`])
///   acts as a seat;
/// - anyone else as a person.
///
/// `identity_types` is the key record's `identity_type` set.
#[must_use]
pub fn capacity_of(
    identity_types: &[String],
    family_id: &str,
    dimension: Option<&str>,
    counted: bool,
) -> SignerCapacity {
    let holds = |t: &str| identity_types.iter().any(|x| x == t);
    if holds(identity_type::NODE) {
        return SignerCapacity::Node;
    }
    if holds(identity_type::AGENT) {
        return SignerCapacity::Agent;
    }
    let root_family = super::typed::is_trust_family(family_id)
        || family_id == "trust:blessing"
        || family_id == namespace_match::family_id("transport:canonical_rebind")
        || family_id.starts_with("accord:");
    if holds(identity_type::ACCORD_HOLDER) && counted && root_family {
        return SignerCapacity::RootHolder;
    }
    if let Some(d) = dimension {
        // v62.0.0 (D1) — a ROOT's grant only: an owner-conferred duty (a
        // node's report about itself) is read in the node's owner binding,
        // and a person signing such a row exercises no standing.
        let delegated = crate::federation::admission::default_reserved_prefix_rules()
            .iter()
            .any(|r| {
                d.starts_with(&r.pattern_prefix)
                    && r.required_delegation_scope.is_some()
                    && r.conferred_by == crate::federation::admission::DutyConferrer::TrustedRoot
            });
        if delegated {
            return SignerCapacity::RootGrantee;
        }
    }
    if listed(SEATED_OUTSIDE_THE_ROOM, family_id) {
        return SignerCapacity::Seat;
    }
    SignerCapacity::Person
}

/// The identity types a comma-joined `identity_type` column holds.
#[must_use]
pub fn identity_types_of(joined: &str) -> Vec<String> {
    joined
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Does a row of this type exercise a standing at its own head? A
/// `withdraws` / `recants` ENDS (or retracts): its head is the end's
/// (HEAD-3), not this rule's. A `supersedes` is the act again.
#[must_use]
pub fn row_type_acts(row_type: &str) -> bool {
    !super::emit::carries_no_dimension(row_type)
}

/// Does `payload` name a head (`refs.head`)?
#[must_use]
pub fn names_a_head(payload: &Value) -> bool {
    names_of(payload)
        .ok()
        .and_then(|n| single(&n, "head"))
        .is_some()
}

/// The group a row's roster head is read from: its `community_id`, else its
/// `family_id`, else (a row placed "at the group", `membership:{stage}`) its
/// `group`.
#[must_use]
pub fn group_of(payload: &Value) -> Option<String> {
    // LEAD-head1 — a `membership:{stage}` row names its group as
    // `community_key_id` / `family_key_id` (the proposal and the reply);
    // without them a member's proposal in a room resolved no roster head and
    // the door refused it `act_names_no_head`.
    [
        "community_id",
        "family_id",
        "group",
        "community_key_id",
        "family_key_id",
    ]
    .iter()
    .find_map(|k| {
        payload
            .get_text(k)
            .and_then(Value::as_text)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    })
}

/// What [`resolve`] needs beyond the kind.
#[derive(Clone, Copy, Debug)]
pub struct HeadAsk<'a> {
    /// The signer's identity-ref (`iss`), which is its key id on the key
    /// plane.
    pub iss: &'a str,
    /// The capacity it signs in.
    pub capacity: SignerCapacity,
    /// The room or family the roster head is read from ([`group_of`]).
    pub group: Option<&'a str>,
    /// The row's own instant, POSIX ms: only an agent's owner read takes it
    /// (`admission::agent_owner_of`), and it decides no head.
    pub asserted_at_ms: u64,
}

/// **The head(s) of `kind`, as this node holds them.** Empty for a kind
/// that names none, or when this node holds no such record (an unowned node,
/// a room whose roster it does not hold, no live delegation): the row is
/// then stated with no head, and the door says whether that is refused.
/// One head for every kind but a roster, which answers EVERY current tip
/// of the group's lineage ([`roster_heads`]).
///
/// # Errors
/// Directory reads.
pub async fn resolve<F>(dir: &F, kind: HeadKind, ask: &HeadAsk<'_>) -> Result<Vec<RowId>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let one = match kind {
        HeadKind::NoHead | HeadKind::Open => None,
        HeadKind::Roster => {
            return match ask.group {
                Some(g) => roster_heads(dir, g).await,
                None => Ok(Vec::new()),
            }
        }
        HeadKind::Bundle => super::genesis::bundle_head_in_force(dir).await?.map(RowId),
        HeadKind::OwnerBinding => {
            owner_binding_row(
                dir,
                ask.iss,
                ask.capacity == SignerCapacity::Agent,
                ask.asserted_at_ms,
            )
            .await?
        }
        HeadKind::Delegation => delegation_row(dir, ask.iss).await?,
    };
    Ok(one.into_iter().collect())
}

/// v62.0.0 (LINEAGE-L2; CC 2.7.8, CC 3.3.4 as settled 11-23) — **the heads
/// this node holds for `group`: the newest nodes of its roster lineage.** A
/// node is a `group:roster` version or a counted widening or removal
/// (`lineage::is_head_row`); the heads are the nodes no other node extends
/// (`lineage::heads`), by row id. One head, or the tips when two changes
/// extend one head ("a row signed while its signer holds several tips names
/// ALL of them": CC 2.7.8, Constitution 11-23). Empty when no node of the
/// group is held here. The production twin of the fixtures'
/// `group_fixtures::held_heads`.
///
/// # Errors
/// Directory reads.
pub async fn roster_heads<F>(dir: &F, group: &str) -> Result<Vec<RowId>, Error>
where
    F: FederationDirectory + ?Sized,
{
    super::lineage::heads(dir, group).await
}

/// The signer of a statement (its CWT `iss`).
fn statement_iss(statement: &[u8]) -> Option<String> {
    let (protected, _) = super::liveness::statement_parts(statement)?;
    protected
        .get_int(15)?
        .get_int(1)?
        .as_text()
        .map(str::to_owned)
}

/// **The owner binding a node or agent acts under**: the lowest row id
/// among the `ownership:*` rows about `key` signed (or authored) by its
/// counted owner, or one of the owner's occurrences. `None` for an unowned
/// key, and for an ambiguous owner (two counted owners is "no principal",
/// `admission::owner_of`).
///
/// # Errors
/// Directory reads.
pub async fn owner_binding_row<F>(
    dir: &F,
    key: &str,
    agent: bool,
    at_ms: u64,
) -> Result<Option<RowId>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let owner = if agent {
        crate::federation::admission::agent_owner_of(dir, key, at_ms).await?
    } else {
        match crate::federation::admission::owner_of_unmarked(dir, key).await {
            Ok(o) => o,
            Err(Error::AmbiguousNodeOwner { .. }) => None,
            Err(e) => return Err(e),
        }
    };
    let Some(owner) = owner else {
        return Ok(None);
    };
    let family = namespace_match::family_id("ownership:{relation}:{target_kind}:{version}");
    let mut best: Option<RowId> = None;
    for st in dir.edition2_statements_about(&family, key).await? {
        let Some(id) = RowId::of_statement(&st) else {
            continue;
        };
        let author = super::liveness::statement_parts(&st).and_then(|(_, p)| {
            p.get_text("author")
                .and_then(Value::as_text)
                .map(str::to_owned)
        });
        let iss = statement_iss(&st);
        let mut by_owner =
            author.as_deref() == Some(owner.as_str()) || iss.as_deref() == Some(owner.as_str());
        if !by_owner {
            if let Some(i) = iss.as_deref() {
                by_owner = dir.active_identity_for_occurrence(i).await? == owner;
            }
        }
        if by_owner {
            best = Some(best.map_or(id, |b| b.min(id)));
        }
    }
    Ok(best)
}

/// **The delegation a delegate acts under**: the lowest row id among the
/// `delegates_to` rows to `key` that are not owner bindings and that no
/// `withdraws` names. (The door judges which of them authorises the act;
/// Constitution: "two live standings, either".)
///
/// # Errors
/// Directory reads.
pub async fn delegation_row<F>(dir: &F, key: &str) -> Result<Option<RowId>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut best: Option<RowId> = None;
    for r in dir.delegations_to(key).await? {
        if crate::federation::admission::is_owner_binding_envelope(&r.attestation_envelope) {
            continue;
        }
        let Some(id) = hex::decode(&r.attestation_id)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .map(RowId)
        else {
            continue;
        };
        let withdrawn = dir
            .list_attestations_referencing(&r.attestation_id)
            .await?
            .iter()
            .any(|x| x.attestation_type == attestation_type::WITHDRAWS);
        if !withdrawn {
            best = Some(best.map_or(id, |b| b.min(id)));
        }
    }
    Ok(best)
}

/// `payload` with `refs.head` = `head`, joining the roles it already states
/// under `refs`. A payload that already names a head is returned unchanged.
///
/// # Errors
/// `edition2_payload_invalid` for a `refs` that is not a map.
pub fn with_head(payload: Value, head: &RowId) -> Result<Value, Error> {
    with_heads(payload, std::slice::from_ref(head))
}

/// v62.0.0 (LINEAGE-L2; CC 2.7.8) — `payload` naming every head in
/// `heads`: the lowest by encoding as `refs.head`, the rest as the set
/// `refs.further_heads` (sorted by encoding, unique), joining the roles it
/// already states under `refs`. A payload that already names a head, or an
/// empty `heads`, is returned unchanged.
///
/// # Errors
/// `edition2_payload_invalid` for a `refs` that is not a map.
pub fn with_heads(payload: Value, heads: &[RowId]) -> Result<Value, Error> {
    if names_a_head(&payload) || heads.is_empty() {
        return Ok(payload);
    }
    let mut refs: Vec<Value> = heads
        .iter()
        .map(|h| ciris_verify_core::edition2::row_ref(&h.0))
        .collect();
    refs.sort_by_key(ciris_verify_core::cde::encode);
    refs.dedup();
    let head = refs.remove(0);
    let mut roles: Vec<(Value, Value)> = match payload.get_text("refs") {
        None => Vec::new(),
        Some(Value::Map(m)) => m.clone(),
        Some(_) => {
            return Err(Error::InvalidArgument(
                "edition2_payload_invalid: `refs` is not a map".into(),
            ))
        }
    };
    roles.push((Value::Text("head".into()), head));
    if !refs.is_empty() {
        roles.push((
            Value::Text(super::group::FURTHER_HEADS_ROLE.into()),
            Value::Array(refs),
        ));
    }
    super::emit::with_member(payload, "refs", super::emit::sorted_map(roles))
        .map_err(|e| super::emit::produce_error("head", e))
}

/// The signer's key-record `identity_type` set as this node holds it
/// (`lookup_public_key`); empty for a key it does not hold.
///
/// # Errors
/// Directory reads.
pub async fn held_identity_types<F>(dir: &F, iss: &str) -> Result<Vec<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(dir
        .lookup_public_key(iss)
        .await?
        .map(|k| identity_types_of(&k.identity_type))
        .unwrap_or_default())
}

/// **The ONE producer step: state the head a row names** (CC 2.4.1.1, "an
/// act names its head"). For a row that acts ([`row_type_acts`]) and does
/// not already name a head, [`head_kind`] over its family, leaf, placement
/// and the signer's capacity, then [`resolve`]; the head found is joined
/// into `refs` ([`with_head`]). A head the payload already names (a counted
/// row's roster or bundle, a roster version's predecessor) is kept as is.
///
/// Called by the one payload builder's two paths
/// (`attestation_emit::produce_row`, `emit::draft_from_envelope_in`) and by
/// the hand builders, always BEFORE the first voice is signed: a further
/// voice signs the payload as stated and is never re-resolved.
///
/// # Errors
/// Directory reads; `edition2_payload_invalid` for a malformed `refs`.
pub async fn state_head<F>(
    dir: &F,
    row_type: &str,
    family_id: &str,
    iss: &str,
    payload: Value,
) -> Result<Value, Error>
where
    F: FederationDirectory + ?Sized,
{
    if !row_type_acts(row_type) || names_a_head(&payload) {
        return Ok(payload);
    }
    let dimension = payload
        .get_text("dimension")
        .and_then(Value::as_text)
        .map(str::to_owned);
    let leaf = super::payloads::leaf_of(family_id, &payload).map(str::to_owned);
    let placement = Placement::of_payload(&payload);
    let counted = payload.get_text("author").is_none();
    let types = held_identity_types(dir, iss).await?;
    let capacity = capacity_of(&types, family_id, dimension.as_deref(), counted);
    let kind = head_kind(family_id, leaf.as_deref(), placement, capacity);
    if !kind.requires_a_head() {
        return Ok(payload);
    }
    let group = group_of(&payload);
    let ask = HeadAsk {
        iss,
        capacity,
        group: group.as_deref(),
        asserted_at_ms: payload
            .get_text("asserted_at")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    };
    with_heads(payload, &resolve(dir, kind, &ask).await?)
}

/// Families whose own gate already refuses a COUNTED row that names no
/// bundle, by its own token (the trust plane's `root_grant_refused`;
/// `transport:canonical_rebind`'s required `refs.head`): the head rule leaves
/// a bundle-headed row of these to that gate.
const BUNDLE_HEAD_GATED_ELSEWHERE: &[&str] =
    &["trust:{job}:{version}", "transport:canonical_rebind"];

/// **THE door's half of the head rule** (HEAD-2, HEAD-4.rev2; CC 2.4.1.1, "A
/// row that exercises a standing and names no head concludes nothing,
/// `act_names_no_head`"), judged FROM THE ROW ALONE (Constitution, head
/// cases (5); the lead's ruling (a)): the family, its leaf, the placement,
/// and whether the signer's KEY RECORD is a node's or an agent's
/// ([`capacity_of`] over the live record the door holds; without it the row
/// is already Waiting). No owner binding, delegation or roster is read, so
/// the answer does not depend on what has arrived. A row that acts
/// ([`row_type_acts`]) and names no `refs.head` is refused when
/// [`head_kind`] names a roster, an owner binding, a delegation, or a bundle
/// (outside [`BUNDLE_HEAD_GATED_ELSEWHERE`]). So an UNOWNED node's
/// self-report is refused like an owned one's: Constitution (head cases (3))
/// rules that an unowned node signs only possession rows (its key record,
/// its own `identity:occurrence`, the pre-seal route exchange), whose cells
/// name none.
///
/// It runs at THE funnel, `ingest::put_admitted_row`, for a row this node
/// holds no fold state for (its first arrival, by any door that reaches the
/// funnel); a re-fold or a further voice of a held row is not re-judged, so
/// rows kept from before the rule stay as they concluded.
///
/// # Errors
/// `act_names_no_head`; the key-plane read.
pub async fn require_head_named<F>(dir: &F, row: &super::door::AdmittedRow) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if !row_type_acts(&row.row_type) || single(&row.names, "head").is_some() {
        return Ok(());
    }
    let types = super::ingest::machine_kind_at(dir, &row.kid, Some(row.asserted_at_ms))
        .await?
        .map(|k| k.0)
        .unwrap_or_default();
    let dimension = row.payload.get_text("dimension").and_then(Value::as_text);
    let capacity = capacity_of(&types, &row.family, dimension, row.author.is_none());
    let leaf = super::payloads::leaf_of(&row.family, &row.payload);
    let placement = Placement::of_payload(&row.payload);
    let kind = head_kind(&row.family, leaf, placement, capacity);
    let refused = match kind {
        HeadKind::Roster | HeadKind::OwnerBinding | HeadKind::Delegation => true,
        HeadKind::Bundle => !listed(BUNDLE_HEAD_GATED_ELSEWHERE, &row.family),
        HeadKind::NoHead | HeadKind::Open => false,
    };
    if !refused {
        return Ok(());
    }
    Err(Error::malformed_row(
        super::door::PLANE,
        crate::federation::malformed_row::ACT_NAMES_NO_HEAD,
        format!(
            "{} {} by {} exercises a standing ({kind:?}, signed as {capacity:?}, placed \
             {placement:?}) and names no refs.head: an act names the head it is at (CC 2.4.1.1)",
            row.row_type,
            row.row_id.hex(),
            row.iss
        ),
    ))
}

// ------------------------------------------------------------ the ends (HEAD-3)

/// The statement this node holds whose row id is `id` (its first held
/// voice), if any.
///
/// # Errors
/// Directory reads.
pub async fn held_statement<F>(dir: &F, id: &RowId) -> Result<Option<Vec<u8>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(dir
        .edition2_voices(id)
        .await?
        .into_iter()
        .find(|st| RowId::of_statement(st) == Some(*id)))
}

/// **The head an end names** (HEAD-3; CC 2.4.1.1, "A row that ends a
/// standing carries `refs.head` beside its target ... That head is the newest
/// its signer holds"), read from the TARGET it ends:
///
/// - a row of the trust family (a root's grant, an acceptance of it): the
///   bundle in force;
/// - any other `delegates_to` (a delegation, an owner binding, a seat's
///   appointment): the target itself, the one row that is the whole record;
/// - a row placed in a room or a family: that roster's version, as this node
///   holds it;
/// - anything else (a claim at self, a key record): none.
///
/// A payload that already names a head (the root's counted withdrawal names
/// its bundle) is kept. `target_statement` is the target's statement, when
/// the producer holds it.
///
/// # Errors
/// Directory reads; `edition2_payload_invalid` for a malformed `refs`.
pub async fn state_end_head<F>(
    dir: &F,
    target: &RowId,
    target_statement: Option<&[u8]>,
    payload: Value,
) -> Result<Value, Error>
where
    F: FederationDirectory + ?Sized,
{
    if names_a_head(&payload) {
        return Ok(payload);
    }
    let held;
    let st = match target_statement {
        Some(st) => st,
        None => {
            held = held_statement(dir, target).await?;
            match held.as_deref() {
                Some(st) => st,
                None => return Ok(payload),
            }
        }
    };
    let Some((protected, target_payload)) = super::liveness::statement_parts(st) else {
        return Ok(payload);
    };
    let text_at = |label: i64| protected.get_int(label).and_then(Value::as_text);
    let heads: Vec<RowId> = if text_at(-70002).is_some_and(super::typed::is_trust_family) {
        super::genesis::bundle_head_in_force(dir)
            .await?
            .map(RowId)
            .into_iter()
            .collect()
    } else if text_at(-70001) == Some(attestation_type::DELEGATES_TO) {
        vec![*target]
    } else if Placement::of_payload(&target_payload).in_a_roster() {
        match group_of(&target_payload) {
            Some(g) => roster_heads(dir, &g).await?,
            None => Vec::new(),
        }
    } else {
        Vec::new()
    };
    with_heads(payload, &heads)
}

/// Does the held lineage head `from` descend from `to` (`to` is in its
/// past, following `refs.head` and `refs.further_heads`)? Bounded by
/// `group::MAX_ROSTER_CHAIN`; `false` when `from` is not a held head, or a
/// link on the way is not held. v62.0.0 (LINEAGE-L2) — a head is a lineage
/// node (`lineage::is_head_row`): a roster version or a counted widening or
/// removal.
///
/// # Errors
/// Directory reads.
async fn roster_descends<F>(dir: &F, from: &RowId, to: &RowId) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut stack = vec![*from];
    let mut seen = std::collections::BTreeSet::new();
    while let Some(at) = stack.pop() {
        if !seen.insert(at) || seen.len() > super::group::MAX_ROSTER_CHAIN {
            continue;
        }
        // v62.0.0 (LINEAGE-L2; CC 3.3.4) — the lineage's own links: a
        // counted widening or removal is a head too, and names the head it
        // extends.
        let parents = match dir.group_lineage_node(&at).await? {
            Some(n) => n.extends,
            None => {
                let Some(st) = held_statement(dir, &at).await? else {
                    continue;
                };
                let Ok(view) = super::group::roster_view_of_statement(&st) else {
                    continue;
                };
                view.parents()
            }
        };
        for p in parents {
            if p == *to {
                return Ok(true);
            }
            stack.push(p);
        }
    }
    Ok(false)
}

/// **An end that acts from an old head concludes nothing** (HEAD-3; CC
/// 2.4.1.1, `end_names_old_head`): a NEW `withdraws` naming `refs.head` h and
/// `refs.target` T, where T names a head that descends from h (a later
/// version of the same roster, or a successor bundle). T is in the end's own
/// past (the end names it), so that newer head is too. Read over the
/// rosters' and bundles' own lineage, never an instant. An end naming no
/// head, a target this node does not hold, or a target naming none or the
/// same head is not judged here.
///
/// # Errors
/// `end_names_old_head`; directory reads.
pub async fn require_end_head_current<F>(
    dir: &F,
    row: &super::door::AdmittedRow,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if row.row_type != attestation_type::WITHDRAWS {
        return Ok(());
    }
    let (Some(head), Some(target)) = (single(&row.names, "head"), single(&row.names, "target"))
    else {
        return Ok(());
    };
    let Some(tst) = held_statement(dir, &target).await? else {
        return Ok(());
    };
    let Some(target_head) =
        super::names::of_statement_names(&tst).and_then(|(_, names)| single(&names, "head"))
    else {
        return Ok(());
    };
    if target_head == head {
        return Ok(());
    }
    let newer = roster_descends(dir, &target_head, &head).await?
        || super::genesis::bundle_descends(dir, &target_head.0, &head.0).await?;
    if !newer {
        return Ok(());
    }
    Err(Error::malformed_row(
        super::door::PLANE,
        crate::federation::malformed_row::END_NAMES_OLD_HEAD,
        format!(
            "withdraws {} names the head {} and ends {}, which names the newer head {}: an \
             end acts from the newest head it holds (CC 2.4.1.1)",
            row.row_id.hex(),
            head.hex(),
            target.hex(),
            target_head.hex()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fid(p: &str) -> String {
        namespace_match::family_id(p)
    }

    /// I6100 — the column is Constitution 76c4550's, whole: 190 families,
    /// the value counts the commit's derivation gives (150 by_placement, 12
    /// none, 9 roster, 8 standing, 11 open), and every family is found by its
    /// id.
    #[test]
    fn i6100_the_column_is_76c4550s() {
        assert_eq!(NAMES_HEAD_TABLE.len(), 190, "I6100: 190 families");
        let count = |v: Option<NamesHead>| NAMES_HEAD_TABLE.iter().filter(|(_, x)| *x == v).count();
        assert_eq!(
            count(Some(NamesHead::ByPlacement)),
            150,
            "I6100: by_placement"
        );
        assert_eq!(count(Some(NamesHead::NoHead)), 12, "I6100: none");
        assert_eq!(count(Some(NamesHead::Roster)), 9, "I6100: roster");
        assert_eq!(count(Some(NamesHead::Standing)), 8, "I6100: standing");
        assert_eq!(count(None), 11, "I6100: open");
        assert_eq!(
            column().len(),
            190,
            "I6100: no two prefixes share a family id"
        );
        for (p, v) in NAMES_HEAD_TABLE {
            if RULED_CELLS.iter().any(|(r, _)| r == p) {
                continue;
            }
            assert_eq!(names_head(&fid(p), None), *v, "I6100: {p}");
        }
        for (p, v) in RULED_CELLS {
            assert!(
                NAMES_HEAD_TABLE.iter().any(|(q, _)| q == p),
                "I6100: a ruled cell is a family of the model: {p}"
            );
            assert_eq!(names_head(&fid(p), None), *v, "I6100: ruled {p}");
        }
        assert_eq!(names_head("no:such:family", None), None);
    }

    /// I6101 — the five standings: a room-placed act names the roster, an
    /// owned node's self-report its binding, a delegate's duty row its
    /// delegation, the holders' count the bundle, a person's own row none.
    #[test]
    fn i6101_the_five_standings() {
        let chat = fid("chat:*");
        let transport = fid("transport:{kind}");
        let detection = fid("detection:{detector}");
        let trust = fid("trust:{job}:{version}");
        let listing = fid("community:listing");
        use HeadKind as K;
        use Placement as P;
        use SignerCapacity as C;
        assert_eq!(head_kind(&chat, None, P::Room, C::Person), K::Roster);
        assert_eq!(
            head_kind(&chat, None, P::Family, C::Node),
            K::Roster,
            "prefer the roster"
        );
        assert_eq!(head_kind(&chat, None, P::Own, C::Person), K::NoHead);
        assert_eq!(
            head_kind(&transport, None, P::Own, C::Node),
            K::OwnerBinding
        );
        assert_eq!(
            head_kind(&transport, None, P::Elsewhere, C::Node),
            K::OwnerBinding
        );
        assert_eq!(
            head_kind(&detection, None, P::Own, C::Delegate),
            K::Delegation
        );
        assert_eq!(
            head_kind(&trust, Some("confers"), P::Elsewhere, C::RootHolder),
            K::Bundle
        );
        assert_eq!(head_kind(&listing, None, P::Elsewhere, C::Seat), K::Roster);
        assert_eq!(head_kind(&chat, None, P::Elsewhere, C::Person), K::NoHead);
    }

    /// I6102 — no head: an acceptance, a key record, a conferral record, a
    /// `none` family whatever the signer, and an open family is Open.
    #[test]
    fn i6102_rows_that_name_no_head() {
        use HeadKind as K;
        use Placement as P;
        use SignerCapacity as C;
        let trust = fid("trust:{job}:{version}");
        assert_eq!(
            head_kind(&trust, Some("accepts"), P::Elsewhere, C::Node),
            K::NoHead
        );
        assert_eq!(
            head_kind(&fid("key:record"), None, P::Elsewhere, C::Node),
            K::NoHead
        );
        assert_eq!(
            head_kind(&fid("device:label"), None, P::Own, C::Person),
            K::NoHead
        );
        assert_eq!(
            head_kind(
                &fid("ownership:{relation}:{target_kind}:{version}"),
                None,
                P::Elsewhere,
                C::Node
            ),
            K::NoHead,
            "the bound node's own voice on its binding"
        );
        assert_eq!(
            head_kind(&fid("group:roster"), None, P::Room, C::Person),
            K::NoHead
        );
        assert_eq!(
            head_kind(&fid("cosign:{state}"), None, P::Room, C::Person),
            K::NoHead
        );
        let kg = fid("key_grant:{axis}");
        assert_eq!(
            head_kind(&kg, None, P::Room, C::Node),
            K::Roster,
            "an asset in a room"
        );
        assert_eq!(
            head_kind(&kg, None, P::Own, C::Node),
            K::NoHead,
            "else none"
        );
        assert_eq!(
            head_kind(&fid("admission:unit"), None, P::Own, C::Person),
            K::NoHead
        );
        assert_eq!(
            head_kind(&fid("preserve_request"), None, P::Elsewhere, C::Node),
            K::Open
        );
        assert!(!K::Open.requires_a_head() && !K::NoHead.requires_a_head());
    }

    /// I6103 — the capacity: a node or agent key acts for its owner; an
    /// accord holder only on a counted root row; a person on a reserved
    /// delegated family is a delegate.
    #[test]
    fn i6103_capacity_of() {
        let node = vec![identity_type::NODE.to_owned()];
        let holder = vec![identity_type::ACCORD_HOLDER.to_owned()];
        let user = vec![identity_type::USER.to_owned()];
        let trust = fid("trust:{job}:{version}");
        assert_eq!(capacity_of(&node, &trust, None, true), SignerCapacity::Node);
        assert_eq!(
            capacity_of(&holder, &trust, None, true),
            SignerCapacity::RootHolder
        );
        assert_eq!(
            capacity_of(&holder, &trust, None, false),
            SignerCapacity::Person
        );
        assert_eq!(
            capacity_of(
                &user,
                &fid("transparency_log:cosigned:{tree_size}"),
                Some("transparency_log:cosigned:7:v1"),
                false
            ),
            SignerCapacity::Delegate
        );
        assert_eq!(
            capacity_of(&user, &fid("chat:*"), Some("chat:message:v1"), false),
            SignerCapacity::Person
        );
        assert_eq!(
            identity_types_of("node, agent,"),
            vec!["node".to_owned(), "agent".to_owned()]
        );
    }

    /// A `withdraws` payload naming `target`, with `extra` members.
    fn withdraws(extra: Vec<(&str, Value)>) -> Value {
        let t = |s: &str| Value::Text(s.into());
        let mut m = vec![
            (t("asserted_at"), Value::Uint(2_000)),
            (
                t("refs"),
                super::super::emit::sorted_map(vec![(
                    t("target"),
                    ciris_verify_core::edition2::row_ref(&[5u8; 32]),
                )]),
            ),
        ];
        m.extend(extra.into_iter().map(|(k, v)| (t(k), v)));
        super::super::emit::sorted_map(m)
    }

    fn token(e: &Error) -> &'static str {
        match e {
            Error::MalformedRow { reason, .. } => reason,
            other => other.kind(),
        }
    }

    /// I6110 — a COUNTED `withdraws` (no `author`) may state `lifts: true`
    /// at the top level: the composer check allows it there.
    #[test]
    fn i6110_a_counted_end_states_lifts() {
        let p = withdraws(vec![("lifts", Value::Bool(true))]);
        super::super::payloads::check_composer("withdraws", &p)
            .expect("I6110: a counted end states lifts");
        super::super::payloads::check_composer("withdraws", &withdraws(vec![]))
            .expect("I6110: and may leave it out");
    }

    /// I6111 — `lifts` on one signer's own end is refused
    /// `lifts_on_own_end`.
    #[test]
    fn i6111_lifts_on_own_end() {
        let p = withdraws(vec![
            ("lifts", Value::Bool(true)),
            (
                "author",
                Value::Text("urn:ietf:params:oauth:ckt:sha-256:x".into()),
            ),
        ]);
        let e = super::super::payloads::check_composer("withdraws", &p).unwrap_err();
        assert_eq!(
            token(&e),
            crate::federation::malformed_row::LIFTS_ON_OWN_END,
            "I6111: {e:?}"
        );
    }

    /// I6112 — `lifts` is present only as `true`, and rides no `recants`.
    #[test]
    fn i6112_lifts_only_true_and_only_on_an_end() {
        for (row_type, v) in [
            ("withdraws", Value::Bool(false)),
            ("withdraws", Value::Uint(1)),
            ("recants", Value::Bool(true)),
        ] {
            let p = withdraws(vec![("lifts", v)]);
            let e = super::super::payloads::check_composer(row_type, &p).unwrap_err();
            assert_eq!(
                token(&e),
                crate::federation::malformed_row::EDITION2_PAYLOAD_INVALID,
                "I6112: {row_type}: {e:?}"
            );
        }
    }

    /// I6113 — a row of a family with no list (no end) states no `lifts`.
    #[test]
    fn i6113_no_lifts_off_an_end() {
        let t = |s: &str| Value::Text(s.into());
        let p = super::super::emit::sorted_map(vec![
            (t("asserted_at"), Value::Uint(2_000)),
            (t("dimension"), t("chat:message:v1")),
            (t("lifts"), Value::Bool(true)),
        ]);
        let e = super::super::payloads::check_by_id(&fid("chat:*"), "scores", &p).unwrap_err();
        assert_eq!(
            token(&e),
            crate::federation::malformed_row::EDITION2_PAYLOAD_INVALID,
            "I6113: {e:?}"
        );
    }

    /// I6115 — Constitution's hand-ruled cells (2026-11-22): a custody
    /// report names the node's owner binding wherever the blob is placed; the
    /// trust family by leaf; registry consensus and a listing name the roster;
    /// duty, act:ack and stream:head go by placement.
    #[test]
    fn i6115_the_ruled_cells() {
        use HeadKind as K;
        use Placement as P;
        use SignerCapacity as C;
        let custody = fid("custody:{kind}");
        for p in [P::Own, P::Room, P::Family, P::Elsewhere] {
            assert_eq!(
                head_kind(&custody, None, p, C::Node),
                K::OwnerBinding,
                "I6115: {p:?}"
            );
        }
        assert_eq!(head_kind(&custody, None, P::Own, C::Person), K::NoHead);
        assert_eq!(
            head_kind(
                &fid("contribution:{subject_kind}"),
                None,
                P::Elsewhere,
                C::Node
            ),
            K::OwnerBinding
        );
        assert_eq!(
            head_kind(&fid("census:share:{class}"), None, P::Elsewhere, C::Node),
            K::OwnerBinding
        );
        let trust = fid("trust:{job}:{version}");
        assert_eq!(
            head_kind(&trust, Some("confers"), P::Elsewhere, C::RootHolder),
            K::Bundle
        );
        assert_eq!(
            head_kind(&trust, Some("confers"), P::Elsewhere, C::Person),
            K::NoHead
        );
        assert_eq!(
            head_kind(&trust, Some("charter"), P::Elsewhere, C::RootHolder),
            K::NoHead
        );
        assert_eq!(
            head_kind(&trust, Some("accepts"), P::Elsewhere, C::RootHolder),
            K::NoHead
        );
        let holder = vec![identity_type::ACCORD_HOLDER.to_owned()];
        assert_eq!(
            capacity_of(&holder, &fid("trust:blessing"), None, true),
            SignerCapacity::RootHolder
        );
        assert_eq!(
            head_kind(&fid("trust:blessing"), None, P::Elsewhere, C::RootHolder),
            K::Bundle
        );
        for f in ["attestation:registry_consensus", "community:listing"] {
            assert_eq!(
                head_kind(&fid(f), None, P::Elsewhere, C::Person),
                K::Roster,
                "I6115: {f}"
            );
        }
        for f in [
            "accord:invoke:constitutional:{halt_id}",
            "accord:invoke:notify:{notify_id}",
            "accord:invoke:drill:{drill_id}",
        ] {
            for c in [C::RootHolder, C::Person] {
                assert_eq!(
                    head_kind(&fid(f), None, P::Elsewhere, c),
                    K::NoHead,
                    "I6115: a halt invocation names no head: {f}"
                );
            }
        }
        for f in ["duty:{kind}", "act:ack", "stream:head"] {
            assert_eq!(
                head_kind(&fid(f), None, P::Room, C::Person),
                K::Roster,
                "I6115: {f}"
            );
            assert_eq!(
                head_kind(&fid(f), None, P::Own, C::Person),
                K::NoHead,
                "I6115: {f}"
            );
        }
    }

    /// I6116 — `lifts` sits beside the row type: a `supersedes` carries none.
    #[test]
    fn i6116_a_supersedes_carries_no_lifts() {
        let t = |s: &str| Value::Text(s.into());
        let p = super::super::emit::sorted_map(vec![
            (t("asserted_at"), Value::Uint(2_000)),
            (t("dimension"), t("chat:message:v1")),
            (t("lifts"), Value::Bool(true)),
            (
                t("refs"),
                super::super::emit::sorted_map(vec![(
                    t("target"),
                    ciris_verify_core::edition2::row_ref(&[5u8; 32]),
                )]),
            ),
        ]);
        let e = super::super::payloads::check_by_id(&fid("chat:*"), "supersedes", &p).unwrap_err();
        assert_eq!(
            token(&e),
            crate::federation::malformed_row::EDITION2_PAYLOAD_INVALID,
            "I6116: {e:?}"
        );
    }

    /// I6117 — counted vs authored is the payload's `author`, never its
    /// head: an admission-unit or trust draft naming `head` and no `author`
    /// is refused; `"author": null` drafts it counted (no `author`).
    #[test]
    fn i6117_a_draft_is_counted_by_its_author_never_its_head() {
        use crate::federation::edition2::door_invariants::fixture::{iref, key};
        let k = key(93);
        let kid = ciris_verify_core::edition2::thumbprint(k.public_key());
        let me = iref(&k);
        let head = "ab".repeat(32);
        for (dim, rt) in [
            ("admission:unit:v1", "scores"),
            ("trust:confers:v1", "delegates_to"),
        ] {
            let env = serde_json::json!({"dimension": dim, "head": head});
            let e = super::super::emit::draft_from_envelope(&kid, &me, &me, rt, &env, 9_000, None)
                .err()
                .unwrap_or_else(|| panic!("I6117: {dim}: a head with no author is refused"));
            assert!(
                e.to_string().contains("edition2_payload_invalid"),
                "I6117: {dim}: {e}"
            );
            let env = serde_json::json!({"dimension": dim, "head": head, "author": null});
            let d = super::super::emit::draft_from_envelope(&kid, &me, &me, rt, &env, 9_000, None)
                .unwrap_or_else(|e| panic!("I6117: {dim}: counted by `author: null`: {e}"));
            let p = ciris_verify_core::cde::decode(&d.payload).expect("I6117: payload");
            assert!(
                p.get_text("author").is_none(),
                "I6117: {dim}: counted: no author"
            );
            assert!(names_a_head(&p), "I6117: {dim}: the head is kept");
        }
    }

    /// I6104 — `with_head` joins `refs`, keeps a named head, and refuses a
    /// `refs` that is not a map.
    #[test]
    fn i6104_with_head_joins_refs() {
        let t = |s: &str| Value::Text(s.into());
        let h = RowId([7u8; 32]);
        let other = RowId([9u8; 32]);
        let p = super::super::emit::sorted_map(vec![(t("asserted_at"), Value::Uint(1))]);
        let p = with_head(p, &h).expect("I6104: joins");
        assert_eq!(names_of(&p).ok().and_then(|n| single(&n, "head")), Some(h));
        let kept = with_head(p.clone(), &other).expect("I6104: kept");
        assert_eq!(kept, p, "I6104: a named head is never replaced");
        let p = super::super::emit::sorted_map(vec![(
            t("refs"),
            super::super::emit::sorted_map(vec![(
                t("target"),
                ciris_verify_core::edition2::row_ref(&other.0),
            )]),
        )]);
        let p = with_head(p, &h).expect("I6104: joins a target");
        let n = names_of(&p).expect("I6104: names");
        assert_eq!(single(&n, "head"), Some(h));
        assert_eq!(single(&n, "target"), Some(other));
        let bad = super::super::emit::sorted_map(vec![(t("refs"), Value::Uint(1))]);
        assert!(with_head(bad, &h).is_err());
    }

    /// I6905 (LINEAGE-L2; CC 2.7.8) — `with_heads` names EVERY tip: the
    /// lowest as `refs.head`, the rest as the set `refs.further_heads`
    /// (sorted by encoding, each once); one tip is `with_head`; no tip and
    /// a named head leave the payload as it is.
    #[test]
    fn i6905_with_heads_names_every_tip() {
        let t = |s: &str| Value::Text(s.into());
        let (a, b, c) = (RowId([3u8; 32]), RowId([5u8; 32]), RowId([9u8; 32]));
        let base = super::super::emit::sorted_map(vec![(t("asserted_at"), Value::Uint(1))]);
        let p = with_heads(base.clone(), &[c, a, b, a]).expect("I6905: joins");
        let n = names_of(&p).expect("I6905: names");
        assert_eq!(
            single(&n, "head"),
            Some(a),
            "I6905: the lowest is refs.head"
        );
        let further: Vec<RowId> = n
            .iter()
            .filter(|x| x.role == "further_heads")
            .map(|x| x.row)
            .collect();
        assert_eq!(further, vec![b, c], "I6905: the rest, sorted, each once");
        let refs = p.get_text("refs").expect("I6905: refs");
        let set = refs
            .get_text("further_heads")
            .and_then(Value::as_array)
            .expect("I6905: a set");
        let enc: Vec<Vec<u8>> = set.iter().map(ciris_verify_core::cde::encode).collect();
        assert!(
            enc.windows(2).all(|w| w[0] < w[1]),
            "I6905: sorted by encoding"
        );
        assert_eq!(
            with_heads(base.clone(), &[b]).unwrap(),
            with_head(base.clone(), &b).unwrap(),
            "I6905: one tip is with_head"
        );
        let one = with_head(base.clone(), &b).unwrap();
        assert!(
            names_of(&one)
                .unwrap()
                .iter()
                .all(|x| x.role != "further_heads"),
            "I6905: one head names no further_heads"
        );
        assert_eq!(with_heads(base.clone(), &[]).unwrap(), base, "I6905: none");
        assert_eq!(
            with_heads(one.clone(), &[a, c]).unwrap(),
            one,
            "I6905: a named head is never replaced"
        );
    }
}
