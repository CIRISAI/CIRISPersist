//! v61 (CIRISPersist#991 planes 2 and 3 of 3; CC 3.1.3, CC 3.1.3.2,
//! CC 2.4; CIRISConstitution#144/#145; `CLM-planes-as-rows`,
//! `CLM-cosigned-rows`) — **the group records and the membership planes as
//! rows.**
//!
//! A family's or community's record and its widening and revocation planes
//! were six tables of their own, each with a framed replication kind. From
//! v61 each is a `scores` row on the attestation plane, and the table is
//! its projection:
//!
//! | family | attester | attested | the row carries |
//! |---|---|---|---|
//! | `group:roster:v1` | the record's signer | the group | [`GROUP_RECORD_MEMBER`]: the signed record |
//! | `membership:widening:v1` | the widening's signer | the member added | [`WIDENING_MEMBER`]: the signed widening |
//! | `membership:removal:v1` | the revocation's signer | the member removed | [`REVOCATION_MEMBER`]: the signed revocation |
//! | `membership:resignation:v1` | the leaving member | the leaving member | [`REVOCATION_MEMBER`]: the signed revocation |
//!
//! # Who signs the row
//!
//! The key plane's rule ([`super::key_plane`]): persist MINTS each row from
//! the signed object it verified, so no producer changes its local `put_*`
//! call. The row's base signature columns are the object's own authority
//! scrub, over the object's own signed bytes (`signing_envelope()`); its
//! `additional_scrubs[]` are the object's co-signatures over the same bytes
//! (CC 2.4, the steward's rc10 ruling: the quorum carrier is
//! `additional_scrubs[]` beside the row). Every other member of the row is a
//! pure function of the object: a receiver re-derives the row from the object
//! it carries and refuses a row that differs by one byte
//! ([`check_canonical_group_row`]).
//!
//! # Placement
//!
//! A group's records are not federation content (CC 6.1.5.3): each row is
//! placed at its group (`cohort_scope` `family` or `community`, the group id
//! as the envelope's cohort target, [`GROUP_KIND_MEMBER`] naming which), and
//! the serve gate sends it through the group's membership-plane audience
//! ([`super::replication_audience::may_receive_group_plane`]): a public
//! group's to every peer, a private group's to its members' nodes, live
//! invitees' nodes and the node of the member a row names.
//!
//! # Admission
//!
//! The row reaches the same shared plan the typed door ran
//! ([`super::community_admit`], the family doors): the record's authorship,
//! the roster authority under the group's `consensus_protocol` at the row's
//! signed instant, the founder gates. The quorum is counted by the ONE
//! predicate ([`super::reverse_quorum::count_distinct_roster_scrubs`]) over
//! the base scrub and `additional_scrubs[]`; the source of the protocol is the
//! family's declaration ([`consensus_source_for`]).

use super::key_plane::{self, MintedFamily, MintedPlacement, PlaneSignature};
use super::types::{
    attestation_type, cohort_scope, Attestation, GroupSupersedeProof, RosterCosignature, ScrubSig,
    SignedCommunity, SignedCommunityMembershipRevocation, SignedCommunityMembershipWidening,
    SignedFamily, SignedFamilyMembershipRevocation, SignedFamilyMembershipWidening,
};
use super::Error;

/// `group:roster:v1` — a family's or community's record at a version (CC
/// 3.1.3; CC 3.2 T6 makes it the lineage head).
pub const GROUP_ROSTER_DIMENSION: &str = "group:roster:v1";
/// `membership:widening:v1` — a member added to a group (CC 3.1.3.2).
pub const MEMBERSHIP_WIDENING_DIMENSION: &str = "membership:widening:v1";
/// `membership:removal:v1` — a member removed by the group (CC 3.1.3.2).
pub const MEMBERSHIP_REMOVAL_DIMENSION: &str = "membership:removal:v1";
/// `membership:resignation:v1` — a member's own leaving (CC 3.1.3.2).
pub const MEMBERSHIP_RESIGNATION_DIMENSION: &str = "membership:resignation:v1";

/// The envelope member a `group:roster:v1` row carries its signed record
/// under.
pub const GROUP_RECORD_MEMBER: &str = "group_record";
/// The envelope member a `membership:widening:v1` row carries its signed
/// widening under.
pub const WIDENING_MEMBER: &str = "widening";
/// The envelope member a `membership:removal:v1` or
/// `membership:resignation:v1` row carries its signed revocation under.
pub const REVOCATION_MEMBER: &str = "revocation";
/// The envelope member naming the group's kind (`family` / `community`), as
/// the membership ceremony rows spell it.
pub const GROUP_KIND_MEMBER: &str = "group_kind";
/// `group:roster:v1` envelope members (CC 3.2 T6): the lineage head's
/// predecessor digest and the charter digest, lifted beside the record.
pub const PREV_HEAD_DIGEST_MEMBER: &str = "prev_head_digest";
/// See [`PREV_HEAD_DIGEST_MEMBER`].
pub const CHARTER_DIGEST_MEMBER: &str = "charter_digest";

/// The two kinds of group whose records ride the plane. `community` and
/// `affiliations` are one record (`federation_communities`) and one plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupKind {
    /// A family (`federation_families`).
    Family,
    /// A community or an affiliation (`federation_communities`).
    Community,
}

impl GroupKind {
    /// The [`GROUP_KIND_MEMBER`] spelling, and the row's placement.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Family => cohort_scope::FAMILY,
            Self::Community => cohort_scope::COMMUNITY,
        }
    }

    /// The envelope member naming the group (the cohort target).
    #[must_use]
    pub const fn target_member(self) -> &'static str {
        match self {
            Self::Family => "family_key_id",
            Self::Community => "community_key_id",
        }
    }

    fn of_str(s: &str) -> Option<Self> {
        match s {
            cohort_scope::FAMILY => Some(Self::Family),
            cohort_scope::COMMUNITY => Some(Self::Community),
            _ => None,
        }
    }
}

/// The four families of the group plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupPlaneFamily {
    /// `group:roster:v1`.
    Roster,
    /// `membership:widening:v1`.
    Widening,
    /// `membership:removal:v1`.
    Removal,
    /// `membership:resignation:v1`.
    Resignation,
}

impl GroupPlaneFamily {
    /// Every family, in declaration order.
    pub const ALL: [GroupPlaneFamily; 4] = [
        Self::Roster,
        Self::Widening,
        Self::Removal,
        Self::Resignation,
    ];

    /// The family's dimension.
    #[must_use]
    pub const fn dimension(self) -> &'static str {
        match self {
            Self::Roster => GROUP_ROSTER_DIMENSION,
            Self::Widening => MEMBERSHIP_WIDENING_DIMENSION,
            Self::Removal => MEMBERSHIP_REMOVAL_DIMENSION,
            Self::Resignation => MEMBERSHIP_RESIGNATION_DIMENSION,
        }
    }

    /// The envelope member the signed object rides under.
    #[must_use]
    pub const fn member(self) -> &'static str {
        match self {
            Self::Roster => GROUP_RECORD_MEMBER,
            Self::Widening => WIDENING_MEMBER,
            Self::Removal | Self::Resignation => REVOCATION_MEMBER,
        }
    }

    /// The id domain: the row id is `sha256(domain ‖ JCS(object))`.
    const fn id_domain(self) -> &'static [u8] {
        match self {
            Self::Roster => b"ciris:group:roster:v1:",
            Self::Widening => b"ciris:membership:widening:v1:",
            Self::Removal => b"ciris:membership:removal:v1:",
            Self::Resignation => b"ciris:membership:resignation:v1:",
        }
    }

    fn minted(self) -> MintedFamily {
        MintedFamily {
            dimension: self.dimension(),
            member: self.member(),
            // CC 3.1.3 / 3.1.3.2: both families are positive-only.
            score: 1,
            id_domain: self.id_domain(),
        }
    }

    /// The family a dimension names, if it is one of the four.
    #[must_use]
    pub fn of_dimension(dimension: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.dimension() == dimension)
    }

    /// The family of a `scores` row, read from its envelope's `dimension`.
    #[must_use]
    pub fn of_row(row: &Attestation) -> Option<Self> {
        if row.attestation_type != attestation_type::SCORES {
            return None;
        }
        super::admission::envelope_dimension(&row.attestation_envelope).and_then(Self::of_dimension)
    }
}

/// Is this row one of the group plane's (by its signed dimension)?
#[must_use]
pub fn is_group_plane_row(row: &Attestation) -> bool {
    GroupPlaneFamily::of_row(row).is_some()
}

/// v61 (CIRISPersist#991, CC 2.4 / 2.1) — **where a cosigned family's
/// `consensus_protocol` is declared**: the receiver's own fold of this source
/// at the row's signed instant decides whether the base scrub and
/// `additional_scrubs[]` satisfy it. A `withdraws` of a cosigned row is judged
/// under the same source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusSource {
    /// The group the row is about: its record's `consensus_protocol` over its
    /// roster (the group's record itself: the protocol of the version it
    /// supersedes; a founding record: its founders).
    Group,
    /// The signer alone (a resignation is the leaving member's own act).
    Signer,
}

/// The [`ConsensusSource`] a dimension's family declares, or `None` when the
/// family is not a cosigned one.
#[must_use]
pub fn consensus_source_for(dimension: &str) -> Option<ConsensusSource> {
    match GroupPlaneFamily::of_dimension(dimension)? {
        GroupPlaneFamily::Roster | GroupPlaneFamily::Widening | GroupPlaneFamily::Removal => {
            Some(ConsensusSource::Group)
        }
        GroupPlaneFamily::Resignation => Some(ConsensusSource::Signer),
    }
}

/// The six typed tables the plane projects into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupPlaneTable {
    /// `federation_families`.
    Families,
    /// `federation_communities`.
    Communities,
    /// `federation_family_membership_revocations`.
    FamilyRevocations,
    /// `federation_community_membership_revocations`.
    CommunityRevocations,
    /// `federation_family_membership_widenings`.
    FamilyWidenings,
    /// `federation_community_membership_widenings`.
    CommunityWidenings,
}

impl GroupPlaneTable {
    /// Every table, in declaration order.
    pub const ALL: [GroupPlaneTable; 6] = [
        Self::Families,
        Self::Communities,
        Self::FamilyRevocations,
        Self::CommunityRevocations,
        Self::FamilyWidenings,
        Self::CommunityWidenings,
    ];

    /// The table name without a schema.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Families => "federation_families",
            Self::Communities => "federation_communities",
            Self::FamilyRevocations => "federation_family_membership_revocations",
            Self::CommunityRevocations => "federation_community_membership_revocations",
            Self::FamilyWidenings => "federation_family_membership_widenings",
            Self::CommunityWidenings => "federation_community_membership_widenings",
        }
    }

    /// The group kind whose rows land here.
    #[must_use]
    pub const fn kind(self) -> GroupKind {
        match self {
            Self::Families | Self::FamilyRevocations | Self::FamilyWidenings => GroupKind::Family,
            Self::Communities | Self::CommunityRevocations | Self::CommunityWidenings => {
                GroupKind::Community
            }
        }
    }

    /// The families whose rows land here (a revocation table takes both the
    /// removal and the resignation rows).
    #[must_use]
    pub const fn families(self) -> &'static [GroupPlaneFamily] {
        match self {
            Self::Families | Self::Communities => &[GroupPlaneFamily::Roster],
            Self::FamilyRevocations | Self::CommunityRevocations => {
                &[GroupPlaneFamily::Removal, GroupPlaneFamily::Resignation]
            }
            Self::FamilyWidenings | Self::CommunityWidenings => &[GroupPlaneFamily::Widening],
        }
    }

    /// The silo projection this table is.
    #[must_use]
    pub const fn projection(self) -> super::silo_projection::SiloProjection {
        use super::silo_projection::SiloProjection as P;
        match self {
            Self::Families => P::Families,
            Self::Communities => P::Communities,
            Self::FamilyRevocations => P::FamilyMembershipRevocations,
            Self::CommunityRevocations => P::CommunityMembershipRevocations,
            Self::FamilyWidenings => P::FamilyMembershipWidenings,
            Self::CommunityWidenings => P::CommunityMembershipWidenings,
        }
    }

    /// The table a silo projection names, if it is one of the six.
    #[must_use]
    pub fn of_projection(p: super::silo_projection::SiloProjection) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.projection() == p)
    }
}

/// A signed group-plane object: the typed signed record a row carries.
#[derive(Debug, Clone, PartialEq)]
pub enum GroupSigned {
    /// A family's record.
    Family(SignedFamily),
    /// A community's (or affiliation's) record.
    Community(SignedCommunity),
    /// A family-membership revocation (a removal or a resignation).
    FamilyRevocation(SignedFamilyMembershipRevocation),
    /// A community-membership revocation (a removal or a resignation).
    CommunityRevocation(SignedCommunityMembershipRevocation),
    /// A family-membership widening.
    FamilyWidening(SignedFamilyMembershipWidening),
    /// A community-membership widening.
    CommunityWidening(SignedCommunityMembershipWidening),
}

/// The base signature of a signed group object.
struct BaseSignature<'a> {
    authority_key_id: &'a str,
    classical: &'a str,
    pqc: Option<&'a str>,
    cosignatures: &'a [RosterCosignature],
}

/// The projection row a group object lands in: the table and its primary
/// key. `member_key_id` and `effective_at` are `None` for a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRowLink {
    /// The table.
    pub table: GroupPlaneTable,
    /// The group (`family_key_id` / `community_key_id`).
    pub group_key_id: String,
    /// The member a plane row names (`removed_identity_key_id` /
    /// `member_key_id`).
    pub member_key_id: Option<String>,
    /// The plane row's `effective_at`.
    pub effective_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl GroupRowLink {
    /// The link of a group's own record.
    #[must_use]
    pub fn record(kind: GroupKind, group_key_id: &str) -> Self {
        Self {
            table: match kind {
                GroupKind::Family => GroupPlaneTable::Families,
                GroupKind::Community => GroupPlaneTable::Communities,
            },
            group_key_id: group_key_id.to_owned(),
            member_key_id: None,
            effective_at: None,
        }
    }

    /// The link of one roster-plane row (a widening or a revocation).
    #[must_use]
    pub fn plane(
        table: GroupPlaneTable,
        group_key_id: &str,
        member_key_id: &str,
        effective_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            table,
            group_key_id: group_key_id.to_owned(),
            member_key_id: Some(member_key_id.to_owned()),
            effective_at: Some(effective_at),
        }
    }
}

impl GroupSigned {
    /// The group's kind.
    #[must_use]
    pub const fn kind(&self) -> GroupKind {
        match self {
            Self::Family(_) | Self::FamilyRevocation(_) | Self::FamilyWidening(_) => {
                GroupKind::Family
            }
            Self::Community(_) | Self::CommunityRevocation(_) | Self::CommunityWidening(_) => {
                GroupKind::Community
            }
        }
    }

    /// The table it projects into.
    #[must_use]
    pub const fn table(&self) -> GroupPlaneTable {
        match self {
            Self::Family(_) => GroupPlaneTable::Families,
            Self::Community(_) => GroupPlaneTable::Communities,
            Self::FamilyRevocation(_) => GroupPlaneTable::FamilyRevocations,
            Self::CommunityRevocation(_) => GroupPlaneTable::CommunityRevocations,
            Self::FamilyWidening(_) => GroupPlaneTable::FamilyWidenings,
            Self::CommunityWidening(_) => GroupPlaneTable::CommunityWidenings,
        }
    }

    /// The group plane family: a revocation whose signer is the removed
    /// member is a resignation (CC 3.1.3.2: "the leaving member"), any other a
    /// removal.
    #[must_use]
    pub fn family(&self) -> GroupPlaneFamily {
        match self {
            Self::Family(_) | Self::Community(_) => GroupPlaneFamily::Roster,
            Self::FamilyWidening(_) | Self::CommunityWidening(_) => GroupPlaneFamily::Widening,
            Self::FamilyRevocation(r) => revocation_family(
                &r.authority_key_id,
                &r.family_membership_revocation.removed_identity_key_id,
            ),
            Self::CommunityRevocation(r) => revocation_family(
                &r.authority_key_id,
                &r.community_membership_revocation.removed_identity_key_id,
            ),
        }
    }

    /// The group the object is about.
    #[must_use]
    pub fn group_key_id(&self) -> &str {
        match self {
            Self::Family(f) => &f.family.family_key_id,
            Self::Community(c) => &c.community.community_key_id,
            Self::FamilyRevocation(r) => &r.family_membership_revocation.family_key_id,
            Self::CommunityRevocation(r) => &r.community_membership_revocation.community_key_id,
            Self::FamilyWidening(w) => &w.family_membership_widening.family_key_id,
            Self::CommunityWidening(w) => &w.community_membership_widening.community_key_id,
        }
    }

    /// The member a plane row names (`None` for a record).
    #[must_use]
    pub fn member_key_id(&self) -> Option<&str> {
        match self {
            Self::Family(_) | Self::Community(_) => None,
            Self::FamilyRevocation(r) => {
                Some(&r.family_membership_revocation.removed_identity_key_id)
            }
            Self::CommunityRevocation(r) => {
                Some(&r.community_membership_revocation.removed_identity_key_id)
            }
            Self::FamilyWidening(w) => Some(&w.family_membership_widening.member_key_id),
            Self::CommunityWidening(w) => Some(&w.community_membership_widening.member_key_id),
        }
    }

    /// The projection row this object lands in.
    #[must_use]
    pub fn link(&self) -> GroupRowLink {
        let effective_at = match self {
            Self::Family(_) | Self::Community(_) => None,
            Self::FamilyRevocation(r) => Some(r.family_membership_revocation.effective_at),
            Self::CommunityRevocation(r) => Some(r.community_membership_revocation.effective_at),
            Self::FamilyWidening(w) => Some(w.family_membership_widening.effective_at),
            Self::CommunityWidening(w) => Some(w.community_membership_widening.effective_at),
        };
        GroupRowLink {
            table: self.table(),
            group_key_id: self.group_key_id().to_owned(),
            member_key_id: self.member_key_id().map(str::to_owned),
            effective_at,
        }
    }

    /// The row's signed instant: a record's head instant (its amendment's
    /// `amended_at`, else `founded_at`), a plane row's `effective_at`.
    #[must_use]
    pub fn signed_instant(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            Self::Family(f) => {
                amended_at(f.supersede_proof.as_ref()).unwrap_or(f.family.founded_at)
            }
            Self::Community(c) => super::canonical_community::head_instant(c),
            Self::FamilyRevocation(r) => r.family_membership_revocation.effective_at,
            Self::CommunityRevocation(r) => r.community_membership_revocation.effective_at,
            Self::FamilyWidening(w) => w.family_membership_widening.effective_at,
            Self::CommunityWidening(w) => w.community_membership_widening.effective_at,
        }
    }

    fn base(&self) -> BaseSignature<'_> {
        macro_rules! base {
            ($s:expr) => {
                BaseSignature {
                    authority_key_id: &$s.authority_key_id,
                    classical: &$s.scrub_signature_classical,
                    pqc: $s.scrub_signature_pqc.as_deref(),
                    cosignatures: &$s.cosignatures,
                }
            };
        }
        match self {
            Self::Family(s) => base!(s),
            Self::Community(s) => base!(s),
            Self::FamilyRevocation(s) => base!(s),
            Self::CommunityRevocation(s) => base!(s),
            Self::FamilyWidening(s) => base!(s),
            Self::CommunityWidening(s) => base!(s),
        }
    }

    /// The object as the row carries it: the signed wrapper, the record's
    /// recomputed `persist_row_hash` left out.
    ///
    /// # Errors
    ///
    /// [`Error::Backend`] when the object does not serialize.
    pub fn object(&self) -> Result<serde_json::Value, Error> {
        let (v, inner) = match self {
            Self::Family(s) => (serde_json::to_value(s), "family"),
            Self::Community(s) => (serde_json::to_value(s), "community"),
            Self::FamilyRevocation(s) => (serde_json::to_value(s), "family_membership_revocation"),
            Self::CommunityRevocation(s) => {
                (serde_json::to_value(s), "community_membership_revocation")
            }
            Self::FamilyWidening(s) => (serde_json::to_value(s), "family_membership_widening"),
            Self::CommunityWidening(s) => {
                (serde_json::to_value(s), "community_membership_widening")
            }
        };
        let mut obj = v.map_err(|e| Error::Backend(format!("group-plane object encode: {e}")))?;
        if let Some(inner) = obj
            .get_mut(inner)
            .and_then(serde_json::Value::as_object_mut)
        {
            inner.remove("persist_row_hash");
        }
        Ok(obj)
    }

    /// Read an object back from a row's carried member: the inverse of
    /// [`Self::object`] (the record's `persist_row_hash` is left empty: the
    /// door that stores it computes its own). `None`
    /// when it does not parse as `family`'s object of `kind`.
    #[must_use]
    pub fn of_object(
        family: GroupPlaneFamily,
        kind: GroupKind,
        object: &serde_json::Value,
    ) -> Option<Self> {
        fn parse<T: serde::de::DeserializeOwned>(
            object: &serde_json::Value,
            inner: &str,
        ) -> Option<T> {
            let mut v = object.clone();
            v.as_object_mut()?.get_mut(inner)?.as_object_mut()?.insert(
                "persist_row_hash".to_owned(),
                serde_json::Value::String(String::new()),
            );
            serde_json::from_value(v).ok()
        }
        let signed = match (family, kind) {
            (GroupPlaneFamily::Roster, GroupKind::Family) => Self::Family(parse(object, "family")?),
            (GroupPlaneFamily::Roster, GroupKind::Community) => {
                Self::Community(parse(object, "community")?)
            }
            (GroupPlaneFamily::Widening, GroupKind::Family) => {
                Self::FamilyWidening(parse(object, "family_membership_widening")?)
            }
            (GroupPlaneFamily::Widening, GroupKind::Community) => {
                Self::CommunityWidening(parse(object, "community_membership_widening")?)
            }
            (GroupPlaneFamily::Removal | GroupPlaneFamily::Resignation, GroupKind::Family) => {
                Self::FamilyRevocation(parse(object, "family_membership_revocation")?)
            }
            (GroupPlaneFamily::Removal | GroupPlaneFamily::Resignation, GroupKind::Community) => {
                Self::CommunityRevocation(parse(object, "community_membership_revocation")?)
            }
        };
        (signed.family() == family).then_some(signed)
    }

    /// v61.3.0 (CIRISPersist#1252) — the bytes every signer of a roster event
    /// signs (the primary and each cosigner alike): the inner row's
    /// `signing_envelope()`. `None` for a group record (no cosign hold).
    #[must_use]
    pub fn plane_signing_envelope(&self) -> Option<serde_json::Value> {
        match self {
            Self::Family(_) | Self::Community(_) => None,
            Self::FamilyRevocation(s) => Some(s.family_membership_revocation.signing_envelope()),
            Self::CommunityRevocation(s) => {
                Some(s.community_membership_revocation.signing_envelope())
            }
            Self::FamilyWidening(s) => Some(s.family_membership_widening.signing_envelope()),
            Self::CommunityWidening(s) => Some(s.community_membership_widening.signing_envelope()),
        }
    }

    /// v61.3.0 (CIRISPersist#1252) — the primary signer of the object.
    #[must_use]
    pub fn authority_key_id(&self) -> &str {
        self.base().authority_key_id
    }

    /// v61.3.0 (CIRISPersist#1252) — the cosignatures the object carries.
    #[must_use]
    pub fn cosignatures(&self) -> &[RosterCosignature] {
        self.base().cosignatures
    }

    /// v61.3.0 (CIRISPersist#1252) — the same object carrying `cosignatures`
    /// instead of its own (the cosign executor's union; the hold's pending
    /// event carries none).
    #[must_use]
    pub fn with_cosignatures(&self, cosignatures: Vec<RosterCosignature>) -> Self {
        let mut out = self.clone();
        match &mut out {
            Self::Family(s) => s.cosignatures = cosignatures,
            Self::Community(s) => s.cosignatures = cosignatures,
            Self::FamilyRevocation(s) => s.cosignatures = cosignatures,
            Self::CommunityRevocation(s) => s.cosignatures = cosignatures,
            Self::FamilyWidening(s) => s.cosignatures = cosignatures,
            Self::CommunityWidening(s) => s.cosignatures = cosignatures,
        }
        out
    }

    /// Is `other` this object, every instant compared at the substrate's
    /// microsecond resolution?
    #[must_use]
    pub fn same_object_at_substrate(&self, other: &GroupSigned) -> bool {
        let at_substrate = |s: &GroupSigned| {
            s.object().ok().map(|mut v| {
                super::types::truncate_instants_to_microseconds(&mut v);
                v
            })
        };
        let mine = at_substrate(self);
        mine.is_some() && mine == at_substrate(other)
    }
}

fn revocation_family(authority: &str, removed: &str) -> GroupPlaneFamily {
    if authority == removed {
        GroupPlaneFamily::Resignation
    } else {
        GroupPlaneFamily::Removal
    }
}

fn cosignature_scrub(c: &RosterCosignature) -> ScrubSig {
    ScrubSig {
        scrub_key_id: c.authority_key_id.clone(),
        scrub_signature_classical: c.scrub_signature_classical.clone(),
        scrub_signature_pqc: c.scrub_signature_pqc.clone(),
        cosigned_at: None,
    }
}

fn amended_at(proof: Option<&GroupSupersedeProof>) -> Option<chrono::DateTime<chrono::Utc>> {
    proof?
        .change_envelope
        .get(super::canonical_community::AMENDED_AT)?
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
}

/// **The one row builder of the group plane** (pure): the row is a function
/// of the signed object alone. `Ok(None)` when the object has no row: it is
/// unsigned (a trusted-local record, outside the projection) or its base
/// scrub is Ed25519-only (a plane row's signature is hybrid, CC 2.4; held
/// without a row, which the rebuild gate names).
///
/// # Errors
///
/// [`Error::Backend`] / a malformed-row refusal when the object does not
/// serialize or canonicalize.
pub fn plan_group_row(signed: &GroupSigned) -> Result<Option<Attestation>, Error> {
    let base = signed.base();
    if base.authority_key_id.is_empty() || base.classical.is_empty() {
        return Ok(None);
    }
    let Some(pqc) = base.pqc else {
        return Ok(None);
    };
    let family = signed.family();
    let kind = signed.kind();
    let instant = signed.signed_instant();
    let attested = signed
        .member_key_id()
        .unwrap_or_else(|| signed.group_key_id());
    let mut members = serde_json::Map::new();
    members.insert(GROUP_KIND_MEMBER.to_owned(), kind.as_str().into());
    members.insert(
        kind.target_member().to_owned(),
        signed.group_key_id().into(),
    );
    let (prev, charter) = match signed {
        GroupSigned::Family(f) => (&f.family.prev_head_digest, &f.family.charter_digest),
        GroupSigned::Community(c) => (&c.community.prev_head_digest, &c.community.charter_digest),
        _ => (&String::new(), &String::new()),
    };
    for (member, value) in [
        (PREV_HEAD_DIGEST_MEMBER, prev),
        (CHARTER_DIGEST_MEMBER, charter),
    ] {
        if !value.is_empty() {
            members.insert(member.to_owned(), value.clone().into());
        }
    }
    key_plane::minted_row_placed(
        family.minted(),
        base.authority_key_id,
        attested,
        signed.object()?,
        instant,
        PlaneSignature {
            scrub_key_id: base.authority_key_id.to_owned(),
            classical: base.classical.to_owned(),
            pqc: Some(pqc.to_owned()),
            scrub_timestamp: instant,
            pqc_completed_at: Some(instant),
        },
        MintedPlacement {
            cohort_scope: kind.as_str(),
            members,
            additional_scrubs: base.cosignatures.iter().map(cosignature_scrub).collect(),
        },
    )
    .map(Some)
}

/// The kind a group-plane row's envelope names.
fn row_kind(row: &Attestation) -> Option<GroupKind> {
    let kind = row
        .attestation_envelope
        .get(GROUP_KIND_MEMBER)
        .and_then(serde_json::Value::as_str)
        .and_then(GroupKind::of_str)?;
    (row.cohort_scope == kind.as_str()).then_some(kind)
}

/// The signed object a group-plane row carries. `Ok(None)` for a row that is
/// not the group plane's.
///
/// # Errors
///
/// A malformed-row refusal (`envelope_member_invalid`) for a group-plane row
/// whose kind or object does not read.
pub fn group_signed_of_row(row: &Attestation) -> Result<Option<GroupSigned>, Error> {
    let Some(family) = GroupPlaneFamily::of_row(row) else {
        return Ok(None);
    };
    let unreadable = |what: &str| {
        Error::malformed_row(
            "group_plane",
            super::malformed_row::ENVELOPE_MEMBER_INVALID,
            format!(
                "{} row {} carries no readable {what} (CIRISPersist#991)",
                family.dimension(),
                row.attestation_id
            ),
        )
    };
    let kind = row_kind(row).ok_or_else(|| unreadable("`group_kind` at its placement"))?;
    let object = row
        .attestation_envelope
        .get(family.member())
        .ok_or_else(|| unreadable(family.member()))?;
    GroupSigned::of_object(family, kind, object)
        .map(Some)
        .ok_or_else(|| unreadable(family.member()))
}

/// **The family's signature rule, at a receiver**: a group-plane row is
/// exactly the row its own object plans to, column for column (its
/// co-signatures included, through `persist_row_hash`, which covers every
/// column).
///
/// # Errors
///
/// A malformed-row refusal (`typed_diverges_from_envelope`) naming the row.
pub fn check_canonical_group_row(
    offered: &Attestation,
    planned: &Attestation,
) -> Result<(), Error> {
    let mut canonical = offered.clone();
    super::canonical_at_rest::canonicalize_in_place(&mut canonical.attestation_envelope)?;
    if offered.attestation_id == planned.attestation_id
        && super::types::compute_persist_row_hash(&canonical)? == planned.persist_row_hash
    {
        return Ok(());
    }
    Err(Error::malformed_row(
        "group_plane",
        super::malformed_row::TYPED_DIVERGES_FROM_ENVELOPE,
        format!(
            "group-plane row {} is not what the row's own signed object plans to (planned row \
             {}) — a group-plane row is a pure function of the object it carries \
             (CIRISPersist#991)",
            offered.attestation_id, planned.attestation_id
        ),
    ))
}

/// Re-derive a group-plane row from the object it carries and require the
/// offered row to be that row. `Ok(None)` for a row that is not the group
/// plane's.
///
/// # Errors
///
/// [`group_signed_of_row`]'s and [`check_canonical_group_row`]'s refusals,
/// and a malformed-row refusal for an object that plans no row (unsigned or
/// Ed25519-only).
pub fn canonical_object_of_row(row: &Attestation) -> Result<Option<GroupSigned>, Error> {
    let Some(signed) = group_signed_of_row(row)? else {
        return Ok(None);
    };
    let planned = plan_group_row(&signed)?.ok_or_else(|| {
        Error::malformed_row(
            "group_plane",
            super::malformed_row::TYPED_DIVERGES_FROM_ENVELOPE,
            format!(
                "group-plane row {} carries an object with no hybrid signature — a group-plane \
                 row's signature is hybrid (CC 2.4)",
                row.attestation_id
            ),
        )
    })?;
    check_canonical_group_row(row, &planned)?;
    Ok(Some(signed))
}

/// The rebuild gate's rendering of one projection row: the object as the row
/// carries it, every instant at microseconds, and the `attestation_id` it
/// names.
#[must_use]
pub fn render_group_projection(signed: &GroupSigned, attestation_id: Option<&str>) -> String {
    let mut claim = signed.object().unwrap_or(serde_json::Value::Null);
    // At the substrate's resolution: a backend that keeps microseconds holds
    // a nanosecond-signed instant truncated, and the row keeps the signed one.
    super::types::truncate_instants_to_microseconds(&mut claim);
    if let Some(obj) = claim.as_object_mut() {
        obj.insert(
            "attestation_id".to_owned(),
            attestation_id.map_or(serde_json::Value::Null, |a| {
                serde_json::Value::String(a.to_owned())
            }),
        );
    }
    crate::verify::canonical::ceg_produce_canonicalize(&claim)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

/// The from-rows rebuild of one group table: every row of the table's
/// families and kind, read back and rendered, in rendering order; and the
/// live table's signed rows rendered the same way. A signed record held
/// without its row, a row whose record is not held, or one member that
/// differs is a red.
#[must_use]
pub fn group_projection_rebuild(
    table: GroupPlaneTable,
    live: Vec<(GroupSigned, Option<String>)>,
    rows: &[Attestation],
) -> super::silo_projection::ProjectionRebuild {
    // Each rendering leads with the record's own key members, so the sort is
    // a total order that needs no second key.
    let mut live: Vec<String> = live
        .into_iter()
        .filter(|(s, _)| s.table() == table)
        .map(|(s, a)| render_group_projection(&s, a.as_deref()))
        .collect();
    let mut rebuilt: Vec<String> = rows
        .iter()
        .filter_map(|row| {
            let signed = group_signed_of_row(row).ok().flatten()?;
            (signed.table() == table)
                .then(|| render_group_projection(&signed, Some(&row.attestation_id)))
        })
        .collect();
    live.sort();
    rebuilt.sort();
    super::silo_projection::ProjectionRebuild { live, rebuilt }
}

/// v61 (CIRISPersist#991) — what a backend does for the group plane.
/// Storage only: every decision is the shared plans'.
#[async_trait::async_trait]
pub(crate) trait GroupPlaneStore: super::FederationDirectory {
    /// Is V206 applied? A schema before it (only a test's
    /// `run_migrations_through` builds one) has no projection pointer, and
    /// the group plane is not on it: [`sync_group_row`] is a no-op there.
    async fn group_plane_present(&self) -> Result<bool, Error>;

    /// The signed object the projection row `link` names holds, as stored;
    /// `None` when the row is not held or is unsigned (trusted-local).
    async fn read_group_object(&self, link: &GroupRowLink) -> Result<Option<GroupSigned>, Error>;

    /// In one transaction: point the projection row `link` names at `row`
    /// (inserting it on the attestation plane), or at nothing when `row` is
    /// `None`, and drop the row it pointed at before (a superseded record's
    /// head). Writes nothing when the pointer is already `row`, and returns
    /// `false` when the projection row is not held. Indexes an inserted row on
    /// the `Attestation` kind after the commit.
    async fn link_group_plane_row(
        &self,
        link: GroupRowLink,
        row: Option<Attestation>,
    ) -> Result<bool, Error>;

    /// Remove the projection row `link` names when it points at
    /// `attestation_id` (a retracted roster event). Writes nothing otherwise.
    async fn drop_group_projection_row(
        &self,
        link: GroupRowLink,
        attestation_id: &str,
    ) -> Result<(), Error>;

    /// The SIGNED projection rows of `table` that name no row yet
    /// (`attestation_id IS NULL`): the rehome's work list (V206's partial
    /// index makes the probe free when there is none).
    async fn unlinked_group_objects(
        &self,
        table: GroupPlaneTable,
    ) -> Result<Vec<GroupSigned>, Error>;

    /// Every SIGNED projection row of `table` (`authority_key_id` set), as
    /// the signed object it stores and the `attestation_id` it names; and
    /// every row on the attestation plane of the table's families.
    async fn read_group_plane(&self, table: GroupPlaneTable) -> Result<GroupPlaneRead, Error>;
}

/// [`GroupPlaneStore::read_group_plane`]'s answer.
#[derive(Debug, Clone, Default)]
pub(crate) struct GroupPlaneRead {
    /// The live table's signed rows.
    pub(crate) live: Vec<(GroupSigned, Option<String>)>,
    /// The plane's rows of the table's families.
    pub(crate) rows: Vec<Attestation>,
}

/// What [`sync_group_row`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupRowSync {
    /// The projection row points at its object's row.
    Linked,
    /// The stored object has no row (unsigned or Ed25519-only); the pointer
    /// is cleared.
    WithoutRow,
    /// No projection row is held under the link.
    NotHeld,
}

/// **The row follows its object**: read the signed object the projection row
/// `link` names back as stored (so the row is over what this backend keeps),
/// mint its row and point the projection at it. Every group write door calls
/// this once its typed write landed; a supersede calls it for the new head.
/// An object with no row (unsigned, Ed25519-only) is held without one: the
/// pointer is cleared and the rebuild gate names a signed one.
///
/// # Errors
///
/// [`plan_group_row`]'s refusal; the executor's.
pub(crate) async fn sync_group_row<D>(dir: &D, link: GroupRowLink) -> Result<GroupRowSync, Error>
where
    D: GroupPlaneStore + ?Sized,
{
    sync_group_row_offered(dir, link, None).await
}

/// [`sync_group_row`] with the object the door was handed. The row is minted
/// from `offered` — the bytes its signer signed — when the store holds that
/// same object at the substrate's resolution (a backend that keeps
/// microseconds reads a nanosecond instant back truncated, and a row minted
/// from the read-back would carry bytes nobody signed); otherwise from what
/// the store holds.
///
/// # Errors
///
/// As [`sync_group_row`].
pub(crate) async fn sync_group_row_offered<D>(
    dir: &D,
    link: GroupRowLink,
    offered: Option<&GroupSigned>,
) -> Result<GroupRowSync, Error>
where
    D: GroupPlaneStore + ?Sized,
{
    if !dir.group_plane_present().await? {
        return Ok(GroupRowSync::NotHeld);
    }
    let row = match dir.read_group_object(&link).await? {
        Some(stored) => match offered {
            Some(o) if o.link() == link && o.same_object_at_substrate(&stored) => {
                plan_group_row(o)?
            }
            _ => plan_group_row(&stored)?,
        },
        None => None,
    };
    let has_row = row.is_some();
    if !dir.link_group_plane_row(link.clone(), row).await? {
        return Ok(GroupRowSync::NotHeld);
    }
    if !has_row {
        tracing::debug!(
            table = link.table.as_str(),
            group = %link.group_key_id,
            "group record held without a row: unsigned or Ed25519-only (CIRISPersist#991)"
        );
        return Ok(GroupRowSync::WithoutRow);
    }
    Ok(GroupRowSync::Linked)
}

tokio::task_local! {
    /// v61 S2 — set while [`apply_group_plane_row`] hands a REPLICATED roster
    /// event to its typed door. The typed doors serve both the local write and
    /// the replicated apply through one trait method; a gate that binds only
    /// the local door ([`applying_replicated_group_row`]) reads this.
    static REPLICATED_GROUP_ROW: ();
}

/// v61 S2 — is the current task applying a replicated group-plane row
/// ([`GroupRowDoor::Replicated`])? `false` on every local write.
#[must_use]
pub(crate) fn applying_replicated_group_row() -> bool {
    REPLICATED_GROUP_ROW.try_with(|()| ()).is_ok()
}

/// Which door a group-plane row arrived through: a community record's door
/// decides on it whether the CC 3.2 infrastructure gate runs (#931).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupRowDoor {
    /// The local write path (`put_attestation`, authored here).
    Local,
    /// The replicated path (`apply_replicated_attestation`, a sync).
    Replicated,
}

/// What [`apply_group_plane_row`] did with a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupPlaneApplied {
    /// The object landed (its row with it).
    Changed,
    /// This node already holds exactly this row.
    Unchanged,
    /// v61.3.0 (CIRISPersist#1252) — this node holds the same act (the same
    /// event, the same quorum key) under another row: a different sufficient
    /// subset of its cosignatures, or other randomised signature bytes.
    /// Nothing was written but the alias.
    HeldEquivalent,
    /// Well-formed, not applied; the held state is untouched. The token is
    /// the typed door's own refusal reason.
    Refused(&'static str),
}

/// v61 (CIRISPersist#991) — **a group-plane row's signature rule, at a
/// receiver**: the row is exactly the row its own object plans to, and the
/// object's base scrub and every co-signature verify over the object's own
/// signed bytes against this node's registered keys (the typed door's
/// verification, ahead of any write). `Ok(false)` for a row that is not the
/// group plane's.
///
/// # Errors
///
/// [`canonical_object_of_row`]'s refusals; the typed verification's.
pub(crate) async fn verify_plane_row<F>(directory: &F, row: &Attestation) -> Result<bool, Error>
where
    F: super::FederationDirectory + ?Sized,
{
    let Some(signed) = canonical_object_of_row(row)? else {
        return Ok(false);
    };
    verify_signed_object(directory, &signed).await?;
    Ok(true)
}

/// v61.3.0 (CIRISPersist#1252) — a signed group object's own verification
/// (its base scrub and every co-signature over its own signed bytes), the
/// typed door's, apart from any row: the cosign pending row's statement is
/// verified through it.
///
/// # Errors
///
/// The typed verification's refusal.
pub(crate) async fn verify_signed_object<F>(
    directory: &F,
    signed: &GroupSigned,
) -> Result<(), Error>
where
    F: super::FederationDirectory + ?Sized,
{
    use super::tier_ingest as ti;
    match signed {
        GroupSigned::Family(s) => ti::verify_family_admission(directory, s).await?,
        GroupSigned::Community(s) => ti::verify_community_admission(directory, s).await?,
        GroupSigned::FamilyRevocation(s) => {
            ti::verify_family_membership_revocation_admission(directory, s).await?;
        }
        GroupSigned::CommunityRevocation(s) => {
            ti::verify_community_membership_revocation_admission(directory, s).await?;
        }
        GroupSigned::FamilyWidening(s) => {
            ti::verify_family_membership_widening_admission(directory, s).await?;
        }
        GroupSigned::CommunityWidening(s) => {
            ti::verify_community_membership_widening_admission(directory, s).await?;
        }
    }
    Ok(())
}

/// v61 (CIRISPersist#991) — **the group-plane door on the attestation
/// plane**: where a `group:roster:v1` or `membership:{widening,removal,
/// resignation}:v1` row arriving through `put_attestation` or
/// `apply_replicated_attestation` goes, ahead of the generic plan. The row
/// is re-derived from the object it carries (one byte off is a refusal), and
/// the object goes through the SAME typed door a local `put_*` runs: its
/// authorship, the roster authority under the group's `consensus_protocol`
/// at the row's signed instant, the founder gates. That door stores the
/// object and syncs its row, which is this row.
///
/// # Errors
///
/// [`canonical_object_of_row`]'s refusals; the typed door's.
pub(crate) async fn apply_group_plane_row<D>(
    dir: &D,
    row: &Attestation,
    door: GroupRowDoor,
) -> Result<GroupPlaneApplied, Error>
where
    D: super::FederationDirectory + ?Sized,
{
    // A byte-identical re-offer of a held row settles ahead of every verify
    // (the #672 rule): one signed object, one id, one row.
    if let Some(held) = dir.get_attestation(&row.attestation_id).await? {
        if held.persist_row_hash == super::types::compute_persist_row_hash(row)? {
            return Ok(GroupPlaneApplied::Unchanged);
        }
    }
    let Some(signed) = canonical_object_of_row(row)? else {
        return Err(Error::InvalidArgument(format!(
            "row {} is not a group-plane row",
            row.attestation_id
        )));
    };
    // v61.3.0 (CIRISPersist#1252) — **an assembled act this node already
    // holds, offered under another id** (a different sufficient subset of its
    // cosignatures, other randomised ML-DSA bytes, or a 61.2 peer's offer under
    // the hash with scrubs) settles as held, with no refusal booked. Its
    // signatures verify first; its id is then recorded as an alias of the
    // act, so a `withdraws` naming it resolves to the row held here.
    if super::cosign::is_cosignable(&signed) {
        // v61.3.0 (CIRISPersist#1252, CC 2.4.1.1 rule 0) — a row of an act
        // this node holds RETRACTED (whichever subset or id the withdraws
        // named) is that act, held: it never lands the act again.
        if super::cosign::act_retracted(dir, &signed, &row.attestation_id).await? {
            verify_signed_object(dir, &signed).await?;
            if let Some(held) = super::cosign::held_rows_of_act(dir, &signed)
                .await?
                .into_iter()
                .find(|h| h.attestation_id != row.attestation_id)
            {
                dir.note_cosign_alias(
                    &row.attestation_id,
                    &super::cosign::quorum_key_of(&signed)?,
                    &held.attestation_id,
                )
                .await?;
            }
            return Ok(GroupPlaneApplied::HeldEquivalent);
        }
        if let Some(held) = super::cosign::held_equivalent(dir, &signed, row).await? {
            verify_signed_object(dir, &signed).await?;
            dir.note_cosign_alias(
                &row.attestation_id,
                &super::cosign::quorum_key_of(&signed)?,
                &held,
            )
            .await?;
            return Ok(GroupPlaneApplied::HeldEquivalent);
        }
    }
    match signed {
        GroupSigned::Family(s) => dir.put_family(s).await?,
        GroupSigned::Community(s) => match door {
            GroupRowDoor::Local => dir.put_community(s).await?,
            GroupRowDoor::Replicated => {
                use super::group_amendment::ReplicatedCommunityOutcome as O;
                match dir.apply_replicated_community(s).await? {
                    O::Inserted | O::Superseded | O::Unchanged => {}
                    O::Refused { reason } => {
                        return Ok(GroupPlaneApplied::Refused(match reason {
                            super::group_amendment::ReplicatedCommunityRefusal::ConflictingRecord => {
                                "conflicting_record"
                            }
                            super::group_amendment::ReplicatedCommunityRefusal::DegradesConformance => {
                                "degrades_conformance"
                            }
                            super::group_amendment::ReplicatedCommunityRefusal::NotInAudience => {
                                "not_in_audience"
                            }
                        }));
                    }
                }
            }
        },
        // v61 S2 — the removal window binds the local door only
        // (`community_admit::check_open_self_admit_removal_window`).
        // v61.3.0 (CIRISPersist#1252) — and the cosign hold is the local
        // door's alone: a replicated under-signed event keeps its refusal, so
        // every roster event is applied under the replicated marker.
        plane => {
            let put = async {
                match plane {
                    GroupSigned::FamilyRevocation(s) => {
                        dir.put_family_membership_revocation(s).await
                    }
                    GroupSigned::CommunityRevocation(s) => {
                        dir.put_community_membership_revocation(s).await
                    }
                    GroupSigned::FamilyWidening(s) => dir.put_family_membership_widening(s).await,
                    GroupSigned::CommunityWidening(s) => {
                        dir.put_community_membership_widening(s).await
                    }
                    GroupSigned::Family(_) | GroupSigned::Community(_) => Ok(()),
                }
            };
            match door {
                GroupRowDoor::Local => put.await?,
                GroupRowDoor::Replicated => REPLICATED_GROUP_ROW.scope((), put).await?,
            }
        }
    }
    // The typed door stored the object and synced its row from the stored
    // bytes: this row, unless the store kept a different object under the
    // same key (a re-offer of a held roster event signed differently, or an
    // older version of a superseded record).
    Ok(
        if dir.get_attestation(&row.attestation_id).await?.is_some() {
            GroupPlaneApplied::Changed
        } else {
            GroupPlaneApplied::Refused("held_object_differs")
        },
    )
}

/// v61 (CIRISPersist#991) — the reason a row naming a group-plane dimension
/// outside the group-plane door carries ([`check_generic_row_dimension`]).
pub const GROUP_PLANE_ROW_SHAPE_REASON: &str = "group_plane_row_shape";

/// v61 (CIRISPersist#991) — **a group-plane dimension is admitted only as a
/// minted `scores` row through its door.** The generic attestation plan asks
/// this of every row's `dimension`: a `delegates_to` or any other type naming
/// `group:roster:v1` or a `membership:{widening,removal,resignation}:v1`
/// dimension is refused (the latch these dimensions were held behind until
/// the door existed). A structural retraction (`withdraws`, `recants`) may
/// name its target's dimension; its authority is
/// [`check_cosigned_withdraws`]'s.
///
/// # Errors
///
/// [`Error::DimensionRejected`] with [`GROUP_PLANE_ROW_SHAPE_REASON`].
pub fn check_generic_row_dimension(attestation_type: &str, dimension: &str) -> Result<(), Error> {
    if GroupPlaneFamily::of_dimension(dimension).is_none()
        || attestation_type == attestation_type::WITHDRAWS
        || attestation_type == attestation_type::RECANTS
    {
        return Ok(());
    }
    Err(Error::DimensionRejected {
        dimension: dimension.to_owned(),
        reason: GROUP_PLANE_ROW_SHAPE_REASON,
    })
}

/// v61 (CIRISPersist#991, CC 2.4, CC 3.1.3) — the refusal of a `withdraws`
/// naming a FAMILY's `group:roster:v1` row. A family dissolves by its own
/// quorum-proved terminal amendment (`dissolved_at`, CIRISPersist#956), so a
/// retraction of its record is refused by name, never admitted inert.
///
/// v61 S2 (CIRISPersist#1143; CC rc14 4.4.3.2.8) — a COMMUNITY's (or an
/// affiliation's) record is different: "dissolution of either kind is the
/// `withdraws` of its record", cosigned under the group's protocol
/// ([`community_dissolved_at`]).
pub const GROUP_RECORD_WITHDRAWS_REFUSED: &str = "group_record_withdraws_refused";

/// v61 S2 (CIRISPersist#1143; CC rc14 4.4.3.2.8, `CLM-affiliation-dissolution`)
/// — **when the community `community_key_id` was dissolved**: the earliest
/// signed instant of an ADMITTED cosigned `withdraws` of one of its
/// `group:roster:v1` rows (the cosign gate stamps
/// `withdraws_admission_rule`), or `None`. From that instant its seats lapse
/// (the authorized roster is empty), no new seat, removal or version is
/// admitted ([`Error::GroupDissolved`]), and the record and its custody rows
/// stand. A directory that cannot list targeted rows answers `None`.
///
/// # Errors
///
/// Directory reads.
pub async fn community_dissolved_at<D>(
    dir: &D,
    community_key_id: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, Error>
where
    D: super::FederationDirectory + ?Sized,
{
    let rows = match dir
        .list_targeted_by_dimension_prefix(
            &[cohort_scope::COMMUNITY],
            community_key_id,
            GROUP_ROSTER_DIMENSION,
        )
        .await
    {
        Ok(rows) => rows,
        Err(Error::Unsupported { .. }) => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut at: Option<chrono::DateTime<chrono::Utc>> = None;
    for r in rows {
        match group_signed_of_row(&r)? {
            Some(GroupSigned::Community(c)) if c.community.community_key_id == community_key_id => {
            }
            _ => continue,
        }
        for w in dir.list_attestations_referencing(&r.attestation_id).await? {
            if w.attestation_type == attestation_type::WITHDRAWS
                && w.withdraws_admission_rule.is_some()
            {
                at = Some(at.map_or(w.asserted_at, |a| a.min(w.asserted_at)));
            }
        }
    }
    Ok(at)
}

/// Refuse a change to a dissolved community ([`Error::GroupDissolved`]).
///
/// # Errors
///
/// [`Error::GroupDissolved`]; directory reads.
pub async fn refuse_if_community_dissolved<D>(dir: &D, community_key_id: &str) -> Result<(), Error>
where
    D: super::FederationDirectory + ?Sized,
{
    match community_dissolved_at(dir, community_key_id).await? {
        Some(dissolved_at) => Err(Error::GroupDissolved {
            group_key_id: community_key_id.to_owned(),
            dissolved_at,
        }),
        None => Ok(()),
    }
}

/// v61 (CIRISPersist#991; CC 2.4.1.1, CC 3.1.3.2) — **the retraction of a
/// cosigned row is a cosigned `withdraws` under the same protocol.** `None`
/// when `target` is not a group-plane row (the other rules decide).
///
/// - A resignation is the leaving member's alone ([`ConsensusSource::Signer`]):
///   only its signer withdraws it (rule 1).
/// - A widening or a removal is the group's ([`ConsensusSource::Group`]): the
///   `withdraws` row's base scrub and its `additional_scrubs[]`, counted by
///   the ONE predicate ([`super::reverse_quorum::count_distinct_roster_scrubs`])
///   over the group's active roster, must satisfy the group's
///   `consensus_protocol` ([`super::consensus::evaluate`], in the direction
///   the retraction moves the roster). CC 2.4.1.1 rules 1 and 2 do not apply:
///   the author alone does not retract the group's decision. Recorded as rule
///   1 when the base signer is the target's, else 4 (an authority other than
///   the producer).
/// - A group's record is refused ([`GROUP_RECORD_WITHDRAWS_REFUSED`]).
///
/// # Errors
///
/// [`Error::RosterAuthorityUnauthorized`] (`roster_consensus_insufficient`)
/// when the counted signers do not meet the protocol;
/// [`Error::WithdrawsNotAdmitted`] for a resignation withdrawn by another key;
/// [`Error::InvalidArgument`] for a group record.
pub(crate) async fn check_cosigned_withdraws(
    directory: &dyn super::FederationDirectory,
    row: &Attestation,
    target: &Attestation,
) -> Result<Option<u8>, Error> {
    let Some(family) = GroupPlaneFamily::of_row(target) else {
        return Ok(None);
    };
    let Some(signed) = group_signed_of_row(target)? else {
        return Ok(None);
    };
    let issuer = row.attesting_key_id.as_str();
    let rule = if issuer == target.attesting_key_id {
        1
    } else {
        4
    };
    match (family, consensus_source_for(family.dimension())) {
        (GroupPlaneFamily::Roster, _) if signed.kind() == GroupKind::Family => {
            Err(Error::InvalidArgument(format!(
                "{GROUP_RECORD_WITHDRAWS_REFUSED}: withdraws names the family record row {} of {}: \
                 a family's dissolution is its quorum-proved terminal amendment (dissolved_at, \
                 CIRISPersist#956), never a withdraws; a record changes by a supersede under \
                 its protocol",
                target.attestation_id,
                signed.group_key_id()
            )))
        }
        (_, Some(ConsensusSource::Signer)) => {
            if issuer == target.attesting_key_id {
                Ok(Some(1))
            } else {
                Err(Error::WithdrawsNotAdmitted {
                    issuer: issuer.to_owned(),
                    target_attestation_id: target.attestation_id.clone(),
                    beyond_delegation_depth_cap: false,
                })
            }
        }
        (_, _) => {
            let group = signed.group_key_id();
            let (protocol, policy_blob, roster): (String, Option<serde_json::Value>, Vec<_>) =
                match signed.kind() {
                    GroupKind::Family => {
                        let Some(f) = directory.lookup_family(group).await? else {
                            return Err(unknown_group(group));
                        };
                        let roster = directory
                            .active_family_members(group)
                            .await?
                            .into_iter()
                            .map(|m| (m.key_id, m.role))
                            .collect();
                        (f.consensus_protocol, None, roster)
                    }
                    GroupKind::Community => {
                        let Some(c) = directory.lookup_community(group).await? else {
                            return Err(unknown_group(group));
                        };
                        let roster = directory
                            .active_community_members(group)
                            .await?
                            .into_iter()
                            .map(|m| (m.key_id, m.role))
                            .collect();
                        (c.consensus_protocol, c.policy_blob, roster)
                    }
                };
            let ids: Vec<String> = roster.iter().map(|(k, _)| k.clone()).collect();
            let seats: Vec<super::consensus::Seat> = roster
                .into_iter()
                .map(|(key_id, role)| super::consensus::Seat {
                    key_id,
                    role,
                    node_bearing: false,
                })
                .collect();
            let scrubs: Vec<ScrubSig> = std::iter::once(ScrubSig {
                scrub_key_id: row.scrub_key_id.clone(),
                scrub_signature_classical: row.scrub_signature_classical.clone(),
                scrub_signature_pqc: row.scrub_signature_pqc.clone(),
                cosigned_at: None,
            })
            .chain(row.additional_scrubs.iter().cloned())
            .collect();
            // CIRISPersist#1198 (CC 4.5.13) — the evaluator counts persons; a
            // seated person's second device signs for them.
            let persons = super::key_person::KeySelves::read(
                directory,
                ids.iter()
                    .chain(scrubs.iter().map(|s| &s.scrub_key_id))
                    .chain(std::iter::once(&target.attested_key_id))
                    .cloned()
                    .collect(),
            )
            .await?;
            let persons = persons.at(row.asserted_at);
            let counted = super::reverse_quorum::count_distinct_roster_scrubs(
                directory,
                &row.attestation_envelope,
                &scrubs,
                &persons.roster_with_devices(&ids, scrubs.iter().map(|s| s.scrub_key_id.as_str())),
            )
            .await;
            // Retracting a widening takes a member off; retracting a removal
            // puts one back. v61 S2 (CIRISPersist#1143) — withdrawing a
            // community's record dissolves it: a whole-group change, judged
            // in the strict direction (Add) and naming no one member.
            let direction = if family == GroupPlaneFamily::Widening {
                super::consensus::Direction::Remove
            } else {
                super::consensus::Direction::Add
            };
            let subject =
                (family != GroupPlaneFamily::Roster).then_some(target.attested_key_id.as_str());
            // v61 (CIRISPersist#1123) — the group's subkind (a public
            // room's `open:self_admit` is evaluable only there) and the member
            // the retracted row names.
            let subkind = policy_blob
                .as_ref()
                .and_then(|b| b.get("cohort_subkind"))
                .and_then(serde_json::Value::as_str);
            let verdict = super::consensus::evaluate(&super::consensus::Ballot {
                protocol: &protocol,
                subkind,
                policy_blob: policy_blob.as_ref(),
                roster: &seats,
                signers: &counted,
                direction,
                subject,
                persons,
            });
            if verdict.admits() {
                Ok(Some(rule))
            } else {
                Err(Error::RosterAuthorityUnauthorized {
                    group_key_id: group.to_owned(),
                    offered_authority_key_id: issuer.to_owned(),
                    rule: super::ROSTER_CONSENSUS_INSUFFICIENT,
                    // v61.4.0 (CIRISPersist#1250; CC 5.2) — the eligible
                    // signers go only to an issuer seated in the roster (as
                    // itself or as one of its person's devices).
                    shortfall: verdict
                        .shortfall()
                        .cloned()
                        .map(|s| s.for_caller(ids.iter().any(|k| persons.same_person(k, issuer)))),
                })
            }
        }
    }
}

fn unknown_group(group: &str) -> Error {
    Error::InvalidArgument(format!(
        "withdraws names a roster event of {group}, a group this node does not hold"
    ))
}

/// v61 (CIRISPersist#991) — **the projection follows a retraction**: once a
/// cosigned `withdraws` of a widening, removal or resignation row is stored,
/// the roster event it retracts leaves its table (the fold then reads the
/// roster as if the event had not happened). The row stays on the plane,
/// withdrawn; the rebuild skips a withdrawn row the same way.
///
/// # Errors
///
/// The executor's.
pub(crate) async fn after_withdraws<D>(dir: &D, row: &Attestation) -> Result<(), Error>
where
    D: GroupPlaneStore + ?Sized,
{
    if row.attestation_type != attestation_type::WITHDRAWS {
        return Ok(());
    }
    let Some(target_id) =
        super::precedence::references_attestation_id_from_envelope(&row.attestation_envelope)
    else {
        return Ok(());
    };
    // v61.3.0 (CIRISPersist#1252) — through an alias, the same act held here
    // under another id.
    let Some(target) = super::cosign::resolve_withdraws_target(dir, target_id).await? else {
        return Ok(());
    };
    if GroupPlaneFamily::of_row(&target).is_none_or(|f| f == GroupPlaneFamily::Roster) {
        return Ok(());
    }
    if let Some(signed) = group_signed_of_row(&target)? {
        dir.drop_group_projection_row(signed.link(), &target.attestation_id)
            .await?;
    }
    Ok(())
}

/// v61 (CIRISPersist#991) — what the one-way rehome at open found: every
/// signed v60 group record and roster event now has its row, except these.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupRehomeReport {
    /// Projection rows given their row this pass.
    pub linked: u64,
    /// Signed projection rows held without a row (Ed25519-only): counted,
    /// named by the rebuild gate, never re-signed.
    pub without_row: u64,
}

/// v61 (CIRISPersist#991) — **the v60 typed rows rehomed once**: every signed
/// group record and roster event a v60 node holds is given its group-plane
/// row (minted from the stored object, the key plane's rule), before anything
/// reads or serves. Idempotent: a linked row is skipped by the probe.
///
/// # Errors
///
/// The executor's.
pub(crate) async fn rehome_group_records<D>(dir: &D) -> Result<GroupRehomeReport, Error>
where
    D: GroupPlaneStore + ?Sized,
{
    let mut report = GroupRehomeReport::default();
    if !dir.group_plane_present().await? {
        return Ok(report);
    }
    for table in GroupPlaneTable::ALL {
        for signed in dir.unlinked_group_objects(table).await? {
            match sync_group_row(dir, signed.link()).await? {
                GroupRowSync::Linked => report.linked += 1,
                GroupRowSync::WithoutRow => report.without_row += 1,
                GroupRowSync::NotHeld => {}
            }
        }
    }
    tracing::info!(
        linked = report.linked,
        without_row = report.without_row,
        "group-plane rehome at open (v61, CIRISPersist#991): every signed v60 group record \
         and roster event has its row; the counted rest is held without one (Ed25519-only)"
    );
    Ok(report)
}

/// The projection gate for one group table (`check_projection_rebuild`'s
/// group arm).
///
/// # Errors
///
/// The executor's read.
pub(crate) async fn projection_rebuild<D>(
    dir: &D,
    table: GroupPlaneTable,
) -> Result<super::silo_projection::ProjectionRebuild, Error>
where
    D: GroupPlaneStore + ?Sized,
{
    let read = dir.read_group_plane(table).await?;
    // A roster event retracted by an admitted `withdraws` is not projected.
    let mut rows = Vec::with_capacity(read.rows.len());
    for row in read.rows {
        let mut withdrawn = dir
            .list_attestations_referencing(&row.attestation_id)
            .await?
            .iter()
            .any(|w| w.attestation_type == attestation_type::WITHDRAWS);
        // v61.3.0 (CIRISPersist#1252) — a cosigned roster event retracted
        // under another id of its act (an alias, another subset's row).
        if !withdrawn {
            if let Some(signed) = group_signed_of_row(&row)? {
                withdrawn = super::cosign::act_retracted(dir, &signed, &row.attestation_id).await?;
            }
        }
        if !withdrawn {
            rows.push(row);
        }
    }
    Ok(group_projection_rebuild(table, read.live, &rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_dimension_is_registered_under_its_stem() {
        for f in GroupPlaneFamily::ALL {
            let stem = if f == GroupPlaneFamily::Roster {
                "group:roster:"
            } else {
                "membership:"
            };
            assert!(f.dimension().starts_with(stem), "{f:?}");
            assert_eq!(GroupPlaneFamily::of_dimension(f.dimension()), Some(f));
        }
        assert_eq!(
            GroupPlaneFamily::of_dimension("membership:proposal:v1"),
            None
        );
    }

    #[test]
    fn consensus_source_is_the_group_except_a_resignation() {
        assert_eq!(
            consensus_source_for(GROUP_ROSTER_DIMENSION),
            Some(ConsensusSource::Group)
        );
        assert_eq!(
            consensus_source_for(MEMBERSHIP_WIDENING_DIMENSION),
            Some(ConsensusSource::Group)
        );
        assert_eq!(
            consensus_source_for(MEMBERSHIP_REMOVAL_DIMENSION),
            Some(ConsensusSource::Group)
        );
        assert_eq!(
            consensus_source_for(MEMBERSHIP_RESIGNATION_DIMENSION),
            Some(ConsensusSource::Signer)
        );
        assert_eq!(consensus_source_for("membership:acceptance:v1"), None);
    }

    #[test]
    fn every_table_is_one_projection() {
        for t in GroupPlaneTable::ALL {
            assert_eq!(GroupPlaneTable::of_projection(t.projection()), Some(t));
        }
    }

    fn family(proof: Option<GroupSupersedeProof>) -> GroupSigned {
        let at = |s: &str| -> chrono::DateTime<chrono::Utc> { s.parse().unwrap() };
        GroupSigned::Family(SignedFamily {
            family: super::super::types::Family {
                family_key_id: "fam".into(),
                family_name: "household".into(),
                members: vec![super::super::types::FamilyMember {
                    key_id: "ann".into(),
                    joined_at: at("2026-01-01T00:00:00Z"),
                    role: Some("founder".into()),
                }],
                founded_at: at("2026-01-01T00:00:00Z"),
                consensus_protocol: "founder_only".into(),
                consensus_protocol_entrenched: false,
                dissolved_at: None,
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                persist_row_hash: String::new(),
            },
            authority_key_id: "ann".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: Some("cHFj".into()),
            supersede_proof: proof,
            cosignatures: Vec::new(),
        })
    }

    /// A record's row is signed at its head instant: an amendment's
    /// `amended_at`, else `founded_at`. An Ed25519-only record has no row;
    /// a row reads back to the object it was minted from.
    #[test]
    fn a_record_row_is_signed_at_its_head_instant() {
        let founded = plan_group_row(&family(None)).unwrap().unwrap();
        assert_eq!(
            founded.asserted_at.to_rfc3339(),
            "2026-01-01T00:00:00+00:00"
        );
        let amended = plan_group_row(&family(Some(GroupSupersedeProof {
            prior_persist_row_hash: "prior".into(),
            change_envelope: serde_json::json!({
                super::super::canonical_community::AMENDED_AT: "2026-03-04T05:06:07Z"
            }),
            quorum_signatures: Vec::new(),
        })))
        .unwrap()
        .unwrap();
        assert_eq!(
            amended.asserted_at.to_rfc3339(),
            "2026-03-04T05:06:07+00:00"
        );
        assert_eq!(
            group_signed_of_row(&founded).unwrap(),
            Some(family(None)),
            "the row carries its object"
        );
        let mut ed25519_only = family(None);
        if let GroupSigned::Family(f) = &mut ed25519_only {
            f.scrub_signature_pqc = None;
        }
        assert!(plan_group_row(&ed25519_only).unwrap().is_none());
        // Unsigned either way: no signer, or no signature.
        for unsigned in [
            |f: &mut SignedFamily| f.authority_key_id.clear(),
            |f: &mut SignedFamily| f.scrub_signature_classical.clear(),
        ] {
            let mut g = family(None);
            if let GroupSigned::Family(f) = &mut g {
                unsigned(f);
            }
            assert!(plan_group_row(&g).unwrap().is_none());
        }
        // T6's two digests ride beside the record when it has them, and only
        // then.
        let mut g = family(None);
        if let GroupSigned::Family(f) = &mut g {
            f.family.prev_head_digest = "aa".repeat(32);
        }
        let row = plan_group_row(&g).unwrap().unwrap();
        assert_eq!(
            row.attestation_envelope[PREV_HEAD_DIGEST_MEMBER],
            "aa".repeat(32)
        );
        assert!(row
            .attestation_envelope
            .get(CHARTER_DIGEST_MEMBER)
            .is_none());
        let mut c = GroupSigned::Community(SignedCommunity {
            community: super::super::types::Community {
                community_key_id: "room".into(),
                community_name: "room".into(),
                members: Vec::new(),
                founded_at: "2026-01-01T00:00:00Z".parse().unwrap(),
                consensus_protocol: "quorum:1/1".into(),
                policy_blob: None,
                prev_head_digest: String::new(),
                charter_digest: "bb".repeat(32),
                persist_row_hash: String::new(),
            },
            authority_key_id: "ann".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: Some("cHFj".into()),
            supersede_proof: None,
            cosignatures: Vec::new(),
            lineage: Vec::new(),
        });
        let row = plan_group_row(&c).unwrap().unwrap();
        assert_eq!(
            row.attestation_envelope[CHARTER_DIGEST_MEMBER],
            "bb".repeat(32)
        );
        assert!(row
            .attestation_envelope
            .get(PREV_HEAD_DIGEST_MEMBER)
            .is_none());
        if let GroupSigned::Community(x) = &mut c {
            x.community.charter_digest.clear();
        }
        let row = plan_group_row(&c).unwrap().unwrap();
        assert!(row
            .attestation_envelope
            .get(CHARTER_DIGEST_MEMBER)
            .is_none());
    }

    /// Outside the door, a group-plane dimension is a retraction's (which
    /// names its target) or nobody's.
    #[test]
    fn a_group_dimension_outside_the_door_is_refused() {
        for t in [attestation_type::WITHDRAWS, attestation_type::RECANTS] {
            check_generic_row_dimension(t, GROUP_ROSTER_DIMENSION).unwrap();
        }
        for t in [attestation_type::SCORES, attestation_type::DELEGATES_TO] {
            for f in GroupPlaneFamily::ALL {
                assert!(check_generic_row_dimension(t, f.dimension()).is_err());
            }
        }
        check_generic_row_dimension(attestation_type::DELEGATES_TO, "membership:proposal:v1")
            .unwrap();
    }

    /// The wire names CC cites (posted on CIRISPersist#991): the envelope
    /// member each family's object rides under, the kind spelling and its
    /// cohort target, and the table names the projections are read from.
    #[test]
    fn the_wire_names_are_pinned() {
        assert_eq!(GroupPlaneFamily::Roster.member(), "group_record");
        assert_eq!(GroupPlaneFamily::Widening.member(), "widening");
        assert_eq!(GroupPlaneFamily::Removal.member(), "revocation");
        assert_eq!(GroupPlaneFamily::Resignation.member(), "revocation");
        assert_eq!(GroupKind::Family.as_str(), "family");
        assert_eq!(GroupKind::Community.as_str(), "community");
        assert_eq!(GroupKind::Family.target_member(), "family_key_id");
        assert_eq!(GroupKind::Community.target_member(), "community_key_id");
        assert_eq!(GroupKind::of_str("family"), Some(GroupKind::Family));
        assert_eq!(GroupKind::of_str("community"), Some(GroupKind::Community));
        assert_eq!(GroupKind::of_str("self"), None);
        for (t, name) in [
            (GroupPlaneTable::Families, "federation_families"),
            (GroupPlaneTable::Communities, "federation_communities"),
            (
                GroupPlaneTable::FamilyRevocations,
                "federation_family_membership_revocations",
            ),
            (
                GroupPlaneTable::CommunityRevocations,
                "federation_community_membership_revocations",
            ),
            (
                GroupPlaneTable::FamilyWidenings,
                "federation_family_membership_widenings",
            ),
            (
                GroupPlaneTable::CommunityWidenings,
                "federation_community_membership_widenings",
            ),
        ] {
            assert_eq!(t.as_str(), name);
            assert_eq!(t.projection().as_str(), name);
        }
        // Every family's id domain is its own: one object never names two
        // rows of different families.
        let domains: std::collections::BTreeSet<&[u8]> = GroupPlaneFamily::ALL
            .iter()
            .map(|f| f.id_domain())
            .collect();
        assert_eq!(domains.len(), GroupPlaneFamily::ALL.len());
        for f in GroupPlaneFamily::ALL {
            let d = std::str::from_utf8(f.id_domain()).unwrap();
            assert_eq!(d, format!("ciris:{}:", f.dimension()));
        }
    }
}
