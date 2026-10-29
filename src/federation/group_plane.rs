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

    /// The link as one sortable string (the rebuild's row order).
    #[must_use]
    pub fn sort_key(&self) -> String {
        format!(
            "{}\u{1f}{}\u{1f}{}",
            self.group_key_id,
            self.member_key_id.as_deref().unwrap_or(""),
            self.effective_at
                .map(|t| {
                    super::admission::truncate_to_substrate_resolution(t)
                        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
                })
                .unwrap_or_default()
        )
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

    /// The signer of the object (its `authority_key_id`).
    #[must_use]
    pub fn authority_key_id(&self) -> &str {
        self.base().authority_key_id
    }

    /// The bytes every scrub covers: the object's own `signing_envelope()`.
    #[must_use]
    pub fn signing_envelope(&self) -> serde_json::Value {
        match self {
            Self::Family(s) => s.family.signing_envelope(),
            Self::Community(s) => s.community.signing_envelope(),
            Self::FamilyRevocation(s) => s.family_membership_revocation.signing_envelope(),
            Self::CommunityRevocation(s) => s.community_membership_revocation.signing_envelope(),
            Self::FamilyWidening(s) => s.family_membership_widening.signing_envelope(),
            Self::CommunityWidening(s) => s.community_membership_widening.signing_envelope(),
        }
    }

    /// Every scrub the row carries, base first: the object's authority scrub
    /// and each co-signature, in the row's `ScrubSig` shape.
    #[must_use]
    pub fn scrubs(&self) -> Vec<ScrubSig> {
        let base = self.base();
        std::iter::once(ScrubSig {
            scrub_key_id: base.authority_key_id.to_owned(),
            scrub_signature_classical: base.classical.to_owned(),
            scrub_signature_pqc: base.pqc.map(str::to_owned),
            cosigned_at: None,
        })
        .chain(base.cosignatures.iter().map(cosignature_scrub))
        .collect()
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
    /// [`Self::object`], the record's `persist_row_hash` recomputed. `None`
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
        let mut signed = match (family, kind) {
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
        signed.stamp_persist_row_hash().ok()?;
        (signed.family() == family).then_some(signed)
    }

    /// Recompute the record's `persist_row_hash` in place.
    ///
    /// # Errors
    ///
    /// [`Error::Backend`] when the record does not hash.
    pub fn stamp_persist_row_hash(&mut self) -> Result<(), Error> {
        use super::types::compute_persist_row_hash as h;
        match self {
            Self::Family(s) => s.family.persist_row_hash = h(&s.family)?,
            Self::Community(s) => s.community.persist_row_hash = h(&s.community)?,
            Self::FamilyRevocation(s) => {
                s.family_membership_revocation.persist_row_hash =
                    h(&s.family_membership_revocation)?;
            }
            Self::CommunityRevocation(s) => {
                s.community_membership_revocation.persist_row_hash =
                    h(&s.community_membership_revocation)?;
            }
            Self::FamilyWidening(s) => {
                s.family_membership_widening.persist_row_hash = h(&s.family_membership_widening)?;
            }
            Self::CommunityWidening(s) => {
                s.community_membership_widening.persist_row_hash =
                    h(&s.community_membership_widening)?;
            }
        }
        Ok(())
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
/// carries it and the `attestation_id` it names.
#[must_use]
pub fn render_group_projection(signed: &GroupSigned, attestation_id: Option<&str>) -> String {
    let mut claim = signed.object().unwrap_or(serde_json::Value::Null);
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
/// families and kind, read back and rendered, in primary-key order; and the
/// live table's signed rows rendered the same way. A signed record held
/// without its row, a row whose record is not held, or one member that
/// differs is a red.
#[must_use]
pub fn group_projection_rebuild(
    table: GroupPlaneTable,
    live: Vec<(GroupSigned, Option<String>)>,
    rows: &[Attestation],
) -> super::silo_projection::ProjectionRebuild {
    let mut live: Vec<(String, String)> = live
        .into_iter()
        .filter(|(s, _)| s.table() == table)
        .map(|(s, a)| {
            (
                s.link().sort_key(),
                render_group_projection(&s, a.as_deref()),
            )
        })
        .collect();
    let mut rebuilt: Vec<(String, String)> = rows
        .iter()
        .filter_map(|row| {
            let signed = group_signed_of_row(row).ok().flatten()?;
            (signed.table() == table).then(|| {
                (
                    signed.link().sort_key(),
                    render_group_projection(&signed, Some(&row.attestation_id)),
                )
            })
        })
        .collect();
    live.sort();
    rebuilt.sort();
    super::silo_projection::ProjectionRebuild {
        live: live.into_iter().map(|(_, r)| r).collect(),
        rebuilt: rebuilt.into_iter().map(|(_, r)| r).collect(),
    }
}

/// v61 (CIRISPersist#991) — what a backend does for the group plane.
/// Storage only: every decision is the shared plans'.
#[async_trait::async_trait]
pub(crate) trait GroupPlaneStore: super::FederationDirectory {
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
    let row = match dir.read_group_object(&link).await? {
        Some(signed) => plan_group_row(&signed)?,
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
    Ok(group_projection_rebuild(table, read.live, &read.rows))
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
}
