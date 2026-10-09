//! v54.0.0 (CIRISPersist#1034, CC 4.4.3.2.8) — **an affiliation is declared,
//! and its config record is typed.**
//!
//! CC 4.4.3.2.8: an affiliation (`cohort_scope: affiliations`) is a community
//! record that gathers by necessity, shares all the community machinery, and
//! adds institutional governance "through one declared config record".
//! Everything in that record is "DECLARED at creation and visible to members on
//! joining". Before this cut persist had none of it:
//!
//! 1. **Nothing said a record IS an affiliation.** `Community` carries no
//!    cohort and `put_community` takes none, so any community could be
//!    addressed as `affiliations` and the reverse.
//! 2. **The config record had no storage, typing or admission.** "A value MUST
//!    resolve" (CC 4.4.3.2.8 A) was unenforced.
//!
//! # The discriminator lives in the SIGNED record
//!
//! The cohort is declared in the record's `policy_blob` as
//! [`POLICY_COHORT_FIELD`] (`"cohort_scope": "affiliations"`) — the label the
//! `Community` doc already names as `policy_blob`'s membership label
//! (CIRISEdge#48-A), and the key adopters' records already carry. Absent
//! means `community`, so every record founded without it keeps its bytes and
//! its meaning. What changes is that persist now READS it. It is persisted at founding because the record is — inside
//! the bytes its founders signed, covered by `persist_row_hash`, and carried
//! to every peer by the same replication that carries the roster. A database
//! column set by a door argument would be none of those: unsigned, local, and
//! absent on a replica. [`declared_cohort`] is the one reading.
//!
//! It is immutable: a supersession whose declared cohort differs from the held
//! record's is refused ([`Error::AffiliationCohortMismatch`]), and so is any
//! door that addresses a held record under the other cohort
//! ([`check_group_cohort`]) — the supersede doors, the membership write doors,
//! and the attestation write-scope gate's room lookup.
//!
//! # The config record
//!
//! [`AffiliationConfig`], at `policy_blob.affiliation_config`, types the limbs
//! CC names as fields: `affiliation_archetype`, `membership_basis`,
//! `classification_scheme`, `retention_policy`, `hierarchy`,
//! `designated_officials`, `compartments`, and `role_term`
//! (CIRISConstitution#163, the charter's term under the one-year ceiling).
//! Every other CC 4.4.3.2.8 limb (`legal_hold`, `erasure_policy`,
//! `lawful_access`, …) is carried verbatim in [`AffiliationConfig::other`]:
//! declared and visible, not yet typed. A config on a record that does not
//! declare `affiliations` is refused — the machinery is never forced on a body
//! that is "simply a community".
//!
//! [`check_community_record`] validates at founding (every backend's community
//! door) and on supersession (the shared supersede path).
//! [`AffiliationConfig::resolve`] is "a value MUST resolve": explicit field,
//! else the archetype's preset, else the canonical no-op default (one
//! `internal` class; retention `rotate-forward`).

use super::cohort::Cohort;
use super::types::Community;
use super::{Error, FederationDirectory};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The `policy_blob` member that declares a community-plane record's cohort
/// (the existing CIRISEdge#48-A membership label).
pub const POLICY_COHORT_FIELD: &str = "cohort_scope";
/// The `policy_blob` member that carries the CC 4.4.3.2.8 config record.
pub const POLICY_AFFILIATION_CONFIG_FIELD: &str = "affiliation_config";
/// The canonical no-op classification class (CC 4.4.3.2.8 A).
pub const DEFAULT_CLASS: &str = "internal";
/// The constitutional ceiling on a role term, in days: "at most one year
/// after `delegation_valid_from`" (CC 4.4.3.2.8 C, CIRISConstitution#163).
pub const ROLE_TERM_CEILING_DAYS: u32 = 365;

/// The refusal rules of [`Error::AffiliationConfigInvalid`]. Stable tokens;
/// append-only.
pub mod rule {
    /// `policy_blob.cohort_scope` is not `community` or `affiliations`.
    pub const COHORT_UNKNOWN: &str = "cohort_unknown";
    /// A config record on a record that does not declare `affiliations`.
    pub const CONFIG_ON_COMMUNITY: &str = "config_on_community";
    /// The config record does not parse as the typed record.
    pub const CONFIG_MALFORMED: &str = "config_malformed";
    /// `classification_scheme.classes` is empty, or a class name is empty or
    /// repeated.
    pub const CLASSIFICATION_INVALID: &str = "classification_invalid";
    /// `retention_policy` names a class the resolved scheme does not declare.
    pub const RETENTION_UNKNOWN_CLASS: &str = "retention_unknown_class";
    /// A class's retention floor lies past its ceiling (or a `permanent`
    /// class declares a ceiling).
    pub const RETENTION_FLOOR_ABOVE_CEILING: &str = "retention_floor_above_ceiling";
    /// A compartment name is empty or repeated, a class names a compartment
    /// that is not declared, or a compartment member is not on the roster
    /// ("membership ⊆ roster").
    pub const COMPARTMENT_INVALID: &str = "compartment_invalid";
    /// `role_term` is zero or past the one-year ceiling.
    pub const ROLE_TERM_OUT_OF_RANGE: &str = "role_term_out_of_range";
    /// `hierarchy.depth_cap` is zero or past the absolute delegation ceiling.
    pub const HIERARCHY_DEPTH_OUT_OF_RANGE: &str = "hierarchy_depth_out_of_range";
    /// A designated official names an empty role or key.
    pub const DESIGNATED_OFFICIAL_INVALID: &str = "designated_official_invalid";
}

/// CC 4.4.3.2.8's named presets. Closed: a preset persist does not know
/// cannot resolve, and "a value MUST resolve".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AffiliationArchetype {
    /// A small committee served by construction (the holiday-party row).
    InformalAdhoc,
    /// A nonprofit board.
    NonprofitBoard,
    /// A healthcare provider.
    HealthcareProvider,
    /// A legal practice.
    LegalPractice,
    /// A government body.
    GovBody,
    /// An intergovernmental organisation (the UN / IGO row).
    Igo,
}

/// CC 4.4.3.2.8 — the necessity axis, orthogonal to `cohort_scope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MembershipBasis {
    /// Voluntarily entered yet total (a collective settlement, an order).
    VoluntaryTotal,
    /// Ascribed (a member-state principal).
    Ascriptive,
    /// Assigned by role (the workplace committee).
    RoleAssigned,
    /// By employment contract.
    EmploymentContract,
}

/// One basis or several (CC's IGO row is `employment-contract + ascriptive`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MembershipBasisDecl {
    /// A single basis.
    One(MembershipBasis),
    /// Several.
    Many(Vec<MembershipBasis>),
}

impl MembershipBasisDecl {
    /// The declared set, sorted and deduplicated.
    #[must_use]
    pub fn set(&self) -> Vec<MembershipBasis> {
        let s: BTreeSet<MembershipBasis> = match self {
            Self::One(b) => std::iter::once(*b).collect(),
            Self::Many(v) => v.iter().copied().collect(),
        };
        s.into_iter().collect()
    }
}

/// One class of the sensitivity lattice and its bindings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassEntry {
    /// The class name (`content_class` value).
    pub name: String,
    /// The compartment this class binds to, if any; must be declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compartment: Option<String>,
    /// Non-erasable during retention (the declared N5 gate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erasure_exempt: Option<bool>,
    /// The remaining bindings (`crypto_tier`, `disclosure_bar`,
    /// `external_controller`, …), carried verbatim.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// CC 4.4.3.2.8 A — an ordered lattice (lowest first) plus handling tags.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassificationScheme {
    /// The classes, lowest sensitivity first.
    pub classes: Vec<ClassEntry>,
    /// Open-vocabulary handling tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handling_tags: Vec<String>,
}

/// A retention floor: a minimum in days, or `permanent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RetentionFloor {
    /// Must not delete before this many days.
    Days(u32),
    /// The literal `"permanent"`.
    Permanent(PermanentToken),
}

/// The literal `"permanent"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermanentToken {
    /// `"permanent"`.
    Permanent,
}

/// One class's retention row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassRetention {
    /// The floor (`retain_minimum`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_minimum: Option<RetentionFloor>,
    /// The ceiling (`delete_after`), in days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_after: Option<u32>,
    /// Days added to the floor for a record about a minor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minor_age_of_majority_offset: Option<u32>,
    /// The declared legal basis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_basis: Option<String>,
}

/// The literal `"rotate-forward"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RotateForward {
    /// `"rotate-forward"` — the CC 6.1.2 noise-floor default.
    RotateForward,
}

/// CC 4.4.3.2.8 A — retention: the noise-floor default, or per class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RetentionPolicy {
    /// `"rotate-forward"`.
    RotateForward(RotateForward),
    /// Per-class rows keyed by class name.
    PerClass(BTreeMap<String, ClassRetention>),
}

/// CC 4.4.3.2.8 C — hierarchy over `delegates_to`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hierarchy {
    /// The configurable depth cap (> the CC 4.1.1 default 5 for deep
    /// secretariats), never past the absolute ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth_cap: Option<u32>,
    /// Roles, branches and nested sub-affiliations, carried verbatim.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// CC 4.4.3.2.8 C — a named accountable-human root for an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesignatedOfficial {
    /// The office (`privacy_officer`, `records_officer`, …).
    pub role: String,
    /// The accountable human's key.
    pub key_id: String,
}

/// CC 4.4.3.2.8 B — a need-to-know sub-cohort, membership ⊆ roster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Compartment {
    /// The compartment name.
    pub name: String,
    /// Members; each must be on the affiliation's roster.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
    /// The per-member deny-list (ethical walls).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclusions: Vec<String>,
}

/// v54.0.0 (CIRISPersist#1034, CC 4.4.3.2.8) — the typed config record.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct AffiliationConfig {
    /// The preset that pre-fills every unset field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affiliation_archetype: Option<AffiliationArchetype>,
    /// The necessity axis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_basis: Option<MembershipBasisDecl>,
    /// MANDATORY-with-default limb.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification_scheme: Option<ClassificationScheme>,
    /// MANDATORY-with-default limb.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_policy: Option<RetentionPolicy>,
    /// OPTIONAL limb.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hierarchy: Option<Hierarchy>,
    /// OPTIONAL limb.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub designated_officials: Option<Vec<DesignatedOfficial>>,
    /// OPTIONAL limb.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compartments: Option<Vec<Compartment>>,
    /// The charter's role term in days (CIRISConstitution#163), at most
    /// [`ROLE_TERM_CEILING_DAYS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_term: Option<u32>,
    /// Every other declared CC 4.4.3.2.8 limb, carried verbatim.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// The config with every mandatory limb resolved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedAffiliationConfig {
    /// The preset, if one was declared.
    pub affiliation_archetype: Option<AffiliationArchetype>,
    /// The resolved basis set (empty when neither declared nor preset).
    pub membership_basis: Vec<MembershipBasis>,
    /// The resolved lattice, lowest first.
    pub classification_scheme: ClassificationScheme,
    /// The resolved retention.
    pub retention_policy: RetentionPolicy,
}

fn class(name: &str) -> ClassEntry {
    ClassEntry {
        name: name.to_owned(),
        compartment: None,
        erasure_exempt: None,
        other: serde_json::Map::new(),
    }
}

fn scheme(names: &[&str]) -> ClassificationScheme {
    ClassificationScheme {
        classes: names.iter().map(|n| class(n)).collect(),
        handling_tags: Vec::new(),
    }
}

/// The canonical no-op default (CC 4.4.3.2.8 A).
#[must_use]
pub fn default_classification() -> ClassificationScheme {
    scheme(&[DEFAULT_CLASS])
}

/// What an archetype pre-fills. Only values CC 4.4.3.2.8's own text gives are
/// filled (its instantiation table pins `informal_adhoc` and `igo`); every
/// other preset resolves each limb to the canonical default until CC publishes
/// the preset table.
fn preset(a: AffiliationArchetype) -> (Vec<MembershipBasis>, Option<ClassificationScheme>) {
    use MembershipBasis as B;
    match a {
        AffiliationArchetype::InformalAdhoc => (vec![B::RoleAssigned], None),
        AffiliationArchetype::Igo => (
            vec![B::Ascriptive, B::EmploymentContract],
            Some(scheme(&[
                "Unclassified",
                "Confidential",
                "Strictly-Confidential",
            ])),
        ),
        AffiliationArchetype::NonprofitBoard
        | AffiliationArchetype::HealthcareProvider
        | AffiliationArchetype::LegalPractice
        | AffiliationArchetype::GovBody => (Vec::new(), None),
    }
}

fn invalid(group: &str, rule: &'static str, detail: impl Into<String>) -> Error {
    Error::AffiliationConfigInvalid {
        group_key_id: group.to_owned(),
        rule,
        detail: detail.into(),
    }
}

impl AffiliationConfig {
    /// "A value MUST resolve": explicit field, else the archetype's preset,
    /// else the canonical no-op default.
    #[must_use]
    pub fn resolve(&self) -> ResolvedAffiliationConfig {
        let (preset_basis, preset_scheme) = self
            .affiliation_archetype
            .map(preset)
            .unwrap_or((Vec::new(), None));
        ResolvedAffiliationConfig {
            affiliation_archetype: self.affiliation_archetype,
            membership_basis: self
                .membership_basis
                .as_ref()
                .map(MembershipBasisDecl::set)
                .unwrap_or(preset_basis),
            classification_scheme: self
                .classification_scheme
                .clone()
                .or(preset_scheme)
                .unwrap_or_else(default_classification),
            retention_policy: self
                .retention_policy
                .clone()
                .unwrap_or(RetentionPolicy::RotateForward(RotateForward::RotateForward)),
        }
    }

    /// Validate against the record it rides on (`group` names it in a
    /// refusal; `roster` is its member key ids).
    ///
    /// # Errors
    /// [`Error::AffiliationConfigInvalid`] naming the [`rule`] that failed.
    pub fn validate(&self, group: &str, roster: &BTreeSet<&str>) -> Result<(), Error> {
        let resolved = self.resolve();
        let mut names = BTreeSet::new();
        if resolved.classification_scheme.classes.is_empty() {
            return Err(invalid(group, rule::CLASSIFICATION_INVALID, "no classes"));
        }
        for c in &resolved.classification_scheme.classes {
            if c.name.is_empty() || !names.insert(c.name.as_str()) {
                return Err(invalid(
                    group,
                    rule::CLASSIFICATION_INVALID,
                    format!("class name {:?} is empty or repeated", c.name),
                ));
            }
        }
        let mut compartments = BTreeSet::new();
        for comp in self.compartments.iter().flatten() {
            if comp.name.is_empty() || !compartments.insert(comp.name.as_str()) {
                return Err(invalid(
                    group,
                    rule::COMPARTMENT_INVALID,
                    format!("compartment name {:?} is empty or repeated", comp.name),
                ));
            }
            if let Some(m) = comp.members.iter().find(|m| !roster.contains(m.as_str())) {
                return Err(invalid(
                    group,
                    rule::COMPARTMENT_INVALID,
                    format!(
                        "compartment {:?} names {m:?}, who is not on the roster (membership ⊆ roster)",
                        comp.name
                    ),
                ));
            }
        }
        for c in &resolved.classification_scheme.classes {
            if let Some(comp) = &c.compartment {
                if !compartments.contains(comp.as_str()) {
                    return Err(invalid(
                        group,
                        rule::COMPARTMENT_INVALID,
                        format!("class {:?} binds undeclared compartment {comp:?}", c.name),
                    ));
                }
            }
        }
        if let RetentionPolicy::PerClass(rows) = &resolved.retention_policy {
            for (name, row) in rows {
                if !names.contains(name.as_str()) {
                    return Err(invalid(
                        group,
                        rule::RETENTION_UNKNOWN_CLASS,
                        format!("retention row for undeclared class {name:?}"),
                    ));
                }
                let floor_past_ceiling = match (&row.retain_minimum, row.delete_after) {
                    (Some(RetentionFloor::Permanent(_)), Some(_)) => true,
                    (Some(RetentionFloor::Days(min)), Some(max)) => min > &max,
                    _ => false,
                };
                if floor_past_ceiling {
                    return Err(invalid(
                        group,
                        rule::RETENTION_FLOOR_ABOVE_CEILING,
                        format!("class {name:?}: retain_minimum lies past delete_after"),
                    ));
                }
            }
        }
        if let Some(t) = self.role_term {
            if t == 0 || t > ROLE_TERM_CEILING_DAYS {
                return Err(invalid(
                    group,
                    rule::ROLE_TERM_OUT_OF_RANGE,
                    format!("role_term {t} days; 1..={ROLE_TERM_CEILING_DAYS} (one-year ceiling)"),
                ));
            }
        }
        if let Some(d) = self.hierarchy.as_ref().and_then(|h| h.depth_cap) {
            let ceiling = super::admission::MAX_WITHDRAWS_DELEGATION_DEPTH;
            if d == 0 || d as usize > ceiling {
                return Err(invalid(
                    group,
                    rule::HIERARCHY_DEPTH_OUT_OF_RANGE,
                    format!("hierarchy.depth_cap {d}; 1..={ceiling}"),
                ));
            }
        }
        if let Some(o) = self
            .designated_officials
            .iter()
            .flatten()
            .find(|o| o.role.is_empty() || o.key_id.is_empty())
        {
            return Err(invalid(
                group,
                rule::DESIGNATED_OFFICIAL_INVALID,
                format!("designated official {o:?} names an empty role or key"),
            ));
        }
        Ok(())
    }
}

/// The cohort a community-plane record declares — the ONE reading.
///
/// `policy_blob` absent, not an object, or without [`POLICY_COHORT_FIELD`]
/// ⇒ [`Cohort::Community`] (every pre-v54 record). `"community"` /
/// `"affiliations"` ⇒ that cohort.
///
/// # Errors
/// [`Error::AffiliationConfigInvalid`] (`cohort_unknown`) for any other value:
/// malformed is a refusal, never absence.
pub fn declared_cohort(c: &Community) -> Result<Cohort, Error> {
    let Some(v) = c
        .policy_blob
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|o| o.get(POLICY_COHORT_FIELD))
    else {
        return Ok(Cohort::Community);
    };
    match v.as_str() {
        Some("community") => Ok(Cohort::Community),
        Some("affiliations") => Ok(Cohort::Affiliations),
        _ => Err(invalid(
            &c.community_key_id,
            rule::COHORT_UNKNOWN,
            format!("policy_blob.{POLICY_COHORT_FIELD} = {v}; expected \"community\" or \"affiliations\""),
        )),
    }
}

/// The record's typed config, if it carries one (no validation).
///
/// # Errors
/// `config_malformed` for a present member that does not parse.
pub fn affiliation_config_of(c: &Community) -> Result<Option<AffiliationConfig>, Error> {
    let Some(v) = c
        .policy_blob
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|o| o.get(POLICY_AFFILIATION_CONFIG_FIELD))
    else {
        return Ok(None);
    };
    serde_json::from_value(v.clone())
        .map(Some)
        .map_err(|e| invalid(&c.community_key_id, rule::CONFIG_MALFORMED, e.to_string()))
}

/// The resolved config of an affiliation record (`None` for a community).
/// An affiliation that declares no config resolves to the no-op default.
///
/// # Errors
/// As [`check_community_record`].
pub fn resolved_affiliation_config(
    c: &Community,
) -> Result<Option<ResolvedAffiliationConfig>, Error> {
    check_community_record(c)?;
    if declared_cohort(c)? != Cohort::Affiliations {
        return Ok(None);
    }
    Ok(Some(
        affiliation_config_of(c)?.unwrap_or_default().resolve(),
    ))
}

/// v54.0.0 (CIRISPersist#1034) — **the record-shape gate**, at founding (every
/// backend's community door) and on supersession: the declared cohort parses,
/// a config rides only on an affiliation, and an affiliation's config
/// validates against its own roster.
///
/// # Errors
/// [`Error::AffiliationConfigInvalid`].
pub fn check_community_record(c: &Community) -> Result<(), Error> {
    let cohort = declared_cohort(c)?;
    let config = affiliation_config_of(c)?;
    match (cohort, config) {
        (Cohort::Affiliations, config) => {
            let roster: BTreeSet<&str> = c.members.iter().map(|m| m.key_id.as_str()).collect();
            config
                .unwrap_or_default()
                .validate(&c.community_key_id, &roster)
        }
        (_, Some(_)) => Err(invalid(
            &c.community_key_id,
            rule::CONFIG_ON_COMMUNITY,
            format!(
                "policy_blob.{POLICY_AFFILIATION_CONFIG_FIELD} on a record that does not declare \
                 \"{POLICY_COHORT_FIELD}\": \"affiliations\" — a body with no use for institutional \
                 governance is simply a community (CC 4.4.3.2.8)"
            ),
        )),
        (_, None) => Ok(()),
    }
}

/// Refuse when `c` declares a cohort other than `addressed`.
///
/// # Errors
/// [`Error::AffiliationCohortMismatch`]; [`declared_cohort`]'s refusal.
pub fn check_record_is(c: &Community, addressed: Cohort) -> Result<(), Error> {
    let declared = declared_cohort(c)?;
    if declared == addressed {
        return Ok(());
    }
    Err(Error::AffiliationCohortMismatch {
        group_key_id: c.community_key_id.clone(),
        declared: declared.as_str(),
        addressed: addressed.as_str(),
    })
}

/// v54.0.0 (CIRISPersist#1034) — **a door that addresses a held
/// community-plane record under `cohort` must find it declared so.** A no-op
/// for `family` / `self`, and for a record this node does not hold (each door
/// answers absence its own way).
///
/// # Errors
/// [`Error::AffiliationCohortMismatch`].
pub async fn check_group_cohort<F>(dir: &F, cohort: Cohort, group_key_id: &str) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if !matches!(cohort, Cohort::Community | Cohort::Affiliations) {
        return Ok(());
    }
    match dir.lookup_community(group_key_id).await? {
        Some(held) => check_record_is(&held, cohort),
        None => Ok(()),
    }
}
