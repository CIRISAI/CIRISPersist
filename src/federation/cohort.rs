//! #249 Cut G1 — the uniform **rostered-group** surface (CIRISServer #249
//! write+governance ask, §1/§2/§6/§Q1-self).
//!
//! Framing (CIRISServer #249): `self` (identity_occurrences), `family`, and
//! `community` are the three **rostered groups** — the same machine
//! (`members[]` + an append-only revocation table + the
//! `roster − effective revocations` fold) at three points on the visibility
//! gradient. Today persist exposes that machine **three times** as mirrored
//! `*_family_*` / `*_community_*` / occurrence-* method sets, so every
//! consumer branches family-vs-community-vs-self by hand and persist
//! maintains the mirror 3×. This module is the single **cohort-parameterized**
//! surface over those three sets, so consumers write rostered-group ops once.
//!
//! The uniform methods live as **default methods on
//! [`FederationDirectory`](crate::federation::FederationDirectory)** — they
//! compose the existing per-backend mirrored methods, so backend parity
//! (pg / sqlite / memory) is inherited for free and no backend override is
//! needed.
//!
//! ## Cohort coverage (CIRISServer #249 Q1/Q4; CC 4.4.3.2.8 / #308)
//! As of v11.4.0 (CC 4.4.3.2.8, CIRISPersist#308) `affiliations` is the
//! **fourth** rostered group. The Q1 "open shape question" resolved in its
//! favor: `affiliations` shares the `community` machinery EXACTLY — the same
//! `federation_communities` storage + `*_community_*` lifecycle, and the same
//! [`CommunityDek`](crate::federation::types::cohort_scope::CryptoTier::CommunityDek)
//! crypto tier with epoch-bump-on-removal forward secrecy (CC 4.4.3.2.2). It is
//! distinguished only by its visibility-gradient position on the wire
//! (`cohort_scope: "affiliations"`). `species` / `biosphere` / `federation`
//! remain audience scopes with **no roster table**, so they are NOT cohorts.
//! [`Cohort`] stays `#[non_exhaustive]` so any further tier joins later without
//! a breaking change.
//!
//! The compartments[] / per-compartment-DEK / per-member-exclusion limb of
//! CC 4.4.3.2.8 is a separate larger Rust-lane item and is NOT in #308.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::types;

/// One of the four rostered-group kinds. Serializes to the wire scope token
/// (`"self"` / `"family"` / `"community"` / `"affiliations"`) so the cohort
/// dispatch is portable over FFI / JSON.
///
/// `#[non_exhaustive]` — see the module docs. As of v11.4.0 (CC 4.4.3.2.8,
/// CIRISPersist#308) `affiliations` is the **fourth** rostered tier, sharing
/// the `community` machinery exactly (same `federation_communities` storage,
/// same per-`(group, epoch)` [`CommunityDek`] cascade with epoch-bump-on-
/// removal forward secrecy). The enum stays `#[non_exhaustive]` so any further
/// tier joins later without breaking callers.
///
/// [`CommunityDek`]: crate::federation::types::cohort_scope::CryptoTier::CommunityDek
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Cohort {
    /// The `self` collective — an identity_key and its device/incarnation
    /// occurrences (`federation_identity_occurrences`). No quorum.
    #[serde(rename = "self")]
    SelfId,
    /// A `family` (`federation_families`) — the entrenched-able M-of-N group
    /// the accord rides on.
    #[serde(rename = "family")]
    Family,
    /// A `community` (`federation_communities`).
    #[serde(rename = "community")]
    Community,
    /// An `affiliations` group (CC 4.4.3.2.8, CIRISPersist#308) — the fourth
    /// rostered tier. Shares the `community` machinery EXACTLY: the same
    /// `federation_communities` rows / `*_community_*` membership lifecycle and
    /// the same [`CommunityDek`] crypto tier (epoch-bump-on-removal forward
    /// secrecy). It differs from `community` only in its visibility-gradient
    /// position on the wire (`cohort_scope: "affiliations"`).
    ///
    /// [`CommunityDek`]: crate::federation::types::cohort_scope::CryptoTier::CommunityDek
    #[serde(rename = "affiliations")]
    Affiliations,
}

impl Cohort {
    /// The wire scope token (`"self"` / `"family"` / `"community"` /
    /// `"affiliations"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Cohort::SelfId => "self",
            Cohort::Family => "family",
            Cohort::Community => "community",
            Cohort::Affiliations => "affiliations",
        }
    }

    /// `true` iff this cohort shares the `community` rostered machinery — the
    /// `federation_communities` storage + the [`CommunityDek`] cascade. Both
    /// `community` and `affiliations` (CC 4.4.3.2.8) resolve `true`; `self` and
    /// `family` resolve `false`. The single predicate every community-routing
    /// dispatch arm consults, so the two tiers never fork.
    ///
    /// [`CommunityDek`]: crate::federation::types::cohort_scope::CryptoTier::CommunityDek
    pub fn shares_community_machinery(&self) -> bool {
        matches!(self, Cohort::Community | Cohort::Affiliations)
    }

    /// Parse the wire scope token. `Err` (the offending token) for anything
    /// that is not a rostered cohort (e.g. `"species"` / `"federation"` — those
    /// are audience scopes with no roster table).
    pub fn from_token(s: &str) -> Result<Cohort, String> {
        match s {
            "self" => Ok(Cohort::SelfId),
            "family" => Ok(Cohort::Family),
            "community" => Ok(Cohort::Community),
            "affiliations" => Ok(Cohort::Affiliations),
            other => Err(other.to_string()),
        }
    }
}

/// A roster entry, uniform across the three cohorts (the read shape §1/§2).
///
/// For `family`/`community` this is the `members[]` entry verbatim; for `self`
/// it projects an `IdentityOccurrence` (`key_id` = the occurrence key,
/// `joined_at` = `asserted_at`, `role` = the `device_class`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterMember {
    /// The member's `federation_keys.key_id` (an occurrence key for `self`).
    pub key_id: String,
    /// When the member joined the roster (`asserted_at` for a `self`
    /// occurrence).
    pub joined_at: DateTime<Utc>,
    /// Optional role tag (the `device_class` for a `self` occurrence).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

impl From<types::FamilyMember> for RosterMember {
    fn from(m: types::FamilyMember) -> Self {
        RosterMember {
            key_id: m.key_id,
            joined_at: m.joined_at,
            role: m.role,
        }
    }
}

impl From<types::CommunityMember> for RosterMember {
    fn from(m: types::CommunityMember) -> Self {
        RosterMember {
            key_id: m.key_id,
            joined_at: m.joined_at,
            role: m.role,
        }
    }
}

impl From<types::IdentityOccurrence> for RosterMember {
    fn from(o: types::IdentityOccurrence) -> Self {
        RosterMember {
            key_id: o.occurrence_key_id,
            joined_at: o.asserted_at,
            role: Some(o.device_class),
        }
    }
}

/// The knobs of a roster removal / swap-out (#249 Cut G1 §1/§6), uniform
/// across the three cohorts. `effective_at` may be future-dated (the member
/// stays active until it arrives); `witness_set` is the vouch set — the
/// member cosignatures the Cut G3 quorum gate will count land here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeSpec {
    /// When the removal takes effect (`effective_at <= now` ⇒ active-drop).
    pub effective_at: DateTime<Utc>,
    /// Optional operator/ceremony annotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Vouch set (`federation_keys.key_id`s) — Cut G3's quorum cosignatures.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness_set: Vec<String>,
}

/// A group identity, uniform across the three cohorts (the `lookup_group` /
/// `groups_of` shape §1). `name` / `consensus_protocol` / `founded_at` are
/// `None` for the `self` cohort (the identity_key IS the group; it carries no
/// roster-row metadata).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupRef {
    /// Which rostered-group kind this is.
    pub cohort: Cohort,
    /// The group's `federation_keys.key_id` (the identity_key for `self`).
    pub group_key_id: String,
    /// Display name (family/community only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The group's `consensus_protocol` (family/community only) — the M-of-N /
    /// majority / founder_only rule a membership change must satisfy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consensus_protocol: Option<String>,
    /// When the group was founded (family/community only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub founded_at: Option<DateTime<Utc>>,
}

impl From<types::Family> for GroupRef {
    fn from(f: types::Family) -> Self {
        GroupRef {
            cohort: Cohort::Family,
            group_key_id: f.family_key_id,
            name: Some(f.family_name),
            consensus_protocol: Some(f.consensus_protocol),
            founded_at: Some(f.founded_at),
        }
    }
}

impl From<types::Community> for GroupRef {
    fn from(c: types::Community) -> Self {
        GroupRef {
            cohort: Cohort::Community,
            group_key_id: c.community_key_id,
            name: Some(c.community_name),
            consensus_protocol: Some(c.consensus_protocol),
            founded_at: Some(c.founded_at),
        }
    }
}

/// One version of a rostered group's history (#249 Cut G2 §8). The live
/// (current) version and every superseded prior version share this shape, so
/// `group_history` returns a uniform chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupVersion {
    /// Which rostered-group kind (`family` / `community`; `self` is not
    /// versioned).
    pub cohort: Cohort,
    /// The group's `federation_keys.key_id`.
    pub group_key_id: String,
    /// Monotonic version number (genesis = 1; each `supersede` increments).
    pub version: u32,
    /// The full `Family` / `Community` row at this version (JSON).
    pub snapshot: serde_json::Value,
    /// The membership-change authorization that PRODUCED this version (the Cut
    /// G3 quorum envelope + cosignatures), or `None` (genesis / a plain
    /// pre-supersede `put`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<serde_json::Value>,
    /// When this version was superseded by the next. `None` ⇒ the live
    /// (current) version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_at: Option<DateTime<Utc>>,
    /// `true` for the current live version, `false` for a historical one.
    pub is_current: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cohort_token_roundtrips_and_rejects_non_rostered() {
        for c in [
            Cohort::SelfId,
            Cohort::Family,
            Cohort::Community,
            Cohort::Affiliations,
        ] {
            assert_eq!(Cohort::from_token(c.as_str()), Ok(c));
        }
        // `self` serializes to the wire token, not the Rust ident.
        assert_eq!(Cohort::SelfId.as_str(), "self");
        // CC 4.4.3.2.8 / #308: `affiliations` is now an admitted rostered
        // cohort (no longer rejected at the boundary).
        assert_eq!(Cohort::from_token("affiliations"), Ok(Cohort::Affiliations));
        assert_eq!(Cohort::Affiliations.as_str(), "affiliations");
        // audience scopes with no roster table are still not cohorts.
        assert_eq!(
            Cohort::from_token("federation"),
            Err("federation".to_string())
        );
        assert_eq!(Cohort::from_token("species"), Err("species".to_string()));
    }

    #[test]
    fn affiliations_shares_community_machinery() {
        // The single predicate every community-routing dispatch arm consults.
        assert!(Cohort::Community.shares_community_machinery());
        assert!(Cohort::Affiliations.shares_community_machinery());
        assert!(!Cohort::Family.shares_community_machinery());
        assert!(!Cohort::SelfId.shares_community_machinery());
    }

    #[test]
    fn cohort_serde_is_the_wire_token() {
        assert_eq!(serde_json::to_string(&Cohort::SelfId).unwrap(), "\"self\"");
        assert_eq!(
            serde_json::to_string(&Cohort::Community).unwrap(),
            "\"community\""
        );
        assert_eq!(
            serde_json::to_string(&Cohort::Affiliations).unwrap(),
            "\"affiliations\""
        );
        let c: Cohort = serde_json::from_str("\"family\"").unwrap();
        assert_eq!(c, Cohort::Family);
        let a: Cohort = serde_json::from_str("\"affiliations\"").unwrap();
        assert_eq!(a, Cohort::Affiliations);
    }
}
