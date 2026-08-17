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

/// v31.0.0 (CIRISPersist#654) — **THE ONE PLACE A ROSTER GROWS.**
///
/// Appends `member` to `family`, recomputes the server-computed
/// `persist_row_hash` over the grown record, and hybrid-Strict-verifies
/// `spec`'s authority signature over the grown record's
/// [`signing_envelope`](types::Family::signing_envelope) through
/// [`verify_family_admission`](super::verify_family_admission) — the SAME gate
/// `put_family` and `supersede_family` run, not a second one written for the
/// add path.
///
/// Every backend calls this and then writes what it returns, so "what a roster
/// addition is signed over" is decided once. Verify-before-mutation (AV-9): the
/// gate runs before the caller's UPDATE, so a refused addition never touches
/// the row.
///
/// The constitutional family is reserved by that gate (#648) and therefore
/// cannot grow through this door either — its roster changes through the
/// genesis/assemble ceremony (`put_family_local`) and nothing else, which is
/// the same single-door property #648 established for its creation.
pub async fn authorize_family_growth<F>(
    directory: &F,
    family: &types::Family,
    member: types::FamilyMember,
    spec: &AdmitSpec,
) -> Result<types::Family, super::Error>
where
    F: super::FederationDirectory + ?Sized,
{
    let mut grown = family.clone();
    grown.members.push(member);
    let signed = super::SignedFamily {
        family: grown,
        authority_key_id: spec.authority_key_id.clone(),
        scrub_signature_classical: spec.scrub_signature_classical.clone(),
        scrub_signature_pqc: spec.scrub_signature_pqc.clone(),
    };
    super::verify_family_admission(directory, &signed).await?;
    let mut grown = signed.family;
    grown.persist_row_hash = types::compute_persist_row_hash(&grown)?;
    Ok(grown)
}

/// v31.0.0 (CIRISPersist#654) — the ONE place a test produces the authority
/// signature a roster addition now needs.
///
/// Every fixture on all three backends goes through these two helpers, so the
/// witness that a roster grow is signed cannot drift from the gate that checks
/// it — and a fixture that forgets to register `authority_key_id` fails closed
/// exactly as production would.
#[cfg(any(test, feature = "test-anchor"))]
pub mod test_support {
    use super::{types, AdmitSpec};

    /// The [`AdmitSpec`] for appending `member` to `family`, hybrid-signed by
    /// `authority_key_id`'s deterministic test keypair over the GROWN record's
    /// `signing_envelope()` — the exact preimage
    /// [`super::authorize_family_growth`] verifies.
    ///
    /// `authority_key_id` MUST already be registered (e.g. via
    /// `tier_ingest::test_support::register_hybrid_key`), the same precondition
    /// `sign_family` documents.
    pub fn admit_family(
        authority_key_id: &str,
        family: &types::Family,
        member: &types::FamilyMember,
    ) -> AdmitSpec {
        let mut grown = family.clone();
        grown.members.push(member.clone());
        let signed =
            crate::federation::tier_ingest::test_support::sign_family(authority_key_id, grown);
        AdmitSpec {
            authority_key_id: signed.authority_key_id,
            scrub_signature_classical: signed.scrub_signature_classical,
            scrub_signature_pqc: signed.scrub_signature_pqc,
        }
    }

    /// The community mirror of [`admit_family`].
    pub fn admit_community(
        authority_key_id: &str,
        community: &types::Community,
        member: &types::CommunityMember,
    ) -> AdmitSpec {
        let mut grown = community.clone();
        grown.members.push(member.clone());
        let signed =
            crate::federation::tier_ingest::test_support::sign_community(authority_key_id, grown);
        AdmitSpec {
            authority_key_id: signed.authority_key_id,
            scrub_signature_classical: signed.scrub_signature_classical,
            scrub_signature_pqc: signed.scrub_signature_pqc,
        }
    }

    /// Look the group up through `directory` and produce the [`AdmitSpec`] for
    /// appending `member` — the one-call form for the many fixtures that do not
    /// already hold the row.
    pub async fn admit_family_via<F>(
        directory: &F,
        authority_key_id: &str,
        family_key_id: &str,
        member: &types::FamilyMember,
    ) -> AdmitSpec
    where
        F: crate::federation::FederationDirectory + ?Sized,
    {
        let family = directory
            .lookup_family(family_key_id)
            .await
            .expect("lookup_family")
            .expect("family exists");
        admit_family(authority_key_id, &family, member)
    }

    /// The cohort-parameterized form, for fixtures driving the uniform
    /// [`add_member`](crate::federation::FederationDirectory::add_member) /
    /// [`swap_member`](crate::federation::FederationDirectory::swap_member)
    /// surface. `self` has no group row to sign over, so it returns an empty
    /// spec — that arm refuses before the spec is ever looked at.
    pub async fn admit_roster_member_via<F>(
        directory: &F,
        authority_key_id: &str,
        cohort: super::Cohort,
        group_key_id: &str,
        member: &super::RosterMember,
    ) -> AdmitSpec
    where
        F: crate::federation::FederationDirectory + ?Sized,
    {
        match cohort {
            super::Cohort::Family => {
                admit_family_via(
                    directory,
                    authority_key_id,
                    group_key_id,
                    &types::FamilyMember {
                        key_id: member.key_id.clone(),
                        joined_at: member.joined_at,
                        role: member.role.clone(),
                    },
                )
                .await
            }
            super::Cohort::Community | super::Cohort::Affiliations => {
                admit_community_via(
                    directory,
                    authority_key_id,
                    group_key_id,
                    &types::CommunityMember {
                        key_id: member.key_id.clone(),
                        joined_at: member.joined_at,
                        role: member.role.clone(),
                    },
                )
                .await
            }
            super::Cohort::SelfId => AdmitSpec {
                authority_key_id: String::new(),
                scrub_signature_classical: String::new(),
                scrub_signature_pqc: None,
            },
        }
    }

    /// v31.0.0 (CIRISPersist#654) — **ROSTER GROWTH IS AUTHORIZED, ON EVERY
    /// BACKEND.**
    ///
    /// One body, driven from memory, sqlite AND postgres, because the defect
    /// was in each backend's own `add_*_member` and a single-backend witness is
    /// the test shape that let it live. Four properties per plane:
    ///
    /// 1. an EMPTY [`AdmitSpec`] — what every pre-#654 caller effectively
    ///    supplied — is refused;
    /// 2. a spec signed over a DIFFERENT grown roster does not admit this one;
    /// 3. neither refusal touches `members` (verify-before-mutation, AV-9);
    /// 4. after a genuine signed add, the STORED row re-verifies against the
    ///    STORED signature — the property the old in-place mutation destroyed
    ///    by rewriting `members` (inside `signing_envelope()`) and leaving the
    ///    old `authority_key_id` / `scrub_signature_*` behind.
    ///
    /// Key ids lead with the DISTINGUISHING part:
    /// `tier_ingest::test_support::seed_for` truncates at 32 bytes, and a
    /// uuid-bearing postgres tag in front would collapse `…-seated` and
    /// `…-newcomer` into ONE identity — making the whole witness vacuous on the
    /// one backend production runs.
    pub async fn exercise_roster_growth_is_authorized<F>(
        directory: &F,
        tag: &str,
    ) -> Result<(), crate::federation::Error>
    where
        F: crate::federation::FederationDirectory + ?Sized,
    {
        use crate::federation::tier_ingest::test_support as ts;
        let seated = format!("seated-{tag}");
        let newcomer = format!("newcomer-{tag}");
        let other = format!("other-{tag}");
        let fam = format!("fam-{tag}");
        let comm = format!("comm-{tag}");
        // Members register as `user`-role identities: the community plane
        // refuses an unstewarded member, and a witness that dies at THAT gate
        // is not measuring the authorship one.
        for k in [&seated, &newcomer, &other] {
            ts::register_identity_key(directory, k, types::identity_type::USER).await;
        }
        for k in [&fam, &comm] {
            ts::register_hybrid_key(directory, k).await;
        }
        let now =
            crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
        let unsigned = AdmitSpec {
            authority_key_id: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
        };

        // ── family plane ────────────────────────────────────────────────
        directory
            .put_family(ts::sign_family(
                &fam,
                types::Family {
                    family_key_id: fam.clone(),
                    family_name: "roster growth".into(),
                    members: vec![types::FamilyMember {
                        key_id: seated.clone(),
                        joined_at: now,
                        role: None,
                    }],
                    founded_at: now,
                    consensus_protocol: types::consensus_protocol::FOUNDER_ONLY.into(),
                    consensus_protocol_entrenched: false,
                    persist_row_hash: String::new(),
                },
            ))
            .await?;
        let member = types::FamilyMember {
            key_id: newcomer.clone(),
            joined_at: now,
            role: None,
        };
        let err = directory
            .add_family_member(&fam, member.clone(), &unsigned)
            .await
            .expect_err("(1) an unsigned family roster grow must be refused");
        assert!(
            err.to_string().contains("not registered") || err.to_string().contains("signature"),
            "({tag}) the refusal is about AUTHORSHIP: {err:?}"
        );
        let wrong = admit_family_via(
            directory,
            &seated,
            &fam,
            &types::FamilyMember {
                key_id: other.clone(),
                joined_at: now,
                role: None,
            },
        )
        .await;
        directory
            .add_family_member(&fam, member.clone(), &wrong)
            .await
            .expect_err("(2) a signature over a different grown roster must not admit this one");
        assert_eq!(
            directory
                .lookup_family(&fam)
                .await?
                .expect("family")
                .members
                .len(),
            1,
            "({tag}) (3) verify-before-mutation: neither refusal touched the family roster"
        );
        let admit = admit_family_via(directory, &seated, &fam, &member).await;
        assert!(
            directory.add_family_member(&fam, member, &admit).await?,
            "({tag}) the signed grow is a genuine add"
        );
        let signed_fam = directory
            .list_signed_families_since(None, u32::MAX)
            .await?
            .into_iter()
            .find(|f| f.family.family.family_key_id == fam)
            .expect("the grown family is served on the signed read surface")
            .family;
        assert_eq!(signed_fam.family.members.len(), 2, "({tag})");
        crate::federation::verify_family_admission(directory, &signed_fam)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "({tag}) (4) the STORED family must verify against its own STORED signature \
                     — the roster and its authorization move together (#654/#651): {e}"
                )
            });

        // ── community plane (the exact mirror) ───────────────────────────
        directory
            .put_community(ts::sign_community(
                &comm,
                types::Community {
                    community_key_id: comm.clone(),
                    community_name: "roster growth".into(),
                    members: vec![types::CommunityMember {
                        key_id: seated.clone(),
                        joined_at: now,
                        role: None,
                    }],
                    founded_at: now,
                    consensus_protocol: types::consensus_protocol::FOUNDER_ONLY.into(),
                    policy_blob: None,
                    persist_row_hash: String::new(),
                },
            ))
            .await?;
        let member = types::CommunityMember {
            key_id: newcomer.clone(),
            joined_at: now,
            role: None,
        };
        directory
            .add_community_member(&comm, member.clone(), &unsigned)
            .await
            .expect_err("(1) an unsigned community roster grow must be refused");
        let wrong = admit_community_via(
            directory,
            &seated,
            &comm,
            &types::CommunityMember {
                key_id: other.clone(),
                joined_at: now,
                role: None,
            },
        )
        .await;
        directory
            .add_community_member(&comm, member.clone(), &wrong)
            .await
            .expect_err("(2) a signature over a different grown roster must not admit this one");
        assert_eq!(
            directory
                .lookup_community(&comm)
                .await?
                .expect("community")
                .members
                .len(),
            1,
            "({tag}) (3) verify-before-mutation: neither refusal touched the community roster"
        );
        let admit = admit_community_via(directory, &seated, &comm, &member).await;
        assert!(
            directory
                .add_community_member(&comm, member, &admit)
                .await?,
            "({tag}) the signed grow is a genuine add"
        );
        let signed_comm = directory
            .list_signed_communities_since(None, u32::MAX)
            .await?
            .into_iter()
            .find(|c| c.community.community.community_key_id == comm)
            .expect("the grown community is served on the signed read surface")
            .community;
        assert_eq!(signed_comm.community.members.len(), 2, "({tag})");
        crate::federation::verify_community_admission(directory, &signed_comm)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "({tag}) (4) the STORED community must verify against its own STORED \
                     signature (#654/#651): {e}"
                )
            });
        Ok(())
    }

    /// The community mirror of [`admit_family_via`].
    pub async fn admit_community_via<F>(
        directory: &F,
        authority_key_id: &str,
        community_key_id: &str,
        member: &types::CommunityMember,
    ) -> AdmitSpec
    where
        F: crate::federation::FederationDirectory + ?Sized,
    {
        let community = directory
            .lookup_community(community_key_id)
            .await
            .expect("lookup_community")
            .expect("community exists");
        admit_community(authority_key_id, &community, member)
    }
}

/// v31.0.0 (CIRISPersist#654) — the community mirror of
/// [`authorize_family_growth`]. Verifies through
/// [`verify_community_admission`](super::verify_community_admission).
pub async fn authorize_community_growth<F>(
    directory: &F,
    community: &types::Community,
    member: types::CommunityMember,
    spec: &AdmitSpec,
) -> Result<types::Community, super::Error>
where
    F: super::FederationDirectory + ?Sized,
{
    let mut grown = community.clone();
    grown.members.push(member);
    let signed = super::SignedCommunity {
        community: grown,
        authority_key_id: spec.authority_key_id.clone(),
        scrub_signature_classical: spec.scrub_signature_classical.clone(),
        scrub_signature_pqc: spec.scrub_signature_pqc.clone(),
    };
    super::verify_community_admission(directory, &signed).await?;
    let mut grown = signed.community;
    grown.persist_row_hash = types::compute_persist_row_hash(&grown)?;
    Ok(grown)
}

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

/// v31.0.0 (CIRISPersist#654) — the authority signature over a roster
/// ADDITION, the exact mirror of [`RevokeSpec`]'s three signature fields.
///
/// # Why an addition needs one
///
/// Roster growth mutates `members`, and `members` is INSIDE
/// [`Family::signing_envelope`](types::Family::signing_envelope) /
/// [`Community::signing_envelope`](types::Community::signing_envelope) — the
/// whole record minus the server-computed `persist_row_hash`. So an unsigned
/// `add_*_member` left `federation_families` holding a roster no authority had
/// ever signed, next to the `authority_key_id` / `scrub_signature_*` columns
/// #651 taught `supersede_group_row` to keep in step, still describing the
/// roster that USED to be there. And the roster is both the numerator and the
/// denominator of
/// [`family_quorum_over`](crate::federation::trust_root) and
/// `wa_quorum_over_body`: a free seat changes who can charter a trust root and
/// what threshold they must clear. The write door was reachable from PyO3 with
/// no authority check at all.
///
/// # What the signature covers
///
/// `JCS(signing_envelope())` of the **GROWN** record — the stored group with
/// this member appended — verified through the same
/// [`verify_family_admission`](crate::federation::verify_family_admission) /
/// [`verify_community_admission`](crate::federation::verify_community_admission)
/// gate `put_*` and `supersede_*` run. That is byte-identical to what a
/// supersede of the same grown record would be signed over, which is the point:
/// growing a roster is not a lesser act than replacing one, so it is not a
/// second, weaker spelling of it.
///
/// A caller therefore signs a record it can compute in full: read the group,
/// append the member it chose (`key_id` / `joined_at` / `role` are all
/// caller-known — the v21.0.0 #502 E4 rule that every field the gate verifies
/// over must be caller-known IN ADVANCE, the same reason a revocation's
/// `removed_at` is its caller-supplied `effective_at` and not a server-minted
/// `now`). If the stored roster moved under the caller between reading and
/// writing, the signature simply does not verify and the add fails closed.
///
/// Additive (`#[serde(default)]`) so an old JSON payload decodes fine and then
/// fails closed at admission — an empty signer/signature never verifies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmitSpec {
    /// The claimed authority for the addition — a `federation_keys.key_id`
    /// whose REGISTERED pubkeys the signatures below must verify against.
    #[serde(default)]
    pub authority_key_id: String,
    /// Ed25519 signature (base64) over `JCS(signing_envelope())` of the
    /// GROWN group record.
    #[serde(default)]
    pub scrub_signature_classical: String,
    /// ML-DSA-65 signature (base64) over the bound payload
    /// `canonical ‖ ed25519_sig`. `None` ⇒ hybrid-Strict verify rejects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
}

/// The knobs of a roster removal / swap-out (#249 Cut G1 §1/§6), uniform
/// across the three cohorts. `effective_at` may be future-dated (the member
/// stays active until it arrives); `witness_set` is the vouch set — the
/// member cosignatures the Cut G3 quorum gate will count land here.
///
/// v21.0.0 (CIRISPersist#502 E4) — `authority_key_id` +
/// `scrub_signature_classical` + `scrub_signature_pqc`: `FederationDirectory::
/// revoke_member`'s family/community branches build a
/// `SignedFamilyMembershipRevocation` / `SignedCommunityMembershipRevocation`
/// from this spec and hand it to the now-gated `put_family_membership_
/// revocation` / `put_community_membership_revocation` — the caller (the
/// `cohort_revoke_member` / `cohort_swap_member` PyO3 surface) supplies the
/// authority signature here so the gate has something real to verify.
/// Additive (`#[serde(default)]`) so an old JSON payload decodes fine and
/// then fails closed at admission.
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
    /// The claimed authority for the removal — a `federation_keys.key_id`.
    #[serde(default)]
    pub authority_key_id: String,
    /// Ed25519 signature (base64) over the removal's
    /// `signing_envelope()` (JCS-canonicalized).
    #[serde(default)]
    pub scrub_signature_classical: String,
    /// ML-DSA-65 signature (base64) over the bound payload
    /// `canonical ‖ ed25519_sig`. `None` ⇒ hybrid-Strict verify rejects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
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
