//! [`CallerAdmission`] + [`build_caller_admission`] — the substrate-built
//! admission set (FSD §4.1, §4.2, §4.4, §11.2) and AV-44 mitigation
//! (FSD §13).
//!
//! # AV-44 forge resistance
//!
//! `CallerAdmission`'s fields are `pub` so the §4.3 SQL helper can read
//! them, but the struct carries a private zero-sized seal field
//! ([`AdmissionSeal`]). An external crate cannot name that field, so it
//! cannot construct a `CallerAdmission` by struct literal, and there is
//! no public `new`. The SOLE public path to a `CallerAdmission` is
//! [`build_caller_admission`], which resolves identity / families /
//! communities deterministically from the federation chain. A Python
//! caller (or any external Rust caller) therefore cannot fabricate
//! `Authenticated { admission: { identity: <victim>, families: <all>,
//! communities: <all> } }` — the type system refuses the literal
//! (FSD §13 `forged_admission_refused_at_compile_time`).
//!
//! `CallerAdmission` is deliberately NOT `Deserialize` — a serde
//! construction path would be a second forge surface (FSD §13 test
//! note "deserialization paths are blocked by serde-skip on the
//! struct").

use std::collections::BTreeSet;

use super::KeyId;
#[cfg(any(feature = "postgres", feature = "sqlite"))]
use crate::engine::Engine;

/// Private seal — prevents external struct-literal construction of
/// [`CallerAdmission`]. Zero-sized; only `super`-module code (the
/// builder) can name it. This is the type-system half of the AV-44
/// mitigation (FSD §13).
#[derive(Clone, Debug)]
struct AdmissionSeal;

/// The substrate-resolved admission set for an authenticated caller
/// (FSD §4.1).
///
/// Every field except `occurrence_key_id` is resolved by the substrate
/// from the federation chain — never caller-asserted. The struct has
/// no public constructor (see module docs / [`build_caller_admission`]);
/// its fields are `pub` only so the §4.3 SQL helper can read them.
#[derive(Clone, Debug)]
pub struct CallerAdmission {
    /// The caller's occurrence key — the literal signing key they
    /// presented at the boundary. The only field the caller has any
    /// agency over; everything else below is substrate-resolved.
    pub occurrence_key_id: KeyId,

    /// The caller's IDENTITY — resolved via
    /// `federation_identity_occurrences` (V059 §5.6.8.8):
    /// "lookup occurrence_key_id → identity_key_id."
    ///
    /// Singleton fallback (FSD §4.4): when the occurrence key is not
    /// bound (not yet declared as an occurrence of any identity), the
    /// caller IS its own identity (`identity_key_id == occurrence_key_id`).
    pub identity_key_id: KeyId,

    /// Every family the caller's IDENTITY is a member of — resolved via
    /// `list_families_for_member(identity_key_id)` against
    /// `federation_families` (V059 §5.6.8.9). Members are IDENTITY
    /// keys, NOT occurrence keys.
    pub family_key_ids: BTreeSet<KeyId>,

    /// Every community the caller's IDENTITY is a member of — resolved
    /// via `list_communities_for_member(identity_key_id)` against
    /// `federation_communities` (V060, Commit D). Same
    /// identity-keys-as-members shape as families.
    pub community_key_ids: BTreeSet<KeyId>,

    /// Construction seal — see [`AdmissionSeal`]. Not `pub`; blocks
    /// external struct-literal construction (AV-44).
    _seal: AdmissionSeal,
}

/// Failure building a [`CallerAdmission`] (FSD §11.2).
///
/// Resolution backend errors surface here. The §4.4 singleton fallback
/// is NOT an error — an unbound occurrence key resolves to itself; this
/// enum fires only when a substrate read genuinely fails.
///
/// Backend-gated: admission resolution requires a `FederationDirectory`,
/// which only exists with a `postgres`/`sqlite` backend.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError {
    /// A `FederationDirectory` read (identity-occurrence lookup, family
    /// fan-out, or community fan-out) failed at the backend.
    #[error("admission resolution failed: {0}")]
    Resolution(#[from] crate::federation::Error),
}

/// Build the admission set for a caller from their occurrence key
/// (FSD §4.1, §11.2). Substrate-side helper — the SOLE way to construct
/// a [`CallerAdmission`] (AV-44, FSD §13).
///
/// Resolution (FSD §11.2):
///
/// 1. `occurrence_key_id → identity_key_id` via
///    [`lookup_identity_for_occurrence`](crate::federation::FederationDirectory::lookup_identity_for_occurrence)
///    (V059 §5.6.8.8). On no binding — OR an **active revocation** of the
///    binding (v4.8.0, CIRISPersist#161 Ask 6, CEG §11.7.1) — the §4.4
///    singleton fallback applies: `identity == occurrence`, empty
///    family/community sets. A revoked occurrence speaks only for itself,
///    never for the identity it was removed from.
/// 2. `identity_key_id → family_key_ids` via
///    [`list_families_for_member_active`](crate::federation::FederationDirectory::list_families_for_member_active)
///    (V059 §5.6.8.9) — **active** membership only: families this identity
///    has an effective revocation from are excluded.
/// 3. `identity_key_id → community_key_ids` via
///    `list_communities_for_member_active` (V060) — same revocation
///    honesty.
///
/// Honoring revocation here is the substrate-side closure of the
/// symmetric forge surface: without it, a removed member's read access
/// would persist silently.
///
/// Backend-gated: resolution goes through `Engine::federation_directory`,
/// which only exists when a `postgres`/`sqlite` backend is compiled in.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub async fn build_caller_admission(
    engine: &Engine,
    occurrence_key_id: &KeyId,
) -> Result<CallerAdmission, AdmissionError> {
    let directory = engine.federation_directory();
    let now = chrono::Utc::now();

    // Step 1 — occurrence → identity. §4.4 singleton fallback when the
    // occurrence key is not bound as an occurrence of any identity, OR
    // (Ask 6) when the binding has an effective revocation: the caller
    // IS its own identity, with no inherited family/community admission.
    let identity_key_id = match directory
        .lookup_identity_for_occurrence(occurrence_key_id)
        .await?
    {
        Some(occurrence) => {
            // v16.0.0 (#421): THE fold comparator — a re-established
            // occurrence (asserted after its revocation) regains identity
            // admission; a still-revoked one speaks only for itself.
            let revoked = directory
                .list_identity_occurrence_revocations_for(&occurrence.identity_key_id)
                .await?
                .into_iter()
                .any(|r| r.revokes(&occurrence, now));
            if revoked {
                occurrence_key_id.clone()
            } else {
                occurrence.identity_key_id
            }
        }
        None => occurrence_key_id.clone(),
    };

    // Step 2 — identity → ACTIVE families. Members are identity keys; the
    // family's own key_id is the admission token. Revoked memberships
    // are filtered (Ask 2 / Ask 6).
    let family_key_ids: BTreeSet<KeyId> = directory
        .list_families_for_member_active(&identity_key_id)
        .await?
        .into_iter()
        .map(|family| family.family_key_id)
        .collect();

    // Step 3 — identity → ACTIVE communities. Symmetric to families.
    let community_key_ids: BTreeSet<KeyId> = directory
        .list_communities_for_member_active(&identity_key_id)
        .await?
        .into_iter()
        .map(|community| community.community_key_id)
        .collect();

    Ok(CallerAdmission {
        occurrence_key_id: occurrence_key_id.clone(),
        identity_key_id,
        family_key_ids,
        community_key_ids,
        _seal: AdmissionSeal,
    })
}

impl CallerAdmission {
    /// v4.0 (CIRISPersist#160 comment 4, FSD §4.6) — crate-internal
    /// constructor from already-resolved admission parts.
    ///
    /// [`build_caller_admission`] is the `Engine`-based resolution path
    /// used on the read side. The trace-ingest write path
    /// (`IngestPipeline`) holds only a `Backend` (no `Engine`), so it
    /// resolves the writer's identity / family / community sets through
    /// the `Backend` admission fan-out methods and assembles the
    /// `CallerAdmission` here. The constructor stays `pub(crate)` so the
    /// AV-44 forge-resistance seal is intact — no external crate can
    /// reach this path (FSD §13). Membership semantics are identical to
    /// the read-side builder; only the resolution plumbing differs.
    pub(crate) fn from_resolved(
        occurrence_key_id: impl Into<KeyId>,
        identity_key_id: impl Into<KeyId>,
        family_key_ids: impl IntoIterator<Item = KeyId>,
        community_key_ids: impl IntoIterator<Item = KeyId>,
    ) -> Self {
        Self {
            occurrence_key_id: occurrence_key_id.into(),
            identity_key_id: identity_key_id.into(),
            family_key_ids: family_key_ids.into_iter().collect(),
            community_key_ids: community_key_ids.into_iter().collect(),
            _seal: AdmissionSeal,
        }
    }
}

#[cfg(test)]
impl CallerAdmission {
    /// Test-only direct constructor. The seal blocks *external*
    /// construction (AV-44); within-crate tests for the §4.3 SQL
    /// predicate need to fabricate admissions without standing up an
    /// `Engine` + backend. Gated `#[cfg(test)]` so it never appears in
    /// the public API surface.
    pub(crate) fn for_test(
        occurrence_key_id: impl Into<KeyId>,
        identity_key_id: impl Into<KeyId>,
        family_key_ids: impl IntoIterator<Item = KeyId>,
        community_key_ids: impl IntoIterator<Item = KeyId>,
    ) -> Self {
        Self {
            occurrence_key_id: occurrence_key_id.into(),
            identity_key_id: identity_key_id.into(),
            family_key_ids: family_key_ids.into_iter().collect(),
            community_key_ids: community_key_ids.into_iter().collect(),
            _seal: AdmissionSeal,
        }
    }
}

/// v4.8.0 (CIRISPersist#161 Ask 6) — `build_caller_admission` honors
/// revocation: a revoked occurrence falls through to the singleton
/// fallback and a removed family member drops out of `family_key_ids`.
#[cfg(all(test, feature = "sqlite"))]
mod revocation_honesty_tests {
    use crate::federation::{
        FamilyMembershipRevocation, FederationDirectory, IdentityOccurrence,
        IdentityOccurrenceRevocation, KeyRecord, SignedFamily, SignedFamilyMembershipRevocation,
        SignedKeyRecord,
    };
    use crate::signing::LocalSigner;
    use crate::Engine;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;

    fn signer() -> Arc<LocalSigner> {
        Arc::new(LocalSigner::from_parts(
            SigningKey::from_bytes(&[0x11u8; 32]),
            "admission-test".into(),
            None,
            None,
        ))
    }

    fn key(k: &str) -> SignedKeyRecord {
        SignedKeyRecord {
            record: KeyRecord {
                key_id: k.into(),
                pubkey_ed25519_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                pubkey_ml_dsa_65_base64: None,
                algorithm: crate::federation::types::algorithm::HYBRID.into(),
                identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
                identity_ref: k.into(),
                valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
                valid_until: None,
                registration_envelope: serde_json::json!({ "id": k }),
                original_content_hash: "deadbeef".into(),
                scrub_signature_classical: "c2ln".into(),
                scrub_signature_pqc: None,
                scrub_key_id: k.into(),
                scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        }
    }

    #[tokio::test]
    async fn revoked_occurrence_falls_through_to_singleton() {
        let engine = Engine::with_signer(signer(), "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        for k in ["alice-root", "alice-phone", "fam-1"] {
            sq.put_public_key(key(k)).await.unwrap();
        }
        sq.put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: "alice-root".into(),
            occurrence_key_id: "alice-phone".into(),
            device_class: crate::federation::types::device_class::PHONE.into(),
            hardware_attestation: None,
            asserted_at: "2026-06-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap();
        sq.put_family(SignedFamily {
            family: crate::federation::Family {
                family_key_id: "fam-1".into(),
                family_name: "Fam".into(),
                members: vec![crate::federation::FamilyMember {
                    key_id: "alice-root".into(),
                    joined_at: "2026-06-01T00:00:00Z".parse().unwrap(),
                    role: None,
                }],
                founded_at: "2026-06-01T00:00:00Z".parse().unwrap(),
                consensus_protocol: "unanimous".into(),
                consensus_protocol_entrenched: false,
                persist_row_hash: String::new(),
            },
        })
        .await
        .unwrap();

        // Pre-revocation: alice-phone resolves to alice-root + fam-1.
        let adm = super::build_caller_admission(&engine, &"alice-phone".to_string())
            .await
            .unwrap();
        assert_eq!(adm.identity_key_id, "alice-root");
        assert!(adm.family_key_ids.contains("fam-1"));

        // Revoke the occurrence binding (effective in the past). Trusted-local
        // write (#421): the test acts as the engine-internal path; the gated
        // put is for wire-received, signed revocations.
        sq.put_identity_occurrence_revocation_local(IdentityOccurrenceRevocation {
            identity_key_id: "alice-root".into(),
            occurrence_key_id: "alice-phone".into(),
            revoked_at: "2026-06-02T00:00:00Z".parse().unwrap(),
            effective_at: "2026-06-02T00:00:00Z".parse().unwrap(),
            reason: None,
            witness_set: vec!["alice-root".into()],
            persist_row_hash: String::new(),
        })
        .await
        .unwrap();

        // Post-revocation: alice-phone speaks only for itself — singleton
        // fallback, no inherited family admission.
        let adm = super::build_caller_admission(&engine, &"alice-phone".to_string())
            .await
            .unwrap();
        assert_eq!(
            adm.identity_key_id, "alice-phone",
            "revoked occurrence falls through to singleton identity"
        );
        assert!(
            adm.family_key_ids.is_empty(),
            "revoked occurrence inherits no family admission"
        );
    }

    #[tokio::test]
    async fn removed_family_member_drops_from_admission() {
        let engine = Engine::with_signer(signer(), "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        for k in ["bob-root", "fam-1"] {
            sq.put_public_key(key(k)).await.unwrap();
        }
        sq.put_family(SignedFamily {
            family: crate::federation::Family {
                family_key_id: "fam-1".into(),
                family_name: "Fam".into(),
                members: vec![crate::federation::FamilyMember {
                    key_id: "bob-root".into(),
                    joined_at: "2026-06-01T00:00:00Z".parse().unwrap(),
                    role: None,
                }],
                founded_at: "2026-06-01T00:00:00Z".parse().unwrap(),
                consensus_protocol: "unanimous".into(),
                consensus_protocol_entrenched: false,
                persist_row_hash: String::new(),
            },
        })
        .await
        .unwrap();
        // bob-root is a singleton identity (no occurrence binding) in fam-1.
        let adm = super::build_caller_admission(&engine, &"bob-root".to_string())
            .await
            .unwrap();
        assert!(adm.family_key_ids.contains("fam-1"));

        sq.put_family_membership_revocation(SignedFamilyMembershipRevocation {
            family_membership_revocation: FamilyMembershipRevocation {
                family_key_id: "fam-1".into(),
                removed_identity_key_id: "bob-root".into(),
                removed_at: "2026-06-02T00:00:00Z".parse().unwrap(),
                effective_at: "2026-06-02T00:00:00Z".parse().unwrap(),
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        })
        .await
        .unwrap();

        let adm = super::build_caller_admission(&engine, &"bob-root".to_string())
            .await
            .unwrap();
        assert!(
            adm.family_key_ids.is_empty(),
            "removed member loses family admission (forge surface closed)"
        );
    }
}
