//! CIRISPersist#973 — **the software ceremony minter**: the full output of a
//! trust-root re-mint, signed by SOFTWARE holders, so a host can dry-run the
//! ceremony end to end before the real one.
//!
//! [`mint_test_ceremony`] produces, for a three-holder test anchor, exactly
//! the two artifacts the real ceremony outputs, in the JSON shapes the boot
//! path reads:
//!
//! - the **bundle** (`canonical_seed.json`'s shape, a [`GenesisBundle`]): the
//!   holder roster as carried, one accord-scrubbed canonical serve node, the
//!   three delegation rows (`genesis-charter` with `witness_quorum: 0`,
//!   `genesis-grant:<node>`, `genesis-lifecycle`) each scrubbed by all three
//!   holders, and all three holders' authorizations;
//! - the **community asset** (`canonical_community_seed.json`'s shape, a
//!   [`SignedCommunity`]): the `ciris-canonical` birth, founders = the three
//!   holders, all three signing, the node listed as `member` and never
//!   signing.
//!
//! The anchor block ([`mint_test_anchor_block`](super::mint_test_anchor_block))
//! is unchanged and returned beside them. Everything here is behind the
//! `test-anchor` feature: no production build contains it.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer, PqcSigner as _};

use super::bundle::authorization_digest;
use super::{
    mint_test_anchor_block, test_anchor_mldsa_seed, GenesisAuthorization, GenesisBundle,
    TestAnchorBlock,
};
use crate::federation::accord_test_support::Identity;
use crate::federation::canonical_community::CIRIS_CANONICAL_COMMUNITY_KEY_ID;
use crate::federation::types::{
    Community, CommunityMember, RosterCosignature, ScrubSig, SignedCommunity,
};
use crate::federation::{Attestation, Error, SignedAttestation, SignedKeyRecord};

/// The key id of the one canonical serve node a minted ceremony seats.
pub const TEST_CEREMONY_NODE_KEY_ID: &str = "test-canonical-node-0";

/// The delegation-plane ids of a minted ceremony, in bundle order.
#[must_use]
pub fn test_ceremony_delegation_ids() -> [String; 3] {
    [
        "genesis-charter".to_owned(),
        format!("genesis-grant:{TEST_CEREMONY_NODE_KEY_ID}"),
        "genesis-lifecycle".to_owned(),
    ]
}

/// What [`mint_test_ceremony`] returns: the anchor block and the two
/// artifacts of the ceremony.
#[derive(Debug, Clone)]
pub struct TestCeremonyOutputs {
    /// The `CIRIS_TEST_TRUST_ROOT*` block for the three holders — arm it
    /// before booting against the artifacts below.
    pub block: TestAnchorBlock,
    /// The bundle (`canonical_seed.json`'s shape).
    pub bundle: GenesisBundle,
    /// The `ciris-canonical` birth (`canonical_community_seed.json`'s shape).
    pub community: SignedCommunity,
}

impl TestCeremonyOutputs {
    /// The bundle as the JSON the boot path parses.
    ///
    /// # Errors
    ///
    /// Serialization failure.
    pub fn bundle_json(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(&self.bundle)
            .map_err(|e| Error::Backend(format!("serialize bundle: {e}")))
    }

    /// The community asset as the JSON the boot path parses.
    ///
    /// # Errors
    ///
    /// Serialization failure.
    pub fn community_json(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(&self.community)
            .map_err(|e| Error::Backend(format!("serialize community: {e}")))
    }
}

fn bad(what: &str, e: impl std::fmt::Display) -> Error {
    Error::InvalidArgument(format!("mint_test_ceremony: {what}: {e}"))
}

/// One delegation row: sealed (signed instants + the typed-column mirror),
/// scrubbed by `holders[0]` and co-scrubbed by the rest over the SAME
/// envelope.
fn delegation_row(
    id: &str,
    attested: &str,
    attestation_type: &str,
    envelope: serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
    holders: &[Identity],
) -> Result<SignedAttestation, Error> {
    let mut row = Attestation {
        attestation_id: id.to_owned(),
        attesting_key_id: holders[0].key_id.clone(),
        attested_key_id: attested.to_owned(),
        attestation_type: attestation_type.to_owned(),
        weight: Some(1.0),
        asserted_at: at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: holders[0].key_id.clone(),
        scrub_timestamp: at,
        pqc_completed_at: Some(at),
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
        tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    };
    crate::federation::envelope::stamp_signed_instants(&mut row)
        .map_err(|e| bad("stamp instants", e))?;
    let mirror =
        crate::federation::envelope::RowMirror::of(&row).map_err(|e| bad("row mirror", e))?;
    row.attestation_envelope[crate::federation::envelope::paths::ROW] =
        serde_json::to_value(&mirror).map_err(|e| bad("row mirror serialize", e))?;
    let (och, classical, pqc) = holders[0].sign_envelope(&row.attestation_envelope);
    row.original_content_hash = och;
    row.scrub_signature_classical = classical;
    row.scrub_signature_pqc = pqc;
    row.additional_scrubs = holders[1..]
        .iter()
        .map(|h| {
            let (_, classical, pqc) = h.sign_envelope(&row.attestation_envelope);
            ScrubSig {
                cosigned_at: None,
                scrub_key_id: h.key_id.clone(),
                scrub_signature_classical: classical,
                scrub_signature_pqc: pqc,
            }
        })
        .collect();
    Ok(SignedAttestation { attestation: row })
}

/// **Mint the software ceremony** for three test-anchor holders
/// (`test-accord-holder-{0,1,2}`, seeds in that order) and one canonical node
/// ([`TEST_CEREMONY_NODE_KEY_ID`], from `node_seed`), every instant stamped
/// from `produced_at` (the three delegation rows 1 ms apart, in bundle
/// order). A re-mint is the same call with a later `produced_at`: the ids are
/// kept and the instants move forward, which is what the #665 supersede path
/// requires.
///
/// Pure: no directory, no clock, no environment.
///
/// # Errors
///
/// [`Error::InvalidArgument`] unless exactly three seeds are given, or on a
/// seed a signer rejects.
pub fn mint_test_ceremony(
    ed_seeds: &[[u8; 32]],
    node_seed: &[u8; 32],
    produced_at: chrono::DateTime<chrono::Utc>,
) -> Result<TestCeremonyOutputs, Error> {
    mint_test_ceremony_scoped(ed_seeds, node_seed, produced_at, None)
}

/// CIRISPersist#973 — [`mint_test_ceremony`] with one extra scope token on
/// the charter and the grant, so two ceremonies minted at the SAME instant
/// carry DIFFERENT signed content (the equal-vintage case the posture leg
/// has to classify). `None` is `mint_test_ceremony` exactly.
///
/// # Errors
///
/// As [`mint_test_ceremony`].
pub fn mint_test_ceremony_scoped(
    ed_seeds: &[[u8; 32]],
    node_seed: &[u8; 32],
    produced_at: chrono::DateTime<chrono::Utc>,
    extra_scope: Option<&str>,
) -> Result<TestCeremonyOutputs, Error> {
    if ed_seeds.len() != 3 {
        return Err(Error::InvalidArgument(format!(
            "mint_test_ceremony: the accord roster is three holders (quorum 2 of 3); got {} \
             seed(s)",
            ed_seeds.len()
        )));
    }
    // Truncated to microseconds: every backend stores an instant at that
    // precision, and a row minted finer would not round-trip byte-equal.
    let produced_at = chrono::DateTime::from_timestamp_micros(produced_at.timestamp_micros())
        .ok_or_else(|| bad("produced_at", "out of range"))?;
    let block = mint_test_anchor_block(ed_seeds)?;
    let holders: Vec<Identity> = ed_seeds
        .iter()
        .zip(&block.holders)
        .map(|(seed, h)| Identity::from_seeds(&h.key_id, seed, &test_anchor_mldsa_seed(seed)))
        .collect::<Result<_, _>>()?;
    let holder_records: Vec<SignedKeyRecord> = block
        .holders
        .iter()
        .map(|h| {
            let envelope =
                super::test_anchor_registration_envelope(&h.key_id, &h.root, Some(&h.pqc));
            let canonical = crate::verify::canonical::ceg_produce_canonicalize(&envelope)
                .map_err(|e| bad("canonicalize holder envelope", e))?;
            Ok(super::test_anchor_holder_record(
                &h.key_id,
                h.root.clone(),
                Some(h.pqc.clone()),
                envelope,
                &canonical,
                Some(h.scrub.clone()),
                Some(h.scrub_pqc.clone()),
            ))
        })
        .collect::<Result<_, Error>>()?;

    // The canonical serve node: its own software pair, its record scrubbed by
    // all three holders (the accord's m-of-n over the registration envelope).
    let node_ed = Ed25519Signer::from_seed(node_seed).map_err(|e| bad("node ed25519 seed", e))?;
    let node_mldsa = MlDsa65Signer::from_seed(&test_anchor_mldsa_seed(node_seed))
        .map_err(|e| bad("node ml-dsa-65 seed", e))?;
    let node_ed_pub = B64.encode(node_ed.public_key().map_err(|e| bad("node ed pubkey", e))?);
    let node_pqc_pub = B64.encode(
        node_mldsa
            .public_key()
            .map_err(|e| bad("node ml-dsa pubkey", e))?,
    );
    let node_roles = vec![
        crate::federation::trust_root::INFRA_SERVE_SCOPE.to_owned(),
        crate::federation::trust_root::INFRA_ATTEST_SCOPE.to_owned(),
        "infra:store".to_owned(),
    ];
    let scrubbers: Vec<&Identity> = holders.iter().collect();
    let mut node_record =
        crate::federation::accord_test_support::signed_canonical_record_with_roles(
            TEST_CEREMONY_NODE_KEY_ID,
            "canonical,node",
            &node_ed_pub,
            Some(&node_pqc_pub),
            node_roles.clone(),
            serde_json::json!({
                "purpose": "federation-peering",
                "roles": node_roles,
                "test_anchor": true,
            }),
            &scrubbers,
        );
    node_record.valid_from = produced_at;
    node_record.scrub_timestamp = produced_at;
    node_record.pqc_completed_at = Some(produced_at);
    node_record.attestation_evidence = None;

    // The delegation plane, in the baked bundle's order and shape; the
    // charter carries the rc6 witness member at 0 (witnessed mode off).
    let family = ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
    let [charter_id, grant_id, lifecycle_id] = test_ceremony_delegation_ids();
    let successors: Vec<String> = holders[1..].iter().map(|h| h.key_id.clone()).collect();
    let commitment = crate::federation::trust_root::pre_rotation_commitment(&successors)?;
    let mut scope_tokens = vec![
        crate::federation::trust_root::INFRA_ATTEST_SCOPE.to_owned(),
        crate::federation::trust_root::INFRA_SERVE_SCOPE.to_owned(),
        "infra:store".to_owned(),
    ];
    scope_tokens.extend(extra_scope.map(str::to_owned));
    let scope = serde_json::json!(scope_tokens);
    let ms = |n: i64| produced_at + chrono::Duration::milliseconds(n);
    let attestations = vec![
        delegation_row(
            &charter_id,
            family,
            crate::federation::types::attestation_type::DELEGATES_TO,
            serde_json::json!({
                "references_attestation_id": charter_id,
                "pre_rotation_commitment": commitment,
                "scope": scope,
                "successor_key_ids": successors,
                crate::federation::envelope::paths::WITNESS_QUORUM: 0,
            }),
            ms(0),
            &holders,
        )?,
        delegation_row(
            &grant_id,
            TEST_CEREMONY_NODE_KEY_ID,
            crate::federation::types::attestation_type::DELEGATES_TO,
            serde_json::json!({
                "references_attestation_id": grant_id,
                "scope": scope,
            }),
            ms(1),
            &holders,
        )?,
        delegation_row(
            &lifecycle_id,
            family,
            crate::federation::types::attestation_type::SCORES,
            serde_json::json!({
                "references_attestation_id": lifecycle_id,
                "dimension": "accord:lifecycle:v1",
            }),
            ms(2),
            &holders,
        )?,
    ];

    let mut bundle = GenesisBundle {
        version: 2,
        family_key_id: family.to_owned(),
        holders: holder_records,
        serve_nodes: vec![SignedKeyRecord {
            record: node_record,
        }],
        consensus_protocol: ciris_verify_core::accord_genesis::ACCORD_CONSENSUS_PROTOCOL.to_owned(),
        attestations,
        authorizations: Vec::new(),
        produced_at: produced_at.to_rfc3339(),
    };
    let digest = authorization_digest(&bundle)?;
    bundle.authorizations = holders
        .iter()
        .map(|h| {
            let (classical, pqc) = h.sign_bytes(&digest);
            GenesisAuthorization {
                holder_key_id: h.key_id.clone(),
                signature_classical: classical,
                signature_pqc: pqc,
            }
        })
        .collect();

    // The community birth: founders = the holders, all three signing; the
    // node is a member and signs nothing.
    let mut members: Vec<CommunityMember> = holders
        .iter()
        .map(|h| CommunityMember {
            key_id: h.key_id.clone(),
            joined_at: produced_at,
            role: Some("founder".to_owned()),
        })
        .collect();
    members.push(CommunityMember {
        key_id: TEST_CEREMONY_NODE_KEY_ID.to_owned(),
        joined_at: produced_at,
        role: Some("member".to_owned()),
    });
    let row = Community {
        community_key_id: CIRIS_CANONICAL_COMMUNITY_KEY_ID.to_owned(),
        community_name: "CIRIS Canonical Services".to_owned(),
        members,
        founded_at: produced_at,
        consensus_protocol: "quorum:2/3".to_owned(),
        policy_blob: Some(serde_json::json!({
            "cohort_subkind": "infrastructure",
            "cohort_subkind_payload": {
                "infrastructure_constraint": {
                    "service_class": "canonical",
                    "admission_quorum_basis": "founders",
                }
            },
            "consensus_protocol_entrenched": true,
        })),
        persist_row_hash: String::new(),
    };
    let envelope = row.signing_envelope();
    let (_, classical, pqc) = holders[0].sign_envelope(&envelope);
    let cosignatures = holders[1..]
        .iter()
        .map(|h| {
            let (_, classical, pqc) = h.sign_envelope(&envelope);
            RosterCosignature {
                authority_key_id: h.key_id.clone(),
                scrub_signature_classical: classical,
                scrub_signature_pqc: pqc,
            }
        })
        .collect();
    let community = SignedCommunity {
        community: row,
        authority_key_id: holders[0].key_id.clone(),
        scrub_signature_classical: classical,
        scrub_signature_pqc: pqc,
        supersede_proof: None,
        cosignatures,
        lineage: Vec::new(),
    };
    Ok(TestCeremonyOutputs {
        block,
        bundle,
        community,
    })
}

/// CIRISPersist#973 — [`install_test_ceremony_outputs`](super::install_test_ceremony_outputs)
/// from the two JSON artifacts, as a host that received them from its own
/// ceremony routes (or from [`mint_test_ceremony`]) holds them. Call it
/// BEFORE constructing the Engine: the boot seed then runs every leg against
/// these artifacts.
///
/// # Errors
///
/// A file that does not parse as its shape.
pub fn install_test_ceremony_outputs_json(
    bundle_json: &str,
    community_json: Option<&str>,
) -> Result<(), Error> {
    let bundle = super::parse_genesis_bundle(bundle_json)?;
    let community = community_json
        .map(|c| {
            serde_json::from_str::<SignedCommunity>(c)
                .map_err(|e| Error::InvalidArgument(format!("community asset: {e}")))
        })
        .transpose()?;
    super::install_test_ceremony_outputs(bundle, community);
    Ok(())
}
