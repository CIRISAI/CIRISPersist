//! CIRISPersist#973 — **the software ceremony minter**: the full output of a
//! trust-root re-mint, signed by SOFTWARE holders, so a host can dry-run the
//! ceremony end to end before the real one.
//!
//! [`mint_test_ceremony`] produces, for a three-holder test anchor, the
//! artifact the real ceremony outputs, through the same assembler
//! ([`super::ceremony`]): the **bundle** (`canonical_seed.json`'s shape, a
//! [`GenesisBundle`]) — the holder roster as carried, one accord-scrubbed
//! canonical serve node, the three delegation rows (`genesis-charter` with
//! `witness_quorum: 0` and every holder's recovery commitment,
//! `genesis-grant:<node>`, `genesis-lifecycle`) each scrubbed by all three
//! holders, and, as further members of `attestations` (v53.0.0, CC rc7), the
//! accord family's genesis record and the `ciris-canonical` birth (founders =
//! the three holders, all three signing, the node listed as `member` and never
//! signing), with all three holders' authorizations over the whole.
//!
//! The anchor block ([`mint_test_anchor_block`](super::mint_test_anchor_block))
//! is unchanged and returned beside it. Everything here is behind the
//! `test-anchor` feature: no production build contains it.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer, PqcSigner as _};

use super::{mint_test_anchor_block, test_anchor_mldsa_seed, GenesisBundle, TestAnchorBlock};
use crate::federation::accord_test_support::Identity;
use crate::federation::canonical_community::CIRIS_CANONICAL_COMMUNITY_KEY_ID;
use crate::federation::types::SignedCommunity;
use crate::federation::{Error, SignedKeyRecord};

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

/// What [`mint_test_ceremony`] returns: the anchor block and the bundle.
#[derive(Debug, Clone)]
pub struct TestCeremonyOutputs {
    /// The `CIRIS_TEST_TRUST_ROOT*` block for the three holders — arm it
    /// before booting against the bundle below.
    pub block: TestAnchorBlock,
    /// The bundle (`canonical_seed.json`'s shape) — the only artifact.
    pub bundle: GenesisBundle,
    /// The `ciris-canonical` birth the bundle carries, cloned out for
    /// convenience (never a second artifact).
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
}

/// v53.0.0 (CC 4.2.6) — the recovery seed of a holder seed: domain-separated,
/// so the recovery pair is never the signing pair.
#[must_use]
pub fn test_ceremony_recovery_seed(holder_seed: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(b"ciris-test-ceremony-recovery-v1\0");
    h.update(holder_seed);
    h.finalize().into()
}

/// v53.0.0 (CC 4.2.6) — the software recovery key a minted ceremony commits for
/// `holder_key_id`: `<holder>-recovery`, its pair derived from
/// [`test_ceremony_recovery_seed`].
///
/// # Errors
///
/// A seed a signer rejects.
pub fn test_ceremony_recovery_key(
    holder_key_id: &str,
    holder_seed: &[u8; 32],
) -> Result<crate::federation::trust_root::CommittedKey, Error> {
    let seed = test_ceremony_recovery_seed(holder_seed);
    let ed = Ed25519Signer::from_seed(&seed).map_err(|e| bad("recovery ed25519 seed", e))?;
    let mldsa = MlDsa65Signer::from_seed(&test_anchor_mldsa_seed(&seed))
        .map_err(|e| bad("recovery ml-dsa-65 seed", e))?;
    Ok(crate::federation::trust_root::CommittedKey {
        key_id: format!("{holder_key_id}-recovery"),
        pubkey_ed25519_base64: B64.encode(ed.public_key().map_err(|e| bad("recovery ed pk", e))?),
        pubkey_ml_dsa_65_base64: B64.encode(
            mldsa
                .public_key()
                .map_err(|e| bad("recovery ml-dsa pk", e))?,
        ),
    })
}

fn bad(what: &str, e: impl std::fmt::Display) -> Error {
    Error::InvalidArgument(format!("mint_test_ceremony: {what}: {e}"))
}

/// **Mint the software ceremony** for three test-anchor holders
/// (`test-accord-holder-{0,1,2}`, seeds in that order) and one canonical node
/// ([`TEST_CEREMONY_NODE_KEY_ID`], from `node_seed`), every instant stamped
/// from `produced_at` (the three delegation rows 1 ms apart, in bundle
/// order). A re-mint is the same call with a later `produced_at`: the ids are
/// kept and the instants move forward, which is what the #665 supersede path
/// requires.
///
/// v53.0.0 — a thin caller of the production assembler
/// ([`CeremonyState`](super::ceremony::CeremonyState)): plan, have each
/// software holder sign every item, assemble. One code path, so the dry run
/// proves the production one.
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
    let (block, holders, inputs) =
        test_ceremony_inputs(ed_seeds, node_seed, produced_at, extra_scope)?;
    let mut state = super::ceremony::CeremonyState::plan(inputs).map_err(|e| bad("plan", e))?;
    sign_every_item(&mut state, &holders)?;
    let bundle = state.assemble().map_err(|e| bad("assemble", e))?;
    let community = bundle
        .community_record(CIRIS_CANONICAL_COMMUNITY_KEY_ID)
        .cloned()
        .ok_or_else(|| bad("assemble", "no community birth"))?;
    Ok(TestCeremonyOutputs {
        block,
        bundle,
        community,
    })
}

/// v53.0.0 — have every software holder sign every item a ceremony still owes,
/// round by round (the heads and the authorization become signable once the
/// charter is complete).
///
/// # Errors
///
/// A partial the assembler refuses.
pub fn sign_every_item(
    state: &mut super::ceremony::CeremonyState,
    holders: &[Identity],
) -> Result<(), Error> {
    loop {
        let items = state.next_items().map_err(|e| bad("items", e))?;
        if items.is_empty() {
            return Ok(());
        }
        for item in items {
            for h in holders.iter().filter(|h| item.owed.contains(&h.key_id)) {
                let (classical, pqc) = h.sign_bytes(&item.bytes);
                state
                    .add_partial(super::ceremony::Partial {
                        item: item.id.clone(),
                        holder_key_id: h.key_id.clone(),
                        signature_classical: classical,
                        signature_pqc: pqc,
                    })
                    .map_err(|e| bad("add partial", e))?;
            }
        }
    }
}

/// v53.0.0 — the software ceremony's inputs: the anchor block, the three
/// software holders (to sign with), and the [`CeremonyInputs`](super::ceremony::CeremonyInputs)
/// a host would stamp at propose.
///
/// # Errors
///
/// As [`mint_test_ceremony`].
pub fn test_ceremony_inputs(
    ed_seeds: &[[u8; 32]],
    node_seed: &[u8; 32],
    produced_at: chrono::DateTime<chrono::Utc>,
    extra_scope: Option<&str>,
) -> Result<
    (
        TestAnchorBlock,
        Vec<Identity>,
        super::ceremony::CeremonyInputs,
    ),
    Error,
> {
    if ed_seeds.len() != 3 {
        return Err(Error::InvalidArgument(format!(
            "mint_test_ceremony: the accord roster is three holders (quorum 2 of 3); got {} \
             seed(s)",
            ed_seeds.len()
        )));
    }
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

    // The canonical serve node: its own software pair.
    let node_ed = Ed25519Signer::from_seed(node_seed).map_err(|e| bad("node ed25519 seed", e))?;
    let node_mldsa = MlDsa65Signer::from_seed(&test_anchor_mldsa_seed(node_seed))
        .map_err(|e| bad("node ml-dsa-65 seed", e))?;
    let node_roles = vec![
        crate::federation::trust_root::INFRA_SERVE_SCOPE.to_owned(),
        crate::federation::trust_root::INFRA_ATTEST_SCOPE.to_owned(),
        "infra:store".to_owned(),
    ];
    let serve_node = super::ceremony::ServeNodeInput {
        key_id: TEST_CEREMONY_NODE_KEY_ID.to_owned(),
        identity_type: "canonical,node".to_owned(),
        pubkey_ed25519_base64: B64
            .encode(node_ed.public_key().map_err(|e| bad("node ed pubkey", e))?),
        pubkey_ml_dsa_65_base64: B64.encode(
            node_mldsa
                .public_key()
                .map_err(|e| bad("node ml-dsa pubkey", e))?,
        ),
        capability_roles: node_roles.clone(),
        registration_envelope: serde_json::json!({
            "purpose": "federation-peering",
            "roles": node_roles,
            "test_anchor": true,
        }),
        attestation_evidence: None,
    };

    // v53.0.0 (CC 3.2 T3, rc7) — the successors as their records carry them.
    let successor_keys: Vec<crate::federation::trust_root::CommittedKey> = holder_records[1..]
        .iter()
        .map(|r| crate::federation::trust_root::CommittedKey::from_record(&r.record))
        .collect::<Result<_, _>>()?;
    // v53.0.0 (CC 4.2.6, rc7) — every holder's pre-committed recovery key.
    let recovery_keys = holders
        .iter()
        .zip(ed_seeds)
        .map(|(h, seed)| {
            Ok((
                h.key_id.clone(),
                test_ceremony_recovery_key(&h.key_id, seed)?,
            ))
        })
        .collect::<Result<_, Error>>()?;
    let mut scope = vec![
        crate::federation::trust_root::INFRA_ATTEST_SCOPE.to_owned(),
        crate::federation::trust_root::INFRA_SERVE_SCOPE.to_owned(),
        "infra:store".to_owned(),
    ];
    scope.extend(extra_scope.map(str::to_owned));
    let inputs = super::ceremony::CeremonyInputs {
        family_key_id: ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID.to_owned(),
        consensus_protocol: ciris_verify_core::accord_genesis::ACCORD_CONSENSUS_PROTOCOL.to_owned(),
        holders: holder_records,
        serve_nodes: vec![serve_node],
        successor_keys,
        recovery_keys,
        scope,
        community: super::ceremony::CommunityInput {
            community_key_id: CIRIS_CANONICAL_COMMUNITY_KEY_ID.to_owned(),
            community_name: "CIRIS Canonical Services".to_owned(),
            consensus_protocol: "quorum:2/3".to_owned(),
            policy_blob: serde_json::json!({
                "cohort_subkind": "infrastructure",
                "cohort_subkind_payload": {
                    "infrastructure_constraint": {
                        "service_class": "canonical",
                        "admission_quorum_basis": "founders",
                    }
                },
                "consensus_protocol_entrenched": true,
            }),
        },
        produced_at,
    };
    Ok((block, holders, inputs))
}

/// CIRISPersist#973 — [`install_test_ceremony_outputs`](super::install_test_ceremony_outputs)
/// from the bundle JSON, as a host that received it from its own ceremony
/// routes (or from [`mint_test_ceremony`]) holds it. Call it
/// BEFORE constructing the Engine: the boot seed then runs every leg against
/// these artifacts.
///
/// # Errors
///
/// A file that does not parse as its shape.
pub fn install_test_ceremony_outputs_json(bundle_json: &str) -> Result<(), Error> {
    super::install_test_ceremony_outputs(super::parse_genesis_bundle(bundle_json)?);
    Ok(())
}
