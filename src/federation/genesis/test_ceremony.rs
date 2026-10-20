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
    mint_test_ceremony_versioned(ed_seeds, node_seed, produced_at, extra_scope, None)
}

/// v59.0.0 (CIRISPersist#1106) — [`mint_test_ceremony_scoped`] at an explicit
/// bundle version: `Some(3)` mints the pre-v59 shape (no serve transport
/// rows), the base an AMEND turns into a v4; `None` is the current version,
/// which carries the test serve node's signed transport destination
/// ([`test_serve_transport_destination`]).
///
/// # Errors
///
/// As [`mint_test_ceremony`].
pub fn mint_test_ceremony_versioned(
    ed_seeds: &[[u8; 32]],
    node_seed: &[u8; 32],
    produced_at: chrono::DateTime<chrono::Utc>,
    extra_scope: Option<&str>,
    bundle_version: Option<u32>,
) -> Result<TestCeremonyOutputs, Error> {
    let (block, holders, mut inputs) =
        test_ceremony_inputs(ed_seeds, node_seed, produced_at, extra_scope)?;
    if bundle_version.is_some_and(|v| v < super::bundle::SERVE_TRANSPORT_DESTINATIONS_VERSION) {
        inputs.serve_transport_destinations.clear();
    }
    inputs.bundle_version = bundle_version;
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
        serve_transport_destinations: vec![test_serve_transport_destination(
            node_seed,
            produced_at,
            0x71,
            0x72,
        )?],
        bundle_version: None,
    };
    Ok((block, holders, inputs))
}

/// v59.0.0 (CIRISPersist#1106) — the test serve node's signed Reticulum
/// transport destination, carrying a transit KEX pair from fill bytes
/// (`x_fill`, `m_fill`; key-separated from the node's keys and link key), at
/// epoch 1, asserted at `asserted_at`, signed by the node's own software pair.
///
/// # Errors
///
/// A seed a signer rejects.
pub fn test_serve_transport_destination(
    node_seed: &[u8; 32],
    asserted_at: chrono::DateTime<chrono::Utc>,
    x_fill: u8,
    m_fill: u8,
) -> Result<crate::federation::self_at_login::SignedTransportDestination, Error> {
    test_serve_transport_destination_at_epoch(node_seed, asserted_at, x_fill, m_fill, 1)
}

/// [`test_serve_transport_destination`] at an explicit `epoch` (a rotation).
///
/// # Errors
///
/// A seed a signer rejects.
pub fn test_serve_transport_destination_at_epoch(
    node_seed: &[u8; 32],
    asserted_at: chrono::DateTime<chrono::Utc>,
    x_fill: u8,
    m_fill: u8,
    epoch: u64,
) -> Result<crate::federation::self_at_login::SignedTransportDestination, Error> {
    use crate::federation::self_at_login as sal;
    let asserted_at =
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(asserted_at.timestamp_millis())
            .ok_or_else(|| bad("transport row instant", "out of range"))?;
    let row = sal::TransportDestination {
        occurrence_key_id: TEST_CEREMONY_NODE_KEY_ID.to_owned(),
        transport_kind: "reticulum".to_owned(),
        destination: hex::encode([0x5Du8; 16]),
        asserted_at,
        last_seen_at: None,
        transport_ed25519_pubkey_base64: Some(B64.encode([0x62u8; 32])),
        transport_x25519_pubkey_base64: Some(B64.encode([0x61u8; 32])),
        binding_provenance: sal::BindingProvenance::Rooted,
        epoch,
        retired_at: None,
    };
    let mut envelope = serde_json::to_value(&row).map_err(|e| bad("route envelope", e))?;
    envelope
        .as_object_mut()
        .ok_or_else(|| bad("route envelope", "not an object"))?
        .insert(
            sal::TRANSIT_KEX_PUBKEYS_MEMBER.to_owned(),
            serde_json::json!({
                sal::TRANSIT_KEX_X25519_MEMBER: B64.encode([x_fill; sal::TRANSIT_KEX_X25519_LEN]),
                sal::TRANSIT_KEX_ML_KEM_768_MEMBER:
                    B64.encode(vec![m_fill; sal::TRANSIT_KEX_ML_KEM_768_LEN]),
            }),
        );
    let node = Identity::from_seeds(
        TEST_CEREMONY_NODE_KEY_ID,
        node_seed,
        &test_anchor_mldsa_seed(node_seed),
    )?;
    let bytes = crate::verify::canonical::ceg_produce_canonicalize(&envelope)
        .map_err(|e| bad("route canonicalize", e))?;
    let (ed, mldsa) = node.sign_bytes(&bytes);
    Ok(sal::SignedTransportDestination {
        transport_destination: row,
        attesting_key_id: TEST_CEREMONY_NODE_KEY_ID.to_owned(),
        signed_envelope: envelope,
        signature: ciris_verify_core::transport_binding::TransportBindingSignature {
            ed25519_signature_base64: ed,
            mldsa65_signature_base64: Some(mldsa),
        },
    })
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

/// v59.0.0 (CIRISPersist#1106) — the software holders of a test ceremony, in
/// roster order (`test-accord-holder-{0,1,2}`), to sign with.
///
/// # Errors
///
/// A seed a signer rejects.
pub fn test_ceremony_holders(ed_seeds: &[[u8; 32]]) -> Result<Vec<Identity>, Error> {
    let block = mint_test_anchor_block(ed_seeds)?;
    ed_seeds
        .iter()
        .zip(&block.holders)
        .map(|(seed, h)| Identity::from_seeds(&h.key_id, seed, &test_anchor_mldsa_seed(seed)))
        .collect()
}

/// v59.0.0 (CIRISPersist#1106) — one test holder's authorization of an AMEND
/// over `bytes` ([`AmendState::authz_bytes`](super::amend::AmendState::authz_bytes)).
#[must_use]
pub fn test_amend_authorization(holder: &Identity, bytes: &[u8]) -> super::GenesisAuthorization {
    let (classical, pqc) = holder.sign_bytes(bytes);
    super::GenesisAuthorization {
        holder_key_id: holder.key_id.clone(),
        signature_classical: classical,
        signature_pqc: pqc,
    }
}

/// v59.0.0 (CIRISPersist#1106, CC 5.3.4) — the holders' quorum re-bind of a
/// serve node's transport destination: a
/// [`REBIND_DIMENSION`](crate::federation::transport_rebind::REBIND_DIMENSION)
/// row about the node, carrying `carried`, signed by `signers[0]` and
/// cosigned (`additional_scrubs`) by the rest, every scrub over the same
/// canonical envelope.
///
/// # Errors
///
/// An envelope that does not canonicalize.
pub fn test_rebind_row(
    signers: &[&Identity],
    carried: &crate::federation::self_at_login::SignedTransportDestination,
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> Result<crate::federation::Attestation, Error> {
    use crate::federation::transport_rebind as tr;
    use crate::federation::types::{attestation_tier, attestation_type, cohort_scope, ScrubSig};
    let asserted_at =
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(asserted_at.timestamp_millis())
            .ok_or_else(|| bad("re-bind instant", "out of range"))?;
    let primary = signers.first().ok_or_else(|| bad("re-bind", "no signer"))?;
    let mut row = crate::federation::Attestation {
        attestation_id: uuid::Uuid::new_v4().to_string(),
        attesting_key_id: primary.key_id.clone(),
        attested_key_id: carried.transport_destination.occurrence_key_id.clone(),
        attestation_type: attestation_type::SCORES.to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: serde_json::json!({
            "dimension": tr::REBIND_DIMENSION,
            "score": 1,
            "confidence": 1,
            tr::REBIND_MEMBER: serde_json::to_value(carried).map_err(|e| bad("carried row", e))?,
        }),
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: primary.key_id.clone(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: Some(asserted_at),
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_owned(),
        tier: attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    };
    crate::federation::envelope::RowMirror::stamp_local_row(&mut row, false)?;
    crate::federation::canonical_at_rest::canonicalize_in_place(&mut row.attestation_envelope)?;
    let canonical = crate::verify::canonical::ceg_produce_canonicalize(&row.attestation_envelope)
        .map_err(|e| bad("re-bind canonicalize", e))?;
    row.original_content_hash = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&canonical));
    let (classical, pqc) = primary.sign_bytes(&canonical);
    row.scrub_signature_classical = classical;
    row.scrub_signature_pqc = Some(pqc);
    for s in &signers[1..] {
        let (classical, pqc) = s.sign_bytes(&canonical);
        row.additional_scrubs.push(ScrubSig {
            scrub_key_id: s.key_id.clone(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: Some(pqc),
            cosigned_at: None,
        });
    }
    Ok(row)
}
