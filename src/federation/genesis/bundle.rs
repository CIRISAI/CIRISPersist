//! v19.1.0 (CIRISPersist#490) — bake/adopt an **assembled genesis
//! trust-root bundle** (the ceremony's "cold-start bake" artifact).
//!
//! During a genesis ceremony the accord holders co-sign a portable
//! [`GenesisBundle`]: the family + holder set, the `infra:serve`-blessed
//! serve nodes (re-blessed canonical records), the delegation plane
//! (charter + serve grants), and an m-of-n set of **hybrid holder
//! authorizations** over the whole artifact. Before this cut the local
//! adopt of a re-blessed canonical was REFUSED by the anti-downgrade gate
//! (`adopt_scrub_upgrade`: "already anchored to a different record") — the
//! gate doing its job against an *unauthenticated* replace, with no path
//! for the *authenticated* one. [`bake_assembled_genesis`] is that path:
//!
//! - **Authenticated re-anchor**: a canonical already anchored to a
//!   different record IS replaced when the bundle carries a valid quorum —
//!   verified against **persist's OWN holder roster and pinned pubkeys**
//!   (never the bundle's carried holder records: authority is re-derived
//!   from own verified state, the #377 lesson — a forged bundle carrying
//!   attacker "holders" verifies nothing here).
//! - **Idempotent**: re-baking the same bundle is a no-op report, not an
//!   error.
//! - **Anti-rollback**: a re-anchor must carry `valid_from` newer than the
//!   anchored record — replaying an OLD co-scrubbed record (e.g. the
//!   original roles-less seed) cannot roll the anchor back.
//! - **After-the-fact import**: the operator's saved artifact JSON bakes a
//!   ceremony whose durable write failed (CIRISServer#309/#310) without
//!   re-running the ceremony.
//!
//! The [`authorization_digest`] preimage is BYTE-IDENTICAL to CIRISServer
//! `mesh_genesis::authorization_digest` (the producer): bundle identity +
//! holder ids + serve ids + the whole delegation plane, canonicalized with
//! the same JCS producer. A co-signer cannot be replayed onto a bundle
//! with a swapped serve node or a widened charter.

use super::super::types::{SignedAttestation, SignedKeyRecord};
use super::super::{Error, FederationDirectory};
use serde::{Deserialize, Serialize};

/// One holder's hybrid authorization over [`authorization_digest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAuthorization {
    /// The authorizing holder's key_id (must resolve in persist's OWN
    /// roster — bundle-carried holder records are never the authority).
    pub holder_key_id: String,
    /// Ed25519 over the digest, base64.
    pub signature_classical: String,
    /// ML-DSA-65 over `digest ‖ ed25519_sig` (the bound rule), base64.
    pub signature_pqc: String,
}

/// The assembled genesis artifact (wire-compatible with CIRISServer
/// `mesh_genesis::GenesisBundle` — same field names, same persist row
/// types inside).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisBundle {
    /// Artifact schema version.
    pub version: u32,
    /// The accord family this genesis seeds (e.g. `humanity-accord`).
    pub family_key_id: String,
    /// The holder roster AS CARRIED — cross-check input only, never the
    /// verification authority.
    pub holders: Vec<SignedKeyRecord>,
    /// The `infra:serve`-blessed serve-node records (the re-blessed
    /// canonicals) to anchor.
    pub serve_nodes: Vec<SignedKeyRecord>,
    /// `quorum:M/N` — floored at a strict majority of persist's OWN roster
    /// at verify time (a tampered policy string cannot talk it down).
    pub consensus_protocol: String,
    /// The delegation plane: the root charter + serve grants.
    pub attestations: Vec<SignedAttestation>,
    /// The accumulated holder authorizations over [`authorization_digest`].
    pub authorizations: Vec<GenesisAuthorization>,
    /// Ceremony timestamp (RFC 3339) — in the digest, so two ceremonies
    /// are distinguishable.
    pub produced_at: String,
}

/// The bytes every holder authorization signs — BYTE-IDENTICAL to the
/// producer's construction (CIRISServer `mesh_genesis`): bundle identity,
/// holder ids, serve ids, and the whole delegation plane. Deliberately
/// excludes `authorizations` (they are what is being accumulated).
pub fn authorization_digest(bundle: &GenesisBundle) -> Result<Vec<u8>, Error> {
    let preimage = serde_json::json!({
        "version": bundle.version,
        "family_key_id": bundle.family_key_id,
        "consensus_protocol": bundle.consensus_protocol,
        "produced_at": bundle.produced_at,
        "holders": bundle.holders.iter().map(|h| &h.record.key_id).collect::<Vec<_>>(),
        "serve_nodes": bundle.serve_nodes.iter().map(|n| &n.record.key_id).collect::<Vec<_>>(),
        "attestations": bundle
            .attestations
            .iter()
            .map(|a| {
                serde_json::json!({
                    "attestation_id": a.attestation.attestation_id,
                    "attesting_key_id": a.attestation.attesting_key_id,
                    "attested_key_id": a.attestation.attested_key_id,
                    "attestation_type": a.attestation.attestation_type,
                    "attestation_envelope": a.attestation.attestation_envelope,
                })
            })
            .collect::<Vec<_>>(),
    });
    crate::verify::canonical::ceg_produce_canonicalize(&preimage)
        .map_err(|e| Error::InvalidArgument(format!("genesis digest canonicalize: {e}")))
}

/// Parse `quorum:M/N` → `(M, N)`.
fn parse_quorum(s: &str) -> Option<(usize, usize)> {
    let rest = s.strip_prefix("quorum:")?;
    let (m, n) = rest.split_once('/')?;
    Some((m.parse().ok()?, n.parse().ok()?))
}

/// v19.1.0 (#490) — verify a bundle's holder quorum **against persist's own
/// verified state**: each authorization's holder must resolve in THIS
/// node's directory as a seated accord holder (the baked/effective roster),
/// its hybrid signature (Strict — Ed25519 + bound ML-DSA-65) must verify
/// over [`authorization_digest`] with the DIRECTORY-pinned pubkeys, and the
/// distinct count must reach `max(carried M, strict_majority(own roster))`
/// — the floor means a tampered `consensus_protocol` cannot talk the
/// threshold down. Returns the distinct verified-holder count.
pub async fn verify_bundle_quorum<D>(directory: &D, bundle: &GenesisBundle) -> Result<usize, Error>
where
    D: FederationDirectory + ?Sized,
{
    let refuse = |detail: String| Error::GenesisBundleInvalid { detail };

    // Own roster: the effective accord holder key_ids (baked genesis).
    let roster: Vec<String> = super::effective_accord_holder_records()
        .iter()
        .map(|r| r.record.key_id.clone())
        .collect();
    if roster.is_empty() {
        return Err(refuse("no accord holder roster on this node".into()));
    }
    let carried_m = parse_quorum(&bundle.consensus_protocol)
        .map(|(m, _)| m)
        .ok_or_else(|| {
            refuse(format!(
                "unparseable consensus_protocol {:?} — a verifier must not guess \
                 the threshold",
                bundle.consensus_protocol
            ))
        })?;
    let needed = carried_m.max(ciris_verify_core::accord_genesis::strict_majority(
        roster.len(),
    ));

    let digest = authorization_digest(bundle)?;
    let mut distinct: Vec<&str> = Vec::new();
    for auth in &bundle.authorizations {
        if distinct.contains(&auth.holder_key_id.as_str()) {
            return Err(refuse(format!(
                "duplicate authorization from {} — m-of-n counts DISTINCT holders",
                auth.holder_key_id
            )));
        }
        if !roster.contains(&auth.holder_key_id) {
            return Err(refuse(format!(
                "{} is not a seated holder on THIS node's roster",
                auth.holder_key_id
            )));
        }
        // Resolve the holder's pubkeys from OUR directory — never from the
        // bundle's carried records.
        let holder = directory
            .lookup_public_key(&auth.holder_key_id)
            .await?
            .ok_or_else(|| {
                refuse(format!(
                    "holder {} not resolvable in this node's directory",
                    auth.holder_key_id
                ))
            })?;
        crate::verify::hybrid::verify_hybrid(
            &digest,
            &auth.signature_classical,
            Some(&auth.signature_pqc),
            &holder.pubkey_ed25519_base64,
            holder.pubkey_ml_dsa_65_base64.as_deref(),
            crate::verify::hybrid::HybridPolicy::Strict,
            None,
        )
        .map_err(|e| {
            refuse(format!(
                "{}: hybrid authorization failed to verify against the \
                 directory-pinned keys: {e}",
                auth.holder_key_id
            ))
        })?;
        distinct.push(auth.holder_key_id.as_str());
    }
    if distinct.len() < needed {
        return Err(refuse(format!(
            "quorum not met: {} distinct verified holder(s), {needed} required",
            distinct.len()
        )));
    }
    Ok(distinct.len())
}

/// Per-item outcome inside a [`GenesisBakeReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BakeItemOutcome {
    /// Freshly inserted (no prior row).
    Anchored,
    /// Byte-identical row already present — idempotent no-op.
    AlreadyPresent,
    /// An anchored-but-different row was REPLACED under bundle-quorum
    /// authority (the #490 fix).
    ReAnchored,
    /// Skipped, with the reason (e.g. an attestation the gates refused).
    Skipped(String),
}

/// The typed result of [`bake_assembled_genesis`] — "what anchored, what
/// was skipped and why" (the issue's clear-surfacing requirement).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisBakeReport {
    /// Distinct holders whose authorizations verified.
    pub quorum_verified: usize,
    /// Per serve-node key_id → outcome.
    pub serve_nodes: Vec<(String, BakeItemOutcome)>,
    /// Per attestation_id → outcome.
    pub attestations: Vec<(String, BakeItemOutcome)>,
}

/// Is `candidate` a byte-equivalent of `existing` for idempotency purposes?
/// Compared on the content identity fields (persist_row_hash covers the
/// row content; envelope equality is the fallback when hashes were
/// computed by different producers).
fn same_record(existing: &super::super::KeyRecord, candidate: &super::super::KeyRecord) -> bool {
    existing.persist_row_hash == candidate.persist_row_hash
        || (existing.registration_envelope == candidate.registration_envelope
            && existing.scrubs() == candidate.scrubs())
}

/// v19.1.0 (CIRISPersist#490) — bake an assembled genesis bundle into this
/// node's state: verify the holder quorum FIRST (fail-closed — nothing is
/// written on an unverified bundle), then land serve nodes (insert /
/// idempotent / **authenticated re-anchor**) and the delegation plane.
///
/// The bundle-carried `holders` are cross-check input only: the roster this
/// node trusts is its own baked genesis, which is already seeded — holder
/// records are never written from a bundle.
pub async fn bake_assembled_genesis<D>(
    directory: &D,
    bundle_json: &str,
) -> Result<GenesisBakeReport, Error>
where
    D: FederationDirectory + ?Sized,
{
    let bundle: GenesisBundle =
        serde_json::from_str(bundle_json).map_err(|e| Error::GenesisBundleInvalid {
            detail: format!("bundle parse: {e}"),
        })?;

    // Fail-closed FIRST: no write before the quorum verifies against our
    // own roster + pinned keys.
    let quorum_verified = verify_bundle_quorum(directory, &bundle).await?;

    // Serve nodes: insert / idempotent / authenticated re-anchor.
    let mut serve_outcomes = Vec::with_capacity(bundle.serve_nodes.len());
    for sn in &bundle.serve_nodes {
        let kid = sn.record.key_id.clone();
        let outcome = match directory.lookup_public_key(&kid).await? {
            None => {
                directory.put_public_key(sn.clone()).await?;
                BakeItemOutcome::Anchored
            }
            Some(existing) if same_record(&existing, &sn.record) => BakeItemOutcome::AlreadyPresent,
            Some(existing) => {
                // Anchored to a different record — the exact refusal #490
                // reported. Under verified bundle quorum, re-anchor with
                // anti-rollback: identity must match and time must move
                // forward.
                if existing.pubkey_ed25519_base64 != sn.record.pubkey_ed25519_base64 {
                    return Err(Error::GenesisBundleInvalid {
                        detail: format!(
                            "serve node {kid}: pubkey differs from the anchored row — \
                             a genesis bundle re-anchors a RECORD, never an identity"
                        ),
                    });
                }
                if sn.record.valid_from <= existing.valid_from {
                    return Err(Error::GenesisBundleInvalid {
                        detail: format!(
                            "serve node {kid}: bundle record valid_from {} is not newer \
                             than the anchored {} — rollback refused",
                            sn.record.valid_from, existing.valid_from
                        ),
                    });
                }
                directory
                    .adopt_genesis_reanchor(sn.clone(), &bundle)
                    .await?;
                BakeItemOutcome::ReAnchored
            }
        };
        serve_outcomes.push((kid, outcome));
    }

    // Delegation plane: put each attestation; the normal gates run (charter
    // admission incl. pre-rotation commitment, envelope size, tier-ingest
    // signature verify). Duplicates are idempotent; a refused row is
    // reported, not silently dropped.
    let mut att_outcomes = Vec::with_capacity(bundle.attestations.len());
    for sa in &bundle.attestations {
        let id = sa.attestation.attestation_id.clone();
        let outcome = match directory.put_attestation(sa.clone()).await {
            Ok(()) => BakeItemOutcome::Anchored,
            Err(Error::Conflict(_)) => BakeItemOutcome::AlreadyPresent,
            Err(e) => BakeItemOutcome::Skipped(format!("{}: {e}", e.kind())),
        };
        att_outcomes.push((id, outcome));
    }

    Ok(GenesisBakeReport {
        quorum_verified,
        serve_nodes: serve_outcomes,
        attestations: att_outcomes,
    })
}
