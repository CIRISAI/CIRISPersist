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
//! holder **ids** + serve **ids** + the whole delegation plane, canonicalized
//! with the same JCS producer.
//!
//! # What that digest does and does not bind (CIRISPersist#660)
//!
//! This paragraph used to end *"a co-signer cannot be replayed onto a bundle
//! with a swapped serve node or a widened charter."* Half of that was true and
//! the half that was not is corrected here rather than deleted, because a
//! comment claiming a property the code does not have is worse than no comment:
//! it is the thing a reviewer trusts instead of reading the preimage.
//!
//! - **A widened charter: genuinely covered.** Each attestation contributes its
//!   `attestation_id`, `attesting_key_id`, `attested_key_id`,
//!   `attestation_type` AND its whole `attestation_envelope`, so the conferral
//!   plane — the scopes, the subject, the verb — is bound byte-for-byte.
//! - **A swapped serve node: covered only by IDENTITY.** `serve_nodes` and
//!   `holders` contribute their `key_id`s and nothing else. Adding, removing or
//!   renaming a serve node breaks every authorization; **substituting the
//!   RECORD under an unchanged `key_id`** — a different `pubkey_ed25519_base64`,
//!   `registration_envelope`, scrub set, `valid_from`, roles or custody
//!   evidence — does not appear in the digest at all.
//!
//! What actually stops that substitution is not this digest, and a reader
//! should know where to look: a serve-node record still has to pass
//! `put_public_key`'s canonical-role admission (a 2-of-3 accord co-scrub
//! re-verified against THIS node's pinned holder anchors), and
//! [`bake_assembled_genesis`] additionally refuses a re-anchor whose pubkey
//! differs from the anchored row or whose `valid_from` does not move forward.
//! Those are real gates and they are why this gap has never been exploitable on
//! its own — but they are a different mechanism, adjudicating a different
//! question, and the digest should not be described as if it did their job.
//!
//! **Why the digest was not simply widened here.** The preimage is a
//! cross-repo wire contract: it is declared byte-identical to the PRODUCER's
//! (CIRISServer `mesh_genesis::authorization_digest`), and holder
//! authorizations are computed over the producer's construction. Widening it in
//! persist alone would make this node refuse every bundle CIRISServer emits,
//! including the baked `canonical_seed.json` whose authorizations are already
//! signed over the narrow preimage — a consumer-side break with no producer-side
//! half. It is the right change and the v31 re-ceremony is the right window for
//! it, so it is tracked as CIRISServer-side work rather than described as
//! covered; when both halves land together the bullet above becomes obsolete
//! and must be rewritten, not quietly dropped.

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
///
/// # Read the preimage below, not a summary of it (CIRISPersist#660)
///
/// `holders` and `serve_nodes` contribute **`key_id` only** — the record
/// content under an unchanged id is NOT in these bytes. `attestations`
/// contribute their full `attestation_envelope` and so ARE bound. See this
/// module's doc for what closes the serve-node gap instead, and for why the
/// preimage is not widened unilaterally on the consumer side.
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

/// v23.0.0 (CIRISPersist#551 item 1) — the **single door** every genesis
/// bundle enters through, whether it arrives as an operator artifact
/// ([`bake_assembled_genesis`]) or as the compiled-in seed asset
/// ([`super::canonical_genesis_bundle`]). One predicate, one impl: the
/// embedded seed cannot drift into a shape a hand-passed artifact would be
/// refused for.
///
/// The bare `[{record}]` seed list is DELETED, not deprecated. A record list
/// carries the identity plane ONLY — no charter, no conferral, no liveness
/// witness — so a node seeded from one roots, reports healthy, and can never
/// satisfy the delegation plane. That failure was silent, which is why the
/// legacy shape must fail *loudly* here rather than parse into an inert node:
/// the refusal NAMES the shape it got, because a raw serde type error
/// ("invalid type: map, expected u32") teaches an operator nothing about
/// what their file is or what to do about it.
pub fn parse_genesis_bundle(json: &str) -> Result<GenesisBundle, Error> {
    match serde_json::from_str::<GenesisBundle>(json) {
        Ok(bundle) => Ok(bundle),
        Err(e) => {
            // Sniff the legacy shape so the refusal can name it. A bare JSON
            // array at the top level is the pre-v23 `[{record}]` seed.
            let detail = match serde_json::from_str::<Vec<serde_json::Value>>(json) {
                Ok(list) => format!(
                    "expected a genesis bundle object, got a bare JSON array of {} element(s) — \
                     the `[{{record}}]` seed shape was DELETED in v23.0.0 (CIRISPersist#551 \
                     item 1). A record list carries identity only: no charter, no conferral, \
                     no liveness witness, so a node seeded from it roots, looks healthy, and \
                     withholds every trace. Re-emit this seed as the bundle a ceremony \
                     produces (version, family_key_id, holders, serve_nodes, \
                     consensus_protocol, attestations, authorizations, produced_at)",
                    list.len()
                ),
                Err(_) => format!("bundle parse: {e}"),
            };
            Err(Error::GenesisBundleInvalid { detail })
        }
    }
}

/// Parse `quorum:M/N` → `(M, N)`.
///
/// v24.0.0 (CIRISPersist#557) — `pub(crate)` so the family trust root reads the
/// threshold through the SAME parser the bundle verifier does. Two parsers for
/// one wire form is how the two answers start to disagree.
pub(crate) fn parse_quorum(s: &str) -> Option<(usize, usize)> {
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

    // v23.1.0 (CIRISPersist#554) — **one verdict for one artifact.** The
    // carried holder records are cross-check input, never the quorum
    // authority (above) — but they ARE what a consumer installs, so their
    // evidence must clear the SAME gate `put_public_key` runs. One predicate,
    // one impl.
    //
    // Before this, the two validators disagreed about the same bytes: this
    // function passed the production bundle — structure, signatures, 2-of-3
    // quorum all green — while the put gate refused every holder it carried
    // as `malformed`. A producer got a green light and shipped an artifact
    // that could not install, and the refusal surfaced at ingest with no hint
    // that the verifier and the gate disagreed about what a valid holder
    // record even is. A verifier whose "valid" does not mean "installable" is
    // worse than no verifier: it converts a loud producer-side failure into a
    // silent consumer-side one.
    let policy = directory.hardware_attestation_policy();
    let now = chrono::Utc::now();
    for holder in &bundle.holders {
        if !holder
            .record
            .claims_role(crate::federation::types::identity_type::ACCORD_HOLDER)
        {
            continue;
        }
        policy
            .check(
                &holder.record.key_id,
                holder.record.attestation_evidence.as_ref(),
                now,
            )
            .map_err(|e| {
                refuse(format!(
                    "holder {}: custody evidence would be REFUSED at install time \
                     ({}: {e}) — a bundle that verifies must be a bundle that installs",
                    holder.record.key_id,
                    e.kind()
                ))
            })?;
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
    let bundle = parse_genesis_bundle(bundle_json)?;

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
    //
    // v31.1.0 (CIRISPersist#665 review) — **THE RE-CEREMONY PATH, WHICH THIS
    // LOOP DID NOT HAVE.** It was a bare `put_attestation`, and that was
    // survivable only while nothing else installed these ids: the bake was the
    // sole writer of the delegation plane, so it never collided. #665 gave the
    // BOOT SEED the same three ids, and after every normal startup they are all
    // occupied by the compiled-in rows — so a later authenticated re-ceremony
    // collided on all three, reported them as `Skipped`, and returned a
    // PARTIALLY APPLIED bake while quietly retaining the old delegation plane.
    // The documented candidate re-mint path became unusable on any entrenched
    // node, which is every node.
    //
    // The fix is not new policy; it is the discipline the SERVE-NODE loop above
    // has always had, finally applied to its sibling. Compare them side by
    // side: identity is fixed by the reserved id (`check_genesis_attestation_reserved`
    // already refuses anything not attested by a seated holder), and time must
    // move forward — `candidate_is_strictly_newer`, the same predicate the boot
    // seed uses, so the two doors cannot hold two opinions of which statement
    // is later. A bundle row that is NOT newer is refused outright rather than
    // reported: a rollback offered under verified quorum is still a rollback,
    // and the serve-node half errors on exactly this, so this half does too.
    let mut att_outcomes = Vec::with_capacity(bundle.attestations.len());
    for sa in &bundle.attestations {
        let id = sa.attestation.attestation_id.clone();
        let stored = directory.get_attestation(&id).await?;
        let outcome = match stored {
            // Nothing there, or a row this bundle does not own: the ordinary
            // insert, with every gate running.
            None => match directory.put_attestation(sa.clone()).await {
                Ok(()) => BakeItemOutcome::Anchored,
                // A concurrent writer got there first. See
                // `Error::is_duplicate_key` — a PK collision is `Backend` on
                // every backend, never `Conflict`, which is why the old arm
                // below never fired and duplicates fell through to `Skipped`.
                Err(e) if e.is_duplicate_key() => BakeItemOutcome::AlreadyPresent,
                Err(e) => BakeItemOutcome::Skipped(format!("{}: {e}", e.kind())),
            },
            Some(existing) => {
                if super::baked_row_matches_stored(&existing, &sa.attestation).unwrap_or(false) {
                    BakeItemOutcome::AlreadyPresent
                } else if !super::candidate_is_strictly_newer(&sa.attestation, &existing) {
                    // Anti-rollback, mirroring the serve-node half's
                    // `valid_from` refusal exactly.
                    return Err(Error::GenesisBundleInvalid {
                        detail: format!(
                            "delegation row {id}: bundle asserted_at {} is not newer than the \
                             installed {} — rollback refused",
                            sa.attestation.asserted_at, existing.asserted_at
                        ),
                    });
                } else {
                    // A genuinely newer ceremony statement under a reserved id.
                    // Replace through the narrow door (`check_genesis_rebake_purge_admission`
                    // bounds it to ids the bundle actually carries), then insert
                    // through the ordinary one so the row pays the full
                    // admission stack — canonical-at-rest, the #660 reservation,
                    // `persist_row_hash`, the V106 subject projection — exactly
                    // as a first install does.
                    // v31.1.0 (CIRISPersist#665 review) — COMPARE-AND-DELETE
                    // against the row this loop actually classified. The same
                    // read-then-write window the boot seed has: a concurrent
                    // initializer replacing this row between the
                    // `get_attestation` above and here must not have its
                    // statement deleted by a decision taken before it existed.
                    // `Ok(false)` ⇒ the corpus moved, so REPORT rather than
                    // force — the operator re-runs the bake against the state
                    // that now exists.
                    if directory
                        .purge_genesis_delegation_row_v31(&id, &existing.persist_row_hash)
                        .await?
                    {
                        directory.put_attestation(sa.clone()).await?;
                        BakeItemOutcome::ReAnchored
                    } else {
                        BakeItemOutcome::Skipped(
                            "the installed row changed while this bake was classifying it; \
                             nothing was written — re-run against the current state"
                                .to_owned(),
                        )
                    }
                }
            }
        };
        att_outcomes.push((id, outcome));
    }

    Ok(GenesisBakeReport {
        quorum_verified,
        serve_nodes: serve_outcomes,
        attestations: att_outcomes,
    })
}
