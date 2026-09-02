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
//! `mesh_genesis::authorization_digest` — which is guaranteed rather than
//! asserted, because that module **re-exports this function**: bundle identity,
//! the holder and serve-node RECORDS, and the whole delegation plane,
//! canonicalized with the same JCS producer and then **SHA-256'd**.
//!
//! v31.2.0 — that final hash is new, and it is not cosmetic. This function used
//! to return the canonical bytes themselves, so holders signed a preimage whose
//! size grew with the bundle: 1,976 bytes narrow, **83,060 bytes** once it bound
//! full `KeyRecord`s. PKCS#11 PureEdDSA refuses an input that large and a
//! YubiKey failed mid-ceremony. It is called a digest and now behaves as one
//! (CIRISServer#398).
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
//! - **A swapped serve node: covered by RECORD CONTENT, as of v31.2.0.**
//!   `holders` and `serve_nodes` contribute the whole `KeyRecord` minus
//!   [`NODE_LOCAL_RECORD_FIELDS`] and [`CEREMONY_MUTATED_RECORD_FIELDS`], so
//!   `pubkey_ed25519_base64`, the PQC leg, `identity_type`, `identity_ref`,
//!   `valid_from`/`valid_until`, `registration_envelope`,
//!   `original_content_hash`, `roles` and `attestation_evidence` are bound
//!   byte-for-byte. Substituting the record under an unchanged `key_id` breaks
//!   every authorization.
//!
//!   The **scrub set is deliberately NOT bound** — and that is not a gap, it is
//!   the same rule the `attestations` arm has always followed. The scrub set is
//!   quorum evidence *about* the record which the CEREMONY ITSELF accumulates
//!   between holder signatures; binding it makes the ceremony circular and a
//!   2-of-3 genesis impossible to complete (CIRISPersist#683, measured on a live
//!   ceremony: `have=2 needed=2 complete=false`). Each scrub remains
//!   independently verifiable against this node's pinned holder anchors, and the
//!   record's content is still bound through every content field plus
//!   `original_content_hash`. **Content is bound; evidence about content is
//!   not.**
//!
//! Until v31.2.0 that was NOT true: holders and serve nodes contributed their
//! `key_id`s and nothing else, so a record substituted under an unchanged id was
//! invisible to the digest (CIRISPersist#660). It was never exploitable on its
//! own, because a serve-node record still has to pass `put_public_key`'s
//! canonical-role admission (a 2-of-3 accord co-scrub re-verified against THIS
//! node's pinned holder anchors), and [`bake_assembled_genesis`] refuses a
//! re-anchor whose pubkey differs from the anchored row or whose `valid_from`
//! does not move forward. Those gates still stand — but they adjudicate a
//! different question, and the digest is no longer described as if it did their
//! job because it now genuinely does.
//!
//! **Why this could not be widened earlier, and why it could now.** The preimage
//! is a cross-repo wire contract, declared byte-identical to the PRODUCER's, and
//! holder authorizations are computed over the producer's construction. Widening
//! it in persist alone would have made this node refuse every bundle CIRISServer
//! emits — including a baked seed already signed over the narrow preimage — a
//! consumer-side break with no producer-side half.
//!
//! Two things closed that gap. CIRISServer `mesh_genesis` **re-exports this
//! function** rather than declaring its own (*"two implementations drifting by a
//! byte silently invalidates a ceremony's quorum"*), so widening here widens the
//! producer in the same act, with no server code change. And the seed is
//! **re-minted by a fresh genesis ceremony** on this cut, so no existing
//! authorization has to survive the change. That is the window this comment said
//! to wait for (CIRISServer#398 §5); it is here, and the bullet above has been
//! rewritten rather than dropped.

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

/// The fields of [`KeyRecord`] that are **node-local** and therefore must
/// never enter the authorization preimage.
///
/// v31.2.0 (CIRISPersist#660, CIRISServer#398 §5) — the line is *"producer
/// authors it"* versus *"this node computes it"*, and it is drawn here rather
/// than by listing what to INCLUDE, so a field added to `KeyRecord` is bound by
/// default and a reviewer has to argue for excluding it.
///
/// - `persist_row_hash` is documented **"Server-computed"** and *"ignored on
///   write — persist computes its own"*. Binding it would make the producer and
///   every consumer disagree by construction.
/// - `pqc_completed_at` is a *"telemetry + observability signal"* stamped
///   locally by `attach_pqc_signature`. A node-local instant inside a content
///   hash is the exact defect class v31.1.0 removed from five replication
///   positions (#655/#662); it does not get to reappear here.
const NODE_LOCAL_RECORD_FIELDS: [&str; 2] = ["persist_row_hash", "pqc_completed_at"];

/// The record fields the CEREMONY ITSELF mutates after a holder has signed —
/// the accumulating scrub set.
///
/// v31.2.0 (CIRISPersist#683) — **this is not an aesthetic exclusion; binding
/// these makes a 2-of-3 genesis impossible to complete.** The ceremony
/// accumulates two things over one bundle, one pass per holder: the
/// `authorizations`, and the serve node's scrub set (each holder appends its
/// scrub so the canonical reaches family quorum — persist's own baked-genesis
/// test asserts `distinct_scrub_count() >= 2`, so a 1-scrub canonical is not a
/// shippable seed).
///
/// If the digest binds the scrub set, those two accumulations are **circular**:
/// A1 signs, B1's co-scrub rewrites bytes A1 authorized, and A1's entirely
/// honest signature stops verifying. Measured on a live ceremony: `have=2
/// needed=2 complete=false`, with a third holder unable to help because every
/// new signature is taken over bytes the next co-scrub moves again.
///
/// **The `attestations` arm already had this right**, and this makes the two
/// arms consistent: attestations project
/// `{attestation_id, attesting_key_id, attested_key_id, attestation_type,
/// attestation_envelope}` and have never carried scrub evidence — which is
/// exactly what lets CIRISServer's cosign path work, since a 1-scrub and a
/// 2-scrub attestation canonicalize identically.
///
/// **Excluding them costs nothing.** The scrub set is accumulating quorum
/// evidence *about* the record, each scrub signed over the record's own
/// canonical bytes — which the digest still binds through every content field
/// plus `original_content_hash`. A forged scrub does not survive
/// `put_public_key`'s co-scrub admission against this node's pinned holder
/// anchors. The #660 substitution this widening exists to stop — a swapped
/// pubkey, `identity_type`, `roles` or envelope under an unchanged `key_id` —
/// is still caught, because that is CONTENT, not evidence.
const CEREMONY_MUTATED_RECORD_FIELDS: [&str; 5] = [
    "scrub_key_id",
    "scrub_signature_classical",
    "scrub_signature_pqc",
    "scrub_timestamp",
    "additional_scrubs",
];

/// One holder's or serve node's contribution to [`authorization_digest`]:
/// the whole record MINUS [`NODE_LOCAL_RECORD_FIELDS`].
///
/// v31.2.0 — this used to be `&record.key_id` and nothing else, which is why
/// **substituting the RECORD under an unchanged `key_id`** — a different
/// `pubkey_ed25519_base64`, `registration_envelope`, scrub set, `valid_from`,
/// `identity_type`, roles or custody evidence — did not appear in the digest at
/// all (CIRISPersist#660).
///
/// `identity_type` deserves its own mention: `is_canonical` reads it off the row
/// to decide canonical standing, and it was the member persist's subject binding
/// omitted in the v31.0.0 alignment (#659/#661). A projection that binds a
/// pubkey but not the type that decides what the pubkey is ALLOWED to do closes
/// half a door.
///
/// Serialization is by `serde`, so a field ADDED to `KeyRecord` is bound
/// automatically; `authorized_record_projection_binds_every_producer_field`
/// fails the build if the field set changes, so "bound automatically" is a
/// reviewed act rather than a silent one.
fn authorized_record_projection(
    record: &super::super::types::KeyRecord,
) -> Result<serde_json::Value, Error> {
    let mut value = serde_json::to_value(record).map_err(|e| Error::GenesisBundleInvalid {
        detail: format!(
            "authorization_digest: could not project key record {}: {e}",
            record.key_id
        ),
    })?;
    let map = value
        .as_object_mut()
        .ok_or_else(|| Error::GenesisBundleInvalid {
            detail: format!(
                "authorization_digest: key record {} did not serialize to an object",
                record.key_id
            ),
        })?;
    for field in NODE_LOCAL_RECORD_FIELDS
        .iter()
        .chain(CEREMONY_MUTATED_RECORD_FIELDS.iter())
    {
        map.remove(*field);
    }
    Ok(value)
}

/// The bytes every holder authorization signs — BYTE-IDENTICAL to the
/// producer's construction, because CIRISServer `mesh_genesis` **re-exports
/// this function** rather than declaring one. Bundle identity, the holder and
/// serve-node RECORDS, and the whole delegation plane. Deliberately excludes
/// `authorizations` (they are what is being accumulated).
///
/// # Read the preimage below, not a summary of it (CIRISPersist#660)
///
/// v31.2.0 (CIRISServer#398 §5) — `holders` and `serve_nodes` now contribute
/// their whole [`KeyRecord`] minus [`NODE_LOCAL_RECORD_FIELDS`], not `key_id`
/// alone, so a record substituted under an unchanged id breaks every
/// authorization. `attestations` contribute their full `attestation_envelope`
/// and were always bound.
///
/// **This is a signing-preimage change and it is deliberately breaking.** Every
/// authorization taken over the narrow preimage is invalid against these bytes —
/// which is the point, and why it lands with a fresh genesis ceremony rather
/// than alone. See this module's doc for the full before/after.
///
/// # It returns a DIGEST now, and did not before (CIRISServer#398)
///
/// Until v31.2.0 this returned `ceg_produce_canonicalize(&preimage)` — the
/// **canonical bytes themselves**. The name said digest; the behaviour was
/// preimage; holders signed the whole preimage directly. That was survivable
/// only while it stayed small: the narrow preimage was **1,976 bytes**.
///
/// Widening it to bind full `KeyRecord`s took it to **83,060 bytes** — 42×
/// larger, because each record carries a ~2.6 KB base64 ML-DSA-65 pubkey twice
/// over (top level, and again inside `registration_envelope`). PKCS#11
/// PureEdDSA refuses an input that size, so a YubiKey `C_Sign` failed with
/// *"plaintext input data has a bad length… too long"* and the ceremony could
/// not complete. Measured by CIRISServer, not inferred.
///
/// So this now returns `SHA-256(canonical)` — 32 bytes, signable on any token.
/// **The security property is unchanged**: the hash covers exactly the same
/// widened preimage, so record substitution is still detected. What changed is
/// only how much the holder's key has to swallow.
///
/// Producer and verifier cannot drift apart on this, because CIRISServer
/// `mesh_genesis` re-exports this function rather than declaring its own — the
/// same property that let the widening land with no server code change.
///
/// `authorization_digest_returns_a_fixed_size_digest` pins the 32-byte output,
/// so a future change back to returning a variable-length preimage fails the
/// build instead of failing at a hardware token during a ceremony.
pub fn authorization_digest(bundle: &GenesisBundle) -> Result<Vec<u8>, Error> {
    let preimage = serde_json::json!({
        "version": bundle.version,
        "family_key_id": bundle.family_key_id,
        "consensus_protocol": bundle.consensus_protocol,
        "produced_at": bundle.produced_at,
        "holders": bundle
            .holders
            .iter()
            .map(|h| authorized_record_projection(&h.record))
            .collect::<Result<Vec<_>, Error>>()?,
        "serve_nodes": bundle
            .serve_nodes
            .iter()
            .map(|n| authorized_record_projection(&n.record))
            .collect::<Result<Vec<_>, Error>>()?,
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
    let canonical = crate::verify::canonical::ceg_produce_canonicalize(&preimage)
        .map_err(|e| Error::InvalidArgument(format!("genesis digest canonicalize: {e}")))?;
    // v31.2.0 — HASH the canonical bytes. See this function's doc: until now it
    // returned the canonical bytes themselves, so holders signed a preimage
    // whose size grew with the bundle. Signing 32 bytes is what the name always
    // claimed and what every token can actually do.
    Ok(<sha2::Sha256 as sha2::Digest>::digest(&canonical).to_vec())
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

/// v38.0.0 (CIRISPersist#671) — **proof that a bundle's holder quorum
/// verified on THIS node.** The only constructor is
/// [`verify_bundle_quorum`], which makes the value an unforgeable token:
/// holding one means an m-of-n strict-majority of the node's OWN roster
/// signed the bundle's `authorization_digest` — a digest over the WHOLE
/// bundle, its attestation ids included. That is what lets the genesis
/// purge door widen from "ids the compiled-in artifact carries" to "ids a
/// verified ceremony carries" without degenerating into "ids the caller
/// names": the authority is a proof of quorum, never a string list.
#[derive(Debug)]
pub struct QuorumVerifiedBundle<'a> {
    bundle: &'a GenesisBundle,
    distinct_holders: usize,
}

impl<'a> QuorumVerifiedBundle<'a> {
    /// How many distinct holders verified — the bake report's number.
    #[must_use]
    pub fn distinct_holders(&self) -> usize {
        self.distinct_holders
    }

    /// Whether the verified bundle carries `attestation_id` — the purge
    /// door's widened predicate. Covered by the quorum signatures: the ids
    /// are inside the authorization digest.
    #[must_use]
    pub fn carries_attestation_id(&self, attestation_id: &str) -> bool {
        self.bundle
            .attestations
            .iter()
            .any(|sa| sa.attestation.attestation_id == attestation_id)
    }
}

/// v38.0.0 (CIRISPersist#671) — **who authorizes a genesis delegation-row
/// purge.** The #665 door's bound was "the id must be one the COMPILED-IN
/// bundle carries" — drawn when the compiled artifact was the only source
/// of genesis ids. `bake_assembled_genesis` broke that premise: a verified
/// candidate bundle may carry a NOVEL id (`genesis-grant:<new-serve-node>`),
/// which installed fine and then could never be re-cut — every later
/// ceremony reissuing that stable id hit the purge refusal, and the `?`
/// aborted the whole bake. The authority names which regime the caller is
/// in; the door re-asks it INTERNALLY on every backend (the AV-9
/// discipline — a delete door whose safety lives in its caller is the #652
/// shape).
pub enum GenesisPurgeAuthority<'a> {
    /// The boot path re-baking the compiled-in artifact — the original
    /// #665 bound, unchanged.
    CompiledIn,
    /// A candidate bundle whose holder quorum THIS NODE verified. The
    /// blast-radius argument survives intact: for a quorum-verified id the
    /// bundle authorizing the purge is BY CONSTRUCTION holding the
    /// replacement.
    QuorumVerified(&'a QuorumVerifiedBundle<'a>),
}

/// v19.1.0 (#490) — verify a bundle's holder quorum **against persist's own
/// verified state**: each authorization's holder must resolve in THIS
/// node's directory as a seated accord holder (the baked/effective roster),
/// its hybrid signature (Strict — Ed25519 + bound ML-DSA-65) must verify
/// over [`authorization_digest`] with the DIRECTORY-pinned pubkeys, and the
/// distinct count must reach `max(carried M, strict_majority(own roster))`
/// — the floor means a tampered `consensus_protocol` cannot talk the
/// threshold down. Returns the quorum PROOF (v38.0.0/#671): a
/// [`QuorumVerifiedBundle`] carrying the distinct verified-holder count and
/// authorizing the genesis purge door for the ids this bundle carries.
pub async fn verify_bundle_quorum<'a, D>(
    directory: &D,
    bundle: &'a GenesisBundle,
) -> Result<QuorumVerifiedBundle<'a>, Error>
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

    Ok(QuorumVerifiedBundle {
        bundle,
        distinct_holders: distinct.len(),
    })
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

/// v31.1.0 (CIRISPersist#665 review) — **a duplicate key proves somebody won
/// the race; it does not prove the winner wrote YOUR row.**
///
/// The one rule both delegation call sites use to answer *"what is actually
/// there"* after losing a primary-key race. Re-reads the row and classifies it
/// against the candidate rather than assuming the collision vindicates the
/// bundle.
///
/// The two sites lost the race differently and neither was right:
///
/// - the INSERT branch reported [`BakeItemOutcome::AlreadyPresent`] on the
///   collision alone, skipping the equality and recency checks the
///   `Some(existing)` branch applies. That is a FALSE SUCCESS — two concurrent
///   bakes with different content both returned success while the corpus held
///   one of them, or a mix, and `bake_assembled_genesis` runs no final plane
///   verification to catch it;
/// - the REPLACEMENT branch propagated the duplicate as a hard error. Fail-safe
///   (nothing is lost, the winner's row stands) but OVER-reporting: the winner
///   may have written exactly what this bundle wanted.
///
/// One helper, so "what is actually there" has one answer at both sites rather
/// than two that drift.
///
/// `AlreadyPresent` is now only ever said of a row this bundle would itself
/// have written. Anything else is [`BakeItemOutcome::Skipped`] naming the
/// divergence — never success, because the caller's next move (re-run, or
/// investigate) depends on knowing the corpus is not what it asked for.
pub(crate) async fn classify_after_duplicate<D>(
    directory: &D,
    sa: &SignedAttestation,
) -> Result<BakeItemOutcome, Error>
where
    D: FederationDirectory + ?Sized,
{
    let id = &sa.attestation.attestation_id;
    let Some(winner) = directory.get_attestation(id).await? else {
        // Present at the insert, absent at the re-read: something removed it in
        // between. Report rather than guess.
        return Ok(BakeItemOutcome::Skipped(
            "a concurrent writer won the insert and the row was then removed; nothing this bake \
             wrote is present — re-run against the current state"
                .to_owned(),
        ));
    };
    if super::baked_row_matches_stored(&winner, &sa.attestation).unwrap_or(false) {
        // The winner wrote THIS bundle's row. Genuinely already present.
        return Ok(BakeItemOutcome::AlreadyPresent);
    }
    Ok(BakeItemOutcome::Skipped(format!(
        "a concurrent writer won this id with DIFFERENT content (installed content hash {}, this \
         bundle's {}); nothing was written and this bundle's ceremony is NOT what the corpus \
         holds — re-run against the current state",
        winner.original_content_hash, sa.attestation.original_content_hash,
    )))
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
    let quorum = verify_bundle_quorum(directory, &bundle).await?;
    let purge_authority = GenesisPurgeAuthority::QuorumVerified(&quorum);

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
                Ok(crate::federation::AttestationOutcome::Inserted) => BakeItemOutcome::Anchored,
                // v38.5.0 (#771) — `AlreadyHeld` reaches the same classifier
                // as the duplicate-key arm below, for the reason that arm
                // states: a collision proves somebody won, NOT that your row
                // is the one present.
                Ok(_) => classify_after_duplicate(directory, sa).await?,
                // v31.1.0 (CIRISPersist#665 review) — A DUPLICATE KEY PROVES
                // SOMEBODY WON, NOT THAT **YOUR** ROW IS PRESENT.
                //
                // This arm reported `AlreadyPresent` on the strength of the
                // collision alone, skipping every check the `Some(existing)`
                // branch applies. Two concurrent bakes carrying DIFFERENT
                // content therefore both returned success, and the loser's
                // report claimed a ceremony the corpus does not hold — or holds
                // half of, since each id races independently. `bake_assembled_genesis`
                // runs no final plane verification, so nothing downstream
                // corrected it.
                //
                // Re-read and classify what is actually there. `AlreadyPresent`
                // is now only ever said about a row this bundle would itself
                // have written.
                Err(e) if e.is_duplicate_key() => classify_after_duplicate(directory, sa).await?,
                Err(e) => BakeItemOutcome::Skipped(format!("{}: {e}", e.kind())),
            },
            Some(existing) => {
                if super::baked_row_matches_stored(&existing, &sa.attestation).unwrap_or(false) {
                    BakeItemOutcome::AlreadyPresent
                } else if super::envelope_matches_baked(&existing, &sa.attestation).unwrap_or(false)
                {
                    // v31.1.0 (CIRISPersist#665 review) — **THE SAME SIGNED
                    // STATEMENT, DAMAGED AROUND IT: REPAIRABLE, NOT A ROLLBACK.**
                    //
                    // Equal `asserted_at` was one undifferentiated case and it
                    // is two. A row whose signed envelope is byte-identical to
                    // the bundle's, with only UNSIGNED material altered
                    // (`additional_scrubs` thinned, a scribbled hash), failed
                    // whole-row equality and then failed the strict recency test
                    // — the envelope-bound instants are identical — and fell
                    // into the anti-rollback `return Err` below.
                    //
                    // So **re-running the saved ceremony bundle could not repair
                    // the node's own ceremony row.** The boot seed cannot help
                    // either when that ceremony is newer than the compiled-in
                    // artifact, and posture rejects the damaged row — leaving
                    // another full ceremony as the only recovery, on the exact
                    // path an operator reaches for during an incident.
                    //
                    // There is no rollback risk here at all: the signed bytes
                    // are identical, so restoring the unsigned material to what
                    // the ceremony stated is not a supersession. It is the same
                    // statement, made whole. Classified BEFORE the recency test,
                    // because recency is the wrong question about a row that is
                    // not proposing anything different.
                    //
                    // Deliberately not gated on the stored row being a verifiable
                    // holder statement, unlike the supersede arm below: nothing
                    // is being erased that is not being restored byte-identically,
                    // so there is no evidence to preserve.
                    super::preflight_replacement_admission(&sa.attestation)?;
                    if directory
                        .purge_genesis_delegation_row_v31(
                            &id,
                            &existing.persist_row_hash,
                            &purge_authority,
                        )
                        .await?
                    {
                        match directory.put_attestation(sa.clone()).await {
                            Ok(crate::federation::AttestationOutcome::Inserted) => {
                                BakeItemOutcome::ReAnchored
                            }
                            // v38.5.0 (#771) — `AlreadyHeld` is the same
                            // condition the duplicate-key arm handles, now
                            // typed instead of string-tested. It must reach
                            // the SAME classifier: a collision proves somebody
                            // won, not that YOUR row is present.
                            Ok(_) => classify_after_duplicate(directory, sa).await?,
                            Err(e) if e.is_duplicate_key() => {
                                classify_after_duplicate(directory, sa).await?
                            }
                            Err(e) => return Err(e),
                        }
                    } else {
                        BakeItemOutcome::Skipped(
                            "the damaged row changed while this bake was classifying it; nothing \
                             was written — re-run against the current state"
                                .to_owned(),
                        )
                    }
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
                    //
                    // v31.1.0 (CIRISPersist#665 review) — PREFLIGHT BEFORE THE
                    // DELETE. `put_attestation` refusing after the purge leaves
                    // the constitutional row GONE and the retry hitting the same
                    // refusal; the trigger needs nothing exotic — a ceremony
                    // machine whose clock runs ahead of `DEFAULT_MAX_TOUCH_SKEW`
                    // is v31-conformant at its own instant (so recency and shape
                    // both pass) and refused by the door's wall-clock gate. Same
                    // fix, same shared predicate, as the seed path.
                    super::preflight_replacement_admission(&sa.attestation)?;
                    // v31.1.0 (CIRISPersist#665 review) — **DO NOT PURGE THE
                    // EVIDENCE OF A SUBSTITUTION.**
                    //
                    // A substituted or corrupted row carrying an OLDER bound
                    // instant passes the recency test above, so this arm would
                    // delete it — destroying the only evidence that anything was
                    // wrong, unrecoverably, and reporting a clean re-anchor.
                    //
                    // The BOOT path already knows better: its replacement matrix
                    // leaves an unverifiable statement in place precisely so
                    // posture can report it (`LeftAsSubstituted`). This is that
                    // same asymmetry between the two doors onto this plane — the
                    // question that has now found six defects in this file — so
                    // the bake asks the boot path's question, with the boot
                    // path's predicate, before it deletes anything.
                    if !super::stored_row_is_verifiable_holder_statement(directory, &existing).await
                    {
                        att_outcomes.push((
                            id,
                            BakeItemOutcome::Skipped(
                                "the installed row is NOT a verifiable statement by a seated \
                                 accord holder; refusing to delete it. It is evidence of a \
                                 substitution and the posture leg must be able to report it — \
                                 investigate the host before re-running"
                                    .to_owned(),
                            ),
                        ));
                        continue;
                    }
                    if directory
                        .purge_genesis_delegation_row_v31(
                            &id,
                            &existing.persist_row_hash,
                            &purge_authority,
                        )
                        .await?
                    {
                        // A duplicate here is NOT a false success — the `?`
                        // propagates it — but erroring is over-reporting when
                        // the winner's row may be exactly what this bundle
                        // wanted. Reclassify through the same helper the insert
                        // branch uses, so one rule answers "what is actually
                        // there" at both sites.
                        match directory.put_attestation(sa.clone()).await {
                            Ok(crate::federation::AttestationOutcome::Inserted) => {
                                BakeItemOutcome::ReAnchored
                            }
                            // v38.5.0 (#771) — `AlreadyHeld` is the same
                            // condition the duplicate-key arm handles, now
                            // typed instead of string-tested. It must reach
                            // the SAME classifier: a collision proves somebody
                            // won, not that YOUR row is present.
                            Ok(_) => classify_after_duplicate(directory, sa).await?,
                            Err(e) if e.is_duplicate_key() => {
                                classify_after_duplicate(directory, sa).await?
                            }
                            Err(e) => return Err(e),
                        }
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
        quorum_verified: quorum.distinct_holders(),
        serve_nodes: serve_outcomes,
        attestations: att_outcomes,
    })
}

#[cfg(test)]
mod authorization_digest_tests {
    use super::*;

    /// v38.0.0 (CIRISPersist#671) — **the purge door widens under quorum,
    /// and ONLY under quorum.** The un-recuttable-candidate-id defect: a
    /// verified ceremony could install `genesis-grant:<new-serve-node>`
    /// (a novel id), and every later ceremony reissuing that stable id hit
    /// the compiled-in-only purge refusal — with the `?` aborting the whole
    /// bake. Four arms, each a distinct fact: baked id under CompiledIn
    /// (the #665 bound, unchanged); novel id under CompiledIn (the negative
    /// pin — no verified bundle, no purge); novel id under a quorum proof
    /// CARRYING it (the re-cut, now open); novel id under a quorum proof
    /// NOT carrying it (a proof is not a skeleton key).
    #[test]
    fn the_purge_door_widens_under_quorum_and_only_under_quorum_671() {
        use crate::federation::genesis::check_genesis_rebake_purge_admission_under as door;

        let artifact = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/genesis_v2.json"
        ));
        let mut bundle = parse_genesis_bundle(artifact).expect("fixture parses");
        // The real re-cut shape: a ceremony carrying a grant for a NEW
        // serve node — an id the compiled-in artifact has never heard of.
        let novel = "genesis-grant:new-serve-node-671";
        bundle.attestations[1].attestation.attestation_id = novel.to_owned();
        // Same-module construction: the predicate under test is the DOOR's,
        // not the verifier's (verify_bundle_quorum's own witnesses live in
        // tests/accord_holder_real_custody.rs against real signatures).
        let proof = QuorumVerifiedBundle {
            bundle: &bundle,
            distinct_holders: 2,
        };

        let baked = "genesis-charter";
        assert!(door(baked, &GenesisPurgeAuthority::CompiledIn).is_ok());
        assert!(door(baked, &GenesisPurgeAuthority::QuorumVerified(&proof)).is_ok());

        // The negative pin: an id named by a caller with NO verified bundle
        // is still refused — on every backend, since each re-asks this
        // predicate internally.
        let err = door(novel, &GenesisPurgeAuthority::CompiledIn).unwrap_err();
        assert!(err.to_string().contains("#665/#671"), "{err}");

        // The re-cut: the proof carries the id, the door opens.
        assert!(door(novel, &GenesisPurgeAuthority::QuorumVerified(&proof)).is_ok());

        // A proof is not a skeleton key: an id the bundle does NOT carry
        // stays refused under it.
        assert!(door(
            "genesis-grant:some-other-node",
            &GenesisPurgeAuthority::QuorumVerified(&proof)
        )
        .is_err());
    }

    /// v31.2.0 (CIRISPersist#660, CIRISServer#398 §5) — **the field set of
    /// `KeyRecord` is pinned, so widening the record widens the digest as a
    /// REVIEWED act.**
    ///
    /// `authorized_record_projection` serializes the whole record and removes
    /// only [`NODE_LOCAL_RECORD_FIELDS`], which means a field added to
    /// `KeyRecord` enters the signing preimage automatically. That is the right
    /// default — a new producer-authored field SHOULD be bound — but it must not
    /// happen silently, because it changes the bytes every holder signs.
    ///
    /// So this test fails on ANY change to the record's shape. Adding a field:
    /// decide whether it is producer-authored (leave it bound, add it here) or
    /// node-local (add it to `NODE_LOCAL_RECORD_FIELDS`, add it here). Either
    /// way the decision is made by a human and shows up in a diff.
    #[test]
    fn authorized_record_projection_binds_every_producer_field() {
        let bundle = crate::federation::genesis::canonical_genesis_bundle();

        // UNION over every record, holders AND serve nodes. Sampling one record
        // is how this guard missed `additional_scrubs` (CIRISPersist#683): it is
        // absent on A1/B1/C1 and present ONLY on the serve node — the very
        // record the ceremony co-scrubs. A `skip_serializing_if` field hides on
        // any record that does not happen to carry it.
        let all: Vec<serde_json::Value> = bundle
            .holders
            .iter()
            .chain(bundle.serve_nodes.iter())
            .map(|r| serde_json::to_value(&r.record).expect("record serializes"))
            .collect();
        assert!(
            all.len() >= 2,
            "need holders AND serve nodes to see the whole field space"
        );
        let full_keys: std::collections::BTreeSet<&str> = all
            .iter()
            .flat_map(|v| v.as_object().expect("record is an object").keys())
            .map(String::as_str)
            .collect();
        let record = &bundle
            .serve_nodes
            .first()
            .expect("the canonical bundle carries a serve node")
            .record;

        // Every field the record actually carries, as of v31.2.0. `Option`
        // fields with `skip_serializing_if` only appear when populated, so this
        // is the set for a fully-populated hybrid holder record.
        let expected: std::collections::BTreeSet<&str> = [
            "key_id",
            "pubkey_ed25519_base64",
            "pubkey_ml_dsa_65_base64",
            "algorithm",
            "identity_type",
            "identity_ref",
            "valid_from",
            "valid_until",
            "registration_envelope",
            "original_content_hash",
            "scrub_signature_classical",
            "scrub_signature_pqc",
            "scrub_key_id",
            "scrub_timestamp",
            // Both named explicitly by #660 as things the narrow preimage did
            // NOT bind — "roles or custody evidence". `roles` is the capability
            // set (a serve node with widened roles under an unchanged key_id is
            // the substitution this whole change prevents); `attestation_evidence`
            // is the hardware custody blob (TPM / Secure Enclave / StrongBox).
            // Producer-authored, both bound.
            "roles",
            "attestation_evidence",
            // Present ONLY on the serve node, which is why a one-record sample
            // never saw it — and it is the field that made the ceremony
            // circular (#683).
            "additional_scrubs",
            "pqc_completed_at",
            "persist_row_hash",
        ]
        .into_iter()
        .collect();

        let unexpected: Vec<_> = full_keys.difference(&expected).collect();
        assert!(
            unexpected.is_empty(),
            "KeyRecord grew {unexpected:?}. These are now in the AUTHORIZATION \
             PREIMAGE that every genesis holder signs. Decide deliberately: \
             producer-authored (leave bound) or node-local (add to \
             NODE_LOCAL_RECORD_FIELDS) — then update this list."
        );

        // The projection must drop exactly the node-local pair, nothing else.
        let projected = authorized_record_projection(record).expect("projects");
        let projected_keys: std::collections::BTreeSet<&str> = projected
            .as_object()
            .expect("projection is an object")
            .keys()
            .map(String::as_str)
            .collect();
        for field in NODE_LOCAL_RECORD_FIELDS {
            assert!(
                !projected_keys.contains(field),
                "{field} is node-local and must never enter the preimage"
            );
        }
        for field in CEREMONY_MUTATED_RECORD_FIELDS {
            assert!(
                !projected_keys.contains(field),
                "{field} is mutated BY THE CEREMONY after a holder signs; \
                 binding it makes a 2-of-3 genesis impossible to complete (#683)"
            );
        }
    }

    /// v31.2.0 (CIRISServer#398) — **the output is a FIXED-SIZE digest, and
    /// stays fixed as the bundle grows.**
    ///
    /// This function used to return the canonical preimage itself, so what
    /// holders signed grew with the bundle. Nobody noticed while it was ~2 KB;
    /// binding full `KeyRecord`s took it to ~83 KB and a YubiKey refused to sign
    /// it — *"plaintext input data has a bad length… too long"* — mid-ceremony.
    ///
    /// So the assertion is not merely "32 bytes for this bundle". It is **the
    /// length does not depend on the bundle**, which is the property that was
    /// actually violated. A revert to returning canonical bytes reds here rather
    /// than at a hardware token during a ceremony.
    #[test]
    fn authorization_digest_returns_a_fixed_size_digest() {
        let base = crate::federation::genesis::canonical_genesis_bundle().clone();
        let small = authorization_digest(&base).expect("digest");
        assert_eq!(small.len(), 32, "SHA-256 is 32 bytes; got {}", small.len());

        // Grow the bundle substantially — duplicate the holder roster several
        // times over. The PREIMAGE gets much bigger; the DIGEST must not.
        let mut grown = base.clone();
        for _ in 0..8 {
            let more = grown.holders.clone();
            grown.holders.extend(more);
        }
        let big = authorization_digest(&grown).expect("digest");
        assert_eq!(
            big.len(),
            small.len(),
            "the signed output grew with the bundle — this is CIRISServer#398 \
             exactly: a preimage wearing the name `digest`, which no hardware \
             token will sign once the bundle is real"
        );
        assert_ne!(big, small, "a bigger roster must still change the digest");

        // And prove it is HASHED, not merely truncated canonical bytes.
        let canonical = crate::verify::canonical::ceg_produce_canonicalize(&serde_json::json!({
            "version": base.version,
        }))
        .expect("canonicalize");
        assert!(
            !canonical.starts_with(&small[..4.min(small.len())]),
            "the digest looks like a canonical-bytes prefix rather than a hash"
        );
    }

    /// v31.2.0 (CIRISPersist#683) — **the ceremony's own co-scrub must not move
    /// the digest.** This is the property that failed on a live 2-of-3.
    ///
    /// The ceremony accumulates authorizations AND the serve node's scrub set
    /// over one bundle, one pass per holder. If the digest binds the scrub set,
    /// those two accumulations are circular: B1's co-scrub rewrites bytes A1
    /// already signed, A1's honest authorization stops verifying, and the node
    /// reports `have=2 needed=2 complete=false`. A third holder cannot help —
    /// every new signature is over bytes the next co-scrub moves again.
    ///
    /// Driven by mutating the scrub set exactly as a co-scrub does, rather than
    /// by asserting the projection's key list: a key-list assertion would pass
    /// against a projection that dropped the right names for the wrong reason.
    #[test]
    fn appending_a_co_scrub_does_not_move_the_digest() {
        let base = crate::federation::genesis::canonical_genesis_bundle().clone();
        let baseline = authorization_digest(&base).expect("digest");

        let mut cosigned = base.clone();
        let sn = &mut cosigned
            .serve_nodes
            .first_mut()
            .expect("the canonical bundle carries a serve node")
            .record;

        // B1 appends its scrub, and the primary scrub fields move with it.
        sn.additional_scrubs
            .push(crate::federation::types::ScrubSig {
                cosigned_at: None,
                scrub_key_id: "B1".to_owned(),
                scrub_signature_classical: "B".repeat(88),
                scrub_signature_pqc: Some("B".repeat(4412)),
            });
        sn.scrub_key_id = "B1".to_owned();
        sn.scrub_signature_classical = "C".repeat(88);
        sn.scrub_signature_pqc = Some("C".repeat(4412));
        sn.scrub_timestamp =
            base.serve_nodes[0].record.scrub_timestamp + chrono::Duration::seconds(90);

        assert_eq!(
            authorization_digest(&cosigned).expect("digest"),
            baseline,
            "a co-scrub moved the digest — A1's authorization would stop \
             verifying and a 2-of-3 genesis could never complete (#683)"
        );

        // The counter-control: CONTENT must still move it, or this test would
        // pass against a projection that bound nothing at all.
        let mut swapped = cosigned.clone();
        swapped.serve_nodes[0].record.pubkey_ed25519_base64 = "Z".repeat(44);
        assert_ne!(
            authorization_digest(&swapped).expect("digest"),
            baseline,
            "content stopped moving the digest — the exclusion went too far and \
             #660 is back"
        );
    }

    /// **The property #660 existed to fix, driven directly.**
    ///
    /// Substituting the RECORD under an unchanged `key_id` — the case the old
    /// `key_id`-only preimage could not see — must change the digest. Asserted
    /// per node-local field too: those must NOT change it, or the producer and
    /// every consumer disagree by construction.
    #[test]
    fn substituting_a_record_under_an_unchanged_key_id_moves_the_digest() {
        let base = crate::federation::genesis::canonical_genesis_bundle().clone();
        let baseline = authorization_digest(&base).expect("digest");

        // A swapped pubkey under the SAME key_id. Pre-v31.2.0 this was
        // invisible: `holders` contributed `key_id` and nothing else.
        let mut swapped = base.clone();
        let target = &mut swapped.holders[0].record;
        let original_key_id = target.key_id.clone();
        target.pubkey_ed25519_base64 = "A".repeat(44);
        assert_eq!(
            target.key_id, original_key_id,
            "the whole point is that the id is UNCHANGED"
        );
        assert_ne!(
            authorization_digest(&swapped).expect("digest"),
            baseline,
            "a substituted holder pubkey under an unchanged key_id did not move \
             the digest — this is CIRISPersist#660 exactly"
        );

        // identity_type decides canonical standing (`is_canonical` reads it off
        // the row) and was the member persist's subject binding omitted in
        // v31.0.0 (#659/#661). Binding a pubkey but not the type that governs
        // what it may do closes half a door.
        let mut retyped = base.clone();
        retyped.serve_nodes[0].record.identity_type = "definitely-not-the-real-type".to_owned();
        assert_ne!(
            authorization_digest(&retyped).expect("digest"),
            baseline,
            "a swapped serve-node identity_type did not move the digest"
        );

        // And the other direction: a node-local field must NOT move it.
        let mut local = base.clone();
        local.holders[0].record.persist_row_hash = "deadbeef".repeat(8);
        local.holders[0].record.pqc_completed_at = Some(chrono::Utc::now());
        assert_eq!(
            authorization_digest(&local).expect("digest"),
            baseline,
            "a node-local field moved the digest — the producer and every \
             consumer would disagree by construction"
        );
    }
}
