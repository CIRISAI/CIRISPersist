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
//! for the *authenticated* one. `bake_assembled_genesis` was that path
//! (deleted in v62.0.0, json-cut C5; what remains here is the bundle/1 type,
//! its parser and its quorum check, kept for the baked seed until the E flip):
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
//! The [`authorization_digest`] holders sign is CIRISVerify's
//! [`ciris_verify_core::genesis_bundle::authorization_digest`]: SHA-256 over the
//! JCS canonicalization of a projection of the bundle. Persist delegates to it
//! (CIRISPersist#1141), so persist, CIRISServer and CIRISVerify sign and check
//! one preimage. The digest is 32 bytes so a hardware token can sign it
//! (CIRISServer#398).
//!
//! # What the digest binds
//!
//! - **The delegation plane.** Each attestation contributes its
//!   `attestation_id`, `attesting_key_id`, `attested_key_id`,
//!   `attestation_type` and its whole `attestation_envelope`, so the scopes, the
//!   subject and the verb are bound byte for byte. Each roster record
//!   contributes its own signing envelope under `family` / `community`.
//! - **Record content.** `holders` and `serve_nodes` contribute the whole
//!   `KeyRecord` through typed serde, minus two node-local members
//!   (`persist_row_hash`, `pqc_completed_at`) and the five scrub members the
//!   ceremony itself accumulates (`scrub_key_id`, `scrub_signature_classical`,
//!   `scrub_signature_pqc`, `scrub_timestamp`, `additional_scrubs`). A record
//!   substituted under an unchanged `key_id` breaks every authorization
//!   (CIRISPersist#660).
//! - **The scrub set is not bound.** It is quorum evidence about the record
//!   that the ceremony accumulates between holder signatures; binding it makes
//!   a 2-of-3 genesis impossible to complete (CIRISPersist#683). Each scrub is
//!   verified on its own against this node's pinned holder anchors, and the
//!   record's content is bound through every content member plus
//!   `original_content_hash`.
//! - **Version ≥ 4 only:** each serve node's transport row, as
//!   `{attesting_key_id, signed_envelope}`.
//!
//! The threshold is persist's policy and stays here: [`verify_bundle_quorum`]
//! requires `max(carried M, strict majority of persist's OWN roster)`.

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

/// v53.0.0 (CC 3.2 T6 / 5.3.4, rc7 b578b59) — **a lineage's genesis head, as
/// the bundle carries it**: the signed roster record at its first version.
/// CC: "the `humanity-accord` family record and the `ciris-canonical` birth
/// record are members of `bundle.attestations`, pinned by
/// `bundle_fingerprint`". On the wire each is an element of the
/// `attestations` array, after every delegation row, recognised by its key
/// (`"family"` / `"community"`, where a delegation row has `"attestation"`).
///
/// Parsed by its key, never as an untagged enum: serde's untagged buffering
/// does not round-trip a row's numbers and instants.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum GenesisRosterRecord {
    /// A family record (the `humanity-accord` genesis head).
    Family(super::super::types::SignedFamily),
    /// A community record (the `ciris-canonical` birth).
    Community(super::super::types::SignedCommunity),
}

impl GenesisRosterRecord {
    /// The record's key id (`family_key_id` / `community_key_id`).
    #[must_use]
    pub fn key_id(&self) -> &str {
        match self {
            Self::Family(f) => &f.family.family_key_id,
            Self::Community(c) => &c.community.community_key_id,
        }
    }
}

/// One element of the wire `attestations` array, as written.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
enum GenesisBundleMember {
    Row(SignedAttestation),
    Record(GenesisRosterRecord),
}

/// The bundle as it is written: the delegation rows and the roster records
/// share one `attestations` array (CC 5.3.4).
#[derive(Debug, Clone, Serialize)]
struct GenesisBundleWire {
    version: u32,
    family_key_id: String,
    holders: Vec<SignedKeyRecord>,
    serve_nodes: Vec<SignedKeyRecord>,
    consensus_protocol: String,
    attestations: Vec<GenesisBundleMember>,
    authorizations: Vec<GenesisAuthorization>,
    produced_at: String,
    /// v59.0.0 (CIRISPersist#1106, CC 5.3.4) — omitted when empty, so a v2 /
    /// v3 bundle re-serializes byte for byte.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    serve_transport_destinations: Vec<super::super::self_at_login::SignedTransportDestination>,
}

/// The bundle as it is read: each `attestations` element is dispatched by its
/// one key (`attestation` / `family` / `community`).
#[derive(Debug, Clone, Deserialize)]
struct GenesisBundleWireIn {
    version: u32,
    family_key_id: String,
    holders: Vec<SignedKeyRecord>,
    serve_nodes: Vec<SignedKeyRecord>,
    consensus_protocol: String,
    attestations: Vec<serde_json::Value>,
    authorizations: Vec<GenesisAuthorization>,
    produced_at: String,
    #[serde(default)]
    serve_transport_destinations: Vec<super::super::self_at_login::SignedTransportDestination>,
}

impl TryFrom<GenesisBundleWireIn> for GenesisBundle {
    type Error = String;

    fn try_from(w: GenesisBundleWireIn) -> Result<Self, String> {
        let mut attestations = Vec::new();
        let mut roster_records = Vec::new();
        for (n, member) in w.attestations.into_iter().enumerate() {
            let has = |k: &str| member.get(k).is_some();
            let kinds = [has("attestation"), has("family"), has("community")];
            let parse_err = |e: serde_json::Error| format!("bundle attestations[{n}]: {e}");
            match kinds {
                [true, false, false] => {
                    // One spelling: every delegation row precedes every roster
                    // record, so a parse and a re-serialization are the same
                    // bytes.
                    if !roster_records.is_empty() {
                        return Err(format!(
                            "bundle attestations[{n}]: a delegation row follows a roster record; \
                             the roster records (family, community) come after every row"
                        ));
                    }
                    attestations.push(serde_json::from_value(member).map_err(parse_err)?);
                }
                [false, true, false] => roster_records.push(GenesisRosterRecord::Family(
                    serde_json::from_value(member).map_err(parse_err)?,
                )),
                [false, false, true] => roster_records.push(GenesisRosterRecord::Community(
                    serde_json::from_value(member).map_err(parse_err)?,
                )),
                _ => {
                    return Err(format!(
                        "bundle attestations[{n}]: an element is exactly one of a delegation row \
                         (`attestation`), a family record (`family`) or a community record \
                         (`community`)"
                    ))
                }
            }
        }
        Ok(Self {
            version: w.version,
            family_key_id: w.family_key_id,
            holders: w.holders,
            serve_nodes: w.serve_nodes,
            consensus_protocol: w.consensus_protocol,
            attestations,
            roster_records,
            authorizations: w.authorizations,
            produced_at: w.produced_at,
            serve_transport_destinations: w.serve_transport_destinations,
        })
    }
}

impl From<GenesisBundle> for GenesisBundleWire {
    fn from(b: GenesisBundle) -> Self {
        Self {
            version: b.version,
            family_key_id: b.family_key_id,
            holders: b.holders,
            serve_nodes: b.serve_nodes,
            consensus_protocol: b.consensus_protocol,
            attestations: b
                .attestations
                .into_iter()
                .map(GenesisBundleMember::Row)
                .chain(
                    b.roster_records
                        .into_iter()
                        .map(GenesisBundleMember::Record),
                )
                .collect(),
            authorizations: b.authorizations,
            produced_at: b.produced_at,
            serve_transport_destinations: b.serve_transport_destinations,
        }
    }
}

/// The bundle version the assembler emits. Version 3 (v53, CC rc7) is the
/// first that carries the roster records (a version-2 bundle carries none);
/// version 4 (v59.0.0, CIRISPersist#1106, CC 5.3.4 rc9 `6cde890`) the first
/// that carries the serve nodes' signed transport destinations
/// ([`GenesisBundle::serve_transport_destinations`]), bound by
/// [`authorization_digest`].
pub const GENESIS_BUNDLE_VERSION: u32 = 4;

/// The first bundle version whose [`authorization_digest`] binds
/// [`GenesisBundle::serve_transport_destinations`].
pub const SERVE_TRANSPORT_DESTINATIONS_VERSION: u32 = 4;

/// v59.0.0 (CIRISPersist#1106) — the stable token a bundle whose serve-node
/// transport rows fail [`check_serve_transport_destinations`] is refused with
/// (it leads the [`Error::GenesisBundleInvalid`] detail): the WHOLE bundle
/// fails closed.
pub const SERVE_TRANSPORT_DESTINATION_INVALID: &str = "genesis_serve_transport_destination_invalid";

/// The assembled genesis artifact (wire-compatible with CIRISServer
/// `mesh_genesis::GenesisBundle` — same field names, same persist row
/// types inside).
///
/// v53.0.0 — on the wire, [`Self::roster_records`] are further elements of
/// `attestations` (see [`GenesisRosterRecord`]); in Rust they are their own
/// field, so every reader of the delegation plane keeps reading rows only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "GenesisBundleWireIn", into = "GenesisBundleWire")]
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
    /// v53.0.0 (CC rc7) — the genesis heads: the accord family record and the
    /// `ciris-canonical` birth. Serialized inside `attestations`, after the
    /// rows; bound by [`authorization_digest`] the same way.
    pub roster_records: Vec<GenesisRosterRecord>,
    /// The accumulated holder authorizations over [`authorization_digest`].
    pub authorizations: Vec<GenesisAuthorization>,
    /// Ceremony timestamp (RFC 3339) — in the digest, so two ceremonies
    /// are distinguishable.
    pub produced_at: String,
    /// v59.0.0 (CIRISPersist#1106, CC 5.3.4 rc9 `6cde890`,
    /// `CLM-bundle-seeds-transit-pairs`) — each seated serve node's signed
    /// transport destination carrying its transit KEX pair, so a fresh node
    /// holds a Rooted pair for every serve node offline. Wire member
    /// `serve_transport_destinations`; version ≥ 4 only (bound by the digest);
    /// empty, and omitted on the wire, below that.
    pub serve_transport_destinations: Vec<super::super::self_at_login::SignedTransportDestination>,
}

impl GenesisBundle {
    /// v53.0.0 — the community record the bundle carries under `community_key_id`
    /// (the `ciris-canonical` birth), if any.
    #[must_use]
    pub fn community_record(
        &self,
        community_key_id: &str,
    ) -> Option<&super::super::types::SignedCommunity> {
        self.roster_records.iter().find_map(|r| match r {
            GenesisRosterRecord::Community(c)
                if c.community.community_key_id == community_key_id =>
            {
                Some(c)
            }
            _ => None,
        })
    }

    /// v53.0.0 — the family record the bundle carries under `family_key_id`
    /// (the accord family's genesis head), if any.
    #[must_use]
    pub fn family_record(&self, family_key_id: &str) -> Option<&super::super::types::SignedFamily> {
        self.roster_records.iter().find_map(|r| match r {
            GenesisRosterRecord::Family(f) if f.family.family_key_id == family_key_id => Some(f),
            _ => None,
        })
    }
}

/// The bytes every holder authorization signs:
/// [`ciris_verify_core::genesis_bundle::authorization_digest`] over this bundle.
///
/// CIRISVerify owns the projection (CIRISPersist#1141); this is a thin
/// adapter. The bundle is serialized to its wire form and parsed by verify's
/// [`GenesisBundle::from_value`](ciris_verify_core::genesis_bundle::GenesisBundle::from_value),
/// whose mirror types carry `KeyRecord`'s, `Family`'s and `Community`'s serde
/// attributes member for member, so the records are projected through typed
/// serde exactly as before. `authorizations` are not in the preimage (they are
/// what is being accumulated). The module doc lists what is bound.
///
/// I1476 pins the result against verify's seven vectors;
/// `authorization_digest_returns_a_fixed_size_digest` pins the 32-byte output.
pub fn authorization_digest(bundle: &GenesisBundle) -> Result<Vec<u8>, Error> {
    use ciris_verify_core::genesis_bundle as vgb;
    let refused = |e: &dyn std::fmt::Display| Error::GenesisBundleInvalid {
        detail: format!("authorization_digest: {e}"),
    };
    let wire = serde_json::to_value(bundle).map_err(|e| refused(&e))?;
    let parsed = vgb::GenesisBundle::from_value(&wire).map_err(|e| refused(&e))?;
    let digest = vgb::authorization_digest(&parsed).map_err(|e| refused(&e))?;
    Ok(digest.to_vec())
}

/// v23.0.0 (CIRISPersist#551 item 1) — the **single door** every genesis
/// bundle enters through, whether it arrives as an operator artifact
/// (`bake_assembled_genesis`, deleted in v62.0.0) or as the compiled-in seed asset
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

/// v59.0.0 (CIRISPersist#1106, CC 5.3.4) — **the serve nodes' transport rows,
/// structurally**, against the bundle's own `serve_nodes` (a fresh node does
/// not hold them yet): every row is about and signed by a key in
/// `serve_nodes` (hybrid 1-of-1 over `JCS(signed_envelope)` against that
/// record's keys), carries a transit KEX pair, and passes the separation rule
/// ([`check_transit_kex_pair`](super::super::self_at_login::check_transit_kex_pair))
/// against its own link key and the node's signing keys. A bundle below
/// version 4 must carry none (the digest does not bind them). Any failure
/// fails the WHOLE bundle, [`SERVE_TRANSPORT_DESTINATION_INVALID`].
///
/// # Errors
///
/// [`Error::GenesisBundleInvalid`], detail led by the token.
pub fn check_serve_transport_destinations(bundle: &GenesisBundle) -> Result<(), Error> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use ciris_verify_core::threshold::{
        verify_threshold_signatures, ThresholdMember, ThresholdSignature,
    };
    let refuse = |detail: String| Error::GenesisBundleInvalid {
        detail: format!("{SERVE_TRANSPORT_DESTINATION_INVALID}: {detail}"),
    };
    if bundle.version < SERVE_TRANSPORT_DESTINATIONS_VERSION {
        if bundle.serve_transport_destinations.is_empty() {
            return Ok(());
        }
        return Err(refuse(format!(
            "a version-{} bundle carries serve transport destinations its authorizations do not \
             cover",
            bundle.version
        )));
    }
    for (i, row) in bundle.serve_transport_destinations.iter().enumerate() {
        let td = &row.transport_destination;
        let Some(node) = bundle
            .serve_nodes
            .iter()
            .find(|n| n.record.key_id == row.attesting_key_id)
        else {
            return Err(refuse(format!(
                "row [{i}] is signed by {:?}, which is not one of the bundle's serve nodes",
                row.attesting_key_id
            )));
        };
        if td.occurrence_key_id != row.attesting_key_id {
            return Err(refuse(format!(
                "row [{i}] is about {:?} but signed by {:?}: a serve node signs its own route",
                td.occurrence_key_id, row.attesting_key_id
            )));
        }
        let pair =
            super::super::self_at_login::transit_kex_pair_from_envelope(&row.signed_envelope)
                .map_err(|e| refuse(format!("row [{i}]: {e}")))?
                .ok_or_else(|| refuse(format!("row [{i}] carries no transit KEX pair")))?;
        let dec = |b64: Option<&str>| b64.and_then(|s| B64.decode(s).ok());
        // (a) + (b): what a bundle carries about the node.
        let others = super::super::self_at_login::TransitKexOtherKeys {
            federation_signing: [
                dec(Some(node.record.pubkey_ed25519_base64.as_str())),
                dec(node.record.pubkey_ml_dsa_65_base64.as_deref()),
            ]
            .into_iter()
            .flatten()
            .collect(),
            transport_identity: [
                dec(td.transport_x25519_pubkey_base64.as_deref()),
                dec(td.transport_ed25519_pubkey_base64.as_deref()),
            ]
            .into_iter()
            .flatten()
            .collect(),
            ..Default::default()
        };
        super::super::self_at_login::check_transit_kex_pair(&pair, &others)
            .map_err(|r| refuse(format!("row [{i}]: {}", r.as_str())))?;
        let bytes = crate::verify::canonical::ceg_produce_canonicalize(&row.signed_envelope)
            .map_err(|e| refuse(format!("row [{i}] canonicalize: {e}")))?;
        let members = [ThresholdMember {
            member_id: node.record.key_id.clone(),
            ed25519_public_key_base64: node.record.pubkey_ed25519_base64.clone(),
            mldsa65_public_key_base64: node.record.pubkey_ml_dsa_65_base64.clone(),
            role: None,
        }];
        let sigs = [ThresholdSignature {
            member_id: row.attesting_key_id.clone(),
            ed25519_signature_base64: row.signature.ed25519_signature_base64.clone(),
            mldsa65_signature_base64: row.signature.mldsa65_signature_base64.clone(),
        }];
        if row.signature.mldsa65_signature_base64.is_none()
            || verify_threshold_signatures(&bytes, &members, &sigs, 1).is_err()
        {
            return Err(refuse(format!(
                "row [{i}]: the hybrid signature does not verify against serve node {:?}'s \
                 bundle record",
                row.attesting_key_id
            )));
        }
    }
    Ok(())
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
    // v59.0.0 (CIRISPersist#1106) — the serve nodes' transport rows are part
    // of what the quorum authorizes; a bad one fails the whole bundle.
    check_serve_transport_destinations(bundle)?;

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
    let now = crate::host::clock::now();
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
                crate::federation::hardware_attestation::record_ed25519(&holder.record).as_deref(),
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

        // v62.0.0 (json-cut C5): the `genesis_v2.json` fixture is deleted;
        // the compiled seed carries the same delegation-plane shape.
        let mut bundle = crate::federation::genesis::canonical_genesis_bundle().clone();
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

    /// CIRISPersist#660, #1141 — **the field set of `KeyRecord` is pinned, so a
    /// new member cannot fall out of the digest unnoticed.**
    ///
    /// The digest is CIRISVerify's, computed over its mirror of `KeyRecord`. A
    /// member persist adds and verify's mirror does not carry is DROPPED by
    /// verify's parse, so the digest would silently not bind it. This test
    /// fails on ANY change to the record's shape: a new member needs verify's
    /// mirror to carry it first (a new preimage version, with a new `*_VERSION`
    /// gate), and the decision shows up in a diff.
    #[test]
    fn key_record_field_set_is_pinned_to_the_digest() {
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
            "KeyRecord grew {unexpected:?}. CIRISVerify's digest projects its own \
             mirror of KeyRecord and drops a member it does not know, so these \
             would NOT be bound by the authorization every genesis holder signs. \
             Widen verify's mirror first (a new preimage version), then update \
             this list."
        );
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
