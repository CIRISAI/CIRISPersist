//! v53.0.0 (CIRISPersist#973, CC rc7) — **the genesis ceremony assembler.**
//!
//! A genesis ceremony is a set of signing items the accord holders sign one
//! at a time, often minutes apart and over separate HTTP requests:
//!
//! - `record:<node>` — each serve node's registration envelope (its scrub);
//! - `row:<id>` — each delegation row's envelope: the root charter
//!   (`trust:charter:v1`, carrying the T3 successor commitment and every
//!   holder's CC 4.2.6 recovery commitment), one `trust:confers:v1` grant per
//!   serve node, the lifecycle row;
//! - `family:<id>` — the accord family's genesis record (its lineage head);
//! - `community:<id>` — the `ciris-canonical` birth record;
//! - `authz` — [`authorization_digest`] over the whole bundle.
//!
//! Every holder signs every item: the founding rule (every primary signs once
//! at the mint), which also gives each grant the family's quorum as its
//! charter has it (CC 3.4.7).
//!
//! The heads name the charter in force by its stored row hash (CC 3.2 T6,
//! `charter_digest`), which covers the charter's scrubs; so `family:`,
//! `community:` and `authz` (which binds them) wait until every holder has
//! signed the charter. [`CeremonyState::next_items`] offers only what can be
//! signed now.
//!
//! [`CeremonyState`] holds only the caller's inputs and the partials received.
//! The bytes of every item are **recomputed from the inputs on every call**,
//! never stored, and every instant in them is derived from the ONE
//! `produced_at` the caller stamped at propose: the assembler never reads a
//! clock, so a session spanning many requests (or a restart) re-forms
//! byte-identical items. The state and each [`Partial`] are serde values the
//! host keeps between requests.
//!
//! [`CeremonyState::add_partial`] verifies a partial (Ed25519 over the item's
//! bytes, ML-DSA-65 over `bytes ‖ ed25519_sig`) against the holder's carried
//! public keys when it arrives, and refuses a bad one by name.
//! [`CeremonyState::assemble`] builds the [`GenesisBundle`] once every item is
//! complete; [`CeremonyState::finish`] assembles and then runs
//! [`verify_ceremony_outputs`](super::verify_ceremony_outputs), the same doors
//! a booting node runs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::bundle::{
    authorization_digest, GenesisAuthorization, GenesisBundle, GenesisRosterRecord,
    GENESIS_BUNDLE_VERSION,
};
use crate::federation::trust_root::{
    pre_rotation_commitment, recovery_commitment, CommittedKey, TRUST_CHARTER_DIMENSION,
    TRUST_CONFERS_DIMENSION,
};
use crate::federation::types::{
    attestation_tier, attestation_type, cohort_scope, Attestation, Community, CommunityMember,
    KeyRecord, RosterCosignature, ScrubSig, SignedAttestation, SignedCommunity, SignedFamily,
    SignedKeyRecord,
};

/// The schema version of a serialized [`CeremonyState`].
pub const CEREMONY_STATE_VERSION: u32 = 1;

/// The id of the root charter row a ceremony mints.
pub const GENESIS_CHARTER_ID: &str = "genesis-charter";
/// The id of the lifecycle row a ceremony mints.
pub const GENESIS_LIFECYCLE_ID: &str = "genesis-lifecycle";
/// The item id of the holders' authorization over the bundle.
pub const AUTHZ_ITEM_ID: &str = "authz";

/// The id of the grant row a ceremony mints for `node_key_id`.
#[must_use]
pub fn genesis_grant_id(node_key_id: &str) -> String {
    format!("genesis-grant:{node_key_id}")
}

/// One serve node the ceremony seats: its keys and the envelope its record
/// carries. The #659 subject binding is added by the assembler.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServeNodeInput {
    /// The node's key id.
    pub key_id: String,
    /// The record's `identity_type` (e.g. `canonical,node`).
    pub identity_type: String,
    /// Ed25519 public key, standard base64.
    pub pubkey_ed25519_base64: String,
    /// ML-DSA-65 public key, standard base64.
    pub pubkey_ml_dsa_65_base64: String,
    /// The record's capability roles.
    pub capability_roles: Vec<String>,
    /// The registration envelope before the subject binding (a JSON object).
    pub registration_envelope: serde_json::Value,
    /// The node's custody evidence, if it carries any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_evidence: Option<serde_json::Value>,
}

/// The `ciris-canonical` birth's own fields. Founders are the holders; the
/// serve nodes are seated as `member`s and sign nothing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommunityInput {
    /// The community's key id (`ciris-canonical`).
    pub community_key_id: String,
    /// The community's display name.
    pub community_name: String,
    /// `quorum:M/N` over the founders.
    pub consensus_protocol: String,
    /// The policy blob (the `infrastructure` subkind and its payload).
    pub policy_blob: serde_json::Value,
}

/// Everything a ceremony needs, stamped once by the caller at propose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CeremonyInputs {
    /// The accord family (`humanity-accord`).
    pub family_key_id: String,
    /// The family's `consensus_protocol` (`quorum:M/N`).
    pub consensus_protocol: String,
    /// The accord holders' records as carried, in signing order (the first is
    /// each object's primary signer).
    pub holders: Vec<SignedKeyRecord>,
    /// The serve nodes to seat.
    pub serve_nodes: Vec<ServeNodeInput>,
    /// The T3 successor set the charter commits to.
    pub successor_keys: Vec<CommittedKey>,
    /// Each holder's CC 4.2.6 recovery key, by holder key id.
    pub recovery_keys: BTreeMap<String, CommittedKey>,
    /// The scope the charter and every grant carry.
    pub scope: Vec<String>,
    /// The community birth.
    pub community: CommunityInput,
    /// THE ceremony instant. Every instant in every item derives from it; the
    /// assembler reads no clock. Truncated to microseconds at plan.
    pub produced_at: chrono::DateTime<chrono::Utc>,
}

/// One holder's hybrid signature over one item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Partial {
    /// The item id.
    pub item: String,
    /// The signing holder's key id.
    pub holder_key_id: String,
    /// Ed25519 over the item's bytes, standard base64.
    pub signature_classical: String,
    /// ML-DSA-65 over `bytes ‖ ed25519_sig`, standard base64.
    pub signature_pqc: String,
}

/// An item still owed signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignItem {
    /// The stable id.
    pub id: String,
    /// The exact bytes to sign.
    pub bytes: Vec<u8>,
    /// The holders that have not yet signed it.
    pub owed: Vec<String>,
    /// The items it waits on (empty when it can be signed now). The heads and
    /// the authorization wait on the charter: they name its stored row hash,
    /// which covers its scrubs. While it waits, `bytes` is empty.
    pub waits_on: Vec<String>,
}

/// Why the assembler refused. The wire token is [`CeremonyError::as_str`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeremonyError {
    /// The inputs cannot form a ceremony.
    InvalidInputs(String),
    /// A serialized state this build cannot read.
    StateVersion(u32),
    /// A partial names an item this ceremony does not have.
    UnknownItem(String),
    /// A partial names an item that waits on another item's signatures.
    NotReady {
        /// The item.
        item: String,
        /// What it waits on.
        waits_on: Vec<String>,
    },
    /// A partial is signed by a key that is not a holder of this ceremony.
    NotAHolder(String),
    /// A partial's signature does not verify over the item's bytes.
    BadSignature {
        /// The item.
        item: String,
        /// The holder.
        holder: String,
        /// The verifier's words.
        detail: String,
    },
    /// A second, different partial for an (item, holder) already signed.
    ConflictingPartial {
        /// The item.
        item: String,
        /// The holder.
        holder: String,
    },
    /// An item is still owed signatures.
    Incomplete(BTreeMap<String, Vec<String>>),
    /// The assembled outputs were refused by the ordinary doors.
    Outputs(super::CeremonyOutputsRefused),
}

impl CeremonyError {
    /// The stable token.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidInputs(_) => "ceremony_inputs_invalid",
            Self::StateVersion(_) => "ceremony_state_version",
            Self::UnknownItem(_) => "ceremony_item_unknown",
            Self::NotReady { .. } => "ceremony_item_not_ready",
            Self::NotAHolder(_) => "ceremony_signer_not_a_holder",
            Self::BadSignature { .. } => "ceremony_signature_invalid",
            Self::ConflictingPartial { .. } => "ceremony_partial_conflicts",
            Self::Incomplete(_) => "ceremony_incomplete",
            Self::Outputs(_) => "ceremony_outputs_refused",
        }
    }
}

impl std::fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token = self.as_str();
        match self {
            Self::InvalidInputs(d) => write!(f, "{token}: {d}"),
            Self::StateVersion(v) => write!(
                f,
                "{token}: state version {v}, this build reads {CEREMONY_STATE_VERSION}"
            ),
            Self::UnknownItem(i) => write!(f, "{token}: no item {i:?}"),
            Self::NotReady { item, waits_on } => {
                write!(f, "{token}: {item} waits on {waits_on:?}")
            }
            Self::NotAHolder(h) => write!(f, "{token}: {h} is not a holder of this ceremony"),
            Self::BadSignature {
                item,
                holder,
                detail,
            } => write!(f, "{token}: {holder} over {item}: {detail}"),
            Self::ConflictingPartial { item, holder } => write!(
                f,
                "{token}: {holder} already signed {item} with a different signature"
            ),
            Self::Incomplete(owed) => write!(f, "{token}: still owed {owed:?}"),
            Self::Outputs(e) => write!(f, "{token}: {e}"),
        }
    }
}

impl std::error::Error for CeremonyError {}

/// The ceremony in progress: the inputs and the partials received.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CeremonyState {
    /// [`CEREMONY_STATE_VERSION`].
    pub version: u32,
    /// The inputs, as planned.
    pub inputs: CeremonyInputs,
    /// Received partials: item id → holder key id → partial.
    pub partials: BTreeMap<String, BTreeMap<String, Partial>>,
}

/// What [`CeremonyState::finish`] returns.
#[derive(Debug, Clone)]
pub struct CeremonyFinished {
    /// The bundle: the only genesis artifact.
    pub bundle: GenesisBundle,
    /// The bundle as the JSON a node bakes.
    pub bundle_json: String,
    /// What the ordinary doors admitted.
    pub verified: super::CeremonyOutputsVerified,
}

/// The unsigned objects of a ceremony and its items, in item order.
/// Recomputed from the inputs (and, for the heads, the charter's signatures);
/// never stored.
struct Draft {
    node_records: Vec<KeyRecord>,
    rows: Vec<Attestation>,
    heads: Option<(crate::federation::types::Family, Community)>,
    items: Vec<DraftItem>,
}

/// One item of a draft: its bytes, or (while it waits) the items it waits on.
struct DraftItem {
    id: String,
    bytes: Option<Vec<u8>>,
    waits_on: Vec<String>,
}

fn scrub_sig(p: &Partial) -> ScrubSig {
    ScrubSig {
        cosigned_at: None,
        scrub_key_id: p.holder_key_id.clone(),
        scrub_signature_classical: p.signature_classical.clone(),
        scrub_signature_pqc: Some(p.signature_pqc.clone()),
    }
}

fn canonical(value: &serde_json::Value, what: &str) -> Result<Vec<u8>, CeremonyError> {
    crate::verify::canonical::ceg_produce_canonicalize(value)
        .map_err(|e| CeremonyError::InvalidInputs(format!("canonicalize {what}: {e}")))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

impl CeremonyState {
    /// **Plan a ceremony** from inputs the caller stamped once.
    ///
    /// # Errors
    ///
    /// [`CeremonyError::InvalidInputs`]: no holders, a repeated holder, a
    /// holder record or recovery key that cannot form a commitment element, a
    /// holder without exactly one recovery key, a recovery key that is a holder
    /// key or shared, no serve node, or anything the items cannot be formed
    /// from.
    pub fn plan(mut inputs: CeremonyInputs) -> Result<Self, CeremonyError> {
        let bad = |d: String| Err(CeremonyError::InvalidInputs(d));
        // Every backend stores an instant at microsecond precision; an item
        // formed finer would not round-trip byte-equal.
        inputs.produced_at =
            chrono::DateTime::from_timestamp_micros(inputs.produced_at.timestamp_micros())
                .ok_or_else(|| CeremonyError::InvalidInputs("produced_at out of range".into()))?;
        if inputs.holders.is_empty() {
            return bad("a ceremony needs its accord holders".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        for h in &inputs.holders {
            if !ids.insert(h.record.key_id.as_str()) {
                return bad(format!("holder {} is listed twice", h.record.key_id));
            }
            CommittedKey::from_record(&h.record)
                .map_err(|e| CeremonyError::InvalidInputs(e.to_string()))?;
        }
        if inputs.serve_nodes.is_empty() {
            return bad("a ceremony seats at least one serve node".into());
        }
        if inputs.successor_keys.is_empty() {
            return bad("the charter commits to a non-empty successor set (CC 3.2 T3)".into());
        }
        let held: std::collections::BTreeSet<&str> =
            inputs.recovery_keys.keys().map(String::as_str).collect();
        if held != ids {
            return bad(format!(
                "every holder carries exactly one recovery key (CC 4.2.6): holders {ids:?}, \
                 recovery keys for {held:?}"
            ));
        }
        let mut recovery_ids = std::collections::BTreeSet::new();
        for (holder, key) in &inputs.recovery_keys {
            if ids.contains(key.key_id.as_str()) {
                return bad(format!(
                    "{holder}'s recovery key {} is a holder signing key; a recovery key is held \
                     apart",
                    key.key_id
                ));
            }
            if !recovery_ids.insert(key.key_id.as_str()) {
                return bad(format!(
                    "recovery key {} is shared by two holders",
                    key.key_id
                ));
            }
        }
        let state = Self {
            version: CEREMONY_STATE_VERSION,
            inputs,
            partials: BTreeMap::new(),
        };
        state.draft()?;
        Ok(state)
    }

    /// Parse a serialized state, refusing a version this build cannot read.
    ///
    /// # Errors
    ///
    /// [`CeremonyError::InvalidInputs`] on malformed JSON,
    /// [`CeremonyError::StateVersion`] on another version.
    pub fn from_json(json: &str) -> Result<Self, CeremonyError> {
        let state: Self = serde_json::from_str(json)
            .map_err(|e| CeremonyError::InvalidInputs(format!("ceremony state: {e}")))?;
        if state.version != CEREMONY_STATE_VERSION {
            return Err(CeremonyError::StateVersion(state.version));
        }
        Ok(state)
    }

    /// The state as JSON.
    ///
    /// # Errors
    ///
    /// Serialization failure.
    pub fn to_json(&self) -> Result<String, CeremonyError> {
        serde_json::to_string(self)
            .map_err(|e| CeremonyError::InvalidInputs(format!("ceremony state: {e}")))
    }

    fn holder_ids(&self) -> Vec<String> {
        self.inputs
            .holders
            .iter()
            .map(|h| h.record.key_id.clone())
            .collect()
    }

    fn charter_envelope(&self) -> Result<serde_json::Value, CeremonyError> {
        let i = &self.inputs;
        let commitment = pre_rotation_commitment(&i.successor_keys)
            .map_err(|e| CeremonyError::InvalidInputs(e.to_string()))?;
        let recovery: BTreeMap<String, String> = i
            .recovery_keys
            .iter()
            .map(|(h, k)| {
                recovery_commitment(k)
                    .map(|c| (h.clone(), c))
                    .map_err(|e| CeremonyError::InvalidInputs(e.to_string()))
            })
            .collect::<Result<_, _>>()?;
        let successors: Vec<&str> = i.successor_keys.iter().map(|k| k.key_id.as_str()).collect();
        Ok(serde_json::json!({
            "dimension": TRUST_CHARTER_DIMENSION,
            "references_attestation_id": GENESIS_CHARTER_ID,
            "pre_rotation_commitment": commitment,
            "scope": i.scope,
            "successor_key_ids": successors,
            crate::federation::envelope::paths::WITNESS_QUORUM: 0,
            crate::federation::envelope::paths::RECOVERY_COMMITMENTS: recovery,
        }))
    }

    /// One unsigned delegation row, its signed instants stamped from `at` and
    /// its typed-column mirror bound, primary = the first holder.
    fn row(
        &self,
        id: &str,
        attested: &str,
        kind: &str,
        envelope: serde_json::Value,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Attestation, CeremonyError> {
        let primary = self.inputs.holders[0].record.key_id.clone();
        let mut row = Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: primary.clone(),
            attested_key_id: attested.to_owned(),
            attestation_type: kind.to_owned(),
            weight: Some(1.0),
            asserted_at: at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: primary,
            scrub_timestamp: at,
            pqc_completed_at: Some(at),
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: cohort_scope::FEDERATION.to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        crate::federation::envelope::stamp_signed_instants(&mut row)
            .map_err(|e| CeremonyError::InvalidInputs(format!("row {id}: stamp: {e}")))?;
        let mirror = crate::federation::envelope::RowMirror::of(&row)
            .map_err(|e| CeremonyError::InvalidInputs(format!("row {id}: mirror: {e}")))?;
        row.attestation_envelope[crate::federation::envelope::paths::ROW] =
            serde_json::to_value(&mirror)
                .map_err(|e| CeremonyError::InvalidInputs(format!("row {id}: mirror: {e}")))?;
        Ok(row)
    }

    /// `row` with the signatures the ceremony holds for it: the first holder in
    /// roster order is the primary scrub, the rest co-scrub. Only for a
    /// complete item.
    fn signed_row(&self, row: &Attestation) -> Result<Attestation, CeremonyError> {
        let id = format!("row:{}", row.attestation_id);
        let mut signed = self.signed(&id).into_iter();
        let p = signed
            .next()
            .ok_or_else(|| CeremonyError::Incomplete(self.owed_of(&id)))?;
        let mut row = row.clone();
        let bytes = canonical(&row.attestation_envelope, "row envelope")?;
        row.original_content_hash = sha256_hex(&bytes);
        row.scrub_signature_classical = p.signature_classical.clone();
        row.scrub_signature_pqc = Some(p.signature_pqc.clone());
        row.scrub_key_id = p.holder_key_id.clone();
        row.additional_scrubs = signed.map(scrub_sig).collect();
        Ok(row)
    }

    fn owed_of(&self, item: &str) -> BTreeMap<String, Vec<String>> {
        let slot = self.partials.get(item);
        let owed: Vec<String> = self
            .holder_ids()
            .into_iter()
            .filter(|h| slot.is_none_or(|s| !s.contains_key(h)))
            .collect();
        BTreeMap::from([(item.to_owned(), owed)])
    }

    fn complete(&self, item: &str) -> bool {
        self.owed_of(item).values().all(Vec::is_empty)
    }

    fn draft(&self) -> Result<Draft, CeremonyError> {
        let i = &self.inputs;
        let at = i.produced_at;
        let primary = i.holders[0].record.key_id.clone();
        let mut items = Vec::new();
        let ready = |id: String, bytes: Vec<u8>| DraftItem {
            id,
            bytes: Some(bytes),
            waits_on: Vec::new(),
        };

        // Serve nodes: the subject bound into the envelope before the bytes
        // are formed (#659), the scrub over the full envelope.
        let mut node_records = Vec::new();
        for n in &i.serve_nodes {
            let mut envelope = n.registration_envelope.clone();
            crate::federation::admission::bind_subject_into_envelope(
                &mut envelope,
                &n.key_id,
                &n.identity_type,
                &n.pubkey_ed25519_base64,
                Some(&n.pubkey_ml_dsa_65_base64),
                None,
            )
            .map_err(|e| CeremonyError::InvalidInputs(format!("serve node {}: {e}", n.key_id)))?;
            let bytes = canonical(&envelope, "serve node envelope")?;
            node_records.push(KeyRecord {
                key_id: n.key_id.clone(),
                pubkey_ed25519_base64: n.pubkey_ed25519_base64.clone(),
                pubkey_ml_dsa_65_base64: Some(n.pubkey_ml_dsa_65_base64.clone()),
                algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
                identity_type: n.identity_type.clone(),
                identity_ref: n.key_id.clone(),
                valid_from: at,
                valid_until: None,
                registration_envelope: envelope,
                original_content_hash: sha256_hex(&bytes),
                scrub_signature_classical: String::new(),
                scrub_signature_pqc: None,
                scrub_key_id: primary.clone(),
                scrub_timestamp: at,
                pqc_completed_at: Some(at),
                persist_row_hash: String::new(),
                capability_roles: n.capability_roles.clone(),
                attestation_evidence: n.attestation_evidence.clone(),
                consent_role: None,
                additional_scrubs: Vec::new(),
            });
            items.push(ready(format!("record:{}", n.key_id), bytes));
        }

        // The delegation plane, 1 ms apart in bundle order.
        let ms = |n: i64| at + chrono::Duration::milliseconds(n);
        let mut rows = vec![self.row(
            GENESIS_CHARTER_ID,
            &i.family_key_id,
            attestation_type::DELEGATES_TO,
            self.charter_envelope()?,
            ms(0),
        )?];
        for (k, n) in i.serve_nodes.iter().enumerate() {
            let id = genesis_grant_id(&n.key_id);
            let offset = i64::try_from(k + 1)
                .map_err(|_| CeremonyError::InvalidInputs("too many serve nodes".into()))?;
            rows.push(self.row(
                &id,
                &n.key_id,
                attestation_type::DELEGATES_TO,
                serde_json::json!({
                    "dimension": TRUST_CONFERS_DIMENSION,
                    "references_attestation_id": id,
                    "scope": i.scope,
                }),
                ms(offset),
            )?);
        }
        let offset = i64::try_from(i.serve_nodes.len() + 1)
            .map_err(|_| CeremonyError::InvalidInputs("too many serve nodes".into()))?;
        rows.push(self.row(
            GENESIS_LIFECYCLE_ID,
            &i.family_key_id,
            attestation_type::SCORES,
            serde_json::json!({
                "references_attestation_id": GENESIS_LIFECYCLE_ID,
                "dimension": "accord:lifecycle:v1",
            }),
            ms(offset),
        )?);
        for r in &rows {
            items.push(ready(
                format!("row:{}", r.attestation_id),
                canonical(&r.attestation_envelope, "row envelope")?,
            ));
        }

        // The genesis heads (CC 3.2 T6): the accord family record and the
        // community birth, each its own signed record at its first version,
        // naming the charter in force by its stored row hash. That hash covers
        // the charter's scrubs, so the heads — and the authorization, which
        // binds them — wait until every holder has signed the charter.
        let family_id = format!("family:{}", i.family_key_id);
        let community_id = format!("community:{}", i.community.community_key_id);
        let charter_item = format!("row:{GENESIS_CHARTER_ID}");
        let heads = if self.complete(&charter_item) {
            let charter = self.signed_row(&rows[0])?;
            let charter_digest = crate::federation::canonical_community::stored_row_hash(&charter)
                .map_err(|e| CeremonyError::InvalidInputs(format!("charter digest: {e}")))?;
            let family = super::accord_family_genesis_record_for(
                &i.family_key_id,
                &i.consensus_protocol,
                i.holders.iter().map(|h| h.record.key_id.as_str()),
                &charter_digest,
            );
            let mut members: Vec<CommunityMember> = i
                .holders
                .iter()
                .map(|h| CommunityMember {
                    key_id: h.record.key_id.clone(),
                    joined_at: at,
                    role: Some("founder".to_owned()),
                })
                .collect();
            members.extend(i.serve_nodes.iter().map(|n| CommunityMember {
                key_id: n.key_id.clone(),
                joined_at: at,
                role: Some("member".to_owned()),
            }));
            let community = Community {
                prev_head_digest: String::new(),
                charter_digest,
                community_key_id: i.community.community_key_id.clone(),
                community_name: i.community.community_name.clone(),
                members,
                founded_at: at,
                consensus_protocol: i.community.consensus_protocol.clone(),
                policy_blob: Some(i.community.policy_blob.clone()),
                persist_row_hash: String::new(),
            };
            items.push(ready(
                family_id,
                canonical(&family.signing_envelope(), "family record")?,
            ));
            items.push(ready(
                community_id,
                canonical(&community.signing_envelope(), "community record")?,
            ));
            // Last: the holders' authorization over the whole bundle. The
            // digest binds content, not the scrubs the other items accumulate.
            let unsigned = self.bundle_from(&node_records, &rows, &family, &community, Vec::new());
            let digest = authorization_digest(&unsigned)
                .map_err(|e| CeremonyError::InvalidInputs(format!("authorization digest: {e}")))?;
            items.push(ready(AUTHZ_ITEM_ID.to_owned(), digest));
            Some((family, community))
        } else {
            for id in [family_id, community_id, AUTHZ_ITEM_ID.to_owned()] {
                items.push(DraftItem {
                    id,
                    bytes: None,
                    waits_on: vec![charter_item.clone()],
                });
            }
            None
        };

        Ok(Draft {
            node_records,
            rows,
            heads,
            items,
        })
    }

    fn bundle_from(
        &self,
        nodes: &[KeyRecord],
        rows: &[Attestation],
        family: &crate::federation::types::Family,
        community: &Community,
        authorizations: Vec<GenesisAuthorization>,
    ) -> GenesisBundle {
        let primary = self.inputs.holders[0].record.key_id.clone();
        GenesisBundle {
            version: GENESIS_BUNDLE_VERSION,
            family_key_id: self.inputs.family_key_id.clone(),
            holders: self.inputs.holders.clone(),
            serve_nodes: nodes
                .iter()
                .map(|r| SignedKeyRecord { record: r.clone() })
                .collect(),
            consensus_protocol: self.inputs.consensus_protocol.clone(),
            attestations: rows
                .iter()
                .map(|r| SignedAttestation {
                    attestation: r.clone(),
                })
                .collect(),
            roster_records: vec![
                GenesisRosterRecord::Family(SignedFamily {
                    family: family.clone(),
                    authority_key_id: primary.clone(),
                    scrub_signature_classical: String::new(),
                    scrub_signature_pqc: None,
                    supersede_proof: None,
                    cosignatures: Vec::new(),
                }),
                GenesisRosterRecord::Community(SignedCommunity {
                    community: community.clone(),
                    authority_key_id: primary,
                    scrub_signature_classical: String::new(),
                    scrub_signature_pqc: None,
                    supersede_proof: None,
                    cosignatures: Vec::new(),
                    lineage: Vec::new(),
                }),
            ],
            authorizations,
            produced_at: self.inputs.produced_at.to_rfc3339(),
        }
    }

    /// Every item in item order, complete ones included (their `owed` is
    /// empty). An item that waits on another (the heads and the
    /// authorization wait on the charter) has empty `bytes` and names what it
    /// waits on.
    ///
    /// # Errors
    ///
    /// The inputs no longer form a ceremony (a state edited by hand).
    pub fn items(&self) -> Result<Vec<SignItem>, CeremonyError> {
        Ok(self
            .draft()?
            .items
            .into_iter()
            .map(|d| {
                let owed = self.owed_of(&d.id).into_values().next().unwrap_or_default();
                SignItem {
                    id: d.id,
                    bytes: d.bytes.unwrap_or_default(),
                    owed,
                    waits_on: d.waits_on,
                }
            })
            .collect())
    }

    /// The items a holder can sign now: owed, and waiting on nothing.
    ///
    /// # Errors
    ///
    /// As [`Self::items`].
    pub fn next_items(&self) -> Result<Vec<SignItem>, CeremonyError> {
        Ok(self
            .items()?
            .into_iter()
            .filter(|i| !i.owed.is_empty() && i.waits_on.is_empty())
            .collect())
    }

    /// Item id → the holders still owed, for every item not yet complete
    /// (waiting ones included).
    ///
    /// # Errors
    ///
    /// As [`Self::items`].
    pub fn status(&self) -> Result<BTreeMap<String, Vec<String>>, CeremonyError> {
        Ok(self
            .items()?
            .into_iter()
            .filter(|i| !i.owed.is_empty())
            .map(|i| (i.id, i.owed))
            .collect())
    }

    /// **Take one holder's signature over one item**, verified now against the
    /// holder's carried keys. Re-sending the same partial is a no-op.
    ///
    /// # Errors
    ///
    /// [`CeremonyError::UnknownItem`], [`CeremonyError::NotReady`],
    /// [`CeremonyError::NotAHolder`], [`CeremonyError::BadSignature`] (either
    /// half), [`CeremonyError::ConflictingPartial`].
    pub fn add_partial(&mut self, partial: Partial) -> Result<(), CeremonyError> {
        let draft = self.draft()?;
        let Some(item) = draft.items.iter().find(|d| d.id == partial.item) else {
            return Err(CeremonyError::UnknownItem(partial.item));
        };
        let Some(bytes) = item.bytes.as_deref() else {
            return Err(CeremonyError::NotReady {
                item: partial.item,
                waits_on: item.waits_on.clone(),
            });
        };
        let Some(holder) = self
            .inputs
            .holders
            .iter()
            .find(|h| h.record.key_id == partial.holder_key_id)
        else {
            return Err(CeremonyError::NotAHolder(partial.holder_key_id));
        };
        crate::verify::hybrid::verify_hybrid(
            bytes,
            &partial.signature_classical,
            Some(&partial.signature_pqc),
            &holder.record.pubkey_ed25519_base64,
            holder.record.pubkey_ml_dsa_65_base64.as_deref(),
            crate::verify::hybrid::HybridPolicy::Strict,
            None,
        )
        .map_err(|e| CeremonyError::BadSignature {
            item: partial.item.clone(),
            holder: partial.holder_key_id.clone(),
            detail: e.to_string(),
        })?;
        let slot = self.partials.entry(partial.item.clone()).or_default();
        match slot.get(&partial.holder_key_id) {
            Some(held) if *held == partial => Ok(()),
            Some(_) => Err(CeremonyError::ConflictingPartial {
                item: partial.item,
                holder: partial.holder_key_id,
            }),
            None => {
                slot.insert(partial.holder_key_id.clone(), partial);
                Ok(())
            }
        }
    }

    /// The partials of `item` in holder order: the primary first.
    fn signed(&self, item: &str) -> Vec<&Partial> {
        let slot = self.partials.get(item);
        self.inputs
            .holders
            .iter()
            .filter_map(|h| slot.and_then(|s| s.get(&h.record.key_id)))
            .collect()
    }

    /// **Assemble the bundle** from a complete ceremony. Pure: no directory,
    /// no clock. [`Self::finish`] is this plus the doors.
    ///
    /// # Errors
    ///
    /// [`CeremonyError::Incomplete`] naming every item still owed.
    pub fn assemble(&self) -> Result<GenesisBundle, CeremonyError> {
        let owed = self.status()?;
        if !owed.is_empty() {
            return Err(CeremonyError::Incomplete(owed));
        }
        let draft = self.draft()?;
        let (family, community) = draft
            .heads
            .as_ref()
            .ok_or_else(|| CeremonyError::Incomplete(self.owed_of(AUTHZ_ITEM_ID)))?;
        let primary_of = |item: &str| -> Result<Partial, CeremonyError> {
            self.signed(item)
                .first()
                .map(|p| (*p).clone())
                .ok_or_else(|| CeremonyError::Incomplete(self.owed_of(item)))
        };
        let cosigs = |item: &str| -> Vec<RosterCosignature> {
            self.signed(item)
                .iter()
                .skip(1)
                .map(|p| RosterCosignature {
                    authority_key_id: p.holder_key_id.clone(),
                    scrub_signature_classical: p.signature_classical.clone(),
                    scrub_signature_pqc: Some(p.signature_pqc.clone()),
                })
                .collect()
        };

        let nodes: Vec<KeyRecord> = draft
            .node_records
            .iter()
            .map(|r| {
                let id = format!("record:{}", r.key_id);
                let p = primary_of(&id)?;
                let mut r = r.clone();
                r.scrub_signature_classical = p.signature_classical;
                r.scrub_signature_pqc = Some(p.signature_pqc);
                r.scrub_key_id = p.holder_key_id;
                r.additional_scrubs = self
                    .signed(&id)
                    .into_iter()
                    .skip(1)
                    .map(scrub_sig)
                    .collect();
                Ok(r)
            })
            .collect::<Result<_, CeremonyError>>()?;
        let rows: Vec<Attestation> = draft
            .rows
            .iter()
            .map(|row| self.signed_row(row))
            .collect::<Result<_, _>>()?;
        let authorizations = self
            .signed(AUTHZ_ITEM_ID)
            .iter()
            .map(|p| GenesisAuthorization {
                holder_key_id: p.holder_key_id.clone(),
                signature_classical: p.signature_classical.clone(),
                signature_pqc: p.signature_pqc.clone(),
            })
            .collect();
        let mut bundle = self.bundle_from(&nodes, &rows, family, community, authorizations);
        for record in &mut bundle.roster_records {
            match record {
                GenesisRosterRecord::Family(f) => {
                    let id = format!("family:{}", f.family.family_key_id);
                    let p = primary_of(&id)?;
                    f.authority_key_id = p.holder_key_id;
                    f.scrub_signature_classical = p.signature_classical;
                    f.scrub_signature_pqc = Some(p.signature_pqc);
                    f.cosignatures = cosigs(&id);
                }
                GenesisRosterRecord::Community(c) => {
                    let id = format!("community:{}", c.community.community_key_id);
                    let p = primary_of(&id)?;
                    c.authority_key_id = p.holder_key_id;
                    c.scrub_signature_classical = p.signature_classical;
                    c.scrub_signature_pqc = Some(p.signature_pqc);
                    c.cosignatures = cosigs(&id);
                }
            }
        }
        Ok(bundle)
    }

    /// **Finish the ceremony**: [`Self::assemble`], then
    /// [`verify_ceremony_outputs`](super::verify_ceremony_outputs) — the
    /// ordinary doors a booting node runs, against this build's accord roster.
    ///
    /// # Errors
    ///
    /// [`CeremonyError::Incomplete`], or [`CeremonyError::Outputs`] naming the
    /// stage that refused.
    pub async fn finish(&self) -> Result<CeremonyFinished, CeremonyError> {
        let bundle = self.assemble()?;
        let bundle_json = serde_json::to_string_pretty(&bundle)
            .map_err(|e| CeremonyError::InvalidInputs(format!("serialize bundle: {e}")))?;
        let verified = super::verify_ceremony_outputs(&bundle_json)
            .await
            .map_err(CeremonyError::Outputs)?;
        Ok(CeremonyFinished {
            bundle,
            bundle_json,
            verified,
        })
    }
}
