//! v57.0.0 (CIRISPersist#988 item 3; CC 3.4.8, CLM-detection-on-base) — a
//! detection is a `detection:{detector}:v1` row on the attestation plane, and
//! `detection_events` is that row's projection.
//!
//! # The row
//!
//! A `scores` row whose envelope carries the detection whole under the
//! [`BODY_MEMBER`] member: every `detection_events` column, the bytes in
//! base64 ([`DetectionProjection`]). The attester is the detector's key
//! (`signing_key_id`), and the `detection:` prefix is the detector-only
//! reserved family (CC 3.4.8: `lenscore_detector`), so the dimension gate
//! refuses any other emitter.
//!
//! One door writes one (v62.0.0, P8-fix11: the earlier-form
//! `put_detection_event` / `put_detection_planned`, which refused at their
//! first line once the earlier form was shut, are deleted): the detector's
//! own edition-2 `detection:{detector}` statement, through the statement door
//! ([`state_detection`]; a remote pen drafts with [`draft_detection`] and
//! submits the assembled statement). It replicates like any other row; the
//! plan checks its body ([`check_detection_body`]) and the executor projects
//! it.
//!
//! # The Art. 17 tombstone (V080)
//!
//! A signed row is immutable bytes. Its erasure goes through the purge door
//! (`steward_purge`), the one tombstone mechanism: the row carries its trace
//! as `evidence_refs`, so a purge of the trace derives it; while the purge
//! tombstone stands the projection is the V080 tombstone
//! ([`project_detection_row_under`]), and when `purge_finalize` deletes the
//! row its projection row goes with it.
//!
//! `calibration_bundles` stays configuration (CC 3.4.8: "calibration bundles
//! stay configuration, never claims").

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::types::{ConformityVariant, DetectionEvent, DetectionSeverity};
use crate::federation::types::Attestation;

/// The family stem of every detection row (CC 3.4.8).
pub const DIMENSION_PREFIX: &str = "detection:";

/// The envelope member that carries the detection on a detection row.
pub const BODY_MEMBER: &str = "detection";

/// Ed25519 signature length (V008 CHECK).
const ED25519_SIG_LEN: usize = 64;
/// FIPS 204 final ML-DSA-65 signature length (V008 CHECK).
const ML_DSA_65_SIG_LEN: usize = 3309;
/// SHA-256 length (V008 CHECK).
const BODY_SHA256_LEN: usize = 32;
/// V008's `canonical_bytes` bound.
const CANONICAL_BYTES_MAX: usize = 1024 * 1024;

/// `detection:{detector}:v1` — the dimension a detection is written under.
#[must_use]
pub fn detection_dimension(detector: &str) -> String {
    format!("{DIMENSION_PREFIX}{detector}:v1")
}

/// The row id of a detection: a UUID derived from its `detection_id`, so a
/// re-put of the same detection names the same row (V008's idempotence on
/// `detection_id`, kept by the row).
#[must_use]
pub fn detection_attestation_id(detection_id: &uuid::Uuid) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(b"ciris:detection:v1:");
    h.update(detection_id.as_bytes());
    let digest = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    uuid::Uuid::from_bytes(b).to_string()
}

/// Base64 for an optional byte field (`null` when absent).
mod opt_b64 {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        bytes.as_ref().map(|b| B64.encode(b)).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| B64.decode(s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// One `detection_events` row, and the body of the detection row it is the
/// projection of. The V080 tombstone is the same shape with the three
/// linkage columns `None` and `erased_at` set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionProjection {
    /// Detection identifier.
    pub detection_id: uuid::Uuid,
    /// Trace this detection fired against; `None` once erased.
    pub trace_id: Option<String>,
    /// SHA-256 of the original wire body; `None` once erased.
    #[serde(with = "opt_b64")]
    pub body_sha256: Option<Vec<u8>>,
    /// Detector token.
    pub detector: String,
    /// Triage bucket.
    pub severity: DetectionSeverity,
    /// 6-tuple cohort cell.
    pub cohort_cell: serde_json::Value,
    /// Manifold-conformity variant.
    pub conformity_variant: ConformityVariant,
    /// Variant-specific payload.
    pub conformity_payload: serde_json::Value,
    /// Lens-core version (LC-AV-19).
    pub lens_core_version: String,
    /// Calibration version current at score time.
    pub ratchet_calibration_version: i32,
    /// The bytes the detector signed; `None` once erased.
    #[serde(with = "opt_b64")]
    pub canonical_bytes: Option<Vec<u8>>,
    /// Ed25519 signature over `canonical_bytes`. v62.0.0 (v62 P8): absent
    /// from an edition-2 row's body, whose statement signature is the
    /// detector's (its Ed25519 half fills this column on projection).
    #[serde(with = "crate::federation::serde_bytes_b64", default)]
    pub ed25519_sig: Vec<u8>,
    /// ML-DSA-65 signature over `canonical_bytes`. v62.0.0 (v62 P8): as
    /// `ed25519_sig`, the statement signature's ML-DSA-65 half.
    #[serde(with = "crate::federation::serde_bytes_b64", default)]
    pub ml_dsa_65_sig: Vec<u8>,
    /// The detector's key (the row's attester).
    pub signing_key_id: String,
    /// The detection's instant.
    pub ts: DateTime<Utc>,
    /// The Art. 17 tombstone instant (V080), `None` while live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erased_at: Option<DateTime<Utc>>,
}

impl From<&DetectionEvent> for DetectionProjection {
    fn from(e: &DetectionEvent) -> Self {
        Self {
            detection_id: e.detection_id,
            trace_id: Some(e.trace_id.clone()),
            body_sha256: Some(e.body_sha256.clone()),
            detector: e.detector.clone(),
            severity: e.severity,
            cohort_cell: e.cohort_cell.clone(),
            conformity_variant: e.conformity_variant,
            conformity_payload: e.conformity_payload.clone(),
            lens_core_version: e.lens_core_version.clone(),
            ratchet_calibration_version: e.ratchet_calibration_version,
            canonical_bytes: Some(e.canonical_bytes.clone()),
            ed25519_sig: e.ed25519_sig.clone(),
            ml_dsa_65_sig: e.ml_dsa_65_sig.clone(),
            signing_key_id: e.signing_key_id.clone(),
            ts: e.ts,
            erased_at: None,
        }
    }
}

impl DetectionProjection {
    /// The live [`DetectionEvent`], or `None` for a tombstone (V080: an erased
    /// detection is not a `DetectionEvent`, and the read does not return it).
    #[must_use]
    pub fn to_event(&self) -> Option<DetectionEvent> {
        if self.erased_at.is_some() {
            return None;
        }
        Some(DetectionEvent {
            detection_id: self.detection_id,
            trace_id: self.trace_id.clone()?,
            body_sha256: self.body_sha256.clone()?,
            detector: self.detector.clone(),
            severity: self.severity,
            cohort_cell: self.cohort_cell.clone(),
            conformity_variant: self.conformity_variant,
            conformity_payload: self.conformity_payload.clone(),
            lens_core_version: self.lens_core_version.clone(),
            ratchet_calibration_version: self.ratchet_calibration_version,
            canonical_bytes: self.canonical_bytes.clone()?,
            ed25519_sig: self.ed25519_sig.clone(),
            ml_dsa_65_sig: self.ml_dsa_65_sig.clone(),
            signing_key_id: self.signing_key_id.clone(),
            ts: self.ts,
        })
    }

    /// The V080 tombstone of this detection.
    #[must_use]
    pub fn tombstoned(&self, erased_at: DateTime<Utc>) -> Self {
        Self {
            trace_id: None,
            body_sha256: None,
            canonical_bytes: None,
            erased_at: Some(erased_at),
            ..self.clone()
        }
    }
}

/// The signed envelope of a detection row: `{dimension, detection: <body>}`.
pub fn detection_envelope(
    body: &DetectionProjection,
) -> Result<serde_json::Value, serde_json::Error> {
    let mut envelope = serde_json::json!({
        "dimension": detection_dimension(&body.detector),
        BODY_MEMBER: serde_json::to_value(body)?,
    });
    // The trace a detection scored is its EVIDENCE: a purge of the trace
    // derives the detection row (the purge door's "scores over purged
    // evidence follow it"), so the Art. 17 path needs no second mechanism.
    if let Some(trace_id) = &body.trace_id {
        envelope["evidence_refs"] = serde_json::json!([trace_id]);
    }
    Ok(envelope)
}

/// The shape V008's CHECKs hold a detection to, as the refusal message, or
/// `None` when it fits. A live body carries all three linkage columns; a
/// tombstone carries none and an `erased_at`.
#[must_use]
pub fn detection_shape_refusal(body: &DetectionProjection) -> Option<String> {
    if body.ed25519_sig.len() != ED25519_SIG_LEN {
        return Some(format!(
            "ed25519_sig must be {ED25519_SIG_LEN} bytes (got {})",
            body.ed25519_sig.len()
        ));
    }
    if body.ml_dsa_65_sig.len() != ML_DSA_65_SIG_LEN {
        return Some(format!(
            "ml_dsa_65_sig must be {ML_DSA_65_SIG_LEN} bytes (got {})",
            body.ml_dsa_65_sig.len()
        ));
    }
    if let Some(b) = &body.body_sha256 {
        if b.len() != BODY_SHA256_LEN {
            return Some(format!(
                "body_sha256 must be {BODY_SHA256_LEN} bytes (got {})",
                b.len()
            ));
        }
    }
    if let Some(c) = &body.canonical_bytes {
        if c.is_empty() || c.len() > CANONICAL_BYTES_MAX {
            return Some(format!(
                "canonical_bytes must be 1..={CANONICAL_BYTES_MAX} bytes (got {})",
                c.len()
            ));
        }
    }
    let linkage = [
        body.trace_id.is_some(),
        body.body_sha256.is_some(),
        body.canonical_bytes.is_some(),
    ];
    match body.erased_at {
        None if linkage.iter().all(|x| *x) => None,
        Some(_) if linkage.iter().all(|x| !*x) => None,
        None => Some("a live detection carries trace_id, body_sha256 and canonical_bytes".into()),
        Some(_) => {
            Some("an erased detection carries no trace_id, body_sha256 or canonical_bytes".into())
        }
    }
}

/// The detection body a row carries, when its dimension is a detection's and
/// the member parses. No shape judgement (see [`check_detection_body`]).
fn detection_body(row: &Attestation) -> Option<DetectionProjection> {
    let dimension = row.attestation_envelope.get("dimension")?.as_str()?;
    if !dimension.starts_with(DIMENSION_PREFIX) {
        return None;
    }
    let body = row.attestation_envelope.get(BODY_MEMBER)?;
    serde_json::from_value(body.clone()).ok()
}

/// v57.0.0 (CIRISPersist#988 item 3; CLM-silo-projection-rebuildable) —
/// **the projection, rows → `detection_events`.** The one function the
/// write step (in the row's transaction) and the from-rows rebuild call.
/// `Some` for a `scores` row of any tier that is the detection's own row:
/// its id is the one derived from the body's `detection_id`
/// ([`detection_attestation_id`]), its dimension is the detection's
/// (`detection:{detector}:v1`), its body is the detector's (`signing_key_id`
/// = the attester) and fits V008's shape.
///
/// The id rule is what keeps `detection_id` the table's key: one detection,
/// one row. The row the door writes carries that id from birth, and keeps it
/// when the detector signs it across to the federation tier and a peer
/// replicates it. A `detection:*` row under any other id (a `supersedes`
/// widening, a claim the detector emitted under a fresh id) is a claim on the
/// plane but not the detection's row, and does not project.
///
/// v62.0.0 (v62 P8) — an edition-2 row (it carries its statement) is the
/// detection's own row under its node-computed row id, and its two
/// signature columns are its statement's composite signature halves
/// ([`statement_signature_halves`]): the detector signed the row itself.
#[must_use]
pub fn project_detection_row(row: &Attestation) -> Option<DetectionProjection> {
    if row.attestation_type != crate::federation::types::attestation_type::SCORES {
        return None;
    }
    let mut body = detection_body(row)?;
    let edition2 = statement_signature_halves(row);
    let own_row = match &edition2 {
        Some((ml_dsa, ed25519)) => {
            body.ml_dsa_65_sig = ml_dsa.clone();
            body.ed25519_sig = ed25519.clone();
            true
        }
        None => row.attestation_id == detection_attestation_id(&body.detection_id),
    };
    let dimension = row.attestation_envelope.get("dimension")?.as_str()?;
    (own_row
        && dimension == detection_dimension(&body.detector)
        && body.signing_key_id == row.attesting_key_id
        && detection_shape_refusal(&body).is_none())
    .then_some(body)
}

/// v57.0.0 (CIRISPersist#988 item 3) — the put door's body gate: a
/// `detection:*` row that carries a `detection` member must be one the
/// projection reads ([`project_detection_row`]), and a federation-tier offer
/// is never a tombstone. A row with no such member is not a projected
/// detection and passes (it is a plain `detection:*` claim). Pure.
pub fn check_detection_body(row: &Attestation) -> Result<(), crate::federation::Error> {
    let Some(dimension) = row
        .attestation_envelope
        .get("dimension")
        .and_then(|d| d.as_str())
    else {
        return Ok(());
    };
    if !dimension.starts_with(DIMENSION_PREFIX)
        || row.attestation_envelope.get(BODY_MEMBER).is_none()
    {
        return Ok(());
    }
    let refuse = |reason: String| {
        crate::federation::Error::InvalidArgument(format!(
        "{dimension}: the `{BODY_MEMBER}` member is not a detection this node can project: {reason}"
    ))
    };
    let mut body = detection_body(row).ok_or_else(|| refuse("it does not parse".into()))?;
    // Only the detection's own row (its derived id) is projected; a body
    // under another id is a claim this node holds without projecting it.
    // v62.0.0 (v62 P8) — an edition-2 row is its own row under its computed
    // id, its signatures the statement's.
    match statement_signature_halves(row) {
        Some((ml_dsa, ed25519)) => {
            body.ml_dsa_65_sig = ml_dsa;
            body.ed25519_sig = ed25519;
        }
        None if row.attestation_id != detection_attestation_id(&body.detection_id) => {
            return Ok(());
        }
        None => {}
    }
    if dimension != detection_dimension(&body.detector) {
        return Err(refuse(format!(
            "its detector `{}` is not the dimension's",
            body.detector
        )));
    }
    if body.signing_key_id != row.attesting_key_id {
        return Err(refuse(format!(
            "its signing_key_id {} is not the attester {}",
            body.signing_key_id, row.attesting_key_id
        )));
    }
    if body.erased_at.is_some() {
        return Err(refuse("an erased detection is not offered".into()));
    }
    if let Some(reason) = detection_shape_refusal(&body) {
        return Err(refuse(reason));
    }
    Ok(())
}

/// v62.0.0 (v62 P8) — the halves of the composite signature an edition-2
/// row's carried statement (`ceg_statement`) bears: `(ML-DSA-65 3309 bytes,
/// Ed25519 64 bytes)`. `None` for an earlier-form row, or a statement that
/// does not decode.
#[must_use]
pub fn statement_signature_halves(row: &Attestation) -> Option<(Vec<u8>, Vec<u8>)> {
    use ciris_verify_core::cde::{self, Value};
    let hexed = row
        .attestation_envelope
        .get(crate::federation::edition2::ingest::STATEMENT_MEMBER)?
        .as_str()?;
    let bytes = hex::decode(hexed).ok()?;
    let Value::Tag(18, inner) = cde::decode(&bytes).ok()? else {
        return None;
    };
    let sig = inner.as_array()?.get(3)?.as_bytes()?;
    (sig.len() == ML_DSA_65_SIG_LEN + ED25519_SIG_LEN).then(|| {
        (
            sig[..ML_DSA_65_SIG_LEN].to_vec(),
            sig[ML_DSA_65_SIG_LEN..].to_vec(),
        )
    })
}

/// v62.0.0 (v62 P8; CC ruling on body reals) — **a detection body as CBOR**:
/// every number through P1's shared `edition2::payloads::body_number` (an
/// integral value a plain integer, a non-integral one a normalised CBOR tag-4
/// decimal fraction, `0.25` → `4([-2, 25])`; never a float, never text),
/// maps in deterministic order (CC 2.6.1.3). Fixed-scale MEMBERS (`score`,
/// `confidence`, `weight` at the payload's top level) are not a body's and
/// stay fixed6 elsewhere.
///
/// # Errors
/// `body_number_unrepresentable`.
pub fn body_cbor(
    v: &serde_json::Value,
) -> Result<ciris_verify_core::cde::Value, crate::federation::Error> {
    use ciris_verify_core::cde::Value;
    use serde_json::Value as J;
    Ok(match v {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => crate::federation::edition2::payloads::body_number(n)?,
        J::String(t) => Value::Text(t.clone()),
        J::Array(a) => Value::Array(a.iter().map(body_cbor).collect::<Result<_, _>>()?),
        J::Object(o) => {
            let mut m = o
                .iter()
                .map(|(k, v)| Ok((Value::Text(k.clone()), body_cbor(v)?)))
                .collect::<Result<Vec<_>, crate::federation::Error>>()?;
            m.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(k));
            Value::Map(m)
        }
    })
}

/// v62.0.0 (v62 P8) — **the digest a detection's `evidence_refs` names its
/// trace by** on the clean mesh: SHA-256 over `ciris:trace:v1:` ‖ the trace
/// id, lowercase hex. An edition-2 `evidence_refs` member is a sequence of
/// `[-16, bstr .size 32]` digests (CC 2.6.1.5), and a trace id is not one;
/// the purge resolver keys a selected trace by this digest too
/// (`steward_purge`), so a purge of the trace still reaches its detection
/// row (the Art. 17 route this module's doc names).
#[must_use]
pub fn trace_evidence_ref(trace_id: &str) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(b"ciris:trace:v1:");
    h.update(trace_id.as_bytes());
    hex::encode(h.finalize())
}

/// v62.0.0 (v62 P8; CC 3.4.8) — **a detection's `detection:{detector}`
/// statement parts**: `(sub, family, payload)`. `subject` is the scored
/// agent's canonical subject, stated as `subject_key_ids` (named, not
/// empowered; the DSAR erasure's by-subject reach). `sub` is the detector
/// (`signing_key_id`, an identity-ref); the payload is `{asserted_at: ts,
/// dimension: detection:{detector}:v1, detection: <body>}` with `author`
/// when the family is authored. The body is the [`DetectionProjection`]
/// WITHOUT its two signature members (the statement's composite signature
/// is the detector's), every number as [`body_cbor`] states it (CC ruling:
/// tag-4 decimal fractions for non-integral body reals). The row id is node-computed; the
/// earlier [`detection_attestation_id`] is not used.
///
/// # Errors
/// `edition2_payload_invalid` for a detector with no registered family, an
/// instant before the epoch, or a body that does not encode; the V008
/// shape (`detection_shape_refusal`, the signatures aside).
pub fn detection_statement_parts(
    event: &DetectionEvent,
    subject: Option<&str>,
) -> Result<(String, String, ciris_verify_core::cde::Value), crate::federation::Error> {
    use ciris_verify_core::cde::Value;
    let invalid = |m: String| {
        crate::federation::Error::InvalidArgument(format!("edition2_payload_invalid: {m}"))
    };
    let mut shape = DetectionProjection::from(event);
    // The statement signs the row; the earlier signature columns are not
    // payload members, so the shape is asked of the rest.
    shape.ed25519_sig = vec![0; ED25519_SIG_LEN];
    shape.ml_dsa_65_sig = vec![0; ML_DSA_65_SIG_LEN];
    if let Some(reason) = detection_shape_refusal(&shape) {
        return Err(crate::federation::Error::InvalidArgument(reason));
    }
    let dimension = detection_dimension(&event.detector);
    let family = crate::federation::edition2::emit::family_of_dimension(&dimension)
        .ok_or_else(|| invalid(format!("{dimension} resolves to no registered family")))?;
    let mut body = serde_json::to_value(DetectionProjection::from(event))
        .map_err(|e| invalid(format!("the detection body: {e}")))?;
    if let Some(o) = body.as_object_mut() {
        o.remove("ed25519_sig");
        o.remove("ml_dsa_65_sig");
        o.remove("erased_at");
    }

    let at = u64::try_from(event.ts.timestamp_millis())
        .map_err(|_| invalid("the detection's instant is before the epoch".into()))?;
    let text = |s: &str| Value::Text(s.to_owned());
    let mut m = vec![
        (text("asserted_at"), Value::Uint(at)),
        (text("dimension"), text(dimension.as_str())),
        (text(BODY_MEMBER), body_cbor(&body)?),
    ];
    // The trace is the detection's EVIDENCE: kept, as a digest, so a purge of
    // the trace derives the detection row (`trace_evidence_ref`).
    let trace_digest = hex::decode(trace_evidence_ref(&event.trace_id))
        .map_err(|e| invalid(format!("the trace digest: {e}")))?;
    m.push((
        text("evidence_refs"),
        Value::Array(vec![Value::Array(vec![
            Value::int(-16),
            Value::Bytes(trace_digest),
        ])]),
    ));
    // The scored agent's canonical subject (`subject_erasure::agent_subject`)
    // is NAMED, not empowered: a DSAR erasure by subject reaches the row
    // through it (`attestation_subjects`), even once its trace is gone.
    if let Some(subject) = subject {
        crate::federation::validate_subject_key_ids(&[subject.to_owned()])?;
        m.push((text("subject_key_ids"), Value::Array(vec![text(subject)])));
    }
    if crate::federation::edition2::emit::family_is_authored(&family, Some(dimension.as_str())) {
        m.push((text("author"), text(event.signing_key_id.as_str())));
    }
    m.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(k));
    Ok((event.signing_key_id.clone(), family, Value::Map(m)))
}

/// v62.0.0 (v62 P8) — **a detection drafted for its detector's pen** (an
/// external detector, LensCore): the detector signs `sig_structure` and
/// submits `Draft::assemble(signature)` through the statement door
/// (`Engine::put_edition2_statement`).
///
/// # Errors
/// As [`detection_statement_parts`]; a `signing_key_id` that is not an
/// identity-ref.
pub fn draft_detection(
    event: &DetectionEvent,
    subject: Option<&str>,
) -> Result<crate::federation::edition2::emit::Draft, crate::federation::Error> {
    let (sub, family, payload) = detection_statement_parts(event, subject)?;
    let kid = crate::federation::edition2::ingest::kid_of_identity_ref(&sub).ok_or_else(|| {
        crate::federation::Error::InvalidArgument(format!(
            "detection: the detector {sub} is not an identity-ref"
        ))
    })?;
    crate::federation::edition2::emit::draft_row(&kid, &sub, &sub, "scores", &family, &payload)
        .map_err(|e| crate::federation::edition2::emit::produce_error("detection", e))
}

/// v62.0.0 (v62 P8; CC 3.4.8, CC 4.4.3.34) — **state a detection on the
/// clean mesh**: [`detection_statement_parts`] signed by the detector's
/// composite key (`edition2::produce::sign_row`) and admitted through the
/// statement door (`put_statement`, federation tier). Its standing is the
/// conferral plane's (`infra:detect` by a delegation from a root this node
/// trusts, P4), never the key's type. A detection naming a trace a steward
/// purge tombstoned is refused first. Returns the node-computed row id.
///
/// # Errors
/// `InvalidArgument` for a signer that is not the event's detector;
/// `composite_signing_unavailable`; the purge refusal; the door's and the
/// gates' refusals (`ReservedPrefixEmitterMismatch` without the conferral).
pub(crate) async fn state_detection<D>(
    dir: &D,
    signer: &crate::signing::LocalSigner,
    event: &DetectionEvent,
) -> Result<String, crate::federation::Error>
where
    D: crate::federation::attestation_admit::AttestationStore,
{
    let iss = signer.federation_id().await;
    if iss != event.signing_key_id {
        return Err(crate::federation::Error::InvalidArgument(format!(
            "detection: the signer {iss} is not the detector {}",
            event.signing_key_id
        )));
    }
    crate::federation::steward_purge::refuse_if_tombstoned_trace(dir, &event.trace_id).await?;
    // The scored agent's subject, resolved from the trace as the earlier door
    // resolved it (`attestation_admit::detection_subject`).
    let subject =
        crate::federation::attestation_admit::detection_subject(dir, Some(&event.trace_id)).await?;
    let (sub, family, payload) = detection_statement_parts(event, subject.as_deref())?;
    let statement =
        crate::federation::edition2::produce::sign_row(signer, &sub, "scores", &family, &payload)
            .await
            .map_err(|e| crate::federation::edition2::emit::produce_error("detection", e))?;
    let outcome = crate::federation::edition2::ingest::put_statement(
        dir,
        &statement,
        None,
        crate::federation::edition2::ingest::INGEST_TIER,
    )
    .await?;
    use crate::federation::edition2::ingest::StatementOutcome as O;
    Ok(match outcome {
        O::Row { row_id, .. }
        | O::Voice { row_id, .. }
        | O::KeyPlane { row_id, .. }
        | O::Pending { row_id, .. } => row_id.hex(),
    })
}

/// v57.0.0 (CIRISPersist#988 item 3; lead ruling 5) — **the projection of a
/// row the purge door tombstoned.** A signed row is immutable bytes; its
/// erasure goes through the one tombstone mechanism, the purge door
/// (`steward_purge`): the door tombstones the row (it is no longer served,
/// and a replica's copy is refused) and later hard-deletes it at
/// `purge_finalize`. While the tombstone stands, the row's projection is the
/// V080 tombstone ([`DetectionProjection::tombstoned`]) at the instant the
/// earliest-admitted execution naming the row executed; once the row is gone
/// its projection row goes with it (`ON DELETE CASCADE`). `tombstoned_at` is
/// that instant, or `None` for a row no tombstone names.
#[must_use]
pub fn project_detection_row_under(
    row: &Attestation,
    tombstoned_at: Option<DateTime<Utc>>,
) -> Option<DetectionProjection> {
    let body = project_detection_row(row)?;
    Some(match tombstoned_at {
        Some(at) if body.erased_at.is_none() => body.tombstoned(at),
        _ => body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> DetectionEvent {
        DetectionEvent {
            detection_id: uuid::Uuid::new_v4(),
            trace_id: "t-1".into(),
            body_sha256: vec![7u8; 32],
            detector: "cohort_declared_inferred_mismatch".into(),
            severity: DetectionSeverity::Warning,
            cohort_cell: serde_json::json!({"agent_role": "x"}),
            conformity_variant: ConformityVariant::Numeric,
            conformity_payload: serde_json::json!({"score": 0.25}),
            lens_core_version: "1.0.0".into(),
            ratchet_calibration_version: 3,
            canonical_bytes: b"{\"a\":1}".to_vec(),
            ed25519_sig: vec![1u8; 64],
            ml_dsa_65_sig: vec![2u8; 3309],
            signing_key_id: "lens-key".into(),
            ts: "2026-10-14T10:00:00Z".parse().unwrap(),
        }
    }

    #[test]
    fn the_body_round_trips_through_the_envelope() {
        let e = event();
        let p = DetectionProjection::from(&e);
        let env = detection_envelope(&p).unwrap();
        let back: DetectionProjection = serde_json::from_value(env[BODY_MEMBER].clone()).unwrap();
        assert_eq!(back, p);
        assert_eq!(back.to_event().unwrap(), e);
        assert_eq!(
            env["dimension"],
            "detection:cohort_declared_inferred_mismatch:v1"
        );
    }

    #[test]
    fn a_tombstone_is_its_own_shape_and_not_an_event() {
        let p = DetectionProjection::from(&event());
        assert_eq!(detection_shape_refusal(&p), None);
        let t = p.tombstoned("2026-10-14T11:00:00Z".parse().unwrap());
        assert_eq!(detection_shape_refusal(&t), None);
        assert_eq!(t.to_event(), None);
        let half = DetectionProjection {
            trace_id: None,
            ..p.clone()
        };
        assert!(detection_shape_refusal(&half).is_some());
        let short = DetectionProjection {
            ml_dsa_65_sig: vec![0u8; 3293],
            ..p
        };
        assert!(detection_shape_refusal(&short).is_some());
    }

    #[test]
    fn the_row_id_derives_from_the_detection_id() {
        let id = uuid::Uuid::new_v4();
        assert_eq!(detection_attestation_id(&id), detection_attestation_id(&id));
        assert_ne!(
            detection_attestation_id(&id),
            detection_attestation_id(&uuid::Uuid::new_v4())
        );
        assert_ne!(detection_attestation_id(&id), id.to_string());
    }
}

/// v62.0.0 (v62 P8-fix11) — **test support: an edition-2 detection on a
/// backend**, for the witnesses that used to seed rows through the deleted
/// earlier-form door (`DerivedSchema::put_detection_event`). A detection is
/// its detector's own statement ([`state_detection`]); its standing is the
/// `infra:detect` conferral (P4's shape, `standing_invariants`): a key root
/// [`ROOT`] charters itself, THIS node (its `node_key_id`; [`NODE`] when the
/// caller lets [`confer`] declare one) accepts it, and it confers `infra:detect` on [`DETECTOR`], who voices
/// the conferral (its second signer, CC 2.6.1.9).
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod test_support {
    use crate::federation::attestation_admit::AttestationStore;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::hard_case::test_support::DeclaresNode;
    use crate::federation::FederationDirectory;

    /// The node seed (its kid is declared the backend's node key).
    pub(crate) const NODE: &str = "p8-detect-node";
    /// The key root's seed.
    pub(crate) const ROOT: &str = "p8-detect-root";
    /// The detector's seed (an `agent` key: the duty is the conferral's).
    pub(crate) const DETECTOR: &str = "p8-detect-detector";

    /// The detector's identity-ref (an event's `signing_key_id`).
    #[must_use]
    pub(crate) fn detector() -> String {
        e2::kid(DETECTOR)
    }

    /// Declare [`NODE`] this backend's node key, then [`confer_here`].
    pub(crate) async fn confer<B>(b: &B)
    where
        B: FederationDirectory + DeclaresNode,
    {
        e2::put_key(b, NODE, &["node"]).await;
        b.declare_node_key_for_test(&e2::kid(NODE));
        confer_here(b).await;
    }

    /// Confer `infra:detect` on [`DETECTOR`] from a root THIS node (the
    /// directory's `node_key_id`, a fixture seed's key) accepts. A second call
    /// states the edges again (new instants); the conferral stands.
    ///
    /// # Panics
    /// A directory with no node key, or a node key no fixture seed made.
    pub(crate) async fn confer_here<D>(b: &D)
    where
        D: FederationDirectory + ?Sized,
    {
        use crate::federation::trust_root::{
            TRUST_ACCEPTS_DIMENSION, TRUST_CHARTER_DIMENSION, TRUST_CONFERS_DIMENSION,
        };
        use crate::federation::types::{attestation_tier, attestation_type, cohort_scope};
        let node_kid = b
            .node_key_id()
            .expect("the caller set this node's key before conferring");
        let node = e2::seed_of(&node_kid);
        let node = node.as_str();
        e2::put_key(b, ROOT, &["node"]).await;
        e2::put_key(b, DETECTOR, &["agent"]).await;
        let commitment = crate::federation::trust_root::test_pre_rotation_commitment(&[format!(
            "{ROOT}-successor"
        )])
        .expect("commitment");
        for (from, to, envelope) in [
            (
                ROOT,
                ROOT,
                serde_json::json!({
                    "dimension": TRUST_CHARTER_DIMENSION,
                    "scope": ["infra:serve", "infra:attest"],
                    "pre_rotation_commitment": commitment,
                }),
            ),
            (
                node,
                ROOT,
                serde_json::json!({"dimension": TRUST_ACCEPTS_DIMENSION, "scope": ["infra:serve"]}),
            ),
            (
                ROOT,
                DETECTOR,
                serde_json::json!({
                    "dimension": TRUST_CONFERS_DIMENSION,
                    "scope": [crate::federation::types::delegation_scope::INFRA_DETECT],
                }),
            ),
        ] {
            let now = crate::host::clock::now();
            let lit = crate::federation::Attestation {
                attestation_id: String::new(),
                attesting_key_id: e2::kid(from),
                attested_key_id: e2::kid(to),
                attestation_type: attestation_type::DELEGATES_TO.to_owned(),
                weight: Some(1.0),
                asserted_at: now,
                expires_at: None,
                attestation_envelope: envelope.clone(),
                original_content_hash: String::new(),
                scrub_signature_classical: String::new(),
                scrub_signature_pqc: None,
                scrub_key_id: e2::kid(from),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                subject_key_ids: Vec::new(),
                withdraws_admission_rule: None,
                cohort_scope: cohort_scope::FEDERATION.to_owned(),
                tier: attestation_tier::FEDERATION.to_owned(),
                promoted_at: None,
                additional_scrubs: Vec::new(),
            };
            let edge = e2::try_put_row(b, &lit, from)
                .await
                .unwrap_or_else(|e| panic!("the trust edge {from} -> {to} is admitted: {e:?}"));
            // The conferral waits for its delegate's voice (CC 2.6.1.9).
            if envelope
                .get("dimension")
                .and_then(serde_json::Value::as_str)
                == Some(TRUST_CONFERS_DIMENSION)
            {
                let st = e2::carried_statement(&edge).expect("the conferral's statement");
                e2::put_statement(b, &e2::voice_of(&st, to))
                    .await
                    .expect("the detector's own voice on its conferral");
            }
        }
    }

    /// State `ev` (its `signing_key_id` = [`detector`]) as [`DETECTOR`]'s own
    /// statement through the door: its node-computed row id. The caller
    /// [`confer`]red first.
    pub(crate) async fn state<B: AttestationStore>(b: &B, ev: &super::DetectionEvent) -> String {
        super::state_detection(
            b,
            &crate::federation::tier_ingest::test_support::local_signer(DETECTOR),
            ev,
        )
        .await
        .unwrap_or_else(|e| panic!("the conferred detector states its detection: {e}"))
    }
}
