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
//! Two doors write one:
//!
//! - **`put_detection_event`** (the LensCore path every host runs today): the
//!   detector's hybrid signature over `canonical_bytes` is verified by the
//!   caller (`Engine` / the PyO3 surface, `HybridPolicy::Strict`), then the
//!   row is written at the local tier with its own signature deferred — the
//!   `trace:complete:v1` precedent. It crosses to the federation tier when
//!   the detector signs it as the actor (`enter_mesh`).
//! - **`put_attestation`** (and the replicated apply): a detector that emits
//!   the row itself, hybrid-signed, at the federation tier. It replicates like
//!   any other row; the plan checks its body
//!   ([`check_detection_body`]) and the executor projects it.
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
    /// Ed25519 signature over `canonical_bytes`; `None` only on an
    /// erasure-derived tombstone ([`erased_detection_projection`]: the bytes
    /// it covered are gone).
    #[serde(with = "opt_b64")]
    pub ed25519_sig: Option<Vec<u8>>,
    /// ML-DSA-65 signature over `canonical_bytes`; `None` as above.
    #[serde(with = "opt_b64")]
    pub ml_dsa_65_sig: Option<Vec<u8>>,
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
            ed25519_sig: Some(e.ed25519_sig.clone()),
            ml_dsa_65_sig: Some(e.ml_dsa_65_sig.clone()),
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
            ed25519_sig: self.ed25519_sig.clone()?,
            ml_dsa_65_sig: self.ml_dsa_65_sig.clone()?,
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
    // A detection's row always carries both signature halves: a body
    // without them is only ever an erasure-derived projection, never a row.
    let ed = body.ed25519_sig.as_deref().unwrap_or_default();
    if ed.len() != ED25519_SIG_LEN {
        return Some(format!(
            "ed25519_sig must be {ED25519_SIG_LEN} bytes (got {})",
            ed.len()
        ));
    }
    let pq = body.ml_dsa_65_sig.as_deref().unwrap_or_default();
    if pq.len() != ML_DSA_65_SIG_LEN {
        return Some(format!(
            "ml_dsa_65_sig must be {ML_DSA_65_SIG_LEN} bytes (got {})",
            pq.len()
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
#[must_use]
pub fn project_detection_row(row: &Attestation) -> Option<DetectionProjection> {
    if row.attestation_type != crate::federation::types::attestation_type::SCORES {
        return None;
    }
    let body = detection_body(row)?;
    let dimension = row.attestation_envelope.get("dimension")?.as_str()?;
    (row.attestation_id == detection_attestation_id(&body.detection_id)
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
    let body = detection_body(row).ok_or_else(|| refuse("it does not parse".into()))?;
    // Only the detection's own row (its derived id) is projected; a body
    // under another id is a claim this node holds without projecting it.
    if row.attestation_id != detection_attestation_id(&body.detection_id) {
        return Ok(());
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

// ─────────────────────────────────────────────────────────────────────────
//  v57.0.0 (CIRISPersist#988 item 3; lead ruling on the DSAR path) — the
//  Art. 17 erasure's tombstones, carried by the erasure's own row
// ─────────────────────────────────────────────────────────────────────────

/// The `detail` member of a `hard_case:trace_erasure:v1` row that carries the
/// V080 tombstone content of every detection the erasure hard-deleted.
pub const ERASURE_DETAIL_MEMBER: &str = "detection_tombstones";

/// At most this many erased detections ride one `hard_case:trace_erasure:v1`
/// row; an erasure with more emits one row per chunk (one act, N rows, one
/// transaction). An entry is about 0.5 KB for a typical detection (the
/// analytics columns only: no linkage, no signatures), so 512 entries are
/// about 256 KB, well inside `MAX_ATTESTATION_ENVELOPE_BYTES` (1 MiB).
pub const MAX_ERASED_DETECTIONS_PER_ROW: usize = 512;

/// A second bound on a chunk, by bytes: an entry's `cohort_cell` and
/// `conformity_payload` are consumer-shaped JSON, so a chunk also closes once
/// its serialized entries pass this many bytes (half the envelope cap).
pub const MAX_ERASED_DETECTION_BYTES_PER_ROW: usize = 512 * 1024;

/// One erased detection, as the erasure row carries it: exactly the columns
/// V080's tombstone keeps (#222: keep the substrate analytics, drop the
/// linkage), and neither the three linkage columns nor the signatures.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErasedDetection {
    /// Detection identifier.
    pub detection_id: uuid::Uuid,
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
    /// Lens-core version.
    pub lens_core_version: String,
    /// Calibration version.
    pub ratchet_calibration_version: i32,
    /// The detector's key.
    pub signing_key_id: String,
    /// The detection's instant.
    pub ts: DateTime<Utc>,
}

impl From<&DetectionProjection> for ErasedDetection {
    fn from(p: &DetectionProjection) -> Self {
        Self {
            detection_id: p.detection_id,
            detector: p.detector.clone(),
            severity: p.severity,
            cohort_cell: p.cohort_cell.clone(),
            conformity_variant: p.conformity_variant,
            conformity_payload: p.conformity_payload.clone(),
            lens_core_version: p.lens_core_version.clone(),
            ratchet_calibration_version: p.ratchet_calibration_version,
            signing_key_id: p.signing_key_id.clone(),
            ts: p.ts,
        }
    }
}

/// The V080 tombstone row an erased detection projects to: linkage and
/// signatures NULL, analytics kept, `erased_at` = the erasure row's
/// `asserted_at`.
#[must_use]
pub fn erased_detection_projection(
    e: &ErasedDetection,
    erased_at: DateTime<Utc>,
) -> DetectionProjection {
    DetectionProjection {
        detection_id: e.detection_id,
        trace_id: None,
        body_sha256: None,
        detector: e.detector.clone(),
        severity: e.severity,
        cohort_cell: e.cohort_cell.clone(),
        conformity_variant: e.conformity_variant,
        conformity_payload: e.conformity_payload.clone(),
        lens_core_version: e.lens_core_version.clone(),
        ratchet_calibration_version: e.ratchet_calibration_version,
        canonical_bytes: None,
        ed25519_sig: None,
        ml_dsa_65_sig: None,
        signing_key_id: e.signing_key_id.clone(),
        ts: e.ts,
        erased_at: Some(erased_at),
    }
}

/// v57.0.0 — **the projection of an erasure row** (CLM-silo-projection-
/// rebuildable): the V080 tombstone of every detection a
/// `hard_case:trace_erasure:v1` row carries, at the row's `asserted_at`.
/// The one function the erasure's live write and the rebuild call. Empty for
/// any other row.
#[must_use]
pub fn project_erasure_row(row: &Attestation) -> Vec<DetectionProjection> {
    let Some(event) = crate::federation::hard_case::project_hard_case_row(row) else {
        return Vec::new();
    };
    if event.kind != crate::federation::hard_case::kind::TRACE_ERASURE {
        return Vec::new();
    }
    let Some(entries) = event.detail.get(ERASURE_DETAIL_MEMBER) else {
        return Vec::new();
    };
    let entries: Vec<ErasedDetection> = serde_json::from_value(entries.clone()).unwrap_or_default();
    entries
        .iter()
        .map(|e| erased_detection_projection(e, row.asserted_at))
        .collect()
}

/// v57.0.0 — split an erasure's tombstone entries into chunks, each within
/// [`MAX_ERASED_DETECTIONS_PER_ROW`] entries and
/// [`MAX_ERASED_DETECTION_BYTES_PER_ROW`] serialized bytes (a single entry
/// larger than the byte bound rides alone). Order kept.
#[must_use]
pub fn chunk_erased_detections(entries: Vec<ErasedDetection>) -> Vec<Vec<ErasedDetection>> {
    let mut out: Vec<Vec<ErasedDetection>> = Vec::new();
    let mut cur: Vec<ErasedDetection> = Vec::new();
    let mut cur_bytes = 0usize;
    for e in entries {
        let n = serde_json::to_vec(&e).map(|v| v.len()).unwrap_or(0);
        if !cur.is_empty()
            && (cur.len() >= MAX_ERASED_DETECTIONS_PER_ROW
                || cur_bytes + n > MAX_ERASED_DETECTION_BYTES_PER_ROW)
        {
            out.push(std::mem::take(&mut cur));
            cur_bytes = 0;
        }
        cur_bytes += n;
        cur.push(e);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// A refusal of the detection door, in the `DerivedSchema` error tree: a
/// conflict stays a conflict, a substrate failure stays `Backend`, and every
/// admission refusal is the caller's (`InvalidArgument`, the type V008's
/// shape refusals always had), its `kind()` token leading the message.
pub(crate) fn derived_error(e: crate::federation::Error) -> super::Error {
    use crate::federation::Error as F;
    match e {
        F::Conflict(m) => super::Error::Conflict(m),
        F::Backend(m) => super::Error::Backend(m),
        other => super::Error::InvalidArgument(format!("{}: {other}", other.kind())),
    }
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
            ml_dsa_65_sig: Some(vec![0u8; 3293]),
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
