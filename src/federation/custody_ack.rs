//! v53.0.0 (CIRISPersist#942 part 2, CC 3.1.3.3, CIRISConstitution#130) —
//! **custody reports: which of a cohort's own devices hold a blob, and which
//! hold none.**
//!
//! A family must be able to see how many copies of its content exist ("only
//! one copy, back it up") without weakening encryption or outsider
//! invisibility. A device says so itself, in a `scores` row on its own leaf,
//! `custody:ack:v1` — never a `holds_bytes:*` sub-form, so no matcher error
//! can advertise self/family holdings to outsiders.
//!
//! # The row
//!
//! `attestation_type = scores`, `attesting_key_id == attested_key_id` = the
//! device (holder self-report: nobody reports custody for another device).
//! Envelope members:
//!
//! - `dimension` = [`CUSTODY_ACK_DIMENSION`];
//! - `custody_state` = `here` | `none` (CC 2.1, REQUIRED on this leaf);
//! - `evidence_refs` = exactly one entry, the blob's address digest (the
//!   at-rest sha256, 64 lowercase hex) — the slot `holds_bytes` already uses
//!   for the full digest;
//! - `size` — the blob's stored length, present iff `here`;
//! - `asserted_at` — the signer-stamped instant. It is the SIGNER's clock;
//!   the universal instant gate
//!   ([`check_instant_binding`](super::admission::check_instant_binding))
//!   refuses one more than [`DEFAULT_MAX_TOUCH_SKEW`](super::admission::DEFAULT_MAX_TOUCH_SKEW)
//!   ahead of the receiving node's clock, so a future-dated `here` cannot stay
//!   live for ever;
//! - the cohort target (`community_id` / `family_key_id`) per the row's
//!   `cohort_scope`, which is the blob's own: `self`, `family` or
//!   `community`. Nothing about the blob beyond its address and size rides
//!   the row; its name and format stay in the sealed descriptor.
//!
//! # The fold (read time; never a stored verdict)
//!
//! Per device: the device's latest non-retired report for the blob by signed
//! instant (ties by row hash). It is LIVE for [`CUSTODY_LIVE_SECS`] (72 h)
//! from its instant, judged on the READER's clock. Then, per CC 3.1.3.3:
//!
//! - **here** — a live `here` report;
//! - **received** — a CC 5.3.3.6 delivery receipt with no LATER live report;
//! - **none** — a live `none` report;
//! - **unknown** — no live report and no receipt.
//!
//! The count of *here* is the number of known copies. *Unknown* is never
//! *none*, and a lapsed `here` is never a copy.
//!
//! # No possession challenge (CC 3.1.3.3, CIRISPersist#976)
//!
//! A `here` report is trusted as signed by the device. Nothing yet asks the
//! device to prove it still holds the bytes. The view carries a
//! `challengeable` flag (a live `here` that names its size) so the challenge
//! protocol can attach to exactly the reports it would test.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::types::cohort_scope as cs;
use super::{Attestation, BlobError, BlobStorage, Error, FederationDirectory};

/// The one wire leaf of the `custody:{kind}` family (CC 3.1.3.3: `{kind}` ∈
/// `ack`, closed).
pub const CUSTODY_ACK_DIMENSION: &str = "custody:ack:v1";

/// The family stem. A row under it that is not [`CUSTODY_ACK_DIMENSION`] is
/// the namespace registry's to refuse (an unregistered leaf), not this gate's.
pub const CUSTODY_FAMILY_STEM: &str = "custody:";

/// The envelope member that carries the report (CC 2.1).
pub const CUSTODY_STATE_MEMBER: &str = "custody_state";

/// The envelope member that carries a `here` report's byte length.
pub const CUSTODY_SIZE_MEMBER: &str = "size";

/// A report is live for 72 hours from its signed instant (CC 3.1.3.3): a lost
/// device stops counting within three days; a phone off for a weekend still
/// counts.
pub const CUSTODY_LIVE_SECS: i64 = 72 * 3600;

/// What a device reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyState {
    /// The device holds the blob.
    Here,
    /// The device is responsive and holds no copy — a custody fact, not an
    /// absence.
    None,
}

impl CustodyState {
    /// The wire token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Here => "here",
            Self::None => "none",
        }
    }

    /// Parse the wire token; anything else is `None` (the caller refuses).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "here" => Some(Self::Here),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// One admitted report, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyAck {
    /// The reporting device (= attesting = attested).
    pub device_key_id: String,
    /// The blob's address digest, lowercase hex.
    pub blob_sha256_hex: String,
    /// `here` | `none`.
    pub state: CustodyState,
    /// The blob's length, present iff `here`.
    pub size: Option<u64>,
    /// The signer-stamped instant.
    pub instant: DateTime<Utc>,
    /// The row's hash — the tie-break between two reports at one instant.
    pub row_hash: String,
    /// The row's id.
    pub attestation_id: String,
}

fn malformed(detail: impl std::fmt::Display) -> Error {
    Error::InvalidArgument(format!(
        "custody_ack_malformed: {detail} ({CUSTODY_ACK_DIMENSION}, CC 3.1.3.3) — a malformed \
         custody report is refused, never read as an absent one"
    ))
}

fn is_lower_hex_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The cohorts a custody report may be placed at (CC 3.1.3.3: "`self` for a
/// person's own devices, `family`, or `community`").
fn is_custody_scope(scope: &str) -> bool {
    matches!(scope, cs::SELF | cs::FAMILY | cs::COMMUNITY)
}

/// **Parse a row as a custody report.** `Ok(None)` when the row is not on
/// [`CUSTODY_ACK_DIMENSION`]; `Err` when it is and is malformed — the row
/// shape alone, no directory. The admission gate and the fold read the same
/// parse, so a row the gate admits is a row the fold can read.
pub fn parse_custody_ack(row: &Attestation) -> Result<Option<CustodyAck>, Error> {
    let env = &row.attestation_envelope;
    if super::admission::envelope_dimension(env) != Some(CUSTODY_ACK_DIMENSION) {
        return Ok(None);
    }
    if row.attestation_type != super::types::attestation_type::SCORES {
        return Err(malformed(format!(
            "a custody report is a `scores` row, not {:?}",
            row.attestation_type
        )));
    }
    let state = match env.get(CUSTODY_STATE_MEMBER) {
        Some(serde_json::Value::String(s)) => CustodyState::parse(s)
            .ok_or_else(|| malformed(format!("custody_state {s:?} is not `here` | `none`")))?,
        Some(other) => {
            return Err(malformed(format!("custody_state {other} is not a string")));
        }
        None => return Err(malformed("custody_state is REQUIRED on this leaf")),
    };
    let refs = env
        .get("evidence_refs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| malformed("evidence_refs must carry the blob's address digest"))?;
    let [digest] = refs.as_slice() else {
        return Err(malformed(format!(
            "evidence_refs must name exactly one blob, not {}",
            refs.len()
        )));
    };
    let digest = digest
        .as_str()
        .filter(|d| is_lower_hex_digest(d))
        .ok_or_else(|| malformed("the blob's address digest is not 64 lowercase hex"))?;
    let size = match (state, env.get(CUSTODY_SIZE_MEMBER)) {
        (CustodyState::Here, Some(v)) => Some(
            v.as_u64()
                .ok_or_else(|| malformed(format!("size {v} is not a non-negative integer")))?,
        ),
        (CustodyState::Here, None) => {
            return Err(malformed("a `here` report carries the blob's size"));
        }
        (CustodyState::None, Some(_)) => {
            return Err(malformed("a `none` report carries no size"));
        }
        (CustodyState::None, None) => None,
    };
    if !is_custody_scope(&row.cohort_scope) {
        return Err(malformed(format!(
            "a custody report is placed at the blob's own cohort (self | family | community), \
             not {:?}",
            row.cohort_scope
        )));
    }
    Ok(Some(CustodyAck {
        device_key_id: row.attesting_key_id.clone(),
        blob_sha256_hex: digest.to_owned(),
        state,
        size,
        instant: row.asserted_at,
        row_hash: row.persist_row_hash.clone(),
        attestation_id: row.attestation_id.clone(),
    }))
}

/// **Is the reporting device in the blob's cohort?** The ONE audience call
/// site of this module. A `self` report is the device's own self; a `family`
/// or `community` report needs the device (or a human it is an occurrence of)
/// on that roster.
async fn device_in_cohort(
    directory: &dyn FederationDirectory,
    row: &Attestation,
    target: Option<&str>,
) -> Result<bool, Error> {
    let device = row.attesting_key_id.as_str();
    super::replication::hold::is_audience(
        directory,
        &row.cohort_scope,
        target,
        device,
        |_| false,
        device,
    )
    .await
}

/// **The custody-report admission gate** (CC 3.1.3.3), at every put door and
/// the promotion chokepoint. A no-op off the `custody:` family; on
/// [`CUSTODY_ACK_DIMENSION`] it refuses:
///
/// - a row that is not a holder self-report (`attesting_key_id` ≠
///   `attested_key_id`): nobody reports custody for another device;
/// - a malformed report ([`parse_custody_ack`]);
/// - a report placed at a cohort the device is not in.
pub async fn check_custody_ack_admission(
    directory: &dyn FederationDirectory,
    row: &Attestation,
) -> Result<(), Error> {
    if !super::admission::envelope_dimension(&row.attestation_envelope)
        .is_some_and(|d| d.starts_with(CUSTODY_FAMILY_STEM))
    {
        return Ok(());
    }
    if row.attesting_key_id != row.attested_key_id {
        return Err(Error::InvalidArgument(format!(
            "custody_ack_not_self_report: {CUSTODY_ACK_DIMENSION} is a holder self-report (CC \
             3.1.3.3): attesting_key_id {:?} must be the device the report is about ({:?}) — \
             nobody reports custody for another device",
            row.attesting_key_id, row.attested_key_id
        )));
    }
    if parse_custody_ack(row)?.is_none() {
        // A `custody:` row on another leaf: the registry's to refuse.
        return Ok(());
    }
    let target = super::admission::envelope_cohort_target(&row.attestation_envelope)?;
    if !device_in_cohort(directory, row, target).await? {
        return Err(Error::InvalidArgument(format!(
            "custody_ack_outside_cohort: device {:?} is not in the {} cohort {:?} its report is \
             placed at (CC 3.1.3.3: a custody report stays within the blob's own cohort)",
            row.attesting_key_id,
            row.cohort_scope,
            target.unwrap_or("")
        )));
    }
    Ok(())
}

/// **The envelope of a custody report** for `blob` — what a device signs.
/// `size` is REQUIRED for `here` and refused for `none`; the cohort target is
/// written under `community_id` (community) or `family_key_id` (family).
pub fn custody_ack_envelope(
    blob_sha256: &[u8; 32],
    state: CustodyState,
    size: Option<u64>,
    cohort_scope: &str,
    cohort_target: Option<&str>,
) -> Result<serde_json::Value, Error> {
    if !is_custody_scope(cohort_scope) {
        return Err(malformed(format!(
            "cohort {cohort_scope:?} is not self | family | community"
        )));
    }
    let mut env = serde_json::json!({
        "dimension": CUSTODY_ACK_DIMENSION,
        CUSTODY_STATE_MEMBER: state.as_str(),
        "evidence_refs": [hex::encode(blob_sha256)],
        "score": 1.0,
        "confidence": 1.0,
    });
    match (state, size) {
        (CustodyState::Here, Some(n)) => env[CUSTODY_SIZE_MEMBER] = serde_json::json!(n),
        (CustodyState::Here, None) => {
            return Err(malformed("a `here` report carries the blob's size"))
        }
        (CustodyState::None, Some(_)) => return Err(malformed("a `none` report carries no size")),
        (CustodyState::None, None) => {}
    }
    match (cohort_scope, cohort_target) {
        (cs::COMMUNITY, Some(c)) => env["community_id"] = serde_json::json!(c),
        (cs::FAMILY, Some(f)) => env["family_key_id"] = serde_json::json!(f),
        (cs::COMMUNITY | cs::FAMILY, None) => {
            return Err(malformed(format!(
                "a {cohort_scope} report names its {cohort_scope}"
            )));
        }
        _ => {}
    }
    Ok(env)
}

/// What a cohort member sees for one device (CC 3.1.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyVerdict {
    /// A live `here` report.
    Here,
    /// A delivery receipt with no later live report.
    Received,
    /// A live `none` report.
    None,
    /// No live report and no receipt. Never rendered as `none`.
    Unknown,
}

/// One device's custody of one blob, folded at read time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCustody {
    /// The device.
    pub device_key_id: String,
    /// `here` | `received` | `none` | `unknown`.
    pub state: CustodyVerdict,
    /// The latest report's signed instant, live or not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_at: Option<DateTime<Utc>>,
    /// The latest delivery receipt's stored instant, when one was consulted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_at: Option<DateTime<Utc>>,
    /// The size a live `here` report names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// A live `here` naming its size: what a possession challenge
    /// (CIRISPersist#976) would test. No challenge exists yet.
    pub challengeable: bool,
}

/// Is a report signed at `instant` live at `now`? `≤`: a report exactly 72 h
/// old still counts; one second later it does not.
pub fn is_live(instant: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    now.signed_duration_since(instant) <= chrono::Duration::seconds(CUSTODY_LIVE_SECS)
}

/// **The per-device fold.** `acks` are the device's admitted, non-retired
/// reports for ONE blob (any order); `receipt_at` the latest delivery
/// receipt's instant for that device, if one was consulted; `now` the
/// reader's clock.
pub fn fold_device_custody(
    device_key_id: &str,
    acks: &[CustodyAck],
    receipt_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> DeviceCustody {
    let latest = acks
        .iter()
        .max_by(|a, b| (a.instant, &a.row_hash).cmp(&(b.instant, &b.row_hash)));
    let live = latest.filter(|a| is_live(a.instant, now));
    let state = match (live, receipt_at) {
        (Some(l), Some(r)) if r > l.instant => CustodyVerdict::Received,
        (Some(l), _) => match l.state {
            CustodyState::Here => CustodyVerdict::Here,
            CustodyState::None => CustodyVerdict::None,
        },
        (None, Some(_)) => CustodyVerdict::Received,
        (None, None) => CustodyVerdict::Unknown,
    };
    let size = live
        .filter(|_| state == CustodyVerdict::Here)
        .and_then(|l| l.size);
    DeviceCustody {
        device_key_id: device_key_id.to_owned(),
        state,
        reported_at: latest.map(|a| a.instant),
        received_at: receipt_at,
        size,
        challengeable: state == CustodyVerdict::Here && size.is_some(),
    }
}

/// **`device`'s admitted reports for one blob**, re-derived from the rows the
/// device signed: retired rows (its own `supersedes` / `withdraws`) fold out,
/// a row that no longer parses is skipped (the gate refused every such row at
/// admission; nothing stored is a verdict).
pub async fn custody_acks_of<D>(
    directory: &D,
    device_key_id: &str,
    blob_sha256_hex: &str,
) -> Result<Vec<CustodyAck>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let rows = directory.list_attestations_by(device_key_id).await?;
    let refs: Vec<&Attestation> = rows.iter().collect();
    let retired = super::precedence::retired_ids(&refs);
    Ok(rows
        .iter()
        .filter(|r| !retired.contains(&r.attestation_id))
        .filter_map(|r| match parse_custody_ack(r) {
            Ok(Some(a)) => Some(a),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(attestation_id = %r.attestation_id, error = %e, "custody fold skips a malformed report");
                None
            }
        })
        .filter(|a| a.device_key_id == device_key_id && a.blob_sha256_hex == blob_sha256_hex)
        .collect())
}

/// **One device's custody of one blob**, from the directory alone: the
/// device's reports folded with `receipt_at` at `now`.
pub async fn device_custody_of<D>(
    directory: &D,
    device_key_id: &str,
    blob_sha256_hex: &str,
    receipt_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<DeviceCustody, Error>
where
    D: FederationDirectory + ?Sized,
{
    let acks = custody_acks_of(directory, device_key_id, blob_sha256_hex).await?;
    Ok(fold_device_custody(device_key_id, &acks, receipt_at, now))
}

/// The custody of one blob across the devices this node can name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyView {
    /// Lowercase hex of the at-rest sha256.
    pub sha256_hex: String,
    /// One entry per device, sorted by device.
    pub devices: Vec<DeviceCustody>,
    /// The devices whose verdict is `here`: the known copies.
    pub copies_here: u32,
    /// Whether delivery receipts were consulted (a `stream_id` was given).
    pub receipts_consulted: bool,
}

/// The devices a node can name for a blob: the key recipients of its tier
/// (at-rest grants for `self`/`family`, the sealing epoch's member grants for
/// `community`) and this node itself.
async fn candidate_devices<B>(
    backend: &B,
    at_rest_sha256: &[u8; 32],
    tier: cs::CryptoTier,
) -> Result<BTreeSet<String>, BlobError>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let mut out: BTreeSet<String> = BTreeSet::new();
    match tier {
        cs::CryptoTier::InvisibleEncrypted => {
            out.extend(
                backend
                    .list_at_rest_grants(at_rest_sha256)
                    .await?
                    .into_iter()
                    .map(|g| g.recipient_key_id)
                    .filter(|r| r != super::at_rest_cascade::PERSIST_SELF_RECIPIENT),
            );
        }
        cs::CryptoTier::CommunityDek => {
            if let Some((community, minter, epoch)) =
                backend.community_dek_blob_epoch(at_rest_sha256).await?
            {
                out.extend(
                    backend
                        .community_dek_member_grant_recipients(&community, &minter, epoch)
                        .await?,
                );
            }
        }
        cs::CryptoTier::Plaintext => {}
    }
    if let Some(me) = backend.node_key_id() {
        out.insert(me);
    }
    Ok(out)
}

/// **The custody view of one blob** for `viewer_key_id`, authorized exactly as
/// the bytes read (a stranger is `NotGranted` and learns nothing). Devices are
/// the blob's key recipients, this node, and — when `stream_id` names the
/// blob's stream — every subscriber that receipted it; each is folded at
/// `now` (the reader's clock).
pub async fn custody_view<B>(
    backend: &B,
    at_rest_sha256: &[u8; 32],
    viewer_key_id: &str,
    stream_id: Option<&str>,
    now: DateTime<Utc>,
) -> Result<CustodyView, BlobError>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    use super::at_rest_cascade::orchestrate::{authorize_viewer_by_tier, refuse_missing_row};
    let Some(head) = backend.blob_head(at_rest_sha256).await? else {
        return Err(refuse_missing_row(backend, at_rest_sha256, viewer_key_id).await?);
    };
    authorize_viewer_by_tier(backend, at_rest_sha256, head.crypto_tier, viewer_key_id).await?;
    let mut devices = candidate_devices(backend, at_rest_sha256, head.crypto_tier).await?;
    let mut receipts: BTreeMap<String, DateTime<Utc>> = BTreeMap::new();
    if let Some(stream) = stream_id {
        for r in backend
            .list_stored_delivery_receipts_for(stream, 1_000_000)
            .await?
        {
            let at = receipts
                .entry(r.receipt.subscriber_key_id.clone())
                .or_insert(r.received_at);
            if r.received_at > *at {
                *at = r.received_at;
            }
        }
        devices.extend(receipts.keys().cloned());
    }
    let hex_sha = hex::encode(at_rest_sha256);
    let mut out = Vec::with_capacity(devices.len());
    for d in devices {
        let view = device_custody_of(backend, &d, &hex_sha, receipts.get(&d).copied(), now)
            .await
            .map_err(|e| BlobError::Backend(format!("custody fold for {d}: {e}")))?;
        out.push(view);
    }
    let copies_here = out
        .iter()
        .filter(|d| d.state == CustodyVerdict::Here)
        .count() as u32;
    Ok(CustodyView {
        sha256_hex: hex_sha,
        devices: out,
        copies_here,
        receipts_consulted: stream_id.is_some(),
    })
}

/// **What this node signs for `blob`** — the input of a custody report,
/// derived from what the node holds. `here` needs the bytes on this node (a
/// device does not report a copy it does not have) and takes its size from the
/// stored row; the cohort is the stored row's, and a caller-named cohort that
/// differs is refused. With no row held, only `none` can be reported, at the
/// caller-named cohort.
pub async fn custody_ack_input_for<B>(
    backend: &B,
    blob_sha256: &[u8; 32],
    state: CustodyState,
    cohort_scope: Option<&str>,
    cohort_target: Option<&str>,
) -> Result<super::EmitAttestationInput, Error>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let blob_err = |e: BlobError| Error::Backend(format!("custody report: {e}"));
    let head = backend.blob_head(blob_sha256).await.map_err(blob_err)?;
    let (scope, size) = match (&head, state) {
        (Some(h), _) => {
            if let Some(named) = cohort_scope.filter(|c| *c != h.cohort_scope) {
                return Err(malformed(format!(
                    "the blob is held at cohort {:?}, not {named:?}",
                    h.cohort_scope
                )));
            }
            let size = match state {
                CustodyState::Here => {
                    if !backend.has_blob(blob_sha256).await.map_err(blob_err)? {
                        return Err(Error::InvalidArgument(
                            "custody_ack_here_not_held: this node does not hold the blob's bytes, \
                             so it cannot report `here` (CC 3.1.3.3)"
                                .into(),
                        ));
                    }
                    Some(h.size_bytes)
                }
                CustodyState::None => None,
            };
            (h.cohort_scope.clone(), size)
        }
        (None, CustodyState::Here) => {
            return Err(Error::InvalidArgument(
                "custody_ack_here_not_held: this node holds no row for the blob, so it cannot \
                 report `here` (CC 3.1.3.3)"
                    .into(),
            ));
        }
        (None, CustodyState::None) => (
            cohort_scope
                .ok_or_else(|| {
                    malformed("with no row held, a `none` report names the blob's cohort")
                })?
                .to_owned(),
            None,
        ),
    };
    let target = match (cohort_target, scope.as_str()) {
        (Some(t), _) => Some(t.to_owned()),
        (None, cs::COMMUNITY) => backend
            .community_dek_blob_epoch(blob_sha256)
            .await
            .map_err(blob_err)?
            .map(|(community, _, _)| community),
        (None, _) => None,
    };
    let env = custody_ack_envelope(blob_sha256, state, size, &scope, target.as_deref())?;
    let core: super::envelope::EnvelopeCore = serde_json::from_value(env)
        .map_err(|e| Error::Backend(format!("custody report envelope: {e}")))?;
    Ok(super::EmitAttestationInput::with_envelope(
        super::types::attestation_type::SCORES,
        core,
        scope,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_800_000_000 + secs, 0).unwrap()
    }

    fn ack(state: CustodyState, instant: DateTime<Utc>, hash: &str) -> CustodyAck {
        CustodyAck {
            device_key_id: "d".into(),
            blob_sha256_hex: "ab".repeat(32),
            state,
            size: (state == CustodyState::Here).then_some(7),
            instant,
            row_hash: hash.into(),
            attestation_id: hash.into(),
        }
    }

    #[test]
    fn a_tie_at_one_instant_breaks_by_row_hash() {
        let v = fold_device_custody(
            "d",
            &[
                ack(CustodyState::None, at(0), "b"),
                ack(CustodyState::Here, at(0), "a"),
            ],
            None,
            at(10),
        );
        assert_eq!(
            v.state,
            CustodyVerdict::None,
            "the larger row hash wins a tie"
        );
    }

    #[test]
    fn a_receipt_older_than_the_live_report_does_not_win() {
        let v = fold_device_custody(
            "d",
            &[ack(CustodyState::None, at(100), "a")],
            Some(at(50)),
            at(200),
        );
        assert_eq!(v.state, CustodyVerdict::None);
        let v = fold_device_custody(
            "d",
            &[ack(CustodyState::None, at(100), "a")],
            Some(at(150)),
            at(200),
        );
        assert_eq!(
            v.state,
            CustodyVerdict::Received,
            "a later receipt outranks the report"
        );
    }
}
