//! # The consent expiry sweep — `consent:state:expired`, recorded by the substrate
//!
//! v44.8.0 (CIRISPersist#866 C3, `FSD/CONTEXTUAL_INTEGRITY_ENVELOPE.md` §5.7).
//!
//! CC 3.3.1 makes `consent:state:expired` the one `consent:state:` leaf the
//! **substrate** emits: *"Lapse of a grant when `valid_until` passes without
//! renewal. Substrate-emitted, not subject-emitted — it records an observed
//! clock event, not a stance."* Persist recognised the leaf in its fold from
//! the start and never emitted one: expiry was *computed* per node from the
//! grant's `expires_at`, so a lapse was a private clock reading on every node
//! rather than a replicable fact with a causal edge. This sweep records it.
//!
//! ## What it does
//!
//! For every `consent:state:granted` row whose **lapse instant** has passed —
//! the earlier of its signed `expires_at` and the end of any `retain:<window>`
//! its scope names ([`super::consent::grant_lapse_instant`], one spelling) —
//! and which no `consent:state:expired` row already names, the sweep emits one
//! expired row, signed by this node's key, with:
//!
//! - `consent_supersedes` = the grant's `attestation_id` — **the edge**. The
//!   fold admits a substrate-emitted expired row into the subject's universe
//!   only through this edge, and only when the row is asserted at or after the
//!   grant's own lapse ([`super::consent`], `substrate_expiry_bound_to_subject`):
//!   no node can expire a consent early, or someone else's, by emitting one.
//! - `asserted_at` = the lapse instant, not the sweep's wall clock. The record
//!   says WHEN the consent lapsed; the sweep merely noticed.
//! - `scope`, `content_class` copied from the grant, so the record folds in
//!   exactly the scope the grant covered. `for_key_id` is deliberately NOT
//!   copied: a machine author may name only itself (#857), and the edge —
//!   not the member — is what binds the record to the human's grant.
//! - `attested_key_id` = the grant's target; `subject_key_ids` = the subject
//!   whose consent lapsed (the data subject of the observation);
//!   `cohort_scope` = the grant's, so the record travels where the grant did.
//!
//! Idempotent: a grant already named by an expired row is counted as
//! `already_recorded` and left alone. A later fresh grant is a new row the
//! edge does not name; consent re-opens on it as before (#642).
//!
//! ## What it does not do
//!
//! It does not delete anything, does not touch the grant, and does not run on
//! its own — a maintenance loop calls
//! [`crate::Engine::run_consent_expiry_sweep`] (PyO3
//! `run_consent_expiry_sweep_json`), exactly like the deletion-window watch.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::admission::envelope_dimension;
use super::consent::{consent_dimension, grant_lapse_instant, ConsentCausalEdge};
use super::envelope::{paths, EnvelopeCore};
use super::types::{attestation_type, EmitAttestationInput};
use super::{Attestation, Error, FederationDirectory};

/// Rows examined per page; the same cap as the deletion-window watch.
pub const CONSENT_EXPIRY_SCAN_CAP: u32 = 10_000;
/// Pages per pass; beyond this the report says `scan_truncated`.
pub const MAX_SCAN_PAGES: usize = 128;

/// Outcome of one [`run_consent_expiry_sweep`] pass. Counts are conditions
/// observed; `emitted` is the only count that wrote a row.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentExpirySweepReport {
    /// Rows examined this pass.
    pub rows_scanned: usize,
    /// `consent:state:granted` rows among them.
    pub grants_seen: usize,
    /// Grants whose lapse instant has passed at `now`.
    pub lapsed: usize,
    /// Lapsed grants a `consent:state:expired` row already names.
    pub already_recorded: usize,
    /// Expired rows emitted this pass.
    pub emitted: usize,
    /// Lapsed grants the emit refused (logged); re-tried next pass.
    pub skipped: usize,
    /// The scan filled every page — grants beyond were not examined.
    pub scan_truncated: bool,
}

fn is_granted(a: &Attestation) -> bool {
    envelope_dimension(&a.attestation_envelope)
        .is_some_and(|d| d.starts_with(consent_dimension::STATE_GRANTED_PREFIX))
}

fn is_expired(a: &Attestation) -> bool {
    envelope_dimension(&a.attestation_envelope)
        .is_some_and(|d| d.starts_with(consent_dimension::STATE_EXPIRED_PREFIX))
}

/// Does any `consent:state:expired` row among `rows` name `grant_id`?
fn already_recorded(rows: &[Attestation], grant_id: &str) -> bool {
    rows.iter().any(|a| {
        is_expired(a)
            && matches!(super::consent::causal_edge(a), ConsentCausalEdge::Names(g) if g == grant_id)
    })
}

/// The expired row the sweep emits for `grant`, lapsed at `lapse`. Pure, so
/// the shape is testable without a directory.
pub fn expiry_record_for(
    grant: &Attestation,
    lapse: DateTime<Utc>,
) -> Result<EmitAttestationInput, Error> {
    let mut env = serde_json::json!({
        paths::DIMENSION: format!("{}:v1", consent_dimension::STATE_EXPIRED_PREFIX),
        paths::CONSENT_SUPERSEDES: grant.attestation_id,
        paths::ASSERTED_AT: super::admission::render_signed_instant(lapse),
    });
    for member in [paths::SCOPE, "content_class"] {
        if let Some(v) = grant.attestation_envelope.get(member) {
            env[member] = v.clone();
        }
    }
    let mut input = EmitAttestationInput::with_envelope(
        attestation_type::SCORES,
        EnvelopeCore::from_value(env)?,
        grant.cohort_scope.clone(),
    );
    input.attested_key_id = Some(grant.attested_key_id.clone());
    input.subject_key_ids = vec![grant.attesting_key_id.clone()];
    Ok(input)
}

/// One pass. `emit` is the node's signing door
/// ([`crate::Engine::emit_attestation_self`]); the sweep never signs.
pub async fn run_consent_expiry_sweep<F, Fut>(
    dir: &dyn FederationDirectory,
    now: DateTime<Utc>,
    emit: F,
) -> Result<ConsentExpirySweepReport, Error>
where
    F: Fn(EmitAttestationInput) -> Fut,
    Fut: std::future::Future<Output = Result<String, Error>>,
{
    use std::collections::{HashMap, HashSet};

    let mut report = ConsentExpirySweepReport::default();
    let mut seen: HashSet<String> = HashSet::new();
    // target → its rows, read once per target per pass (the expired rows
    // that may already name a grant live beside it).
    let mut by_target: HashMap<String, Vec<Attestation>> = HashMap::new();
    let mut cursor: Option<(DateTime<Utc>, String)> = None;
    let mut truncated = true;

    for _page in 0..MAX_SCAN_PAGES {
        let page = dir
            .list_attestations_since(cursor.clone(), CONSENT_EXPIRY_SCAN_CAP)
            .await?;
        let Some(last) = page.last() else {
            truncated = false;
            break;
        };
        let page_full = page.len() as u32 >= CONSENT_EXPIRY_SCAN_CAP;
        let next_cursor = last.resume_pair();

        for served in &page {
            let grant = &served.attestation;
            if !seen.insert(grant.attestation_id.clone()) {
                continue;
            }
            report.rows_scanned += 1;
            if !is_granted(grant) {
                continue;
            }
            report.grants_seen += 1;
            let Some(lapse) = grant_lapse_instant(grant) else {
                continue;
            };
            if lapse > now {
                continue;
            }
            report.lapsed += 1;

            let target = &grant.attested_key_id;
            if !by_target.contains_key(target) {
                let rows = dir.list_attestations_for(target).await?;
                by_target.insert(target.clone(), rows);
            }
            let rows = by_target.get(target).map(Vec::as_slice).unwrap_or(&[]);
            if already_recorded(rows, &grant.attestation_id) {
                report.already_recorded += 1;
                continue;
            }
            match emit(expiry_record_for(grant, lapse)?).await {
                Ok(id) => {
                    report.emitted += 1;
                    // Keep this pass's own view current so a second lapsed
                    // grant on the same target is not double-recorded.
                    if let Some(rows) = by_target.get_mut(target) {
                        if let Some(row) = dir.get_attestation(&id).await? {
                            rows.push(row);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        grant = %grant.attestation_id,
                        subject = %grant.attesting_key_id,
                        target = %target,
                        error = %e,
                        "consent expiry sweep: could not record the lapse; retried next pass"
                    );
                    report.skipped += 1;
                }
            }
        }

        if !page_full {
            truncated = false;
            break;
        }
        cursor = Some(next_cursor);
    }

    report.scan_truncated = truncated;
    Ok(report)
}
