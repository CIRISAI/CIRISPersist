//! v61 (CC 2.6.2; the steward's strict ruling) — **the open-time pass
//! over stored attestation rows whose signed instants are not in the one
//! canonical form.**
//!
//! CC 2.6.2: every signed datetime is `YYYY-MM-DDTHH:MM:SS.sssZ`, and a
//! consumer MUST reject any other form when verifying a signature. The ruling
//! for v61: only that form verifies, there is no cut-over instant, and no
//! reader normalises another form. The admission doors refuse it
//! ([`check_envelope_member_shapes`](super::admission::check_envelope_member_shapes)
//! on [`signed_instant_form_violation`](super::admission::signed_instant_form_violation)).
//! This pass settles the rows a v60 node already holds, once, at open:
//!
//! - **This node's own rows** (`attesting_key_id` = the node's key) are
//!   re-signed in the canonical form as an ordinary `supersedes` of each,
//!   through the ordinary emit door, keeping the claim's own instant. The
//!   original stays where it is: its successor cites it.
//! - **A row that takes something away** ([`keeps_force`]) stays in force
//!   where it is, whoever signed it. A revocation refused for its form alone
//!   never un-revokes (CC 3.2 T3, CC 6.1.7).
//! - **Any other row another producer signed** is refused at read: removed,
//!   and recorded (no body) in the V211 ledger, so every read path on both
//!   backends refuses it by absence and nothing serves it onward.
//!
//! The pass is idempotent: a second open finds every own row already
//! superseded by this node and every refused row already set aside, and does
//! no work. It never aborts a boot; a row the door refuses is counted and
//! logged, and the next open retries it.

use super::admission::{signed_instant_form_violation, InstantFormViolation};
use super::types::{attestation_tier, attestation_type, Attestation};
use super::Error;

/// Rows read per corpus page.
pub const PAGE_SIZE: u32 = 500;

/// What one pass did, counted from the rows it read.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InstantFormPass {
    /// Rows read.
    pub scanned: u64,
    /// Rows whose signed instants are not in the canonical form.
    pub violations: u64,
    /// Own rows re-signed this pass as a canonical `supersedes`.
    pub healed: u64,
    /// Own rows a `supersedes` by this node already re-states.
    pub already_healed: u64,
    /// Own rows the emit door refused to re-state (counted, logged, retried
    /// next open).
    pub heal_refused: u64,
    /// Own rows this node cannot re-state as an ordinary `supersedes`: a
    /// structural composer, a cosigned row, a local-tier row, an expired row.
    /// They stay where they are.
    pub own_left: u64,
    /// Rows another producer signed that take something away, kept in force.
    pub kept_in_force: u64,
    /// Rows another producer signed, removed and recorded in the V211 ledger.
    pub set_aside: u64,
}

impl InstantFormPass {
    /// `true` when the pass changed the store.
    #[must_use]
    pub const fn changed_anything(&self) -> bool {
        self.healed > 0 || self.set_aside > 0
    }
}

/// Dimension families, beyond [`super::migration::is_exclusion_bearing`],
/// whose rows take something away: a removal or resignation from a group, and
/// a revoked consent. Refusing one at read would re-admit what it removed.
pub const TAKE_AWAY_DIMENSION_PREFIXES: &[&str] = &[
    "membership:removal:",
    "membership:resignation:",
    "consent:state:revoked",
];

/// Does `row` stay in force when refused for the form of an instant alone?
/// Every structural composer, every delegation (the exclusion acts hang off
/// the delegation plane), revocation, quarantine, moderation,
/// reconsideration, slashing, objection and the accountability record
/// ([`super::migration::is_exclusion_bearing`], which also answers yes for an
/// unreadable dimension), and [`TAKE_AWAY_DIMENSION_PREFIXES`]. Fail-secure:
/// refusing an exclusion at read is the direction that re-admits.
#[must_use]
pub fn keeps_force(row: &Attestation) -> bool {
    if super::migration::is_exclusion_bearing(row).is_some() {
        return true;
    }
    super::admission::envelope_dimension(&row.attestation_envelope).is_some_and(|d| {
        TAKE_AWAY_DIMENSION_PREFIXES
            .iter()
            .any(|p| d.starts_with(p))
    })
}

/// The disposition of one row that fails the form, decided from the row
/// alone (the "already healed" question needs the store and is asked by the
/// pass).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// An own row to re-state as a canonical `supersedes`.
    Heal,
    /// An own row that cannot be re-stated as an ordinary `supersedes`.
    OwnLeft,
    /// Another producer's row that takes something away.
    KeepInForce,
    /// Another producer's row, refused at read.
    SetAside,
}

/// Decide what the pass does with `row`, which fails the form.
#[must_use]
pub fn disposition(
    row: &Attestation,
    self_key_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Disposition {
    if row.attesting_key_id != self_key_id {
        return if keeps_force(row) {
            Disposition::KeepInForce
        } else {
            Disposition::SetAside
        };
    }
    let restatable_type = matches!(
        row.attestation_type.as_str(),
        attestation_type::SCORES | attestation_type::DELEGATES_TO | attestation_type::SUPERSEDES
    );
    let live = row.expires_at.is_none_or(|t| t > now);
    if restatable_type
        && row.tier == attestation_tier::FEDERATION
        && row.additional_scrubs.is_empty()
        && live
    {
        Disposition::Heal
    } else {
        Disposition::OwnLeft
    }
}

/// The canonical `supersedes` of `row`: its envelope with every signed
/// instant re-rendered `.sssZ` (the same instant, at the millisecond),
/// `references_attestation_id` naming `row`, the `row` mirror left for the
/// emit door to stamp, and the claim's own `asserted_at` kept, so a family
/// window measured from it (a proposal's expiry, a delegation's term) holds.
///
/// # Errors
/// [`Error::InvalidArgument`] when an instant member does not parse as RFC
/// 3339 at all: there is no instant to re-state.
pub fn heal_input(row: &Attestation) -> Result<super::EmitAttestationInput, Error> {
    use super::admission::{render_signed_instant, truncate_to_substrate_resolution as trunc};
    let mut envelope = row.attestation_envelope.clone();
    let members = envelope.as_object_mut().ok_or_else(|| {
        Error::InvalidArgument(format!(
            "attestation {}: the envelope is not an object",
            row.attestation_id
        ))
    })?;
    for member in super::admission::SIGNED_INSTANT_MEMBERS {
        if let Some(serde_json::Value::String(s)) = members.get(*member) {
            let t = chrono::DateTime::parse_from_rfc3339(s)
                .map_err(|e| {
                    Error::InvalidArgument(format!(
                        "attestation {}: `{member}` = {s:?} is not RFC 3339 ({e}); there is no \
                         instant to re-state",
                        row.attestation_id
                    ))
                })?
                .with_timezone(&chrono::Utc);
            members.insert(
                (*member).to_owned(),
                serde_json::Value::String(render_signed_instant(trunc(t))),
            );
        }
    }
    members.remove(super::envelope::paths::ROW);
    members.insert(
        "references_attestation_id".to_owned(),
        serde_json::Value::String(row.attestation_id.clone()),
    );
    // The expiry column is derived from the signed member at the mint; keep the
    // two the same instant.
    let expires_at = members
        .get(super::envelope::paths::EXPIRES_AT)
        .and_then(serde_json::Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&chrono::Utc));
    Ok(super::EmitAttestationInput {
        attestation_type: attestation_type::SUPERSEDES.to_owned(),
        attested_key_id: Some(row.attested_key_id.clone()),
        attestation_envelope: super::envelope::EnvelopeCore::from_value(envelope)?,
        subject_key_ids: row.subject_key_ids.clone(),
        cohort_scope: row.cohort_scope.clone(),
        expires_at,
        weight: row.weight,
    })
}

/// What the pass needs from a store: the corpus walk, the composers that cite
/// a page of rows, the emit door for this node's re-statements, and the
/// set-aside door.
#[allow(async_fn_in_trait)]
pub trait InstantFormStore {
    /// One corpus page, keyset on `attestation_id`, every tier.
    async fn corpus_page(&self, after: Option<&str>, limit: u32)
        -> Result<Vec<Attestation>, Error>;
    /// Composers attested by `self_key_id` that cite any of `ids`.
    async fn own_composers_citing(
        &self,
        ids: &[String],
        self_key_id: &str,
    ) -> Result<Vec<Attestation>, Error>;
    /// Emit `input` through this node's ordinary emit door; the new row's id.
    async fn emit_own(&self, input: super::EmitAttestationInput) -> Result<String, Error>;
    /// Remove `row`'s projections, then remove it and record it in the ledger.
    async fn set_aside(
        &self,
        row: &Attestation,
        violation: &InstantFormViolation,
    ) -> Result<bool, Error>;
}

/// Run the pass over every stored attestation row.
///
/// # Errors
/// A store error on the corpus walk or the composer read. A refusal of one
/// row's re-statement or set-aside is counted, never returned.
pub async fn run_pass<S: InstantFormStore>(
    store: &S,
    self_key_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<InstantFormPass, Error> {
    let mut pass = InstantFormPass::default();
    let mut after: Option<String> = None;
    loop {
        let page = store.corpus_page(after.as_deref(), PAGE_SIZE).await?;
        let Some(last) = page.last() else {
            return Ok(pass);
        };
        after = Some(last.attestation_id.clone());
        pass.scanned += page.len() as u64;
        let failing: Vec<(Attestation, InstantFormViolation)> = page
            .into_iter()
            .filter_map(|r| signed_instant_form_violation(&r).map(|v| (r, v)))
            .collect();
        if failing.is_empty() {
            continue;
        }
        pass.violations += failing.len() as u64;
        let own_ids: Vec<String> = failing
            .iter()
            .filter(|(r, _)| r.attesting_key_id == self_key_id)
            .map(|(r, _)| r.attestation_id.clone())
            .collect();
        let restated: std::collections::BTreeSet<String> = if own_ids.is_empty() {
            std::collections::BTreeSet::new()
        } else {
            store
                .own_composers_citing(&own_ids, self_key_id)
                .await?
                .into_iter()
                .filter(|c| c.attestation_type == attestation_type::SUPERSEDES)
                .filter_map(|c| {
                    super::precedence::references_attestation_id_from_envelope(
                        &c.attestation_envelope,
                    )
                    .map(str::to_owned)
                })
                .collect()
        };
        for (row, violation) in failing {
            match disposition(&row, self_key_id, now) {
                Disposition::Heal if restated.contains(&row.attestation_id) => {
                    pass.already_healed += 1;
                }
                Disposition::Heal => match heal_input(&row) {
                    Ok(input) => match store.emit_own(input).await {
                        Ok(_) => pass.healed += 1,
                        Err(e) => {
                            pass.heal_refused += 1;
                            tracing::warn!(
                                attestation_id = %row.attestation_id,
                                member = %violation.member,
                                error = %e,
                                "CC 2.6.2: this node's row could not be re-stated in the \
                                 canonical form; it stays, and the next open retries"
                            );
                        }
                    },
                    Err(e) => {
                        pass.heal_refused += 1;
                        tracing::warn!(attestation_id = %row.attestation_id, error = %e,
                            "CC 2.6.2: this node's row has no instant to re-state");
                    }
                },
                Disposition::OwnLeft => pass.own_left += 1,
                Disposition::KeepInForce => pass.kept_in_force += 1,
                Disposition::SetAside => match store.set_aside(&row, &violation).await {
                    Ok(true) => pass.set_aside += 1,
                    Ok(false) => {}
                    Err(e) => tracing::warn!(
                        attestation_id = %row.attestation_id,
                        error = %e,
                        "CC 2.6.2: a refused row could not be set aside; the next open retries"
                    ),
                },
            }
        }
    }
}

/// The engine's store for the pass: the backend's corpus and set-aside doors,
/// and the engine's own emit door (software and hardware-hybrid signers alike).
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) struct EngineStore<'a, D> {
    pub(crate) engine: &'a crate::Engine,
    pub(crate) backend: &'a D,
}

#[cfg(any(feature = "postgres", feature = "sqlite"))]
impl<D> InstantFormStore for EngineStore<'_, D>
where
    D: super::attestation_admit::AttestationStore + Sync,
{
    async fn corpus_page(
        &self,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Vec<Attestation>, Error> {
        super::FederationDirectory::list_attestations_for_migration(self.backend, after, limit)
            .await
    }

    async fn own_composers_citing(
        &self,
        ids: &[String],
        self_key_id: &str,
    ) -> Result<Vec<Attestation>, Error> {
        super::FederationDirectory::list_composers_referencing_any(
            self.backend,
            ids,
            None,
            Some(self_key_id),
        )
        .await
    }

    async fn emit_own(&self, input: super::EmitAttestationInput) -> Result<String, Error> {
        self.engine.emit_attestation_self(input).await
    }

    async fn set_aside(
        &self,
        row: &Attestation,
        violation: &InstantFormViolation,
    ) -> Result<bool, Error> {
        super::FederationDirectory::purge_attestation_projections(
            self.backend,
            &row.attestation_id,
        )
        .await?;
        self.backend
            .set_aside_form_refused(row, &violation.member, &violation.value, chrono::Utc::now())
            .await
    }
}
