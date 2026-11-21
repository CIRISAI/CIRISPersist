//! v62.0.0 (AU-fix1; CC rc21 2.7.11, CC 2.6.1.9, CC 4.4.3.34) — **may a
//! unit an `admission:unit` row admits run on THIS host, at an instant**.
//!
//! [`admission_unit_runnable`] answers [`AdmissionAnswer::Runnable`] only
//! when EVERY leg of CC 2.7.11 that a store can read holds, read at the
//! instant the caller passes (never the wall clock: a present-tense host read
//! passes `now` at its own boundary):
//!
//! 1. **held** — a voice of a `scores` row of the family is held
//!    (`admission_none`, `no_row`);
//! 2. **concluded** — the row's fold concluded it: a counted row whose count
//!    is not met at the head it names is held (`count_short`), answered
//!    `admission_count_unmet`; a row held for any other fold condition is
//!    answered [`ADMISSION_UNIT_HELD`] (persist-local) with the fold reason
//!    as its detail;
//! 3. **the lease** — `asserted_at <= at < valid_until` (half-open, the K1
//!    ruling; CC 2.7.11 "The lease"): before it, `admission_none`
//!    [`LEASE_NOT_OPEN`] (persist-local detail); at or after it,
//!    `admission_none` `lease_ended`;
//! 4. **the end** — not retired by an entitled `withdraws` (its author's for
//!    an authored row, the same count for a counted one,
//!    `admission::check_admission_unit_withdrawal`) asserted by `at`
//!    (`admission_none`, `withdrawn`), through the one consolidated fold
//!    (`precedence::retired_ids`);
//! 5. **persons** — every voice is re-admitted under the key plane as it
//!    stands at `at`, and only a voice whose key is live and a person's
//!    counts: an authored row's author must still be one
//!    (`admission_issuer_not_person`, [`SIGNER_NOT_LIVE`]); a counted row is
//!    COUNTED AGAIN over those voices alone (`admission_count_unmet`);
//! 6. **standing** (CC 2.7.11 "Standing", CC 4.4.3.34 "The walk") — the
//!    author, or the group whose head a counted row names, IS the host
//!    owner's own key, or the owner's own live `trust:accepts` edges reach
//!    it, the class `admission` listed on every edge, within the edges'
//!    `trust_depth` and the cap of five hops; an edge signed by a program's
//!    key carries nothing. One person's row that names an effect stands only
//!    when that person IS the host owner. Otherwise
//!    `admission_issuer_not_reached` (detail [`NO_HOST_OWNER`],
//!    [`NOT_OWNER_HOST`] or [`NOT_REACHED`]);
//! 7. **the receipt** — the receipt leg, unchanged
//!    ([`super::receipts::admission_unit_receipt`]):
//!    `admission_receipt_missing` (`none`, `unverifiable`,
//!    `untrusted_service`).
//!
//! **Not a leg here: the halt.** CC 2.7.11 "The halt reaches every unit":
//! "the host permits no effect of any admitted unit. The host reads the latch
//! before every effect. Computing and reading continue." So the latch is read
//! at the EFFECT, by the host (`admission_halted`), not at the unit's start;
//! persist's answer here says whether the unit may run at all.
//!
//! **Not read here (BELIEVED gap, AU-fix1 notes): "at most
//! `unit_lease_max_secs` after the host first held it"** — no store column
//! records when this node first held a row; with `valid_until <= asserted_at +
//! unit_lease_max_secs` (the door's pure rule) the bound binds only a
//! future-dated row.

use std::collections::{BTreeSet, VecDeque};

use ciris_verify_core::cde::Value;

use super::names::RowId;
use super::receipts::{self, AdmissionReceipt};
use crate::federation::types::{identity_type, Attestation};
use crate::federation::{Error, FederationDirectory};

/// CC 2.7.11's table: no live row admits this digest (details `no_row`,
/// `lease_ended`, `withdrawn`).
pub const ADMISSION_NONE: &str = receipts::ADMISSION_NONE;
/// CC 2.7.11's table: held, the count not met at the head the row names.
pub const ADMISSION_COUNT_UNMET: &str = crate::federation::admission::ADMISSION_COUNT_UNMET;
/// CC 2.7.11's table: the author or group does not stand at this host, or
/// one person's row names an effect on a host that person does not own.
pub const ADMISSION_ISSUER_NOT_REACHED: &str = "admission_issuer_not_reached";
/// CC 2.7.11's table: a signer whose key is not a person's.
pub const ADMISSION_ISSUER_NOT_PERSON: &str =
    crate::federation::malformed_row::ADMISSION_ISSUER_NOT_PERSON;
/// CC 2.7.11's table: no receipt from a trusted service is held.
pub const ADMISSION_RECEIPT_MISSING: &str = receipts::ADMISSION_RECEIPT_MISSING;
/// **persist-local** — the row is held by its fold for a condition that is
/// not its count (the detail is the fold's reason token).
pub const ADMISSION_UNIT_HELD: &str = "admission_unit_held";

/// CC detail of `admission_none`: no row of this id is held.
pub const NO_ROW: &str = "no_row";
/// CC detail of `admission_none`: the lease has closed at the instant asked.
pub const LEASE_ENDED: &str = "lease_ended";
/// CC detail of `admission_none`: the row is withdrawn.
pub const WITHDRAWN: &str = "withdrawn";
/// **persist-local** detail of `admission_none`: the instant asked is before
/// the lease opens (`asserted_at`).
pub const LEASE_NOT_OPEN: &str = "lease_not_open";
/// **persist-local** detail of `admission_issuer_not_person`: a signer's key
/// is not live (or not a person's) at the instant asked.
pub const SIGNER_NOT_LIVE: &str = "signer_not_live";
/// **persist-local** detail of `admission_issuer_not_reached`: this node has
/// no node key or no (unambiguous) owner.
pub const NO_HOST_OWNER: &str = "no_host_owner";
/// **persist-local** detail of `admission_issuer_not_reached`: one person's
/// row names an effect, and that person does not own this host.
pub const NOT_OWNER_HOST: &str = "not_owner_host";
/// **persist-local** detail of `admission_unit_held`: a counted row's roster
/// head is not held here (the model's "waiting on the head").
pub const HEAD_UNHELD: &str = "head_unheld";
/// **persist-local** detail of `admission_issuer_not_reached`: the owner's
/// `admission` walk does not reach the author or group.
pub const NOT_REACHED: &str = "not_reached";

/// CC 4.4.3.34 / CC 4.1.1 — the cap of the acceptance walk, in hops.
pub const ADMISSION_WALK_MAX_HOPS: u64 = 5;
/// CC 2.7.11 / CC 4.4.3.34 — the acceptance class an admission stands by.
pub const ADMISSION_CLASS: &str = "admission";

/// One concluded `admission:unit` row, as the host answer and the live read
/// (AU-fix2's `admission_unit_rows`) show it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AdmissionUnitRow {
    /// The row id (64 hex).
    pub row_id: String,
    /// The row's `sub`: `canonical:sha256:{hex}` of the unit.
    pub sub: String,
    /// The unit digest (64 hex).
    pub unit: String,
    /// The admitted capabilities, as signed (a sorted set).
    pub capabilities: Vec<String>,
    /// The lease opens (POSIX ms).
    pub asserted_at_ms: u64,
    /// The lease closes (POSIX ms, exclusive).
    pub valid_until_ms: u64,
    /// The signers' identity-refs (every held voice's `iss`, distinct,
    /// sorted).
    pub signers: Vec<String>,
    /// `true`: one person's row (`author`); `false`: a counted row.
    pub authored: bool,
    /// The author (authored rows only).
    pub author: Option<String>,
    /// The group whose roster head a counted row names (counted rows only,
    /// when the head is held).
    pub group: Option<String>,
    /// The row's `cohort_scope` as signed (`federation` when absent).
    pub cohort_scope: String,
}

impl AdmissionUnitRow {
    /// Does the row name an effect capability (CC 2.7.11: the last five)?
    #[must_use]
    pub fn names_an_effect(&self) -> bool {
        self.capabilities
            .iter()
            .any(|c| super::payloads::ADMISSION_EFFECTS.contains(&c.as_str()))
    }

    /// The row as JSON for a host surface.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// The host answer for one `admission:unit` row at one instant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionAnswer {
    /// Every leg holds: the unit may run, with `row.capabilities`.
    Runnable {
        /// The row.
        row: AdmissionUnitRow,
        /// The Transparency Service whose receipt verified.
        service: String,
        /// The voice the receipt registered.
        statement_id: super::Digest32,
    },
    /// A leg fails: the unit does not run (or waits).
    NotRunnable {
        /// The token (module docs; CC's where CC names one).
        token: &'static str,
        /// The detail (CC's where CC names one, else persist-local).
        detail: String,
        /// The row, when one is held and read.
        row: Option<AdmissionUnitRow>,
    },
}

impl AdmissionAnswer {
    fn refused(
        token: &'static str,
        detail: impl Into<String>,
        row: Option<AdmissionUnitRow>,
    ) -> Self {
        Self::NotRunnable {
            token,
            detail: detail.into(),
            row,
        }
    }

    /// May the unit run?
    #[must_use]
    pub const fn is_runnable(&self) -> bool {
        matches!(self, Self::Runnable { .. })
    }

    /// The token: `None` when runnable.
    #[must_use]
    pub fn token(&self) -> Option<&'static str> {
        match self {
            Self::Runnable { .. } => None,
            Self::NotRunnable { token, .. } => Some(token),
        }
    }

    /// The detail: `None` when runnable.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Runnable { .. } => None,
            Self::NotRunnable { detail, .. } => Some(detail),
        }
    }

    /// The row the answer read, if any.
    #[must_use]
    pub fn row(&self) -> Option<&AdmissionUnitRow> {
        match self {
            Self::Runnable { row, .. } => Some(row),
            Self::NotRunnable { row, .. } => row.as_ref(),
        }
    }

    /// The answer as JSON for a host surface: `{"row_id", "runnable",
    /// "token", "detail", "service", "statement_id", "row"}`.
    #[must_use]
    pub fn to_json(&self, row_id: &RowId) -> serde_json::Value {
        let (service, statement_id) = match self {
            Self::Runnable {
                service,
                statement_id,
                ..
            } => (Some(service.clone()), Some(hex::encode(statement_id))),
            Self::NotRunnable { .. } => (None, None),
        };
        serde_json::json!({
            "row_id": row_id.hex(),
            "runnable": self.is_runnable(),
            "token": self.token(),
            "detail": self.detail(),
            "service": service,
            "statement_id": statement_id,
            "row": self.row().map(AdmissionUnitRow::to_json),
        })
    }
}

fn ms_instant(ms: u64) -> chrono::DateTime<chrono::Utc> {
    i64::try_from(ms)
        .ok()
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC)
}

fn ms_of(at: chrono::DateTime<chrono::Utc>) -> u64 {
    u64::try_from(at.timestamp_millis()).unwrap_or(0)
}

/// Is `statement` a `scores` statement (not a composer) of `admission:unit`?
fn is_admission_unit_row_statement(statement: &[u8]) -> bool {
    super::liveness::statement_parts(statement).is_some_and(|(p, _)| {
        p.get_int(-70002).and_then(Value::as_text) == Some(super::payloads::ADMISSION_UNIT_FAMILY)
            && p.get_int(-70001)
                .and_then(Value::as_text)
                .is_some_and(|t| !super::payloads::COMPOSER_ROW_TYPES.contains(&t))
    })
}

/// The CWT `iss` of a statement.
fn iss_of(statement: &[u8]) -> Option<String> {
    let (p, _) = super::liveness::statement_parts(statement)?;
    p.get_int(15)?.get_int(1)?.as_text().map(str::to_owned)
}

/// **The row a held `admission:unit` voice states** (every voice of one row
/// id shares the payload), with `signers` and `group` as given. `None` for
/// bytes that are no such row.
fn row_of(
    statement: &[u8],
    signers: Vec<String>,
    group: Option<String>,
) -> Option<AdmissionUnitRow> {
    let row_id = RowId::of_statement(statement)?;
    let (protected, payload) = super::liveness::statement_parts(statement)?;
    let sub = protected.get_int(15)?.get_int(2)?.as_text()?.to_owned();
    let unit = payload
        .get_text("unit")
        .and_then(Value::as_array)
        .and_then(|a| a.get(1))
        .and_then(Value::as_bytes)
        .map(hex::encode)?;
    let capabilities: Vec<String> = payload
        .get_text("capabilities")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_text)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let author = payload
        .get_text("author")
        .and_then(Value::as_text)
        .map(str::to_owned);
    Some(AdmissionUnitRow {
        row_id: row_id.hex(),
        sub,
        unit,
        capabilities,
        asserted_at_ms: payload.get_text("asserted_at").and_then(Value::as_u64)?,
        valid_until_ms: payload.get_text("valid_until").and_then(Value::as_u64)?,
        signers,
        authored: author.is_some(),
        author,
        group,
        cohort_scope: payload
            .get_text("cohort_scope")
            .and_then(Value::as_text)
            .unwrap_or(crate::federation::types::cohort_scope::FEDERATION)
            .to_owned(),
    })
}

/// The voices of `row_id` whose key is live and a person's at `at_ms`
/// (re-admitted under the key plane as it stands, as
/// `voices::primary_voice` re-admits a held voice), by `iss`.
async fn live_person_voices<F>(
    dir: &F,
    row_id: &RowId,
    voices: &[Vec<u8>],
    at_ms: u64,
) -> Result<BTreeSet<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut out = BTreeSet::new();
    for st in voices {
        let Some(kid) = super::ingest::statement_kid(st) else {
            continue;
        };
        let keys = super::ingest::held_keys_for(dir, st).await?;
        if super::door::admit_row(
            st,
            &keys,
            Some(&row_id.0),
            ciris_verify_core::edition2::family::SelectContext::default(),
        )
        .is_err()
        {
            continue;
        }
        let person = match keys.liveness(&kid, at_ms) {
            super::liveness::Liveness::Live(r) => r
                .identity_type
                .iter()
                .any(|t| t == identity_type::USER || t == identity_type::ACCORD_HOLDER),
            _ => false,
        };
        if person {
            if let Some(iss) = iss_of(st) {
                out.insert(iss);
            }
        }
    }
    Ok(out)
}

/// Is `key` a program's key (its record's `identity_type` holds `node` or
/// `agent`)? An edge it signs carries nothing on the walk (CC 2.7.11).
async fn is_program_key<F>(dir: &F, key: &str) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(dir.lookup_public_key(key).await?.is_some_and(|k| {
        identity_type::set_contains(&k.identity_type, identity_type::NODE)
            || identity_type::set_contains(&k.identity_type, identity_type::AGENT)
    }))
}

/// Does `edge` list the class `admission` (CC 4.4.3.34: `trust_classes`
/// absent is every class a charter declares, and no charter declares
/// `admission`, so an absent list never carries it)?
fn lists_admission(edge: &Attestation) -> bool {
    edge.attestation_envelope
        .get(super::typed::TRUST_CLASSES_MEMBER)
        .and_then(serde_json::Value::as_array)
        .is_some_and(|a| a.iter().any(|c| c.as_str() == Some(ADMISSION_CLASS)))
}

/// An edge's `trust_depth` (absent reads `0`; capped at the walk's cap).
fn trust_depth(edge: &Attestation) -> u64 {
    edge.attestation_envelope
        .get("trust_depth")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
        .min(ADMISSION_WALK_MAX_HOPS)
}

/// v62.0.0 (AU-fix1; CC 2.7.11 "Standing", CC 4.4.3.34 "The walk") — **does
/// `owner`'s `admission` walk reach `target` at `at`?** Breadth-first from
/// the owner's own live `trust:accepts` edges (signed by the key itself,
/// listing `admission`, unexpired at `at`); an onward hop only from a reached
/// key's own such edges, the remaining depth the lesser of what is left and
/// the edge's own `trust_depth`, within [`ADMISSION_WALK_MAX_HOPS`]; an edge
/// signed by a program's key carries nothing; each key visited once.
///
/// BELIEVED limit: an onward hop from a GROUP (a community or family) would
/// need the group's counted acceptance edges; the walk follows a key's own
/// authored edges only, so a group reached is a target, never a waypoint.
///
/// # Errors
/// Directory reads.
pub async fn admission_walk_reaches<F>(
    dir: &F,
    owner: &str,
    target: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::attestation_query::{AttestationQuery, FOLD_PAGE};
    use crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION;
    if owner == target {
        return Ok(true);
    }
    let mut seen: BTreeSet<String> = BTreeSet::from([owner.to_owned()]);
    let mut queue: VecDeque<(String, u64)> =
        VecDeque::from([(owner.to_owned(), ADMISSION_WALK_MAX_HOPS)]);
    while let Some((key, budget)) = queue.pop_front() {
        if is_program_key(dir, &key).await? {
            continue;
        }
        let (live, _) = super::typed::acceptance_edges(
            dir,
            AttestationQuery::by(&key, FOLD_PAGE).dimension(TRUST_ACCEPTS_DIMENSION),
        )
        .await?;
        for e in &live {
            if e.attesting_key_id != key
                || !lists_admission(e)
                || e.asserted_at > at
                || !e.expires_at.is_none_or(|t| t > at)
            {
                continue;
            }
            if e.attested_key_id == target {
                return Ok(true);
            }
            let left = budget.min(trust_depth(e));
            if left == 0 || !seen.insert(e.attested_key_id.clone()) {
                continue;
            }
            queue.push_back((e.attested_key_id.clone(), left - 1));
        }
    }
    Ok(false)
}

/// The concluded row's withdrawal: is it retired, by `at`, by an entitled
/// composer (the consolidated fold)?
async fn withdrawn_by<F>(
    dir: &F,
    row: &Attestation,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let composers: Vec<Attestation> = dir
        .list_composers_referencing_any(std::slice::from_ref(&row.attestation_id), None, None)
        .await?
        .into_iter()
        .filter(|c| c.asserted_at <= at)
        .collect();
    if composers.is_empty() {
        return Ok(false);
    }
    let refs: Vec<&Attestation> = std::iter::once(row).chain(composers.iter()).collect();
    Ok(crate::federation::precedence::retired_ids(&refs).contains(&row.attestation_id))
}

/// The host owner the answer is read for: `owner` when the caller names it
/// (Server's `owner_key_id`), else the owner this node's owner binding names
/// (`admission::owner_of_unmarked` over the node key; the owner signs, the
/// node cosigns, CC 3.2). `None`: no node key, no owner, or an ambiguous one.
async fn host_owner<F>(dir: &F, owner: Option<&str>) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    if let Some(o) = owner {
        return Ok(Some(o.to_owned()));
    }
    let Some(node) = dir.node_key_id() else {
        return Ok(None);
    };
    match crate::federation::admission::owner_of_unmarked(dir, &node).await {
        Ok(o) => Ok(o),
        Err(Error::AmbiguousNodeOwner { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Does `owner` (when there is one) stand behind `target` at `at`: the
/// owner's own key, or its `admission` walk ([`admission_walk_reaches`])?
async fn stands<F>(
    dir: &F,
    owner: Option<&str>,
    target: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    match owner {
        None => Ok(false),
        Some(o) => admission_walk_reaches(dir, o, target, at).await,
    }
}

/// v62.0.0 (AU-fix1; CC 2.7.11, the model's `one()` order,
/// `formal/admission/admission.py`) — **every leg but the receipt** for
/// `row_id` at `at` on a host owned by `owner` (or the node's own owner):
/// `Ok(row)` when they all hold, else the first failing leg's answer.
///
/// 1. a voice of a `scores` row of the family is held (`admission_none`,
///    `no_row`);
/// 2. AUTHORED: the author is a live person's key at `at`
///    (`admission_issuer_not_person`, `signer_not_live`); the host owner's
///    walk reaches the author (`admission_issuer_not_reached`,
///    `not_reached`); a row naming an effect admits only on a host the
///    author OWNS (`admission_issuer_not_reached`, `not_owner_host`; ownership,
///    not reach). COUNTED: the head it names is held (else WAITING,
///    `admission_unit_held` / `head_unheld`); the group is reached
///    (`admission_issuer_not_reached`, `not_reached`); the count is met over
///    the voices still live at `at` (WAITING, `admission_count_unmet`);
/// 3. the fold concluded it (`admission_count_unmet` while held
///    `count_short`, else `admission_unit_held` with the fold reason);
/// 4. the lease: `asserted_at <= at < valid_until` and `at` before
///    `unit_lease_max_secs` after this node FIRST held the row
///    (`ceg_statements.first_held_us`, written once at insert and never
///    updated, the least over its voices; `unit_lease_max_secs` is CC's
///    constant, constants.tsv l.44: 86 400 s;
///    `admission_none`, `lease_not_open` / `lease_ended`);
/// 5. not withdrawn by `at` (`admission_none`, `withdrawn`).
///
/// # Errors
/// Directory read failures.
async fn legs<F>(
    dir: &F,
    row_id: &RowId,
    at: chrono::DateTime<chrono::Utc>,
    owner: Option<&str>,
) -> Result<Result<AdmissionUnitRow, AdmissionAnswer>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let refused = |t: &'static str, d: &str, row: Option<AdmissionUnitRow>| {
        Ok(Err(AdmissionAnswer::refused(t, d, row)))
    };
    let at_ms = ms_of(at);
    // 1. Held.
    let voices: Vec<Vec<u8>> = dir
        .edition2_voices(row_id)
        .await?
        .into_iter()
        .filter(|v| is_admission_unit_row_statement(v) && RowId::of_statement(v) == Some(*row_id))
        .collect();
    let Some(first) = voices.first() else {
        return refused(ADMISSION_NONE, NO_ROW, None);
    };
    let all: Vec<String> = voices
        .iter()
        .filter_map(|v| iss_of(v))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let head = super::liveness::statement_parts(first)
        .and_then(|(_, p)| super::names::names_of(&p).ok())
        .and_then(|n| super::names::single(&n, "head"));
    let group = match &head {
        Some(h) => {
            crate::federation::admission::admission_head_group(dir.as_dyn_directory(), h).await?
        }
        None => None,
    };
    let Some(row) = row_of(first, all, group.clone()) else {
        return refused(ADMISSION_NONE, NO_ROW, None);
    };
    let owner = host_owner(dir, owner).await?;
    let live = live_person_voices(dir, row_id, &voices, at_ms).await?;
    // 2. The issuer: authored or counted (the model's order).
    let held = super::fold::why_held(dir, row_id).await?;
    let att = dir.get_attestation(&row_id.hex()).await?;
    match (row.author.clone(), head) {
        (Some(author), _) => {
            if !live.contains(&author) {
                return refused(ADMISSION_ISSUER_NOT_PERSON, SIGNER_NOT_LIVE, Some(row));
            }
            if !stands(dir, owner.as_deref(), &author, at).await? {
                let d = if owner.is_none() {
                    NO_HOST_OWNER
                } else {
                    NOT_REACHED
                };
                return refused(ADMISSION_ISSUER_NOT_REACHED, d, Some(row));
            }
            if row.names_an_effect() && owner.as_deref() != Some(author.as_str()) {
                return refused(ADMISSION_ISSUER_NOT_REACHED, NOT_OWNER_HOST, Some(row));
            }
        }
        (None, None) => return refused(ADMISSION_NONE, NO_ROW, Some(row)),
        (None, Some(h)) => {
            let Some(g) = group.as_deref() else {
                return refused(ADMISSION_UNIT_HELD, HEAD_UNHELD, Some(row));
            };
            if !stands(dir, owner.as_deref(), g, at).await? {
                let d = if owner.is_none() {
                    NO_HOST_OWNER
                } else {
                    NOT_REACHED
                };
                return refused(ADMISSION_ISSUER_NOT_REACHED, d, Some(row));
            }
            // The count over the voices still live at `at`.
            if let crate::federation::admission::HeadCount::Short { detail, .. } =
                crate::federation::admission::admission_unit_count_at_head(
                    dir.as_dyn_directory(),
                    ms_instant(row.asserted_at_ms),
                    &h,
                    &live,
                )
                .await?
            {
                return Ok(Err(AdmissionAnswer::refused(
                    ADMISSION_COUNT_UNMET,
                    detail,
                    Some(row),
                )));
            }
        }
    }
    // 3. Concluded.
    if let Some(h) = held {
        let token = if h.reason == super::fold::reason::COUNT_SHORT && !row.authored {
            ADMISSION_COUNT_UNMET
        } else {
            ADMISSION_UNIT_HELD
        };
        return Ok(Err(AdmissionAnswer::refused(
            token,
            format!("{}: {}", h.reason, h.detail),
            Some(row),
        )));
    }
    let Some(att) = att else {
        return refused(ADMISSION_UNIT_HELD, "not_concluded", Some(row));
    };
    // 4. The lease, on the host's clock: signed, and from first held.
    if at_ms < row.asserted_at_ms {
        return refused(ADMISSION_NONE, LEASE_NOT_OPEN, Some(row));
    }
    if at_ms >= row.valid_until_ms {
        return refused(ADMISSION_NONE, LEASE_ENDED, Some(row));
    }
    if let Some(first_us) = dir.edition2_first_held_us(row_id).await? {
        let first_ms = u64::try_from(first_us / 1_000).unwrap_or(0);
        if at_ms >= first_ms.saturating_add(super::payloads::UNIT_LEASE_MAX_MS) {
            return refused(ADMISSION_NONE, LEASE_ENDED, Some(row));
        }
    }
    // 5. The end.
    if withdrawn_by(dir, &att, at).await? {
        return refused(ADMISSION_NONE, WITHDRAWN, Some(row));
    }
    Ok(Ok(row))
}

/// v62.0.0 (AU-fix1; CC 2.7.11) — **may the unit `row_id`'s
/// `admission:unit` row admits run at `at` on a host owned by `owner`**
/// (Server's `owner_key_id`; `None`: the owner this node's owner binding
/// names): every leg of [`legs`], then the receipt
/// ([`super::receipts::admission_unit_receipt`]; `admission_receipt_missing`
/// waits). The first failing leg is the answer.
///
/// # Errors
/// Directory read failures.
pub async fn admission_unit_runnable<F>(
    dir: &F,
    row_id: &RowId,
    at: chrono::DateTime<chrono::Utc>,
    owner: Option<&str>,
) -> Result<AdmissionAnswer, Error>
where
    F: FederationDirectory + ?Sized,
{
    let row = match legs(dir, row_id, at, owner).await? {
        Ok(row) => row,
        Err(answer) => return Ok(answer),
    };
    Ok(
        match receipts::admission_unit_receipt(dir, row_id, at).await? {
            AdmissionReceipt::Runnable {
                service,
                statement_id,
            } => AdmissionAnswer::Runnable {
                row,
                service,
                statement_id,
            },
            r => AdmissionAnswer::refused(
                r.token().unwrap_or(ADMISSION_RECEIPT_MISSING),
                r.detail().unwrap_or_default(),
                Some(row),
            ),
        },
    )
}

/// v62.0.0 (AU-fix2; CC 2.7.11) — **the LIVE `admission:unit` rows about
/// `sub`** (`canonical:sha256:{hex}` of a unit) at `at`, on a host owned by
/// `owner` (Server's `owner_key_id`; `None`: this node's owner binding):
/// every held row whose legs ([`legs`]: issuer, standing at this host,
/// concluded, lease, not withdrawn) hold, in row-id order. A held row is
/// never listed. The receipt is [`admission_unit_runnable`]'s (a host asks it
/// before it runs a unit).
///
/// # Errors
/// Directory read failures (the first read is
/// `FederationDirectory::edition2_statements_about`).
pub async fn admission_unit_rows<F>(
    dir: &F,
    sub: &str,
    at: chrono::DateTime<chrono::Utc>,
    owner: Option<&str>,
) -> Result<Vec<AdmissionUnitRow>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let held = dir
        .edition2_statements_about(super::payloads::ADMISSION_UNIT_FAMILY, sub)
        .await?;
    let ids: BTreeSet<RowId> = held
        .iter()
        .filter(|st| is_admission_unit_row_statement(st))
        .filter_map(|st| RowId::of_statement(st))
        .collect();
    let mut out = Vec::new();
    for id in ids {
        if let Ok(row) = legs(dir, &id, at, owner).await? {
            out.push(row);
        }
    }
    Ok(out)
}
