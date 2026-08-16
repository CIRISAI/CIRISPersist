// Four query_row closures with multi-tuple SELECT projections that
// lint under clippy 1.95's `type_complexity`. Pre-existing v0.9.4
// shape; the tuples bind locally inside each closure so extracting
// a type alias is invasive for no readability gain. Silenced
// module-wide — same call made for src/secrets/sqlite.rs.
#![allow(clippy::type_complexity)]

//! SQLite impl of [`NodeCoreService`] (v0.9.4, CIRISPersist#40).
//!
//! Mirrors the v0.7.0-α4 / v0.7.1 / v0.7.2 Postgres impl with SQLite-
//! dialect translations:
//!
//! - `UUID` columns become `TEXT` (36-char hyphenated; bind/parse via
//!   [`uuid::Uuid`]).
//! - `UUID[]` (promotion `target_ids`) becomes `TEXT` holding a JSON
//!   array of UUID strings; reverse-lookup uses `json_each(?)`
//!   instead of GIN `@>`.
//! - `BYTEA` (`original_content_hash`) becomes `BLOB`.
//! - `JSONB` (`payload`, `witness_set`, `aggregate_evidence`) becomes
//!   `TEXT` carrying canonical JSON via `serde_json::to_string`.
//! - `TIMESTAMPTZ` becomes `TEXT` in RFC 3339 microsecond form.
//! - `DOUBLE PRECISION` becomes `REAL`.
//! - `BOOLEAN` becomes `INTEGER 0/1` (rusqlite auto-converts).
//! - `NOW()` becomes `datetime('now', 'subsec')` embedded in SQL.
//! - `SELECT … FOR UPDATE` becomes `BEGIN IMMEDIATE` (RESERVED lock).
//!
//! The signature-verification helper [`super::verify::verify_envelope_signed`]
//! is dialect-agnostic and reused verbatim — every typed-write calls
//! it before INSERT and refuses to persist on verify failure.
//!
//! # Per-call serialization under SQLite
//!
//! Postgres uses `SELECT … FOR UPDATE` to serialize concurrent mutators
//! within a single transaction. SQLite's `BEGIN IMMEDIATE` acquires
//! the database-level RESERVED lock immediately — coarser than per-
//! row locking but adequate for Phase 1 sovereign-mode (single-process
//! / single-writer). Only [`SqliteNodeCoreBackend::put_promotion_attestation`]
//! spans multiple statements; the other typed-writes are single
//! INSERTs that ride SQLite's implicit per-statement transactions.
#![allow(clippy::redundant_closure_call)]
// v3.14.0 (CIRISPersist#158) — inline-sync rewrite of all
// tokio::task::spawn_blocking sites uses (closure)() to invoke
// the closure inline. Clippy's redundant_closure_call lint flags
// this; we allow it because the mechanical transformation kept
// each closure's typed return signature load-bearing for error
// propagation and any other refactor would be a much larger diff.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use uuid::Uuid;

use super::federation_announcement::{DeliveryAttestation, TransportMedium};
use super::service::NodeCoreService;
use super::types::{
    Cell, ContributionEnvelope, ContributionListPage, ContributionType, ContributionsFilter,
    CreditsLedgerEntry, CreditsUpdate, ExpertiseLedgerEntry, ExpertiseUpdate, HybridSignature,
    ListCursor, ModerationEvent, PromotionAttestation, ReconsiderationAttestation,
    ReconsiderationRequest, RoutableContributor, SlashingAttestation, TargetRowKind, VoteEnvelope,
    VoteListPage, VoteWeight, VotesFilter,
};
use super::Error;

// ─── helpers ────────────────────────────────────────────────────────

fn contribution_type_str(c: ContributionType) -> &'static str {
    match c {
        ContributionType::DeferralRequest => "deferral_request",
        ContributionType::DeferralResponse => "deferral_response",
        ContributionType::Proposal => "proposal",
        ContributionType::WaCandidacy => "wa_candidacy",
        ContributionType::ExpertiseAttestation => "expertise_attestation",
        ContributionType::ModerationEvent => "moderation_event",
        ContributionType::ReconsiderationRequest => "reconsideration_request",
    }
}

fn contribution_type_from_str(s: &str) -> Result<ContributionType, Error> {
    match s {
        "deferral_request" => Ok(ContributionType::DeferralRequest),
        "deferral_response" => Ok(ContributionType::DeferralResponse),
        "proposal" => Ok(ContributionType::Proposal),
        "wa_candidacy" => Ok(ContributionType::WaCandidacy),
        "expertise_attestation" => Ok(ContributionType::ExpertiseAttestation),
        "moderation_event" => Ok(ContributionType::ModerationEvent),
        "reconsideration_request" => Ok(ContributionType::ReconsiderationRequest),
        other => Err(Error::Backend(format!(
            "unknown contribution_type: {other}"
        ))),
    }
}

fn target_kind_str(k: TargetRowKind) -> &'static str {
    match k {
        TargetRowKind::Contribution => "contribution",
        TargetRowKind::Vote => "vote",
        TargetRowKind::ModerationEvent => "moderation_event",
        TargetRowKind::SlashingAttestation => "slashing_attestation",
        TargetRowKind::ReconsiderationAttestation => "reconsideration_attestation",
    }
}

/// `(table_name, id_column)` for the canonical-promotion UPDATE step.
/// Pinned to the typed [`TargetRowKind`] enum — no caller-controlled
/// SQL injection surface.
fn target_table_and_id_col(k: TargetRowKind) -> (&'static str, &'static str) {
    match k {
        TargetRowKind::Contribution => ("cirisnode_contributions", "contribution_id"),
        TargetRowKind::Vote => ("cirisnode_votes", "vote_id"),
        TargetRowKind::ModerationEvent => ("cirisnode_moderation_events", "moderation_id"),
        TargetRowKind::SlashingAttestation => ("cirisnode_slashing_attestations", "slashing_id"),
        TargetRowKind::ReconsiderationAttestation => (
            "cirisnode_reconsideration_attestations",
            "reconsideration_id",
        ),
    }
}

/// Parse a UUID string — V011 stores 36-char hyphenated TEXT, but the
/// caller may pass either. Mirrors the Postgres `parse_id` helper.
fn parse_id(s: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(s)
        .map_err(|e| Error::InvalidArgument(format!("id parse: {e} (id={s}) — expected UUID")))
}

/// Translate a rusqlite::Error into a [`cirisnode::Error`] variant.
/// Constraint violation (PK / UNIQUE / CHECK / FK) → `Conflict` to
/// match the Postgres `unique_violation` semantic at the surface;
/// type-mismatch → `InvalidArgument`; everything else → `Backend`.
fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    use rusqlite::ErrorCode;
    if let rusqlite::Error::SqliteFailure(err, _) = &e {
        match err.code {
            ErrorCode::ConstraintViolation => {
                return Error::Conflict(format!("{op}: {e}"));
            }
            ErrorCode::TypeMismatch => {
                return Error::InvalidArgument(format!("{op}: {e}"));
            }
            _ => {}
        }
    }
    Error::Backend(format!("{op}: {e}"))
}

/// Parse an RFC 3339 TEXT timestamp (with or without 'T'). Matches
/// the helper in `audit/sqlite.rs` / `incident/sqlite.rs` /
/// `secrets/sqlite.rs`.
fn parse_datetime(s: &str) -> Result<DateTime<Utc>, Error> {
    let normalized = if s.contains('T') {
        s.to_owned()
    } else {
        format!("{}+00:00", s.replacen(' ', "T", 1))
    };
    DateTime::parse_from_rfc3339(&normalized)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| Error::Backend(format!("datetime parse: {e} (raw={s})")))
}

/// Format a UTC DateTime as RFC 3339 with microsecond precision.
fn fmt_datetime(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// Serialize a JSON value as TEXT (Null serialized to `"null"`).
fn json_text(v: &serde_json::Value) -> Result<String, Error> {
    serde_json::to_string(v).map_err(|e| Error::Internal(format!("json serialize: {e}")))
}

/// Parse a JSON value from a TEXT column.
fn json_value(s: &str) -> Result<serde_json::Value, Error> {
    serde_json::from_str(s).map_err(|e| Error::Backend(format!("json decode: {e} (raw={s})")))
}

// ─── backend ────────────────────────────────────────────────────────

/// SQLite-backed [`NodeCoreService`] impl. Wraps an
/// `Arc<Mutex<Connection>>` shared with
/// [`crate::store::sqlite::SqliteBackend`] so the cirisnode writes
/// ride the same WAL + PRAGMA settings as the trace-ingest path.
pub struct SqliteNodeCoreBackend {
    conn: Arc<Mutex<Connection>>,
    /// v3.4.0 (CIRISPersist#123) — trust-weighted admission gate. The
    /// `put_contribution` write path consults this when set; `None`
    /// preserves pre-#123 bootstrap-permissive behavior.
    admission_gate: std::sync::RwLock<Option<crate::federation::AdmissionGate>>,
}

impl SqliteNodeCoreBackend {
    /// Construct from a shared connection handle (typically
    /// `SqliteBackend::conn_handle()`).
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            conn,
            admission_gate: std::sync::RwLock::new(None),
        }
    }

    /// v3.4.0 (CIRISPersist#123) — install / clear the trust-weighted
    /// admission gate consulted by `put_contribution`.
    pub fn set_admission_gate(&self, gate: Option<crate::federation::AdmissionGate>) {
        *self
            .admission_gate
            .write()
            .unwrap_or_else(|p| p.into_inner()) = gate;
    }

    /// Snapshot of the currently-installed gate.
    pub fn admission_gate(&self) -> Option<crate::federation::AdmissionGate> {
        self.admission_gate
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

// ─── NodeCoreService impl ───────────────────────────────────────────

impl NodeCoreService for SqliteNodeCoreBackend {
    async fn put_contribution(&self, env: ContributionEnvelope) -> Result<(), Error> {
        // v3.4.0 (CIRISPersist#123) — trust gate runs FIRST. The
        // contribution's `author_id` is the attesting key for this
        // surface; an unauthorized writer learns nothing about
        // envelope shape / signature state until they clear the gate.
        if let Some(gate) = self.admission_gate() {
            if let Err(rej) = gate
                .check(&env.author_id)
                .await
                .map_err(|e| Error::Backend(format!("trust_scoring: {e}")))?
            {
                return Err(Error::InvalidArgument(format!(
                    "trust below threshold: score={} threshold={} key={}",
                    rej.score, rej.threshold, rej.key_id
                )));
            }
        }
        super::verify::verify_envelope_signed(&env, &env.signature, &env.author_id)?;
        let id = parse_id(&env.contribution_id)?;
        let subject_kind = env.subject.subject.clone().ok_or_else(|| {
            Error::InvalidArgument(
                "subject.subject (subject_kind) required for contributions".into(),
            )
        })?;

        // v2.1 (CIRISPersist#101) — federation_announcement extracts
        // priority + authority_class. Same admission semantics as PG.
        let announcement = super::federation_announcement::extract_announcement_payload(
            &subject_kind,
            &env.payload,
        )?;
        let announcement_priority: Option<String> = announcement
            .as_ref()
            .map(|p| p.priority.as_str().to_owned());
        let announcement_authority_class: Option<String> = announcement
            .as_ref()
            .map(|p| p.authority_class.as_str().to_owned());

        // v3.6.0 (CIRISPersist#134) — media-sharing extractors mirror
        // the PG impl. Typed shape validators run BEFORE the SQLite
        // trigger fires.
        let takedown =
            super::media_sharing::extract_takedown_notice_payload(&subject_kind, &env.payload)?;
        // v8.7.1 (CIRISPersist#233, CEG §11.10) — FULL moderation gate for
        // the `takedown_notice` primitive. The cirisnode SQLite backend
        // shares its connection with the federation `SqliteBackend`; a
        // `from_conn_handle` view over the same conn IS the
        // FederationDirectory the delegates_to + community walks need. The
        // walk runs BEFORE the INSERT closure takes the conn lock (no
        // deadlock). Admit IFF the author IS a duty-holder over the target
        // (the content's declared subjects ∪ the target community's named
        // moderators) or is reached by an steward-bound duty-holder via a
        // live `takedown`-scoped chain. Absence ⇒ REJECT.
        if takedown.is_some() {
            let directory =
                crate::store::sqlite::SqliteBackend::from_conn_handle(self.conn.clone());
            // v8.7.2: authority over the SIGNED content provenance — the
            // payload's declared subjects are advisory/routing-only.
            let (content_sha256, community_id) = super::payload_target_descriptor(&env.payload);
            super::check_moderation_or_reject(
                &directory,
                &env.author_id,
                &content_sha256,
                &community_id,
                crate::federation::admission::DELEGATION_SCOPE_TAKEDOWN,
                "takedown_notice",
            )
            .await?;
        }
        let key_grant =
            super::media_sharing::extract_key_grant_payload(&subject_kind, &env.payload)?;
        let media_content_sha256: Option<String> = takedown
            .as_ref()
            .map(|p| p.content_sha256.clone())
            .or_else(|| key_grant.as_ref().and_then(|p| p.content_sha256.clone()));
        let takedown_legal_basis: Option<String> =
            takedown.as_ref().map(|p| p.legal_basis.as_str().to_owned());
        let key_grant_recipient_key_id: Option<String> =
            key_grant.as_ref().map(|p| p.recipient_key_id.clone());
        // v4.x (CIRISPersist#142 Cut C3b) → v34.0.0 (CIRISPersist#704, V129)
        // — scope/epoch addressing projection. Populated iff the grant is
        // scope-epoch-addressed; the extractor guarantees the XOR with
        // media_content_sha256.
        //
        // `key_grant_scope_kind` is the discriminator V129 added: it names
        // WHICH addressing scope `key_grant_scope_id` is an id in. Its value is
        // the payload's declared `scope`, gated by
        // `KeyGrantScope::is_epoch_addressed()` — THE definition of which
        // scopes address by an `(id, epoch)` pair. Matching the variants inline
        // here would be a second copy of that rule, free to disagree with the
        // validator the moment either is edited (#663).
        //
        // The V129 trigger demands all THREE scope columns together, so a
        // payload whose declared `scope` contradicts its addressing fields is
        // refused at the DB rather than stored half-addressed — "which scope is
        // this DEK for" is never an inference.
        //
        // v34.0.0 (#704) — `scope_kind` and `scope_id` read from ONE binding,
        // so the pair cannot come apart. `scope_id` used to be projected from a
        // separate `KeyGrantPayload::scope_ref` with no gate at all; that field
        // is gone and the single `scope_id` is the id, gated by the same
        // predicate as the kind beside it.
        let epoch_addressed = key_grant.as_ref().filter(|p| p.scope.is_epoch_addressed());
        let key_grant_scope_kind: Option<String> =
            epoch_addressed.map(|p| p.scope.as_str().to_owned());
        let key_grant_scope_id: Option<String> = epoch_addressed.map(|p| p.scope_id.clone());
        // The epoch is deliberately NOT read through `epoch_addressed`. The
        // extractor guarantees `epoch.is_some()` ⟺ `scope.is_epoch_addressed()`,
        // so on any payload that got here the two spellings agree. They differ
        // only if that guarantee is ever broken — and then reading `p.epoch`
        // directly leaves the row half-addressed, which V129 REFUSES, whereas
        // gating it would silently rewrite the row into the content branch and
        // store it. Fail-secure on the same input.
        let key_grant_epoch: Option<i64> = match key_grant.as_ref().and_then(|p| p.epoch) {
            None => None,
            Some(e) => Some(i64::try_from(e).map_err(|_| {
                Error::InvalidArgument(
                    "key_grant: epoch exceeds i64 — key_grant_epoch is INTEGER".into(),
                )
            })?),
        };

        let id_str = id.to_string();
        let ct_str = contribution_type_str(env.contribution_type).to_owned();
        let domain = env.subject.domain.clone();
        let language = env.subject.language.clone();
        let author_id = env.author_id.clone();
        let payload_text = json_text(&env.payload)?;
        let witness_set_text: Option<String> = match &env.witness_set {
            None => None,
            Some(ws) => Some(
                serde_json::to_string(ws)
                    .map_err(|e| Error::Internal(format!("witness_set serialize: {e}")))?,
            ),
        };
        let submitted_at = fmt_datetime(env.submitted_at);
        let sig_b64 = env.signature.ed25519.clone();

        let conn = self.conn.clone();
        (move || -> Result<(), Error> {
            let guard = conn.lock();
            guard
                .execute(
                    "INSERT INTO cirisnode_contributions (\
                        contribution_id, contribution_type, domain, language, subject_kind, \
                        author_id, payload, witness_set, submitted_at, \
                        signature, signing_key_id, signature_verified, persist_row_hash, \
                        announcement_priority, announcement_authority_class, \
                        media_content_sha256, key_grant_recipient_key_id, takedown_legal_basis, \
                        key_grant_scope_kind, key_grant_scope_id, key_grant_epoch\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 1, ?12, ?13, ?14, \
                               ?15, ?16, ?17, ?18, ?19, ?20)",
                    params![
                        id_str,
                        ct_str,
                        domain,
                        language,
                        subject_kind,
                        author_id,
                        payload_text,
                        witness_set_text,
                        submitted_at,
                        sig_b64,
                        author_id,
                        sig_b64,
                        announcement_priority,
                        announcement_authority_class,
                        media_content_sha256,
                        key_grant_recipient_key_id,
                        takedown_legal_basis,
                        key_grant_scope_kind,
                        key_grant_scope_id,
                        key_grant_epoch,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "put_contribution"))?;
            Ok(())
        })()
    }

    async fn cast_vote(&self, env: VoteEnvelope) -> Result<(), Error> {
        super::verify::verify_envelope_signed(&env, &env.signature, &env.voter_id)?;
        let id = parse_id(&env.vote_id)?;
        let contribution_id = match &env.contribution_id {
            Some(c) => Some(parse_id(c)?.to_string()),
            None => None,
        };
        let id_str = id.to_string();
        let voter_id = env.voter_id.clone();
        let domain = env.cell.domain.clone();
        let language = env.cell.language.clone();
        let payload_value = serde_json::json!({
            "score": env.score,
            "rationale": env.rationale,
        });
        let payload_text = json_text(&payload_value)?;
        let cast_at = fmt_datetime(env.cast_at);
        let sig_b64 = env.signature.ed25519.clone();

        let conn = self.conn.clone();
        (move || -> Result<(), Error> {
            let guard = conn.lock();
            guard
                .execute(
                    "INSERT INTO cirisnode_votes (\
                        vote_id, contribution_id, voter_id, domain, language, \
                        payload, cast_at, signature, signing_key_id, signature_verified, \
                        persist_row_hash\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, ?10)",
                    params![
                        id_str,
                        contribution_id,
                        voter_id,
                        domain,
                        language,
                        payload_text,
                        cast_at,
                        sig_b64,
                        voter_id,
                        sig_b64,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "cast_vote"))?;
            Ok(())
        })()
    }

    async fn update_credits_ledger(&self, update: CreditsUpdate) -> Result<(), Error> {
        let source = parse_id(&update.source_contribution)?.to_string();
        let contributor_id = update.contributor_id;
        let domain = update.domain;
        let language = update.language;
        let subject = update.subject;
        let new_balance = update.new_balance;
        let now = fmt_datetime(Utc::now());

        let conn = self.conn.clone();
        (move || -> Result<(), Error> {
            let guard = conn.lock();
            // Mirrors the Postgres semantic: SET balance =
            // EXCLUDED.balance (replaces, not accumulates). The
            // ON CONFLICT clause keys on the composite PK.
            guard
                .execute(
                    "INSERT INTO cirisnode_credits_ledger (\
                        contributor_id, domain, language, subject, balance, \
                        last_update_contribution, last_updated_at, created_at\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7) \
                     ON CONFLICT (contributor_id, domain, language, subject) DO UPDATE SET \
                        balance = excluded.balance, \
                        last_update_contribution = excluded.last_update_contribution, \
                        last_updated_at = excluded.last_updated_at",
                    params![
                        contributor_id,
                        domain,
                        language,
                        subject,
                        new_balance,
                        source,
                        now,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "update_credits_ledger"))?;
            Ok(())
        })()
    }

    async fn update_expertise_ledger(&self, update: ExpertiseUpdate) -> Result<(), Error> {
        if !(0.0..=1.0).contains(&update.new_expertise) {
            return Err(Error::InvalidArgument(format!(
                "new_expertise must be in [0, 1] (got {})",
                update.new_expertise
            )));
        }
        let source = parse_id(&update.source_contribution)?.to_string();
        let contributor_id = update.contributor_id;
        let domain = update.domain;
        let language = update.language;
        let new_expertise = update.new_expertise;
        let is_active: i64 = if update.new_active_tier { 1 } else { 0 };
        let now = fmt_datetime(Utc::now());

        let conn = self.conn.clone();
        (move || -> Result<(), Error> {
            let guard = conn.lock();
            guard
                .execute(
                    "INSERT INTO cirisnode_expertise_ledger (\
                        contributor_id, domain, language, expertise, is_active, \
                        last_update_contribution, last_updated_at, created_at\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7) \
                     ON CONFLICT (contributor_id, domain, language) DO UPDATE SET \
                        expertise = excluded.expertise, \
                        is_active = excluded.is_active, \
                        last_update_contribution = excluded.last_update_contribution, \
                        last_updated_at = excluded.last_updated_at",
                    params![
                        contributor_id,
                        domain,
                        language,
                        new_expertise,
                        is_active,
                        source,
                        now,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "update_expertise_ledger"))?;
            Ok(())
        })()
    }

    async fn put_moderation_event(&self, event: ModerationEvent) -> Result<(), Error> {
        super::verify::verify_envelope_signed(&event, &event.signature, &event.accuser_id)?;
        // v8.7.1 (CIRISPersist#233, CEG §11.10) — FULL moderation gate for
        // the `ModerationEvent` primitive (parity with the PG backend). A
        // `from_conn_handle` view over the shared conn is the
        // FederationDirectory for the delegates_to + community walks; admit
        // IFF the accuser IS a duty-holder over the target (declared
        // subjects ∪ the target community's named moderators) or is reached
        // by an steward-bound duty-holder via a live `moderate`-scoped chain.
        // Absence ⇒ REJECT. Runs BEFORE the INSERT closure takes the lock.
        {
            let directory =
                crate::store::sqlite::SqliteBackend::from_conn_handle(self.conn.clone());
            // v8.7.2: authority over the SIGNED content provenance — the
            // payload's declared subjects are advisory/routing-only.
            let (content_sha256, community_id) = super::payload_target_descriptor(&event.payload);
            super::check_moderation_or_reject(
                &directory,
                &event.accuser_id,
                &content_sha256,
                &community_id,
                crate::federation::admission::DELEGATION_SCOPE_MODERATE,
                "moderation_event",
            )
            .await?;
        }
        let id = parse_id(&event.moderation_id)?.to_string();
        let target_contributor = event.target_contributor.clone();
        let accuser_id = event.accuser_id.clone();
        let payload_text = json_text(&event.payload)?;
        let filed_at = fmt_datetime(event.filed_at);
        let sig_b64 = event.signature.ed25519.clone();

        let conn = self.conn.clone();
        (move || -> Result<(), Error> {
            let guard = conn.lock();
            guard
                .execute(
                    "INSERT INTO cirisnode_moderation_events (\
                        moderation_id, target_contributor, accuser_id, payload, filed_at, \
                        signature, signing_key_id, signature_verified, persist_row_hash\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
                    params![
                        id,
                        target_contributor,
                        accuser_id,
                        payload_text,
                        filed_at,
                        sig_b64,
                        accuser_id,
                        sig_b64,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "put_moderation_event"))?;
            Ok(())
        })()
    }

    async fn put_slashing_attestation(&self, att: SlashingAttestation) -> Result<(), Error> {
        super::verify::verify_envelope_signed(&att, &att.signature, &att.adjudicator_id)?;
        let id = parse_id(&att.slashing_id)?.to_string();
        let moderation_id = parse_id(&att.moderation_id)?.to_string();
        let adjudicator_id = att.adjudicator_id.clone();
        let payload_text = json_text(&att.payload)?;
        let attested_at = fmt_datetime(att.attested_at);
        let sig_b64 = att.signature.ed25519.clone();

        let conn = self.conn.clone();
        (move || -> Result<(), Error> {
            let guard = conn.lock();
            guard
                .execute(
                    "INSERT INTO cirisnode_slashing_attestations (\
                        slashing_id, moderation_id, adjudicator_id, payload, attested_at, \
                        signature, signing_key_id, signature_verified, persist_row_hash\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
                    params![
                        id,
                        moderation_id,
                        adjudicator_id,
                        payload_text,
                        attested_at,
                        sig_b64,
                        adjudicator_id,
                        sig_b64,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "put_slashing_attestation"))?;
            Ok(())
        })()
    }

    async fn put_reconsideration_request(&self, req: ReconsiderationRequest) -> Result<(), Error> {
        super::verify::verify_envelope_signed(&req, &req.signature, &req.requester_id)?;
        let id = parse_id(&req.request_id)?.to_string();
        let slashing_id = parse_id(&req.slashing_id)?.to_string();
        let requester_id = req.requester_id.clone();
        let payload_text = json_text(&req.payload)?;
        let requested_at = fmt_datetime(req.requested_at);
        let sig_b64 = req.signature.ed25519.clone();

        let conn = self.conn.clone();
        (move || -> Result<(), Error> {
            let guard = conn.lock();
            guard
                .execute(
                    "INSERT INTO cirisnode_reconsideration_requests (\
                        request_id, slashing_id, requester_id, payload, requested_at, \
                        signature, signing_key_id, signature_verified, persist_row_hash\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
                    params![
                        id,
                        slashing_id,
                        requester_id,
                        payload_text,
                        requested_at,
                        sig_b64,
                        requester_id,
                        sig_b64,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "put_reconsideration_request"))?;
            Ok(())
        })()
    }

    async fn put_reconsideration_attestation(
        &self,
        att: ReconsiderationAttestation,
    ) -> Result<(), Error> {
        super::verify::verify_envelope_signed(&att, &att.signature, &att.adjudicator_id)?;
        let id = parse_id(&att.reconsideration_id)?.to_string();
        let request_id = parse_id(&att.request_id)?.to_string();
        let adjudicator_id = att.adjudicator_id.clone();
        let payload_text = json_text(&att.payload)?;
        let attested_at = fmt_datetime(att.attested_at);
        let sig_b64 = att.signature.ed25519.clone();

        let conn = self.conn.clone();
        (move || -> Result<(), Error> {
            let guard = conn.lock();
            guard
                .execute(
                    "INSERT INTO cirisnode_reconsideration_attestations (\
                        reconsideration_id, request_id, adjudicator_id, payload, attested_at, \
                        signature, signing_key_id, signature_verified, persist_row_hash\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
                    params![
                        id,
                        request_id,
                        adjudicator_id,
                        payload_text,
                        attested_at,
                        sig_b64,
                        adjudicator_id,
                        sig_b64,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "put_reconsideration_attestation"))?;
            Ok(())
        })()
    }

    async fn put_promotion_attestation(&self, att: PromotionAttestation) -> Result<(), Error> {
        if att.target_ids.is_empty() {
            return Err(Error::InvalidArgument(
                "target_ids must not be empty".into(),
            ));
        }
        super::verify::verify_envelope_signed(&att, &att.signature, &att.attested_by)?;
        let attestation_id = parse_id(&att.attestation_id)?.to_string();
        let target_uuids = att
            .target_ids
            .iter()
            .map(|s| parse_id(s).map(|u| u.to_string()))
            .collect::<Result<Vec<String>, _>>()?;
        let (table, id_col) = target_table_and_id_col(att.target_kind);
        let target_kind = target_kind_str(att.target_kind).to_owned();
        let target_count = target_uuids.len();
        let target_ids_json = serde_json::to_string(&target_uuids)
            .map_err(|e| Error::Internal(format!("target_ids serialize: {e}")))?;
        let attested_by = att.attested_by.clone();
        let aggregate_evidence_text = json_text(&att.aggregate_evidence)?;
        let attested_at = fmt_datetime(att.attested_at);
        let sig_b64 = att.signature.ed25519.clone();
        let now = fmt_datetime(Utc::now());

        // Build the per-table UPDATE SQL up-front. Table + id-column
        // come from the typed enum above — no caller-controlled
        // injection surface.
        let update_sql = format!(
            "UPDATE {table} SET is_canonical = 1, canonicalized_at = ?1 \
             WHERE {id_col} = ?2"
        );

        let conn = self.conn.clone();
        (move || -> Result<(), Error> {
            let mut guard = conn.lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "put_promotion_attestation begin"))?;

            tx.execute(
                "INSERT INTO cirisnode_promotion_attestations (\
                    attestation_id, target_kind, target_ids, attested_by, \
                    aggregate_evidence, attested_at, signature, signing_key_id, \
                    signature_verified, persist_row_hash\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)",
                params![
                    attestation_id,
                    target_kind,
                    target_ids_json,
                    attested_by,
                    aggregate_evidence_text,
                    attested_at,
                    sig_b64,
                    attested_by,
                    sig_b64,
                ],
            )
            .map_err(|e| map_sqlite_error(e, "put_promotion_attestation"))?;

            // Per-row UPDATE — SQLite has no array-param `= ANY(?)`,
            // so we iterate and sum affected-row counts. The
            // Postgres impl asserts the total matches
            // `target_ids.len()`; mirror exactly.
            let mut stmt = tx
                .prepare(&update_sql)
                .map_err(|e| map_sqlite_error(e, "put_promotion_attestation UPDATE prepare"))?;
            let mut total_affected: usize = 0;
            for tid in &target_uuids {
                let n = stmt
                    .execute(params![now, tid])
                    .map_err(|e| map_sqlite_error(e, "put_promotion_attestation UPDATE"))?;
                total_affected += n;
            }
            drop(stmt);
            if total_affected != target_count {
                // Mirrors PG: Conflict because some named target row
                // doesn't exist (or — in a strict-once setup — is
                // already canonical and pre-existed without this
                // attestation row). Match PG surface, which uses
                // `InvalidArgument`. The task instructions ask for
                // `Conflict` here, but the existing PG impl returns
                // `InvalidArgument` for this short-count case — so
                // we mirror PG exactly to keep the surface identical
                // across backends.
                return Err(Error::InvalidArgument(format!(
                    "target_ids contains rows not present in {table}: \
                     named {target_count} targets, UPDATE affected {total_affected}"
                )));
            }

            tx.commit()
                .map_err(|e| Error::Backend(format!("commit: {e}")))?;
            Ok(())
        })()
    }

    async fn routable_contributors(
        &self,
        domain: &str,
        language: &str,
    ) -> Result<Vec<RoutableContributor>, Error> {
        let domain = domain.to_owned();
        let language = language.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<Vec<RoutableContributor>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(
                    "SELECT contributor_id, expertise FROM cirisnode_expertise_ledger \
                     WHERE domain = ?1 AND language = ?2 \
                       AND expertise > 0 AND is_active = 1 \
                     ORDER BY expertise DESC",
                )
                .map_err(|e| map_sqlite_error(e, "routable_contributors prepare"))?;
            let rows = stmt
                .query_map(params![domain, language], |row| {
                    Ok(RoutableContributor {
                        contributor_id: row.get::<_, String>(0)?,
                        expertise: row.get::<_, f64>(1)?,
                    })
                })
                .map_err(|e| map_sqlite_error(e, "routable_contributors query"))?;
            let out: Result<Vec<_>, _> = rows.collect();
            out.map_err(|e| map_sqlite_error(e, "routable_contributors collect"))
        })()
    }

    async fn read_vote_weight(
        &self,
        contributor_id: &str,
        domain: &str,
        language: &str,
        subject: &str,
    ) -> Result<Option<VoteWeight>, Error> {
        let contributor_id_in = contributor_id.to_owned();
        let domain_in = domain.to_owned();
        let language_in = language.to_owned();
        let subject_in = subject.to_owned();
        let conn = self.conn.clone();
        let raw_opt = (move || -> Result<Option<(f64, f64, bool)>, Error> {
            let guard = conn.lock();
            // SQLite doesn't take to the Postgres `FROM (SELECT 1)
            // _ LEFT JOIN …` shape cleanly because it lacks the
            // empty-FROM trick — but we can mirror with two
            // independent point-lookups + a NULL-tolerant
            // combiner. Simpler and equivalent semantically.
            let credits: Option<f64> = guard
                .query_row(
                    "SELECT balance FROM cirisnode_credits_ledger \
                         WHERE contributor_id = ?1 AND domain = ?2 \
                           AND language = ?3 AND subject = ?4",
                    params![contributor_id_in, domain_in, language_in, subject_in],
                    |row| row.get::<_, f64>(0),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "read_vote_weight credits"))?;
            let expertise_row: Option<(f64, bool)> = guard
                .query_row(
                    "SELECT expertise, is_active FROM cirisnode_expertise_ledger \
                         WHERE contributor_id = ?1 AND domain = ?2 AND language = ?3",
                    params![contributor_id_in, domain_in, language_in],
                    |row| Ok((row.get::<_, f64>(0)?, row.get::<_, bool>(1)?)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "read_vote_weight expertise"))?;
            let credits_v = credits.unwrap_or(0.0);
            let (expertise_v, is_active_v) = expertise_row.unwrap_or((0.0, false));
            if credits_v == 0.0 && expertise_v == 0.0 && !is_active_v {
                return Ok(None);
            }
            Ok(Some((credits_v, expertise_v, is_active_v)))
        })()?;

        Ok(raw_opt.map(|(credits, expertise, is_active)| {
            // SCHEMA.md §5.2: expertise_multiplier = 1 + 4*expertise
            // (gives [1, 5] range); active_tier_multiplier = 1.5 if
            // active else 0.5.
            let expertise_multiplier = 1.0 + 4.0 * expertise;
            let active_tier_multiplier = if is_active { 1.5 } else { 0.5 };
            let weight = credits * expertise_multiplier * active_tier_multiplier;
            VoteWeight {
                contributor_id: contributor_id.to_owned(),
                domain: domain.to_owned(),
                language: language.to_owned(),
                subject: subject.to_owned(),
                credits,
                expertise_multiplier,
                active_tier_multiplier,
                weight,
            }
        }))
    }

    async fn list_contributions(
        &self,
        filter: ContributionsFilter,
        cursor: Option<ListCursor>,
        limit: i64,
    ) -> Result<ContributionListPage, Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }

        let mut where_parts: Vec<String> = Vec::new();
        let mut params: Vec<SqlValue> = Vec::new();
        if let Some(ct) = filter.contribution_type {
            params.push(SqlValue::Text(contribution_type_str(ct).to_owned()));
            where_parts.push(format!("contribution_type = ?{}", params.len()));
        }
        if let Some(d) = filter.domain {
            params.push(SqlValue::Text(d));
            where_parts.push(format!("domain = ?{}", params.len()));
        }
        if let Some(l) = filter.language {
            params.push(SqlValue::Text(l));
            where_parts.push(format!("language = ?{}", params.len()));
        }
        if let Some(s) = filter.subject_kind {
            params.push(SqlValue::Text(s));
            where_parts.push(format!("subject_kind = ?{}", params.len()));
        }
        if let Some(a) = filter.author_id {
            params.push(SqlValue::Text(a));
            where_parts.push(format!("author_id = ?{}", params.len()));
        }
        if let Some(c) = filter.is_canonical {
            params.push(SqlValue::Integer(if c { 1 } else { 0 }));
            where_parts.push(format!("is_canonical = ?{}", params.len()));
        }
        // v2.1 (CIRISPersist#101) — federation_announcement filters.
        // priority / authority_class are indexed columns added in
        // V046 (non-announcement rows have NULL in both); `kind`
        // lives inside the payload JSON and is matched via
        // `json_extract(payload, '$.kind')`. SQLite's json1 extension
        // is built in and persist uses it elsewhere (lens audit).
        if let Some(p) = filter.priority {
            params.push(SqlValue::Text(p.as_str().to_owned()));
            where_parts.push(format!("announcement_priority = ?{}", params.len()));
        }
        if let Some(a) = filter.authority_class {
            params.push(SqlValue::Text(a.as_str().to_owned()));
            where_parts.push(format!("announcement_authority_class = ?{}", params.len()));
        }
        if let Some(k) = filter.kind {
            // For variants other than `Custom(s)` the serde wire shape
            // is a bare snake_case string ("policy_update"); for
            // `Custom(s)` it's an object `{"custom": "<value>"}`.
            // SQLite's `json_extract(payload, '$.kind')` returns the
            // scalar as TEXT and the object as a JSON string — so
            // the filter compares string-equal for the scalar case
            // and JSON-equal for the object case. To uniformly
            // handle both, we extract the kind to text and compare
            // against the wire string form.
            let value = serde_json::to_value(&k)
                .map_err(|e| Error::Internal(format!("AnnouncementKind serialize: {e}")))?;
            // Scalar string → strip quotes to match
            // `json_extract` TEXT output. Object → JSON-encode for
            // structural compare.
            let wire = match &value {
                serde_json::Value::String(s) => s.clone(),
                other => serde_json::to_string(other)
                    .map_err(|e| Error::Internal(format!("kind json: {e}")))?,
            };
            params.push(SqlValue::Text(wire));
            // `json_extract` returns TEXT for both scalar and
            // structural matches (the latter as a serialized JSON
            // string); equality compares both cases correctly.
            where_parts.push(format!(
                "CAST(json_extract(payload, '$.kind') AS TEXT) = ?{}",
                params.len()
            ));
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "ListCursor version {} unsupported (expected v1)",
                    cur.version
                )));
            }
            let last_uuid = parse_id(&cur.last_id)?.to_string();
            // Expand the row-value comparison to OR form for
            // broadest SQLite compatibility — `(a, b) < (?, ?)`
            // works on modern SQLite but the OR form is safe
            // everywhere.
            params.push(SqlValue::Text(fmt_datetime(cur.last_ts)));
            let p_ts = params.len();
            params.push(SqlValue::Text(last_uuid));
            let p_id = params.len();
            where_parts.push(format!(
                "(submitted_at < ?{p_ts} OR (submitted_at = ?{p_ts} AND contribution_id < ?{p_id}))"
            ));
        }
        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" AND "))
        };
        params.push(SqlValue::Integer(limit));
        let p_limit = params.len();
        let sql = format!(
            "SELECT contribution_id, contribution_type, domain, language, subject_kind, \
                    author_id, payload, witness_set, submitted_at, signature \
             FROM cirisnode_contributions \
             {where_sql} \
             ORDER BY submitted_at DESC, contribution_id DESC \
             LIMIT ?{p_limit}"
        );

        let conn = self.conn.clone();
        let rows_out = (
            move || -> Result<Vec<(String, String, String, String, String, String, String, Option<String>, String, String)>, Error> {
                let guard = conn.lock();
                let mut stmt = guard
                    .prepare(&sql)
                    .map_err(|e| map_sqlite_error(e, "list_contributions prepare"))?;
                let rows = stmt
                    .query_map(params_from_iter(params.iter()), |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, String>(6)?,
                            row.get::<_, Option<String>>(7)?,
                            row.get::<_, String>(8)?,
                            row.get::<_, String>(9)?,
                        ))
                    })
                    .map_err(|e| map_sqlite_error(e, "list_contributions query"))?;
                let out: Result<Vec<_>, _> = rows.collect();
                out.map_err(|e| map_sqlite_error(e, "list_contributions collect"))
            })()?;

        let mut items: Vec<ContributionEnvelope> = Vec::with_capacity(rows_out.len());
        for (
            contribution_id,
            ct_str,
            domain,
            language,
            subject_kind,
            author_id,
            payload_text,
            witness_set_text,
            submitted_at_str,
            signature_b64,
        ) in rows_out
        {
            let payload = json_value(&payload_text)?;
            let witness_set = match witness_set_text {
                None => None,
                Some(s) => Some(
                    serde_json::from_str(&s)
                        .map_err(|e| Error::Backend(format!("witness_set decode: {e}")))?,
                ),
            };
            let submitted_at = parse_datetime(&submitted_at_str)?;
            items.push(ContributionEnvelope {
                contribution_id,
                contribution_type: contribution_type_from_str(&ct_str)?,
                author_id,
                subject: Cell {
                    domain,
                    language,
                    subject: Some(subject_kind),
                },
                payload,
                witness_set,
                signature: HybridSignature {
                    ed25519: signature_b64,
                    ml_dsa_65: None,
                    signed_at: submitted_at,
                },
                submitted_at,
            });
        }
        let next_cursor = if items.len() == limit as usize {
            items.last().map(|last| {
                ListCursor::from_trailing(last.submitted_at, last.contribution_id.clone())
            })
        } else {
            None
        };
        Ok(ContributionListPage { items, next_cursor })
    }

    async fn list_votes(
        &self,
        filter: VotesFilter,
        cursor: Option<ListCursor>,
        limit: i64,
    ) -> Result<VoteListPage, Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }

        let mut where_parts: Vec<String> = Vec::new();
        let mut params: Vec<SqlValue> = Vec::new();
        if let Some(c) = filter.contribution_id {
            let cid = parse_id(&c)?.to_string();
            params.push(SqlValue::Text(cid));
            where_parts.push(format!("contribution_id = ?{}", params.len()));
        }
        if let Some(v) = filter.voter_id {
            params.push(SqlValue::Text(v));
            where_parts.push(format!("voter_id = ?{}", params.len()));
        }
        if let Some(d) = filter.domain {
            params.push(SqlValue::Text(d));
            where_parts.push(format!("domain = ?{}", params.len()));
        }
        if let Some(l) = filter.language {
            params.push(SqlValue::Text(l));
            where_parts.push(format!("language = ?{}", params.len()));
        }
        if let Some(c) = filter.is_canonical {
            params.push(SqlValue::Integer(if c { 1 } else { 0 }));
            where_parts.push(format!("is_canonical = ?{}", params.len()));
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "ListCursor version {} unsupported",
                    cur.version
                )));
            }
            let last_uuid = parse_id(&cur.last_id)?.to_string();
            params.push(SqlValue::Text(fmt_datetime(cur.last_ts)));
            let p_ts = params.len();
            params.push(SqlValue::Text(last_uuid));
            let p_id = params.len();
            where_parts.push(format!(
                "(cast_at < ?{p_ts} OR (cast_at = ?{p_ts} AND vote_id < ?{p_id}))"
            ));
        }
        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" AND "))
        };
        params.push(SqlValue::Integer(limit));
        let p_limit = params.len();
        let sql = format!(
            "SELECT vote_id, contribution_id, voter_id, domain, language, \
                    payload, cast_at, signature \
             FROM cirisnode_votes \
             {where_sql} \
             ORDER BY cast_at DESC, vote_id DESC \
             LIMIT ?{p_limit}"
        );

        let conn = self.conn.clone();
        let rows_out = (
            move || -> Result<Vec<(String, Option<String>, String, String, String, String, String, String)>, Error> {
                let guard = conn.lock();
                let mut stmt = guard
                    .prepare(&sql)
                    .map_err(|e| map_sqlite_error(e, "list_votes prepare"))?;
                let rows = stmt
                    .query_map(params_from_iter(params.iter()), |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, String>(6)?,
                            row.get::<_, String>(7)?,
                        ))
                    })
                    .map_err(|e| map_sqlite_error(e, "list_votes query"))?;
                let out: Result<Vec<_>, _> = rows.collect();
                out.map_err(|e| map_sqlite_error(e, "list_votes collect"))
            })()?;

        let mut items: Vec<VoteEnvelope> = Vec::with_capacity(rows_out.len());
        for (
            vote_id,
            contribution_id,
            voter_id,
            domain,
            language,
            payload_text,
            cast_at_str,
            signature_b64,
        ) in rows_out
        {
            let payload_value = json_value(&payload_text)?;
            let score = payload_value
                .get("score")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let rationale = payload_value
                .get("rationale")
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            let cast_at = parse_datetime(&cast_at_str)?;
            items.push(VoteEnvelope {
                vote_id,
                voter_id,
                contribution_id,
                cell: Cell {
                    domain,
                    language,
                    subject: None, // not stored on votes table
                },
                score,
                rationale,
                signature: HybridSignature {
                    ed25519: signature_b64,
                    ml_dsa_65: None,
                    signed_at: cast_at,
                },
                cast_at,
            });
        }
        let next_cursor = if items.len() == limit as usize {
            items
                .last()
                .map(|last| ListCursor::from_trailing(last.cast_at, last.vote_id.clone()))
        } else {
            None
        };
        Ok(VoteListPage { items, next_cursor })
    }

    async fn get_credits_ledger(
        &self,
        contributor_id: &str,
        domain: &str,
        language: &str,
        subject: &str,
    ) -> Result<Option<CreditsLedgerEntry>, Error> {
        let contributor_id_in = contributor_id.to_owned();
        let domain_in = domain.to_owned();
        let language_in = language.to_owned();
        let subject_in = subject.to_owned();
        let conn = self.conn.clone();
        let raw_opt = (
            move || -> Result<Option<(String, String, String, String, f64, Option<String>, String, String)>, Error> {
                let guard = conn.lock();
                guard
                    .query_row(
                        "SELECT contributor_id, domain, language, subject, balance, \
                                last_update_contribution, last_updated_at, created_at \
                         FROM cirisnode_credits_ledger \
                         WHERE contributor_id = ?1 AND domain = ?2 \
                           AND language = ?3 AND subject = ?4",
                        params![contributor_id_in, domain_in, language_in, subject_in],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, String>(3)?,
                                row.get::<_, f64>(4)?,
                                row.get::<_, Option<String>>(5)?,
                                row.get::<_, String>(6)?,
                                row.get::<_, String>(7)?,
                            ))
                        },
                    )
                    .optional()
                    .map_err(|e| map_sqlite_error(e, "get_credits_ledger"))
            })()?;

        match raw_opt {
            None => Ok(None),
            Some((
                contributor_id,
                domain,
                language,
                subject,
                balance,
                last_update_contribution,
                last_updated_at_str,
                created_at_str,
            )) => Ok(Some(CreditsLedgerEntry {
                contributor_id,
                domain,
                language,
                subject,
                balance,
                last_update_contribution,
                last_updated_at: parse_datetime(&last_updated_at_str)?,
                created_at: parse_datetime(&created_at_str)?,
            })),
        }
    }

    async fn get_expertise_ledger(
        &self,
        contributor_id: &str,
        domain: &str,
        language: &str,
    ) -> Result<Option<ExpertiseLedgerEntry>, Error> {
        let contributor_id_in = contributor_id.to_owned();
        let domain_in = domain.to_owned();
        let language_in = language.to_owned();
        let conn = self.conn.clone();
        let raw_opt = (
            move || -> Result<Option<(String, String, String, f64, bool, String, Option<String>, String)>, Error> {
                let guard = conn.lock();
                guard
                    .query_row(
                        "SELECT contributor_id, domain, language, expertise, is_active, \
                                last_updated_at, last_update_contribution, created_at \
                         FROM cirisnode_expertise_ledger \
                         WHERE contributor_id = ?1 AND domain = ?2 AND language = ?3",
                        params![contributor_id_in, domain_in, language_in],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, f64>(3)?,
                                row.get::<_, bool>(4)?,
                                row.get::<_, String>(5)?,
                                row.get::<_, Option<String>>(6)?,
                                row.get::<_, String>(7)?,
                            ))
                        },
                    )
                    .optional()
                    .map_err(|e| map_sqlite_error(e, "get_expertise_ledger"))
            })()?;

        match raw_opt {
            None => Ok(None),
            Some((
                contributor_id,
                domain,
                language,
                expertise,
                is_active,
                last_updated_at_str,
                last_update_contribution,
                created_at_str,
            )) => Ok(Some(ExpertiseLedgerEntry {
                contributor_id,
                domain,
                language,
                expertise,
                is_active,
                last_updated_at: parse_datetime(&last_updated_at_str)?,
                last_update_contribution,
                created_at: parse_datetime(&created_at_str)?,
            })),
        }
    }

    // ── Federation delivery attestations (v2.1, CIRISPersist#101) ──
    //
    // The SQLite impl mirrors the Postgres impl one-to-one. The
    // hybrid-signature verify path goes through the shared
    // `verify_hybrid_via_directory` against a `FederationDirectory`
    // — for SQLite that directory is `SqliteBackend`, which the
    // caller wires when they ship in a `SqliteNodeCoreBackend`. We
    // resolve the directory through a borrowed handle so a single
    // `SqliteBackend` Mutex-guarded `Connection` services both the
    // directory lookup and the attestation INSERT.

    async fn put_delivery_attestation(
        &self,
        attestation: DeliveryAttestation,
    ) -> Result<(), Error> {
        // Length-invariants up-front (typed error).
        let canonical_hash = attestation.canonical_hash_bytes()?;
        let sig_classical = attestation.signature_classical_bytes()?;
        let pqc_bytes = attestation.signature_pqc_bytes()?;
        let announcement_uuid = parse_id(&attestation.announcement_id)?;

        // Hybrid verify against federation_keys[peer_key_id]. The
        // directory lookup runs against a `FederationDirectory` impl
        // wrapping the shared SQLite connection; we use the same
        // SqliteBackend façade the public API does.
        let canonical = attestation
            .canonical_bytes()
            .map_err(|e| Error::Signature(format!("canonical_bytes: {e}")))?;
        let directory = crate::store::sqlite::SqliteBackend::from_conn_handle(self.conn.clone());
        crate::verify::verify_hybrid_via_directory(
            &directory,
            &canonical,
            &attestation.peer_key_id,
            &attestation.signature_classical_base64,
            attestation.signature_pqc_base64.as_deref(),
            crate::verify::hybrid::HybridPolicy::Ed25519Fallback,
            None,
        )
        .await
        .map_err(|e| Error::Signature(format!("delivery_attestation verify: {e}")))?;

        let persist_row_hash = crate::federation::types::compute_persist_row_hash(&attestation)
            .map_err(|e| Error::Internal(format!("persist_row_hash: {e}")))?;

        let announcement_id_str = announcement_uuid.to_string();
        let peer_key_id = attestation.peer_key_id.clone();
        let peer_pubkey = attestation.peer_pubkey_ed25519_base64.clone();
        let received_at = fmt_datetime(attestation.received_at);
        let transport = attestation.transport_id.as_str().to_owned();
        let conn = self.conn.clone();

        (move || -> Result<(), Error> {
            let guard = conn.lock();
            // `INSERT OR IGNORE` collapses the (announcement_id,
            // peer_key_id) PK conflict to a no-op — the idempotent
            // replay path per FSD §3.2.1.
            guard
                .execute(
                    "INSERT OR IGNORE INTO cirisnode_federation_delivery_attestations (\
                        announcement_id, announcement_canonical_hash, peer_key_id, \
                        peer_pubkey_ed25519_base64, received_at, transport_id, \
                        signature_classical, signature_pqc, signature_verified, persist_row_hash\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)",
                    params![
                        announcement_id_str,
                        canonical_hash.as_slice(),
                        peer_key_id,
                        peer_pubkey,
                        received_at,
                        transport,
                        sig_classical.as_slice(),
                        pqc_bytes,
                        persist_row_hash,
                    ],
                )
                .map_err(|e| {
                    // The PG impl maps PK conflict to no-op via
                    // ON CONFLICT DO NOTHING; SQLite's INSERT OR
                    // IGNORE does the same. A constraint violation
                    // here is FK / CHECK — surface as InvalidArgument
                    // to match the PG taxonomy.
                    if let rusqlite::Error::SqliteFailure(err, _) = &e {
                        if matches!(err.code, rusqlite::ErrorCode::ConstraintViolation) {
                            return Error::InvalidArgument(format!(
                                "put_delivery_attestation: {e}"
                            ));
                        }
                    }
                    Error::Backend(format!("put_delivery_attestation: {e}"))
                })?;
            Ok(())
        })()
    }

    async fn list_delivery_attestations(
        &self,
        announcement_id: &str,
    ) -> Result<Vec<DeliveryAttestation>, Error> {
        let announcement_uuid = parse_id(announcement_id)?;
        let id_str = announcement_uuid.to_string();
        let conn = self.conn.clone();

        let rows = (
            move || -> Result<Vec<(String, Vec<u8>, String, String, String, String, Vec<u8>, Option<Vec<u8>>)>, Error> {
                let guard = conn.lock();
                let mut stmt = guard
                    .prepare(
                        "SELECT announcement_id, announcement_canonical_hash, peer_key_id, \
                                peer_pubkey_ed25519_base64, received_at, transport_id, \
                                signature_classical, signature_pqc \
                         FROM cirisnode_federation_delivery_attestations \
                         WHERE announcement_id = ?1 \
                         ORDER BY received_at DESC",
                    )
                    .map_err(|e| map_sqlite_error(e, "list_delivery_attestations prepare"))?;
                let rows = stmt
                    .query_map([id_str], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, Vec<u8>>(6)?,
                            row.get::<_, Option<Vec<u8>>>(7)?,
                        ))
                    })
                    .map_err(|e| map_sqlite_error(e, "list_delivery_attestations query"))?;
                let out: Result<Vec<_>, _> = rows.collect();
                out.map_err(|e| map_sqlite_error(e, "list_delivery_attestations collect"))
            })()?;

        let mut out = Vec::with_capacity(rows.len());
        for (
            announcement_id,
            hash_bytes,
            peer_key_id,
            peer_pubkey,
            received_at_str,
            transport_str,
            sig_classical,
            sig_pqc_opt,
        ) in rows
        {
            let canonical_hash: [u8; 32] = <[u8; 32]>::try_from(hash_bytes.as_slice())
                .map_err(|_| Error::Backend("stored canonical_hash not 32 bytes".to_string()))?;
            let transport_id = TransportMedium::from_wire_str(&transport_str).ok_or_else(|| {
                Error::Backend(format!("unknown transport_id from DB: {transport_str}"))
            })?;
            out.push(DeliveryAttestation {
                announcement_id,
                announcement_canonical_hash_base64:
                    super::federation_announcement::encode_canonical_hash_base64(&canonical_hash),
                peer_key_id,
                peer_pubkey_ed25519_base64: peer_pubkey,
                received_at: parse_datetime(&received_at_str)?,
                transport_id,
                signature_classical_base64: super::federation_announcement::encode_signature_base64(
                    &sig_classical,
                ),
                signature_pqc_base64: sig_pqc_opt
                    .map(|b| super::federation_announcement::encode_signature_base64(&b)),
            });
        }
        Ok(out)
    }

    async fn count_delivery_attestations(&self, announcement_id: &str) -> Result<u64, Error> {
        let announcement_uuid = parse_id(announcement_id)?;
        let id_str = announcement_uuid.to_string();
        let conn = self.conn.clone();

        (move || -> Result<u64, Error> {
            let guard = conn.lock();
            let n: i64 = guard
                .query_row(
                    "SELECT COUNT(*) FROM cirisnode_federation_delivery_attestations \
                     WHERE announcement_id = ?1",
                    [id_str],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|e| map_sqlite_error(e, "count_delivery_attestations"))?;
            Ok(u64::try_from(n).unwrap_or(0))
        })()
    }

    // ── Media-sharing reads (v3.6.0, CIRISPersist#134) ─────────────

    async fn list_takedowns_for(
        &self,
        content_sha256: &str,
    ) -> Result<Vec<ContributionEnvelope>, Error> {
        let sha = content_sha256.to_owned();
        let conn = self.conn.clone();
        let rows = (move || -> Result<Vec<ContributionRow>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(
                    "SELECT contribution_id, contribution_type, domain, language, subject_kind, \
                            author_id, payload, witness_set, submitted_at, signature \
                     FROM cirisnode_contributions \
                     WHERE subject_kind = 'takedown_notice' \
                       AND media_content_sha256 = ?1 \
                     ORDER BY submitted_at DESC, contribution_id DESC",
                )
                .map_err(|e| map_sqlite_error(e, "list_takedowns_for prepare"))?;
            let rows = stmt
                .query_map([sha], read_contribution_row)
                .map_err(|e| map_sqlite_error(e, "list_takedowns_for query"))?;
            let out: Result<Vec<_>, _> = rows.collect();
            out.map_err(|e| map_sqlite_error(e, "list_takedowns_for collect"))
        })()?;
        rows.into_iter().map(materialize_contribution).collect()
    }

    async fn list_key_grants_for(
        &self,
        recipient_key_id: &str,
    ) -> Result<Vec<ContributionEnvelope>, Error> {
        let recipient = recipient_key_id.to_owned();
        let conn = self.conn.clone();
        let rows = (move || -> Result<Vec<ContributionRow>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(
                    "SELECT contribution_id, contribution_type, domain, language, subject_kind, \
                            author_id, payload, witness_set, submitted_at, signature \
                     FROM cirisnode_contributions \
                     WHERE subject_kind = 'key_grant' \
                       AND key_grant_recipient_key_id = ?1 \
                     ORDER BY submitted_at DESC, contribution_id DESC",
                )
                .map_err(|e| map_sqlite_error(e, "list_key_grants_for prepare"))?;
            let rows = stmt
                .query_map([recipient], read_contribution_row)
                .map_err(|e| map_sqlite_error(e, "list_key_grants_for query"))?;
            let out: Result<Vec<_>, _> = rows.collect();
            out.map_err(|e| map_sqlite_error(e, "list_key_grants_for collect"))
        })()?;
        rows.into_iter().map(materialize_contribution).collect()
    }

    async fn list_key_grants_for_content(
        &self,
        content_sha256: &str,
        recipient_key_id: &str,
    ) -> Result<Vec<ContributionEnvelope>, Error> {
        let sha = content_sha256.to_owned();
        let recipient = recipient_key_id.to_owned();
        let conn = self.conn.clone();
        let rows = (move || -> Result<Vec<ContributionRow>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(
                    "SELECT contribution_id, contribution_type, domain, language, subject_kind, \
                            author_id, payload, witness_set, submitted_at, signature \
                     FROM cirisnode_contributions \
                     WHERE subject_kind = 'key_grant' \
                       AND media_content_sha256 = ?1 \
                       AND key_grant_recipient_key_id = ?2 \
                     ORDER BY submitted_at DESC, contribution_id DESC",
                )
                .map_err(|e| map_sqlite_error(e, "list_key_grants_for_content prepare"))?;
            let rows = stmt
                .query_map([sha, recipient], read_contribution_row)
                .map_err(|e| map_sqlite_error(e, "list_key_grants_for_content query"))?;
            let out: Result<Vec<_>, _> = rows.collect();
            out.map_err(|e| map_sqlite_error(e, "list_key_grants_for_content collect"))
        })()?;
        rows.into_iter().map(materialize_contribution).collect()
    }

    async fn list_key_grants_for_scope_epoch(
        &self,
        scope_kind: &str,
        scope_id: &str,
        epoch: u64,
    ) -> Result<Vec<ContributionEnvelope>, Error> {
        let kind = scope_kind.to_owned();
        let scope = scope_id.to_owned();
        // u64 epoch → bound i64; key_grant_epoch is INTEGER.
        let epoch_i64 = i64::try_from(epoch).map_err(|_| {
            Error::InvalidArgument("list_key_grants_for_scope_epoch: epoch exceeds i64".into())
        })?;
        let conn = self.conn.clone();
        let rows = (move || -> Result<Vec<ContributionRow>, Error> {
            let guard = conn.lock();
            // v34.0.0 (#704, V129) — the three predicates are written in
            // the leading order of `contributions_key_grant_scope_epoch`
            // (scope_kind, scope_id, epoch) so the partial index is a
            // prefix match, not a scan.
            //
            // `key_grant_scope_kind` is NOT decoration: `scope_id` is an
            // id WITHIN a scope kind, so a transit `netname` and a
            // `stream_id` may collide as strings. Without this predicate
            // a transit grant at the same epoch is returned to a
            // STREAMING reader.
            let mut stmt = guard
                .prepare(
                    "SELECT contribution_id, contribution_type, domain, language, subject_kind, \
                            author_id, payload, witness_set, submitted_at, signature \
                     FROM cirisnode_contributions \
                     WHERE subject_kind = 'key_grant' \
                       AND key_grant_scope_kind = ?1 \
                       AND key_grant_scope_id = ?2 \
                       AND key_grant_epoch = ?3 \
                     ORDER BY submitted_at DESC, contribution_id DESC",
                )
                .map_err(|e| map_sqlite_error(e, "list_key_grants_for_scope_epoch prepare"))?;
            let rows = stmt
                .query_map(params![kind, scope, epoch_i64], read_contribution_row)
                .map_err(|e| map_sqlite_error(e, "list_key_grants_for_scope_epoch query"))?;
            let out: Result<Vec<_>, _> = rows.collect();
            out.map_err(|e| map_sqlite_error(e, "list_key_grants_for_scope_epoch collect"))
        })()?;
        rows.into_iter().map(materialize_contribution).collect()
    }

    async fn put_key_grant(&self, env: ContributionEnvelope) -> Result<(), Error> {
        // v16 (CIRISPersist#432, CC 5.1) — fail-closed shape gate
        // FIRST (must BE a key_grant), then the full put_contribution
        // admission (trust gate + signature + projection). Mirrors the
        // PG impl.
        super::media_sharing::require_key_grant_envelope(&env)?;
        self.put_contribution(env).await
    }

    async fn retire_key_grants(
        &self,
        actor_key_id: &str,
        signer: &dyn ciris_keyring::HardwareSigner,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<super::RetireKeyGrantsReport, Error> {
        // CEG 0.3 §5.6.8.4 — rotation_chain supersession (option b
        // from CIRISRegistry#38): each prior grant is retired by
        // emitting a fresh key_grant Contribution whose rotation_chain
        // is extended by the prior contribution_id.
        let actor = actor_key_id.to_owned();
        let conn = self.conn.clone();
        let priors = (move || -> Result<Vec<(String, String, String, String)>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(
                    "SELECT contribution_id, domain, language, payload \
                         FROM cirisnode_contributions \
                         WHERE subject_kind = 'key_grant' AND author_id = ?1",
                )
                .map_err(|e| map_sqlite_error(e, "retire_key_grants list prepare"))?;
            let rows = stmt
                .query_map([actor], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(|e| map_sqlite_error(e, "retire_key_grants list query"))?;
            let out: Result<Vec<_>, _> = rows.collect();
            out.map_err(|e| map_sqlite_error(e, "retire_key_grants list collect"))
        })()?;

        let mut report = super::RetireKeyGrantsReport {
            grants_seen: priors.len(),
            ..Default::default()
        };
        for (prior_id, domain, language, payload_text) in priors {
            let prior: super::media_sharing::KeyGrantPayload =
                match serde_json::from_str(&payload_text) {
                    Ok(p) => p,
                    Err(e) => {
                        report.supersedes_failed += 1;
                        tracing::warn!(
                            error = %e,
                            actor = %actor_key_id,
                            contribution_id = %prior_id,
                            "ciris-persist v3.6.0 retire_key_grants: prior payload decode failed"
                        );
                        continue;
                    }
                };
            let outcome = emit_key_grant_supersession_sqlite(
                self,
                &prior_id,
                actor_key_id,
                &domain,
                &language,
                &prior,
                signer,
                now,
            )
            .await;
            match outcome {
                Ok(()) => report.supersedes_emitted += 1,
                Err(e) => {
                    report.supersedes_failed += 1;
                    tracing::warn!(
                        error = %e,
                        actor = %actor_key_id,
                        contribution_id = %prior_id,
                        "ciris-persist v3.6.0 retire_key_grants: supersession emission failed"
                    );
                }
            }
        }
        Ok(report)
    }
}

/// Raw column tuple for the list_* media-sharing reads.
type ContributionRow = (
    String,         // contribution_id
    String,         // contribution_type
    String,         // domain
    String,         // language
    String,         // subject_kind
    String,         // author_id
    String,         // payload (JSON text)
    Option<String>, // witness_set (JSON text)
    String,         // submitted_at
    String,         // signature
);

fn read_contribution_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ContributionRow> {
    Ok((
        row.get::<_, String>(0)?,
        row.get::<_, String>(1)?,
        row.get::<_, String>(2)?,
        row.get::<_, String>(3)?,
        row.get::<_, String>(4)?,
        row.get::<_, String>(5)?,
        row.get::<_, String>(6)?,
        row.get::<_, Option<String>>(7)?,
        row.get::<_, String>(8)?,
        row.get::<_, String>(9)?,
    ))
}

fn materialize_contribution(raw: ContributionRow) -> Result<ContributionEnvelope, Error> {
    let (
        contribution_id,
        ct_str,
        domain,
        language,
        subject_kind,
        author_id,
        payload_text,
        witness_set_text,
        submitted_at_str,
        signature_b64,
    ) = raw;
    let payload = json_value(&payload_text)?;
    let witness_set = match witness_set_text {
        None => None,
        Some(s) => Some(
            serde_json::from_str(&s)
                .map_err(|e| Error::Backend(format!("witness_set decode: {e}")))?,
        ),
    };
    let submitted_at = parse_datetime(&submitted_at_str)?;
    Ok(ContributionEnvelope {
        contribution_id,
        contribution_type: contribution_type_from_str(&ct_str)?,
        author_id,
        subject: Cell {
            domain,
            language,
            subject: Some(subject_kind),
        },
        payload,
        witness_set,
        signature: HybridSignature {
            ed25519: signature_b64,
            ml_dsa_65: None,
            signed_at: submitted_at,
        },
        submitted_at,
    })
}

/// v3.6.0 (CIRISPersist#134) — sibling of the PG-side
/// `emit_key_grant_supersession`. Emits a fresh `key_grant` Contribution
/// against the SQLite NodeCore backend with the rotation_chain
/// extended by the prior contribution_id.
///
/// CEG 0.3 §5.6.8.4 — rotation_chain supersession (option b from
/// CIRISRegistry#38).
#[allow(clippy::too_many_arguments)]
async fn emit_key_grant_supersession_sqlite(
    backend: &SqliteNodeCoreBackend,
    prior_contribution_id: &str,
    actor_key_id: &str,
    domain: &str,
    language: &str,
    prior: &super::media_sharing::KeyGrantPayload,
    signer: &dyn ciris_keyring::HardwareSigner,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    let mut rotation_chain = prior.rotation_chain.clone();
    rotation_chain.push(prior_contribution_id.to_owned());

    let revocation_dek = B64.encode(Vec::<u8>::new());

    let supersession_payload = super::media_sharing::KeyGrantPayload {
        recipient_key_id: prior.recipient_key_id.clone(),
        content_sha256: prior.content_sha256.clone(),
        // Carry the prior grant's addressing so a scope-epoch supersession
        // stays scope-epoch-addressed. v34.0.0 (#704): `epoch` is the whole
        // addressing carry now — the id rides `scope_id` below, which every
        // grant already copies.
        epoch: prior.epoch,
        wrapped_dek_base64: revocation_dek,
        wrap_algorithm: prior.wrap_algorithm,
        ratchet_version: prior.ratchet_version,
        key_validity_window: super::media_sharing::KeyValidityWindow {
            not_before: now,
            not_after: now + chrono::Duration::seconds(1),
        },
        scope: prior.scope,
        scope_id: prior.scope_id.clone(),
        rotation_chain,
        // v34.0.0 (#704) — transit-only; absent on every other scope.
        ifac_size: None,
    };
    let payload_value = serde_json::to_value(&supersession_payload)
        .map_err(|e| Error::Internal(format!("supersession serialize: {e}")))?;

    let mut env = ContributionEnvelope {
        contribution_id: uuid::Uuid::new_v4().to_string(),
        contribution_type: ContributionType::Proposal,
        author_id: actor_key_id.to_owned(),
        subject: Cell {
            domain: domain.to_owned(),
            language: language.to_owned(),
            subject: Some(super::media_sharing::KEY_GRANT_SUBJECT_KIND.to_owned()),
        },
        payload: payload_value,
        witness_set: None,
        signature: HybridSignature {
            ed25519: String::new(),
            ml_dsa_65: None,
            signed_at: now,
        },
        submitted_at: now,
    };
    let canonical = super::verify::canonical_bytes_for_envelope(&env)?;
    let sig_bytes = signer
        .sign(&canonical)
        .await
        .map_err(|e| Error::Backend(format!("supersession sign: {e}")))?;
    env.signature = HybridSignature {
        ed25519: B64.encode(&sig_bytes),
        ml_dsa_65: None,
        signed_at: now,
    };
    use super::NodeCoreService;
    backend.put_contribution(env).await
}

#[cfg(test)]
#[allow(missing_docs)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;

    /// v0.7.1 — produce the contributor's base64-encoded Ed25519
    /// pubkey from a deterministic seed (for tests). Per SCHEMA.md
    /// §2.2 the pubkey IS the contributor_id.
    fn pubkey_b64(key: &ed25519_dalek::SigningKey) -> String {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        BASE64.encode(key.verifying_key().to_bytes())
    }

    /// Sign the canonical bytes of an envelope and stamp the signature
    /// field. Generic over the typed-envelope shape.
    fn sign_envelope<T: serde::Serialize>(
        env: &T,
        key: &ed25519_dalek::SigningKey,
    ) -> HybridSignature {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;
        let canonical = super::super::verify::canonical_bytes_for_envelope(env)
            .expect("canonical bytes for sign");
        let sig = key.sign(&canonical);
        HybridSignature {
            ed25519: BASE64.encode(sig.to_bytes()),
            ml_dsa_65: None,
            signed_at: Utc::now(),
        }
    }

    async fn fresh_backend() -> (SqliteBackend, SqliteNodeCoreBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let cn = SqliteNodeCoreBackend::new(backend.conn_handle());
        (backend, cn)
    }

    /// v0.9.4 SQLite parity: same lifecycle as the v0.7.1 / v0.7.2
    /// Postgres tests, run against in-memory SQLite. Covers the full
    /// 14-method NodeCoreService surface + duplicate-key conflict +
    /// tampered-envelope signature rejection + promotion-attestation
    /// transaction (flip `is_canonical` on 2 targets in one
    /// attestation) + rollback on phantom target.
    #[tokio::test]
    async fn cirisnode_sqlite_round_trip_full_lifecycle() {
        let (b, backend) = fresh_backend().await;

        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xA1; 32]);
        let voter_key = ed25519_dalek::SigningKey::from_bytes(&[0xB2; 32]);
        let adjudicator_key = ed25519_dalek::SigningKey::from_bytes(&[0xC3; 32]);
        let consensus_key = ed25519_dalek::SigningKey::from_bytes(&[0xD4; 32]);
        let author = pubkey_b64(&author_key);
        let voter = pubkey_b64(&voter_key);
        let adjudicator = pubkey_b64(&adjudicator_key);
        let consensus = pubkey_b64(&consensus_key);
        let domain = format!("test-dom-{}", Uuid::new_v4());
        let language = "en";
        let subject_kind = "arc_question";

        // 1. put_contribution
        let contribution_id = Uuid::new_v4();
        let mut env = ContributionEnvelope {
            contribution_id: contribution_id.to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author.clone(),
            subject: Cell {
                domain: domain.clone(),
                language: language.into(),
                subject: Some(subject_kind.into()),
            },
            payload: serde_json::json!({"question_id": "test_q01"}),
            witness_set: None,
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            submitted_at: Utc::now(),
        };
        env.signature = sign_envelope(&env, &author_key);
        backend.put_contribution(env.clone()).await.unwrap();

        // 1b. duplicate → Conflict
        let dup = backend.put_contribution(env.clone()).await.unwrap_err();
        assert!(
            matches!(dup, Error::Conflict(_)),
            "expected Conflict on duplicate, got: {dup:?}"
        );

        // 1c. tampered envelope → Signature
        let mut tampered = env.clone();
        tampered.contribution_id = Uuid::new_v4().to_string();
        tampered.payload = serde_json::json!({"q": "TAMPERED"});
        let tampered_err = backend.put_contribution(tampered).await.unwrap_err();
        assert!(
            matches!(tampered_err, Error::Signature(_)),
            "expected Signature on tampered, got: {tampered_err:?}"
        );

        // 2. cast_vote
        let vote_id = Uuid::new_v4();
        let mut vote = VoteEnvelope {
            vote_id: vote_id.to_string(),
            voter_id: voter.clone(),
            contribution_id: Some(contribution_id.to_string()),
            cell: Cell {
                domain: domain.clone(),
                language: language.into(),
                subject: Some(subject_kind.into()),
            },
            score: serde_json::json!({"verdict": "approve", "magnitude": 1.0}),
            rationale: Some("test".into()),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            cast_at: Utc::now(),
        };
        vote.signature = sign_envelope(&vote, &voter_key);
        backend.cast_vote(vote).await.unwrap();

        // 3. update_credits_ledger
        backend
            .update_credits_ledger(CreditsUpdate {
                contributor_id: voter.clone(),
                domain: domain.clone(),
                language: language.into(),
                subject: subject_kind.into(),
                new_balance: 10.0,
                source_contribution: contribution_id.to_string(),
            })
            .await
            .unwrap();

        // 4. update_expertise_ledger
        backend
            .update_expertise_ledger(ExpertiseUpdate {
                contributor_id: voter.clone(),
                domain: domain.clone(),
                language: language.into(),
                new_expertise: 0.5,
                new_active_tier: true,
                source_contribution: contribution_id.to_string(),
            })
            .await
            .unwrap();

        // 5. routable_contributors
        let routable = backend
            .routable_contributors(&domain, language)
            .await
            .unwrap();
        assert_eq!(routable.len(), 1);
        assert_eq!(routable[0].contributor_id, voter);
        assert!((routable[0].expertise - 0.5).abs() < 1e-9);

        // 6. read_vote_weight
        let vw = backend
            .read_vote_weight(&voter, &domain, language, subject_kind)
            .await
            .unwrap()
            .expect("vote weight present");
        assert!((vw.credits - 10.0).abs() < 1e-9);
        assert!((vw.expertise_multiplier - 3.0).abs() < 1e-9);
        assert!((vw.active_tier_multiplier - 1.5).abs() < 1e-9);
        assert!((vw.weight - 45.0).abs() < 1e-9);

        // 7. list_contributions
        let page = backend
            .list_contributions(
                ContributionsFilter {
                    domain: Some(domain.clone()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].contribution_id, contribution_id.to_string());

        // 8. list_votes
        let page = backend
            .list_votes(
                VotesFilter {
                    domain: Some(domain.clone()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);

        // 9. get_credits_ledger
        let cl = backend
            .get_credits_ledger(&voter, &domain, language, subject_kind)
            .await
            .unwrap()
            .expect("credits present");
        assert!((cl.balance - 10.0).abs() < 1e-9);

        // 10. get_expertise_ledger
        let el = backend
            .get_expertise_ledger(&voter, &domain, language)
            .await
            .unwrap()
            .expect("expertise present");
        assert!((el.expertise - 0.5).abs() < 1e-9);
        assert!(el.is_active);

        // 11. put_moderation_event
        // v8.7.2 (#233 follow-on): the accuser's subject-self authority now
        // resolves over the SIGNED content provenance, not the payload. Seed
        // an establishing scores attestation binding `mod_sha` with signed
        // subjects=[author] so the as-self path admits (this lifecycle test
        // exercises storage, not the moderation authority gate).
        let mod_sha = fixture_sha_hex_sqlite(0xab);
        seed_fed_key(&b, &author).await;
        seed_establishing_content(&b, "est-lifecycle", &author, &mod_sha, &[&author]).await;
        let moderation_id = Uuid::new_v4();
        let mut mod_event = ModerationEvent {
            moderation_id: moderation_id.to_string(),
            target_contributor: voter.clone(),
            accuser_id: author.clone(),
            // The payload `subject_key_ids` is advisory/routing-only; the
            // `content_sha256` drives subject_of authority resolution.
            payload: serde_json::json!({
                "violation": "test",
                "subject_key_ids": [author.clone()],
                "content_sha256": mod_sha,
            }),
            filed_at: Utc::now(),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
        };
        mod_event.signature = sign_envelope(&mod_event, &author_key);
        backend.put_moderation_event(mod_event).await.unwrap();

        // 12. put_slashing_attestation
        let slashing_id = Uuid::new_v4();
        let mut slash = SlashingAttestation {
            slashing_id: slashing_id.to_string(),
            moderation_id: moderation_id.to_string(),
            adjudicator_id: adjudicator.clone(),
            payload: serde_json::json!({"outcome": "dismiss"}),
            attested_at: Utc::now(),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
        };
        slash.signature = sign_envelope(&slash, &adjudicator_key);
        backend.put_slashing_attestation(slash).await.unwrap();

        // 13. put_reconsideration_request + put_reconsideration_attestation
        let request_id = Uuid::new_v4();
        let mut recon_req = ReconsiderationRequest {
            request_id: request_id.to_string(),
            slashing_id: slashing_id.to_string(),
            requester_id: voter.clone(),
            payload: serde_json::json!({"grounds": "new evidence"}),
            requested_at: Utc::now(),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
        };
        recon_req.signature = sign_envelope(&recon_req, &voter_key);
        backend
            .put_reconsideration_request(recon_req)
            .await
            .unwrap();

        let reconsideration_id = Uuid::new_v4();
        let mut recon_att = ReconsiderationAttestation {
            reconsideration_id: reconsideration_id.to_string(),
            request_id: request_id.to_string(),
            adjudicator_id: adjudicator.clone(),
            payload: serde_json::json!({"outcome": "uphold"}),
            attested_at: Utc::now(),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
        };
        recon_att.signature = sign_envelope(&recon_att, &adjudicator_key);
        backend
            .put_reconsideration_attestation(recon_att)
            .await
            .unwrap();

        // 14. put_promotion_attestation — flip 2 contributions canonical
        // First, INSERT a second pending contribution to promote
        // alongside `contribution_id`.
        let contribution_id_2 = Uuid::new_v4();
        let mut env2 = ContributionEnvelope {
            contribution_id: contribution_id_2.to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author.clone(),
            subject: Cell {
                domain: domain.clone(),
                language: language.into(),
                subject: Some(subject_kind.into()),
            },
            payload: serde_json::json!({"q": "second"}),
            witness_set: None,
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            submitted_at: Utc::now(),
        };
        env2.signature = sign_envelope(&env2, &author_key);
        backend.put_contribution(env2).await.unwrap();

        let attestation_id = Uuid::new_v4();
        let mut att = PromotionAttestation {
            attestation_id: attestation_id.to_string(),
            target_kind: TargetRowKind::Contribution,
            target_ids: vec![contribution_id.to_string(), contribution_id_2.to_string()],
            attested_by: consensus.clone(),
            aggregate_evidence: serde_json::json!({
                "threshold": "policy-A",
                "votes_for": 12,
                "witness_count": 3,
            }),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            attested_at: Utc::now(),
        };
        att.signature = sign_envelope(&att, &consensus_key);
        backend
            .put_promotion_attestation(att.clone())
            .await
            .unwrap();

        // Verify both targets are now canonical.
        let page = backend
            .list_contributions(
                ContributionsFilter {
                    domain: Some(domain.clone()),
                    is_canonical: Some(true),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(
            page.items.len(),
            2,
            "both contributions should be canonical after promotion"
        );

        // Duplicate attestation_id → Conflict.
        let dup_err = backend.put_promotion_attestation(att).await.unwrap_err();
        assert!(
            matches!(dup_err, Error::Conflict(_)),
            "expected Conflict on dup attestation, got: {dup_err:?}"
        );

        // Empty target_ids → InvalidArgument.
        let mut empty_att = PromotionAttestation {
            attestation_id: Uuid::new_v4().to_string(),
            target_kind: TargetRowKind::Contribution,
            target_ids: vec![],
            attested_by: consensus.clone(),
            aggregate_evidence: serde_json::json!({}),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            attested_at: Utc::now(),
        };
        empty_att.signature = sign_envelope(&empty_att, &consensus_key);
        let empty_err = backend
            .put_promotion_attestation(empty_att)
            .await
            .unwrap_err();
        assert!(
            matches!(empty_err, Error::InvalidArgument(_)),
            "expected InvalidArgument on empty target_ids, got: {empty_err:?}"
        );

        // Phantom target → InvalidArgument + rollback. Re-using the
        // same attestation_id afterwards with a valid target succeeds
        // (proving the INSERT was rolled back).
        let phantom_id = Uuid::new_v4();
        let phantom_attestation_id = Uuid::new_v4();
        let mut phantom_att = PromotionAttestation {
            attestation_id: phantom_attestation_id.to_string(),
            target_kind: TargetRowKind::Contribution,
            target_ids: vec![phantom_id.to_string()],
            attested_by: consensus.clone(),
            aggregate_evidence: serde_json::json!({}),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            attested_at: Utc::now(),
        };
        phantom_att.signature = sign_envelope(&phantom_att, &consensus_key);
        let phantom_err = backend
            .put_promotion_attestation(phantom_att)
            .await
            .unwrap_err();
        assert!(
            matches!(phantom_err, Error::InvalidArgument(_)),
            "expected InvalidArgument on phantom target, got: {phantom_err:?}"
        );

        // Insert a fresh pending contribution + re-use the same
        // attestation_id with a valid target → must succeed (proves
        // rollback of the earlier phantom attempt).
        let recovery_cid = Uuid::new_v4();
        let mut recovery_env = ContributionEnvelope {
            contribution_id: recovery_cid.to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author.clone(),
            subject: Cell {
                domain: domain.clone(),
                language: language.into(),
                subject: Some(subject_kind.into()),
            },
            payload: serde_json::json!({"q": "recovery"}),
            witness_set: None,
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            submitted_at: Utc::now(),
        };
        recovery_env.signature = sign_envelope(&recovery_env, &author_key);
        backend.put_contribution(recovery_env).await.unwrap();

        let mut recovery_att = PromotionAttestation {
            attestation_id: phantom_attestation_id.to_string(),
            target_kind: TargetRowKind::Contribution,
            target_ids: vec![recovery_cid.to_string()],
            attested_by: consensus,
            aggregate_evidence: serde_json::json!({}),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            attested_at: Utc::now(),
        };
        recovery_att.signature = sign_envelope(&recovery_att, &consensus_key);
        backend
            .put_promotion_attestation(recovery_att)
            .await
            .expect("attestation row was rolled back; re-use must succeed");
    }

    // ─── Federation Announcement (v2.1, CIRISPersist#101) ───────────

    fn build_announcement_sqlite(
        author_key: &ed25519_dalek::SigningKey,
        priority: crate::cirisnode::AnnouncementPriority,
        authority_class: crate::cirisnode::AuthorityClass,
        kind: crate::cirisnode::AnnouncementKind,
        accord_payload: Option<crate::cirisnode::AccordCarrier>,
        supersedes: Option<String>,
    ) -> ContributionEnvelope {
        let author = pubkey_b64(author_key);
        let payload = crate::cirisnode::FederationAnnouncementPayload {
            priority,
            kind,
            title: "test announcement".into(),
            body: "test body".into(),
            authority_class,
            accord_payload,
            supersedes,
            expires_at: chrono::Utc::now() + chrono::Duration::days(1),
            evidence_refs: vec![],
        };
        let mut env = ContributionEnvelope {
            contribution_id: Uuid::new_v4().to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author,
            subject: Cell {
                domain: "federation".into(),
                language: "en".into(),
                subject: Some(crate::cirisnode::SUBJECT_KIND.into()),
            },
            payload: serde_json::to_value(&payload).unwrap(),
            witness_set: None,
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            submitted_at: Utc::now(),
        };
        env.signature = sign_envelope(&env, author_key);
        env
    }

    #[tokio::test]
    async fn sqlite_federation_announcement_round_trip_each_authority_class() {
        use crate::cirisnode::{AnnouncementKind, AnnouncementPriority, AuthorityClass};
        let (_b, backend) = fresh_backend().await;

        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xC1; 32]);

        let fixtures: Vec<(AnnouncementPriority, AuthorityClass, AnnouncementKind)> = vec![
            (
                AnnouncementPriority::Informational,
                AuthorityClass::BootstrapSeed,
                AnnouncementKind::PolicyUpdate,
            ),
            (
                AnnouncementPriority::Advisory,
                AuthorityClass::RootWa,
                AnnouncementKind::ThreatAdvisory,
            ),
            (
                AnnouncementPriority::Urgent,
                AuthorityClass::WaQuorum,
                AnnouncementKind::KeyRotation,
            ),
            (
                AnnouncementPriority::AccordCarrier,
                AuthorityClass::HumanityAccord,
                AnnouncementKind::AccordCarrier,
            ),
        ];

        let mut accord_id: Option<String> = None;
        for (priority, authority, kind) in fixtures {
            let accord_payload = if matches!(priority, AnnouncementPriority::AccordCarrier) {
                Some(crate::cirisnode::AccordCarrier {
                    payload_bytes: (0u8..77).collect(),
                    rationale: Some("drill".into()),
                })
            } else {
                None
            };
            let env = build_announcement_sqlite(
                &author_key,
                priority,
                authority,
                kind,
                accord_payload,
                None,
            );
            if matches!(priority, AnnouncementPriority::AccordCarrier) {
                accord_id = Some(env.contribution_id.clone());
            }
            backend.put_contribution(env).await.unwrap();
        }

        // 77-byte accord round-trip via list_contributions.
        let page = backend
            .list_contributions(
                ContributionsFilter {
                    subject_kind: Some(crate::cirisnode::SUBJECT_KIND.into()),
                    priority: Some(AnnouncementPriority::AccordCarrier),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        let accord_id = accord_id.unwrap();
        let item = page
            .items
            .iter()
            .find(|i| i.contribution_id == accord_id)
            .unwrap();
        let payload: crate::cirisnode::FederationAnnouncementPayload =
            serde_json::from_value(item.payload.clone()).unwrap();
        let accord = payload.accord_payload.expect("accord_payload present");
        assert_eq!(accord.payload_bytes.len(), 77);
        assert_eq!(accord.payload_bytes, (0u8..77).collect::<Vec<u8>>());
    }

    #[tokio::test]
    async fn sqlite_federation_announcement_rejects_constitutional_asymmetry_violation() {
        use crate::cirisnode::{AnnouncementKind, AnnouncementPriority, AuthorityClass};
        let (_b, backend) = fresh_backend().await;

        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xC2; 32]);
        let env = build_announcement_sqlite(
            &author_key,
            AnnouncementPriority::AccordCarrier,
            AuthorityClass::BootstrapSeed,
            AnnouncementKind::AccordCarrier,
            Some(crate::cirisnode::AccordCarrier {
                payload_bytes: vec![0u8; 77],
                rationale: None,
            }),
            None,
        );
        let err = backend.put_contribution(env).await.unwrap_err();
        assert!(
            matches!(err, Error::FederationAnnouncementAuthorityMismatch(_)),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn sqlite_federation_announcement_supersedes_chain_round_trip() {
        use crate::cirisnode::{AnnouncementKind, AnnouncementPriority, AuthorityClass};
        let (_b, backend) = fresh_backend().await;

        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xC3; 32]);
        let env_a = build_announcement_sqlite(
            &author_key,
            AnnouncementPriority::Advisory,
            AuthorityClass::RootWa,
            AnnouncementKind::PolicyUpdate,
            None,
            None,
        );
        let a_id = env_a.contribution_id.clone();
        backend.put_contribution(env_a).await.unwrap();

        let env_b = build_announcement_sqlite(
            &author_key,
            AnnouncementPriority::Advisory,
            AuthorityClass::RootWa,
            AnnouncementKind::PolicyUpdate,
            None,
            Some(a_id.clone()),
        );
        let b_id = env_b.contribution_id.clone();
        backend.put_contribution(env_b).await.unwrap();

        let page = backend
            .list_contributions(
                ContributionsFilter {
                    subject_kind: Some(crate::cirisnode::SUBJECT_KIND.into()),
                    author_id: Some(pubkey_b64(&author_key)),
                    priority: Some(AnnouncementPriority::Advisory),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        let ids: std::collections::HashSet<_> = page
            .items
            .iter()
            .map(|i| i.contribution_id.clone())
            .collect();
        assert!(ids.contains(&a_id));
        assert!(ids.contains(&b_id));
    }

    #[tokio::test]
    async fn sqlite_list_contributions_filter_extension() {
        use crate::cirisnode::{AnnouncementKind, AnnouncementPriority, AuthorityClass};
        let (_b, backend) = fresh_backend().await;

        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xC4; 32]);
        let author = pubkey_b64(&author_key);

        let fixtures: Vec<(AnnouncementPriority, AuthorityClass, AnnouncementKind)> = vec![
            (
                AnnouncementPriority::Informational,
                AuthorityClass::BootstrapSeed,
                AnnouncementKind::PolicyUpdate,
            ),
            (
                AnnouncementPriority::Informational,
                AuthorityClass::RootWa,
                AnnouncementKind::Deprecation,
            ),
            (
                AnnouncementPriority::Advisory,
                AuthorityClass::RootWa,
                AnnouncementKind::ThreatAdvisory,
            ),
            (
                AnnouncementPriority::Advisory,
                AuthorityClass::WaQuorum,
                AnnouncementKind::MissionUpdate,
            ),
            (
                AnnouncementPriority::Urgent,
                AuthorityClass::WaQuorum,
                AnnouncementKind::KeyRotation,
            ),
            (
                AnnouncementPriority::AccordCarrier,
                AuthorityClass::HumanityAccord,
                AnnouncementKind::AccordCarrier,
            ),
        ];
        for (pri, aut, kind) in &fixtures {
            let accord_payload = if matches!(pri, AnnouncementPriority::AccordCarrier) {
                Some(crate::cirisnode::AccordCarrier {
                    payload_bytes: vec![0u8; 77],
                    rationale: None,
                })
            } else {
                None
            };
            let env = build_announcement_sqlite(
                &author_key,
                *pri,
                *aut,
                kind.clone(),
                accord_payload,
                None,
            );
            backend.put_contribution(env).await.unwrap();
        }

        // priority filter
        let page = backend
            .list_contributions(
                ContributionsFilter {
                    subject_kind: Some(crate::cirisnode::SUBJECT_KIND.into()),
                    author_id: Some(author.clone()),
                    priority: Some(AnnouncementPriority::Informational),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2);

        // authority_class filter
        let page = backend
            .list_contributions(
                ContributionsFilter {
                    subject_kind: Some(crate::cirisnode::SUBJECT_KIND.into()),
                    author_id: Some(author.clone()),
                    authority_class: Some(AuthorityClass::RootWa),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2);

        // priority + authority_class composed
        let page = backend
            .list_contributions(
                ContributionsFilter {
                    subject_kind: Some(crate::cirisnode::SUBJECT_KIND.into()),
                    author_id: Some(author.clone()),
                    priority: Some(AnnouncementPriority::Advisory),
                    authority_class: Some(AuthorityClass::WaQuorum),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);

        // kind filter
        let page = backend
            .list_contributions(
                ContributionsFilter {
                    subject_kind: Some(crate::cirisnode::SUBJECT_KIND.into()),
                    author_id: Some(author.clone()),
                    kind: Some(AnnouncementKind::KeyRotation),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
    }

    // ─── Federation Delivery Attestations (FSD §3.2.1) ──────────────

    async fn put_peer_federation_key_sqlite(
        backend: &SqliteBackend,
        seed: u8,
    ) -> (String, ed25519_dalek::SigningKey, String) {
        use crate::federation::FederationDirectory;
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let pubkey_b64 = B64.encode(signing_key.verifying_key().to_bytes());
        let key_id = format!("test-peer-{seed:02x}-{}", Uuid::new_v4());
        let record = crate::federation::KeyRecord {
            key_id: key_id.clone(),
            pubkey_ed25519_base64: pubkey_b64.clone(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::AGENT.into(),
            identity_ref: format!("agent-{seed:02x}"),
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: None,
            registration_envelope: serde_json::json!({"id": key_id}),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.clone(),
            scrub_timestamp: Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        backend
            .put_public_key(crate::federation::SignedKeyRecord { record })
            .await
            .unwrap();
        (key_id, signing_key, pubkey_b64)
    }

    fn build_signed_attestation_sqlite(
        announcement_id: &str,
        canonical_hash: &[u8; 32],
        peer_key_id: &str,
        peer_pubkey_b64: &str,
        peer_signing_key: &ed25519_dalek::SigningKey,
    ) -> crate::cirisnode::DeliveryAttestation {
        use ed25519_dalek::Signer as _;
        let mut att = crate::cirisnode::DeliveryAttestation {
            announcement_id: announcement_id.to_owned(),
            announcement_canonical_hash_base64: crate::cirisnode::encode_canonical_hash_base64(
                canonical_hash,
            ),
            peer_key_id: peer_key_id.to_owned(),
            peer_pubkey_ed25519_base64: peer_pubkey_b64.to_owned(),
            received_at: Utc::now(),
            transport_id: crate::cirisnode::TransportMedium::HttpOverTls,
            signature_classical_base64: crate::cirisnode::encode_signature_base64(&[0u8; 64]),
            signature_pqc_base64: None,
        };
        let canonical = att.canonical_bytes().unwrap();
        let sig = peer_signing_key.sign(&canonical);
        att.signature_classical_base64 = crate::cirisnode::encode_signature_base64(&sig.to_bytes());
        att
    }

    #[tokio::test]
    async fn sqlite_delivery_attestation_round_trip_idempotent() {
        let (b, backend) = fresh_backend().await;

        // Write the announcement (FK target).
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xC5; 32]);
        let env = build_announcement_sqlite(
            &author_key,
            crate::cirisnode::AnnouncementPriority::Advisory,
            crate::cirisnode::AuthorityClass::RootWa,
            crate::cirisnode::AnnouncementKind::ThreatAdvisory,
            None,
            None,
        );
        let announcement_id = env.contribution_id.clone();
        backend.put_contribution(env).await.unwrap();

        let canonical_hash: [u8; 32] = [0x42; 32];
        let mut peers = Vec::new();
        for seed in [0xD1u8, 0xD2u8, 0xD3u8] {
            peers.push(put_peer_federation_key_sqlite(&b, seed).await);
        }

        for (key_id, signing_key, pubkey_b64) in &peers {
            let att = build_signed_attestation_sqlite(
                &announcement_id,
                &canonical_hash,
                key_id,
                pubkey_b64,
                signing_key,
            );
            backend.put_delivery_attestation(att.clone()).await.unwrap();
            // Idempotent replay.
            backend.put_delivery_attestation(att).await.unwrap();
        }

        let rows = backend
            .list_delivery_attestations(&announcement_id)
            .await
            .unwrap();
        assert_eq!(rows.len(), 3);
        let peer_ids: std::collections::HashSet<&str> =
            rows.iter().map(|r| r.peer_key_id.as_str()).collect();
        for (kid, _, _) in &peers {
            assert!(peer_ids.contains(kid.as_str()));
        }

        let n = backend
            .count_delivery_attestations(&announcement_id)
            .await
            .unwrap();
        assert_eq!(n, 3);

        let first = &rows[0];
        let back_hash = first.canonical_hash_bytes().unwrap();
        assert_eq!(back_hash, canonical_hash);
        assert_eq!(
            first.transport_id,
            crate::cirisnode::TransportMedium::HttpOverTls
        );
    }

    #[tokio::test]
    async fn sqlite_delivery_attestation_rejects_forged_signature() {
        let (b, backend) = fresh_backend().await;

        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xC6; 32]);
        let env = build_announcement_sqlite(
            &author_key,
            crate::cirisnode::AnnouncementPriority::Informational,
            crate::cirisnode::AuthorityClass::BootstrapSeed,
            crate::cirisnode::AnnouncementKind::PolicyUpdate,
            None,
            None,
        );
        let announcement_id = env.contribution_id.clone();
        backend.put_contribution(env).await.unwrap();

        let (legit_key_id, _legit_signer, legit_pubkey_b64) =
            put_peer_federation_key_sqlite(&b, 0xE1).await;
        let attacker_signer = ed25519_dalek::SigningKey::from_bytes(&[0xFE; 32]);

        let att = build_signed_attestation_sqlite(
            &announcement_id,
            &[0u8; 32],
            &legit_key_id,
            &legit_pubkey_b64,
            &attacker_signer,
        );
        let err = backend.put_delivery_attestation(att).await.unwrap_err();
        assert!(matches!(err, Error::Signature(_)), "got: {err:?}");
    }

    /// v3.4.0 (CIRISPersist#123) — admission gate gates
    /// `put_contribution` on author_id trust score.
    #[tokio::test]
    async fn put_contribution_trust_gate_rejects_low_score() {
        let (_b, backend) = fresh_backend().await;
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xA1; 32]);
        let author = pubkey_b64(&author_key);

        // Install a gate that rates the author at 0.1, threshold 0.5.
        let mut scoring = crate::federation::MemoryTrustScoring::new();
        scoring.set_score(author.clone(), 0.1);
        let gate = crate::federation::AdmissionGate::new(std::sync::Arc::new(scoring), 0.5, 0);
        backend.set_admission_gate(Some(gate));

        let env = ContributionEnvelope {
            contribution_id: Uuid::new_v4().to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author.clone(),
            subject: Cell {
                domain: "trust-gate-test".into(),
                language: "en".into(),
                subject: Some("arc_question".into()),
            },
            payload: serde_json::json!({"question_id": "tg_q01"}),
            witness_set: None,
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            submitted_at: Utc::now(),
        };
        let mut env = env;
        env.signature = sign_envelope(&env, &author_key);

        let err = backend
            .put_contribution(env)
            .await
            .expect_err("trust-reject");
        match err {
            Error::InvalidArgument(msg) => {
                assert!(msg.contains("trust below threshold"), "got: {msg}");
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    // ── Media-sharing tests (v3.6.0, CIRISPersist#134) ─────────────

    fn fixture_sha_hex_sqlite(seed: u8) -> String {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        hex::encode(bytes)
    }

    fn build_takedown_contribution_sqlite(
        author_key: &ed25519_dalek::SigningKey,
        sha_hex: &str,
        basis: crate::cirisnode::LegalBasis,
    ) -> ContributionEnvelope {
        let author = pubkey_b64(author_key);
        let payload = crate::cirisnode::TakedownNoticePayload {
            content_sha256: sha_hex.to_owned(),
            perceptual_hash: None,
            content_holder_key_ids: vec![],
            claimant_key_id: author.clone(),
            legal_basis: basis,
            jurisdiction: "US".into(),
            good_faith_statement: "good faith".into(),
            claim_text: "claim".into(),
            evidence_refs: vec![],
            counter_notice_channel: None,
            asserted_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(30),
        };
        // v8.7.2 (#233 follow-on): the §11.10 gate requires the author to
        // be a duty-holder over the SIGNED content provenance. The payload
        // `subject_key_ids` is now advisory/routing-only — it no longer
        // admits. Storage/listing-mechanics tests using this helper must
        // seed an establishing `scores` attestation binding `sha_hex` with
        // signed subjects=[author] (see `seed_establishing_content`). The
        // advisory field is left set for routing parity.
        let mut payload_json = serde_json::to_value(&payload).unwrap();
        payload_json["subject_key_ids"] = serde_json::json!([author.clone()]);
        let mut env = ContributionEnvelope {
            contribution_id: Uuid::new_v4().to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author,
            subject: Cell {
                domain: format!("media-{}", Uuid::new_v4()),
                language: "en".into(),
                subject: Some(crate::cirisnode::TAKEDOWN_NOTICE_SUBJECT_KIND.into()),
            },
            payload: payload_json,
            witness_set: None,
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            submitted_at: Utc::now(),
        };
        env.signature = sign_envelope(&env, author_key);
        env
    }

    fn build_key_grant_contribution_sqlite(
        author_key: &ed25519_dalek::SigningKey,
        sha_hex: &str,
        recipient_key_id: &str,
    ) -> ContributionEnvelope {
        let author = pubkey_b64(author_key);
        let payload = crate::cirisnode::KeyGrantPayload {
            recipient_key_id: recipient_key_id.to_owned(),
            content_sha256: Some(sha_hex.to_owned()),
            epoch: None,
            wrapped_dek_base64: {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode([0u8; 48])
            },
            wrap_algorithm: crate::cirisnode::WrapAlgorithm::X25519MlKem768Aes256GcmHkdfSha256,
            ratchet_version: 1,
            key_validity_window: crate::cirisnode::KeyValidityWindow {
                not_before: Utc::now(),
                not_after: Utc::now() + chrono::Duration::days(30),
            },
            scope: crate::cirisnode::KeyGrantScope::SingleContent,
            scope_id: sha_hex.to_owned(),
            rotation_chain: vec![],
            // v34.0.0 (#704) — transit-only; absent on every other scope.
            ifac_size: None,
        };
        let mut env = ContributionEnvelope {
            contribution_id: Uuid::new_v4().to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author,
            subject: Cell {
                domain: format!("media-{}", Uuid::new_v4()),
                language: "en".into(),
                subject: Some(crate::cirisnode::KEY_GRANT_SUBJECT_KIND.into()),
            },
            payload: serde_json::to_value(&payload).unwrap(),
            witness_set: None,
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            submitted_at: Utc::now(),
        };
        env.signature = sign_envelope(&env, author_key);
        env
    }

    #[tokio::test]
    async fn sqlite_takedown_notice_admits_via_put_contribution() {
        let (b, cn) = fresh_backend().await;
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xF1; 32]);
        let author = pubkey_b64(&author_key);
        let sha_hex = fixture_sha_hex_sqlite(0x70);
        // v8.7.2: author must be a SIGNED subject of the establishing
        // content for the as-self takedown path to admit.
        seed_fed_key(&b, &author).await;
        seed_establishing_content(&b, "est-admit", &author, &sha_hex, &[&author]).await;
        let env = build_takedown_contribution_sqlite(
            &author_key,
            &sha_hex,
            crate::cirisnode::LegalBasis::Dmca512,
        );
        cn.put_contribution(env).await.unwrap();
    }

    #[tokio::test]
    async fn sqlite_takedown_notice_payload_shape_validates() {
        let (_b, cn) = fresh_backend().await;
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xF2; 32]);
        let env = build_takedown_contribution_sqlite(
            &author_key,
            "not-hex",
            crate::cirisnode::LegalBasis::Dmca512,
        );
        let err = cn.put_contribution(env).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn sqlite_key_grant_admits_via_put_contribution() {
        let (_b, cn) = fresh_backend().await;
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xF3; 32]);
        let sha_hex = fixture_sha_hex_sqlite(0x71);
        let env = build_key_grant_contribution_sqlite(&author_key, &sha_hex, "recipient-key-1");
        cn.put_contribution(env).await.unwrap();
    }

    #[tokio::test]
    async fn sqlite_key_grant_payload_shape_validates() {
        let (_b, cn) = fresh_backend().await;
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xF4; 32]);
        let sha_hex = fixture_sha_hex_sqlite(0x72);
        let mut env = build_key_grant_contribution_sqlite(&author_key, &sha_hex, "rec");
        if let Some(obj) = env.payload.as_object_mut() {
            obj.insert(
                "wrapped_dek_base64".into(),
                serde_json::Value::String("!!not_base64!!".into()),
            );
        }
        env.signature = sign_envelope(&env, &author_key);
        let err = cn.put_contribution(env).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn sqlite_list_takedowns_for_returns_only_matching_sha() {
        let (b, cn) = fresh_backend().await;
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xF5; 32]);
        let author = pubkey_b64(&author_key);
        let sha_a = fixture_sha_hex_sqlite(0x10);
        let sha_b = fixture_sha_hex_sqlite(0x20);
        // v8.7.2: author is the SIGNED subject of both target contents so
        // the as-self takedown path admits over each.
        seed_fed_key(&b, &author).await;
        seed_establishing_content(&b, "est-a", &author, &sha_a, &[&author]).await;
        seed_establishing_content(&b, "est-b", &author, &sha_b, &[&author]).await;
        cn.put_contribution(build_takedown_contribution_sqlite(
            &author_key,
            &sha_a,
            crate::cirisnode::LegalBasis::Dmca512,
        ))
        .await
        .unwrap();
        cn.put_contribution(build_takedown_contribution_sqlite(
            &author_key,
            &sha_b,
            crate::cirisnode::LegalBasis::DsaArticle16,
        ))
        .await
        .unwrap();
        let rows = cn.list_takedowns_for(&sha_a).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0]
                .payload
                .get("content_sha256")
                .and_then(|v| v.as_str()),
            Some(sha_a.as_str())
        );
    }

    #[tokio::test]
    async fn sqlite_list_key_grants_for_returns_only_matching_recipient() {
        let (_b, cn) = fresh_backend().await;
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xF6; 32]);
        let sha = fixture_sha_hex_sqlite(0x30);
        let recip = format!("rec-{}", Uuid::new_v4());
        let other = format!("other-{}", Uuid::new_v4());
        cn.put_contribution(build_key_grant_contribution_sqlite(
            &author_key,
            &sha,
            &recip,
        ))
        .await
        .unwrap();
        cn.put_contribution(build_key_grant_contribution_sqlite(
            &author_key,
            &sha,
            &other,
        ))
        .await
        .unwrap();
        let rows = cn.list_key_grants_for(&recip).await.unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn sqlite_list_key_grants_for_content_filters_both_axes() {
        let (_b, cn) = fresh_backend().await;
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xF7; 32]);
        let sha_a = fixture_sha_hex_sqlite(0x40);
        let sha_b = fixture_sha_hex_sqlite(0x50);
        let recip_a = format!("rec-a-{}", Uuid::new_v4());
        let recip_b = format!("rec-b-{}", Uuid::new_v4());
        cn.put_contribution(build_key_grant_contribution_sqlite(
            &author_key,
            &sha_a,
            &recip_a,
        ))
        .await
        .unwrap();
        cn.put_contribution(build_key_grant_contribution_sqlite(
            &author_key,
            &sha_a,
            &recip_b,
        ))
        .await
        .unwrap();
        cn.put_contribution(build_key_grant_contribution_sqlite(
            &author_key,
            &sha_b,
            &recip_a,
        ))
        .await
        .unwrap();
        let rows = cn
            .list_key_grants_for_content(&sha_a, &recip_a)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
    }

    // ── Cut C3b: scope/epoch-addressed grant cascade (CEG §10.5.3) ──

    /// The `scope_kind` tokens the reads are addressed by, taken from
    /// [`KeyGrantScope::as_str`] rather than spelled as literals — the
    /// tests must not be able to agree with themselves on a token the
    /// write path does not stamp (V129 header, #704).
    fn stream_kind() -> &'static str {
        crate::cirisnode::KeyGrantScope::StreamEpoch.as_str()
    }

    fn transit_kind() -> &'static str {
        crate::cirisnode::KeyGrantScope::TransitMembership.as_str()
    }

    fn build_scope_key_grant_sqlite(
        author_key: &ed25519_dalek::SigningKey,
        scope: crate::cirisnode::KeyGrantScope,
        scope_id: &str,
        epoch: u64,
        recipient_key_id: &str,
    ) -> ContributionEnvelope {
        let author = pubkey_b64(author_key);
        let payload = crate::cirisnode::KeyGrantPayload {
            recipient_key_id: recipient_key_id.to_owned(),
            content_sha256: None,
            epoch: Some(epoch),
            wrapped_dek_base64: {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode([0u8; 48])
            },
            wrap_algorithm: crate::cirisnode::WrapAlgorithm::X25519MlKem768Aes256GcmHkdfSha256,
            ratchet_version: 1,
            key_validity_window: crate::cirisnode::KeyValidityWindow {
                not_before: Utc::now(),
                not_after: Utc::now() + chrono::Duration::days(30),
            },
            scope,
            scope_id: scope_id.to_owned(),
            rotation_chain: vec![],
            // v34.0.0 (#704) — transit-only; absent on every other scope.
            ifac_size: None,
        };
        let mut env = ContributionEnvelope {
            contribution_id: Uuid::new_v4().to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author,
            subject: Cell {
                domain: format!("stream-{}", Uuid::new_v4()),
                language: "en".into(),
                subject: Some(crate::cirisnode::KEY_GRANT_SUBJECT_KIND.into()),
            },
            payload: serde_json::to_value(&payload).unwrap(),
            witness_set: None,
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            submitted_at: Utc::now(),
        };
        env.signature = sign_envelope(&env, author_key);
        env
    }

    fn build_stream_key_grant_sqlite(
        author_key: &ed25519_dalek::SigningKey,
        stream_id: &str,
        epoch: u64,
        recipient_key_id: &str,
    ) -> ContributionEnvelope {
        build_scope_key_grant_sqlite(
            author_key,
            crate::cirisnode::KeyGrantScope::StreamEpoch,
            stream_id,
            epoch,
            recipient_key_id,
        )
    }

    /// v34.0.0 (#704, CIRISEdge#492) — THE COLLISION WITNESS.
    ///
    /// `scope_id` is an id WITHIN a `scope_kind`, so the two vocabularies
    /// are free to collide: an IFAC `netname` may be spelled exactly like
    /// a `stream_id`. Two grants at the SAME `scope_id` and the SAME
    /// `epoch`, differing ONLY in `scope_kind`, must not see each other —
    /// the streaming reader gets the streaming grant, the transit reader
    /// gets the transit grant, and neither gets both.
    ///
    /// This is the ONLY shape that witnesses the `key_grant_scope_kind`
    /// predicate. Every other test on this read uses distinct
    /// `scope_id`s, and so passes with the predicate present or absent —
    /// which is the whole defect being fixed here. Delete
    /// `AND key_grant_scope_kind = ?1` from the sqlite read and this test
    /// goes red on both assertions; the neighbouring tests stay green.
    #[tokio::test]
    async fn sqlite_scope_kind_separates_colliding_scope_ids_at_same_epoch() {
        let (_b, cn) = fresh_backend().await;
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xD4; 32]);
        // ONE id string, used as a stream_id AND as a transit netname.
        let colliding_id = format!("collide-{}", Uuid::new_v4());
        let epoch = 7u64;
        let stream_recip = format!("rec-stream-{}", Uuid::new_v4());
        let transit_recip = format!("rec-transit-{}", Uuid::new_v4());

        let stream_grant = build_scope_key_grant_sqlite(
            &author_key,
            crate::cirisnode::KeyGrantScope::StreamEpoch,
            &colliding_id,
            epoch,
            &stream_recip,
        );
        let transit_grant = build_scope_key_grant_sqlite(
            &author_key,
            crate::cirisnode::KeyGrantScope::TransitMembership,
            &colliding_id,
            epoch,
            &transit_recip,
        );
        let stream_id_pk = stream_grant.contribution_id.clone();
        let transit_id_pk = transit_grant.contribution_id.clone();
        cn.put_contribution(stream_grant).await.unwrap();
        cn.put_contribution(transit_grant).await.unwrap();

        // The STREAMING read sees exactly the streaming grant.
        let streaming = cn
            .list_key_grants_for_scope_epoch(stream_kind(), &colliding_id, epoch)
            .await
            .unwrap();
        assert_eq!(
            streaming.len(),
            1,
            "streaming read must not see the transit grant at the same (scope_id, epoch); got {:?}",
            streaming
                .iter()
                .map(|e| e.contribution_id.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(streaming[0].contribution_id, stream_id_pk);
        let p: crate::cirisnode::KeyGrantPayload =
            serde_json::from_value(streaming[0].payload.clone()).unwrap();
        assert_eq!(p.scope, crate::cirisnode::KeyGrantScope::StreamEpoch);
        assert_eq!(p.recipient_key_id, stream_recip);

        // The TRANSIT read sees exactly the transit grant.
        let transit = cn
            .list_key_grants_for_scope_epoch(transit_kind(), &colliding_id, epoch)
            .await
            .unwrap();
        assert_eq!(
            transit.len(),
            1,
            "transit read must not see the streaming grant at the same (scope_id, epoch); got {:?}",
            transit
                .iter()
                .map(|e| e.contribution_id.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(transit[0].contribution_id, transit_id_pk);
        let p: crate::cirisnode::KeyGrantPayload =
            serde_json::from_value(transit[0].payload.clone()).unwrap();
        assert_eq!(p.scope, crate::cirisnode::KeyGrantScope::TransitMembership);
        assert_eq!(p.recipient_key_id, transit_recip);
    }

    /// A v2 stream/epoch grant is admitted, projected onto the V129
    /// columns, and served by list_key_grants_for_scope_epoch filtered
    /// on (scope_kind, scope_id, epoch) — and only that triple.
    #[tokio::test]
    async fn sqlite_stream_epoch_grant_round_trip_and_filter() {
        let (_b, cn) = fresh_backend().await;
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xC3; 32]);
        let stream = format!("stream-{}", Uuid::new_v4());
        let other_stream = format!("stream-{}", Uuid::new_v4());
        let recip = format!("rec-{}", Uuid::new_v4());

        // Two epochs of the target stream + one of another stream.
        cn.put_contribution(build_stream_key_grant_sqlite(
            &author_key,
            &stream,
            1,
            &recip,
        ))
        .await
        .unwrap();
        cn.put_contribution(build_stream_key_grant_sqlite(
            &author_key,
            &stream,
            2,
            &recip,
        ))
        .await
        .unwrap();
        cn.put_contribution(build_stream_key_grant_sqlite(
            &author_key,
            &other_stream,
            1,
            &recip,
        ))
        .await
        .unwrap();

        // (stream, epoch 1) returns exactly the one grant.
        let rows = cn
            .list_key_grants_for_scope_epoch(stream_kind(), &stream, 1)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "exactly the (stream, epoch=1) grant");
        // A different epoch of the same stream is a distinct authorization.
        let rows2 = cn
            .list_key_grants_for_scope_epoch(stream_kind(), &stream, 2)
            .await
            .unwrap();
        assert_eq!(rows2.len(), 1);
        // An epoch with no grant is empty (LensCore sees this and pulls).
        let none = cn
            .list_key_grants_for_scope_epoch(stream_kind(), &stream, 99)
            .await
            .unwrap();
        assert!(none.is_empty());
    }

    /// v16 (#432, CC 5.1 `CLM-epoch-keying`) — SQLite parity for the
    /// dedicated `put_key_grant` writer: (S, n) grant appears in
    /// list(S, n) and NOT in list(S, n+1) / list(S', n); a second
    /// grantee in the same epoch is listed alongside; duplicate
    /// `contribution_id` (the PK) → Conflict, re-grant under a fresh
    /// id appends; non-key_grant envelopes are rejected fail-closed.
    #[tokio::test]
    async fn sqlite_put_key_grant_writer_round_trip_epoch_isolation() {
        let (_b, cn) = fresh_backend().await;
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xC7; 32]);
        let stream = format!("stream-{}", Uuid::new_v4());
        let other_stream = format!("stream-{}", Uuid::new_v4());
        let recip_a = format!("rec-{}", Uuid::new_v4());
        let recip_b = format!("rec-{}", Uuid::new_v4());

        // (S, 1) grantee A — reused below for the Conflict check.
        let grant_a = build_stream_key_grant_sqlite(&author_key, &stream, 1, &recip_a);
        cn.put_key_grant(grant_a.clone()).await.unwrap();
        // (S, 1) grantee B — second grantee, same epoch.
        cn.put_key_grant(build_stream_key_grant_sqlite(
            &author_key,
            &stream,
            1,
            &recip_b,
        ))
        .await
        .unwrap();
        // Epoch + stream noise: (S, 2) and (S', 1).
        cn.put_key_grant(build_stream_key_grant_sqlite(
            &author_key,
            &stream,
            2,
            &recip_a,
        ))
        .await
        .unwrap();
        cn.put_key_grant(build_stream_key_grant_sqlite(
            &author_key,
            &other_stream,
            1,
            &recip_a,
        ))
        .await
        .unwrap();

        // list(S, 1) = both grantees, and ONLY epoch-1 rows.
        let rows = cn
            .list_key_grants_for_scope_epoch(stream_kind(), &stream, 1)
            .await
            .unwrap();
        assert_eq!(rows.len(), 2, "both (S,1) grantees listed");
        let recipients: std::collections::HashSet<String> = rows
            .iter()
            .map(|env| {
                let p: crate::cirisnode::KeyGrantPayload =
                    serde_json::from_value(env.payload.clone()).unwrap();
                assert_eq!(p.scope_id, stream);
                assert_eq!(p.epoch, Some(1));
                p.recipient_key_id
            })
            .collect();
        assert!(recipients.contains(&recip_a) && recipients.contains(&recip_b));
        // Epoch isolation: (S, 2) and (S', 1) see only their own
        // grants; (S, 3) is empty.
        assert_eq!(
            cn.list_key_grants_for_scope_epoch(stream_kind(), &stream, 2)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            cn.list_key_grants_for_scope_epoch(stream_kind(), &other_stream, 1)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(cn
            .list_key_grants_for_scope_epoch(stream_kind(), &stream, 3)
            .await
            .unwrap()
            .is_empty());

        // Conflict: same contribution_id (the PK) re-written → Conflict.
        let dup = cn.put_key_grant(grant_a.clone()).await.unwrap_err();
        assert!(matches!(dup, Error::Conflict(_)), "got: {dup:?}");
        // Re-grant same (S, 1, recip_a) under a FRESH id appends.
        cn.put_key_grant(build_stream_key_grant_sqlite(
            &author_key,
            &stream,
            1,
            &recip_a,
        ))
        .await
        .unwrap();
        assert_eq!(
            cn.list_key_grants_for_scope_epoch(stream_kind(), &stream, 1)
                .await
                .unwrap()
                .len(),
            3,
            "re-grant under a fresh contribution_id appends"
        );

        // Fail-closed: non-key_grant envelopes through the dedicated
        // writer are rejected with no row.
        let mut not_grant = build_stream_key_grant_sqlite(&author_key, &stream, 5, &recip_a);
        not_grant.subject.subject = Some("arc_question".into());
        not_grant.signature = sign_envelope(&not_grant, &author_key);
        let err = cn.put_key_grant(not_grant).await.unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(ref m) if m.contains("subject_kind")),
            "got: {err:?}"
        );
        let mut wrong_type = build_stream_key_grant_sqlite(&author_key, &stream, 5, &recip_a);
        wrong_type.contribution_type = ContributionType::ModerationEvent;
        wrong_type.signature = sign_envelope(&wrong_type, &author_key);
        let err = cn.put_key_grant(wrong_type).await.unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(ref m) if m.contains("contribution_type=proposal")),
            "got: {err:?}"
        );
        assert!(cn
            .list_key_grants_for_scope_epoch(stream_kind(), &stream, 5)
            .await
            .unwrap()
            .is_empty());
    }

    /// CEG 0.3 §5.6.8.4 — option (b) supersession: retire_key_grants
    /// emits a FRESH key_grant Contribution with rotation_chain
    /// extended by the prior contribution_id.
    #[tokio::test]
    async fn sqlite_retire_key_grants_emits_rotation_chain_not_withdraws() {
        let (backend, cn) = fresh_backend().await;
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xF8; 32]);
        let author = pubkey_b64(&author_key);

        // Seed federation_keys for the actor so the put_contribution
        // signature-verify path clears.
        let key_record = crate::federation::types::KeyRecord {
            key_id: author.clone(),
            pubkey_ed25519_base64: author.clone(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: author.clone(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({"id": author}),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: author.clone(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        use crate::federation::FederationDirectory;
        backend
            .put_public_key(crate::federation::types::SignedKeyRecord { record: key_record })
            .await
            .unwrap();

        let sha_a = fixture_sha_hex_sqlite(0x60);
        let sha_b = fixture_sha_hex_sqlite(0x61);
        let prior_a = build_key_grant_contribution_sqlite(&author_key, &sha_a, "rec-1");
        let prior_a_id = prior_a.contribution_id.clone();
        let prior_b = build_key_grant_contribution_sqlite(&author_key, &sha_b, "rec-2");
        let prior_b_id = prior_b.contribution_id.clone();
        cn.put_contribution(prior_a).await.unwrap();
        cn.put_contribution(prior_b).await.unwrap();

        use crate::signing::{LocalSigner, LocalSignerHardwareAdapter};
        let local = std::sync::Arc::new(LocalSigner::from_parts(
            author_key.clone(),
            author.clone(),
            None,
            None,
        ));
        let signer = LocalSignerHardwareAdapter::new(local);
        let report = cn
            .retire_key_grants(&author, &signer, Utc::now())
            .await
            .unwrap();
        assert_eq!(report.grants_seen, 2);
        assert_eq!(report.supersedes_emitted, 2);
        assert_eq!(report.supersedes_failed, 0);

        let recip_a_grants = cn.list_key_grants_for("rec-1").await.unwrap();
        let supersedes_a = recip_a_grants
            .iter()
            .find(|g| {
                g.payload
                    .get("rotation_chain")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().any(|x| x.as_str() == Some(prior_a_id.as_str())))
                    .unwrap_or(false)
            })
            .expect("supersession grant referencing prior_a_id");
        assert_eq!(
            supersedes_a
                .payload
                .get("wrapped_dek_base64")
                .and_then(|v| v.as_str()),
            Some(""),
            "CEG 0.3 §5.6.8.4 revocation sentinel: empty DEK base64"
        );
        assert_eq!(
            supersedes_a
                .payload
                .get("wrap_algorithm")
                .and_then(|v| v.as_str()),
            Some("x25519_mlkem768_aes256_gcm_hkdf_sha256"),
            "CEG 0.3 §5.6.8.4 wrap_algorithm wire string"
        );

        let recip_b_grants = cn.list_key_grants_for("rec-2").await.unwrap();
        assert!(
            recip_b_grants.iter().any(|g| g
                .payload
                .get("rotation_chain")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().any(|x| x.as_str() == Some(prior_b_id.as_str())))
                .unwrap_or(false)),
            "supersession grant referencing prior_b_id"
        );
    }

    /// V054 trigger discipline (SQLite): bare-SQL INSERT that
    /// violates the takedown subject_kind / column asymmetry must
    /// be rejected at the trigger.
    #[tokio::test]
    async fn sqlite_v054_trigger_rejects_mismatched_takedown_columns() {
        let (backend, _cn) = fresh_backend().await;
        let conn = backend.conn_handle();
        let err = (move || -> rusqlite::Result<usize> {
            let guard = conn.lock();
            guard.execute(
                "INSERT INTO cirisnode_contributions (\
                    contribution_id, contribution_type, domain, language, subject_kind, \
                    author_id, payload, witness_set, submitted_at, \
                    signature, signing_key_id, signature_verified, persist_row_hash, \
                    takedown_legal_basis\
                 ) VALUES ('id-1', 'proposal', 'd', 'en', 'arc_question', 'a', '{}', NULL, \
                           '2026-01-01T00:00:00Z', 'sig', 'a', 1, 'h', 'dmca_512')",
                [],
            )
        })()
        .unwrap_err();
        let detail = err.to_string();
        assert!(
            detail.contains("constitutional")
                || detail.contains("constraint")
                || detail.contains("takedown"),
            "expected trigger violation; got: {detail}"
        );
    }

    #[tokio::test]
    async fn sqlite_v054_trigger_rejects_mismatched_key_grant_columns() {
        let (backend, _cn) = fresh_backend().await;
        let conn = backend.conn_handle();
        let err = (move || -> rusqlite::Result<usize> {
            let guard = conn.lock();
            guard.execute(
                "INSERT INTO cirisnode_contributions (\
                    contribution_id, contribution_type, domain, language, subject_kind, \
                    author_id, payload, witness_set, submitted_at, \
                    signature, signing_key_id, signature_verified, persist_row_hash, \
                    key_grant_recipient_key_id\
                 ) VALUES ('id-2', 'proposal', 'd', 'en', 'arc_question', 'a', '{}', NULL, \
                           '2026-01-01T00:00:00Z', 'sig', 'a', 1, 'h', 'rec-1')",
                [],
            )
        })()
        .unwrap_err();
        let detail = err.to_string();
        assert!(
            detail.contains("constitutional")
                || detail.contains("constraint")
                || detail.contains("key_grant"),
            "expected trigger violation; got: {detail}"
        );
    }

    // v34.0.0 (CIRISPersist#704, V129) — DELETED:
    // `sqlite_v064_trigger_admits_both_key_grant_addressing_modes`.
    //
    // The test's central positive case asserted that a key_grant carrying the
    // V064 stream/epoch column pair and nothing else INSERTS —
    // "stream/epoch-addressed key_grant must insert post-V064". V129 renamed
    // that pair to `(key_grant_scope_id, key_grant_epoch)` and added a THIRD
    // column, `key_grant_scope_kind`, which the recreated asymmetry triggers
    // require alongside them: a two-of-three scope insert is now refused by
    // construction. The assertion cannot be carried across the rename — only
    // replaced by a different one about a different rule — and the test's name
    // pins V064's rule, so it is deleted rather than rewritten into a passing
    // shape that still claims to check V064.
    //
    // The V129 rule (all three scope columns together, XOR content-addressed)
    // is unguarded at the DB layer here as a result and wants a deliberately
    // authored V129-named replacement.

    /// v34.0.0 (CIRISPersist#704, V129) — the authored replacement for the
    /// deleted `sqlite_v064_trigger_admits_both_key_grant_addressing_modes`.
    ///
    /// BARE SQL, DELIBERATELY. The subject under test is the recreated
    /// `cirisnode_contributions_key_grant_asymmetry_ins` trigger, not the Rust
    /// write path. Routing through `put_contribution` would let
    /// `extract_key_grant_payload` refuse the half-addressed shapes first and
    /// the trigger would never run — the test would pass while the DB rule was
    /// arbitrarily wrong, which is the whole class this test exists to close.
    ///
    /// Two ADMITs (the two branches of the XOR) and five REFUSEs (every
    /// half-addressed shape between them, plus a non-grant row carrying grant
    /// columns). The refusals assert the ABORT TEXT names the addressing rule:
    /// a bare `is_err()` would also be satisfied by a typo'd column list or an
    /// unrelated NOT NULL, and would then keep passing after the trigger was
    /// dropped.
    #[tokio::test]
    async fn sqlite_v129_trigger_admits_scope_epoch_and_refuses_half_addressed() {
        let (backend, _cn) = fresh_backend().await;
        let conn = backend.conn_handle();

        // Valid per the V054 single-column CHECK (64 lowercase hex).
        const SHA: &str = "aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00ee11ff2233445566778899aa";

        // ONE insert shape, every addressing column bound by the caller, so
        // each case below differs from its neighbour in exactly the columns
        // the rule is about — and nothing else can explain a refusal.
        let insert = |id: &str,
                      subject_kind: &str,
                      recipient: Option<&str>,
                      sha: Option<&str>,
                      scope_kind: Option<&str>,
                      scope_id: Option<&str>,
                      epoch: Option<i64>|
         -> rusqlite::Result<usize> {
            let guard = conn.lock();
            guard.execute(
                "INSERT INTO cirisnode_contributions (\
                    contribution_id, contribution_type, domain, language, subject_kind, \
                    author_id, payload, witness_set, submitted_at, \
                    signature, signing_key_id, signature_verified, persist_row_hash, \
                    media_content_sha256, key_grant_recipient_key_id, \
                    key_grant_scope_kind, key_grant_scope_id, key_grant_epoch\
                 ) VALUES (?1, 'proposal', 'd', 'en', ?2, 'a', '{}', NULL, \
                           '2026-01-01T00:00:00Z', 'sig', 'a', 1, 'h', \
                           ?4, ?3, ?5, ?6, ?7)",
                params![
                    id,
                    subject_kind,
                    recipient,
                    sha,
                    scope_kind,
                    scope_id,
                    epoch
                ],
            )
        };

        // A refusal only counts if the ABORT names THIS rule. The V129
        // trigger's RAISE text is the only one in the schema carrying
        // "exactly one addressing mode" — the V054 takedown pair, the V046
        // accord-carrier pair and the V056 consent pair all say something
        // else, and a malformed statement says something else again.
        let expect_v129_abort = |label: &str, err: rusqlite::Error| {
            let detail = err.to_string();
            assert!(
                detail.contains("exactly one addressing mode")
                    && detail.contains("key_grant_scope_kind"),
                "{label}: expected the V129 key_grant asymmetry trigger to ABORT; \
                 got a different failure: {detail}"
            );
        };

        // ── ADMIT ───────────────────────────────────────────────────────
        // (a) content-addressed: sha NOT NULL, all three scope cols NULL.
        insert(
            "v129-a",
            "key_grant",
            Some("rec-1"),
            Some(SHA),
            None,
            None,
            None,
        )
        .expect("(a) content-addressed key_grant must insert under V129");

        // (b) scope-epoch-addressed: all three NOT NULL, sha NULL. Written
        //     with the TRANSIT scope kind on purpose — it is the value V064
        //     could not express, so this row is the one the cut exists for.
        insert(
            "v129-b",
            "key_grant",
            Some("rec-1"),
            None,
            Some(crate::cirisnode::KeyGrantScope::TransitMembership.as_str()),
            Some("netname-1"),
            Some(3),
        )
        .expect("(b) scope-epoch-addressed key_grant must insert under V129");

        // ── REFUSE — the half-addressed shapes ──────────────────────────
        // (c) scope_kind + scope_id, epoch NULL.
        expect_v129_abort(
            "(c) scope_kind + scope_id, no epoch",
            insert(
                "v129-c",
                "key_grant",
                Some("rec-1"),
                None,
                Some("stream_epoch"),
                Some("scope-1"),
                None,
            )
            .expect_err("(c) must be refused"),
        );

        // (d) scope_kind + epoch, scope_id NULL.
        expect_v129_abort(
            "(d) scope_kind + epoch, no scope_id",
            insert(
                "v129-d",
                "key_grant",
                Some("rec-1"),
                None,
                Some("stream_epoch"),
                None,
                Some(3),
            )
            .expect_err("(d) must be refused"),
        );

        // (e) scope_id + epoch, scope_kind NULL — the exact V064 shape, now
        //     refused by construction. This is the assertion that inverts the
        //     deleted test's central positive case.
        expect_v129_abort(
            "(e) scope_id + epoch, no scope_kind (the V064 pair)",
            insert(
                "v129-e",
                "key_grant",
                Some("rec-1"),
                None,
                None,
                Some("scope-1"),
                Some(3),
            )
            .expect_err("(e) must be refused"),
        );

        // (f) BOTH addressing modes populated — the XOR, not an OR.
        expect_v129_abort(
            "(f) content AND scope-epoch",
            insert(
                "v129-f",
                "key_grant",
                Some("rec-1"),
                Some(SHA),
                Some("stream_epoch"),
                Some("scope-1"),
                Some(3),
            )
            .expect_err("(f) must be refused"),
        );

        // (g) a non-key_grant subject_kind carrying key_grant columns. Uses
        //     the SCOPE columns with a NULL recipient, so it is V129's half
        //     of the asymmetry and not the recipient half V054 already pins.
        expect_v129_abort(
            "(g) non-key_grant row carrying key_grant scope columns",
            insert(
                "v129-g",
                "arc_question",
                None,
                None,
                Some("stream_epoch"),
                Some("scope-1"),
                Some(3),
            )
            .expect_err("(g) must be refused"),
        );
    }

    // ── v8.7.0 (CIRISPersist#232, CEG §11.10) — delegated-duty gate on
    // the cirisnode `ModerationEvent` (moderate scope) + `takedown_notice`
    // (takedown scope) primitives. The cirisnode SQLite backend shares its
    // connection with the federation `SqliteBackend`, so seeding
    // federation_keys + `delegates_to` rows via `_b` makes them visible to
    // the gate's `from_conn_handle` directory view.

    /// Seed a `federation_keys` row for `key_id` (identity_type=primitive).
    async fn seed_fed_key(backend: &SqliteBackend, key_id: &str) {
        use crate::federation::FederationDirectory;
        // v9.0.0 (CC 5.3.2.4.3.1) — real deterministic hybrid pubkeys (see
        // `seed_user_key`).
        let (ed_pk, mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(key_id);
        let rec = crate::federation::types::KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: key_id.into(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": key_id }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        backend
            .put_public_key(crate::federation::types::SignedKeyRecord { record: rec })
            .await
            .unwrap();
    }

    /// Seed a `delegates_to` edge `granter → grantee` bearing `scope`.
    async fn seed_delegation(
        backend: &SqliteBackend,
        id: &str,
        granter: &str,
        grantee: &str,
        scope: serde_json::Value,
    ) {
        use crate::federation::FederationDirectory;
        // v9.0.0 (CC 5.3.2.4.3.1) — hybrid-sign with `granter`'s
        // deterministic key (matches the registered pubkeys).
        let envelope = serde_json::json!({
            "references_attestation_id": id,
            "scope": scope,
        });
        let (och, classical, pqc) =
            crate::federation::tier_ingest::test_support::sign_envelope(granter, &envelope);
        let att = crate::federation::types::Attestation {
            attestation_id: id.into(),
            attesting_key_id: granter.into(),
            attested_key_id: grantee.into(),
            attestation_type: crate::federation::types::attestation_type::DELEGATES_TO.into(),
            weight: None,
            asserted_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            scrub_key_id: granter.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: Some("2026-05-01T00:00:00Z".parse().unwrap()),
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_string(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        // v31.0.0 (CIRISPersist#598/#643) — SEAL, don't hand-sign: the put door
        // requires the signed instants and the typed-column mirror.
        let att = crate::federation::tier_ingest::test_support::seal_row(granter, att);
        backend
            .put_attestation(crate::federation::types::SignedAttestation { attestation: att })
            .await
            .unwrap();
    }

    /// Seed a `delegates_to` edge `granter → grantee` bearing `scope`,
    /// with an explicit `sub_delegation` flag (§11.10 deputization).
    async fn seed_delegation_sub(
        backend: &SqliteBackend,
        id: &str,
        granter: &str,
        grantee: &str,
        scope: serde_json::Value,
        sub_delegation: bool,
    ) {
        use crate::federation::FederationDirectory;
        // v9.0.0 (CC 5.3.2.4.3.1) — hybrid-sign with `granter`'s
        // deterministic key (matches the registered pubkeys).
        let envelope = serde_json::json!({
            "references_attestation_id": id,
            "scope": scope,
            "sub_delegation": sub_delegation,
        });
        let (och, classical, pqc) =
            crate::federation::tier_ingest::test_support::sign_envelope(granter, &envelope);
        let att = crate::federation::types::Attestation {
            attestation_id: id.into(),
            attesting_key_id: granter.into(),
            attested_key_id: grantee.into(),
            attestation_type: crate::federation::types::attestation_type::DELEGATES_TO.into(),
            weight: None,
            asserted_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            scrub_key_id: granter.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: Some("2026-05-01T00:00:00Z".parse().unwrap()),
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_string(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        // v31.0.0 (CIRISPersist#598/#643) — SEAL, don't hand-sign: the put door
        // requires the signed instants and the typed-column mirror.
        let att = crate::federation::tier_ingest::test_support::seal_row(granter, att);
        backend
            .put_attestation(crate::federation::types::SignedAttestation { attestation: att })
            .await
            .unwrap();
    }

    /// Seed a `federation_keys` row for `key_id` with identity_type=user
    /// (steward-bound by clause (1) of `is_steward_bound`).
    async fn seed_user_key(backend: &SqliteBackend, key_id: &str) {
        use crate::federation::FederationDirectory;
        // v9.0.0 (CC 5.3.2.4.3.1) — register REAL deterministic hybrid
        // pubkeys so the federation-tier seed attestations (signed via
        // `sign_envelope(key_id, ...)`) verify at the ingest gate.
        // Moderation/contribution payloads are verified self-contained
        // against their `author_id` pubkey (SCHEMA.md §2.2), NOT this
        // registered row, so overriding the registered Ed25519 pubkey here
        // is safe.
        let (ed_pk, mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(key_id);
        let rec = crate::federation::types::KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::USER.into(),
            identity_ref: key_id.into(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": key_id }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        backend
            .put_public_key(crate::federation::types::SignedKeyRecord { record: rec })
            .await
            .unwrap();
    }

    /// v8.7.2 (CIRISPersist#233 follow-on, CEG RC27 §11.10) — seed a
    /// content-ESTABLISHING federation `scores` attestation that binds
    /// `content_sha256` in its envelope `evidence_refs` and carries the
    /// SIGNED `subject_key_ids`. This is what `subject_of_content` resolves
    /// over — the producer's signed subject set behind the hash, NOT a
    /// later takedown/moderation payload's self-declared subjects.
    async fn seed_establishing_content(
        backend: &SqliteBackend,
        id: &str,
        producer: &str,
        content_sha256: &str,
        subjects: &[&str],
    ) {
        use crate::federation::FederationDirectory;
        // v9.0.0 (CC 5.3.2.4.3.1) — hybrid-sign the federation-tier
        // establishing-content envelope with `producer`'s deterministic
        // key (matching `seed_user_key`/`seed_fed_key`'s registered
        // pubkeys) so the ingest gate admits it.
        let envelope = serde_json::json!({
            "dimension": "content:established:v1",
            "evidence_refs": [content_sha256],
        });
        let (och, classical, pqc) =
            crate::federation::tier_ingest::test_support::sign_envelope(producer, &envelope);
        let att = crate::federation::types::Attestation {
            attestation_id: id.into(),
            attesting_key_id: producer.into(),
            attested_key_id: producer.into(),
            attestation_type: crate::federation::types::attestation_type::SCORES.into(),
            weight: None,
            asserted_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            scrub_key_id: producer.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: Some("2026-05-01T00:00:00Z".parse().unwrap()),
            persist_row_hash: String::new(),
            subject_key_ids: subjects.iter().map(|s| s.to_string()).collect(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_string(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        // v31.0.0 (CIRISPersist#598/#643) — SEAL, don't hand-sign. The put door
        // requires the signed instants and the typed-column mirror inside the
        // envelope; a hand-signed fixture is a row no host can write.
        let att = crate::federation::tier_ingest::test_support::seal_row(producer, att);
        backend
            .put_attestation(crate::federation::types::SignedAttestation { attestation: att })
            .await
            .unwrap();
    }

    /// Build a signed `ModerationEvent` from `signer_key`. `subjects` is
    /// the payload's (now advisory/routing-only) declared subject set;
    /// `content_sha256` is the target content hash that drives
    /// `subject_of` authority resolution.
    fn build_moderation_event(
        signer_key: &ed25519_dalek::SigningKey,
        target: &str,
        subjects: &[&str],
        community_id: Option<&str>,
        content_sha256: Option<&str>,
    ) -> ModerationEvent {
        let accuser = pubkey_b64(signer_key);
        let mut payload = serde_json::json!({
            "violation": "rogue_action",
            "subject_key_ids": subjects,
        });
        if let Some(c) = community_id {
            payload["community_id"] = serde_json::Value::String(c.to_owned());
        }
        if let Some(h) = content_sha256 {
            payload["content_sha256"] = serde_json::Value::String(h.to_owned());
        }
        let mut ev = ModerationEvent {
            moderation_id: Uuid::new_v4().to_string(),
            target_contributor: target.into(),
            accuser_id: accuser,
            payload,
            filed_at: Utc::now(),
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
        };
        ev.signature = sign_envelope(&ev, signer_key);
        ev
    }

    /// The content hash every `build_takedown_notice` targets — the
    /// establishing `scores` attestation must bind THIS hash for
    /// subject-self to resolve (v8.7.2).
    fn takedown_content_sha() -> String {
        fixture_sha_hex_sqlite(0x70)
    }

    /// Build a signed `takedown_notice` Contribution from `signer_key`.
    /// `subjects` is the payload's (now advisory/routing-only) declared
    /// subject set; authority resolves over [`takedown_content_sha`] via
    /// `subject_of_content`.
    fn build_takedown_notice(
        signer_key: &ed25519_dalek::SigningKey,
        subjects: &[&str],
        community_id: Option<&str>,
    ) -> ContributionEnvelope {
        let author = pubkey_b64(signer_key);
        let mut payload = serde_json::json!({
            "content_sha256": takedown_content_sha(),
            "claimant_key_id": author,
            "legal_basis": "ncmec_csam",
            "jurisdiction": "US",
            "good_faith_statement": "good faith",
            "claim_text": "test",
            "asserted_at": "2026-05-01T00:00:00Z",
            "expires_at": "2027-05-01T00:00:00Z",
            "subject_key_ids": subjects,
        });
        if let Some(c) = community_id {
            payload["community_id"] = serde_json::Value::String(c.to_owned());
        }
        let mut env = ContributionEnvelope {
            contribution_id: Uuid::new_v4().to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author,
            subject: Cell {
                domain: "media".into(),
                language: "en".into(),
                subject: Some(crate::cirisnode::TAKEDOWN_NOTICE_SUBJECT_KIND.into()),
            },
            payload,
            witness_set: None,
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            submitted_at: Utc::now(),
        };
        env.signature = sign_envelope(&env, signer_key);
        env
    }

    /// Seed a community keyed by `community_id` with a `founder` member.
    async fn seed_community(backend: &SqliteBackend, community_id: &str, founder: &str) {
        use crate::federation::FederationDirectory;
        // v21.0.0 (CIRISPersist#502 E4) — sign with `founder` (already
        // registered with real deterministic hybrid keys).
        backend
            .put_community(
                crate::federation::tier_ingest::test_support::sign_community(
                    founder,
                    crate::federation::types::Community {
                        community_key_id: community_id.into(),
                        community_name: "tc".into(),
                        members: vec![crate::federation::types::CommunityMember {
                            key_id: founder.into(),
                            joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                            role: Some("founder".into()),
                        }],
                        founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                        consensus_protocol:
                            crate::federation::types::consensus_protocol::FOUNDER_ONLY.into(),
                        policy_blob: None,
                        persist_row_hash: String::new(),
                    },
                ),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sqlite_moderation_event_full_matrix() {
        let (b, cn) = fresh_backend().await;
        let subject_key = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]);
        let delegate_key = ed25519_dalek::SigningKey::from_bytes(&[0x22; 32]);
        let rando_key = ed25519_dalek::SigningKey::from_bytes(&[0x33; 32]);
        let founder_key = ed25519_dalek::SigningKey::from_bytes(&[0x44; 32]);
        let subject = pubkey_b64(&subject_key);
        let delegate = pubkey_b64(&delegate_key);
        let rando = pubkey_b64(&rando_key);
        let founder = pubkey_b64(&founder_key);
        seed_user_key(&b, &subject).await;
        seed_user_key(&b, &founder).await;
        for k in [&delegate, &rando] {
            seed_fed_key(&b, k).await;
        }
        seed_community(&b, "comm-mod", &founder).await;

        // v8.7.2: seed the content-ESTABLISHING scores attestation binding
        // `sha` with SIGNED subjects = [subject]. subject-self authority
        // now resolves over THIS, not the moderation payload's declaration.
        let sha = fixture_sha_hex_sqlite(0x9a);
        seed_establishing_content(&b, "est-mod", &subject, &sha, &[&subject]).await;

        // (a) as-self subject (signed in the establishing content) → ADMITTED.
        cn.put_moderation_event(build_moderation_event(
            &subject_key,
            "target",
            &[&subject],
            None,
            Some(&sha),
        ))
        .await
        .expect("(a) as-self subject moderation admitted");

        // (b1) subject-delegated chain (subject → delegate, moderate) → ADMIT.
        seed_delegation(
            &b,
            "d-mod",
            &subject,
            &delegate,
            serde_json::json!(["moderate"]),
        )
        .await;
        cn.put_moderation_event(build_moderation_event(
            &delegate_key,
            "target",
            &[&subject],
            None,
            Some(&sha),
        ))
        .await
        .expect("(b1) subject-delegated moderation admitted");

        // (b2) named-moderator (community founder, steward-bound) → ADMIT.
        // No establishing content needed — community-scoped duty.
        cn.put_moderation_event(build_moderation_event(
            &founder_key,
            "target",
            &[],
            Some("comm-mod"),
            None,
        ))
        .await
        .expect("(b2) named-moderator (founder) moderation admitted");

        // (c) no authority → REJECTED.
        let err = cn
            .put_moderation_event(build_moderation_event(
                &rando_key,
                "target",
                &[&subject],
                None,
                Some(&sha),
            ))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "cirisnode_delegated_scope_unauthorized");

        // (c2) NOTHING — no subjects, no community → REJECTED (bypass guard).
        let err = cn
            .put_moderation_event(build_moderation_event(
                &rando_key,
                "target",
                &[],
                None,
                None,
            ))
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "cirisnode_delegated_scope_unauthorized",
            "(c2) absent principal must REJECT, not admit"
        );

        // (d) scope isolation — consent_revocation-only chain ⇏ moderate.
        seed_delegation(
            &b,
            "d-cr",
            &subject,
            &rando,
            serde_json::json!(["consent_revocation"]),
        )
        .await;
        let err = cn
            .put_moderation_event(build_moderation_event(
                &rando_key,
                "target",
                &[&subject],
                None,
                Some(&sha),
            ))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "cirisnode_delegated_scope_unauthorized");
    }

    /// v8.7.2 (CIRISPersist#233 follow-on, CEG RC27 §11.10; CIRISRegistry#96)
    /// — the self-declaration SPOOF is closed: a signer who self-declares
    /// `subject_key_ids=[self]` in the moderation payload but is NOT in the
    /// establishing content's SIGNED subjects and is NOT a named-mod is
    /// REJECTED. THE regression guard — payload self-declaration no longer
    /// admits.
    #[tokio::test]
    async fn sqlite_moderation_payload_self_declaration_spoof_rejected() {
        let (b, cn) = fresh_backend().await;
        let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[0xe1; 32]);
        let real_subject_key = ed25519_dalek::SigningKey::from_bytes(&[0xe2; 32]);
        let attacker = pubkey_b64(&attacker_key);
        let real_subject = pubkey_b64(&real_subject_key);
        seed_fed_key(&b, &attacker).await;
        seed_user_key(&b, &real_subject).await;

        // Establishing content's SIGNED subjects = [real_subject], NOT attacker.
        let sha = fixture_sha_hex_sqlite(0xb1);
        seed_establishing_content(&b, "est-spoof", &real_subject, &sha, &[&real_subject]).await;

        // Attacker self-declares subject_key_ids=[attacker] in the payload.
        // Pre-v8.7.2 this admitted (payload trust). Now: REJECT — attacker
        // is not in the signed subjects and is not a named-mod.
        let err = cn
            .put_moderation_event(build_moderation_event(
                &attacker_key,
                "target",
                &[&attacker],
                None,
                Some(&sha),
            ))
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "cirisnode_delegated_scope_unauthorized",
            "payload self-declaration must NOT admit (spoof closed)"
        );

        // The REAL signed subject still admits as-self over the same content.
        cn.put_moderation_event(build_moderation_event(
            &real_subject_key,
            "target",
            &[&real_subject],
            None,
            Some(&sha),
        ))
        .await
        .expect("real signed subject admits as-self");
    }

    /// v8.7.2 — fail-secure: no establishing attestation locally held ⇒
    /// subject-self FAILS (undetermined subject_of); the named-mod path (b)
    /// still ADMITs a real named-mod; a non-authority signer REJECTs.
    #[tokio::test]
    async fn sqlite_moderation_fail_secure_no_establishing_content() {
        let (b, cn) = fresh_backend().await;
        let subject_key = ed25519_dalek::SigningKey::from_bytes(&[0xf1; 32]);
        let founder_key = ed25519_dalek::SigningKey::from_bytes(&[0xf2; 32]);
        let rando_key = ed25519_dalek::SigningKey::from_bytes(&[0xf3; 32]);
        let subject = pubkey_b64(&subject_key);
        let founder = pubkey_b64(&founder_key);
        let rando = pubkey_b64(&rando_key);
        seed_user_key(&b, &subject).await;
        seed_user_key(&b, &founder).await;
        seed_fed_key(&b, &rando).await;
        seed_community(&b, "comm-fs", &founder).await;

        // No establishing content for this sha — subject_of is undetermined.
        let sha = fixture_sha_hex_sqlite(0xc2);

        // subject-self FAILS (nothing locally binds the hash to a subject).
        let err = cn
            .put_moderation_event(build_moderation_event(
                &subject_key,
                "target",
                &[&subject],
                None,
                Some(&sha),
            ))
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "cirisnode_delegated_scope_unauthorized",
            "fail-secure: undetermined subject_of must REJECT subject-self"
        );

        // named-mod path (b) still ADMITs a real steward-bound founder.
        cn.put_moderation_event(build_moderation_event(
            &founder_key,
            "target",
            &[&subject],
            Some("comm-fs"),
            Some(&sha),
        ))
        .await
        .expect("named-mod still admits under fail-secure subject_of");

        // a non-authority signer still REJECTs.
        let err = cn
            .put_moderation_event(build_moderation_event(
                &rando_key,
                "target",
                &[&subject],
                Some("comm-fs"),
                Some(&sha),
            ))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "cirisnode_delegated_scope_unauthorized");
    }

    #[tokio::test]
    async fn sqlite_takedown_notice_full_matrix() {
        let (b, cn) = fresh_backend().await;
        let subject_key = ed25519_dalek::SigningKey::from_bytes(&[0x4a; 32]);
        let delegate_key = ed25519_dalek::SigningKey::from_bytes(&[0x5a; 32]);
        let rando_key = ed25519_dalek::SigningKey::from_bytes(&[0x6a; 32]);
        let subject = pubkey_b64(&subject_key);
        let delegate = pubkey_b64(&delegate_key);
        let rando = pubkey_b64(&rando_key);
        seed_user_key(&b, &subject).await;
        for k in [&delegate, &rando] {
            seed_fed_key(&b, k).await;
        }

        // v8.7.2: the establishing scores attestation binds the takedown's
        // target hash with SIGNED subjects = [subject]. subject-self
        // authority resolves over THIS, not the takedown payload.
        let td_sha = takedown_content_sha();
        seed_establishing_content(&b, "est-td", &subject, &td_sha, &[&subject]).await;

        // (a) as-self subject (signed in the establishing content) → ADMITTED.
        cn.put_contribution(build_takedown_notice(&subject_key, &[&subject], None))
            .await
            .expect("(a) as-self subject takedown admitted");

        // (b1) subject-delegated chain (subject → delegate, takedown) → ADMIT.
        seed_delegation(
            &b,
            "d-td",
            &subject,
            &delegate,
            serde_json::json!(["takedown"]),
        )
        .await;
        cn.put_contribution(build_takedown_notice(&delegate_key, &[&subject], None))
            .await
            .expect("(b1) subject-delegated takedown admitted");

        // (c) no authority → REJECTED.
        let err = cn
            .put_contribution(build_takedown_notice(&rando_key, &[&subject], None))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "cirisnode_delegated_scope_unauthorized");

        // (c2) NOTHING → REJECTED (bypass-closed regression guard).
        let err = cn
            .put_contribution(build_takedown_notice(&rando_key, &[], None))
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            "cirisnode_delegated_scope_unauthorized",
            "(c2) absent principal must REJECT, not admit"
        );

        // (d) scope isolation — consent_revocation-only chain ⇏ takedown.
        seed_delegation(
            &b,
            "d-cr2",
            &subject,
            &rando,
            serde_json::json!(["consent_revocation"]),
        )
        .await;
        let err = cn
            .put_contribution(build_takedown_notice(&rando_key, &[&subject], None))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "cirisnode_delegated_scope_unauthorized");

        // (e) chain beyond the §11.10 depth cap (5) → REJECTED. Root k0 is
        // the steward-bound subject; every edge takedown-scoped + sub_delegation.
        let depth = crate::federation::admission::MAX_MODERATION_DELEGATION_DEPTH;
        let n = depth + 2;
        let chain_keys: Vec<ed25519_dalek::SigningKey> = (0..n)
            .map(|i| ed25519_dalek::SigningKey::from_bytes(&[0x80 + i as u8; 32]))
            .collect();
        let chain_ids: Vec<String> = chain_keys.iter().map(pubkey_b64).collect();
        seed_user_key(&b, &chain_ids[0]).await;
        for k in chain_ids.iter().skip(1) {
            seed_fed_key(&b, k).await;
        }
        for i in 0..(n - 1) {
            seed_delegation_sub(
                &b,
                &format!("dc{i}"),
                &chain_ids[i],
                &chain_ids[i + 1],
                serde_json::json!(["takedown"]),
                true,
            )
            .await;
        }
        // v8.7.2: bind chain_ids[0] as a SIGNED subject of td_sha so it is a
        // duty-holder root the walk starts from — otherwise the rejection
        // would be "not a duty-holder", not the depth-cap we want to assert.
        seed_establishing_content(&b, "est-depth", &chain_ids[0], &td_sha, &[&chain_ids[0]]).await;
        // signer = the too-deep tail; root (subject) = chain_ids[0].
        let err = cn
            .put_contribution(build_takedown_notice(
                &chain_keys[n - 1],
                &[&chain_ids[0]],
                None,
            ))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "cirisnode_delegated_scope_unauthorized");
    }
}
