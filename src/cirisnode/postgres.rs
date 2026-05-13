//! PostgreSQL impl of [`NodeCoreService`] (v0.7.0-α4).
//!
//! Concrete impl backed by `cirisnode.*` (V011 schema). Every
//! typed-write goes through a `verify_envelope_signature` gate
//! before INSERT (audit-envelope invariant from FSD Appendix A.2).
//! Reads follow the v0.5.5 §I cursor-paged newest-first shape.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::service::NodeCoreService;
use super::types::{
    Cell, ContributionEnvelope, ContributionListPage, ContributionType, ContributionsFilter,
    CreditsLedgerEntry, CreditsUpdate, ExpertiseLedgerEntry, ExpertiseUpdate, HybridSignature,
    ListCursor, ModerationEvent, ReconsiderationAttestation, ReconsiderationRequest,
    RoutableContributor, SlashingAttestation, VoteEnvelope, VoteListPage, VoteWeight, VotesFilter,
};
use super::Error;
use crate::store::postgres::PostgresBackend;

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

/// Parse a ULID-or-UUID string to a UUID (V011 columns are UUID type).
/// CIRISNodeCore uses ULIDs (`SCHEMA.md` §2.2); we accept either since
/// both fit in 128 bits.
fn parse_id(s: &str) -> Result<Uuid, Error> {
    // Try UUID-string first; fall back to ULID-string interpretation
    // by stripping non-hex chars. ULIDs use Crockford base32 which is
    // NOT directly UUID-compatible; we strict-parse UUID here. If the
    // caller passes a ULID, they should convert client-side first.
    Uuid::parse_str(s)
        .map_err(|e| Error::InvalidArgument(format!("id parse: {e} (id={s}) — expected UUID")))
}

/// v0.7.0-α4 signature-verify stub. Real impl threads
/// `verify_hybrid_via_directory` from v0.4.1 once the caller-side
/// canonicalization for cirisnode envelopes is locked. For now: parse
/// the signature fields, require ed25519 to be base64-decodable,
/// require signed_at to be non-zero. Production wiring lands in a
/// v0.7.0.x patch once the canonical-bytes spec is settled.
fn verify_envelope_signature(sig: &HybridSignature) -> Result<(), Error> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    if sig.ed25519.is_empty() {
        return Err(Error::Signature("ed25519 signature missing".into()));
    }
    BASE64
        .decode(&sig.ed25519)
        .map_err(|e| Error::Signature(format!("ed25519 not base64: {e}")))?;
    if let Some(ml) = &sig.ml_dsa_65 {
        BASE64
            .decode(ml)
            .map_err(|e| Error::Signature(format!("ml_dsa_65 not base64: {e}")))?;
    }
    // signed_at non-default (DateTime::default() is the UNIX epoch).
    if sig.signed_at.timestamp() <= 0 {
        return Err(Error::Signature("signed_at unset".into()));
    }
    Ok(())
}

/// Translate tokio_postgres errors into typed Error variants.
/// `unique_violation` 23505 → Conflict; FK violation 23503 →
/// InvalidArgument; check 23514 → InvalidArgument; everything else
/// → Backend (with the inner db-error message preserved for tracing).
fn map_pg_error(e: tokio_postgres::Error, op: &str) -> Error {
    use tokio_postgres::error::SqlState;
    // The tokio_postgres `Display` impl is famously terse ("db error")
    // — pull the SQLSTATE off the typed cause instead.
    let code = e.as_db_error().map(|d| d.code().clone());
    let detail = e
        .as_db_error()
        .map(|d| d.message().to_owned())
        .unwrap_or_else(|| e.to_string());
    match code {
        Some(c) if c == SqlState::UNIQUE_VIOLATION => Error::Conflict(format!("{op}: {detail}")),
        Some(c) if c == SqlState::FOREIGN_KEY_VIOLATION => {
            Error::InvalidArgument(format!("{op} FK: {detail}"))
        }
        Some(c) if c == SqlState::CHECK_VIOLATION => {
            Error::InvalidArgument(format!("{op} CHECK: {detail}"))
        }
        _ => Error::Backend(format!("{op}: {detail}")),
    }
}

// ─── NodeCoreService impl ───────────────────────────────────────────

impl NodeCoreService for PostgresBackend {
    async fn put_contribution(&self, env: ContributionEnvelope) -> Result<(), Error> {
        verify_envelope_signature(&env.signature)?;
        let id = parse_id(&env.contribution_id)?;
        let subject_kind = env.subject.subject.as_deref().ok_or_else(|| {
            Error::InvalidArgument(
                "subject.subject (subject_kind) required for contributions".into(),
            )
        })?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let witness_set_json = match &env.witness_set {
            None => serde_json::Value::Null,
            Some(ws) => serde_json::to_value(ws).map_err(|e| Error::Internal(e.to_string()))?,
        };
        client
            .execute(
                "INSERT INTO cirisnode.contributions (\
                    contribution_id, contribution_type, domain, language, subject_kind, \
                    author_id, payload, witness_set, submitted_at, \
                    signature, signing_key_id, signature_verified, persist_row_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, TRUE, $12)",
                &[
                    &id,
                    &contribution_type_str(env.contribution_type),
                    &env.subject.domain,
                    &env.subject.language,
                    &subject_kind,
                    &env.author_id,
                    &env.payload,
                    &witness_set_json,
                    &env.submitted_at,
                    &env.signature.ed25519,
                    &env.author_id, // signing_key_id = author for self-signed contributions
                    &env.signature.ed25519, // persist_row_hash placeholder; canonical hash lands in v0.7.0.x
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "put_contribution"))?;
        Ok(())
    }

    async fn cast_vote(&self, env: VoteEnvelope) -> Result<(), Error> {
        verify_envelope_signature(&env.signature)?;
        let id = parse_id(&env.vote_id)?;
        let contribution_id = match &env.contribution_id {
            Some(c) => Some(parse_id(c)?),
            None => None,
        };
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let payload = serde_json::json!({
            "score": env.score,
            "rationale": env.rationale,
        });
        client
            .execute(
                "INSERT INTO cirisnode.votes (\
                    vote_id, contribution_id, voter_id, domain, language, \
                    payload, cast_at, signature, signing_key_id, signature_verified, \
                    persist_row_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE, $10)",
                &[
                    &id,
                    &contribution_id,
                    &env.voter_id,
                    &env.cell.domain,
                    &env.cell.language,
                    &payload,
                    &env.cast_at,
                    &env.signature.ed25519,
                    &env.voter_id,
                    &env.signature.ed25519,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "cast_vote"))?;
        Ok(())
    }

    async fn update_credits_ledger(&self, update: CreditsUpdate) -> Result<(), Error> {
        let source = parse_id(&update.source_contribution)?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        client
            .execute(
                "INSERT INTO cirisnode.credits_ledger (\
                    contributor_id, domain, language, subject, balance, \
                    last_update_contribution, last_updated_at\
                 ) VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
                 ON CONFLICT (contributor_id, domain, language, subject) DO UPDATE \
                 SET balance = EXCLUDED.balance, \
                     last_update_contribution = EXCLUDED.last_update_contribution, \
                     last_updated_at = NOW()",
                &[
                    &update.contributor_id,
                    &update.domain,
                    &update.language,
                    &update.subject,
                    &update.new_balance,
                    &source,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "update_credits_ledger"))?;
        Ok(())
    }

    async fn update_expertise_ledger(&self, update: ExpertiseUpdate) -> Result<(), Error> {
        if !(0.0..=1.0).contains(&update.new_expertise) {
            return Err(Error::InvalidArgument(format!(
                "new_expertise must be in [0, 1] (got {})",
                update.new_expertise
            )));
        }
        let source = parse_id(&update.source_contribution)?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        client
            .execute(
                "INSERT INTO cirisnode.expertise_ledger (\
                    contributor_id, domain, language, expertise, is_active, \
                    last_update_contribution, last_updated_at\
                 ) VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
                 ON CONFLICT (contributor_id, domain, language) DO UPDATE \
                 SET expertise = EXCLUDED.expertise, \
                     is_active = EXCLUDED.is_active, \
                     last_update_contribution = EXCLUDED.last_update_contribution, \
                     last_updated_at = NOW()",
                &[
                    &update.contributor_id,
                    &update.domain,
                    &update.language,
                    &update.new_expertise,
                    &update.new_active_tier,
                    &source,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "update_expertise_ledger"))?;
        Ok(())
    }

    async fn put_moderation_event(&self, event: ModerationEvent) -> Result<(), Error> {
        verify_envelope_signature(&event.signature)?;
        let id = parse_id(&event.moderation_id)?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        client
            .execute(
                "INSERT INTO cirisnode.moderation_events (\
                    moderation_id, target_contributor, accuser_id, payload, filed_at, \
                    signature, signing_key_id, signature_verified, persist_row_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8)",
                &[
                    &id,
                    &event.target_contributor,
                    &event.accuser_id,
                    &event.payload,
                    &event.filed_at,
                    &event.signature.ed25519,
                    &event.accuser_id,
                    &event.signature.ed25519,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "put_moderation_event"))?;
        Ok(())
    }

    async fn put_slashing_attestation(&self, att: SlashingAttestation) -> Result<(), Error> {
        verify_envelope_signature(&att.signature)?;
        let id = parse_id(&att.slashing_id)?;
        let moderation_id = parse_id(&att.moderation_id)?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        client
            .execute(
                "INSERT INTO cirisnode.slashing_attestations (\
                    slashing_id, moderation_id, adjudicator_id, payload, attested_at, \
                    signature, signing_key_id, signature_verified, persist_row_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8)",
                &[
                    &id,
                    &moderation_id,
                    &att.adjudicator_id,
                    &att.payload,
                    &att.attested_at,
                    &att.signature.ed25519,
                    &att.adjudicator_id,
                    &att.signature.ed25519,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "put_slashing_attestation"))?;
        Ok(())
    }

    async fn put_reconsideration_request(&self, req: ReconsiderationRequest) -> Result<(), Error> {
        verify_envelope_signature(&req.signature)?;
        let id = parse_id(&req.request_id)?;
        let slashing_id = parse_id(&req.slashing_id)?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        client
            .execute(
                "INSERT INTO cirisnode.reconsideration_requests (\
                    request_id, slashing_id, requester_id, payload, requested_at, \
                    signature, signing_key_id, signature_verified, persist_row_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8)",
                &[
                    &id,
                    &slashing_id,
                    &req.requester_id,
                    &req.payload,
                    &req.requested_at,
                    &req.signature.ed25519,
                    &req.requester_id,
                    &req.signature.ed25519,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "put_reconsideration_request"))?;
        Ok(())
    }

    async fn put_reconsideration_attestation(
        &self,
        att: ReconsiderationAttestation,
    ) -> Result<(), Error> {
        verify_envelope_signature(&att.signature)?;
        let id = parse_id(&att.reconsideration_id)?;
        let request_id = parse_id(&att.request_id)?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        client
            .execute(
                "INSERT INTO cirisnode.reconsideration_attestations (\
                    reconsideration_id, request_id, adjudicator_id, payload, attested_at, \
                    signature, signing_key_id, signature_verified, persist_row_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8)",
                &[
                    &id,
                    &request_id,
                    &att.adjudicator_id,
                    &att.payload,
                    &att.attested_at,
                    &att.signature.ed25519,
                    &att.adjudicator_id,
                    &att.signature.ed25519,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "put_reconsideration_attestation"))?;
        Ok(())
    }

    async fn routable_contributors(
        &self,
        domain: &str,
        language: &str,
    ) -> Result<Vec<RoutableContributor>, Error> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                "SELECT contributor_id, expertise FROM cirisnode.expertise_ledger \
                 WHERE domain = $1 AND language = $2 \
                   AND expertise > 0 AND is_active = TRUE \
                 ORDER BY expertise DESC",
                &[&domain, &language],
            )
            .await
            .map_err(|e| map_pg_error(e, "routable_contributors"))?;
        Ok(rows
            .into_iter()
            .map(|r| RoutableContributor {
                contributor_id: r.get(0),
                expertise: r.get(1),
            })
            .collect())
    }

    async fn read_vote_weight(
        &self,
        contributor_id: &str,
        domain: &str,
        language: &str,
        subject: &str,
    ) -> Result<Option<VoteWeight>, Error> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT \
                    COALESCE(c.balance, 0)::float8 AS credits, \
                    COALESCE(e.expertise, 0)::float8 AS expertise, \
                    COALESCE(e.is_active, FALSE) AS is_active \
                 FROM (SELECT 1) _ \
                 LEFT JOIN cirisnode.credits_ledger c \
                    ON c.contributor_id = $1 AND c.domain = $2 \
                       AND c.language = $3 AND c.subject = $4 \
                 LEFT JOIN cirisnode.expertise_ledger e \
                    ON e.contributor_id = $1 AND e.domain = $2 AND e.language = $3",
                &[&contributor_id, &domain, &language, &subject],
            )
            .await
            .map_err(|e| map_pg_error(e, "read_vote_weight"))?;
        match row_opt {
            None => Ok(None),
            Some(row) => {
                let credits: f64 = row.get(0);
                let expertise: f64 = row.get(1);
                let is_active: bool = row.get(2);
                if credits == 0.0 && expertise == 0.0 && !is_active {
                    return Ok(None);
                }
                // SCHEMA.md §5.2: expertise_multiplier = 1 + 4*expertise
                // (gives [1, 5] range); active_tier_multiplier = 1.5 if
                // active else 0.5. Caller-side computation per the spec;
                // persist returns the components for transparency.
                let expertise_multiplier = 1.0 + 4.0 * expertise;
                let active_tier_multiplier = if is_active { 1.5 } else { 0.5 };
                let weight = credits * expertise_multiplier * active_tier_multiplier;
                Ok(Some(VoteWeight {
                    contributor_id: contributor_id.to_owned(),
                    domain: domain.to_owned(),
                    language: language.to_owned(),
                    subject: subject.to_owned(),
                    credits,
                    expertise_multiplier,
                    active_tier_multiplier,
                    weight,
                }))
            }
        }
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
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;

        let mut where_parts: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if let Some(ct) = filter.contribution_type {
            params.push(Box::new(contribution_type_str(ct).to_owned()));
            where_parts.push(format!("contribution_type = ${}", params.len()));
        }
        if let Some(d) = filter.domain {
            params.push(Box::new(d));
            where_parts.push(format!("domain = ${}", params.len()));
        }
        if let Some(l) = filter.language {
            params.push(Box::new(l));
            where_parts.push(format!("language = ${}", params.len()));
        }
        if let Some(s) = filter.subject_kind {
            params.push(Box::new(s));
            where_parts.push(format!("subject_kind = ${}", params.len()));
        }
        if let Some(a) = filter.author_id {
            params.push(Box::new(a));
            where_parts.push(format!("author_id = ${}", params.len()));
        }
        if let Some(c) = filter.is_canonical {
            params.push(Box::new(c));
            where_parts.push(format!("is_canonical = ${}", params.len()));
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "ListCursor version {} unsupported (expected v1)",
                    cur.version
                )));
            }
            let last_uuid = parse_id(&cur.last_id)?;
            params.push(Box::new(cur.last_ts));
            let p_ts = params.len();
            params.push(Box::new(last_uuid));
            let p_id = params.len();
            where_parts.push(format!(
                "(submitted_at, contribution_id) < (${p_ts}, ${p_id})"
            ));
        }
        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" AND "))
        };
        params.push(Box::new(limit));
        let p_limit = params.len();
        let sql = format!(
            "SELECT contribution_id::text, contribution_type, domain, language, subject_kind, \
                    author_id, payload, witness_set, submitted_at, signature \
             FROM cirisnode.contributions \
             {where_sql} \
             ORDER BY submitted_at DESC, contribution_id DESC \
             LIMIT ${p_limit}"
        );
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let rows = client
            .query(&sql, &params_ref[..])
            .await
            .map_err(|e| map_pg_error(e, "list_contributions"))?;
        let mut items: Vec<ContributionEnvelope> = Vec::with_capacity(rows.len());
        for row in rows {
            let ct_str: String = row.get(1);
            let witness_set_val: Option<serde_json::Value> = row.get(7);
            let witness_set = match witness_set_val {
                Some(v) if !v.is_null() => {
                    Some(serde_json::from_value(v).map_err(|e| Error::Internal(e.to_string()))?)
                }
                _ => None,
            };
            items.push(ContributionEnvelope {
                contribution_id: row.get(0),
                contribution_type: contribution_type_from_str(&ct_str)?,
                author_id: row.get(5),
                subject: Cell {
                    domain: row.get(2),
                    language: row.get(3),
                    subject: Some(row.get(4)),
                },
                payload: row.get(6),
                witness_set,
                signature: HybridSignature {
                    ed25519: row.get(9),
                    ml_dsa_65: None,
                    signed_at: row.get(8),
                },
                submitted_at: row.get(8),
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
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;

        let mut where_parts: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if let Some(c) = filter.contribution_id {
            let cid = parse_id(&c)?;
            params.push(Box::new(cid));
            where_parts.push(format!("contribution_id = ${}", params.len()));
        }
        if let Some(v) = filter.voter_id {
            params.push(Box::new(v));
            where_parts.push(format!("voter_id = ${}", params.len()));
        }
        if let Some(d) = filter.domain {
            params.push(Box::new(d));
            where_parts.push(format!("domain = ${}", params.len()));
        }
        if let Some(l) = filter.language {
            params.push(Box::new(l));
            where_parts.push(format!("language = ${}", params.len()));
        }
        if let Some(c) = filter.is_canonical {
            params.push(Box::new(c));
            where_parts.push(format!("is_canonical = ${}", params.len()));
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "ListCursor version {} unsupported",
                    cur.version
                )));
            }
            let last_uuid = parse_id(&cur.last_id)?;
            params.push(Box::new(cur.last_ts));
            let p_ts = params.len();
            params.push(Box::new(last_uuid));
            let p_id = params.len();
            where_parts.push(format!("(cast_at, vote_id) < (${p_ts}, ${p_id})"));
        }
        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" AND "))
        };
        params.push(Box::new(limit));
        let p_limit = params.len();
        let sql = format!(
            "SELECT vote_id::text, contribution_id::text, voter_id, domain, language, \
                    payload, cast_at, signature \
             FROM cirisnode.votes \
             {where_sql} \
             ORDER BY cast_at DESC, vote_id DESC \
             LIMIT ${p_limit}"
        );
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let rows = client
            .query(&sql, &params_ref[..])
            .await
            .map_err(|e| map_pg_error(e, "list_votes"))?;
        let mut items: Vec<VoteEnvelope> = Vec::with_capacity(rows.len());
        for row in rows {
            let payload: serde_json::Value = row.get(5);
            let score = payload
                .get("score")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let rationale = payload
                .get("rationale")
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            let cast_at: DateTime<Utc> = row.get(6);
            items.push(VoteEnvelope {
                vote_id: row.get(0),
                voter_id: row.get(2),
                contribution_id: row.get(1),
                cell: Cell {
                    domain: row.get(3),
                    language: row.get(4),
                    subject: None, // not stored on votes table
                },
                score,
                rationale,
                signature: HybridSignature {
                    ed25519: row.get(7),
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
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT contributor_id, domain, language, subject, balance, \
                        last_update_contribution::text, last_updated_at, created_at \
                 FROM cirisnode.credits_ledger \
                 WHERE contributor_id = $1 AND domain = $2 \
                   AND language = $3 AND subject = $4",
                &[&contributor_id, &domain, &language, &subject],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_credits_ledger"))?;
        Ok(row_opt.map(|row| CreditsLedgerEntry {
            contributor_id: row.get(0),
            domain: row.get(1),
            language: row.get(2),
            subject: row.get(3),
            balance: row.get(4),
            last_update_contribution: row.get(5),
            last_updated_at: row.get(6),
            created_at: row.get(7),
        }))
    }

    async fn get_expertise_ledger(
        &self,
        contributor_id: &str,
        domain: &str,
        language: &str,
    ) -> Result<Option<ExpertiseLedgerEntry>, Error> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT contributor_id, domain, language, expertise, is_active, \
                        last_updated_at, last_update_contribution::text, created_at \
                 FROM cirisnode.expertise_ledger \
                 WHERE contributor_id = $1 AND domain = $2 AND language = $3",
                &[&contributor_id, &domain, &language],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_expertise_ledger"))?;
        Ok(row_opt.map(|row| ExpertiseLedgerEntry {
            contributor_id: row.get(0),
            domain: row.get(1),
            language: row.get(2),
            expertise: row.get(3),
            is_active: row.get(4),
            last_updated_at: row.get(5),
            last_update_contribution: row.get(6),
            created_at: row.get(7),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::postgres::PostgresBackend;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
    }

    fn fix_sig() -> HybridSignature {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        HybridSignature {
            ed25519: BASE64.encode([0u8; 64]),
            ml_dsa_65: None,
            signed_at: Utc::now(),
        }
    }

    /// Smoke test the full NodeCoreService round-trip path:
    /// put_contribution → cast_vote → update_credits/expertise →
    /// routable_contributors → read_vote_weight → list_* → get_*.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn cirisnode_round_trip_full_lifecycle() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let author = "test-author-cirisnode";
        let voter = "test-voter-cirisnode";
        let domain = format!("test-dom-{}", Uuid::new_v4());
        let language = "en";
        let subject_kind = "arc_question";

        // 1. put_contribution
        let contribution_id = Uuid::new_v4();
        let env = ContributionEnvelope {
            contribution_id: contribution_id.to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author.into(),
            subject: Cell {
                domain: domain.clone(),
                language: language.into(),
                subject: Some(subject_kind.into()),
            },
            payload: serde_json::json!({"question_id": "test_q01"}),
            witness_set: None,
            signature: fix_sig(),
            submitted_at: Utc::now(),
        };
        backend.put_contribution(env.clone()).await.unwrap();

        // 1b. duplicate → Conflict
        let dup = backend.put_contribution(env).await.unwrap_err();
        assert!(
            matches!(dup, Error::Conflict(_)),
            "expected Conflict, got: {dup:?}"
        );

        // 2. cast_vote
        let vote_id = Uuid::new_v4();
        let vote = VoteEnvelope {
            vote_id: vote_id.to_string(),
            voter_id: voter.into(),
            contribution_id: Some(contribution_id.to_string()),
            cell: Cell {
                domain: domain.clone(),
                language: language.into(),
                subject: Some(subject_kind.into()),
            },
            score: serde_json::json!({"verdict": "approve", "magnitude": 1.0}),
            rationale: Some("test".into()),
            signature: fix_sig(),
            cast_at: Utc::now(),
        };
        backend.cast_vote(vote).await.unwrap();

        // 3. update_credits_ledger
        backend
            .update_credits_ledger(CreditsUpdate {
                contributor_id: voter.into(),
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
                contributor_id: voter.into(),
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
            .read_vote_weight(voter, &domain, language, subject_kind)
            .await
            .unwrap()
            .expect("vote weight present");
        assert!((vw.credits - 10.0).abs() < 1e-9);
        // expertise_multiplier = 1 + 4*0.5 = 3.0; active_multiplier = 1.5
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
            .get_credits_ledger(voter, &domain, language, subject_kind)
            .await
            .unwrap()
            .expect("credits present");
        assert!((cl.balance - 10.0).abs() < 1e-9);

        // 10. get_expertise_ledger
        let el = backend
            .get_expertise_ledger(voter, &domain, language)
            .await
            .unwrap()
            .expect("expertise present");
        assert!((el.expertise - 0.5).abs() < 1e-9);
        assert!(el.is_active);
    }
}
