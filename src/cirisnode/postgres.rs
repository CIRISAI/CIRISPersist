//! PostgreSQL impl of [`NodeCoreService`] (v0.7.0-α4; verify gate
//! made real in v0.7.1).
//!
//! Concrete impl backed by `cirisnode.*` (V011 schema). Every
//! typed-write goes through [`super::verify::verify_envelope_signed`]
//! before INSERT — the envelope is canonicalized (signature field
//! stripped) and the contributor-identity Ed25519 pubkey verifies
//! over those bytes. Persist refuses to insert on verify failure;
//! `signature_verified = TRUE` is gated on the real verify pass.
//! Reads follow the v0.5.5 §I cursor-paged newest-first shape.

use chrono::{DateTime, Utc};
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

// v0.7.1 — the stub `verify_envelope_signature` (which did not
// actually verify the signature) was replaced by
// `super::verify::verify_envelope_signed`. Each typed-write below
// calls that helper with the envelope + the contributor identity
// field (which IS the Ed25519 pubkey per SCHEMA.md §2.2). Persist
// refuses to INSERT on verify failure, and `signature_verified` is
// set to TRUE only after the verify gate passes.

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
        // v3.4.0 (CIRISPersist#123) — trust gate runs FIRST.
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
        let subject_kind = env.subject.subject.as_deref().ok_or_else(|| {
            Error::InvalidArgument(
                "subject.subject (subject_kind) required for contributions".into(),
            )
        })?;

        // v2.1 (CIRISPersist#101) — federation_announcement extracts
        // priority + authority_class from the payload and writes them
        // to the dedicated columns. The admission helper applies the
        // constitutional asymmetry (FSD §4.5) BEFORE the DB CHECK
        // fires, so callers get the more specific typed error.
        let announcement = super::federation_announcement::extract_announcement_payload(
            subject_kind,
            &env.payload,
        )?;
        let (announcement_priority, announcement_authority_class): (
            Option<&'static str>,
            Option<&'static str>,
        ) = match announcement.as_ref() {
            Some(p) => (Some(p.priority.as_str()), Some(p.authority_class.as_str())),
            None => (None, None),
        };

        // v3.6.0 (CIRISPersist#134) — media-sharing extractors. The
        // typed shape validators run BEFORE the DB CHECK fires (same
        // discipline as the announcement extractor). Mismatched
        // payloads land Error::InvalidArgument up-front.
        let takedown =
            super::media_sharing::extract_takedown_notice_payload(subject_kind, &env.payload)?;
        // v8.7.1 (CIRISPersist#233, CEG §11.10) — FULL moderation gate for
        // the `takedown_notice` primitive. PostgresBackend IS the
        // FederationDirectory, so `self` walks the delegates_to + community
        // graph. Admit IFF the author IS a duty-holder over the target
        // (declared subjects ∪ the target community's named moderators) or
        // is reached by an steward-bound duty-holder via a live `takedown`-
        // scoped chain. Absence ⇒ REJECT. Runs BEFORE the INSERT — a
        // rejected emission leaves no trace.
        if takedown.is_some() {
            // v8.7.2: authority over the SIGNED content provenance — the
            // payload's declared subjects are advisory/routing-only.
            let (content_sha256, community_id) = super::payload_target_descriptor(&env.payload);
            super::check_moderation_or_reject(
                self,
                &env.author_id,
                &content_sha256,
                &community_id,
                crate::federation::admission::DELEGATION_SCOPE_TAKEDOWN,
                "takedown_notice",
            )
            .await?;
        }
        let key_grant =
            super::media_sharing::extract_key_grant_payload(subject_kind, &env.payload)?;
        let media_content_sha256: Option<String> = takedown
            .as_ref()
            .map(|p| p.content_sha256.clone())
            .or_else(|| key_grant.as_ref().and_then(|p| p.content_sha256.clone()));
        let takedown_legal_basis: Option<&'static str> =
            takedown.as_ref().map(|p| p.legal_basis.as_str());
        let key_grant_recipient_key_id: Option<String> =
            key_grant.as_ref().map(|p| p.recipient_key_id.clone());
        // v4.x (CIRISPersist#142 Cut C3b) — stream/epoch addressing
        // projection (V064 columns). XOR with media_content_sha256 is
        // guaranteed by extract_key_grant_payload. stream_epoch is u64
        // in Rust → bound i64 (BIGINT); tokio_postgres has no ToSql u64.
        let key_grant_stream_id: Option<String> =
            key_grant.as_ref().and_then(|p| p.stream_id.clone());
        let key_grant_stream_epoch: Option<i64> =
            match key_grant.as_ref().and_then(|p| p.stream_epoch) {
                None => None,
                Some(e) => Some(i64::try_from(e).map_err(|_| {
                    Error::InvalidArgument(
                        "key_grant: stream_epoch exceeds i64 — key_grant_stream_epoch is BIGINT"
                            .into(),
                    )
                })?),
            };

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
                    signature, signing_key_id, signature_verified, persist_row_hash, \
                    announcement_priority, announcement_authority_class, \
                    media_content_sha256, key_grant_recipient_key_id, takedown_legal_basis, \
                    key_grant_stream_id, key_grant_stream_epoch\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, TRUE, $12, $13, $14, \
                           $15, $16, $17, $18, $19)",
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
                    &announcement_priority,
                    &announcement_authority_class,
                    &media_content_sha256,
                    &key_grant_recipient_key_id,
                    &takedown_legal_basis,
                    &key_grant_stream_id,
                    &key_grant_stream_epoch,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "put_contribution"))?;
        Ok(())
    }

    async fn cast_vote(&self, env: VoteEnvelope) -> Result<(), Error> {
        super::verify::verify_envelope_signed(&env, &env.signature, &env.voter_id)?;
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
        super::verify::verify_envelope_signed(&event, &event.signature, &event.accuser_id)?;
        // v8.7.1 (CIRISPersist#233, CEG §11.10) — FULL moderation gate for
        // the `ModerationEvent` primitive. Admit IFF the accuser (signer)
        // IS a duty-holder over the target (declared subjects ∪ the target
        // community's named moderators) or is reached by an steward-bound
        // duty-holder via a live `moderate`-scoped chain. Absence ⇒ REJECT.
        // Runs AFTER signature verify, BEFORE INSERT.
        // v8.7.2: authority over the SIGNED content provenance — the
        // payload's declared subjects are advisory/routing-only.
        let (content_sha256, community_id) = super::payload_target_descriptor(&event.payload);
        super::check_moderation_or_reject(
            self,
            &event.accuser_id,
            &content_sha256,
            &community_id,
            crate::federation::admission::DELEGATION_SCOPE_MODERATE,
            "moderation_event",
        )
        .await?;
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
        super::verify::verify_envelope_signed(&att, &att.signature, &att.adjudicator_id)?;
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
        super::verify::verify_envelope_signed(&req, &req.signature, &req.requester_id)?;
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
        super::verify::verify_envelope_signed(&att, &att.signature, &att.adjudicator_id)?;
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

    async fn put_promotion_attestation(&self, att: PromotionAttestation) -> Result<(), Error> {
        if att.target_ids.is_empty() {
            return Err(Error::InvalidArgument(
                "target_ids must not be empty".into(),
            ));
        }
        super::verify::verify_envelope_signed(&att, &att.signature, &att.attested_by)?;
        let attestation_id = parse_id(&att.attestation_id)?;
        let target_uuids = att
            .target_ids
            .iter()
            .map(|s| parse_id(s))
            .collect::<Result<Vec<Uuid>, _>>()?;

        // (table_name, id_column) for the UPDATE step. Pinned to
        // table identifiers — no caller-controlled SQL injection
        // surface, since target_kind is the typed enum.
        let (table, id_col) = match att.target_kind {
            TargetRowKind::Contribution => ("cirisnode.contributions", "contribution_id"),
            TargetRowKind::Vote => ("cirisnode.votes", "vote_id"),
            TargetRowKind::ModerationEvent => ("cirisnode.moderation_events", "moderation_id"),
            TargetRowKind::SlashingAttestation => {
                ("cirisnode.slashing_attestations", "slashing_id")
            }
            TargetRowKind::ReconsiderationAttestation => (
                "cirisnode.reconsideration_attestations",
                "reconsideration_id",
            ),
        };
        let target_kind_str = match att.target_kind {
            TargetRowKind::Contribution => "contribution",
            TargetRowKind::Vote => "vote",
            TargetRowKind::ModerationEvent => "moderation_event",
            TargetRowKind::SlashingAttestation => "slashing_attestation",
            TargetRowKind::ReconsiderationAttestation => "reconsideration_attestation",
        };

        let mut client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| Error::Backend(format!("begin: {e}")))?;

        tx.execute(
            "INSERT INTO cirisnode.promotion_attestations (\
                attestation_id, target_kind, target_ids, attested_by, \
                aggregate_evidence, attested_at, signature, signing_key_id, \
                signature_verified, persist_row_hash\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE, $9)",
            &[
                &attestation_id,
                &target_kind_str,
                &target_uuids,
                &att.attested_by,
                &att.aggregate_evidence,
                &att.attested_at,
                &att.signature.ed25519,
                &att.attested_by,
                &att.signature.ed25519,
            ],
        )
        .await
        .map_err(|e| map_pg_error(e, "put_promotion_attestation"))?;

        // Transactionally flip is_canonical + canonicalized_at. The
        // affected-row count must match target_ids.len() — if any
        // target doesn't exist, we rollback. The table/column names
        // come from the typed enum above (no injection surface).
        let update_sql = format!(
            "UPDATE {table} SET is_canonical = TRUE, canonicalized_at = NOW() \
             WHERE {id_col} = ANY($1::uuid[])"
        );
        let affected = tx
            .execute(&update_sql, &[&target_uuids])
            .await
            .map_err(|e| map_pg_error(e, "put_promotion_attestation UPDATE"))?;
        if affected as usize != target_uuids.len() {
            return Err(Error::InvalidArgument(format!(
                "target_ids contains rows not present in {table}: \
                 named {} targets, UPDATE affected {affected}",
                target_uuids.len()
            )));
        }

        tx.commit()
            .await
            .map_err(|e| Error::Backend(format!("commit: {e}")))?;
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
        // v2.1 (CIRISPersist#101) — federation_announcement filters.
        // priority / authority_class are indexed columns added in
        // V046 (non-announcement rows have NULL in both); `kind`
        // lives inside the payload JSONB and is matched via
        // `payload->'kind'` equality. All three compose AND-style.
        if let Some(p) = filter.priority {
            params.push(Box::new(p.as_str().to_owned()));
            where_parts.push(format!("announcement_priority = ${}", params.len()));
        }
        if let Some(a) = filter.authority_class {
            params.push(Box::new(a.as_str().to_owned()));
            where_parts.push(format!("announcement_authority_class = ${}", params.len()));
        }
        if let Some(k) = filter.kind {
            // `serde_json::to_value` of the enum produces either a
            // bare string ("policy_update") or an object
            // (`{"custom": "..."}`). Either shape compares via the
            // `payload->'kind'` JSONB path.
            let value = serde_json::to_value(&k)
                .map_err(|e| Error::Internal(format!("AnnouncementKind serialize: {e}")))?;
            params.push(Box::new(value));
            where_parts.push(format!("payload->'kind' = ${}::jsonb", params.len()));
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

    // ── Federation delivery attestations (v2.1, CIRISPersist#101) ──

    async fn put_delivery_attestation(
        &self,
        attestation: DeliveryAttestation,
    ) -> Result<(), Error> {
        // Validate the FSD §3.2.1 byte-length invariants up-front. The
        // DB has matching CHECKs, but admission catches the error with
        // a typed shape before consuming a pool connection.
        let canonical_hash = attestation.canonical_hash_bytes()?;
        let _ = attestation.signature_classical_bytes()?;
        let pqc_bytes = attestation.signature_pqc_bytes()?;
        let announcement_uuid = parse_id(&attestation.announcement_id)?;

        // Hybrid signature verify against federation_keys[peer_key_id]
        // via persist's existing directory path. The peer is the
        // signer; the canonical-bytes encoding is the FSD §3.2.1
        // domain-prefixed layout produced by
        // `DeliveryAttestation::canonical_bytes`.
        let canonical = attestation
            .canonical_bytes()
            .map_err(|e| Error::Signature(format!("canonical_bytes: {e}")))?;
        let outcome = crate::verify::verify_hybrid_via_directory(
            self,
            &canonical,
            &attestation.peer_key_id,
            &attestation.signature_classical_base64,
            attestation.signature_pqc_base64.as_deref(),
            // Ed25519Fallback mirrors the cirisnode envelope verify
            // policy (`super::verify::verify_envelope_signed`): PQC
            // accepted when present, classical-only accepted while
            // the per-peer PQC rollout runs.
            crate::verify::hybrid::HybridPolicy::Ed25519Fallback,
            None,
        )
        .await
        .map_err(|e| {
            // Translate the verify error tokens through the cirisnode
            // Error::Signature variant — the kind() token is preserved
            // for downstream callers via the verify_kind taxonomy.
            Error::Signature(format!("delivery_attestation verify: {e}"))
        })?;
        let _ = outcome;

        let persist_row_hash = crate::federation::types::compute_persist_row_hash(&attestation)
            .map_err(|e| Error::Internal(format!("persist_row_hash: {e}")))?;

        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;

        let result = client
            .execute(
                "INSERT INTO cirisnode.federation_delivery_attestations (\
                    announcement_id, announcement_canonical_hash, peer_key_id, \
                    peer_pubkey_ed25519_base64, received_at, transport_id, \
                    signature_classical, signature_pqc, signature_verified, persist_row_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE, $9) \
                 ON CONFLICT (announcement_id, peer_key_id) DO NOTHING",
                &[
                    &announcement_uuid,
                    &canonical_hash.as_slice(),
                    &attestation.peer_key_id,
                    &attestation.peer_pubkey_ed25519_base64,
                    &attestation.received_at,
                    &attestation.transport_id.as_str(),
                    &attestation.signature_classical_bytes()?.as_slice(),
                    &pqc_bytes,
                    &persist_row_hash,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "put_delivery_attestation"))?;
        // ON CONFLICT DO NOTHING returns 0 affected rows when the row
        // already exists — that's the idempotent replay path per
        // FSD §3.2.1. Both 0 and 1 are success.
        let _ = result;
        Ok(())
    }

    async fn list_delivery_attestations(
        &self,
        announcement_id: &str,
    ) -> Result<Vec<DeliveryAttestation>, Error> {
        let announcement_uuid = parse_id(announcement_id)?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                "SELECT announcement_id::text, announcement_canonical_hash, peer_key_id, \
                        peer_pubkey_ed25519_base64, received_at, transport_id, \
                        signature_classical, signature_pqc \
                 FROM cirisnode.federation_delivery_attestations \
                 WHERE announcement_id = $1 \
                 ORDER BY received_at DESC",
                &[&announcement_uuid],
            )
            .await
            .map_err(|e| map_pg_error(e, "list_delivery_attestations"))?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let hash_bytes: Vec<u8> = row.get(1);
            let sig_classical: Vec<u8> = row.get(6);
            let sig_pqc_opt: Option<Vec<u8>> = row.get(7);
            let transport_str: &str = row.get(5);
            let transport_id = TransportMedium::from_wire_str(transport_str).ok_or_else(|| {
                Error::Backend(format!("unknown transport_id from DB: {transport_str}"))
            })?;
            out.push(DeliveryAttestation {
                announcement_id: row.get(0),
                announcement_canonical_hash_base64:
                    super::federation_announcement::encode_canonical_hash_base64(
                        &<[u8; 32]>::try_from(hash_bytes.as_slice()).map_err(|_| {
                            Error::Backend("stored canonical_hash not 32 bytes".to_string())
                        })?,
                    ),
                peer_key_id: row.get(2),
                peer_pubkey_ed25519_base64: row.get(3),
                received_at: row.get(4),
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
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row = client
            .query_one(
                "SELECT COUNT(*) FROM cirisnode.federation_delivery_attestations \
                 WHERE announcement_id = $1",
                &[&announcement_uuid],
            )
            .await
            .map_err(|e| map_pg_error(e, "count_delivery_attestations"))?;
        let n: i64 = row.get(0);
        // COUNT(*) is non-negative; the cast is lossless within real-
        // world deployment sizes (PG counts are i64 max 2^63-1).
        Ok(u64::try_from(n).unwrap_or(0))
    }

    // ── Media-sharing reads (v3.6.0, CIRISPersist#134) ─────────────

    async fn list_takedowns_for(
        &self,
        content_sha256: &str,
    ) -> Result<Vec<ContributionEnvelope>, Error> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                "SELECT contribution_id::text, contribution_type, domain, language, subject_kind, \
                        author_id, payload, witness_set, submitted_at, signature \
                 FROM cirisnode.contributions \
                 WHERE subject_kind = 'takedown_notice' \
                   AND media_content_sha256 = $1 \
                 ORDER BY submitted_at DESC, contribution_id DESC",
                &[&content_sha256],
            )
            .await
            .map_err(|e| map_pg_error(e, "list_takedowns_for"))?;
        rows.into_iter().map(row_to_contribution).collect()
    }

    async fn list_key_grants_for(
        &self,
        recipient_key_id: &str,
    ) -> Result<Vec<ContributionEnvelope>, Error> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                "SELECT contribution_id::text, contribution_type, domain, language, subject_kind, \
                        author_id, payload, witness_set, submitted_at, signature \
                 FROM cirisnode.contributions \
                 WHERE subject_kind = 'key_grant' \
                   AND key_grant_recipient_key_id = $1 \
                 ORDER BY submitted_at DESC, contribution_id DESC",
                &[&recipient_key_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "list_key_grants_for"))?;
        rows.into_iter().map(row_to_contribution).collect()
    }

    async fn list_key_grants_for_content(
        &self,
        content_sha256: &str,
        recipient_key_id: &str,
    ) -> Result<Vec<ContributionEnvelope>, Error> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                "SELECT contribution_id::text, contribution_type, domain, language, subject_kind, \
                        author_id, payload, witness_set, submitted_at, signature \
                 FROM cirisnode.contributions \
                 WHERE subject_kind = 'key_grant' \
                   AND media_content_sha256 = $1 \
                   AND key_grant_recipient_key_id = $2 \
                 ORDER BY submitted_at DESC, contribution_id DESC",
                &[&content_sha256, &recipient_key_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "list_key_grants_for_content"))?;
        rows.into_iter().map(row_to_contribution).collect()
    }

    async fn list_key_grants_for_stream_epoch(
        &self,
        stream_id: &str,
        epoch: u64,
    ) -> Result<Vec<ContributionEnvelope>, Error> {
        // u64 epoch → bound i64 (BIGINT); tokio_postgres has no ToSql u64.
        let epoch_i64 = i64::try_from(epoch).map_err(|_| {
            Error::InvalidArgument("list_key_grants_for_stream_epoch: epoch exceeds i64".into())
        })?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                "SELECT contribution_id::text, contribution_type, domain, language, subject_kind, \
                        author_id, payload, witness_set, submitted_at, signature \
                 FROM cirisnode.contributions \
                 WHERE subject_kind = 'key_grant' \
                   AND key_grant_stream_id = $1 \
                   AND key_grant_stream_epoch = $2 \
                 ORDER BY submitted_at DESC, contribution_id DESC",
                &[&stream_id, &epoch_i64],
            )
            .await
            .map_err(|e| map_pg_error(e, "list_key_grants_for_stream_epoch"))?;
        rows.into_iter().map(row_to_contribution).collect()
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
        // is extended by the prior contribution_id, with an empty
        // wrapped_dek_base64 as the revocation sentinel.
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                "SELECT contribution_id::text, domain, language, payload \
                 FROM cirisnode.contributions \
                 WHERE subject_kind = 'key_grant' AND author_id = $1",
                &[&actor_key_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "retire_key_grants list"))?;
        let mut report = super::RetireKeyGrantsReport {
            grants_seen: rows.len(),
            ..Default::default()
        };
        for row in rows {
            let contribution_id: String = row.get(0);
            let domain: String = row.get(1);
            let language: String = row.get(2);
            let payload_json: serde_json::Value = row.get(3);
            let prior: super::media_sharing::KeyGrantPayload =
                match serde_json::from_value(payload_json.clone()) {
                    Ok(p) => p,
                    Err(e) => {
                        report.supersedes_failed += 1;
                        tracing::warn!(
                            error = %e,
                            actor = %actor_key_id,
                            contribution_id = %contribution_id,
                            "ciris-persist v3.6.0 retire_key_grants: prior payload decode failed"
                        );
                        continue;
                    }
                };
            let outcome = emit_key_grant_supersession(
                self,
                &contribution_id,
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
                        contribution_id = %contribution_id,
                        "ciris-persist v3.6.0 retire_key_grants: supersession emission failed"
                    );
                }
            }
        }
        Ok(report)
    }
}

/// v3.6.0 (CIRISPersist#134) — Postgres row → ContributionEnvelope.
/// Shared between the three media-sharing list_* methods.
fn row_to_contribution(row: tokio_postgres::Row) -> Result<ContributionEnvelope, Error> {
    let ct_str: String = row.get(1);
    let witness_set_val: Option<serde_json::Value> = row.get(7);
    let witness_set = match witness_set_val {
        Some(v) if !v.is_null() => {
            Some(serde_json::from_value(v).map_err(|e| Error::Internal(e.to_string()))?)
        }
        _ => None,
    };
    Ok(ContributionEnvelope {
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
    })
}

/// v3.6.0 (CIRISPersist#134) — emit a supersession `key_grant`
/// Contribution against a prior `key_grant` Contribution row. Used
/// by [`PostgresBackend::retire_key_grants`].
///
/// CEG 0.3 §5.6.8.4 — rotation_chain supersession (option b from
/// CIRISRegistry#38): the new Contribution carries the same
/// `recipient_key_id` + `content_sha256` as the prior grant, with an
/// empty `wrapped_dek_base64` as the revocation sentinel, and
/// `rotation_chain` extended by the prior `contribution_id`.
#[allow(clippy::too_many_arguments)]
async fn emit_key_grant_supersession(
    backend: &PostgresBackend,
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

    // CEG 0.3 §5.6.8.4 revocation sentinel: empty base64 string
    // round-trips to zero-length bytes; recipient sees the empty DEK
    // and knows the grant is retired.
    let revocation_dek = B64.encode(Vec::<u8>::new());

    let supersession_payload = super::media_sharing::KeyGrantPayload {
        recipient_key_id: prior.recipient_key_id.clone(),
        content_sha256: prior.content_sha256.clone(),
        // Carry the prior grant's addressing + wrap algorithm so a
        // stream/epoch-grant supersession stays stream-addressed + v2.
        stream_id: prior.stream_id.clone(),
        stream_epoch: prior.stream_epoch,
        wrapped_dek_base64: revocation_dek,
        wrap_algorithm: prior.wrap_algorithm,
        ratchet_version: prior.ratchet_version,
        key_validity_window: super::media_sharing::KeyValidityWindow {
            // The supersession grant's validity window is bounded by
            // `now` — the prior grant is retired as of the
            // supersession Contribution's wall-clock.
            not_before: now,
            not_after: now + chrono::Duration::seconds(1),
        },
        scope: prior.scope,
        scope_id: prior.scope_id.clone(),
        rotation_chain,
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
    backend.put_contribution(env).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::postgres::PostgresBackend;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
    }

    /// v0.7.1 — produce the contributor's base64-encoded Ed25519
    /// pubkey from a deterministic seed (for tests). Per
    /// `SCHEMA.md` §2.2, the pubkey doubles as the contributor_id.
    fn pubkey_b64(key: &ed25519_dalek::SigningKey) -> String {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        BASE64.encode(key.verifying_key().to_bytes())
    }

    /// v0.7.1 — sign canonical bytes of an envelope and stamp the
    /// signature field. Generic over the typed-envelope shape.
    fn sign_envelope<T: serde::Serialize>(
        env: &T,
        key: &ed25519_dalek::SigningKey,
    ) -> HybridSignature {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine as _;
        use ed25519_dalek::Signer as _;
        let canonical =
            super::super::verify::canonical_bytes_for_envelope(env).expect("canonical bytes");
        let sig = key.sign(&canonical);
        HybridSignature {
            ed25519: BASE64.encode(sig.to_bytes()),
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

        // v0.7.1 — contributors are now identified by their Ed25519
        // pubkey (SCHEMA.md §2.2). The pubkey IS the contributor_id;
        // signature verification is self-signed against it.
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xA1; 32]);
        let voter_key = ed25519_dalek::SigningKey::from_bytes(&[0xB2; 32]);
        let author = pubkey_b64(&author_key);
        let voter = pubkey_b64(&voter_key);
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
            "expected Conflict, got: {dup:?}"
        );

        // 1c. v0.7.1: tampered envelope rejects with Signature.
        let mut tampered = env.clone();
        tampered.contribution_id = Uuid::new_v4().to_string();
        tampered.payload = serde_json::json!({"q": "TAMPERED"});
        // Keep the original signature — won't match canonical bytes
        // of the tampered envelope.
        let tampered_err = backend.put_contribution(tampered).await.unwrap_err();
        assert!(
            matches!(tampered_err, Error::Signature(_)),
            "expected Signature on tampered envelope, got: {tampered_err:?}"
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
    }

    /// v0.7.2 (CIRISPersist#32) — round-trip the canonical-promotion
    /// path: insert 2 pending contributions, promote both via one
    /// PromotionAttestation, verify is_canonical flips + the
    /// attestation row lands. Also covers: empty target_ids rejects;
    /// unknown target rejects; duplicate attestation_id conflicts.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn promotion_attestation_round_trip() {
        use crate::cirisnode::{PromotionAttestation, TargetRowKind};
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
        let consensus_key = ed25519_dalek::SigningKey::from_bytes(&[0x88; 32]);
        let author = pubkey_b64(&author_key);
        let consensus = pubkey_b64(&consensus_key);
        let domain = format!("promo-dom-{}", Uuid::new_v4());

        // INSERT 2 pending contributions.
        let mut contribution_ids = Vec::new();
        for _ in 0..2 {
            let cid = Uuid::new_v4();
            let mut env = ContributionEnvelope {
                contribution_id: cid.to_string(),
                contribution_type: ContributionType::Proposal,
                author_id: author.clone(),
                subject: Cell {
                    domain: domain.clone(),
                    language: "en".into(),
                    subject: Some("arc_question".into()),
                },
                payload: serde_json::json!({"q": "test"}),
                witness_set: None,
                signature: HybridSignature {
                    ed25519: String::new(),
                    ml_dsa_65: None,
                    signed_at: Utc::now(),
                },
                submitted_at: Utc::now(),
            };
            env.signature = sign_envelope(&env, &author_key);
            backend.put_contribution(env).await.unwrap();
            contribution_ids.push(cid.to_string());
        }

        // Promote both with one attestation.
        let attestation_id = Uuid::new_v4();
        let mut att = PromotionAttestation {
            attestation_id: attestation_id.to_string(),
            target_kind: TargetRowKind::Contribution,
            target_ids: contribution_ids.clone(),
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
            "both contributions should be canonical"
        );

        // Duplicate attestation_id → Conflict.
        let dup_err = backend.put_promotion_attestation(att).await.unwrap_err();
        assert!(
            matches!(dup_err, Error::Conflict(_)),
            "expected Conflict on duplicate attestation, got: {dup_err:?}"
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

        // Unknown target_id → InvalidArgument; transaction rolls back
        // so the attestation row must NOT be persisted.
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
        // Confirm rollback: attempt re-using the same attestation_id
        // with a valid target now succeeds (proving the prior INSERT
        // was rolled back, not persisted).
        let recovery_cid = Uuid::new_v4();
        let mut recovery_env = ContributionEnvelope {
            contribution_id: recovery_cid.to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author.clone(),
            subject: Cell {
                domain: domain.clone(),
                language: "en".into(),
                subject: Some("arc_question".into()),
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
            .expect("attestation row was rolled back, so re-use must succeed");
    }

    // ─── Federation Announcement (v2.1, CIRISPersist#101) ───────────

    /// Build an envelope carrying a `FederationAnnouncementPayload`
    /// and sign it. The contribution_type is `Proposal` — the broad
    /// envelope class for subject-kind-routed payloads per SCHEMA.md
    /// section 4; subject.subject = `federation_announcement` is the
    /// discriminator the row-table CHECK + announcement columns pivot
    /// on.
    fn build_announcement(
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

    /// Round-trip a federation_announcement per AuthorityClass +
    /// representative AnnouncementKind. Covers the four authority
    /// classes (BootstrapSeed, RootWa, WaQuorum, HumanityAccord) and
    /// confirms the indexed columns + JSONB payload survive a
    /// list_contributions read.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn federation_announcement_round_trip_each_authority_class() {
        use crate::cirisnode::{AnnouncementKind, AnnouncementPriority, AuthorityClass};
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

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

        let mut written_ids: Vec<String> = Vec::new();
        for (priority, authority, kind) in fixtures {
            let accord_payload = if matches!(priority, AnnouncementPriority::AccordCarrier) {
                Some(crate::cirisnode::AccordCarrier {
                    payload_bytes: (0u8..77).collect(),
                    rationale: Some("drill".into()),
                })
            } else {
                None
            };
            let env =
                build_announcement(&author_key, priority, authority, kind, accord_payload, None);
            written_ids.push(env.contribution_id.clone());
            backend.put_contribution(env).await.unwrap();
        }

        // 77-byte accord payload round-trip — read the AccordCarrier
        // row back and confirm payload_bytes is byte-equal.
        let accord_id = &written_ids[3];
        let page = backend
            .list_contributions(
                ContributionsFilter {
                    subject_kind: Some(crate::cirisnode::SUBJECT_KIND.into()),
                    priority: Some(AnnouncementPriority::AccordCarrier),
                    ..Default::default()
                },
                None,
                1000,
            )
            .await
            .unwrap();
        let accord_item = page
            .items
            .iter()
            .find(|i| &i.contribution_id == accord_id)
            .expect("accord carrier row read back");
        let payload: crate::cirisnode::FederationAnnouncementPayload =
            serde_json::from_value(accord_item.payload.clone()).unwrap();
        let accord = payload.accord_payload.expect("accord_payload present");
        assert_eq!(accord.payload_bytes.len(), 77);
        assert_eq!(accord.payload_bytes, (0u8..77).collect::<Vec<u8>>());
    }

    /// FSD §4.5: a federation_announcement claiming AccordCarrier
    /// priority under a non-HumanityAccord authority class is
    /// rejected at write admission with the typed error variant.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn federation_announcement_rejects_constitutional_asymmetry_violation() {
        use crate::cirisnode::{AnnouncementKind, AnnouncementPriority, AuthorityClass};
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xC2; 32]);
        // AccordCarrier priority signed by RootWa — wire-format violation.
        let env = build_announcement(
            &author_key,
            AnnouncementPriority::AccordCarrier,
            AuthorityClass::RootWa,
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
            "expected FederationAnnouncementAuthorityMismatch, got: {err:?}"
        );

        // Conversely: HumanityAccord signing Urgent is also rejected.
        let env2 = build_announcement(
            &author_key,
            AnnouncementPriority::Urgent,
            AuthorityClass::HumanityAccord,
            AnnouncementKind::PolicyUpdate,
            None,
            None,
        );
        let err2 = backend.put_contribution(env2).await.unwrap_err();
        assert!(matches!(
            err2,
            Error::FederationAnnouncementAuthorityMismatch(_)
        ));
    }

    /// Supersedes chain — write announcement A, then announcement B
    /// with `supersedes = Some(A.id)`. list_contributions returns
    /// both rows; the payload on B carries the back-reference.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn federation_announcement_supersedes_chain_round_trip() {
        use crate::cirisnode::{AnnouncementKind, AnnouncementPriority, AuthorityClass};
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xC3; 32]);

        let env_a = build_announcement(
            &author_key,
            AnnouncementPriority::Advisory,
            AuthorityClass::RootWa,
            AnnouncementKind::PolicyUpdate,
            None,
            None,
        );
        let a_id = env_a.contribution_id.clone();
        backend.put_contribution(env_a).await.unwrap();

        let env_b = build_announcement(
            &author_key,
            AnnouncementPriority::Advisory,
            AuthorityClass::RootWa,
            AnnouncementKind::PolicyUpdate,
            None,
            Some(a_id.clone()),
        );
        let b_id = env_b.contribution_id.clone();
        backend.put_contribution(env_b).await.unwrap();

        // Both rows surface; B carries the back-reference.
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
        let b_row = page
            .items
            .iter()
            .find(|i| i.contribution_id == b_id)
            .unwrap();
        let p: crate::cirisnode::FederationAnnouncementPayload =
            serde_json::from_value(b_row.payload.clone()).unwrap();
        assert_eq!(p.supersedes.as_deref(), Some(a_id.as_str()));
    }

    /// list_contributions filter extension — 6+ announcements, query
    /// by various filter combinations. Confirms priority,
    /// authority_class, and kind compose AND-style with each other
    /// and the existing subject_kind / author_id filters.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn list_contributions_filter_extension() {
        use crate::cirisnode::{AnnouncementKind, AnnouncementPriority, AuthorityClass};
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        // v2.5.0 — randomize the seed so reruns against a shared
        // postgres DB don't accumulate contributions under the same
        // author key (which made the count assertions flake when the
        // test was rerun manually; closes the latent test-pollution
        // bug per project memory `feedback_hundred_percent_green.md`).
        // Seed entropy via UUID v4 (already a dep) — 16 bytes, copied
        // twice into the 32-byte signing-key seed.
        let mut seed = [0u8; 32];
        let bytes = uuid::Uuid::new_v4().as_bytes().to_owned();
        seed[..16].copy_from_slice(&bytes);
        seed[16..].copy_from_slice(&bytes);
        let author_key = ed25519_dalek::SigningKey::from_bytes(&seed);
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

        let mut written_ids: Vec<String> = Vec::new();
        for (pri, aut, kind) in &fixtures {
            let accord_payload = if matches!(pri, AnnouncementPriority::AccordCarrier) {
                Some(crate::cirisnode::AccordCarrier {
                    payload_bytes: vec![0u8; 77],
                    rationale: None,
                })
            } else {
                None
            };
            let env =
                build_announcement(&author_key, *pri, *aut, kind.clone(), accord_payload, None);
            written_ids.push(env.contribution_id.clone());
            backend.put_contribution(env).await.unwrap();
        }

        // priority = informational → 2 rows.
        let page = backend
            .list_contributions(
                ContributionsFilter {
                    author_id: Some(author.clone()),
                    subject_kind: Some(crate::cirisnode::SUBJECT_KIND.into()),
                    priority: Some(AnnouncementPriority::Informational),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2, "priority=informational");

        // authority_class = root_wa → 2 rows.
        let page = backend
            .list_contributions(
                ContributionsFilter {
                    author_id: Some(author.clone()),
                    subject_kind: Some(crate::cirisnode::SUBJECT_KIND.into()),
                    authority_class: Some(AuthorityClass::RootWa),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2, "authority_class=root_wa");

        // priority = advisory AND authority_class = wa_quorum → 1 row.
        let page = backend
            .list_contributions(
                ContributionsFilter {
                    author_id: Some(author.clone()),
                    subject_kind: Some(crate::cirisnode::SUBJECT_KIND.into()),
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

        // kind = key_rotation → 1 row.
        let page = backend
            .list_contributions(
                ContributionsFilter {
                    author_id: Some(author.clone()),
                    subject_kind: Some(crate::cirisnode::SUBJECT_KIND.into()),
                    kind: Some(AnnouncementKind::KeyRotation),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1, "kind=key_rotation");

        // No filter → all 6 announcement rows for this author.
        let page = backend
            .list_contributions(
                ContributionsFilter {
                    author_id: Some(author.clone()),
                    subject_kind: Some(crate::cirisnode::SUBJECT_KIND.into()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 6);
    }

    // ─── Federation Delivery Attestations (FSD §3.2.1) ──────────────

    /// Build a federation key + sign it on the directory. Returns the
    /// (key_id, signing_key, base64 pubkey) tuple ready to use as the
    /// peer that emits an attestation.
    async fn put_peer_federation_key(
        backend: &PostgresBackend,
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
            roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
        };
        backend
            .put_public_key(crate::federation::SignedKeyRecord { record })
            .await
            .unwrap();
        (key_id, signing_key, pubkey_b64)
    }

    /// Build a signed DeliveryAttestation. The peer signs the
    /// canonical-bytes of the attestation with the federation key
    /// referenced by `peer_key_id`.
    fn build_signed_attestation(
        announcement_id: &str,
        canonical_hash: &[u8; 32],
        peer_key_id: &str,
        peer_pubkey_b64: &str,
        peer_signing_key: &ed25519_dalek::SigningKey,
    ) -> crate::cirisnode::DeliveryAttestation {
        use ed25519_dalek::Signer as _;
        // Build the attestation with a placeholder signature, then
        // re-sign the canonical bytes and stamp the real signature.
        let mut att = crate::cirisnode::DeliveryAttestation {
            announcement_id: announcement_id.to_owned(),
            announcement_canonical_hash_base64: crate::cirisnode::encode_canonical_hash_base64(
                canonical_hash,
            ),
            peer_key_id: peer_key_id.to_owned(),
            peer_pubkey_ed25519_base64: peer_pubkey_b64.to_owned(),
            received_at: Utc::now(),
            transport_id: crate::cirisnode::TransportMedium::Reticulum,
            signature_classical_base64: crate::cirisnode::encode_signature_base64(&[0u8; 64]),
            signature_pqc_base64: None,
        };
        let canonical = att.canonical_bytes().unwrap();
        let sig = peer_signing_key.sign(&canonical);
        att.signature_classical_base64 = crate::cirisnode::encode_signature_base64(&sig.to_bytes());
        att
    }

    /// Round-trip N delivery attestations for one announcement:
    /// `put_delivery_attestation` × N → `list` × 1 returns N rows,
    /// `count` × 1 returns N. Also covers idempotent replay
    /// (duplicate (announcement_id, peer_key_id) is a no-op).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn delivery_attestation_round_trip_idempotent() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        // First write a federation_announcement to serve as the FK
        // target — attestations reference an existing announcement.
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xC5; 32]);
        let env = build_announcement(
            &author_key,
            crate::cirisnode::AnnouncementPriority::Advisory,
            crate::cirisnode::AuthorityClass::RootWa,
            crate::cirisnode::AnnouncementKind::ThreatAdvisory,
            None,
            None,
        );
        let announcement_id = env.contribution_id.clone();
        backend.put_contribution(env).await.unwrap();

        // Construct 3 peer federation keys + their attestations.
        let canonical_hash: [u8; 32] = [0x42; 32];
        let mut peers = Vec::new();
        for seed in [0xD1u8, 0xD2u8, 0xD3u8] {
            peers.push(put_peer_federation_key(&backend, seed).await);
        }

        for (key_id, signing_key, pubkey_b64) in &peers {
            let att = build_signed_attestation(
                &announcement_id,
                &canonical_hash,
                key_id,
                pubkey_b64,
                signing_key,
            );
            backend.put_delivery_attestation(att.clone()).await.unwrap();
            // Idempotent replay — second call is no-op.
            backend.put_delivery_attestation(att).await.unwrap();
        }

        // list_delivery_attestations returns all 3, newest-first.
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

        // count_delivery_attestations returns 3.
        let n = backend
            .count_delivery_attestations(&announcement_id)
            .await
            .unwrap();
        assert_eq!(n, 3);

        // Canonical hash + transport_id survive round trip byte-equal.
        let first = &rows[0];
        let back_hash = first.canonical_hash_bytes().unwrap();
        assert_eq!(back_hash, canonical_hash);
        assert_eq!(
            first.transport_id,
            crate::cirisnode::TransportMedium::Reticulum
        );
    }

    /// FSD §3.2.1 threat model: a forged attestation (signature
    /// produced by a DIFFERENT key than `peer_key_id` claims) is
    /// rejected at admission with [`Error::Signature`].
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn delivery_attestation_rejects_forged_signature() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        // Set up the FK target.
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xC6; 32]);
        let env = build_announcement(
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
            put_peer_federation_key(&backend, 0xE1).await;
        let attacker_signer = ed25519_dalek::SigningKey::from_bytes(&[0xFE; 32]);

        // Build an attestation CLAIMING to be from the legit peer but
        // sign with the attacker's key. The directory pubkey is
        // legit_pubkey_b64 → verify must fail.
        let att = build_signed_attestation(
            &announcement_id,
            &[0u8; 32],
            &legit_key_id,
            &legit_pubkey_b64,
            &attacker_signer,
        );
        let err = backend.put_delivery_attestation(att).await.unwrap_err();
        assert!(matches!(err, Error::Signature(_)), "got: {err:?}");
    }

    // ── Media-sharing tests (v3.6.0, CIRISPersist#134) ─────────────

    fn fixture_sha_hex(seed: u8) -> String {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        hex::encode(bytes)
    }

    // ── v8.7.2 (#233 follow-on, CEG RC27 §11.10) — PG §11.10 moderation
    // gate seeding helpers (parity with the sqlite matrix). `key_id` =
    // pubkey_b64 (matches the cirisnode signer surface).

    /// Seed a `federation_keys` row for `key_id` with the given
    /// `identity_type`.
    async fn seed_key_pg(backend: &PostgresBackend, key_id: &str, identity_type: &str) {
        use crate::federation::FederationDirectory;
        // v9.0.0 (CC 5.3.2.4.3.1) — real deterministic hybrid pubkeys so
        // the federation-tier seed attestations (signed via
        // `sign_envelope(key_id, ...)`) verify at the ingest gate.
        // Moderation/contribution payloads verify self-contained against
        // their `author_id` pubkey (SCHEMA.md §2.2), not this row.
        let (ed_pk, mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(key_id);
        let rec = crate::federation::types::KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: identity_type.into(),
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
            roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
        };
        // Tolerate an exact-content idempotent re-seed on a reused PG (the
        // lead's local docker DB persists across runs); a genuine
        // wrong-content conflict is impossible here because every test uses
        // a globally-unique signing-key seed (so key_id is unique per test).
        match backend
            .put_public_key(crate::federation::types::SignedKeyRecord { record: rec })
            .await
        {
            Ok(()) | Err(crate::federation::Error::Conflict(_)) => {}
            Err(e) => panic!("seed_key_pg: {e}"),
        }
    }

    async fn seed_fed_key_pg(backend: &PostgresBackend, key_id: &str) {
        seed_key_pg(
            backend,
            key_id,
            crate::federation::types::identity_type::PRIMITIVE,
        )
        .await;
    }

    async fn seed_user_key_pg(backend: &PostgresBackend, key_id: &str) {
        seed_key_pg(
            backend,
            key_id,
            crate::federation::types::identity_type::USER,
        )
        .await;
    }

    /// Seed the content-ESTABLISHING federation `scores` attestation binding
    /// `content_sha256` in `evidence_refs` with SIGNED `subject_key_ids`.
    async fn seed_establishing_content_pg(
        backend: &PostgresBackend,
        producer: &str,
        content_sha256: &str,
        subjects: &[&str],
    ) {
        use crate::federation::FederationDirectory;
        // v9.0.0 (CC 5.3.2.4.3.1) — hybrid-sign with `producer`'s
        // deterministic key (matches `seed_key_pg`'s registered pubkeys).
        let envelope = serde_json::json!({
            "dimension": "content:established:v1",
            "evidence_refs": [content_sha256],
        });
        let (och, classical, pqc) =
            crate::federation::tier_ingest::test_support::sign_envelope(producer, &envelope);
        let att = crate::federation::types::Attestation {
            attestation_id: Uuid::new_v4().to_string(),
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
        };
        backend
            .put_attestation(crate::federation::types::SignedAttestation { attestation: att })
            .await
            .unwrap();
    }

    /// Seed a `delegates_to` edge `granter → grantee` bearing `scope`.
    async fn seed_delegation_pg(
        backend: &PostgresBackend,
        granter: &str,
        grantee: &str,
        scope: serde_json::Value,
    ) {
        use crate::federation::FederationDirectory;
        let id = Uuid::new_v4().to_string();
        // v9.0.0 (CC 5.3.2.4.3.1) — hybrid-sign with `granter`'s
        // deterministic key (matches the registered pubkeys).
        let envelope = serde_json::json!({
            "references_attestation_id": id,
            "scope": scope,
        });
        let (och, classical, pqc) =
            crate::federation::tier_ingest::test_support::sign_envelope(granter, &envelope);
        let att = crate::federation::types::Attestation {
            attestation_id: id.clone(),
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
        };
        backend
            .put_attestation(crate::federation::types::SignedAttestation { attestation: att })
            .await
            .unwrap();
    }

    /// Seed a community keyed by `community_id` with a `founder` member.
    async fn seed_community_pg(backend: &PostgresBackend, community_id: &str, founder: &str) {
        use crate::federation::FederationDirectory;
        backend
            .put_community(crate::federation::SignedCommunity {
                community: crate::federation::types::Community {
                    community_key_id: community_id.into(),
                    community_name: "tc".into(),
                    members: vec![crate::federation::types::CommunityMember {
                        key_id: founder.into(),
                        joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                        role: Some("founder".into()),
                    }],
                    founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                    consensus_protocol: crate::federation::types::consensus_protocol::FOUNDER_ONLY
                        .into(),
                    policy_blob: None,
                    persist_row_hash: String::new(),
                },
            })
            .await
            .unwrap();
    }

    /// Build a signed `ModerationEvent`. `subjects` is the (advisory)
    /// payload subject set; `content_sha256` drives `subject_of` authority.
    fn build_moderation_event_pg(
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

    fn build_takedown_contribution(
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
        // v8.7.2 (#233 follow-on): the §11.10 gate requires the author to be
        // a duty-holder over the SIGNED content provenance. The payload
        // `subject_key_ids` is advisory/routing-only — it no longer admits.
        // Storage/listing tests using this helper seed an establishing
        // `scores` attestation binding `sha_hex` with signed subjects=[author]
        // (`seed_establishing_content_pg`). The advisory field is left set.
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

    fn build_key_grant_contribution(
        author_key: &ed25519_dalek::SigningKey,
        sha_hex: &str,
        recipient_key_id: &str,
    ) -> ContributionEnvelope {
        let author = pubkey_b64(author_key);
        let payload = crate::cirisnode::KeyGrantPayload {
            recipient_key_id: recipient_key_id.to_owned(),
            content_sha256: Some(sha_hex.to_owned()),
            stream_id: None,
            stream_epoch: None,
            wrapped_dek_base64: {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode([0u8; 48])
            },
            wrap_algorithm: crate::cirisnode::WrapAlgorithm::HpkeRfc9180BaseX25519AesGcm,
            ratchet_version: 1,
            key_validity_window: crate::cirisnode::KeyValidityWindow {
                not_before: Utc::now(),
                not_after: Utc::now() + chrono::Duration::days(30),
            },
            scope: crate::cirisnode::KeyGrantScope::SingleContent,
            scope_id: sha_hex.to_owned(),
            rotation_chain: vec![],
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

    // ── Cut C3b: stream/epoch-addressed grant cascade (CEG §10.5.3) ──

    fn build_stream_key_grant(
        author_key: &ed25519_dalek::SigningKey,
        stream_id: &str,
        epoch: u64,
        recipient_key_id: &str,
    ) -> ContributionEnvelope {
        let author = pubkey_b64(author_key);
        let payload = crate::cirisnode::KeyGrantPayload {
            recipient_key_id: recipient_key_id.to_owned(),
            content_sha256: None,
            stream_id: Some(stream_id.to_owned()),
            stream_epoch: Some(epoch),
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
            scope: crate::cirisnode::KeyGrantScope::StreamEpoch,
            scope_id: stream_id.to_owned(),
            rotation_chain: vec![],
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

    /// PG parity for the stream/epoch grant cascade: v2 grant admitted,
    /// projected onto the V064 BIGINT/text columns, served by
    /// list_key_grants_for_stream_epoch filtered on (stream_id, epoch);
    /// and a v1-wrapped streaming grant is rejected at ingest.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_stream_epoch_grant_round_trip_and_v1_reject() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xC5; 32]);
        let stream = format!("stream-{}", Uuid::new_v4());
        let other_stream = format!("stream-{}", Uuid::new_v4());
        let recip = format!("rec-{}", Uuid::new_v4());

        backend
            .put_contribution(build_stream_key_grant(&author_key, &stream, 1, &recip))
            .await
            .unwrap();
        backend
            .put_contribution(build_stream_key_grant(&author_key, &stream, 2, &recip))
            .await
            .unwrap();
        backend
            .put_contribution(build_stream_key_grant(
                &author_key,
                &other_stream,
                1,
                &recip,
            ))
            .await
            .unwrap();

        let rows = backend
            .list_key_grants_for_stream_epoch(&stream, 1)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "exactly the (stream, epoch=1) grant");
        let rows2 = backend
            .list_key_grants_for_stream_epoch(&stream, 2)
            .await
            .unwrap();
        assert_eq!(rows2.len(), 1);
        let none = backend
            .list_key_grants_for_stream_epoch(&stream, 99)
            .await
            .unwrap();
        assert!(none.is_empty());

        // v1 wrap on a streaming grant is rejected at ingest.
        let mut env = build_stream_key_grant(&author_key, &stream, 3, &recip);
        let mut payload: crate::cirisnode::KeyGrantPayload =
            serde_json::from_value(env.payload.clone()).unwrap();
        payload.wrap_algorithm = crate::cirisnode::WrapAlgorithm::HpkeRfc9180BaseX25519AesGcm;
        env.payload = serde_json::to_value(&payload).unwrap();
        env.signature = sign_envelope(&env, &author_key);
        let err = backend.put_contribution(env).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got: {err:?}");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn takedown_notice_admits_via_put_contribution() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xF1; 32]);
        let author = pubkey_b64(&author_key);
        let sha_hex = fixture_sha_hex(0x70);
        // v8.7.2: author must be a SIGNED subject of the establishing
        // content for the as-self takedown path to admit.
        seed_fed_key_pg(&backend, &author).await;
        seed_establishing_content_pg(&backend, &author, &sha_hex, &[&author]).await;
        let env = build_takedown_contribution(
            &author_key,
            &sha_hex,
            crate::cirisnode::LegalBasis::Dmca512,
        );
        backend.put_contribution(env).await.unwrap();
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn takedown_notice_payload_shape_validates() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xF2; 32]);
        let mut env = build_takedown_contribution(
            &author_key,
            "not-hex",
            crate::cirisnode::LegalBasis::Dmca512,
        );
        env.signature = sign_envelope(&env, &author_key);
        let err = backend.put_contribution(env).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got: {err:?}");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn key_grant_admits_via_put_contribution() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xF3; 32]);
        let sha_hex = fixture_sha_hex(0x71);
        let env = build_key_grant_contribution(&author_key, &sha_hex, "recipient-key-1");
        backend.put_contribution(env).await.unwrap();
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn key_grant_payload_shape_validates() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xF4; 32]);
        // wrapped_dek_base64 invalid → InvalidArgument.
        let sha_hex = fixture_sha_hex(0x72);
        let mut env = build_key_grant_contribution(&author_key, &sha_hex, "rec");
        // Mutate the payload JSON in place to corrupt the base64.
        if let Some(obj) = env.payload.as_object_mut() {
            obj.insert(
                "wrapped_dek_base64".into(),
                serde_json::Value::String("!!not_base64!!".into()),
            );
        }
        env.signature = sign_envelope(&env, &author_key);
        let err = backend.put_contribution(env).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "got: {err:?}");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn list_takedowns_for_returns_only_matching_sha() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xF5; 32]);
        let author = pubkey_b64(&author_key);
        let sha_a = fixture_sha_hex(0x10);
        let sha_b = fixture_sha_hex(0x20);
        // v8.7.2: author is the SIGNED subject of both target contents.
        seed_fed_key_pg(&backend, &author).await;
        seed_establishing_content_pg(&backend, &author, &sha_a, &[&author]).await;
        seed_establishing_content_pg(&backend, &author, &sha_b, &[&author]).await;
        backend
            .put_contribution(build_takedown_contribution(
                &author_key,
                &sha_a,
                crate::cirisnode::LegalBasis::Dmca512,
            ))
            .await
            .unwrap();
        backend
            .put_contribution(build_takedown_contribution(
                &author_key,
                &sha_b,
                crate::cirisnode::LegalBasis::DsaArticle16,
            ))
            .await
            .unwrap();
        let rows = backend.list_takedowns_for(&sha_a).await.unwrap();
        assert!(
            rows.iter().all(|r| {
                r.payload
                    .get("content_sha256")
                    .and_then(|v| v.as_str())
                    .is_some_and(|s| s == sha_a)
            }),
            "every row matches sha_a; got {rows:?}"
        );
        assert!(rows.iter().any(|r| {
            r.payload.get("content_sha256").and_then(|v| v.as_str()) == Some(sha_a.as_str())
        }));
    }

    // ── v8.7.2 (#233 follow-on, CEG RC27 §11.10) — PG §11.10 moderation
    // gate matrix (parity with the sqlite matrix), bound to SIGNED content
    // provenance via `subject_of_content`.

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_moderation_event_full_matrix() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        // v8.7.2: globally-unique seed bytes (0x90-0x93) so this test's
        // federation keys never collide with another PG test's fixed-seed
        // keys on a reused DB (cross-type Conflict guard).
        let subject_key = ed25519_dalek::SigningKey::from_bytes(&[0x90; 32]);
        let delegate_key = ed25519_dalek::SigningKey::from_bytes(&[0x91; 32]);
        let rando_key = ed25519_dalek::SigningKey::from_bytes(&[0x92; 32]);
        let founder_key = ed25519_dalek::SigningKey::from_bytes(&[0x93; 32]);
        let subject = pubkey_b64(&subject_key);
        let delegate = pubkey_b64(&delegate_key);
        let rando = pubkey_b64(&rando_key);
        let founder = pubkey_b64(&founder_key);
        seed_user_key_pg(&backend, &subject).await;
        seed_user_key_pg(&backend, &founder).await;
        for k in [&delegate, &rando] {
            seed_fed_key_pg(&backend, k).await;
        }
        let comm = format!("comm-mod-{}", Uuid::new_v4());
        seed_community_pg(&backend, &comm, &founder).await;

        // Establishing content binds `sha` with SIGNED subjects=[subject].
        let sha = fixture_sha_hex(0x9a);
        seed_establishing_content_pg(&backend, &subject, &sha, &[&subject]).await;

        // (a) as-self subject (signed in the establishing content) → ADMIT.
        backend
            .put_moderation_event(build_moderation_event_pg(
                &subject_key,
                "target",
                &[&subject],
                None,
                Some(&sha),
            ))
            .await
            .expect("(a) as-self subject moderation admitted");

        // (b1) subject-delegated chain (subject → delegate, moderate) → ADMIT.
        seed_delegation_pg(
            &backend,
            &subject,
            &delegate,
            serde_json::json!(["moderate"]),
        )
        .await;
        backend
            .put_moderation_event(build_moderation_event_pg(
                &delegate_key,
                "target",
                &[&subject],
                None,
                Some(&sha),
            ))
            .await
            .expect("(b1) subject-delegated moderation admitted");

        // (b2) named-moderator (community founder, steward-bound) → ADMIT.
        backend
            .put_moderation_event(build_moderation_event_pg(
                &founder_key,
                "target",
                &[],
                Some(&comm),
                None,
            ))
            .await
            .expect("(b2) named-moderator (founder) moderation admitted");

        // (c) no authority → REJECT.
        let err = backend
            .put_moderation_event(build_moderation_event_pg(
                &rando_key,
                "target",
                &[&subject],
                None,
                Some(&sha),
            ))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "cirisnode_delegated_scope_unauthorized");

        // (c2) NOTHING → REJECT (bypass guard).
        let err = backend
            .put_moderation_event(build_moderation_event_pg(
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
        seed_delegation_pg(
            &backend,
            &subject,
            &rando,
            serde_json::json!(["consent_revocation"]),
        )
        .await;
        let err = backend
            .put_moderation_event(build_moderation_event_pg(
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

    /// THE regression guard — payload self-declaration no longer admits.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_moderation_payload_self_declaration_spoof_rejected() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[0xe1; 32]);
        let real_subject_key = ed25519_dalek::SigningKey::from_bytes(&[0xe2; 32]);
        let attacker = pubkey_b64(&attacker_key);
        let real_subject = pubkey_b64(&real_subject_key);
        seed_fed_key_pg(&backend, &attacker).await;
        seed_user_key_pg(&backend, &real_subject).await;

        let sha = fixture_sha_hex(0xb1);
        seed_establishing_content_pg(&backend, &real_subject, &sha, &[&real_subject]).await;

        // Attacker self-declares subject_key_ids=[attacker] in the payload.
        let err = backend
            .put_moderation_event(build_moderation_event_pg(
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

        // The REAL signed subject still admits as-self.
        backend
            .put_moderation_event(build_moderation_event_pg(
                &real_subject_key,
                "target",
                &[&real_subject],
                None,
                Some(&sha),
            ))
            .await
            .expect("real signed subject admits as-self");
    }

    /// Fail-secure: no establishing attestation ⇒ subject-self FAILS;
    /// named-mod still ADMITs; non-authority REJECTs.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_moderation_fail_secure_no_establishing_content() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        // v8.7.2: globally-unique seed bytes (0x94-0x96) — see the matrix
        // test's note on cross-test key-collision avoidance.
        let subject_key = ed25519_dalek::SigningKey::from_bytes(&[0x94; 32]);
        let founder_key = ed25519_dalek::SigningKey::from_bytes(&[0x95; 32]);
        let rando_key = ed25519_dalek::SigningKey::from_bytes(&[0x96; 32]);
        let subject = pubkey_b64(&subject_key);
        let founder = pubkey_b64(&founder_key);
        let rando = pubkey_b64(&rando_key);
        seed_user_key_pg(&backend, &subject).await;
        seed_user_key_pg(&backend, &founder).await;
        seed_fed_key_pg(&backend, &rando).await;
        let comm = format!("comm-fs-{}", Uuid::new_v4());
        seed_community_pg(&backend, &comm, &founder).await;

        // No establishing content for this sha — subject_of undetermined.
        let sha = fixture_sha_hex(0xc2);

        // subject-self FAILS.
        let err = backend
            .put_moderation_event(build_moderation_event_pg(
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

        // named-mod path (b) still ADMITs the steward-bound founder.
        backend
            .put_moderation_event(build_moderation_event_pg(
                &founder_key,
                "target",
                &[&subject],
                Some(&comm),
                Some(&sha),
            ))
            .await
            .expect("named-mod still admits under fail-secure subject_of");

        // a non-authority signer still REJECTs.
        let err = backend
            .put_moderation_event(build_moderation_event_pg(
                &rando_key,
                "target",
                &[&subject],
                Some(&comm),
                Some(&sha),
            ))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), "cirisnode_delegated_scope_unauthorized");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn list_key_grants_for_returns_only_matching_recipient() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xF6; 32]);
        let sha = fixture_sha_hex(0x30);
        let recip = format!("rec-{}", Uuid::new_v4());
        let other = format!("other-{}", Uuid::new_v4());
        backend
            .put_contribution(build_key_grant_contribution(&author_key, &sha, &recip))
            .await
            .unwrap();
        backend
            .put_contribution(build_key_grant_contribution(&author_key, &sha, &other))
            .await
            .unwrap();
        let rows = backend.list_key_grants_for(&recip).await.unwrap();
        assert!(rows.iter().all(
            |r| r.payload.get("recipient_key_id").and_then(|v| v.as_str()) == Some(recip.as_str())
        ));
        assert!(!rows.is_empty());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn list_key_grants_for_content_filters_both_axes() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let author_key = ed25519_dalek::SigningKey::from_bytes(&[0xF7; 32]);
        let sha_a = fixture_sha_hex(0x40);
        let sha_b = fixture_sha_hex(0x50);
        let recip_a = format!("rec-a-{}", Uuid::new_v4());
        let recip_b = format!("rec-b-{}", Uuid::new_v4());
        backend
            .put_contribution(build_key_grant_contribution(&author_key, &sha_a, &recip_a))
            .await
            .unwrap();
        backend
            .put_contribution(build_key_grant_contribution(&author_key, &sha_a, &recip_b))
            .await
            .unwrap();
        backend
            .put_contribution(build_key_grant_contribution(&author_key, &sha_b, &recip_a))
            .await
            .unwrap();
        let rows = backend
            .list_key_grants_for_content(&sha_a, &recip_a)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(
            row.payload.get("content_sha256").and_then(|v| v.as_str()),
            Some(sha_a.as_str())
        );
        assert_eq!(
            row.payload.get("recipient_key_id").and_then(|v| v.as_str()),
            Some(recip_a.as_str())
        );
    }

    /// CEG 0.3 §5.6.8.4 — option (b) supersession: retire_key_grants
    /// emits a FRESH key_grant Contribution with rotation_chain
    /// extended by the prior contribution_id, not a withdraws against
    /// the prior. The fresh grant carries an empty wrapped_dek_base64
    /// (revocation sentinel).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn retire_key_grants_emits_rotation_chain_not_withdraws() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let mut seed = [0u8; 32];
        let bytes = uuid::Uuid::new_v4().as_bytes().to_owned();
        seed[..16].copy_from_slice(&bytes);
        seed[16..].copy_from_slice(&bytes);
        let author_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let author = pubkey_b64(&author_key);
        seed_actor_federation_key(&backend, &author, &author_key).await;

        let sha_a = fixture_sha_hex(0x60);
        let sha_b = fixture_sha_hex(0x61);
        let prior_a = build_key_grant_contribution(&author_key, &sha_a, "rec-1");
        let prior_a_id = prior_a.contribution_id.clone();
        let prior_b = build_key_grant_contribution(&author_key, &sha_b, "rec-2");
        let prior_b_id = prior_b.contribution_id.clone();
        backend.put_contribution(prior_a).await.unwrap();
        backend.put_contribution(prior_b).await.unwrap();

        use crate::signing::{LocalSigner, LocalSignerHardwareAdapter};
        let local = std::sync::Arc::new(LocalSigner::from_parts(
            author_key.clone(),
            author.clone(),
            None,
            None,
        ));
        let signer = LocalSignerHardwareAdapter::new(local);
        let report = backend
            .retire_key_grants(&author, &signer, Utc::now())
            .await
            .unwrap();
        assert_eq!(report.grants_seen, 2);
        assert_eq!(report.supersedes_emitted, 2);
        assert_eq!(report.supersedes_failed, 0);

        // Confirm the supersession Contributions exist and carry the
        // expected rotation_chain shape + empty wrapped_dek sentinel.
        let recip_a_grants = backend.list_key_grants_for("rec-1").await.unwrap();
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
            Some("hpke_rfc9180_base_x25519_aes_gcm"),
            "CEG 0.3 §5.6.8.4 wrap_algorithm wire string"
        );

        let recip_b_grants = backend.list_key_grants_for("rec-2").await.unwrap();
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

    /// Helper used by retire_key_grants_emits_withdraws_for_actor —
    /// seeds an `cirislens.federation_keys` row for the actor so the
    /// `WITHDRAWS` attestation FK clears.
    async fn seed_actor_federation_key(
        backend: &PostgresBackend,
        key_id: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) {
        use base64::Engine as _;
        let pubkey_b64 = base64::engine::general_purpose::STANDARD
            .encode(signing_key.verifying_key().to_bytes());
        let record = crate::federation::types::KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: pubkey_b64,
            pubkey_ml_dsa_65_base64: None,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: key_id.to_owned(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({"id": key_id}),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_owned(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
        };
        use crate::federation::FederationDirectory;
        backend
            .put_public_key(crate::federation::types::SignedKeyRecord { record })
            .await
            .unwrap();
    }

    /// V054 CHECK constraint must reject a bare-SQL direct insert
    /// that violates the takedown_notice subject/column asymmetry.
    /// Mirrors V051 / V053 bare-SQL bypass test discipline.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn v054_check_rejects_mismatched_takedown_columns() {
        use crate::store::backend::Backend;
        use tokio_postgres::error::SqlState;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let client = backend.pool().get().await.unwrap();
        // Try to insert a non-takedown subject_kind with
        // takedown_legal_basis populated — the V054 CHECK must reject.
        let err = client
            .execute(
                "INSERT INTO cirisnode.contributions (\
                    contribution_id, contribution_type, domain, language, subject_kind, \
                    author_id, payload, witness_set, submitted_at, \
                    signature, signing_key_id, signature_verified, persist_row_hash, \
                    takedown_legal_basis\
                 ) VALUES ($1, 'proposal', 'd', 'en', 'arc_question', 'a', '{}'::jsonb, NULL, NOW(), \
                           'sig', 'a', TRUE, 'h', 'dmca_512')",
                &[&Uuid::new_v4()],
            )
            .await
            .unwrap_err();
        let code = err.as_db_error().map(|d| d.code().clone());
        assert_eq!(
            code,
            Some(SqlState::CHECK_VIOLATION),
            "expected CHECK violation (SQLSTATE 23514); got: {err:?}"
        );
    }

    /// Same discipline for the key_grant column asymmetry.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn v054_check_rejects_mismatched_key_grant_columns() {
        use crate::store::backend::Backend;
        use tokio_postgres::error::SqlState;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let client = backend.pool().get().await.unwrap();
        let err = client
            .execute(
                "INSERT INTO cirisnode.contributions (\
                    contribution_id, contribution_type, domain, language, subject_kind, \
                    author_id, payload, witness_set, submitted_at, \
                    signature, signing_key_id, signature_verified, persist_row_hash, \
                    key_grant_recipient_key_id\
                 ) VALUES ($1, 'proposal', 'd', 'en', 'arc_question', 'a', '{}'::jsonb, NULL, NOW(), \
                           'sig', 'a', TRUE, 'h', 'rec-1')",
                &[&Uuid::new_v4()],
            )
            .await
            .unwrap_err();
        let code = err.as_db_error().map(|d| d.code().clone());
        assert_eq!(
            code,
            Some(SqlState::CHECK_VIOLATION),
            "expected CHECK violation (SQLSTATE 23514); got: {err:?}"
        );
    }

    /// V064 (CIRISPersist#142 Cut C3a) — the widened key_grant CHECK
    /// admits BOTH addressing modes (content XOR stream/epoch) and
    /// rejects malformed shapes. Direct bare-SQL inserts exercise the
    /// constraint at the DB layer (the stream-addressed write path is
    /// Cut C3b; C3a only makes the schema admit the shape).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn v064_check_admits_both_key_grant_addressing_modes() {
        use crate::store::backend::Backend;
        use tokio_postgres::error::SqlState;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let client = backend.pool().get().await.unwrap();

        // Raw key_grant insert helper. Columns beyond the standard
        // envelope are passed as $2 (sha), $3 (recipient), $4
        // (stream_id), $5 (stream_epoch).
        let sql = "INSERT INTO cirisnode.contributions (\
                contribution_id, contribution_type, domain, language, subject_kind, \
                author_id, payload, witness_set, submitted_at, \
                signature, signing_key_id, signature_verified, persist_row_hash, \
                media_content_sha256, key_grant_recipient_key_id, \
                key_grant_stream_id, key_grant_stream_epoch\
             ) VALUES ($1, 'proposal', 'd', 'en', 'key_grant', 'a', '{}'::jsonb, NULL, NOW(), \
                       'sig', 'a', TRUE, 'h', $2, $3, $4, $5)";
        let sha = "a".repeat(64);
        let recipient = "rec-1".to_string();
        let stream = "stream-xyz".to_string();
        let epoch: i64 = 7;

        // 1. Existing content-addressed key_grant (sha + recipient,
        //    stream cols NULL) STILL inserts OK.
        client
            .execute(
                sql,
                &[
                    &Uuid::new_v4(),
                    &Some(sha.clone()),
                    &Some(recipient.clone()),
                    &None::<String>,
                    &None::<i64>,
                ],
            )
            .await
            .expect("content-addressed key_grant must still insert post-V064");

        // 2. NEW stream/epoch-addressed key_grant (recipient + stream_id
        //    + stream_epoch, sha NULL) now inserts OK (was rejected
        //    pre-V064).
        client
            .execute(
                sql,
                &[
                    &Uuid::new_v4(),
                    &None::<String>,
                    &Some(recipient.clone()),
                    &Some(stream.clone()),
                    &Some(epoch),
                ],
            )
            .await
            .expect("stream/epoch-addressed key_grant must insert post-V064");

        // 3. BOTH addressing modes set → rejected.
        let err = client
            .execute(
                sql,
                &[
                    &Uuid::new_v4(),
                    &Some(sha.clone()),
                    &Some(recipient.clone()),
                    &Some(stream.clone()),
                    &Some(epoch),
                ],
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.as_db_error().map(|d| d.code().clone()),
            Some(SqlState::CHECK_VIOLATION),
            "both-addressing-modes key_grant must be rejected; got: {err:?}"
        );

        // 4. NEITHER addressing mode set (recipient only) → rejected.
        let err = client
            .execute(
                sql,
                &[
                    &Uuid::new_v4(),
                    &None::<String>,
                    &Some(recipient.clone()),
                    &None::<String>,
                    &None::<i64>,
                ],
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.as_db_error().map(|d| d.code().clone()),
            Some(SqlState::CHECK_VIOLATION),
            "neither-addressing-mode key_grant must be rejected; got: {err:?}"
        );

        // 5. stream_id without stream_epoch → rejected (partial
        //    stream/epoch mode).
        let err = client
            .execute(
                sql,
                &[
                    &Uuid::new_v4(),
                    &None::<String>,
                    &Some(recipient.clone()),
                    &Some(stream.clone()),
                    &None::<i64>,
                ],
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.as_db_error().map(|d| d.code().clone()),
            Some(SqlState::CHECK_VIOLATION),
            "stream_id-without-epoch key_grant must be rejected; got: {err:?}"
        );

        // 6. non-key_grant row with a stream col set → rejected.
        let err = client
            .execute(
                "INSERT INTO cirisnode.contributions (\
                    contribution_id, contribution_type, domain, language, subject_kind, \
                    author_id, payload, witness_set, submitted_at, \
                    signature, signing_key_id, signature_verified, persist_row_hash, \
                    key_grant_stream_id, key_grant_stream_epoch\
                 ) VALUES ($1, 'proposal', 'd', 'en', 'arc_question', 'a', '{}'::jsonb, NULL, NOW(), \
                           'sig', 'a', TRUE, 'h', $2, $3)",
                &[&Uuid::new_v4(), &Some(stream.clone()), &Some(epoch)],
            )
            .await
            .unwrap_err();
        assert_eq!(
            err.as_db_error().map(|d| d.code().clone()),
            Some(SqlState::CHECK_VIOLATION),
            "non-key_grant row with stream col set must be rejected; got: {err:?}"
        );
    }
}
