//! PostgreSQL impl of [`NodeCoreService`] (v0.7.0; narrowed in v60.0.0,
//! CIRISPersist#988 item 1).
//!
//! What the cirisnode track still stores itself: the credits / expertise
//! ledger reads (projections of this node's rows, written by the attestation
//! plane's executor), the promotion records and the delivery attestations.
//! Every cirisnode CLASS is a row (`super::rows`).

use uuid::Uuid;

use super::federation_announcement::{DeliveryAttestation, TransportMedium};
use super::service::{LegacyLedgerRow, NodeCoreService};
use super::types::{
    CreditsLedgerEntry, CreditsUpdate, ExpertiseLedgerEntry, ExpertiseUpdate, PromotionAttestation,
    RoutableContributor, TargetRowKind, VoteWeight,
};
use super::Error;
use crate::store::postgres::PostgresBackend;

// ─── helpers ────────────────────────────────────────────────────────

/// Parse a UUID string (the promotion record's own id and its target ids
/// are UUIDs: `cirisnode.promotion_attestations` keeps `uuid` / `uuid[]`).
fn parse_id(s: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(s)
        .map_err(|e| Error::InvalidArgument(format!("id parse: {e} (id={s}) — expected UUID")))
}

/// Translate tokio_postgres errors: `unique_violation` → Conflict, FK and
/// CHECK violations → InvalidArgument, everything else → Backend.
fn map_pg_error(e: tokio_postgres::Error, op: &str) -> Error {
    use tokio_postgres::error::SqlState;
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

fn target_kind_str(k: TargetRowKind) -> &'static str {
    match k {
        TargetRowKind::Contribution => "contribution",
        TargetRowKind::Vote => "vote",
        TargetRowKind::ModerationEvent => "moderation_event",
        TargetRowKind::SlashingAttestation => "slashing_attestation",
        TargetRowKind::ReconsiderationAttestation => "reconsideration_attestation",
    }
}

impl PostgresBackend {
    async fn cirisnode_client(&self) -> Result<deadpool_postgres::Object, Error> {
        self.pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))
    }
}

// ─── NodeCoreService impl ───────────────────────────────────────────

impl NodeCoreService for PostgresBackend {
    async fn put_promotion_attestation(&self, att: PromotionAttestation) -> Result<(), Error> {
        super::verify::verify_envelope_signed(&att, &att.signature, &att.attested_by)?;
        let attestation_id = parse_id(&att.attestation_id)?;
        let target_uuids = att
            .target_ids
            .iter()
            .map(|s| parse_id(s))
            .collect::<Result<Vec<Uuid>, _>>()?;
        super::rows::check_promotion_targets(self, att.target_kind, &att.target_ids).await?;
        let client = self.cirisnode_client().await?;
        client
            .execute(
                "INSERT INTO cirisnode.promotion_attestations (\
                    attestation_id, target_kind, target_ids, attested_by, \
                    aggregate_evidence, attested_at, signature, signing_key_id, \
                    signature_verified, persist_row_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE, $9)",
                &[
                    &attestation_id,
                    &target_kind_str(att.target_kind),
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
        Ok(())
    }

    async fn routable_contributors(
        &self,
        domain: &str,
        language: &str,
    ) -> Result<Vec<RoutableContributor>, Error> {
        let client = self.cirisnode_client().await?;
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
        let client = self.cirisnode_client().await?;
        let row = client
            .query_one(
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
        let credits: f64 = row.get(0);
        let expertise: f64 = row.get(1);
        let is_active: bool = row.get(2);
        if credits == 0.0 && expertise == 0.0 && !is_active {
            return Ok(None);
        }
        // SCHEMA.md §5.2: expertise_multiplier = 1 + 4*expertise ([1, 5]);
        // active_tier_multiplier = 1.5 if active else 0.5.
        let expertise_multiplier = 1.0 + 4.0 * expertise;
        let active_tier_multiplier = if is_active { 1.5 } else { 0.5 };
        Ok(Some(VoteWeight {
            contributor_id: contributor_id.to_owned(),
            domain: domain.to_owned(),
            language: language.to_owned(),
            subject: subject.to_owned(),
            credits,
            expertise_multiplier,
            active_tier_multiplier,
            weight: credits * expertise_multiplier * active_tier_multiplier,
        }))
    }

    async fn get_credits_ledger(
        &self,
        contributor_id: &str,
        domain: &str,
        language: &str,
        subject: &str,
    ) -> Result<Option<CreditsLedgerEntry>, Error> {
        let client = self.cirisnode_client().await?;
        let row_opt = client
            .query_opt(
                "SELECT contributor_id, domain, language, subject, balance, \
                        last_update_contribution, last_updated_at, created_at, attestation_id \
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
            attestation_id: row.get(8),
        }))
    }

    async fn get_expertise_ledger(
        &self,
        contributor_id: &str,
        domain: &str,
        language: &str,
    ) -> Result<Option<ExpertiseLedgerEntry>, Error> {
        let client = self.cirisnode_client().await?;
        let row_opt = client
            .query_opt(
                "SELECT contributor_id, domain, language, expertise, is_active, \
                        last_updated_at, last_update_contribution, created_at, attestation_id \
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
            attestation_id: row.get(8),
        }))
    }

    async fn legacy_ledger_rows(&self) -> Result<Vec<LegacyLedgerRow>, Error> {
        let client = self.cirisnode_client().await?;
        let mut out = Vec::new();
        for r in client
            .query(
                "SELECT contributor_id, domain, language, subject, balance, \
                        COALESCE(last_update_contribution, '') \
                 FROM cirisnode.credits_ledger WHERE attestation_id IS NULL \
                 ORDER BY contributor_id, domain, language, subject",
                &[],
            )
            .await
            .map_err(|e| map_pg_error(e, "legacy credits"))?
        {
            out.push(LegacyLedgerRow::Credits(CreditsUpdate {
                contributor_id: r.get(0),
                domain: r.get(1),
                language: r.get(2),
                subject: r.get(3),
                new_balance: r.get(4),
                source_contribution: r.get(5),
            }));
        }
        for r in client
            .query(
                "SELECT contributor_id, domain, language, expertise, is_active, \
                        COALESCE(last_update_contribution, '') \
                 FROM cirisnode.expertise_ledger WHERE attestation_id IS NULL \
                 ORDER BY contributor_id, domain, language",
                &[],
            )
            .await
            .map_err(|e| map_pg_error(e, "legacy expertise"))?
        {
            out.push(LegacyLedgerRow::Expertise(ExpertiseUpdate {
                contributor_id: r.get(0),
                domain: r.get(1),
                language: r.get(2),
                new_expertise: r.get(3),
                new_active_tier: r.get(4),
                source_contribution: r.get(5),
            }));
        }
        Ok(out)
    }

    // ── Federation delivery attestations (v2.1, CIRISPersist#101) ──

    async fn put_delivery_attestation(
        &self,
        attestation: DeliveryAttestation,
    ) -> Result<(), Error> {
        let canonical_hash = attestation.canonical_hash_bytes()?;
        let sig_classical = attestation.signature_classical_bytes()?;
        let pqc_bytes = attestation.signature_pqc_bytes()?;
        super::rows::check_announcement_held(self, &attestation.announcement_id).await?;
        let canonical = attestation
            .canonical_bytes()
            .map_err(|e| Error::Signature(format!("canonical_bytes: {e}")))?;
        crate::verify::verify_hybrid_via_directory(
            self,
            &canonical,
            &attestation.peer_key_id,
            &attestation.signature_classical_base64,
            attestation.signature_pqc_base64.as_deref(),
            // v37.0.0 — Strict, in lockstep with the sqlite twin.
            crate::verify::hybrid::HybridPolicy::Strict,
            None,
        )
        .await
        .map_err(|e| Error::Signature(format!("delivery_attestation verify: {e}")))?;
        let persist_row_hash = crate::federation::types::compute_persist_row_hash(&attestation)
            .map_err(|e| Error::Internal(format!("persist_row_hash: {e}")))?;
        let client = self.cirisnode_client().await?;
        // ON CONFLICT DO NOTHING — the idempotent replay path per FSD §3.2.1.
        client
            .execute(
                "INSERT INTO cirisnode.federation_delivery_attestations (\
                    announcement_id, announcement_canonical_hash, peer_key_id, \
                    peer_pubkey_ed25519_base64, received_at, transport_id, \
                    signature_classical, signature_pqc, signature_verified, persist_row_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE, $9) \
                 ON CONFLICT (announcement_id, peer_key_id) DO NOTHING",
                &[
                    &attestation.announcement_id,
                    &canonical_hash.as_slice(),
                    &attestation.peer_key_id,
                    &attestation.peer_pubkey_ed25519_base64,
                    &attestation.received_at,
                    &attestation.transport_id.as_str(),
                    &sig_classical.as_slice(),
                    &pqc_bytes,
                    &persist_row_hash,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "put_delivery_attestation"))?;
        Ok(())
    }

    async fn list_delivery_attestations(
        &self,
        announcement_id: &str,
    ) -> Result<Vec<DeliveryAttestation>, Error> {
        let client = self.cirisnode_client().await?;
        let rows = client
            .query(
                "SELECT announcement_id, announcement_canonical_hash, peer_key_id, \
                        peer_pubkey_ed25519_base64, received_at, transport_id, \
                        signature_classical, signature_pqc \
                 FROM cirisnode.federation_delivery_attestations \
                 WHERE announcement_id = $1 \
                 ORDER BY received_at DESC",
                &[&announcement_id],
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
        let client = self.cirisnode_client().await?;
        let row = client
            .query_one(
                "SELECT COUNT(*) FROM cirisnode.federation_delivery_attestations \
                 WHERE announcement_id = $1",
                &[&announcement_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "count_delivery_attestations"))?;
        let n: i64 = row.get(0);
        Ok(u64::try_from(n).unwrap_or(0))
    }
}
