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
        self.checkout()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))
    }
}

// ─── NodeCoreService impl ───────────────────────────────────────────

impl NodeCoreService for PostgresBackend {
    async fn put_promotion_attestation(&self, att: PromotionAttestation) -> Result<(), Error> {
        super::verify::verify_envelope_signed(self, &att, &att.signature, &att.attested_by).await?;
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
                    &att.signature.composite,
                    &att.attested_by,
                    &att.signature.composite,
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
                "SELECT contributor_id, expertise::text FROM cirisnode.expertise_ledger \
                 WHERE domain = $1 AND language = $2 \
                   AND expertise > 0 AND is_active = TRUE",
                &[&domain, &language],
            )
            .await
            .map_err(|e| map_pg_error(e, "routable_contributors"))?;
        // v62.0.0 (P1-fix8) — ranked on the exact decimal by the one rule
        // both backends share.
        super::service::rank_routable(
            rows.into_iter()
                .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)))
                .collect(),
        )
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
                "SELECT c.balance::text AS credits, \
                    e.expertise::text AS expertise, \
                    e.is_active AS is_active \
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
        // v62.0.0 (P1-fix8) — the exact decimals as text; the arithmetic is
        // the shared exact rule (SCHEMA.md §5.2), never `float8`.
        let credits: Option<String> = row.get(0);
        let expertise: Option<String> = row.get(1);
        let is_active: Option<bool> = row.get(2);
        super::service::vote_weight_of(
            (contributor_id, domain, language, subject),
            credits,
            expertise.map(|e| (e, is_active.unwrap_or(false))),
        )
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
                "SELECT contributor_id, domain, language, subject, balance::text, \
                        last_update_contribution, last_updated_at, created_at, attestation_id \
                 FROM cirisnode.credits_ledger \
                 WHERE contributor_id = $1 AND domain = $2 \
                   AND language = $3 AND subject = $4",
                &[&contributor_id, &domain, &language, &subject],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_credits_ledger"))?;
        // v62.0.0 (P1-fix8) — the exact decimal, as its canonical text.
        row_opt
            .map(|row| {
                let balance: String = row.get(4);
                Ok(CreditsLedgerEntry {
                    contributor_id: row.get(0),
                    domain: row.get(1),
                    language: row.get(2),
                    subject: row.get(3),
                    balance: super::service::stored_decimal("balance", &balance)?.canonical(),
                    last_update_contribution: row.get(5),
                    last_updated_at: row.get(6),
                    created_at: row.get(7),
                    attestation_id: row.get(8),
                })
            })
            .transpose()
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
                "SELECT contributor_id, domain, language, expertise::text, is_active, \
                        last_updated_at, last_update_contribution, created_at, attestation_id \
                 FROM cirisnode.expertise_ledger \
                 WHERE contributor_id = $1 AND domain = $2 AND language = $3",
                &[&contributor_id, &domain, &language],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_expertise_ledger"))?;
        // v62.0.0 (P1-fix8) — the exact decimal, as its canonical text.
        row_opt
            .map(|row| {
                let expertise: String = row.get(3);
                Ok(ExpertiseLedgerEntry {
                    contributor_id: row.get(0),
                    domain: row.get(1),
                    language: row.get(2),
                    expertise: super::service::stored_decimal("expertise", &expertise)?.canonical(),
                    is_active: row.get(4),
                    last_updated_at: row.get(5),
                    last_update_contribution: row.get(6),
                    created_at: row.get(7),
                    attestation_id: row.get(8),
                })
            })
            .transpose()
    }

    async fn legacy_ledger_rows(&self) -> Result<Vec<LegacyLedgerRow>, Error> {
        let client = self.cirisnode_client().await?;
        let mut out = Vec::new();
        for r in client
            .query(
                "SELECT contributor_id, domain, language, subject, balance::text, \
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
                "SELECT contributor_id, domain, language, expertise::text, is_active, \
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
        super::rows::check_announcement_held(self, &attestation.announcement_id).await?;
        // v62.0.0 (F0-cp5) — ONE composite under the peer's LIVE edition-2
        // key, the shared check both backends call.
        let sig_composite = super::verify::verify_delivery_attestation(self, &attestation).await?;
        let persist_row_hash = crate::federation::types::compute_persist_row_hash(&attestation)
            .map_err(|e| Error::Internal(format!("persist_row_hash: {e}")))?;
        let client = self.cirisnode_client().await?;
        // ON CONFLICT DO NOTHING — the idempotent replay path per FSD §3.2.1.
        client
            .execute(
                "INSERT INTO cirisnode.federation_delivery_attestations (\
                    announcement_id, announcement_canonical_hash, peer_key_id, \
                    received_at, transport_id, \
                    signature_composite, signature_verified, persist_row_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7) \
                 ON CONFLICT (announcement_id, peer_key_id) DO NOTHING",
                &[
                    &attestation.announcement_id,
                    &canonical_hash.as_slice(),
                    &attestation.peer_key_id,
                    &attestation.received_at,
                    &attestation.transport_id.as_str(),
                    &sig_composite.as_slice(),
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
                        received_at, transport_id, signature_composite \
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
            let sig_composite: Vec<u8> = row.get(5);
            let transport_str: &str = row.get(4);
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
                received_at: row.get(3),
                transport_id,
                signature_composite_base64: super::federation_announcement::encode_signature_base64(
                    &sig_composite,
                ),
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
