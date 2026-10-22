// Multi-tuple SELECT projections inside query_row closures lint under
// clippy's `type_complexity`; the tuples bind locally, so a type alias would
// be invasive for no readability gain (same call as src/secrets/sqlite.rs).
#![allow(clippy::type_complexity)]

//! SQLite impl of [`NodeCoreService`] (v0.9.4, CIRISPersist#40; narrowed in
//! v60.0.0, CIRISPersist#988 item 1).
//!
//! What the cirisnode track still stores itself: the credits / expertise
//! ledger reads (the ledgers are projections of this node's rows, written by
//! the attestation plane's executor), the promotion records and the
//! delivery attestations. Every cirisnode CLASS is a row (`super::rows`).
//!
//! Dialect notes: `TIMESTAMPTZ` is `TEXT` (RFC 3339), `UUID[]` (promotion
//! `target_ids`) a JSON array in `TEXT`, `BOOLEAN` an `INTEGER 0/1`.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use super::federation_announcement::{DeliveryAttestation, TransportMedium};
use super::service::{LegacyLedgerRow, NodeCoreService};
use super::types::{
    CreditsLedgerEntry, CreditsUpdate, ExpertiseLedgerEntry, ExpertiseUpdate, PromotionAttestation,
    RoutableContributor, TargetRowKind, VoteWeight,
};
use super::Error;

// ─── helpers ────────────────────────────────────────────────────────

fn target_kind_str(k: TargetRowKind) -> &'static str {
    match k {
        TargetRowKind::Contribution => "contribution",
        TargetRowKind::Vote => "vote",
        TargetRowKind::ModerationEvent => "moderation_event",
        TargetRowKind::SlashingAttestation => "slashing_attestation",
        TargetRowKind::ReconsiderationAttestation => "reconsideration_attestation",
    }
}

/// Parse a UUID string (the promotion record's own id is a UUID).
fn parse_id(s: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(s)
        .map_err(|e| Error::InvalidArgument(format!("id parse: {e} (id={s}) — expected UUID")))
}

/// Translate a rusqlite::Error: a constraint violation is `Conflict`, a type
/// mismatch `InvalidArgument`, everything else `Backend`.
fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    use rusqlite::ErrorCode;
    if let rusqlite::Error::SqliteFailure(err, _) = &e {
        match err.code {
            ErrorCode::ConstraintViolation => return Error::Conflict(format!("{op}: {e}")),
            ErrorCode::TypeMismatch => return Error::InvalidArgument(format!("{op}: {e}")),
            _ => {}
        }
    }
    Error::Backend(format!("{op}: {e}"))
}

/// Parse a TEXT timestamp: RFC 3339 (the projection's form) or SQLite's
/// space-separated default text (a pre-V203 ledger row).
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

// ─── backend ────────────────────────────────────────────────────────

/// SQLite-backed [`NodeCoreService`]. Wraps the `Arc<Mutex<Connection>>`
/// shared with [`crate::store::sqlite::SqliteBackend`], whose directory view
/// over the same connection answers the row reads.
pub struct SqliteNodeCoreBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteNodeCoreBackend {
    /// Construct from a shared connection handle (typically
    /// `SqliteBackend::conn_handle()`).
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    fn directory(&self) -> crate::store::sqlite::SqliteBackend {
        crate::store::sqlite::SqliteBackend::from_conn_handle(self.conn.clone())
    }
}

impl NodeCoreService for SqliteNodeCoreBackend {
    async fn put_promotion_attestation(&self, att: PromotionAttestation) -> Result<(), Error> {
        super::verify::verify_envelope_signed(&att, &att.signature, &att.attested_by)?;
        let attestation_id = parse_id(&att.attestation_id)?.to_string();
        super::rows::check_promotion_targets(&self.directory(), att.target_kind, &att.target_ids)
            .await?;
        let target_ids_json = serde_json::to_string(&att.target_ids)
            .map_err(|e| Error::Internal(format!("target_ids serialize: {e}")))?;
        let aggregate_evidence = serde_json::to_string(&att.aggregate_evidence)
            .map_err(|e| Error::Internal(format!("aggregate_evidence serialize: {e}")))?;
        let guard = self.conn.lock();
        guard
            .execute(
                "INSERT INTO cirisnode_promotion_attestations (\
                    attestation_id, target_kind, target_ids, attested_by, \
                    aggregate_evidence, attested_at, signature, signing_key_id, \
                    signature_verified, persist_row_hash\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)",
                params![
                    attestation_id,
                    target_kind_str(att.target_kind),
                    target_ids_json,
                    att.attested_by,
                    aggregate_evidence,
                    fmt_datetime(att.attested_at),
                    att.signature.ed25519,
                    att.attested_by,
                    att.signature.ed25519,
                ],
            )
            .map_err(|e| map_sqlite_error(e, "put_promotion_attestation"))?;
        Ok(())
    }

    async fn routable_contributors(
        &self,
        domain: &str,
        language: &str,
    ) -> Result<Vec<RoutableContributor>, Error> {
        let guard = self.conn.lock();
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
    }

    async fn read_vote_weight(
        &self,
        contributor_id: &str,
        domain: &str,
        language: &str,
        subject: &str,
    ) -> Result<Option<VoteWeight>, Error> {
        let (credits, expertise_row) = {
            let guard = self.conn.lock();
            let credits: Option<f64> = guard
                .query_row(
                    "SELECT balance FROM cirisnode_credits_ledger \
                     WHERE contributor_id = ?1 AND domain = ?2 \
                       AND language = ?3 AND subject = ?4",
                    params![contributor_id, domain, language, subject],
                    |row| row.get::<_, f64>(0),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "read_vote_weight credits"))?;
            let expertise_row: Option<(f64, bool)> = guard
                .query_row(
                    "SELECT expertise, is_active FROM cirisnode_expertise_ledger \
                     WHERE contributor_id = ?1 AND domain = ?2 AND language = ?3",
                    params![contributor_id, domain, language],
                    |row| Ok((row.get::<_, f64>(0)?, row.get::<_, bool>(1)?)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "read_vote_weight expertise"))?;
            (credits, expertise_row)
        };
        let credits = credits.unwrap_or(0.0);
        let (expertise, is_active) = expertise_row.unwrap_or((0.0, false));
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
        let raw = {
            let guard = self.conn.lock();
            guard
                .query_row(
                    "SELECT contributor_id, domain, language, subject, balance, \
                            last_update_contribution, last_updated_at, created_at, attestation_id \
                     FROM cirisnode_credits_ledger \
                     WHERE contributor_id = ?1 AND domain = ?2 \
                       AND language = ?3 AND subject = ?4",
                    params![contributor_id, domain, language, subject],
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
                            row.get::<_, Option<String>>(8)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "get_credits_ledger"))?
        };
        raw.map(|(c, d, l, s, balance, src, upd, created, id)| {
            Ok(CreditsLedgerEntry {
                contributor_id: c,
                domain: d,
                language: l,
                subject: s,
                balance,
                last_update_contribution: src,
                last_updated_at: parse_datetime(&upd)?,
                created_at: parse_datetime(&created)?,
                attestation_id: id,
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
        let raw = {
            let guard = self.conn.lock();
            guard
                .query_row(
                    "SELECT contributor_id, domain, language, expertise, is_active, \
                            last_updated_at, last_update_contribution, created_at, attestation_id \
                     FROM cirisnode_expertise_ledger \
                     WHERE contributor_id = ?1 AND domain = ?2 AND language = ?3",
                    params![contributor_id, domain, language],
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
                            row.get::<_, Option<String>>(8)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "get_expertise_ledger"))?
        };
        raw.map(|(c, d, l, expertise, is_active, upd, src, created, id)| {
            Ok(ExpertiseLedgerEntry {
                contributor_id: c,
                domain: d,
                language: l,
                expertise,
                is_active,
                last_updated_at: parse_datetime(&upd)?,
                last_update_contribution: src,
                created_at: parse_datetime(&created)?,
                attestation_id: id,
            })
        })
        .transpose()
    }

    async fn legacy_ledger_rows(&self) -> Result<Vec<LegacyLedgerRow>, Error> {
        let guard = self.conn.lock();
        let mut out = Vec::new();
        let mut stmt = guard
            .prepare(
                "SELECT contributor_id, domain, language, subject, balance, \
                        COALESCE(last_update_contribution, '') \
                 FROM cirisnode_credits_ledger WHERE attestation_id IS NULL \
                 ORDER BY contributor_id, domain, language, subject",
            )
            .map_err(|e| map_sqlite_error(e, "legacy credits prepare"))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(LegacyLedgerRow::Credits(CreditsUpdate {
                    contributor_id: r.get(0)?,
                    domain: r.get(1)?,
                    language: r.get(2)?,
                    subject: r.get(3)?,
                    new_balance: r.get(4)?,
                    source_contribution: r.get(5)?,
                }))
            })
            .map_err(|e| map_sqlite_error(e, "legacy credits"))?;
        for r in rows {
            out.push(r.map_err(|e| map_sqlite_error(e, "legacy credits row"))?);
        }
        let mut stmt = guard
            .prepare(
                "SELECT contributor_id, domain, language, expertise, is_active, \
                        COALESCE(last_update_contribution, '') \
                 FROM cirisnode_expertise_ledger WHERE attestation_id IS NULL \
                 ORDER BY contributor_id, domain, language",
            )
            .map_err(|e| map_sqlite_error(e, "legacy expertise prepare"))?;
        let rows = stmt
            .query_map([], |r| {
                Ok(LegacyLedgerRow::Expertise(ExpertiseUpdate {
                    contributor_id: r.get(0)?,
                    domain: r.get(1)?,
                    language: r.get(2)?,
                    new_expertise: r.get(3)?,
                    new_active_tier: r.get(4)?,
                    source_contribution: r.get(5)?,
                }))
            })
            .map_err(|e| map_sqlite_error(e, "legacy expertise"))?;
        for r in rows {
            out.push(r.map_err(|e| map_sqlite_error(e, "legacy expertise row"))?);
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
        let directory = self.directory();
        super::rows::check_announcement_held(&directory, &attestation.announcement_id).await?;
        let canonical = attestation
            .canonical_bytes()
            .map_err(|e| Error::Signature(format!("canonical_bytes: {e}")))?;
        crate::verify::verify_hybrid_via_directory(
            &directory,
            &canonical,
            &attestation.peer_key_id,
            &attestation.signature_classical_base64,
            attestation.signature_pqc_base64.as_deref(),
            // v37.0.0 — Strict, in lockstep with the postgres twin: a policy
            // that differed between backends would make the accepted set
            // depend on which backend the node was compiled with.
            crate::verify::hybrid::HybridPolicy::Strict,
            None,
        )
        .await
        .map_err(|e| Error::Signature(format!("delivery_attestation verify: {e}")))?;
        let persist_row_hash = crate::federation::types::compute_persist_row_hash(&attestation)
            .map_err(|e| Error::Internal(format!("persist_row_hash: {e}")))?;
        let guard = self.conn.lock();
        // `INSERT OR IGNORE` collapses the (announcement_id, peer_key_id) PK
        // conflict to a no-op — the idempotent replay path per FSD §3.2.1.
        guard
            .execute(
                "INSERT OR IGNORE INTO cirisnode_federation_delivery_attestations (\
                    announcement_id, announcement_canonical_hash, peer_key_id, \
                    peer_pubkey_ed25519_base64, received_at, transport_id, \
                    signature_classical, signature_pqc, signature_verified, persist_row_hash\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)",
                params![
                    attestation.announcement_id,
                    canonical_hash.as_slice(),
                    attestation.peer_key_id,
                    attestation.peer_pubkey_ed25519_base64,
                    fmt_datetime(attestation.received_at),
                    attestation.transport_id.as_str(),
                    sig_classical.as_slice(),
                    pqc_bytes,
                    persist_row_hash,
                ],
            )
            .map_err(|e| {
                if let rusqlite::Error::SqliteFailure(err, _) = &e {
                    if matches!(err.code, rusqlite::ErrorCode::ConstraintViolation) {
                        return Error::InvalidArgument(format!("put_delivery_attestation: {e}"));
                    }
                }
                Error::Backend(format!("put_delivery_attestation: {e}"))
            })?;
        Ok(())
    }

    async fn list_delivery_attestations(
        &self,
        announcement_id: &str,
    ) -> Result<Vec<DeliveryAttestation>, Error> {
        let rows = {
            let guard = self.conn.lock();
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
                .query_map([announcement_id], |row| {
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
            out.map_err(|e| map_sqlite_error(e, "list_delivery_attestations collect"))?
        };
        let mut out = Vec::with_capacity(rows.len());
        for (id, hash, peer, pubkey, received_at, transport, sig_c, sig_p) in rows {
            let canonical_hash: [u8; 32] = <[u8; 32]>::try_from(hash.as_slice())
                .map_err(|_| Error::Backend("stored canonical_hash not 32 bytes".to_string()))?;
            let transport_id = TransportMedium::from_wire_str(&transport).ok_or_else(|| {
                Error::Backend(format!("unknown transport_id from DB: {transport}"))
            })?;
            out.push(DeliveryAttestation {
                announcement_id: id,
                announcement_canonical_hash_base64:
                    super::federation_announcement::encode_canonical_hash_base64(&canonical_hash),
                peer_key_id: peer,
                peer_pubkey_ed25519_base64: pubkey,
                received_at: parse_datetime(&received_at)?,
                transport_id,
                signature_classical_base64: super::federation_announcement::encode_signature_base64(
                    &sig_c,
                ),
                signature_pqc_base64: sig_p
                    .map(|b| super::federation_announcement::encode_signature_base64(&b)),
            });
        }
        Ok(out)
    }

    async fn count_delivery_attestations(&self, announcement_id: &str) -> Result<u64, Error> {
        let guard = self.conn.lock();
        let n: i64 = guard
            .query_row(
                "SELECT COUNT(*) FROM cirisnode_federation_delivery_attestations \
                 WHERE announcement_id = ?1",
                [announcement_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|e| map_sqlite_error(e, "count_delivery_attestations"))?;
        Ok(u64::try_from(n).unwrap_or(0))
    }
}
