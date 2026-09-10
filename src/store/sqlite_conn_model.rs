//! **The SQLite connection model** (CIRISPersist#829) —
//! `FSD/SQLITE_CONNECTION_MODEL.md`.
//!
//! One writer connection (the `Arc<Mutex<Connection>>` `sqlite.rs` has
//! always had) plus a pool of `N` read-only connections under WAL, and every
//! call — read or write, and the *wait* for its connection — dispatched off
//! the tokio worker onto the blocking pool **when a runtime is current**,
//! inline otherwise. The "otherwise" is CIRISPersist#158's property, kept:
//! a cohabiting consumer's statically-linked copy of persist runs on a
//! foreign worker whose tokio thread-local is unset, and `spawn_blocking`
//! there panics where `Handle::try_current()` merely says no.
//!
//! The classification table ([`SQLITE_CONN_CLASSES`]) and the from-disk gate
//! that enforces it live in the test module below. The gate is a partition
//! in both directions over every production `fn` in `sqlite.rs` that touches
//! a connection: nothing may be unclassified, nothing filed as a `Read` may
//! reach the writer or a write verb, and no row may name an fn that no
//! longer exists. `SQLITE_OPEN_READ_ONLY` on every reader is the dynamic
//! net under the static one — a misfiled write fails loudly in the first
//! test that reaches it instead of writing on the wrong connection.

use std::sync::Arc;

use parking_lot::{Condvar, Mutex};
use rusqlite::{Connection, OpenFlags};

// ── the read pool ─────────────────────────────────────────────────────────

/// Environment override for the reader count consulted by
/// [`crate::store::sqlite::SqliteBackend::open`]. `0` is legal and means
/// "no pool": reads fall back to the writer mutex, still off the runtime.
/// It exists so an operator can A/B the pool without a rebuild and so a
/// defect in the pool has a one-line kill switch (FSD §3.2).
pub const READERS_ENV: &str = "CIRIS_PERSIST_SQLITE_READERS";

/// FSD §3.2 — `available_parallelism().clamp(2, 8)`, or [`READERS_ENV`].
pub fn default_reader_count() -> usize {
    if let Some(n) = std::env::var(READERS_ENV)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
    {
        return n;
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .clamp(2, 8)
}

/// `N` read-only connections to one SQLite file, handed out one at a time.
///
/// A free list under a `parking_lot::Mutex` plus a `Condvar`; `acquire`
/// blocks the calling thread until a connection is free, which is why it
/// is only ever called from inside [`dispatch_blocking`]'s closure. No
/// tokio primitive is involved so it works with no runtime on the thread.
///
/// `size() == 0` is the in-memory / borrowed-handle case (FSD §4): there is
/// nothing to acquire and the backend reads on its writer instead.
pub struct ReadPool {
    free: Mutex<Vec<Connection>>,
    available: Condvar,
    size: usize,
}

impl std::fmt::Debug for ReadPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadPool")
            .field("size", &self.size)
            .field("idle", &self.idle())
            .finish()
    }
}

impl ReadPool {
    /// A pool with no readers. Reads on a backend holding this pool go to
    /// the writer.
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            free: Mutex::new(Vec::new()),
            available: Condvar::new(),
            size: 0,
        })
    }

    /// Open `n` read-only connections to `path`. The writer MUST already
    /// be open and have set `journal_mode = WAL`: a read-only connection
    /// cannot change the journal mode, and a reader that opened first would
    /// find a rollback-journal database and hold every later writer to it.
    ///
    /// Per-connection PRAGMAs are re-applied here because they are
    /// per-connection state (`foreign_keys` is the one people forget);
    /// `query_only = ON` is a second fence behind `SQLITE_OPEN_READ_ONLY`.
    pub fn open(path: &str, n: usize) -> Result<Arc<Self>, rusqlite::Error> {
        let mut free = Vec::with_capacity(n);
        for _ in 0..n {
            let conn = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_URI,
            )?;
            conn.execute_batch(
                "PRAGMA foreign_keys = ON;\n\
                 PRAGMA busy_timeout = 30000;\n\
                 PRAGMA query_only = ON;",
            )?;
            free.push(conn);
        }
        Ok(Arc::new(Self {
            free: Mutex::new(free),
            available: Condvar::new(),
            size: n,
        }))
    }

    /// Number of reader connections this pool was opened with.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Readers not currently checked out. Diagnostic; racy by nature.
    pub fn idle(&self) -> usize {
        self.free.lock().len()
    }

    /// Check out a reader, blocking the calling thread until one is free.
    ///
    /// # Panics
    /// On an empty pool (`size() == 0`) — the backend never calls this on
    /// one, and a caller that does has mis-wired the fallback.
    pub fn acquire(&self) -> ReadGuard<'_> {
        assert!(self.size > 0, "ReadPool::acquire on an empty pool");
        let mut free = self.free.lock();
        while free.is_empty() {
            self.available.wait(&mut free);
        }
        let conn = free.pop().expect("non-empty after wait");
        ReadGuard {
            pool: self,
            conn: Some(conn),
        }
    }
}

/// A checked-out reader; returns itself to the pool on drop.
pub struct ReadGuard<'a> {
    pool: &'a ReadPool,
    conn: Option<Connection>,
}

impl std::ops::Deref for ReadGuard<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.conn.as_ref().expect("reader present until drop")
    }
}

impl Drop for ReadGuard<'_> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            // FSD §3.5 — a reader that goes back with a transaction open is
            // a reader pinning a WAL snapshot against every checkpoint. No
            // read closure opens one; this is the assertion that keeps it so.
            debug_assert!(
                conn.is_autocommit(),
                "a read closure returned its reader with a transaction open"
            );
            let mut free = self.pool.free.lock();
            free.push(conn);
            drop(free);
            self.pool.available.notify_one();
        }
    }
}

// ── the dispatcher ────────────────────────────────────────────────────────

/// Run `f` off the async runtime when there is one, inline when there is
/// not (FSD §3.3).
///
/// `Handle::try_current()` is the same thread-local read
/// `tokio::task::spawn_blocking` performs, but it returns `Err` where
/// `spawn_blocking` panics with `there is no reactor running`. That is the
/// whole of CIRISPersist#158's concern, answered: a cohabiting consumer's
/// statically-linked copy of persist on a foreign worker takes the inline
/// arm, exactly as v3.14.0 → v43.0.0 always did.
///
/// A panic inside `f` is re-raised on the caller (`resume_unwind`) so the
/// observable behaviour matches the inline arm. A join cancelled by runtime
/// shutdown has no value to return; it panics naming the cause, and the
/// caller's task is being torn down regardless.
pub async fn dispatch_blocking<R, F>(f: F) -> R
where
    R: Send + 'static,
    F: FnOnce() -> R + Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.spawn_blocking(f).await {
            Ok(r) => r,
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => panic!("sqlite blocking task cancelled by runtime shutdown: {e}"),
        },
        Err(_) => f(),
    }
}

// ── the classification table and its gate ─────────────────────────────────

/// Which connection a production `fn` in `sqlite.rs` is allowed to reach.
/// FSD/SQLITE_CONNECTION_MODEL.md §5.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnClass {
    /// `self.read(…)` only. Never the writer, never a write verb.
    Read,
    /// `self.write(…)`. May also `self.read(…)` for a non-atomic pre-check.
    Write,
    /// Free fn taking `&Connection`, called from inside a closure; no write
    /// verb in its body.
    HelperRead,
    /// Free fn taking a connection or transaction that writes. May only be
    /// called from a `Write` body.
    HelperWrite,
    /// The two doors and the two handle accessors — `read`, `write`,
    /// `conn_handle`, `read_pool_handle`. They hand out or dispatch on a
    /// connection rather than use one; the gate pins the set by name.
    Door,
}

/// **The table.** Every production `fn` in `src/store/sqlite.rs` that touches
/// a connection, by name, with its class. Keyed by name: where a name occurs
/// twice (`lookup_public_key`, `list_attestations_for`) every occurrence
/// must carry the same class, and the gate checks each occurrence.
///
/// Filed by what the body does, not what the name says (§5): `has_blob`,
/// `get_blob` and `get_blob_range` bump `access_count` inside a transaction
/// and are `Write`.
#[cfg(test)]
pub(crate) const SQLITE_CONN_CLASSES: &[(&str, ConnClass)] = &[
    ("accord_nonce_issued", ConnClass::Read),
    ("add_community_member", ConnClass::Write),
    ("add_family_member", ConnClass::Write),
    ("add_peer_record", ConnClass::Write),
    ("adopt_genesis_reanchor", ConnClass::Write),
    ("adopt_scrub_upgrade", ConnClass::Write),
    ("aggregate_audit_chain", ConnClass::Read),
    ("aggregate_llm_costs", ConnClass::Read),
    ("aggregate_scoring_factors_rollup_batch", ConnClass::Read),
    ("aggregate_scoring_factors_uncached", ConnClass::Read),
    ("aggregate_scrub_stats", ConnClass::Read),
    ("attach_attestation_pqc_signature", ConnClass::Write),
    ("attach_key_pqc_signature", ConnClass::Write),
    ("attach_revocation_pqc_signature", ConnClass::Write),
    ("attestations_binding_content", ConnClass::Read),
    ("backfill_trace_dedup_shard_keys", ConnClass::Write),
    ("blackhole_list", ConnClass::Read),
    ("blackhole_prune_expired", ConnClass::Write),
    ("blackhole_record_hit", ConnClass::Write),
    ("blackhole_remove", ConnClass::Write),
    ("blackhole_upsert", ConnClass::Write),
    ("blob_cohort_scope", ConnClass::Read),
    ("blob_crypto_tier", ConnClass::Read),
    ("cancel_outbound", ConnClass::Write),
    ("check_revocation_anti_rollback_sqlite", ConnClass::Read),
    ("claim_pending_outbound", ConnClass::Write),
    ("clear_active_halt", ConnClass::Write),
    ("communities_containing", ConnClass::Read),
    ("community_dek_bind_blob_epoch", ConnClass::Write),
    ("community_dek_blob_epoch", ConnClass::Read),
    ("community_dek_bump_epoch", ConnClass::Write),
    ("community_dek_communities", ConnClass::Read),
    ("community_dek_current_epoch", ConnClass::Read),
    ("community_dek_epoch_object_count", ConnClass::Read),
    ("community_dek_epochs", ConnClass::Read),
    ("community_dek_evict_epoch_objects", ConnClass::Write),
    ("community_dek_get_self_retention", ConnClass::Read),
    ("community_dek_has_member_grant", ConnClass::Read),
    ("community_dek_key_state", ConnClass::Read),
    ("community_dek_member_grant_recipients", ConnClass::Read),
    ("community_dek_put_member_grant", ConnClass::Write),
    ("community_dek_put_self_retention", ConnClass::Write),
    ("community_dek_retain_past_epochs", ConnClass::Read),
    ("community_dek_set_key_state", ConnClass::Write),
    ("community_dek_set_retain_past_epochs", ConnClass::Write),
    ("conn_handle", ConnClass::Door),
    ("conscience_override_rates", ConnClass::Read),
    ("corpus_shape", ConnClass::Read),
    ("count_identity_changes", ConnClass::Read),
    ("count_overrides", ConnClass::Read),
    ("count_traces", ConnClass::Read),
    ("cross_agent_divergence", ConnClass::Read),
    ("delete_blob", ConnClass::Write),
    ("delete_traces_for_agent", ConnClass::Write),
    ("delete_traces_for_agent_id_hash", ConnClass::Write),
    ("enqueue_outbound", ConnClass::Write),
    ("enter_mesh", ConnClass::Write),
    ("evict_fountain_content_hard_delete", ConnClass::Write),
    ("evict_fountain_content_to_tier", ConnClass::Write),
    ("evict_known_wire_hashes", ConnClass::Write),
    ("evict_scope_blobs", ConnClass::Write),
    ("factor_rollup_present", ConnClass::Read),
    ("fetch_trace_events_page", ConnClass::Read),
    ("fountain_manifest_row", ConnClass::Read),
    ("get_accord_decision", ConnClass::Read),
    ("get_accord_proposal", ConnClass::Read),
    ("get_active_halt", ConnClass::Read),
    ("get_aggregation", ConnClass::Read),
    ("get_at_rest_grant", ConnClass::Read),
    ("get_attestation", ConnClass::Read),
    ("get_blob", ConnClass::Write),
    ("get_blob_range", ConnClass::Write),
    ("get_calibration_bundle_by_version", ConnClass::Read),
    ("get_current_calibration_bundle", ConnClass::Read),
    ("get_detection_events", ConnClass::Read),
    ("get_edge_detection_events", ConnClass::Read),
    ("get_fountain_content", ConnClass::Read),
    ("get_goal", ConnClass::Read),
    ("get_installed_storage_budget", ConnClass::Read),
    ("get_repository_statistics", ConnClass::Read),
    ("get_scope_blob", ConnClass::Write),
    ("get_trace_detail", ConnClass::Read),
    ("get_trace_summary", ConnClass::Read),
    ("grant_trust", ConnClass::Write),
    ("has_blob", ConnClass::Write),
    ("hash_chain_gaps", ConnClass::Read),
    ("heartbeat_shared_instance", ConnClass::Write),
    ("index_stored_record", ConnClass::Write),
    ("insert_known_wire_hash", ConnClass::Write),
    ("insert_trace_events_batch", ConnClass::Write),
    ("insert_trace_llm_calls_batch", ConnClass::Write),
    ("issue_accord_nonce", ConnClass::Write),
    ("known_wire_hash_contains", ConnClass::Read),
    ("last_witness_epoch_for_peer", ConnClass::Read),
    ("latest_stream_sth", ConnClass::Read),
    ("list_accord_participations", ConnClass::Read),
    ("list_accord_proposals_by_anchor", ConnClass::Read),
    ("list_accord_proposals_by_payload", ConnClass::Read),
    ("list_aggregations_at_level", ConnClass::Read),
    ("list_all_transport_destinations", ConnClass::Read),
    ("list_announced_peers", ConnClass::Read),
    ("list_at_rest_blobs_for_recipients", ConnClass::Read),
    ("list_at_rest_grant_recipients", ConnClass::Read),
    ("list_attestation_log", ConnClass::Read),
    ("list_attestations", ConnClass::Read),
    ("list_attestations_by", ConnClass::Read),
    ("list_attestations_for", ConnClass::Read),
    ("list_attestations_for_migration", ConnClass::Read),
    ("list_attestations_since", ConnClass::Read),
    ("list_canonical_servers", ConnClass::Read),
    ("list_canonical_withdrawals", ConnClass::Read),
    ("list_communities_for_member", ConnClass::Read),
    ("list_community_membership_revocations_for", ConnClass::Read),
    ("list_consent_peers", ConnClass::Read),
    ("list_consent_revocations", ConnClass::Read),
    ("list_delivery_receipts_for", ConnClass::Read),
    ("list_expired_attestation_ids", ConnClass::Read),
    ("list_families_for_member", ConnClass::Read),
    ("list_family_membership_revocations_for", ConnClass::Read),
    ("list_federation_keys", ConnClass::Read),
    ("list_fountain_decay_candidates", ConnClass::Read),
    ("list_goals", ConnClass::Read),
    ("list_group_versions", ConnClass::Read),
    ("list_hard_case_events", ConnClass::Read),
    ("list_held_by", ConnClass::Read),
    ("list_held_fountain_content", ConnClass::Read),
    ("list_holders", ConnClass::Read),
    ("list_hybrid_pending_attestations", ConnClass::Read),
    ("list_hybrid_pending_keys", ConnClass::Read),
    ("list_hybrid_pending_revocations", ConnClass::Read),
    ("list_identity_occurrence_revocations_for", ConnClass::Read),
    ("list_identity_occurrences_for", ConnClass::Read),
    ("list_installed_storage_budgets", ConnClass::Read),
    ("list_keys_by_identity_type", ConnClass::Read),
    ("list_known_wire_hashes_since", ConnClass::Read),
    ("list_live_consent_grants_by", ConnClass::Read),
    ("list_llm_calls", ConnClass::Read),
    ("list_local_holders", ConnClass::Read),
    ("list_local_tier_attestations", ConnClass::Read),
    ("list_location_proofs_for", ConnClass::Read),
    ("list_org_memberships_for", ConnClass::Read),
    ("list_org_memberships_since", ConnClass::Read),
    ("list_organizations_for", ConnClass::Read),
    ("list_organizations_since", ConnClass::Read),
    ("list_outbound", ConnClass::Read),
    ("list_partner_records_for", ConnClass::Read),
    ("list_partner_records_since", ConnClass::Read),
    ("list_revocations", ConnClass::Read),
    ("list_scope_blob_symbols", ConnClass::Write),
    ("list_scores", ConnClass::Read),
    ("list_signed_accord_quorum_evidence_since", ConnClass::Read),
    ("list_signed_communities_since", ConnClass::Read),
    (
        "list_signed_community_membership_revocations_since",
        ConnClass::Read,
    ),
    ("list_signed_families_since", ConnClass::Read),
    (
        "list_signed_family_membership_revocations_since",
        ConnClass::Read,
    ),
    (
        "list_signed_identity_occurrence_revocations_for",
        ConnClass::Read,
    ),
    (
        "list_signed_identity_occurrence_revocations_since",
        ConnClass::Read,
    ),
    ("list_signed_identity_occurrences_for", ConnClass::Read),
    ("list_signed_identity_occurrences_since", ConnClass::Read),
    ("list_signed_key_records_since", ConnClass::Read),
    ("list_signed_location_proofs_since", ConnClass::Read),
    ("list_signed_partner_records_since", ConnClass::Read),
    ("list_signed_revocations_since", ConnClass::Read),
    ("list_signed_transport_destinations_for", ConnClass::Read),
    ("list_signed_transport_destinations_since", ConnClass::Read),
    ("list_tasks", ConnClass::Read),
    ("list_trace_summaries", ConnClass::Read),
    (
        "list_transport_destinations_by_destination",
        ConnClass::Read,
    ),
    ("list_transport_destinations_for", ConnClass::Read),
    ("list_trusted_keys", ConnClass::Read),
    ("list_wholeness_witnesses_for_peer", ConnClass::Read),
    ("list_widening_candidates", ConnClass::Read),
    ("list_wire_hashes_since", ConnClass::Read),
    ("list_witness_peer_ids", ConnClass::Read),
    ("load_or_init_content_kem_identity", ConnClass::Write),
    ("load_or_init_content_master", ConnClass::Write),
    ("lookup_canonical_withdrawal", ConnClass::Read),
    ("lookup_community", ConnClass::Read),
    ("lookup_family", ConnClass::Read),
    ("lookup_freshness_floor", ConnClass::Read),
    ("lookup_identity_for_occurrence", ConnClass::Read),
    ("lookup_keys_for_identity", ConnClass::Read),
    ("lookup_public_key", ConnClass::Read),
    ("lookup_role_withdrawal", ConnClass::Read),
    ("lookup_shared_instance_lease", ConnClass::Read),
    ("lookup_signed_record_by_content_hash", ConnClass::Read),
    ("lookup_trust", ConnClass::Read),
    ("mark_ack_received", ConnClass::Write),
    ("mark_replay_resolved", ConnClass::Write),
    ("mark_transport_delivered", ConnClass::Write),
    ("mark_transport_failed", ConnClass::Write),
    ("match_ack_to_outbound", ConnClass::Read),
    ("next_key_admission_position", ConnClass::Read),
    ("outbound_status", ConnClass::Read),
    ("peer_metadata_for", ConnClass::Read),
    ("pinned_blob_bytes", ConnClass::Read),
    ("purge_attestation_projections", ConnClass::Write),
    ("purge_attestation_v31", ConnClass::Write),
    ("purge_genesis_delegation_row_v31", ConnClass::Write),
    ("put_accord_decision", ConnClass::Write),
    ("put_accord_participation", ConnClass::Write),
    ("put_accord_proposal", ConnClass::Write),
    ("put_aggregated_tier", ConnClass::Write),
    ("put_at_rest_grant", ConnClass::Write),
    ("put_attestation_with_origin", ConnClass::Write),
    ("put_blob_chunk", ConnClass::Write),
    ("put_blob_chunks", ConnClass::Write),
    ("put_blob_with_scope", ConnClass::Write),
    ("put_calibration_bundle", ConnClass::Write),
    ("put_community", ConnClass::Write),
    ("put_community_membership_revocation", ConnClass::Write),
    ("put_delivery_receipt", ConnClass::Write),
    ("put_detection_event", ConnClass::Write),
    ("put_edge_detection_event", ConnClass::Write),
    ("put_family", ConnClass::Write),
    ("put_family_local", ConnClass::Write),
    ("put_family_membership_revocation", ConnClass::Write),
    ("put_fountain_content", ConnClass::Write),
    ("put_goal", ConnClass::Write),
    ("put_identity_occurrence", ConnClass::Write),
    ("put_identity_occurrence_local", ConnClass::Write),
    ("put_identity_occurrence_revocation", ConnClass::Write),
    ("put_identity_occurrence_revocation_local", ConnClass::Write),
    ("put_installed_storage_budget", ConnClass::Write),
    ("put_location_proof", ConnClass::Write),
    ("put_org_membership", ConnClass::Write),
    ("put_organization", ConnClass::Write),
    ("put_partner_record", ConnClass::Write),
    ("put_public_key", ConnClass::Write),
    ("put_revocation", ConnClass::Write),
    ("put_scope_blob", ConnClass::Write),
    ("put_signed_transport_destination", ConnClass::Write),
    ("put_stream_sth", ConnClass::Write),
    ("put_touch_claim", ConnClass::Write),
    ("put_transport_destination", ConnClass::Write),
    ("put_wholeness_witness", ConnClass::Write),
    ("read", ConnClass::Door),
    ("read_classifications", ConnClass::Read),
    ("read_features", ConnClass::Read),
    ("read_pool_handle", ConnClass::Door),
    ("rebuild_signed_wire_index", ConnClass::Write),
    ("record_announced_peer", ConnClass::Write),
    ("record_canonical_withdrawal", ConnClass::Write),
    ("record_hard_case", ConnClass::Write),
    ("record_role_withdrawal", ConnClass::Write),
    ("refresh_factor_rollup", ConnClass::Write),
    ("register_accord_public_key", ConnClass::Write),
    ("release_shared_instance_lease", ConnClass::Write),
    ("remove_peer_record", ConnClass::Write),
    ("remove_transport_destination", ConnClass::Write),
    ("replay_abandoned", ConnClass::Write),
    ("reseal_attestation_v31", ConnClass::Write),
    ("resolve_scores", ConnClass::Read),
    ("retire_goal", ConnClass::Write),
    ("revocations_for", ConnClass::Read),
    ("revoke_trust", ConnClass::Write),
    ("run_migrations", ConnClass::Write),
    ("run_migrations_through", ConnClass::Write),
    ("sample_public_keys", ConnClass::Read),
    ("scoring_ingest_watermark_ms", ConnClass::Read),
    ("seal_stream", ConnClass::Write),
    ("seed_genesis_accord_holders", ConnClass::Write),
    ("set_active_halt", ConnClass::Write),
    ("set_consent_role", ConnClass::Write),
    ("sqlite_load_stream_chunk_hashes", ConnClass::HelperRead),
    ("sqlite_next_key_serve_position", ConnClass::HelperRead),
    ("sqlite_next_plane_position", ConnClass::HelperRead),
    (
        "sqlite_project_attestation_subjects",
        ConnClass::HelperWrite,
    ),
    ("sqlite_project_consent_peer_set", ConnClass::HelperWrite),
    ("sqlite_update_peer_field", ConnClass::Write),
    ("sqlite_upsert_wire_index", ConnClass::HelperWrite),
    ("sqlite_write_local_attestation", ConnClass::Write),
    ("store_blob_local", ConnClass::Write),
    ("stream_consistency_proof", ConnClass::Read),
    ("stream_inclusion_proof", ConnClass::Read),
    ("supersede_canonical_record", ConnClass::Write),
    ("supersede_group_row", ConnClass::Write),
    ("sweep_ack_timeouts", ConnClass::Write),
    ("sweep_candidates", ConnClass::Read),
    ("sweep_expired_claims", ConnClass::Write),
    ("sweep_ttl_expired", ConnClass::Write),
    ("temporal_drift", ConnClass::Read),
    ("try_acquire_shared_instance", ConnClass::Write),
    ("write", ConnClass::Door),
    ("write_classifications", ConnClass::Write),
    ("write_features", ConnClass::Write),
];

#[cfg(test)]
mod gate {
    use super::{ConnClass, SQLITE_CONN_CLASSES};
    use std::collections::{BTreeMap, BTreeSet};

    fn sqlite_rs() -> String {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/store/sqlite.rs");
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    }

    /// The production text: everything before the first column-0
    /// `#[cfg(test)]`. `sqlite.rs` keeps every test module at the end of the
    /// file, and the parser floor below (`PARSER_FLOOR`) is what stops this
    /// cut from ever returning an empty universe and passing vacuously.
    fn production_text(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for line in text.lines() {
            if line.starts_with("#[cfg(test)]") {
                break;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// One production `fn`: name, 1-based first line, indent, and body text
    /// with `//` comment lines removed.
    #[derive(Debug)]
    pub(super) struct Func {
        pub name: String,
        pub line: usize,
        /// 1-based last line of the body.
        pub end: usize,
        pub indent: usize,
        /// Body text with `//` comment lines removed.
        pub body: String,
        /// `body` with ALL whitespace removed. rustfmt splits `self.read(`
        /// into `self\n.read(` in a chained expression, so every token that
        /// names a door or a connection is matched against this, never
        /// against `body`.
        pub squashed: String,
    }

    fn fn_header(line: &str) -> Option<(usize, String)> {
        let indent = line.len() - line.trim_start().len();
        let mut t = line.trim_start();
        for prefix in ["pub(crate) ", "pub(super) ", "pub "] {
            if let Some(rest) = t.strip_prefix(prefix) {
                t = rest;
            }
        }
        if let Some(rest) = t.strip_prefix("async ") {
            t = rest;
        }
        let rest = t.strip_prefix("fn ")?;
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        (!name.is_empty()).then_some((indent, name))
    }

    /// Every production fn with a body, in source order.
    pub(super) fn functions(prod: &str) -> Vec<Func> {
        let lines: Vec<&str> = prod.lines().collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let Some((indent, name)) = fn_header(lines[i]) else {
                i += 1;
                continue;
            };
            // Signature ends on the first line ending in `{`; a line ending
            // in `;` first means a bodiless declaration.
            let mut j = i;
            let mut body_start = None;
            while j < lines.len() {
                let l = lines[j].trim_end();
                if l.ends_with('{') {
                    body_start = Some(j);
                    break;
                }
                if l.ends_with(';') {
                    break;
                }
                j += 1;
            }
            let Some(bs) = body_start else {
                i += 1;
                continue;
            };
            let mut depth: i64 = 0;
            let mut k = bs;
            while k < lines.len() {
                depth +=
                    lines[k].matches('{').count() as i64 - lines[k].matches('}').count() as i64;
                if depth <= 0 {
                    break;
                }
                k += 1;
            }
            let body: String = lines[i..=k.min(lines.len() - 1)]
                .iter()
                .filter(|l| !l.trim_start().starts_with("//"))
                .map(|l| format!("{l}\n"))
                .collect();
            let squashed = squash(&body);
            out.push(Func {
                name,
                line: i + 1,
                end: k.min(lines.len() - 1) + 1,
                indent,
                body,
                squashed,
            });
            i = k + 1;
        }
        out
    }

    /// The tokens by which a body reaches a connection at all.
    const TOUCH: &[&str] = &[
        "self.conn",
        "conn.lock()",
        "conn_handle()",
        "conn: &Connection",
        "conn: &mut Connection",
        "conn: &rusqlite::Connection",
        "conn: &mut rusqlite::Connection",
        "Arc<Mutex<Connection>>",
        "tx: &Transaction",
        "tx: &rusqlite::Transaction",
        "self.read(",
        "self.write(",
        "backend.read(",
        "backend.write(",
        "self.readers",
    ];

    /// The read door, as a body reaches it (methods say `self`, the two
    /// free async fns that take the backend say `backend`).
    const DOOR_READ: &[&str] = &["self.read(", "backend.read("];
    /// The write door, likewise.
    const DOOR_WRITE: &[&str] = &["self.write(", "backend.write("];
    /// The fixed set of `Door`-class fns (FSD §5).
    const DOORS: &[&str] = &["read", "write", "conn_handle", "read_pool_handle"];

    /// The tokens that mean "this body writes". Case-sensitive on purpose:
    /// the SQL in this file is upper-case, the enum values that share a
    /// spelling (`'deletes'`, `'update'`) are not.
    const WRITE_VERBS: &[&str] = &[
        "INSERT ",
        "UPDATE ",
        "DELETE ",
        "REPLACE ",
        "CREATE ",
        "DROP ",
        "ALTER ",
        "VACUUM",
        ".execute(",
        ".transaction(",
        "execute_batch(",
        "unchecked_transaction(",
        "BEGIN",
        "COMMIT",
    ];

    /// The writer path, which a `Read` may never mention.
    const WRITER_TOKENS: &[&str] = &[
        "self.conn",
        "conn.lock()",
        "conn_handle()",
        "self.write(",
        "backend.write(",
    ];

    /// Remove all whitespace, so a token matches however rustfmt wrapped it.
    pub(super) fn squash(s: &str) -> String {
        s.split_whitespace().collect()
    }

    pub(super) fn touches_connection(squashed: &str) -> bool {
        TOUCH.iter().any(|t| squashed.contains(&squash(t)))
    }

    pub(super) fn write_verb_in(body: &str) -> Option<&'static str> {
        WRITE_VERBS.iter().copied().find(|v| body.contains(v))
    }

    /// Parser floor. `sqlite.rs` had 404 production fns and 285 that touch a
    /// connection when this gate was written; a parser that finds far fewer
    /// has broken, and a broken parser must red the build rather than
    /// report an empty universe as "all classified".
    const PARSER_FLOOR: (usize, usize) = (350, 250);

    pub(super) fn universe() -> Vec<Func> {
        let prod = production_text(&sqlite_rs());
        let all = functions(&prod);
        assert!(
            all.len() >= PARSER_FLOOR.0,
            "parser floor: found only {} production fns in sqlite.rs (floor {})",
            all.len(),
            PARSER_FLOOR.0
        );
        let touching: Vec<Func> = all
            .into_iter()
            .filter(|f| touches_connection(&f.squashed))
            .collect();
        assert!(
            touching.len() >= PARSER_FLOOR.1,
            "parser floor: found only {} connection-touching fns (floor {})",
            touching.len(),
            PARSER_FLOOR.1
        );
        touching
    }

    fn table() -> BTreeMap<&'static str, ConnClass> {
        let mut m = BTreeMap::new();
        for (name, class) in SQLITE_CONN_CLASSES {
            assert!(
                m.insert(*name, *class).is_none(),
                "SQLITE_CONN_CLASSES lists `{name}` twice"
            );
        }
        m
    }

    // ── I4: the partition, both directions ──────────────────────────────

    #[test]
    fn every_connection_touching_fn_in_sqlite_rs_is_classified() {
        let table = table();
        let missing: Vec<String> = universe()
            .iter()
            .filter(|f| !table.contains_key(f.name.as_str()))
            .map(|f| format!("  sqlite.rs:{} {}", f.line, f.name))
            .collect();
        assert!(
            missing.is_empty(),
            "{} production fn(s) in sqlite.rs touch a connection and are not in \
             SQLITE_CONN_CLASSES (FSD/SQLITE_CONNECTION_MODEL.md §5):\n{}",
            missing.len(),
            missing.join("\n")
        );
    }

    #[test]
    fn no_conn_class_row_is_stale() {
        let names: BTreeSet<String> = universe().into_iter().map(|f| f.name).collect();
        let stale: Vec<&str> = SQLITE_CONN_CLASSES
            .iter()
            .map(|(n, _)| *n)
            .filter(|n| !names.contains(*n))
            .collect();
        assert!(
            stale.is_empty(),
            "SQLITE_CONN_CLASSES names fn(s) that no longer touch a connection in \
             sqlite.rs (delete the row or re-file it): {stale:?}"
        );
    }

    #[test]
    fn every_read_is_on_the_reader_path_and_writes_nothing() {
        let table = table();
        let helper_writes: Vec<&str> = SQLITE_CONN_CLASSES
            .iter()
            .filter(|(_, c)| *c == ConnClass::HelperWrite)
            .map(|(n, _)| *n)
            .collect();
        let mut bad = Vec::new();
        for f in universe() {
            if table.get(f.name.as_str()) != Some(&ConnClass::Read) {
                continue;
            }
            if !DOOR_READ.iter().any(|d| f.squashed.contains(d)) {
                bad.push(format!(
                    "  {}:{} does not use the read door",
                    f.name, f.line
                ));
            }
            for t in WRITER_TOKENS {
                if f.squashed.contains(&squash(t)) {
                    bad.push(format!(
                        "  {}:{} reaches the writer via `{t}`",
                        f.name, f.line
                    ));
                }
            }
            if let Some(v) = write_verb_in(&f.body) {
                bad.push(format!(
                    "  {}:{} contains write verb `{}`",
                    f.name,
                    f.line,
                    v.trim()
                ));
            }
            for h in &helper_writes {
                if f.squashed.contains(&format!("{h}(")) {
                    bad.push(format!("  {}:{} calls HelperWrite `{h}`", f.name, f.line));
                }
            }
        }
        assert!(
            bad.is_empty(),
            "{} Read-classified fn(s) in sqlite.rs are not pure reads on the reader path:\n{}",
            bad.len(),
            bad.join("\n")
        );
    }

    #[test]
    fn every_write_is_on_the_writer_path_and_helpers_are_what_they_say() {
        let table = table();
        let mut bad = Vec::new();
        for f in universe() {
            match table.get(f.name.as_str()) {
                Some(ConnClass::Write) => {
                    if !DOOR_WRITE.iter().any(|d| f.squashed.contains(d)) {
                        bad.push(format!(
                            "  Write {}:{} does not use the write door",
                            f.name, f.line
                        ));
                    }
                }
                Some(ConnClass::Door) => {
                    if !DOORS.contains(&f.name.as_str()) {
                        bad.push(format!(
                            "  Door {}:{} is not one of {DOORS:?}",
                            f.name, f.line
                        ));
                    }
                }
                Some(ConnClass::HelperRead) => {
                    if f.indent != 0 {
                        bad.push(format!(
                            "  HelperRead {}:{} is not a free fn",
                            f.name, f.line
                        ));
                    }
                    if let Some(v) = write_verb_in(&f.body) {
                        bad.push(format!(
                            "  HelperRead {}:{} contains write verb `{}`",
                            f.name,
                            f.line,
                            v.trim()
                        ));
                    }
                }
                Some(ConnClass::HelperWrite) if f.indent != 0 => {
                    bad.push(format!(
                        "  HelperWrite {}:{} is not a free fn",
                        f.name, f.line
                    ));
                }
                _ => {}
            }
        }
        assert!(bad.is_empty(), "{}", bad.join("\n"));
    }

    /// The four classes are the whole alphabet; the table may use nothing
    /// else, and a class nobody files under is a class the gate does not
    /// exercise — this is the row that says so out loud.
    #[test]
    fn the_class_alphabet_is_the_four_documented_classes() {
        const ALL: [ConnClass; 5] = [
            ConnClass::Read,
            ConnClass::Write,
            ConnClass::HelperRead,
            ConnClass::HelperWrite,
            ConnClass::Door,
        ];
        for (name, class) in SQLITE_CONN_CLASSES {
            assert!(
                ALL.contains(class),
                "`{name}` filed under unknown class {class:?}"
            );
        }
    }

    /// The only door to a connection is the dispatcher: no production line
    /// in `sqlite.rs` locks the writer directly. The handle accessors
    /// (`conn_handle`, `from_conn_handle`) clone the `Arc`; they never lock.
    #[test]
    fn no_production_line_in_sqlite_rs_locks_a_connection_directly() {
        let prod = production_text(&sqlite_rs());
        // The two doors are the only places allowed to lock: `read`'s
        // zero-reader fallback and `write`. Their line ranges are exempt;
        // everything else that locks is a bypass.
        let doors: Vec<(usize, usize)> = functions(&prod)
            .into_iter()
            .filter(|f| f.indent == 4 && (f.name == "read" || f.name == "write"))
            .map(|f| (f.line, f.end))
            .collect();
        assert_eq!(
            doors.len(),
            2,
            "expected exactly the read and write doors, found {doors:?}"
        );
        let hits: Vec<String> = prod
            .lines()
            .enumerate()
            .filter(|(i, _)| !doors.iter().any(|(a, b)| (a..=b).contains(&&(i + 1))))
            .filter(|(_, l)| !l.trim_start().starts_with("//"))
            .filter(|(_, l)| l.contains("conn.lock()") || l.contains("conn_handle().lock()"))
            .map(|(i, l)| format!("  sqlite.rs:{} {}", i + 1, l.trim()))
            .collect();
        assert!(
            hits.is_empty(),
            "{} production line(s) in sqlite.rs lock a connection directly instead of \
             going through SqliteBackend::read / ::write:\n{}",
            hits.len(),
            hits.join("\n")
        );
    }
}

// ── the behavioural witnesses ─────────────────────────────────────────────

#[cfg(test)]
mod witnesses {
    use crate::federation::FederationDirectory;
    use crate::store::backend::Backend;
    use crate::store::sqlite::SqliteBackend;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    pub(super) fn temp_db_path(tag: &str) -> String {
        let dir = std::env::temp_dir().join(format!("ciris-829-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("store.db").to_string_lossy().into_owned()
    }

    /// Hold the WRITER mutex from a plain thread for `hold`, signalling once
    /// it is held. This is the CIRISEdge#547 shape: the connection holder is
    /// off in a page fault and everyone else is behind it.
    fn hold_writer(backend: &SqliteBackend, hold: Duration) -> std::thread::JoinHandle<()> {
        let writer = backend.conn_handle();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let h = std::thread::spawn(move || {
            let guard = writer.lock();
            tx.send(()).unwrap();
            std::thread::sleep(hold);
            drop(guard);
        });
        rx.recv().unwrap();
        h
    }

    async fn point_read(backend: &SqliteBackend) {
        let got = FederationDirectory::get_attestation(backend, "absent-829")
            .await
            .expect("point read");
        assert!(got.is_none());
    }

    // ── I2 ─────────────────────────────────────────────────────────────
    /// With the writer connection held for 2 s, a read completes in well
    /// under that. Before #829 the read is the same connection, so it takes
    /// the full 2 s (and blocks its worker for all of it).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn read_completes_while_the_writer_connection_is_held() {
        let path = temp_db_path("held-writer");
        let backend = SqliteBackend::open(&path).await.unwrap();
        backend.run_migrations().await.unwrap();

        let holder = hold_writer(&backend, Duration::from_secs(2));
        let t0 = Instant::now();
        point_read(&backend).await;
        let took = t0.elapsed();
        holder.join().unwrap();
        assert!(
            took < Duration::from_millis(750),
            "a read waited {took:?} behind the held writer connection — the read pool is \
             not serving reads (FSD/SQLITE_CONNECTION_MODEL.md I2)"
        );
    }

    // ── I3 (zero-reader arm) ───────────────────────────────────────────
    /// One worker thread. A read that must WAIT for the writer (in-memory
    /// has no readers, so this is the fallback arm) must not stall the
    /// runtime: a 10 ms sleep spawned alongside it fires within 250 ms.
    /// Before #829 the wait is a `parking_lot` lock on the only worker, and
    /// the timer cannot be polled until the read returns ~1 s later.
    #[test]
    fn runtime_keeps_spinning_while_an_in_memory_read_waits_on_the_writer() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let backend = Arc::new(SqliteBackend::open_in_memory().await.unwrap());
            backend.run_migrations().await.unwrap();
            let holder = hold_writer(&backend, Duration::from_secs(1));

            let t0 = Instant::now();
            let read = tokio::spawn({
                let b = backend.clone();
                async move {
                    point_read(&b).await;
                    t0.elapsed()
                }
            });
            let tick = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                t0.elapsed()
            });
            let fired = tick.await.unwrap();
            let read_took = read.await.unwrap();
            holder.join().unwrap();
            assert!(
                read_took >= Duration::from_millis(900),
                "premise: the read was supposed to wait behind the held writer, took {read_took:?}"
            );
            assert!(
                fired < Duration::from_millis(250),
                "a 10 ms sleep fired after {fired:?} — the read's wait for the connection \
                 stalled the runtime's only worker (FSD/SQLITE_CONNECTION_MODEL.md I3)"
            );
        });
    }

    // ── I5 (#158 preserved) ────────────────────────────────────────────
    /// A read and a write driven with NO tokio runtime on the thread both
    /// complete. This is the property v3.14.0 bought by going inline, and it
    /// must survive the dispatcher: `Handle::try_current()` says no, the
    /// call runs inline.
    fn block_on_without_a_runtime<F: std::future::Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn noop_raw() -> RawWaker {
            fn clone(_: *const ()) -> RawWaker {
                noop_raw()
            }
            fn noop(_: *const ()) {}
            static VT: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
            RawWaker::new(std::ptr::null(), &VT)
        }
        // SAFETY: the vtable functions are all no-ops over a null data
        // pointer; nothing is dereferenced.
        #[allow(unsafe_code)]
        let waker = unsafe { Waker::from_raw(noop_raw()) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = std::pin::pin!(fut);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn sqlite_path_runs_with_no_tokio_runtime_on_the_thread() {
        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "premise: this test must run with no runtime current"
        );
        let path = temp_db_path("no-runtime");
        block_on_without_a_runtime(async {
            let backend = SqliteBackend::open(&path).await.unwrap();
            backend.run_migrations().await.unwrap();
            point_read(&backend).await;
            // A write, too — the dispatcher is one function for both.
            let lease = FederationDirectory::try_acquire_shared_instance(
                &backend,
                "reticulum:829",
                std::process::id() as i32,
                "no-runtime-host",
                None,
            )
            .await
            .expect("write with no runtime");
            assert!(lease.is_some(), "first acquire wins");
        });
    }
}
