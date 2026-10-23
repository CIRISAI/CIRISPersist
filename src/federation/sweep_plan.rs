//! v60.0.0 (CIRISPersist#934 step 4) — **the sweeps' selections, decided
//! once.**
//!
//! A sweep is two halves: WHICH rows go (the selection) and the statement
//! that removes or reads them (the delete). Before v60 each backend wrote
//! both, so the selection lived in three places in two languages, and the
//! copies drifted:
//!
//! - the PQC sweep's selection (`list_hybrid_pending_keys` /
//!   `_attestations`, the rows the cold-path PQC fill walks): a negative
//!   `limit` returned nothing on memory, EVERY row on sqlite (`LIMIT -1` is
//!   no limit) and an error on postgres; ties on the order instant were
//!   unordered on the SQL backends;
//! - the reaper's selection (`list_expired_attestation_ids`): the
//!   never-offered types spelled as a SQL literal twice and as a Rust
//!   predicate once; `ORDER BY expires_at` with no tie-break, so the
//!   reaper's OFFSET paging could skip or repeat rows that expired at the
//!   same instant;
//! - the known-hash eviction (`evict_known_wire_hashes`): the over-bound
//!   report computed three times;
//! - the community retention sweep's room leg
//!   (`stream_dek_evict_room_chunks`): the epoch predicate (scope, room
//!   bound, terminated, not yet evicted, no held manifest) as one SQL text
//!   per dialect.
//!
//! # The shape
//!
//! Each selection is one value here with the predicate as a method:
//! [`HybridPendingSelection`] and [`ExpiredSelection`] render ONE statement
//! per dialect (the `AttestationQuery::render_sql` precedent) and give the
//! memory backend the same predicate and order to evaluate;
//! [`RoomChunkEviction::selects`] is the epoch predicate the executor asks
//! of each epoch row INSIDE its delete transaction, so the selection and the
//! delete are one atomic step and the predicate is still written once.
//! [`SweepStore`] and [`RoomEvictionStore`] are what a backend implements: run
//! the statement, map the rows, delete. They decide nothing.
//!
//! Not moved here, by decision (the handoff lists them): `reap_expired_attestations`
//! (a trait default already, purging through the shared purge door);
//! `run_consent_sla_watch` (a trait default; its revocation read is
//! `consent_admit`'s fold); the observation prunes (their selection is
//! `retention::plan_observation_prune`, the retention module's own
//! plan, because their error type is the retention API's).

use chrono::{DateTime, Utc};

use super::attestation_query::{Bind, Dialect, Statement};
use super::types::{attestation_type, HybridPendingRow, KnownHashEviction};
use super::Error;

// ── the PQC sweep's selection ─────────────────────────────────────────

/// Which table the PQC sweep walks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HybridPlane {
    /// `federation_keys`, oldest `valid_from` first.
    Keys,
    /// `federation_attestations`, oldest `asserted_at` first.
    Attestations,
}

/// **The PQC sweep's selection**: the rows whose ML-DSA-65 half is still
/// pending (`pqc_completed_at IS NULL`), oldest first by the plane's
/// instant, ties by id, at most `limit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HybridPendingSelection {
    /// The table.
    pub(crate) plane: HybridPlane,
    /// The page size, at least 1.
    pub(crate) limit: i64,
}

/// Plan a PQC-sweep page: `None` when `limit` asks for no rows (zero or
/// negative), so no backend reads anything. Before v60 sqlite read every
/// row for a negative limit and postgres refused it.
#[must_use]
pub(crate) fn plan_hybrid_pending(
    plane: HybridPlane,
    limit: i64,
) -> Option<HybridPendingSelection> {
    let limit = u64::try_from(limit)
        .ok()
        .and_then(std::num::NonZeroU64::new)?;
    Some(HybridPendingSelection {
        plane,
        limit: i64::try_from(limit.get()).unwrap_or(i64::MAX),
    })
}

#[cfg_attr(not(any(feature = "postgres", feature = "sqlite")), allow(dead_code))]
impl HybridPendingSelection {
    /// The one statement, for `dialect`: `id`, envelope TEXT, classical
    /// signature, in the selection's order, `LIMIT ?1`.
    #[must_use]
    pub(crate) fn render(&self, dialect: Dialect) -> Statement {
        let (table, id, envelope, instant) = match self.plane {
            HybridPlane::Keys => (
                "federation_keys",
                "key_id",
                "registration_envelope",
                "valid_from",
            ),
            HybridPlane::Attestations => (
                "federation_attestations",
                "attestation_id",
                "attestation_envelope",
                "asserted_at",
            ),
        };
        let (schema, id_expr, id_order, ph) = match dialect {
            Dialect::Sqlite => ("", id.to_owned(), id.to_owned(), "?1"),
            Dialect::Postgres => (
                "cirislens.",
                format!("{id}::text"),
                format!("{id}::text COLLATE \"C\""),
                "$1",
            ),
        };
        Statement {
            sql: format!(
                "SELECT {id_expr} AS row_id, {envelope} AS envelope, scrub_signature_classical \
                 FROM {schema}{table} WHERE pqc_completed_at IS NULL \
                 ORDER BY {instant} ASC, {id_order} ASC LIMIT {ph}"
            ),
            binds: vec![Bind::Int(self.limit)],
        }
    }

    /// The selection over rows a backend holds in memory:
    /// `(id, order instant, pending)` keys in, the page's ids out, in order.
    #[must_use]
    pub(crate) fn cut<T>(&self, rows: Vec<(String, DateTime<Utc>, bool, T)>) -> Vec<(String, T)> {
        let mut pending: Vec<(String, DateTime<Utc>, T)> = rows
            .into_iter()
            .filter(|(_, _, pending, _)| *pending)
            .map(|(id, at, _, t)| (id, at, t))
            .collect();
        pending.sort_by(|a, b| (a.1, a.0.as_str()).cmp(&(b.1, b.0.as_str())));
        pending.truncate(usize::try_from(self.limit).unwrap_or(usize::MAX));
        pending.into_iter().map(|(id, _, t)| (id, t)).collect()
    }
}

/// The PQC sweep's page (`list_hybrid_pending_keys` /
/// `list_hybrid_pending_attestations`): the plan, then the executor.
pub(crate) async fn list_hybrid_pending_planned<D>(
    dir: &D,
    plane: HybridPlane,
    limit: i64,
) -> Result<Vec<HybridPendingRow>, Error>
where
    D: SweepStore + ?Sized,
{
    match plan_hybrid_pending(plane, limit) {
        Some(selection) => dir.read_hybrid_pending(selection).await,
        None => Ok(Vec::new()),
    }
}

// ── the reaper's selection ────────────────────────────────────────────

/// The types the reaper never OFFERS (PR #769 review round 2): the purge
/// door refuses each structurally (`supersedes` / `withdraws` / `recants`
/// are composers, a `delegates_to` is a standing grant), so offering them
/// only builds an immovable prefix the paging walks every sweep.
pub(crate) const NEVER_OFFERED_FOR_REAP: [&str; 4] = [
    attestation_type::SUPERSEDES,
    attestation_type::WITHDRAWS,
    attestation_type::RECANTS,
    attestation_type::DELEGATES_TO,
];

/// **The reaper's selection**: ids of rows whose producer-stated expiry
/// is before `now`, never a [`NEVER_OFFERED_FOR_REAP`] type, oldest expiry
/// first, ties by id (a total order, so OFFSET paging neither skips nor
/// repeats a row), `limit` from `offset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExpiredSelection {
    /// The instant expiry is judged at.
    pub(crate) now: DateTime<Utc>,
    /// The page size, at least 1.
    pub(crate) limit: i64,
    /// Rows skipped (the refusals already paged past).
    pub(crate) offset: i64,
}

/// Plan a reaper page: `None` for an empty page (`limit` 0) or an offset no
/// store can reach.
#[must_use]
pub(crate) fn plan_expired(
    now: DateTime<Utc>,
    limit: usize,
    offset: usize,
) -> Option<ExpiredSelection> {
    let offset = i64::try_from(offset).ok()?;
    let limit = std::num::NonZeroUsize::new(limit)?;
    Some(ExpiredSelection {
        now,
        limit: i64::try_from(limit.get()).unwrap_or(i64::MAX),
        offset,
    })
}

#[cfg_attr(not(any(feature = "postgres", feature = "sqlite")), allow(dead_code))]
impl ExpiredSelection {
    /// Does the reaper offer this row?
    #[must_use]
    pub(crate) fn admits(&self, attestation_type: &str, expires_at: Option<DateTime<Utc>>) -> bool {
        !NEVER_OFFERED_FOR_REAP.contains(&attestation_type)
            && expires_at.is_some_and(|e| e < self.now)
    }

    /// The one statement, for `dialect`.
    #[must_use]
    pub(crate) fn render(&self, dialect: Dialect) -> Statement {
        let ph = |n: usize| match dialect {
            Dialect::Sqlite => format!("?{n}"),
            Dialect::Postgres => format!("${n}"),
        };
        let (table, id, id_order) = match dialect {
            Dialect::Sqlite => (
                "federation_attestations",
                "attestation_id",
                "attestation_id",
            ),
            Dialect::Postgres => (
                "cirislens.federation_attestations",
                "attestation_id::text",
                "attestation_id::text COLLATE \"C\"",
            ),
        };
        let mut binds = vec![Bind::Time(self.now)];
        let mut types = Vec::with_capacity(NEVER_OFFERED_FOR_REAP.len());
        for t in NEVER_OFFERED_FOR_REAP {
            binds.push(Bind::Text(t.to_owned()));
            types.push(ph(binds.len()));
        }
        binds.push(Bind::Int(self.limit));
        let limit = ph(binds.len());
        binds.push(Bind::Int(self.offset));
        let offset = ph(binds.len());
        Statement {
            sql: format!(
                "SELECT {id} AS attestation_id FROM {table} \
                 WHERE expires_at IS NOT NULL AND expires_at < {now} \
                   AND attestation_type NOT IN ({types}) \
                 ORDER BY expires_at ASC, {id_order} ASC LIMIT {limit} OFFSET {offset}",
                now = ph(1),
                types = types.join(", "),
            ),
            binds,
        }
    }

    /// The selection over rows a backend holds in memory:
    /// `(id, type, expires_at)` in, the page's ids out, in order.
    #[must_use]
    pub(crate) fn cut(&self, rows: Vec<(String, String, Option<DateTime<Utc>>)>) -> Vec<String> {
        let mut offered: Vec<(DateTime<Utc>, String)> = rows
            .into_iter()
            .filter(|(_, ty, exp)| self.admits(ty, *exp))
            .filter_map(|(id, _, exp)| exp.map(|e| (e, id)))
            .collect();
        offered.sort();
        offered
            .into_iter()
            .skip(usize::try_from(self.offset).unwrap_or(usize::MAX))
            .take(usize::try_from(self.limit).unwrap_or(usize::MAX))
            .map(|(_, id)| id)
            .collect()
    }
}

/// The reaper's page (`list_expired_attestation_ids`): the plan, then the
/// executor.
pub(crate) async fn list_expired_attestation_ids_planned<D>(
    dir: &D,
    now: DateTime<Utc>,
    limit: usize,
    offset: usize,
) -> Result<Vec<String>, Error>
where
    D: SweepStore + ?Sized,
{
    match plan_expired(now, limit, offset) {
        Some(selection) => dir.read_expired_attestation_ids(selection).await,
        None => Ok(Vec::new()),
    }
}

// ── the known-hash eviction ───────────────────────────────────────────

/// **The known-hash eviction's report** (CIRISPersist#785): what the
/// delete removed, what remains, and by how much the remainder exceeds
/// `bound`. The floor wins over the bound: an overage is REPORTED, never
/// resolved by evicting below the caller's cutoff.
#[must_use]
pub(crate) fn known_hash_eviction(evicted: u64, remaining: u64, bound: u64) -> KnownHashEviction {
    KnownHashEviction {
        evicted,
        remaining,
        over_bound_by: remaining.saturating_sub(bound),
    }
}

/// `evict_known_wire_hashes`: the executor's delete of every entry not
/// advertised since `cutoff` (the caller's instant: persist never derives
/// it), then the report.
pub(crate) async fn evict_known_wire_hashes_planned<D>(
    dir: &D,
    cutoff: DateTime<Utc>,
    bound: u64,
) -> Result<KnownHashEviction, Error>
where
    D: SweepStore + ?Sized,
{
    let (evicted, remaining) = dir.evict_known_wire_hashes_before(cutoff).await?;
    Ok(known_hash_eviction(evicted, remaining, bound))
}

/// The sweeps' executor: what a backend does for the shared selections.
/// Storage only.
#[async_trait::async_trait]
pub(crate) trait SweepStore: Send + Sync {
    /// Run the PQC-sweep page: [`HybridPendingSelection::render`] on SQL,
    /// [`HybridPendingSelection::cut`] on memory.
    async fn read_hybrid_pending(
        &self,
        selection: HybridPendingSelection,
    ) -> Result<Vec<HybridPendingRow>, Error>;

    /// Run the reaper page: [`ExpiredSelection::render`] on SQL,
    /// [`ExpiredSelection::cut`] on memory.
    async fn read_expired_attestation_ids(
        &self,
        selection: ExpiredSelection,
    ) -> Result<Vec<String>, Error>;

    /// Delete every known-but-not-held hash whose `last_advertised_at` is
    /// before `cutoff`; return `(evicted, remaining)`.
    async fn evict_known_wire_hashes_before(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<(u64, u64), Error>;
}

// ── the community retention sweep's room leg ──────────────────────────

/// One room-stream epoch row as stored, with the one fact the selection
/// needs from elsewhere (`manifest_held`: a still-held DAG manifest relates
/// one of the epoch's chunks).
#[cfg_attr(not(any(feature = "postgres", feature = "sqlite")), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RoomEpochRow {
    /// `stream_id`.
    pub(crate) stream_id: String,
    /// `epoch`.
    pub(crate) epoch: i64,
    /// `cohort_scope`.
    pub(crate) cohort_scope: String,
    /// `room_epoch`; `None` for a stream that is not a room's.
    pub(crate) room_epoch: Option<i64>,
    /// `terminated_at IS NOT NULL`.
    pub(crate) terminated: bool,
    /// `evicted_at IS NOT NULL`.
    pub(crate) evicted: bool,
    /// A held manifest relates one of the epoch's chunks.
    pub(crate) manifest_held: bool,
}

/// **The room leg's selection** (CIRISPersist#977, Codex r3/r4 on #1065):
/// the ROOM stream epochs `minter_key_id` sealed for `community_key_id`
/// whose `room_epoch` is at or below `max_room_epoch`.
#[cfg_attr(not(any(feature = "postgres", feature = "sqlite")), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RoomChunkEviction {
    /// `group_key_id`.
    pub(crate) community_key_id: String,
    /// `owner_key_id`.
    pub(crate) minter_key_id: String,
    /// The retention bound.
    pub(crate) max_room_epoch: u64,
    /// The `evicted_at` stamp.
    pub(crate) now: DateTime<Utc>,
}

#[cfg_attr(not(any(feature = "postgres", feature = "sqlite")), allow(dead_code))]
impl RoomChunkEviction {
    /// Does the sweep evict this epoch? A community or affiliations ROOM
    /// epoch at or below the bound; TERMINATED (an open epoch still takes
    /// chunks under its DEK, and evicting it would stamp it and leave every
    /// later chunk outside the sweep — it goes once its terminator lands);
    /// not already evicted (a re-run deletes nothing and never re-stamps);
    /// and no still-held manifest relates its chunks (the bound applies to
    /// the DAG as advertised: its chunks go once its manifest has gone).
    #[must_use]
    pub(crate) fn selects(&self, row: &RoomEpochRow) -> bool {
        matches!(row.cohort_scope.as_str(), "community" | "affiliations")
            && row
                .room_epoch
                .and_then(|r| u64::try_from(r).ok())
                .is_some_and(|r| r <= self.max_room_epoch)
            && row.terminated
            && !row.evicted
            && !row.manifest_held
    }
}

/// The room leg's executor (sqlite and postgres; the memory backend has no
/// blob plane).
#[cfg_attr(not(any(feature = "postgres", feature = "sqlite")), allow(dead_code))]
#[async_trait::async_trait]
pub(crate) trait RoomEvictionStore: Send + Sync {
    /// In ONE transaction: read the minter's epoch rows for the community,
    /// keep those [`RoomChunkEviction::selects`], delete their stored chunk
    /// blobs and stamp them evicted (the epoch rows stay, a record). Returns
    /// the chunk rows deleted.
    async fn evict_selected_room_epochs(
        &self,
        eviction: RoomChunkEviction,
    ) -> Result<u64, super::BlobError>;
}

/// `stream_dek_evict_room_chunks`: the selection, run by the executor
/// inside its transaction.
#[cfg_attr(not(any(feature = "postgres", feature = "sqlite")), allow(dead_code))]
pub(crate) async fn evict_room_chunks_planned<B>(
    backend: &B,
    community_key_id: &str,
    minter_key_id: &str,
    max_room_epoch: u64,
    now: DateTime<Utc>,
) -> Result<u64, super::BlobError>
where
    B: RoomEvictionStore + ?Sized,
{
    backend
        .evict_selected_room_epochs(RoomChunkEviction {
            community_key_id: community_key_id.to_owned(),
            minter_key_id: minter_key_id.to_owned(),
            max_room_epoch,
            now,
        })
        .await
}
