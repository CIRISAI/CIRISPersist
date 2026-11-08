//! v61 (CIRISPersist#934, S4a) — **the gated directory reads, decided once.**
//!
//! `list_scores`, `resolve_scores`, `list_attestation_log`,
//! `list_key_registration_history` and `list_derived_hex` were written twice,
//! in `store/{sqlite,postgres}.rs`, with the same refusals in the same order:
//! the #552 read log ahead of everything, the page bound, the caller-scope
//! gate, the cursor version, the quarantine serve consult, the trailing
//! cursor taken before that filter, the composer fold, the stored-token
//! decode, the hex decode. Each read is now one function here over a typed
//! read a backend answers ([`ReadPlanStore`]): the SQL and the row mapping.
//! It decides nothing.
//!
//! # Which instant each plan reads
//!
//! `resolve_scores` folds at the door's clock read (the verdict's `now`);
//! `list_attestation_log` consults the quarantine marker at its clock read.
//! The others read no instant.

use super::attestation_query::QueryRows;
use super::types::{Attestation, KeyRegistrationHistoryRow, KeyReplacementKind};
use super::{Error, FederationDirectory};
use crate::read::{AttestationCursor, AttestationFilter, ComposedVerdict, ScoresPage};
use crate::scope::CallerScope;

/// The largest page a scores or log read serves.
const MAX_PAGE: i64 = 10_000;

/// One `federation_key_registration_history` row as stored: the replacement
/// kind still its token.
#[derive(Debug, Clone)]
pub(crate) struct StoredKeyRegistrationHistory {
    /// The key the history is of.
    pub(crate) key_id: String,
    /// The replaced registration envelope, JSON text.
    pub(crate) registration_envelope: String,
    /// Its content hash, raw bytes.
    pub(crate) original_content_hash: Vec<u8>,
    /// The replaced classical scrub signature.
    pub(crate) scrub_signature_classical: String,
    /// The replaced PQC scrub signature.
    pub(crate) scrub_signature_pqc: Option<String>,
    /// The replaced scrub key.
    pub(crate) scrub_key_id: String,
    /// The replaced scrub instant.
    pub(crate) scrub_timestamp: chrono::DateTime<chrono::Utc>,
    /// When the row was replaced.
    pub(crate) replaced_at: chrono::DateTime<chrono::Utc>,
    /// The replacing record's hash.
    pub(crate) replaced_by_hash: String,
    /// The replaced row's `persist_row_hash`.
    pub(crate) replaced_row_hash: Option<String>,
    /// `replacement_kind`, the stored token.
    pub(crate) replacement_kind: String,
}

/// The read executor. Storage only: each method is the SQL for one typed
/// read, its rows in the read's order.
#[async_trait::async_trait]
pub(crate) trait ReadPlanStore: FederationDirectory + Sized {
    /// One `list_scores` page: the scores-plane rows `filter` and `scope`
    /// pin, minus the `filter.lifecycle` hidden ones, after `cursor`, newest
    /// first, at most `limit`.
    async fn read_scores_page(
        &self,
        filter: &AttestationFilter,
        scope: &CallerScope,
        cursor: Option<&AttestationCursor>,
        limit: i64,
    ) -> Result<Vec<Attestation>, Error>;

    /// The `scores` rows `filter` and `scope` pin, newest first, at most
    /// [`super::scores::RESOLVE_CANDIDATE_CAP`] (#456).
    async fn read_score_candidates(
        &self,
        filter: &AttestationFilter,
        scope: &CallerScope,
    ) -> Result<Vec<Attestation>, Error>;

    /// Every `supersedes` / `withdraws` / `recants` row by one of
    /// `attesters` (non-empty), whatever its subject or scope.
    async fn read_score_composers(&self, attesters: &[String]) -> Result<Vec<Attestation>, Error>;

    /// One owner-scope log page (#455): federation-tier rows of a
    /// registered type, `subject_key_id`'s when given, after `cursor`,
    /// newest first, at most `limit`. Byte-faithful, unfiltered.
    async fn read_attestation_log_page(
        &self,
        subject_key_id: Option<&str>,
        cursor: Option<&AttestationCursor>,
        limit: i64,
    ) -> Result<QueryRows, Error>;

    /// One page of the rows naming `subject_key_id` under exactly
    /// `dimension` (#1225): the V106 `attestation_subjects_seek` seek,
    /// federation tier, served as `list_attestations_since` serves (no
    /// unregistered type under enforcement, no tombstoned row the tombstone
    /// is not void for), after `cursor`, newest first, at most `fetch` rows.
    async fn read_naming_page(
        &self,
        subject_key_id: &str,
        dimension: &str,
        cursor: Option<&AttestationCursor>,
        fetch: i64,
    ) -> Result<QueryRows, Error>;

    /// The key's registration history rows, oldest first.
    async fn read_key_registration_history(
        &self,
        key_id: &str,
    ) -> Result<Vec<StoredKeyRegistrationHistory>, Error>;

    /// The V149 rendition rows of `original_sha256`, by rendition hash.
    async fn read_renditions(
        &self,
        original_sha256: [u8; 32],
    ) -> Result<Vec<super::renditions::Rendition>, Error>;
}

/// The page bound both paged reads refuse outside of.
fn check_page_limit(limit: i64) -> Result<(), Error> {
    if (1..=MAX_PAGE).contains(&limit) {
        Ok(())
    } else {
        Err(Error::InvalidArgument(format!(
            "limit must be in [1, {MAX_PAGE}], got {limit}"
        )))
    }
}

/// The cursor versions this build reads.
fn check_cursor_version(cursor: Option<&AttestationCursor>) -> Result<(), Error> {
    match cursor {
        Some(c) if c.version != "v1" => Err(Error::InvalidArgument(format!(
            "AttestationCursor version {} unsupported; v1 only",
            c.version
        ))),
        _ => Ok(()),
    }
}

/// The next cursor: the page's trailing row when the page is full.
fn trailing_cursor(items: &[Attestation], limit: i64) -> Option<AttestationCursor> {
    match items.last() {
        Some(last) if items.len() as i64 == limit => Some(AttestationCursor::from_trailing(
            last.asserted_at,
            last.attestation_id.clone(),
        )),
        _ => None,
    }
}

/// The read: every backend's `list_scores`.
pub(crate) async fn list_scores_planned(
    dir: &impl ReadPlanStore,
    caller_occurrence_key_id: &str,
    filter: AttestationFilter,
    cursor: Option<AttestationCursor>,
    limit: i64,
) -> Result<ScoresPage, Error> {
    // #552 (CC 3.4.5) — the scores-plane read log, FIRST, ahead of every
    // refusal: a read rejected for a bad limit or cursor is logged exactly
    // like one that is served.
    super::scores_read_audit::log_scores_read(
        super::scores_read_audit::ScoresReadSite::ListScores,
        caller_occurrence_key_id,
        &filter,
    );
    check_page_limit(limit)?;
    let scope = crate::scope::caller_scope_from_directory(dir, caller_occurrence_key_id)
        .await
        .map_err(|e| Error::Backend(format!("list_scores admission: {e}")))?;
    check_cursor_version(cursor.as_ref())?;
    let items = dir
        .read_scores_page(&filter, &scope, cursor.as_ref(), limit)
        .await?;
    let next_cursor = trailing_cursor(&items, limit);
    Ok(ScoresPage { items, next_cursor })
}

/// The read: every backend's `resolve_scores`.
pub(crate) async fn resolve_scores_planned(
    dir: &impl ReadPlanStore,
    caller_occurrence_key_id: &str,
    filter: AttestationFilter,
    policy: String,
    trace: bool,
) -> Result<ComposedVerdict, Error> {
    // #552 (CC 3.4.5) — the scores-plane read log; see `list_scores_planned`.
    super::scores_read_audit::log_scores_read(
        super::scores_read_audit::ScoresReadSite::ResolveScores,
        caller_occurrence_key_id,
        &filter,
    );
    let scope = crate::scope::caller_scope_from_directory(dir, caller_occurrence_key_id)
        .await
        .map_err(|e| Error::Backend(format!("resolve_scores admission: {e}")))?;
    let data = dir.read_score_candidates(&filter, &scope).await?;
    // Composers (retractions) from the same attesters, regardless of their
    // own subject or scope: a retraction applies for everyone.
    let mut attesters: Vec<String> = data.iter().map(|a| a.attesting_key_id.clone()).collect();
    attesters.sort();
    attesters.dedup();
    let composers = if attesters.is_empty() {
        Vec::new()
    } else {
        dir.read_score_composers(&attesters).await?
    };
    Ok(super::scores::compose_verdict(
        data,
        composers,
        &policy,
        trace,
        chrono::Utc::now(),
    ))
}

/// The read: every backend's `list_attestation_log`.
pub(crate) async fn list_attestation_log_planned(
    dir: &impl ReadPlanStore,
    subject_key_id: Option<&str>,
    cursor: Option<AttestationCursor>,
    limit: i64,
) -> Result<ScoresPage, Error> {
    check_page_limit(limit)?;
    check_cursor_version(cursor.as_ref())?;
    let QueryRows {
        rows,
        bytes,
        backend,
    } = dir
        .read_attestation_log_page(subject_key_id, cursor.as_ref(), limit)
        .await?;
    // The cursor is taken from the SQL page BEFORE the serve consult: it must
    // advance over the rows that exist, or a fully withheld page would stall
    // the walk. Pages may come back short.
    let next_cursor = trailing_cursor(&rows, limit);
    // v25.1.0 (CIRISPersist#570 ask 5) — THE SERVE CONSULT: this is the relay
    // read a peer's rows leave through, so rows authored by a withheld key are
    // dropped here (retained locally, reversible).
    let items = super::quarantine::filter_withheld_rows(dir, rows, chrono::Utc::now()).await?;
    crate::observe::record_read(
        backend,
        crate::observe::Door::ListAttestationLog,
        subject_key_id.unwrap_or("*"),
        &items,
        bytes,
    );
    Ok(ScoresPage { items, next_cursor })
}

/// The read: every backend's `list_attestations_naming_by_dimension`
/// (v61.0.5, CIRISPersist#1225). The executor fetches one row past the page,
/// so `next_cursor` is `Some` exactly when another row exists.
pub(crate) async fn list_attestations_naming_by_dimension_planned(
    dir: &impl ReadPlanStore,
    subject_key_id: &str,
    dimension: &str,
    cursor: Option<AttestationCursor>,
    limit: i64,
) -> Result<ScoresPage, Error> {
    check_page_limit(limit)?;
    check_cursor_version(cursor.as_ref())?;
    let QueryRows {
        mut rows,
        bytes,
        backend,
    } = dir
        .read_naming_page(subject_key_id, dimension, cursor.as_ref(), limit + 1)
        .await?;
    let page = usize::try_from(limit).map_err(|_| Error::Backend("page size".into()))?;
    // An executor that returned more than one row past the page dropped its
    // LIMIT: its read was as wide as the slice.
    if rows.len() > page + 1 {
        return Err(Error::Backend(format!(
            "list_attestations_naming_by_dimension: {} rows for a page of {page}",
            rows.len()
        )));
    }
    let next_cursor = if rows.len() > page {
        rows.truncate(page);
        rows.last()
            .map(|a| AttestationCursor::from_trailing(a.asserted_at, a.attestation_id.clone()))
    } else {
        None
    };
    crate::observe::record_read(
        backend,
        crate::observe::Door::ListAttestationsNamingByDimension,
        subject_key_id,
        &rows,
        bytes,
    );
    Ok(ScoresPage {
        items: rows,
        next_cursor,
    })
}

/// The read: every backend's `list_key_registration_history`. A stored
/// replacement token this build does not know is a refusal, never a row.
pub(crate) async fn list_key_registration_history_planned(
    dir: &impl ReadPlanStore,
    key_id: &str,
) -> Result<Vec<KeyRegistrationHistoryRow>, Error> {
    dir.read_key_registration_history(key_id)
        .await?
        .into_iter()
        .map(|r| {
            let replacement =
                KeyReplacementKind::from_token(&r.replacement_kind).ok_or_else(|| {
                    Error::Backend(format!("history replacement_kind {:?}", r.replacement_kind))
                })?;
            Ok(KeyRegistrationHistoryRow {
                key_id: r.key_id,
                registration_envelope: serde_json::from_str(&r.registration_envelope)
                    .map_err(|e| Error::Backend(format!("history envelope: {e}")))?,
                original_content_hash: hex::encode(r.original_content_hash),
                scrub_signature_classical: r.scrub_signature_classical,
                scrub_signature_pqc: r.scrub_signature_pqc,
                scrub_key_id: r.scrub_key_id,
                scrub_timestamp: r.scrub_timestamp,
                replaced_at: r.replaced_at,
                replaced_by_hash: r.replaced_by_hash,
                replaced_row_hash: r.replaced_row_hash,
                replacement,
            })
        })
        .collect()
}

/// The read: every backend's `list_derived_hex` (v45.0.0, #871).
pub(crate) async fn list_derived_hex_planned(
    dir: &impl ReadPlanStore,
    original_sha256_hex: &str,
) -> Result<Vec<super::renditions::Rendition>, Error> {
    let original = super::renditions::decode_sha256_hex(original_sha256_hex)?;
    dir.read_renditions(original).await
}
