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

use super::attestation_query::{Bind, Dialect, QueryRows, Statement};
use super::types::{
    Attestation, KeyRegistrationHistoryRow, KeyReplacementKind, OwnerBindingChange,
    OwnerBindingPage, ServedAttestation, ServedAttestationPage,
};
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

    /// v61.1.0 (#1190, #1163) — one page of the attestation serve stream
    /// that `narrowing` selects: federation tier, served as
    /// `list_attestations_since` serves (no unregistered type under
    /// enforcement, no tombstoned row the tombstone is not void for), after
    /// `since` (exclusive), oldest serve position first, at most `fetch`
    /// rows; and the stream's head (its greatest serve position over every
    /// held row), read BEFORE the page. The SQL is
    /// [`serve_stream_statement`] and [`serve_stream_head_statement`].
    async fn read_serve_stream_page(
        &self,
        narrowing: ServeNarrowing<'_>,
        since: Option<&(chrono::DateTime<chrono::Utc>, String)>,
        fetch: i64,
    ) -> Result<ServedRows, Error>;

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

/// v61.1.0 (#1190, #1163) — the most prefixes one narrowed serve read
/// takes, dimension and type together. Edge's decision queue names eleven.
pub(crate) const MAX_SERVE_PREFIXES: usize = 64;

/// v61.1.0 (#1190, #1163) — what narrows a read of the attestation serve
/// stream. The serve rule, the cursor and the order are the stream's own;
/// only the selection differs.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ServeNarrowing<'a> {
    /// The rows whose `dimension` starts with one of `dimension_prefixes` or
    /// whose `attestation_type` starts with one of `type_prefixes` (#1190).
    /// Byte prefixes, case-sensitive, as half-open ranges: no `LIKE`.
    Prefixes {
        /// Dimension prefixes.
        dimension_prefixes: &'a [String],
        /// `attestation_type` prefixes.
        type_prefixes: &'a [String],
    },
    /// The rows that can change a node's owner binding (#1163): every
    /// owner-binding `delegates_to` (the ownership dimension or the
    /// `delegation_purpose: owner_binding` marker, as
    /// `is_owner_binding_envelope`), and every `withdraws` / `recants` /
    /// `supersedes` attested to a key some owner-binding row is attested to.
    /// A superset on purpose: the verdict is the live-delegation fold, read
    /// per node by the plan, never this SQL.
    OwnerBindingChanges,
}

/// v61.1.0 (#1190, #1163) — one page of the serve stream as the executor
/// returns it, with the stream's head read before the page.
#[derive(Debug, Clone)]
pub(crate) struct ServedRows {
    /// The rows, in serve order, at most the fetch asked for.
    pub(crate) rows: Vec<ServedAttestation>,
    /// The greatest serve position over every held row, before the page.
    pub(crate) head: Option<(chrono::DateTime<chrono::Utc>, String)>,
    /// Envelope bytes decoded.
    pub(crate) bytes: u64,
    /// The backend that ran the statement.
    pub(crate) backend: crate::observe::StoreBackend,
}

/// The dialect-specific spellings the serve-stream statements read.
struct ServeSpelling {
    /// `FROM` target, with its alias when it has one.
    from: &'static str,
    /// How the outer row is named inside the predicate.
    outer: &'static str,
    /// Schema prefix for the tables the serve rule reads.
    prefix: &'static str,
    /// The serve position expression (the V130 index's).
    pos: &'static str,
    /// The id as the cursor compares it.
    id: &'static str,
    /// The selected columns, the row mapper's names plus `_pos`.
    columns: &'static str,
    /// The text-comparison collation suffix a byte range needs.
    collate: &'static str,
    /// The serve filter's dialect.
    row_type: super::row_type::SqlDialect,
}

/// The sqlite spelling: no alias, so the position expression is the V130
/// `federation_attestations_admitted` index's, character for character, and
/// the walk is pinned to that index (`INDEXED BY`): unpinned and without
/// statistics, a prefix narrowing can take a dimension index and sort the
/// family's whole history on every poll.
const SQLITE_SERVE: ServeSpelling = ServeSpelling {
    from: "federation_attestations INDEXED BY federation_attestations_admitted",
    outer: "federation_attestations",
    prefix: "",
    pos: "COALESCE(admitted_at, promoted_at, asserted_at)",
    id: "attestation_id",
    columns: "attestation_id, attesting_key_id, attested_key_id, attestation_type, \
              weight, asserted_at, expires_at, attestation_envelope, \
              original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
              scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, \
              subject_key_ids, withdraws_admission_rule, cohort_scope, tier, promoted_at, \
              additional_scrubs, COALESCE(admitted_at, promoted_at, asserted_at) AS _pos",
    collate: "",
    row_type: super::row_type::SqlDialect::Sqlite,
};

/// The postgres spelling: `admitted_at` is NOT NULL (V130), and
/// `(admitted_at, attestation_id)` is the `federation_attestations_admitted`
/// index.
const POSTGRES_SERVE: ServeSpelling = ServeSpelling {
    from: "cirislens.federation_attestations fa",
    outer: "fa",
    prefix: "cirislens.",
    pos: "fa.admitted_at",
    id: "fa.attestation_id",
    columns: "fa.attestation_id::text AS attestation_id, fa.attesting_key_id, \
              fa.attested_key_id, fa.attestation_type, fa.weight::float8 AS weight, \
              fa.asserted_at, fa.expires_at, fa.attestation_envelope, \
              fa.original_content_hash, fa.scrub_signature_classical, \
              fa.scrub_signature_pqc, fa.scrub_key_id, fa.scrub_timestamp, \
              fa.pqc_completed_at, fa.persist_row_hash, fa.subject_key_ids, \
              fa.withdraws_admission_rule, fa.cohort_scope, fa.tier, fa.promoted_at, \
              fa.additional_scrubs, fa.admitted_at AS _pos",
    collate: " COLLATE \"C\"",
    row_type: super::row_type::SqlDialect::Postgres,
};

fn serve_spelling(dialect: Dialect) -> &'static ServeSpelling {
    match dialect {
        Dialect::Sqlite => &SQLITE_SERVE,
        Dialect::Postgres => &POSTGRES_SERVE,
    }
}

fn placeholder(dialect: Dialect, binds: &[Bind]) -> String {
    match dialect {
        Dialect::Sqlite => format!("?{}", binds.len()),
        Dialect::Postgres => format!("${}", binds.len()),
    }
}

/// `column` starts with `prefix`, byte for byte: the half-open range
/// `[prefix, successor)` when a successor is representable (an index range,
/// and no `LIKE`, so `%` and `_` are ordinary bytes and case is kept),
/// `substr` otherwise. The #817/#818 rule `attestation_query` spells.
fn serve_prefix_clause(
    dialect: Dialect,
    column: &str,
    prefix: &str,
    binds: &mut Vec<Bind>,
) -> String {
    let collate = serve_spelling(dialect).collate;
    match crate::ceg::list::federation::dimension_prefix_bounds(prefix) {
        Some((lo, hi)) => {
            binds.push(Bind::Text(lo));
            let a = placeholder(dialect, binds);
            binds.push(Bind::Text(hi));
            let b = placeholder(dialect, binds);
            format!("({column}{collate} >= {a} AND {column}{collate} < {b})")
        }
        None => {
            binds.push(Bind::Text(prefix.to_owned()));
            let a = placeholder(dialect, binds);
            format!("substr({column}, 1, {}) = {a}", prefix.chars().count())
        }
    }
}

/// `t` is an owner-binding row by its envelope, as
/// `admission::is_owner_binding_envelope` reads it: the ownership dimension,
/// or the CC 2.4.1.2 `delegation_purpose` marker.
fn owner_binding_marker_sql(dialect: Dialect, t: &str) -> String {
    use super::types::owner_binding;
    let purpose = match dialect {
        Dialect::Sqlite => {
            format!("json_extract({t}.attestation_envelope, '$.delegation_purpose')")
        }
        Dialect::Postgres => {
            format!("(({t}.attestation_envelope)::jsonb ->> 'delegation_purpose')")
        }
    };
    format!(
        "({t}.dimension = '{}' OR {purpose} = '{}')",
        owner_binding::DIMENSION,
        owner_binding::CC_DELEGATION_PURPOSE
    )
}

/// v61.1.0 (#1190, #1163) — THE serve-stream page statement, both dialects:
/// `narrowing`'s rows under `list_attestations_since`'s serve rule (the
/// federation tier, [`super::row_type::serve_filter_sql`],
/// [`super::steward_purge::served_under_purge_sql`]), strictly after `since`
/// on `(serve position, attestation_id)`, ascending, `LIMIT fetch`. It walks
/// the V130 `federation_attestations_admitted` index from the cursor.
pub(crate) fn serve_stream_statement(
    dialect: Dialect,
    narrowing: ServeNarrowing<'_>,
    since: Option<&(chrono::DateTime<chrono::Utc>, String)>,
    fetch: i64,
) -> Statement {
    use super::types::attestation_type as at;
    let sp = serve_spelling(dialect);
    let o = sp.outer;
    let mut binds: Vec<Bind> = Vec::new();
    let mut parts: Vec<String> = Vec::new();
    match narrowing {
        ServeNarrowing::Prefixes {
            dimension_prefixes,
            type_prefixes,
        } => {
            let mut arms: Vec<String> = Vec::new();
            for p in dimension_prefixes {
                arms.push(serve_prefix_clause(
                    dialect,
                    &format!("{o}.dimension"),
                    p,
                    &mut binds,
                ));
            }
            for p in type_prefixes {
                arms.push(serve_prefix_clause(
                    dialect,
                    &format!("{o}.attestation_type"),
                    p,
                    &mut binds,
                ));
            }
            // An empty narrowing never reaches here (`check_serve_prefixes`);
            // were it to, it selects nothing rather than everything.
            if arms.is_empty() {
                arms.push("1 = 0".to_owned());
            }
            parts.push(format!("({})", arms.join(" OR ")));
        }
        ServeNarrowing::OwnerBindingChanges => {
            parts.push(format!(
                "{o}.attestation_type IN ('{}', '{}', '{}', '{}')",
                at::DELEGATES_TO,
                at::SUPERSEDES,
                at::WITHDRAWS,
                at::RECANTS
            ));
            parts.push(format!(
                "(({o}.attestation_type = '{dt}' AND {own}) \
                  OR ({o}.attestation_type <> '{dt}' AND EXISTS ( \
                      SELECT 1 FROM {prefix}federation_attestations ob \
                       WHERE ob.attested_key_id = {o}.attested_key_id \
                         AND ob.attestation_type = '{dt}' AND {ob})))",
                dt = at::DELEGATES_TO,
                own = owner_binding_marker_sql(dialect, o),
                prefix = sp.prefix,
                ob = owner_binding_marker_sql(dialect, "ob"),
            ));
        }
    }
    // E5 — a local-tier row never reaches the serve surface.
    parts.push(format!("{o}.tier = 'federation'"));
    // v53.0.0 (#975, CC 2.4) — under enforcement, an unregistered type is
    // neither served nor replicated.
    parts.extend(super::row_type::serve_filter_sql(
        &format!("{o}.attestation_type"),
        sp.row_type,
    ));
    // v54.1.0 (#1046) — a tombstoned row is not served, unless the tombstone
    // is void for it.
    parts.push(super::steward_purge::served_under_purge_sql(o, sp.prefix));
    if let Some((at_, id)) = since {
        binds.push(Bind::Time(*at_));
        let a = placeholder(dialect, &binds);
        binds.push(Bind::Text(id.clone()));
        let b = placeholder(dialect, &binds);
        parts.push(match dialect {
            // `list_attestations_since`'s OR form, over the index's own
            // expression, behind a `>=` the planner can seek on: the OR
            // alone is not a range, and the walk would start at the oldest
            // row on every page.
            Dialect::Sqlite => format!(
                "({pos} >= {a} AND ({pos} > {a} OR {id} > {b}))",
                pos = sp.pos,
                id = sp.id
            ),
            Dialect::Postgres => format!("({}, {}) > ({a}, {b})", sp.pos, sp.id),
        });
    }
    binds.push(Bind::Int(fetch));
    let limit = placeholder(dialect, &binds);
    Statement {
        sql: format!(
            "SELECT {columns} FROM {from} WHERE {} ORDER BY {pos} ASC, {id} ASC LIMIT {limit}",
            parts.join(" AND "),
            columns = sp.columns,
            from = sp.from,
            pos = sp.pos,
            id = sp.id,
        ),
        binds,
    }
}

/// v61.1.0 (#1190, #1163) — the stream's head: the greatest serve position
/// over every held row (any tier, any type), `_pos` and `attestation_id`.
/// One backward step of the V130 index.
pub(crate) fn serve_stream_head_statement(dialect: Dialect) -> Statement {
    let sp = serve_spelling(dialect);
    let selected_id = match dialect {
        Dialect::Sqlite => "attestation_id",
        Dialect::Postgres => "fa.attestation_id::text",
    };
    Statement {
        sql: format!(
            "SELECT {pos} AS _pos, {selected_id} AS attestation_id FROM {from} \
             ORDER BY {pos} DESC, {id} DESC LIMIT 1",
            pos = sp.pos,
            id = sp.id,
            from = sp.from,
        ),
        binds: Vec::new(),
    }
}

/// The narrowed serve read's refusals: no prefix at all (that read is
/// `list_attestations_since`), an empty prefix (it would select every row),
/// or more than [`MAX_SERVE_PREFIXES`].
fn check_serve_prefixes(
    dimension_prefixes: &[String],
    type_prefixes: &[String],
) -> Result<(), Error> {
    let n = dimension_prefixes.len() + type_prefixes.len();
    if n == 0 {
        return Err(Error::InvalidArgument(
            "list_attestations_since_by_prefixes: name at least one dimension or type prefix; \
             the unnarrowed stream is list_attestations_since"
                .into(),
        ));
    }
    if n > MAX_SERVE_PREFIXES {
        return Err(Error::InvalidArgument(format!(
            "list_attestations_since_by_prefixes: {n} prefixes, at most {MAX_SERVE_PREFIXES}"
        )));
    }
    if dimension_prefixes
        .iter()
        .chain(type_prefixes)
        .any(String::is_empty)
    {
        return Err(Error::InvalidArgument(
            "list_attestations_since_by_prefixes: an empty prefix matches every row; refused"
                .into(),
        ));
    }
    Ok(())
}

/// Cut a serve-stream page fetched one row past `limit`: `next_cursor` is
/// `Some` exactly when that row exists, and `high_water` is the furthest
/// position this read examined (see [`ServedAttestationPage::high_water`]).
#[allow(clippy::type_complexity)]
fn cut_serve_page(
    rows: &mut Vec<ServedAttestation>,
    limit: i64,
    since: Option<&(chrono::DateTime<chrono::Utc>, String)>,
    head: Option<(chrono::DateTime<chrono::Utc>, String)>,
    door: &str,
) -> Result<
    (
        Option<(chrono::DateTime<chrono::Utc>, String)>,
        Option<(chrono::DateTime<chrono::Utc>, String)>,
    ),
    Error,
> {
    let page = usize::try_from(limit).map_err(|_| Error::Backend("page size".into()))?;
    // An executor that returned more than one row past the page dropped its
    // LIMIT: its read was as wide as the stream.
    if rows.len() > page + 1 {
        return Err(Error::Backend(format!(
            "{door}: {} rows for a page of {page}",
            rows.len()
        )));
    }
    if rows.len() > page {
        rows.truncate(page);
        let next = rows.last().map(ServedAttestation::resume_pair);
        return Ok((next.clone(), next));
    }
    // Nothing remains past the page: every held row up to the head read
    // before it was examined, so a resume from the head skips nothing this
    // read could have served.
    let high_water = [
        since.cloned(),
        rows.last().map(ServedAttestation::resume_pair),
        head,
    ]
    .into_iter()
    .flatten()
    .max();
    Ok((None, high_water))
}

/// The read: every backend's `list_attestations_since_by_prefixes` (v61.1.0,
/// CIRISPersist#1190). The executor fetches one row past the page, so
/// `next_cursor` is `Some` exactly when another matching row exists.
pub(crate) async fn list_attestations_since_by_prefixes_planned(
    dir: &impl ReadPlanStore,
    since: Option<(chrono::DateTime<chrono::Utc>, String)>,
    dimension_prefixes: &[String],
    type_prefixes: &[String],
    limit: i64,
) -> Result<ServedAttestationPage, Error> {
    check_page_limit(limit)?;
    check_serve_prefixes(dimension_prefixes, type_prefixes)?;
    let ServedRows {
        mut rows,
        head,
        bytes,
        backend,
    } = dir
        .read_serve_stream_page(
            ServeNarrowing::Prefixes {
                dimension_prefixes,
                type_prefixes,
            },
            since.as_ref(),
            limit + 1,
        )
        .await?;
    let (next_cursor, high_water) = cut_serve_page(
        &mut rows,
        limit,
        since.as_ref(),
        head,
        "list_attestations_since_by_prefixes",
    )?;
    crate::observe::record_read(
        backend,
        crate::observe::Door::ListAttestationsSinceByPrefixes,
        "*",
        &rows,
        bytes,
    );
    Ok(ServedAttestationPage {
        items: rows,
        next_cursor,
        high_water,
    })
}

/// The read: every backend's `list_owner_bindings_since` (v61.1.0,
/// CIRISPersist#1163, CC 5.4.6). The page is the stream's candidate rows
/// ([`ServeNarrowing::OwnerBindingChanges`]); each node they touch is folded
/// once, NOW, by [`super::admission::announced_owner_state`], and reported
/// at its last row in the page. The fold is the verdict: the SQL only says
/// which nodes to ask about.
pub(crate) async fn list_owner_bindings_since_planned(
    dir: &impl ReadPlanStore,
    since: Option<(chrono::DateTime<chrono::Utc>, String)>,
    limit: i64,
) -> Result<OwnerBindingPage, Error> {
    check_page_limit(limit)?;
    let ServedRows {
        mut rows,
        head,
        bytes,
        backend,
    } = dir
        .read_serve_stream_page(
            ServeNarrowing::OwnerBindingChanges,
            since.as_ref(),
            limit + 1,
        )
        .await?;
    let (next_cursor, high_water) = cut_serve_page(
        &mut rows,
        limit,
        since.as_ref(),
        head,
        "list_owner_bindings_since",
    )?;
    crate::observe::record_read(
        backend,
        crate::observe::Door::ListOwnerBindingsSince,
        "*",
        &rows,
        bytes,
    );
    // Each node at its LAST row in the page, in that order.
    let mut last: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for (i, r) in rows.iter().enumerate() {
        let node = r.attestation.attested_key_id.as_str();
        if !node.is_empty() {
            last.insert(node, i);
        }
    }
    let mut order: Vec<(usize, &str)> = last.into_iter().map(|(n, i)| (i, n)).collect();
    order.sort_unstable();
    let mut items = Vec::with_capacity(order.len());
    for (i, node) in order {
        let state = super::admission::announced_owner_state(dir, node).await?;
        items.push(OwnerBindingChange {
            node_key_id: node.to_owned(),
            state,
            position: rows[i].resume_pair(),
        });
    }
    Ok(OwnerBindingPage {
        items,
        next_cursor,
        high_water,
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
