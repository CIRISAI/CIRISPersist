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

use super::attestation_query::{
    placeholder, prefix_range_clause, Bind, Dialect, QueryRows, Statement,
};
use super::types::{
    AnnouncedOwnerState, Attestation, KeyRegistrationHistoryRow, KeyReplacementKind,
    OwnerBindingChange, ServePage, ServePosition, ServedAttestation,
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
    /// held row), read BEFORE the page, with the commit-safe watermark
    /// ([`serve_settled_before`]) read before the head. The SQL is
    /// [`serve_stream_statement`] and [`serve_stream_head_statement`].
    async fn read_serve_stream_page(
        &self,
        narrowing: ServeNarrowing<'_>,
        since: Option<&ServePosition>,
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

/// v61.1.0 (review D6) — **the one-past-the-page cut** every read that
/// fetches `limit + 1` rows makes: refuse an executor that returned more
/// than one row past the page (it dropped its LIMIT, and its read was as wide
/// as the slice), keep at most `limit` rows, and say whether another row
/// existed. The #1225 subject read and the serve-stream reads cut here.
pub(crate) fn cut_one_past<T>(rows: &mut Vec<T>, limit: i64, door: &str) -> Result<bool, Error> {
    let page =
        usize::try_from(limit).map_err(|_| Error::Backend(format!("{door}: page size {limit}")))?;
    if rows.len() > page + 1 {
        return Err(Error::Backend(format!(
            "{door}: {} rows for a page of {page}",
            rows.len()
        )));
    }
    let more = rows.len() > page;
    rows.truncate(page);
    Ok(more)
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
    let more = cut_one_past(&mut rows, limit, "list_attestations_naming_by_dimension")?;
    let next_cursor = if more {
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

/// v61.1.0 (#1190) — the most family prefixes one narrowed serve read takes.
/// Edge's decision queue names eleven.
pub(crate) const MAX_SERVE_PREFIXES: usize = 64;

/// v61.1.0 (#1190) — the largest page the family read serves (the bound of
/// every other paged read here).
pub(crate) const MAX_SERVE_PAGE: i64 = MAX_PAGE;

/// v61.1.0 (#1163 review M5) — the largest page the owner-binding feed
/// serves. Each node a page touches costs one `announced_owner_state` fold
/// (a live-delegation walk, the owner fold, a self-roster lookup per granter:
/// several directory reads), so the page bounds the call's fold work, not
/// just its rows. 500 is the fold page every other walk here takes
/// (`attestation_query::FOLD_PAGE`), keeps a page well inside one capsule
/// round trip, and at the canonical's announced-relay cadence (a pass a
/// minute) still drains a backlog of tens of thousands of candidate rows in
/// minutes.
pub(crate) const MAX_OWNER_FEED_PAGE: i64 = 500;

/// v61.1.0 (#1190, #1163 review D19) — the stable token a serve-stream read's
/// refused page size leads its message with.
pub(crate) const SERVE_LIMIT_OUT_OF_RANGE: &str = "serve_limit_out_of_range";

/// v61.1.0 (#1190 review D19) — the stable token a refused family-prefix
/// list (none, an empty prefix, too many) leads its message with.
pub(crate) const SERVE_PREFIXES_REFUSED: &str = "serve_prefixes_refused";

/// A serve-stream read's page bound: refused outside `[1, max]`, the message
/// led by [`SERVE_LIMIT_OUT_OF_RANGE`].
fn check_serve_limit(door: &str, limit: i64, max: i64) -> Result<(), Error> {
    if (1..=max).contains(&limit) {
        Ok(())
    } else {
        Err(Error::InvalidArgument(format!(
            "{SERVE_LIMIT_OUT_OF_RANGE}: {door}: limit must be in [1, {max}], got {limit}"
        )))
    }
}

/// v61.1.0 (#1190, #1163) — what narrows a read of the attestation serve
/// stream. The serve rule, the cursor and the order are the stream's own;
/// only the selection differs.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ServeNarrowing<'a> {
    /// The rows whose FAMILY starts with one of `family_prefixes` (#1190):
    /// the family as [`super::row_type::claim_token`] defines it, a `scores`
    /// row's envelope `dimension` and any other row's `attestation_type` (a
    /// composer's verb included). Byte prefixes, case-sensitive, as
    /// half-open ranges: no `LIKE`.
    Families {
        /// Family prefixes.
        family_prefixes: &'a [String],
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
    pub(crate) head: Option<ServePosition>,
    /// The executor's commit-safe watermark, read before the head
    /// ([`serve_settled_before`]): `None` where the head is exact (sqlite).
    pub(crate) settled_before: Option<chrono::DateTime<chrono::Utc>>,
    /// Envelope bytes decoded.
    pub(crate) bytes: u64,
    /// The backend that ran the statement.
    pub(crate) backend: crate::observe::StoreBackend,
}

/// v61.1.0 (#1190, #1163 review D3) — **THE serve rule**, as the predicates
/// over the held row `alias` (tables under the schema `prefix`): the
/// federation tier (E5: a local-tier row never reaches the serve surface),
/// the row-type serve filter (v53.0.0 #975, CC 2.4: under enforcement an
/// unregistered type is neither served nor replicated) and the purge plane
/// (v54.1.0 #1046: a tombstoned row is not served unless the tombstone is
/// void for it). `list_attestations_since` on both backends, the #1225
/// subject read and [`serve_stream_statement`] AND these in; none spells its
/// own. The row-type filter reads the enforcement in force on the calling
/// task, so build on the task, before a closure moves to a pool.
#[must_use]
pub(crate) fn serve_rule_parts(dialect: Dialect, alias: &str, prefix: &str) -> Vec<String> {
    let mut parts = vec![format!(
        "{alias}.tier = '{}'",
        super::types::attestation_tier::FEDERATION
    )];
    parts.extend(super::row_type::serve_filter_sql(
        &format!("{alias}.attestation_type"),
        dialect.row_type(),
    ));
    parts.push(super::steward_purge::served_under_purge_sql(alias, prefix));
    parts
}

/// The dialect-specific spellings the serve-stream statements read. The
/// served row is aliased `fa` on both.
struct ServeSpelling {
    /// `FROM` target, with its alias and, on sqlite, its index pin.
    from: &'static str,
    /// The serve position expression (the V130 index's).
    pos: &'static str,
}

/// The sqlite spelling. The position expression is the V130
/// `federation_attestations_admitted` index's (sqlite matches an indexed
/// expression by the columns it resolves to, so the `fa.` qualifier is the
/// index's own expression), and the walk is pinned to that index
/// (`INDEXED BY`): unpinned and without statistics, a prefix narrowing can
/// take a dimension index and sort the family's whole history on every poll.
/// I1579 EXPLAINs both statements.
const SQLITE_SERVE: ServeSpelling = ServeSpelling {
    from: "federation_attestations fa INDEXED BY federation_attestations_admitted",
    pos: "COALESCE(fa.admitted_at, fa.promoted_at, fa.asserted_at)",
};

/// The postgres spelling: `admitted_at` is NOT NULL (V130), and
/// `(admitted_at, attestation_id)` is the `federation_attestations_admitted`
/// index.
const POSTGRES_SERVE: ServeSpelling = ServeSpelling {
    from: "cirislens.federation_attestations fa",
    pos: "fa.admitted_at",
};

fn serve_spelling(dialect: Dialect) -> &'static ServeSpelling {
    match dialect {
        Dialect::Sqlite => &SQLITE_SERVE,
        Dialect::Postgres => &POSTGRES_SERVE,
    }
}

/// v61.1.0 (#1190 review D13) — "the row `o`'s family starts with one of
/// `prefixes`" as SQL, the family as [`super::row_type::claim_token`] reads
/// it: a `scores` row by its `dimension`, every other row by its
/// `attestation_type`. Each prefix is one half-open range per arm
/// ([`prefix_range_clause`]). An empty list selects nothing.
pub(crate) fn family_prefix_sql(
    dialect: Dialect,
    o: &str,
    prefixes: &[String],
    binds: &mut Vec<Bind>,
) -> String {
    use super::types::attestation_type as at;
    if prefixes.is_empty() {
        return "1 = 0".to_owned();
    }
    let mut by_dimension = Vec::with_capacity(prefixes.len());
    let mut by_type = Vec::with_capacity(prefixes.len());
    for p in prefixes {
        by_dimension.push(prefix_range_clause(
            dialect,
            &format!("{o}.dimension"),
            p,
            binds,
        ));
        by_type.push(prefix_range_clause(
            dialect,
            &format!("{o}.attestation_type"),
            p,
            binds,
        ));
    }
    format!(
        "(({o}.attestation_type = '{scores}' AND ({dims})) \
          OR ({o}.attestation_type <> '{scores}' AND ({types})))",
        scores = at::SCORES,
        dims = by_dimension.join(" OR "),
        types = by_type.join(" OR "),
    )
}

/// `t` is an owner-binding row by its envelope, as
/// `admission::is_owner_binding_envelope` reads it: the ownership dimension,
/// or the CC 2.4.1.2 `delegation_purpose` marker. I1674 holds the two equal
/// over a set of envelopes on both backends.
pub(crate) fn owner_binding_marker_sql(dialect: Dialect, t: &str) -> String {
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
/// `narrowing`'s rows under the serve rule ([`serve_rule_parts`]), strictly
/// after `since` on `(serve position, attestation_id)` ([`ServePosition`];
/// the origin reads from the start), ascending, `LIMIT fetch`. It walks the
/// V130 `federation_attestations_admitted` index from the cursor.
pub(crate) fn serve_stream_statement(
    dialect: Dialect,
    narrowing: ServeNarrowing<'_>,
    since: Option<&ServePosition>,
    fetch: i64,
) -> Statement {
    use super::types::attestation_type as at;
    let sp = serve_spelling(dialect);
    let prefix = dialect.schema_prefix();
    let mut binds: Vec<Bind> = Vec::new();
    let mut parts: Vec<String> = Vec::new();
    match narrowing {
        ServeNarrowing::Families { family_prefixes } => {
            // An empty list never reaches here (`check_serve_prefixes`);
            // were it to, it selects nothing rather than everything.
            parts.push(family_prefix_sql(
                dialect,
                "fa",
                family_prefixes,
                &mut binds,
            ));
        }
        ServeNarrowing::OwnerBindingChanges => {
            parts.push(format!(
                "fa.attestation_type IN ('{}', '{}', '{}', '{}')",
                at::DELEGATES_TO,
                at::SUPERSEDES,
                at::WITHDRAWS,
                at::RECANTS
            ));
            parts.push(format!(
                "((fa.attestation_type = '{dt}' AND {own}) \
                  OR (fa.attestation_type <> '{dt}' AND EXISTS ( \
                      SELECT 1 FROM {prefix}federation_attestations ob \
                       WHERE ob.attested_key_id = fa.attested_key_id \
                         AND ob.attestation_type = '{dt}' AND {ob})))",
                dt = at::DELEGATES_TO,
                own = owner_binding_marker_sql(dialect, "fa"),
                ob = owner_binding_marker_sql(dialect, "ob"),
            ));
        }
    }
    parts.extend(serve_rule_parts(dialect, "fa", prefix));
    if let Some((at_, id)) = ServePosition::resume_after(since) {
        binds.push(Bind::Time(at_));
        let a = placeholder(dialect, &binds);
        binds.push(Bind::Text(id));
        let b = placeholder(dialect, &binds);
        parts.push(match dialect {
            // `list_attestations_since`'s OR form, over the index's own
            // expression, behind a `>=` the planner can seek on: the OR
            // alone is not a range, and the walk would start at the oldest
            // row on every page.
            Dialect::Sqlite => format!(
                "({pos} >= {a} AND ({pos} > {a} OR fa.attestation_id > {b}))",
                pos = sp.pos,
            ),
            Dialect::Postgres => format!("({}, fa.attestation_id) > ({a}, {b})", sp.pos),
        });
    }
    binds.push(Bind::Int(fetch));
    let limit = placeholder(dialect, &binds);
    Statement {
        sql: format!(
            "SELECT {columns}, {pos} AS _pos FROM {from} WHERE {} \
             ORDER BY {pos} ASC, fa.attestation_id ASC LIMIT {limit}",
            parts.join(" AND "),
            columns = dialect.fa_columns(),
            from = sp.from,
            pos = sp.pos,
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
        Dialect::Sqlite => "fa.attestation_id",
        Dialect::Postgres => "fa.attestation_id::text",
    };
    Statement {
        sql: format!(
            "SELECT {pos} AS _pos, {selected_id} AS attestation_id FROM {from} \
             ORDER BY {pos} DESC, fa.attestation_id DESC LIMIT 1",
            pos = sp.pos,
            from = sp.from,
        ),
        binds: Vec::new(),
    }
}

/// v61.1.0 (#1190, #1163 review R2/H4) — on postgres, how long a serve
/// position may stay in flight: a writer assigns it
/// (`next_plane_position`: `MAX(admitted_at)`, then its clock) BEFORE its
/// write transaction, and commits it some time later, so a row can commit
/// below a head a reader has already seen. A position assigned more than
/// this long before the read is taken as committed.
///
/// WHY A LAG WINDOW, not the minimum position in flight: the in-flight
/// positions are not visible to a reader (they are uncommitted rows, and the
/// position is assigned before the transaction even begins), so the minimum
/// could only come from a registry every writer, in every process sharing
/// the database, joins before it reads `MAX(admitted_at)`: a migration and a
/// change to every write door. The position is the writer's wall clock (or
/// just above the committed maximum, which only moves it later), so "assigned
/// more than LAG ago" is readable from the position itself. The span it must
/// cover is the write door's: the in-process delegation lock is taken before
/// the position, so it is the transaction (the advisory cycle lock, the
/// cycle re-check, the insert and its projections), normally milliseconds.
/// 30 s is three orders of magnitude above that and costs an idle poller one
/// re-read of the last 30 s of the stream (at most a page). The window
/// assumes writer clocks within it of the reader's. BELIEVED, not enforced:
/// a write transaction held open past it can still commit below a high
/// water; a `statement_timeout` / `idle_in_transaction_session_timeout`
/// under it would make the bound hard.
pub(crate) const PG_SERVE_COMMIT_LAG_SECS: i64 = 30;

/// v61.1.0 (#1190, #1163 review R2/H4) — the executor's commit-safe
/// watermark at `now` (its clock, read BEFORE the head and the page):
/// `None` on sqlite, whose head is exact (its one writer assigns the
/// position inside the write transaction, above every committed position);
/// `now − PG_SERVE_COMMIT_LAG_SECS` on postgres.
#[must_use]
pub(crate) fn serve_settled_before(
    dialect: Dialect,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    match dialect {
        Dialect::Sqlite => None,
        Dialect::Postgres => Some(now - chrono::TimeDelta::seconds(PG_SERVE_COMMIT_LAG_SECS)),
    }
}

/// v61.1.0 (#1190, #1163 review R2/H4) — the head a resume may start from:
/// the head itself when it is below the watermark (or there is none), else
/// the watermark as a position before every row at its instant. Every
/// position below what this returns was settled when the read ran.
#[must_use]
pub(crate) fn commit_safe_head(
    head: Option<ServePosition>,
    settled_before: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<ServePosition> {
    match (head, settled_before) {
        (Some(h), Some(w)) if h.admitted_at >= w => Some(ServePosition::new(w, String::new())),
        (head, _) => head,
    }
}

/// The narrowed serve read's refusals, led by [`SERVE_PREFIXES_REFUSED`]: no
/// prefix at all (that read is `list_attestations_since`), an empty prefix
/// (it would select every row), or more than [`MAX_SERVE_PREFIXES`].
fn check_serve_prefixes(family_prefixes: &[String]) -> Result<(), Error> {
    let door = "list_attestations_since_by_prefixes";
    let n = family_prefixes.len();
    if n == 0 {
        return Err(Error::InvalidArgument(format!(
            "{SERVE_PREFIXES_REFUSED}: {door}: name at least one family prefix; the \
             unnarrowed stream is list_attestations_since"
        )));
    }
    if n > MAX_SERVE_PREFIXES {
        return Err(Error::InvalidArgument(format!(
            "{SERVE_PREFIXES_REFUSED}: {door}: {n} prefixes, at most {MAX_SERVE_PREFIXES}"
        )));
    }
    if family_prefixes.iter().any(String::is_empty) {
        return Err(Error::InvalidArgument(format!(
            "{SERVE_PREFIXES_REFUSED}: {door}: an empty prefix matches every row"
        )));
    }
    Ok(())
}

/// Cut a serve-stream page fetched one row past `limit` ([`cut_one_past`]):
/// `next_cursor` is `Some` exactly when that row exists, and `high_water`
/// is the furthest position this read examined that is safe to resume from
/// ([`super::types::ServePage::high_water`]).
pub(crate) fn cut_serve_page(
    rows: &mut Vec<ServedAttestation>,
    limit: i64,
    since: Option<&ServePosition>,
    head: Option<ServePosition>,
    settled_before: Option<chrono::DateTime<chrono::Utc>>,
    door: &str,
) -> Result<(Option<ServePosition>, ServePosition), Error> {
    if cut_one_past(rows, limit, door)? {
        let next = rows
            .last()
            .map(ServedAttestation::serve_position)
            .ok_or_else(|| Error::Backend(format!("{door}: more past an empty page")))?;
        return Ok((Some(next.clone()), next));
    }
    // Nothing remains past the page: every held row up to the head read
    // before it was examined, so a resume from the head skips nothing this
    // read could have served, once the head is clamped below any position
    // still in flight.
    let high_water = [
        since.cloned(),
        rows.last().map(ServedAttestation::serve_position),
        commit_safe_head(head, settled_before),
    ]
    .into_iter()
    .flatten()
    .max()
    .unwrap_or_else(ServePosition::origin);
    Ok((None, high_water))
}

/// The read: every backend's `list_attestations_since_by_prefixes` (v61.1.0,
/// CIRISPersist#1190). The executor fetches one row past the page, so
/// `next_cursor` is `Some` exactly when another matching row exists.
pub(crate) async fn list_attestations_since_by_prefixes_planned(
    dir: &impl ReadPlanStore,
    since: Option<ServePosition>,
    family_prefixes: &[String],
    limit: i64,
) -> Result<ServePage<ServedAttestation>, Error> {
    let door = "list_attestations_since_by_prefixes";
    check_serve_limit(door, limit, MAX_SERVE_PAGE)?;
    check_serve_prefixes(family_prefixes)?;
    let ServedRows {
        mut rows,
        head,
        settled_before,
        bytes,
        backend,
    } = dir
        .read_serve_stream_page(
            ServeNarrowing::Families { family_prefixes },
            since.as_ref(),
            limit + 1,
        )
        .await?;
    let (next_cursor, high_water) =
        cut_serve_page(&mut rows, limit, since.as_ref(), head, settled_before, door)?;
    crate::observe::record_read(
        backend,
        crate::observe::Door::ListAttestationsSinceByPrefixes,
        "*",
        &rows,
        bytes,
    );
    Ok(ServePage {
        items: rows,
        next_cursor,
        high_water,
    })
}

/// v61.1.0 (#1163 review M5) — the owner-binding feed's items: each node the
/// page's `rows` touch, at its LAST row in the page, in that order, with
/// `fold`'s answer for it. A fold that fails for a node is that node's item
/// ([`AnnouncedOwnerState::Unresolved`]), never the page's failure: one node
/// whose fold errors must not stall the cursor for every other node.
pub(crate) async fn owner_binding_items<'r, F, Fut>(
    rows: &'r [ServedAttestation],
    fold: F,
) -> Vec<OwnerBindingChange>
where
    F: Fn(&'r str) -> Fut,
    Fut: std::future::Future<Output = Result<AnnouncedOwnerState, Error>>,
{
    let mut last: std::collections::BTreeMap<&'r str, usize> = std::collections::BTreeMap::new();
    for (i, r) in rows.iter().enumerate() {
        let node = r.attestation.attested_key_id.as_str();
        if !node.is_empty() {
            last.insert(node, i);
        }
    }
    let mut order: Vec<(usize, &'r str)> = last.into_iter().map(|(n, i)| (i, n)).collect();
    order.sort_unstable();
    let mut items = Vec::with_capacity(order.len());
    for (i, node) in order {
        let state = match fold(node).await {
            Ok(state) => state,
            Err(e) => AnnouncedOwnerState::Unresolved {
                reason: e.to_string(),
            },
        };
        items.push(OwnerBindingChange {
            node_key_id: node.to_owned(),
            state,
            position: rows[i].serve_position(),
        });
    }
    items
}

/// The read: every backend's `list_owner_bindings_since` (v61.1.0,
/// CIRISPersist#1163, CC 5.4.6). The page is the stream's candidate rows
/// ([`ServeNarrowing::OwnerBindingChanges`]), at most
/// [`MAX_OWNER_FEED_PAGE`]; each node they touch is folded once, NOW, by
/// [`super::admission::announced_owner_state`], and reported at its last row
/// in the page ([`owner_binding_items`]). The fold is the verdict: the SQL
/// only says which nodes to ask about.
pub(crate) async fn list_owner_bindings_since_planned(
    dir: &impl ReadPlanStore,
    since: Option<ServePosition>,
    limit: i64,
) -> Result<ServePage<OwnerBindingChange>, Error> {
    let door = "list_owner_bindings_since";
    check_serve_limit(door, limit, MAX_OWNER_FEED_PAGE)?;
    let ServedRows {
        mut rows,
        head,
        settled_before,
        bytes,
        backend,
    } = dir
        .read_serve_stream_page(
            ServeNarrowing::OwnerBindingChanges,
            since.as_ref(),
            limit + 1,
        )
        .await?;
    let (next_cursor, high_water) =
        cut_serve_page(&mut rows, limit, since.as_ref(), head, settled_before, door)?;
    crate::observe::record_read(
        backend,
        crate::observe::Door::ListOwnerBindingsSince,
        "*",
        &rows,
        bytes,
    );
    let items = owner_binding_items(&rows, |node| {
        super::admission::announced_owner_state(dir, node)
    })
    .await;
    Ok(ServePage {
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
