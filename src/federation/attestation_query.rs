//! v56.0.0 (CIRISPersist#1001) — **the typed bounded attestation read.**
//!
//! One read replaces `list_attestations_by` / `list_attestations_for` and
//! their narrowed siblings: an [`AttestationQuery`] names the axes it pins
//! (`by`, `to`), the dimension and types it narrows to, the tier, the order,
//! a REQUIRED page size and an optional cursor, and returns one [`Page`].
//! There is no default limit and no "every row" form: a caller that truly
//! needs every row loops over [`Pages`], and the loop is visible at its call
//! site.
//!
//! **Shared plan, per-backend execution.** The statement is planned here
//! ([`render_sql`]: one parameterised `SELECT … LIMIT n + 1` per query, the
//! same predicate on sqlite and postgres) and the memory backend evaluates
//! the same predicate ([`AttestationQuery::admits`]). Each backend's
//! [`FederationDirectory::execute_attestation_query`] is storage only: run
//! the statement, map the rows. The page is cut, the cursor minted and the
//! read recorded ONCE, in [`AttestationReads::query_attestations`] — the read
//! probe and the per-door counters are a property of this wrapper, not of
//! any backend method.
//!
//! **Order and cursor.** Rows come in `(asserted_at, attestation_id)` order
//! ([`QueryOrder::ByAssertedAt`], descending by default): the SIGNED instant,
//! never receipt time, with the id as the deterministic tie-break. The cursor
//! is the trailing row's pair, the same [`AttestationCursor`] the paged read
//! surfaces use. The backend fetches one row past the limit, so `next` is
//! `Some` exactly when another row exists.
//!
//! **Replayable as of an instant.** [`AttestationQuery::as_of`] keeps only
//! rows whose signed `asserted_at <= t` (CIRISServer `FSD/TOPOLOGY.md` §4.1,
//! CIRISConstitution#131 §5): a fold `V(rows, t)` over the pages of an
//! `as_of(t)` query is the same on every node and at every later moment,
//! because no row a later write lands can enter it unless its signer dated it
//! at or before `t`. The bound is one more range term on the same index.
//!
//! **Error is not empty.** [`AttestationReads::query_attestations`] returns a
//! [`ReadOutcome`]: [`ReadOutcome::Served`] with a [`Page`] (possibly empty —
//! the store answered, and nothing matched) or [`ReadOutcome::NotServed`] with
//! the reason (the query was refused, or the backend failed). A refused or
//! failed read cannot be read as "no rows": the empty page exists only inside
//! `Served` (CIRISClient `CSD.md` v3.0 §2, CSD/3 rule 3; CIRISRegistry
//! `FSD/CSD/README.md`).
//!
//! [`FederationDirectory::execute_attestation_query`]: super::FederationDirectory::execute_attestation_query

use std::num::NonZeroU32;

use chrono::{DateTime, Utc};

use super::{Attestation, Error};
use crate::ceg::list::federation::AttestationCursor;

/// The largest page one statement may return. A page size is a bound, not
/// a formality: a limit above this is refused at the wrapper, so no caller
/// can spell "every row" as one huge page.
pub const MAX_PAGE: u32 = 10_000;

/// A `const` [`NonZeroU32`] page size. Panics at compile time on `0` (the
/// only use is in `const` items).
#[must_use]
pub const fn page_size(n: u32) -> NonZeroU32 {
    match NonZeroU32::new(n) {
        Some(n) => n,
        None => panic!("a page size is at least 1"),
    }
}

/// The page size of a fold that walks every matching row through [`Pages`]:
/// large enough that a typical slice is one statement, small enough that no
/// page is a history. Under `cfg(test)` it is 3, so every fold's witness
/// walks more than one page and exercises the cursor on its own fixture.
pub const FOLD_PAGE: NonZeroU32 = if cfg!(test) {
    page_size(3)
} else {
    page_size(500)
};

/// What the query asks of the envelope's top-level `dimension`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DimensionFilter {
    /// Any dimension, and none.
    #[default]
    Any,
    /// A byte prefix — the #817/#818 half-open range, never `LIKE`.
    Prefix(String),
    /// Exactly this dimension.
    Exact(String),
}

/// Which storage tier the rows come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QueryTier {
    /// The signed, replicated tier — every read the directory serves.
    #[default]
    Federation,
    /// The node-local tier.
    Local,
}

impl QueryTier {
    /// The stored `tier` value.
    #[must_use]
    pub const fn stored(self) -> &'static str {
        match self {
            QueryTier::Federation => crate::federation::types::attestation_tier::FEDERATION,
            QueryTier::Local => crate::federation::types::attestation_tier::LOCAL,
        }
    }
}

/// A sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Ascending (oldest first).
    Asc,
    /// Descending (newest first).
    Desc,
}

/// The order rows come in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryOrder {
    /// By the row's SIGNED `asserted_at` (never receipt time), ties broken by
    /// `attestation_id` (byte order), so the order — and every page cut from
    /// it — is the same on every backend and every replay.
    ByAssertedAt(Direction),
}

impl Default for QueryOrder {
    fn default() -> Self {
        QueryOrder::ByAssertedAt(Direction::Desc)
    }
}

impl QueryOrder {
    /// The direction.
    #[must_use]
    pub const fn direction(self) -> Direction {
        match self {
            QueryOrder::ByAssertedAt(d) => d,
        }
    }
}

/// One bounded attestation read. Built with [`AttestationQuery::by`] or
/// [`AttestationQuery::to`] (a query always pins a key), narrowed by the
/// builder methods, executed by [`AttestationReads::query_attestations`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationQuery {
    /// Rows `by` authored (`attesting_key_id`).
    pub by: Option<String>,
    /// Rows attested to `to` (`attested_key_id`).
    pub to: Option<String>,
    /// The envelope `dimension` narrowing.
    pub dimension: DimensionFilter,
    /// `attestation_type` is one of these; empty is any type.
    pub types: Vec<String>,
    /// `attestation_type` starts with this byte prefix (the half-open range
    /// on the `(key, attestation_type, …)` index; never `LIKE`). For a row
    /// family whose type slot carries a variable suffix — the retired rc6
    /// `holds_bytes:sha256:{prefix}` carrier.
    pub type_prefix: Option<String>,
    /// The envelope `dimension` is none of these (absent and non-string
    /// dimensions are kept).
    pub excluded_dimensions: Vec<String>,
    /// The storage tier.
    pub tier: QueryTier,
    /// The row order.
    pub order: QueryOrder,
    /// The page size. Required; there is no default.
    pub limit: NonZeroU32,
    /// Start after this row (exclusive), in [`Self::order`].
    pub after: Option<AttestationCursor>,
    /// Only rows whose SIGNED `asserted_at` is at or before this instant.
    pub as_of: Option<DateTime<Utc>>,
}

impl AttestationQuery {
    fn pinned(by: Option<String>, to: Option<String>, limit: NonZeroU32) -> Self {
        Self {
            by,
            to,
            dimension: DimensionFilter::Any,
            types: Vec::new(),
            type_prefix: None,
            excluded_dimensions: Vec::new(),
            tier: QueryTier::Federation,
            order: QueryOrder::ByAssertedAt(Direction::Desc),
            limit,
            after: None,
            as_of: None,
        }
    }

    /// The rows `attesting_key_id` authored, `limit` per page.
    #[must_use]
    pub fn by(attesting_key_id: &str, limit: NonZeroU32) -> Self {
        Self::pinned(Some(attesting_key_id.to_owned()), None, limit)
    }

    /// The rows attested to `attested_key_id`, `limit` per page.
    #[must_use]
    pub fn to(attested_key_id: &str, limit: NonZeroU32) -> Self {
        Self::pinned(None, Some(attested_key_id.to_owned()), limit)
    }

    /// Also pin the attester.
    #[must_use]
    pub fn authored_by(mut self, attesting_key_id: &str) -> Self {
        self.by = Some(attesting_key_id.to_owned());
        self
    }

    /// Also pin the attested key.
    #[must_use]
    pub fn attested_to(mut self, attested_key_id: &str) -> Self {
        self.to = Some(attested_key_id.to_owned());
        self
    }

    /// Only rows whose envelope `dimension` starts with `prefix`.
    #[must_use]
    pub fn dimension_prefix(mut self, prefix: &str) -> Self {
        self.dimension = DimensionFilter::Prefix(prefix.to_owned());
        self
    }

    /// Only rows whose envelope `dimension` is exactly `dimension`.
    #[must_use]
    pub fn dimension(mut self, dimension: &str) -> Self {
        self.dimension = DimensionFilter::Exact(dimension.to_owned());
        self
    }

    /// Only rows whose `attestation_type` is one of `types`.
    #[must_use]
    pub fn types(mut self, types: &[&str]) -> Self {
        self.types = types.iter().map(|t| (*t).to_owned()).collect();
        self
    }

    /// Only rows whose `attestation_type` starts with `prefix`.
    #[must_use]
    pub fn type_prefix(mut self, prefix: &str) -> Self {
        self.type_prefix = Some(prefix.to_owned());
        self
    }

    /// Drop rows whose envelope `dimension` is one of `dimensions`.
    #[must_use]
    pub fn excluding_dimensions(mut self, dimensions: &[&str]) -> Self {
        self.excluded_dimensions = dimensions.iter().map(|d| (*d).to_owned()).collect();
        self
    }

    /// Read the node-local tier instead of the federation tier.
    #[must_use]
    pub fn tier(mut self, tier: QueryTier) -> Self {
        self.tier = tier;
        self
    }

    /// Oldest first (`ByAssertedAt(Asc)`).
    #[must_use]
    pub fn oldest_first(mut self) -> Self {
        self.order = QueryOrder::ByAssertedAt(Direction::Asc);
        self
    }

    /// Order by the signed instant in `direction`.
    #[must_use]
    pub fn order(mut self, order: QueryOrder) -> Self {
        self.order = order;
        self
    }

    /// Only rows whose signed `asserted_at <= t`.
    #[must_use]
    pub fn as_of(mut self, t: DateTime<Utc>) -> Self {
        self.as_of = Some(t);
        self
    }

    /// Start after `cursor`.
    #[must_use]
    pub fn after(mut self, cursor: Option<AttestationCursor>) -> Self {
        self.after = cursor;
        self
    }

    /// Whether the query narrows below its pinned key's whole slice (a type,
    /// a dimension, or an exclusion). A witness's "slice read" is a query
    /// that does not.
    #[must_use]
    pub fn is_narrowed(&self) -> bool {
        !self.types.is_empty()
            || self.type_prefix.is_some()
            || self.dimension != DimensionFilter::Any
            || !self.excluded_dimensions.is_empty()
    }

    /// Whether a narrower index than the key's `(key, asserted_at)` one
    /// serves the query (a type or a dimension pins a `(key, type, …)` /
    /// `(key, dimension)` prefix). An exclusion alone does not: it is a
    /// filter on the key's ordered walk.
    #[must_use]
    pub fn seeks_narrow_index(&self) -> bool {
        !self.types.is_empty()
            || self.type_prefix.is_some()
            || self.dimension != DimensionFilter::Any
    }

    /// The read this query's shape replaced (v56.0.0, CIRISPersist#1001):
    /// the name a fault double, a read probe and an operator's log use for
    /// it, stable across the retirement of the reads themselves.
    ///
    /// | query shape                               | shape                                     |
    /// |-------------------------------------------|-------------------------------------------|
    /// | `tier = local`                            | `list_local_tier_attestations`            |
    /// | `by` K, not narrowed                      | `list_attestations_by`                    |
    /// | `to` K, not narrowed (any `by`)           | `list_attestations_for`                   |
    /// | `by` K + dimension                        | `list_attestations_by_dimension_prefix`   |
    /// | `to` K + dimension                        | `list_attestations_for_dimension_prefix`  |
    /// | `by` K + one type, no exclusion           | `list_attestations_by_type`               |
    /// | `to` K + one type, no exclusion           | `list_attestations_for_type`              |
    /// | `by` K + types, or a type prefix          | `list_attestations_by_types`              |
    /// | `to` K + types, or a type prefix          | `list_attestations_for_types`             |
    ///
    /// An exclusion alone (no type, no dimension) filters the key's whole
    /// ordered slice: it is the slice read's shape.
    #[must_use]
    pub fn shape(&self) -> &'static str {
        if self.tier == QueryTier::Local {
            return "list_local_tier_attestations";
        }
        let to = self.to.is_some();
        let dim = self.dimension != DimensionFilter::Any;
        if self.type_prefix.is_some() && !dim {
            return if to {
                "list_attestations_for_types"
            } else {
                "list_attestations_by_types"
            };
        }
        match (dim, self.types.len(), to) {
            (true, _, false) => "list_attestations_by_dimension_prefix",
            (true, _, true) => "list_attestations_for_dimension_prefix",
            (false, 0, false) => "list_attestations_by",
            (false, 0, true) => "list_attestations_for",
            (false, 1, false) if self.excluded_dimensions.is_empty() => "list_attestations_by_type",
            (false, 1, true) if self.excluded_dimensions.is_empty() => "list_attestations_for_type",
            (false, _, false) => "list_attestations_by_types",
            (false, _, true) => "list_attestations_for_types",
        }
    }

    /// The key the query is pinned on, for the probe: the attester, else the
    /// attested key.
    #[must_use]
    pub fn key(&self) -> &str {
        self.by.as_deref().or(self.to.as_deref()).unwrap_or("*")
    }

    /// Refuse a query no backend may run: no pinned key, a page above
    /// [`MAX_PAGE`], or a cursor of an unknown version.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] naming the defect.
    pub fn validate(&self) -> Result<(), Error> {
        if self.by.is_none() && self.to.is_none() {
            return Err(Error::InvalidArgument(
                "AttestationQuery pins no key (by or to)".to_owned(),
            ));
        }
        if self.limit.get() > MAX_PAGE {
            return Err(Error::InvalidArgument(format!(
                "AttestationQuery limit {} exceeds {MAX_PAGE}",
                self.limit
            )));
        }
        if let Some(c) = &self.after {
            if c.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "AttestationCursor version {} unsupported; v1 only",
                    c.version
                )));
            }
        }
        Ok(())
    }

    /// The query's predicate on one row, cursor included — what the memory
    /// backend evaluates and what [`render_sql`]'s WHERE clause states.
    #[must_use]
    pub fn admits(&self, a: &Attestation) -> bool {
        let dimension = super::admission::envelope_dimension(&a.attestation_envelope);
        self.by.as_deref().is_none_or(|k| a.attesting_key_id == k)
            && self.to.as_deref().is_none_or(|k| a.attested_key_id == k)
            && a.tier == self.tier.stored()
            && match &self.dimension {
                DimensionFilter::Any => true,
                DimensionFilter::Prefix(p) => dimension.is_some_and(|d| d.starts_with(p.as_str())),
                DimensionFilter::Exact(x) => dimension == Some(x.as_str()),
            }
            && (self.types.is_empty() || self.types.contains(&a.attestation_type))
            && self
                .type_prefix
                .as_deref()
                .is_none_or(|p| a.attestation_type.starts_with(p))
            && !dimension.is_some_and(|d| self.excluded_dimensions.iter().any(|x| x == d))
            && self.as_of.is_none_or(|t| a.asserted_at <= t)
            && self.after.as_ref().is_none_or(|c| {
                let here = (a.asserted_at, a.attestation_id.as_str());
                let mark = (c.last_asserted_at, c.last_attestation_id.as_str());
                match self.order.direction() {
                    Direction::Desc => here < mark,
                    Direction::Asc => here > mark,
                }
            })
    }

    /// Sort `rows` into the query's order (the memory backend's ORDER BY).
    pub fn sort(&self, rows: &mut [Attestation]) {
        rows.sort_by(|a, b| {
            let o = (a.asserted_at, a.attestation_id.as_str())
                .cmp(&(b.asserted_at, b.attestation_id.as_str()));
            match self.order.direction() {
                Direction::Desc => o.reverse(),
                Direction::Asc => o,
            }
        });
    }

    /// Rows a backend fetches: one past the page, so the wrapper knows
    /// whether another page exists without a second statement.
    #[must_use]
    pub fn fetch(&self) -> usize {
        self.limit.get() as usize + 1
    }

    /// A walk over every page of this query, one statement per page.
    #[must_use]
    pub fn pages(self) -> Pages {
        Pages {
            query: self,
            done: false,
            last: None,
        }
    }
}

/// What a backend's executor returns: at most [`AttestationQuery::fetch`]
/// rows in the query's order, the envelope bytes it decoded (the per-door
/// telemetry's definition) and which backend ran it.
#[derive(Debug)]
pub struct QueryRows {
    /// The rows, in order, at most `limit + 1`.
    pub rows: Vec<Attestation>,
    /// Envelope bytes decoded.
    pub bytes: u64,
    /// The backend that ran the statement.
    pub backend: crate::observe::StoreBackend,
}

/// One page of a query.
#[derive(Debug, Clone, PartialEq)]
pub struct Page {
    /// At most `limit` rows, in the query's order.
    pub rows: Vec<Attestation>,
    /// The cursor of the next page; `None` when this page is the last.
    pub next: Option<AttestationCursor>,
}

/// A visible walk over every page of a query: each [`Pages::next`] is one
/// bounded statement. Hold it in a `while let` at the call site.
#[derive(Debug, Clone)]
pub struct Pages {
    query: AttestationQuery,
    done: bool,
    /// The cursor the previous page returned: the next one must differ, or
    /// the walk would never end.
    last: Option<AttestationCursor>,
}

impl Pages {
    /// The next page's rows, or `None` once the last page was returned.
    ///
    /// # Errors
    ///
    /// Whatever the read returns; [`Error::Backend`] when a page returns the
    /// same cursor as the page before it (a cursor the executor ignored —
    /// the walk would repeat that page forever).
    pub async fn next<E: AttestationQueryExec + ?Sized>(
        &mut self,
        dir: &E,
    ) -> Result<Option<Vec<Attestation>>, Error> {
        if self.done {
            return Ok(None);
        }
        let page = dir.query_attestations(&self.query).await.served()?;
        match page.next {
            Some(c) => {
                if self.last.as_ref() == Some(&c) {
                    return Err(Error::Backend(format!(
                        "attestation query cursor did not advance past ({}, {})",
                        c.last_asserted_at, c.last_attestation_id
                    )));
                }
                self.last = Some(c.clone());
                self.query.after = Some(c);
            }
            None => self.done = true,
        }
        Ok(Some(page.rows))
    }
}

/// The storage half of the read: run one query's statement. Every
/// [`FederationDirectory`](super::FederationDirectory) answers it through
/// [`FederationDirectory::execute_attestation_query`](super::FederationDirectory::execute_attestation_query);
/// the postgres backend also answers it on a transaction's own client (the
/// delegation-cycle gate's walk under its advisory lock, I602).
#[async_trait::async_trait]
pub trait AttestationQueryExec: Send + Sync {
    /// Run `q`'s one statement: at most `q.fetch()` rows in `q`'s order.
    /// Storage only — no page cut, no probe.
    async fn run_attestation_query(&self, q: &AttestationQuery) -> Result<QueryRows, Error>;
}

#[async_trait::async_trait]
impl<D> AttestationQueryExec for D
where
    D: super::FederationDirectory + ?Sized,
{
    async fn run_attestation_query(&self, q: &AttestationQuery) -> Result<QueryRows, Error> {
        super::FederationDirectory::execute_attestation_query(self, q).await
    }
}

/// Why a read was not served. Never a row count: a refused or failed read
/// carries its reason, and only [`ReadOutcome::Served`] carries rows.
#[derive(Debug)]
pub enum NotServedReason {
    /// The query was refused before any statement ran
    /// ([`AttestationQuery::validate`]: no pinned key, a page above
    /// [`MAX_PAGE`], an unknown cursor version), or the directory does not
    /// serve this read at all (a proxy's `Unsupported`).
    Refused(Error),
    /// The backend failed: the statement errored, or the executor broke the
    /// page contract (returned rows past `limit + 1`, a dropped LIMIT).
    Fault(Error),
}

impl NotServedReason {
    /// The underlying error.
    #[must_use]
    pub fn into_error(self) -> Error {
        match self {
            NotServedReason::Refused(e) | NotServedReason::Fault(e) => e,
        }
    }
}

/// The outcome of one typed read: served (with a page, possibly empty) or not
/// served (with the reason). The two are structurally distinct: "the store
/// answered and nothing matched" is `Served` with zero rows, and nothing else
/// is.
#[derive(Debug)]
#[must_use = "a read outcome may be NotServed; an ignored outcome is an ignored error"]
pub enum ReadOutcome {
    /// The store answered; the page holds what matched (maybe nothing).
    Served(Page),
    /// The store did not answer; the reason says why.
    NotServed(NotServedReason),
}

impl ReadOutcome {
    /// The page, or the reason as an error — the `?` form every fold uses:
    /// a not-served read propagates as an error and can never become an
    /// empty row set.
    ///
    /// # Errors
    ///
    /// The [`NotServedReason`]'s error.
    pub fn served(self) -> Result<Page, Error> {
        match self {
            ReadOutcome::Served(p) => Ok(p),
            ReadOutcome::NotServed(r) => Err(r.into_error()),
        }
    }

    /// Whether the store answered.
    #[must_use]
    pub fn is_served(&self) -> bool {
        matches!(self, ReadOutcome::Served(_))
    }
}

/// The read every caller makes: validate, run, cut the page, mint the
/// cursor, and record the read once (the per-door counters and, under test,
/// the read probe). Blanket-implemented, so no implementor can override it.
#[async_trait::async_trait]
pub trait AttestationReads: AttestationQueryExec {
    /// One page of `q`, or why it was not served.
    async fn query_attestations(&self, q: &AttestationQuery) -> ReadOutcome;
}

#[async_trait::async_trait]
impl<E: AttestationQueryExec + ?Sized> AttestationReads for E {
    async fn query_attestations(&self, q: &AttestationQuery) -> ReadOutcome {
        if let Err(e) = q.validate() {
            return ReadOutcome::NotServed(NotServedReason::Refused(e));
        }
        let QueryRows {
            mut rows,
            bytes,
            backend,
        } = match self.run_attestation_query(q).await {
            Ok(r) => r,
            Err(e @ Error::Unsupported { .. }) => {
                return ReadOutcome::NotServed(NotServedReason::Refused(e))
            }
            Err(e) => return ReadOutcome::NotServed(NotServedReason::Fault(e)),
        };
        // The bound is the wrapper's to enforce, not each backend's to
        // remember: an executor that returned more than one row past the
        // page dropped its LIMIT, and its read was as wide as the slice.
        if rows.len() > q.fetch() {
            return ReadOutcome::NotServed(NotServedReason::Fault(Error::Backend(format!(
                "execute_attestation_query returned {} rows past its page of {} \
                 (limit {} + 1)",
                rows.len() - q.fetch(),
                q.fetch(),
                q.limit
            ))));
        }
        let limit = q.limit.get() as usize;
        let next = if rows.len() > limit {
            rows.truncate(limit);
            rows.last()
                .map(|a| AttestationCursor::from_trailing(a.asserted_at, a.attestation_id.clone()))
        } else {
            None
        };
        crate::observe::record_query_read(backend, q, &rows, bytes);
        ReadOutcome::Served(Page { rows, next })
    }
}

/// The SQL dialect a statement is rendered for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// `?N` placeholders; TEXT `asserted_at` (RFC 3339, byte-ordered).
    Sqlite,
    /// `$N` placeholders; `timestamptz` `asserted_at`, `uuid` ids compared
    /// as `text COLLATE "C"`.
    Postgres,
}

/// One bind value of a rendered statement.
#[derive(Debug, Clone, PartialEq)]
pub enum Bind {
    /// A text value.
    Text(String),
    /// An instant (`asserted_at`): RFC 3339 text on sqlite, `timestamptz` on
    /// postgres.
    Time(DateTime<Utc>),
    /// An integer (the LIMIT).
    Int(i64),
}

/// A rendered statement: SQL text and its binds, in placeholder order.
#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    /// The SQL.
    pub sql: String,
    /// The binds, `?1`/`$1` first.
    pub binds: Vec<Bind>,
}

/// Plan `q` as ONE parameterised statement over `table`, selecting
/// `columns`.
///
/// The predicate is [`AttestationQuery::admits`]'s, clause for clause. The
/// index it lands on: a pinned key's `(key, asserted_at DESC)` index walks in
/// order and stops at the limit; a narrowed query (a type or a dimension)
/// seeks the `(key, attestation_type, …)` / `(key, dimension)` index instead
/// and sorts what it matched — on sqlite that needs the unary-plus pin on
/// the order term (v53.1.6, I545), without which the planner takes the
/// ordered index and walks the key's whole slice to test each row.
#[must_use]
pub fn render_sql(q: &AttestationQuery, dialect: Dialect, table: &str, columns: &str) -> Statement {
    let mut binds: Vec<Bind> = Vec::new();
    let ph = |binds: &Vec<Bind>| match dialect {
        Dialect::Sqlite => format!("?{}", binds.len()),
        Dialect::Postgres => format!("${}", binds.len()),
    };
    let dim = match dialect {
        Dialect::Sqlite => "dimension",
        Dialect::Postgres => "dimension COLLATE \"C\"",
    };
    let ty = match dialect {
        Dialect::Sqlite => "attestation_type",
        Dialect::Postgres => "attestation_type COLLATE \"C\"",
    };
    let id = match dialect {
        Dialect::Sqlite => "attestation_id",
        Dialect::Postgres => "attestation_id::text COLLATE \"C\"",
    };
    // On sqlite a narrowed query must seek its narrow index; any term on a
    // bare `asserted_at` (the order, the as-of bound, the cursor) is a range
    // the key's `(key, asserted_at)` index also serves, and the planner then
    // walks the key's whole slice to test each row (v53.1.6, I545). The
    // unary plus makes every such term unindexable, so the narrow index wins.
    let pin = if dialect == Dialect::Sqlite && q.seeks_narrow_index() {
        "+"
    } else {
        ""
    };
    let mut parts: Vec<String> = Vec::new();
    if let Some(k) = &q.by {
        binds.push(Bind::Text(k.clone()));
        parts.push(format!("attesting_key_id = {}", ph(&binds)));
    }
    if let Some(k) = &q.to {
        binds.push(Bind::Text(k.clone()));
        parts.push(format!("attested_key_id = {}", ph(&binds)));
    }
    // A literal, not a bind: the vocabulary is closed, and the planner
    // matches a partial index (`WHERE tier = 'local'`) only on a literal.
    parts.push(format!("tier = '{}'", q.tier.stored()));
    match &q.dimension {
        DimensionFilter::Any => {}
        DimensionFilter::Prefix(p) => {
            match crate::ceg::list::federation::dimension_prefix_bounds(p) {
                Some((lo, hi)) => {
                    binds.push(Bind::Text(lo));
                    let a = ph(&binds);
                    binds.push(Bind::Text(hi));
                    let b = ph(&binds);
                    parts.push(format!("({dim} >= {a} AND {dim} < {b})"));
                }
                None => {
                    binds.push(Bind::Text(p.clone()));
                    parts.push(format!(
                        "substr(dimension, 1, {}) = {}",
                        p.chars().count(),
                        ph(&binds)
                    ));
                }
            }
        }
        DimensionFilter::Exact(x) => {
            binds.push(Bind::Text(x.clone()));
            parts.push(format!("{dim} = {}", ph(&binds)));
        }
    }
    if !q.types.is_empty() {
        let phs: Vec<String> = q
            .types
            .iter()
            .map(|t| {
                binds.push(Bind::Text(t.clone()));
                ph(&binds)
            })
            .collect();
        parts.push(format!("attestation_type IN ({})", phs.join(", ")));
    }
    if let Some(p) = &q.type_prefix {
        match crate::ceg::list::federation::dimension_prefix_bounds(p) {
            Some((lo, hi)) => {
                binds.push(Bind::Text(lo));
                let a = ph(&binds);
                binds.push(Bind::Text(hi));
                let b = ph(&binds);
                parts.push(format!("({ty} >= {a} AND {ty} < {b})"));
            }
            None => {
                binds.push(Bind::Text(p.clone()));
                parts.push(format!(
                    "substr(attestation_type, 1, {}) = {}",
                    p.chars().count(),
                    ph(&binds)
                ));
            }
        }
    }
    if !q.excluded_dimensions.is_empty() {
        let phs: Vec<String> = q
            .excluded_dimensions
            .iter()
            .map(|d| {
                binds.push(Bind::Text(d.clone()));
                ph(&binds)
            })
            .collect();
        parts.push(format!(
            "(dimension IS NULL OR dimension NOT IN ({}))",
            phs.join(", ")
        ));
    }
    if let Some(t) = q.as_of {
        binds.push(Bind::Time(t));
        parts.push(format!("{pin}asserted_at <= {}", ph(&binds)));
    }
    let (cmp, dir) = match q.order.direction() {
        Direction::Desc => ("<", "DESC"),
        Direction::Asc => (">", "ASC"),
    };
    if let Some(c) = &q.after {
        binds.push(Bind::Time(c.last_asserted_at));
        let a = ph(&binds);
        binds.push(Bind::Text(c.last_attestation_id.clone()));
        let b = ph(&binds);
        parts.push(format!("({pin}asserted_at, {id}) {cmp} ({a}, {b})"));
    }
    binds.push(Bind::Int(i64::from(q.limit.get()) + 1));
    let limit = ph(&binds);
    Statement {
        sql: format!(
            "SELECT {columns} FROM {table} WHERE {} \
             ORDER BY {pin}asserted_at {dir}, {id} {dir} LIMIT {limit}",
            parts.join(" AND ")
        ),
        binds,
    }
}

/// Test-only conveniences over the bounded read: every row of a key's
/// slice, paged through [`Pages`]. The reads a witness's verbatim pre-fix
/// oracle made (`list_attestations_by` / `_for`, retired by #1001) are
/// spelled through these, so the oracle still reads the whole slice and the
/// probe still sees it — as un-narrowed queries on the key.
#[cfg(any(test, feature = "test-anchor"))]
pub mod test_support {
    use super::{AttestationQuery, AttestationQueryExec, FOLD_PAGE};
    use crate::federation::{Attestation, Error};

    /// Every federation-tier row of one pinned slice, newest first.
    async fn all<E: AttestationQueryExec + ?Sized>(
        dir: &E,
        q: AttestationQuery,
    ) -> Result<Vec<Attestation>, Error> {
        let mut out = Vec::new();
        let mut pages = q.pages();
        while let Some(rows) = pages.next(dir).await? {
            out.extend(rows);
        }
        Ok(out)
    }

    /// The whole-slice reads, as an extension on every directory.
    #[async_trait::async_trait]
    pub trait AllAttestations: AttestationQueryExec {
        /// Every federation-tier row `attesting_key_id` authored, newest
        /// first.
        async fn all_attestations_by(
            &self,
            attesting_key_id: &str,
        ) -> Result<Vec<Attestation>, Error>;
        /// Every federation-tier row attested to `attested_key_id`, newest
        /// first.
        async fn all_attestations_for(
            &self,
            attested_key_id: &str,
        ) -> Result<Vec<Attestation>, Error>;
    }

    #[async_trait::async_trait]
    impl<E: AttestationQueryExec + ?Sized> AllAttestations for E {
        async fn all_attestations_by(
            &self,
            attesting_key_id: &str,
        ) -> Result<Vec<Attestation>, Error> {
            all(self, AttestationQuery::by(attesting_key_id, FOLD_PAGE)).await
        }
        async fn all_attestations_for(
            &self,
            attested_key_id: &str,
        ) -> Result<Vec<Attestation>, Error> {
            all(self, AttestationQuery::to(attested_key_id, FOLD_PAGE)).await
        }
    }
}
