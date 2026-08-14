//! **The schema-parity gate** (v31.2.0, CIRISPersist#670).
//!
//! [`store::parity`](super::parity) compares the *Rust* write doors. It cannot
//! see SQL by construction, and two of the five divergences v31 found lived
//! there:
//!
//! - **CIRISPersist#622** — postgres typed `federation_revocations.revocation_id`
//!   as `UUID` while memory and sqlite took any `TEXT`. A witness was green on
//!   two backends and red on the one production runs.
//! - **CIRISPersist#656** — postgres omitted `last_accessed_at` / `access_count`
//!   from blob inserts where sqlite binds both. Benign only because postgres
//!   declares `DEFAULT NOW()`; sqlite's default is a **1970 epoch sentinel**
//!   (SQLite's `ALTER TABLE ADD COLUMN` cannot take a function default) and the
//!   eviction sweeper orders on that column.
//!
//! Neither is reachable from a Rust scan, so this is a **separate mechanism**
//! rather than a wider net over the same one. It reads
//! `migrations/{postgres,sqlite}/lens/V*.sql`, replays the DDL to the shape each
//! dialect ends up with, and compares:
//!
//! | check | exemptions today |
//! |---|---|
//! | the two trees declare the same tables | none — 103 of 103 match |
//! | the two trees declare the same columns | none — zero divergences |
//! | every type pair is a sanctioned dialect encoding | [`DIALECT_ENCODINGS`] + [`PG_NARROWED_ID_COLUMNS`] |
//! | nullability agrees | [`NULLABILITY_DIVERGENCES`] (4) |
//! | a column one dialect omits from its INSERT has a DEFAULT there | [`WRITE_COLUMN_DIVERGENCES`] (6) |
//!
//! # Why `UUID` is not just another encoding
//!
//! Most cross-dialect type pairs are *encodings* of one value: sqlite has no
//! `TIMESTAMPTZ` (RFC-3339 `TEXT`), no `BOOLEAN` (`INTEGER` 0/1), no `JSONB`
//! (`TEXT`). None of those can diverge on *which values are admitted*, because
//! the Rust binding is a `DateTime` / `bool` / `Value` and every one of them
//! round-trips.
//!
//! `UUID` is different. The Rust side of every one of these columns is a
//! `String`, so postgres **narrows the admitted value set of a column its
//! siblings leave open** — the same Rust value is stored by sqlite and memory
//! and refused by postgres. That is #622 exactly, and #622 needed a migration
//! (V121, `attestation_id_text_genesis_symbolic_ids`) to fix. The columns that
//! still have it are pinned in [`PG_NARROWED_ID_COLUMNS`] so a **new** one
//! cannot appear silently, and each pinned one must still be there — a pin that
//! goes stale fails.

#![cfg(test)]

/// A sanctioned cross-dialect encoding of one value.
#[derive(Debug)]
pub(crate) struct Encoding {
    /// The postgres type class.
    pub postgres: &'static str,
    /// The sqlite type class.
    pub sqlite: &'static str,
    /// Why the pair cannot diverge on which values are admitted.
    pub reason: &'static str,
}

/// The closed set of type pairs that are the same value in two dialects.
///
/// Anything else is a divergence. `("uuid", "text")` is deliberately **absent**
/// — see the module docs.
pub(crate) const DIALECT_ENCODINGS: &[Encoding] = &[
    Encoding {
        postgres: "time",
        sqlite: "text",
        reason: "SQLite has no timestamp type; the substrate stores RFC-3339 TEXT. Both sides \
                 bind a `DateTime<Utc>`, so no caller value can be admitted by one and refused \
                 by the other.",
    },
    Encoding {
        postgres: "bool",
        sqlite: "int",
        reason: "SQLite has no BOOLEAN; 0/1 INTEGER is the substrate encoding. Both sides bind \
                 a `bool`.",
    },
    Encoding {
        postgres: "json",
        sqlite: "text",
        reason: "SQLite has no JSONB. Since V122 the signed-envelope columns are TEXT on BOTH \
                 dialects precisely so the stored bytes are the signed bytes; the remaining \
                 JSONB columns bind a serialized `serde_json::Value` either way.",
    },
    Encoding {
        postgres: "array",
        sqlite: "text",
        reason: "SQLite has no array type; the substrate stores a JSON array as TEXT. Both \
                 sides bind a `Vec<String>` and the storage boundary serializes it.",
    },
    Encoding {
        postgres: "text",
        sqlite: "text",
        reason: "Identical.",
    },
    Encoding {
        postgres: "int",
        sqlite: "int",
        reason: "Identical. Width differences (BIGINT vs INTEGER) do not narrow the admitted \
                 set for this corpus — SQLite INTEGER is 64-bit.",
    },
    Encoding {
        postgres: "real",
        sqlite: "real",
        reason: "Identical.",
    },
    Encoding {
        postgres: "real",
        sqlite: "int",
        reason: "A NUMERIC/DOUBLE column whose sqlite twin is INTEGER: SQLite's dynamic typing \
                 stores either, and the Rust binding is the same numeric type on both.",
    },
    Encoding {
        postgres: "bytes",
        sqlite: "bytes",
        reason: "BYTEA and BLOB are the same value.",
    },
    Encoding {
        postgres: "time",
        sqlite: "time",
        reason: "Identical (a sqlite column declared DATETIME).",
    },
];

/// **Postgres columns typed `UUID` whose sqlite twin is unvalidated `TEXT`.**
///
/// This is a *pinned inventory of a known divergence class*, not a licence.
/// Every entry is a column where the same `String` a caller hands persist is
/// stored by sqlite and memory and **refused by postgres** — CIRISPersist#622,
/// which needed migration V121 to fix for `attestation_id`. Filed as
/// CIRISPersist#674; not fixed here because altering these columns changes
/// `migration_set_sha256`, which is a pinned build-manifest hash and therefore
/// a release-shape decision.
///
/// The pin is bidirectional: a **new** `UUID` column fails until someone adds
/// it here deliberately, and an entry whose column stopped being `UUID` fails
/// until it is deleted.
pub(crate) const PG_NARROWED_ID_COLUMNS: &[(&str, &str)] = &[
    ("cirisgraph.edges", "edge_id"),
    ("cirisgraph.telemetry_metrics", "metric_id"),
    ("cirislens.audit_archives", "archive_id"),
    ("cirislens.audit_log", "entry_id"),
    (
        "cirislens.cirisnode_consent_sla_watch",
        "target_contribution_id",
    ),
    (
        "cirislens.cirisnode_revocation_promotion_watch",
        "revocation_contribution_id",
    ),
    ("cirislens.edge_detection_events", "detection_id"),
    ("cirislens.edge_outbound_queue", "queue_id"),
    (
        "cirislens.federation_revocation_quorum_state",
        "revocation_id",
    ),
    ("cirislens.federation_revocations", "revocation_id"),
    ("cirislens.federation_trust_grants", "grant_id"),
    ("cirislens.goals", "goal_id"),
    ("cirislens.incident_records", "incident_id"),
    ("cirislens_derived.detection_events", "detection_id"),
    ("cirislens_secrets.access_log", "secret_uuid"),
    ("cirislens_secrets.secrets", "secret_uuid"),
    ("cirisnode.contributions", "contribution_id"),
    ("cirisnode.credits_ledger", "last_update_contribution"),
    ("cirisnode.expertise_ledger", "last_update_contribution"),
    (
        "cirisnode.federation_delivery_attestations",
        "announcement_id",
    ),
    ("cirisnode.moderation_events", "moderation_id"),
    ("cirisnode.promotion_attestations", "attestation_id"),
    (
        "cirisnode.reconsideration_attestations",
        "reconsideration_id",
    ),
    ("cirisnode.reconsideration_attestations", "request_id"),
    ("cirisnode.reconsideration_requests", "request_id"),
    ("cirisnode.reconsideration_requests", "slashing_id"),
    (
        "cirisnode.scheduled_takedown_actions",
        "notice_contribution_id",
    ),
    ("cirisnode.slashing_attestations", "moderation_id"),
    ("cirisnode.slashing_attestations", "slashing_id"),
    ("cirisnode.votes", "contribution_id"),
    ("cirisnode.votes", "vote_id"),
];

/// A column whose `NOT NULL` differs between the two trees, with the reason.
#[derive(Debug)]
pub(crate) struct NullabilityDivergence {
    /// Schema-qualified postgres table.
    pub table: &'static str,
    /// Column name.
    pub column: &'static str,
    /// Is the postgres side `NOT NULL`?
    pub postgres_not_null: bool,
    /// Why the difference does not change what persist admits.
    pub reason: &'static str,
}

/// The four columns whose nullability differs. Pinned rather than fixed: all
/// four are on `cirisnode` / `cirislens_derived` tables persist does not write
/// through a `FederationDirectory` door, so no persist API admits a row on one
/// backend that the other refuses. Filed as CIRISPersist#674.
pub(crate) const NULLABILITY_DIVERGENCES: &[NullabilityDivergence] = &[
    NullabilityDivergence {
        table: "cirislens_derived.detection_events",
        column: "body_sha256",
        postgres_not_null: true,
        reason: "The sqlite twin of a CIRISLens-derived projection table. persist has no write \
                 door into it — the rows are produced by the lens pipeline, which only ever \
                 supplies the column. sqlite's laxer declaration therefore admits nothing extra \
                 in practice, but it is a real difference and is written down rather than \
                 assumed.",
    },
    NullabilityDivergence {
        table: "cirislens_derived.detection_events",
        column: "canonical_bytes",
        postgres_not_null: true,
        reason: "Same table and same reason as `body_sha256`: a lens-derived projection with no \
                 persist write door, where the postgres declaration is the stricter of the two \
                 and the producer always supplies the value.",
    },
    NullabilityDivergence {
        table: "cirislens_derived.detection_events",
        column: "trace_id",
        postgres_not_null: true,
        reason: "Same table and same reason as `body_sha256`: a lens-derived projection with no \
                 persist write door, where the postgres declaration is the stricter of the two \
                 and the producer always supplies the value.",
    },
    NullabilityDivergence {
        table: "cirisnode.scheduled_takedown_actions",
        column: "notice_contribution_id",
        postgres_not_null: false,
        reason: "The one divergence pointing the other way: sqlite is STRICTER, refusing a NULL \
                 postgres accepts. A cirisnode table persist stores for but does not admit \
                 through a federation door, so no persist caller can observe the difference; it \
                 would become observable the moment a door writes this table, which is why it is \
                 pinned and not merely tolerated.",
    },
];

/// A table whose INSERT column set differs between `sqlite.rs` and
/// `postgres.rs`.
#[derive(Debug)]
pub(crate) struct WriteColumnDivergence {
    /// Unqualified table name as it appears in the SQL.
    pub table: &'static str,
    /// Columns one dialect binds and the other never does.
    pub columns: &'static [&'static str],
    /// Which dialect OMITS them; the omitting side must declare a DEFAULT.
    pub omitted_by: &'static str,
    /// Why the omission is correct.
    pub reason: &'static str,
}

/// The six tables where one dialect's INSERT binds a column the other leaves
/// to its schema DEFAULT.
///
/// `a_column_one_dialect_omits_from_its_insert_has_a_default_there` does not
/// take these on trust: it checks that the omitting dialect really does declare
/// a DEFAULT for every column named here. An omission with no default is the
/// silent-NULL half of CIRISPersist#656 and fails.
pub(crate) const WRITE_COLUMN_DIVERGENCES: &[WriteColumnDivergence] = &[
    WriteColumnDivergence {
        table: "federation_blobs",
        columns: &["access_count", "last_accessed_at"],
        omitted_by: "postgres",
        reason: "CIRISPersist#656, and the reason this whole module exists. Postgres declares \
                 `last_accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`; SQLite's `ALTER TABLE \
                 ADD COLUMN` cannot take a function default, so V053 gives it the literal \
                 sentinel '1970-01-01T00:00:00+00:00'. The eviction sweeper orders on this \
                 column ASC, so a sqlite row left at its default would be swept FIRST, every \
                 time. sqlite must bind explicitly; postgres must not, or it would be writing a \
                 value its own default already computes correctly.",
    },
    WriteColumnDivergence {
        table: "federation_scope_blobs",
        columns: &["admitted_at", "last_accessed_at"],
        omitted_by: "postgres",
        reason: "The same shape as `federation_blobs`, one table over: V088 declares both \
                 columns `TIMESTAMPTZ NOT NULL DEFAULT NOW()` on postgres, and the sqlite twin \
                 has no function default available, so the sqlite door supplies the instant \
                 itself. Both columns feed the scope-blob LRU sweep.",
    },
    WriteColumnDivergence {
        table: "edge_outbound_queue",
        columns: &["enqueued_at", "queue_id"],
        omitted_by: "postgres",
        reason: "Postgres mints `queue_id` from `DEFAULT gen_random_uuid()` and stamps \
                 `enqueued_at` from `DEFAULT NOW()`; sqlite has neither function available at \
                 the column level, so its door mints both client-side. The id is not returned \
                 to the caller by either door, so server-side and client-side minting are not \
                 distinguishable through the API.",
    },
    WriteColumnDivergence {
        table: "content_manifest",
        columns: &["admitted_at"],
        omitted_by: "postgres",
        reason: "`admitted_at` is the write wall-clock, `DEFAULT now()` on postgres and no \
                 function default on sqlite. Neither door takes the value from the caller, so \
                 the column records the same fact on both — the substrate that can compute it \
                 does, and the one that cannot is handed it.",
    },
    WriteColumnDivergence {
        table: "wholeness_witness_corpus",
        columns: &["admitted_at"],
        omitted_by: "postgres",
        reason: "Same shape as `content_manifest`: a write wall-clock with `DEFAULT now()` on \
                 postgres and no column-level function default on sqlite, taken from neither \
                 caller and read by neither door. The witness corpus is compared on its \
                 content, never on when a node happened to admit it.",
    },
    WriteColumnDivergence {
        table: "federation_stream_chunks",
        columns: &["created_at"],
        omitted_by: "postgres",
        reason: "Same shape again: the chunk's write instant, defaulted by postgres and supplied \
                 by the sqlite door because SQLite has no column-level `NOW()`. Nothing orders \
                 or seals on this column — the chunk DAG is addressed by hash — so the two \
                 instants are a diagnostic, not a fold input.",
    },
];

#[cfg(test)]
mod tests {
    use super::{
        Encoding, NullabilityDivergence, WriteColumnDivergence, DIALECT_ENCODINGS,
        NULLABILITY_DIVERGENCES, PG_NARROWED_ID_COLUMNS, WRITE_COLUMN_DIVERGENCES,
    };
    use std::collections::{BTreeMap, BTreeSet};

    /// `(name, type, not_null, default)` for one column, in declaration order
    /// of the migrations that built it.
    #[derive(Debug, Clone)]
    struct Col {
        ty: String,
        not_null: bool,
        default: Option<String>,
    }

    type Tables = BTreeMap<String, BTreeMap<String, Col>>;

    fn manifest_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    // ── SQL lexing ──────────────────────────────────────────────────

    /// Blank out `--` and `/* */` comments **without touching string
    /// literals**.
    ///
    /// String-awareness is not a nicety. `V116__consensus_protocol_reverse_quorum.sql`
    /// contains the CHECK value `'quorum:*/*'`; a naive block-comment stripper
    /// eats from the `/*` inside that literal to the next `*/`, which swallowed
    /// the whole `CREATE TABLE federation_communities_new` and made the table
    /// vanish from the sqlite side of this comparison. It reported as one
    /// "postgres-only table" — a plausible-looking finding that was entirely
    /// the parser's. [`the_comment_stripper_respects_string_literals`] is the
    /// dye test for it.
    fn strip_sql(text: &str) -> String {
        let b = text.as_bytes();
        let mut out = String::with_capacity(text.len());
        let mut i = 0usize;
        let mut in_str = false;
        while i < b.len() {
            let c = b[i];
            if in_str {
                if c == b'\'' {
                    if b.get(i + 1) == Some(&b'\'') {
                        out.push_str("  ");
                        i += 2;
                        continue;
                    }
                    in_str = false;
                }
                out.push(c as char);
                i += 1;
                continue;
            }
            match c {
                b'\'' => {
                    in_str = true;
                    out.push('\'');
                    i += 1;
                }
                b'-' if b.get(i + 1) == Some(&b'-') => {
                    while i < b.len() && b[i] != b'\n' {
                        out.push(' ');
                        i += 1;
                    }
                }
                b'/' if b.get(i + 1) == Some(&b'*') => {
                    let end = text[i + 2..].find("*/").map_or(b.len(), |p| i + 2 + p + 2);
                    for &ch in &b[i..end] {
                        out.push(if ch == b'\n' { '\n' } else { ' ' });
                    }
                    i = end;
                }
                _ => {
                    out.push(c as char);
                    i += 1;
                }
            }
        }
        out
    }

    /// Split on `;` at paren depth 0 and outside string literals.
    fn statements(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut buf = String::new();
        let mut depth = 0i32;
        let mut in_str = false;
        for c in text.chars() {
            if in_str {
                if c == '\'' {
                    in_str = false;
                }
                buf.push(c);
                continue;
            }
            match c {
                '\'' => {
                    in_str = true;
                    buf.push(c);
                }
                '(' => {
                    depth += 1;
                    buf.push(c);
                }
                ')' => {
                    depth -= 1;
                    buf.push(c);
                }
                ';' if depth <= 0 => {
                    out.push(std::mem::take(&mut buf));
                }
                _ => buf.push(c),
            }
        }
        out.push(buf);
        out.into_iter()
            .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Split a parenthesised body on top-level commas.
    fn split_top(body: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut buf = String::new();
        let mut depth = 0i32;
        let mut in_str = false;
        for c in body.chars() {
            if in_str {
                if c == '\'' {
                    in_str = false;
                }
                buf.push(c);
                continue;
            }
            match c {
                '\'' => {
                    in_str = true;
                    buf.push(c);
                }
                '(' => {
                    depth += 1;
                    buf.push(c);
                }
                ')' => {
                    depth -= 1;
                    buf.push(c);
                }
                ',' if depth == 0 => out.push(std::mem::take(&mut buf)),
                _ => buf.push(c),
            }
        }
        out.push(buf);
        out.into_iter()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect()
    }

    fn norm_name(s: &str) -> String {
        s.trim()
            .trim_matches('"')
            .to_ascii_lowercase()
            .replace('"', "")
    }

    const CONSTRAINT_WORDS: [&str; 7] = [
        "primary",
        "unique",
        "foreign",
        "check",
        "constraint",
        "exclude",
        "like",
    ];

    /// Modifier keywords that terminate the type in a column definition.
    const MODIFIERS: [&str; 11] = [
        "not",
        "null",
        "default",
        "primary",
        "unique",
        "references",
        "check",
        "generated",
        "collate",
        "constraint",
        "as",
    ];

    fn parse_column(part: &str) -> Option<(String, Col)> {
        let toks: Vec<&str> = part.split_whitespace().collect();
        let first = toks.first()?;
        let name = norm_name(first);
        if CONSTRAINT_WORDS.contains(&name.as_str()) {
            return None;
        }
        // The type runs from the second token to the first modifier keyword.
        let mut ty_parts: Vec<&str> = Vec::new();
        let mut idx = 1usize;
        while idx < toks.len() {
            let lower = toks[idx].trim_end_matches(',').to_ascii_lowercase();
            let bare = lower.split('(').next().unwrap_or(&lower).to_owned();
            if MODIFIERS.contains(&bare.as_str()) {
                break;
            }
            ty_parts.push(toks[idx]);
            idx += 1;
        }
        let ty = ty_parts.join(" ");
        if ty.is_empty() {
            return None;
        }
        let upper = part.to_ascii_uppercase();
        let not_null = upper.contains("NOT NULL");
        let default = upper.find("DEFAULT ").map(|p| {
            let rest = &part[p + "DEFAULT ".len()..];
            // Up to the next modifier keyword at depth 0.
            let mut depth = 0i32;
            let mut acc = String::new();
            for tok in rest.split_whitespace() {
                let bare = tok.trim_end_matches(',').to_ascii_lowercase();
                if depth == 0 && !acc.is_empty() && MODIFIERS.contains(&bare.as_str()) {
                    break;
                }
                depth += i32::try_from(tok.matches('(').count()).unwrap_or(0);
                depth -= i32::try_from(tok.matches(')').count()).unwrap_or(0);
                if !acc.is_empty() {
                    acc.push(' ');
                }
                acc.push_str(tok);
            }
            acc
        });
        Some((
            name,
            Col {
                ty,
                not_null,
                default,
            },
        ))
    }

    fn after<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
        (s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix))
            .then(|| s[prefix.len()..].trim_start())
    }

    /// Replay a dialect's migrations to the table shape it ends up with.
    fn build(dialect: &str) -> Tables {
        let dir = manifest_dir().join("migrations").join(dialect).join("lens");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.extension().is_some_and(|x| x == "sql")
                    && p.file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with('V'))
            })
            .collect();
        files.sort();
        let mut tables: Tables = BTreeMap::new();
        for f in files {
            let text = strip_sql(&std::fs::read_to_string(&f).expect("read migration"));
            for st in statements(&text) {
                apply_statement(&mut tables, &st);
            }
        }
        tables
    }

    fn apply_statement(tables: &mut Tables, st: &str) {
        if let Some(rest) = after(st, "CREATE TABLE ") {
            let rest = after(rest, "IF NOT EXISTS ").unwrap_or(rest);
            let Some(open) = rest.find('(') else { return };
            let name = norm_name(&rest[..open]);
            let Some(close) = rest.rfind(')') else { return };
            let entry = tables.entry(name).or_default();
            for part in split_top(&rest[open + 1..close]) {
                if let Some((c, col)) = parse_column(&part) {
                    entry.insert(c, col);
                }
            }
            return;
        }
        if let Some(rest) = after(st, "ALTER TABLE ") {
            let rest = after(rest, "IF EXISTS ").unwrap_or(rest);
            let Some(sp) = rest.find(' ') else { return };
            let name = norm_name(&rest[..sp]);
            for act in split_top(&rest[sp..]) {
                apply_alter(tables, &name, act.trim());
            }
            return;
        }
        if let Some(rest) = after(st, "DROP TABLE ") {
            let rest = after(rest, "IF EXISTS ").unwrap_or(rest);
            let name = norm_name(rest.split_whitespace().next().unwrap_or(""));
            tables.remove(&name);
        }
    }

    fn apply_alter(tables: &mut Tables, table: &str, act: &str) {
        if let Some(rest) = after(act, "ADD COLUMN ") {
            let rest = after(rest, "IF NOT EXISTS ").unwrap_or(rest);
            if let Some((c, col)) = parse_column(rest) {
                tables.entry(table.to_owned()).or_default().insert(c, col);
            }
            return;
        }
        if let Some(rest) = after(act, "DROP COLUMN ") {
            let rest = after(rest, "IF EXISTS ").unwrap_or(rest);
            let c = norm_name(rest.split_whitespace().next().unwrap_or(""));
            if let Some(t) = tables.get_mut(table) {
                t.remove(&c);
            }
            return;
        }
        if let Some(rest) = after(act, "RENAME COLUMN ") {
            let toks: Vec<&str> = rest.split_whitespace().collect();
            if toks.len() >= 3 && toks[1].eq_ignore_ascii_case("to") {
                let (old, new) = (norm_name(toks[0]), norm_name(toks[2]));
                if let Some(t) = tables.get_mut(table) {
                    if let Some(v) = t.remove(&old) {
                        t.insert(new, v);
                    }
                }
            }
            return;
        }
        if let Some(rest) = after(act, "RENAME TO ") {
            let new = norm_name(rest.split_whitespace().next().unwrap_or(""));
            if let Some(v) = tables.remove(table) {
                tables.insert(new, v);
            }
            return;
        }
        // `ALTER [COLUMN] c [SET DATA] TYPE t [USING ...]`
        if let Some(rest) = after(act, "ALTER ") {
            let rest = after(rest, "COLUMN ").unwrap_or(rest);
            let toks: Vec<&str> = rest.split_whitespace().collect();
            let Some(c) = toks.first().map(|s| norm_name(s)) else {
                return;
            };
            let Some(tp) = toks
                .iter()
                .position(|t| t.eq_ignore_ascii_case("type"))
                .and_then(|p| toks.get(p + 1))
            else {
                return;
            };
            if let Some(col) = tables.get_mut(table).and_then(|t| t.get_mut(&c)) {
                col.ty = (*tp).to_owned();
            }
        }
    }

    // ── type classes ────────────────────────────────────────────────

    fn type_class(ty: &str) -> String {
        let t = ty.trim().to_ascii_lowercase();
        let t = t.split('(').next().unwrap_or(&t).trim().to_owned();
        if t.ends_with("[]") {
            return "array".to_owned();
        }
        for (class, names) in [
            (
                "time",
                &["timestamptz", "timestamp", "datetime", "date"][..],
            ),
            ("json", &["jsonb", "json"][..]),
            ("uuid", &["uuid"][..]),
            ("bool", &["boolean", "bool"][..]),
            ("bytes", &["bytea", "blob"][..]),
            (
                "int",
                &[
                    "bigserial",
                    "bigint",
                    "smallint",
                    "serial",
                    "integer",
                    "int8",
                    "int4",
                    "int2",
                    "int",
                ][..],
            ),
            (
                "real",
                &["double precision", "numeric", "decimal", "float", "real"][..],
            ),
            (
                "text",
                &["character varying", "varchar", "citext", "text", "char"][..],
            ),
        ] {
            if names
                .iter()
                .any(|n| t == *n || t.starts_with(&format!("{n} ")))
            {
                return class.to_owned();
            }
        }
        format!("?{t}")
    }

    /// The sqlite twin of a schema-qualified postgres table is named either
    /// `schema_table` or bare `table` — the sqlite tree uses both conventions
    /// (`cirislens_secrets_secrets`, but plain `federation_keys`).
    fn sqlite_twin(pg_table: &str, sqlite: &Tables) -> Option<String> {
        let candidates = match pg_table.split_once('.') {
            Some((schema, name)) => vec![format!("{schema}_{name}"), name.to_owned()],
            None => vec![pg_table.to_owned()],
        };
        candidates.into_iter().find(|c| sqlite.contains_key(c))
    }

    fn trees() -> (Tables, Tables) {
        (build("postgres"), build("sqlite"))
    }

    // ── the gates ───────────────────────────────────────────────────

    /// A parser that stops matching turns every comparison into a vacuous
    /// agreement, so its own yield is pinned first.
    #[test]
    fn the_schema_scan_is_not_vacuous() {
        let (pg, sq) = trees();
        assert!(
            pg.len() > 90 && sq.len() > 90,
            "the DDL replay collapsed (postgres {} tables, sqlite {}) — this module would pass \
             vacuously",
            pg.len(),
            sq.len()
        );
        let pg_cols: usize = pg.values().map(BTreeMap::len).sum();
        let sq_cols: usize = sq.values().map(BTreeMap::len).sum();
        assert!(
            pg_cols > 800 && sq_cols > 800,
            "only {pg_cols} postgres / {sq_cols} sqlite columns parsed — the column parser \
             stopped matching"
        );
        // Assembled so this file's own text is not what satisfies the check.
        let table = ["cirislens", "federation_attestations"].join(".");
        let cols = pg.get(&table).expect("the busiest table is parsed");
        for needle in [
            ["attestation", "envelope"].join("_"),
            ["original", "content", "hash"].join("_"),
            ["cohort", "scope"].join("_"),
            ["persist", "row", "hash"].join("_"),
        ] {
            assert!(
                cols.contains_key(&needle),
                "{table} lost `{needle}` — the replay is not reaching the migrations that add it"
            );
        }
    }

    /// The dye test for [`strip_sql`]. The real corpus contains the CHECK value
    /// `'quorum:*/*'`, and a stripper that treats the `/*` inside it as a
    /// comment opener silently deleted an entire `CREATE TABLE`. The failure
    /// looked like a finding, which is the worst shape a parser bug can take.
    #[test]
    fn the_comment_stripper_respects_string_literals() {
        let planted = "CREATE TABLE t (a TEXT, CHECK (a GLOB 'quorum:*/*')); \
                       CREATE TABLE u (b TEXT);";
        let stripped = strip_sql(planted);
        let mut tables: Tables = BTreeMap::new();
        for st in statements(&stripped) {
            apply_statement(&mut tables, &st);
        }
        assert!(
            tables.contains_key("t") && tables.contains_key("u"),
            "a `/*` inside a string literal ate a table: parsed {:?}",
            tables.keys().collect::<Vec<_>>()
        );
        // And a REAL block comment is still removed.
        let mut tables2: Tables = BTreeMap::new();
        for st in statements(&strip_sql(
            "/* CREATE TABLE gone (x TEXT); */ CREATE TABLE u (b TEXT);",
        )) {
            apply_statement(&mut tables2, &st);
        }
        assert!(
            !tables2.contains_key("gone") && tables2.contains_key("u"),
            "block comments must still be stripped: parsed {:?}",
            tables2.keys().collect::<Vec<_>>()
        );
    }

    /// **Every table exists in both trees.** No exemptions: 103 of 103 match
    /// today, so a new one-dialect table fails on the commit that adds it.
    #[test]
    fn the_two_migration_trees_declare_the_same_tables() {
        let (pg, sq) = trees();
        let mut matched: BTreeSet<String> = BTreeSet::new();
        let mut missing_in_sqlite: Vec<&String> = Vec::new();
        for t in pg.keys() {
            match sqlite_twin(t, &sq) {
                Some(twin) => {
                    matched.insert(twin);
                }
                None => missing_in_sqlite.push(t),
            }
        }
        let missing_in_pg: Vec<&String> = sq.keys().filter(|t| !matched.contains(*t)).collect();
        assert!(
            missing_in_sqlite.is_empty() && missing_in_pg.is_empty(),
            "the two migration trees do not declare the same tables (CIRISPersist#670).\n  \
             postgres-only: {missing_in_sqlite:?}\n  sqlite-only:   {missing_in_pg:?}\n  \
             A table on one substrate is a surface the other cannot serve. If that is \
             deliberate, it needs a declared reason here — there are none today, which is why \
             this check has no exemption list."
        );
    }

    /// **Every column exists in both trees.** Also without exemptions — there
    /// are zero divergences today.
    #[test]
    fn the_two_migration_trees_declare_the_same_columns() {
        let (pg, sq) = trees();
        let mut failures = Vec::new();
        for (t, pcols) in &pg {
            let Some(twin) = sqlite_twin(t, &sq) else {
                continue; // reported by the table gate
            };
            let scols = &sq[&twin];
            for c in pcols.keys() {
                if !scols.contains_key(c) {
                    failures.push(format!("{t}.{c} — postgres only"));
                }
            }
            for c in scols.keys() {
                if !pcols.contains_key(c) {
                    failures.push(format!("{t}.{c} — sqlite only"));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "column presence differs between the migration trees ({}):\n  {}",
            failures.len(),
            failures.join("\n  ")
        );
    }

    /// **Every cross-dialect type pair is a sanctioned encoding of one value,
    /// or a pinned postgres narrowing.**
    #[test]
    fn every_column_type_pair_is_a_sanctioned_dialect_encoding() {
        let (pg, sq) = trees();
        let sanctioned: BTreeSet<(&str, &str)> = DIALECT_ENCODINGS
            .iter()
            .map(|e| (e.postgres, e.sqlite))
            .collect();
        let pinned: BTreeSet<(&str, &str)> = PG_NARROWED_ID_COLUMNS.iter().copied().collect();
        let mut failures = Vec::new();
        let mut seen_pins: BTreeSet<(&str, &str)> = BTreeSet::new();

        for (t, pcols) in &pg {
            let Some(twin) = sqlite_twin(t, &sq) else {
                continue;
            };
            for (c, pcol) in pcols {
                let Some(scol) = sq[&twin].get(c) else {
                    continue;
                };
                let (kp, ks) = (type_class(&pcol.ty), type_class(&scol.ty));
                let pin = pinned
                    .iter()
                    .find(|(pt, pc)| *pt == t.as_str() && pc == c)
                    .copied();
                if kp == "uuid" && ks == "text" {
                    match pin {
                        Some(k) => {
                            seen_pins.insert(k);
                        }
                        None => failures.push(format!(
                            "{t}.{c} — postgres types this `{}` while sqlite takes any `{}`. The \
                             Rust side is a String on both, so postgres NARROWS a column its \
                             siblings leave open: the same value persist stores on sqlite and \
                             memory is REFUSED here. That is CIRISPersist#622, which needed \
                             migration V121 to fix for `attestation_id`. Either type it TEXT, or \
                             add it to PG_NARROWED_ID_COLUMNS deliberately.",
                            pcol.ty, scol.ty
                        )),
                    }
                    continue;
                }
                if let Some(k) = pin {
                    seen_pins.insert(k);
                }
                if kp == ks || sanctioned.contains(&(kp.as_str(), ks.as_str())) {
                    continue;
                }
                failures.push(format!(
                    "{t}.{c} — postgres `{}` ({kp}) vs sqlite `{}` ({ks}) is not a sanctioned \
                     dialect encoding. Add an `Encoding` in src/store/schema_parity.rs saying why \
                     the two hold the same value, or make the declarations agree.",
                    pcol.ty, scol.ty
                ));
            }
        }
        // The pin is a partition, not a floor: a stale entry licenses nothing
        // and must go.
        for k in pinned.difference(&seen_pins) {
            failures.push(format!(
                "{}.{} is pinned in PG_NARROWED_ID_COLUMNS but is no longer a postgres-UUID / \
                 sqlite-TEXT pair — delete the pin.",
                k.0, k.1
            ));
        }
        assert!(
            failures.is_empty(),
            "schema type parity (CIRISPersist#670) — {} finding(s):\n\n{}",
            failures.len(),
            failures.join("\n\n")
        );
    }

    /// **`NOT NULL` agrees, or the difference is written down.**
    #[test]
    fn nullability_agrees_across_the_two_trees() {
        let (pg, sq) = trees();
        let declared: BTreeSet<(&str, &str)> = NULLABILITY_DIVERGENCES
            .iter()
            .map(|d| (d.table, d.column))
            .collect();
        let mut failures = Vec::new();
        let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
        for (t, pcols) in &pg {
            let Some(twin) = sqlite_twin(t, &sq) else {
                continue;
            };
            for (c, pcol) in pcols {
                let Some(scol) = sq[&twin].get(c) else {
                    continue;
                };
                if pcol.not_null == scol.not_null {
                    continue;
                }
                match declared
                    .iter()
                    .find(|(dt, dc)| *dt == t.as_str() && dc == c)
                {
                    Some(k) => {
                        seen.insert(*k);
                        let d = NULLABILITY_DIVERGENCES
                            .iter()
                            .find(|d| d.table == t && d.column == c)
                            .expect("found above");
                        assert_eq!(
                            d.postgres_not_null, pcol.not_null,
                            "{t}.{c} — the declared divergence says postgres NOT NULL is {}, but \
                             the migrations say {}. The pin flipped direction; re-read it.",
                            d.postgres_not_null, pcol.not_null
                        );
                    }
                    None => failures.push(format!(
                        "{t}.{c} — postgres NOT NULL = {}, sqlite NOT NULL = {}. One substrate \
                         admits a NULL the other refuses. Make them agree, or declare it in \
                         NULLABILITY_DIVERGENCES with a reason.",
                        pcol.not_null, scol.not_null
                    )),
                }
            }
        }
        for k in declared.difference(&seen) {
            failures.push(format!(
                "{}.{} is declared in NULLABILITY_DIVERGENCES but the two trees now agree — \
                 delete the entry.",
                k.0, k.1
            ));
        }
        assert!(
            failures.is_empty(),
            "nullability parity (CIRISPersist#670) — {} finding(s):\n  {}",
            failures.len(),
            failures.join("\n  ")
        );
    }

    // ── the write-column half ───────────────────────────────────────

    /// Every Rust string literal in `text`, with `\` + newline continuations
    /// joined — the shape every multi-line SQL statement in this crate uses.
    fn rust_string_literals(text: &str) -> Vec<String> {
        let b = text.as_bytes();
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < b.len() {
            if b[i] != b'"' {
                i += 1;
                continue;
            }
            let mut buf = String::new();
            let mut j = i + 1;
            while j < b.len() {
                match b[j] {
                    b'\\' => {
                        if b.get(j + 1) == Some(&b'\n') {
                            j += 2;
                            while j < b.len() && (b[j] == b' ' || b[j] == b'\t') {
                                j += 1;
                            }
                            continue;
                        }
                        if let Some(&n) = b.get(j + 1) {
                            buf.push(n as char);
                        }
                        j += 2;
                    }
                    b'"' => break,
                    c => {
                        buf.push(c as char);
                        j += 1;
                    }
                }
            }
            out.push(buf);
            i = j + 1;
        }
        out
    }

    /// `table -> the union of every column any INSERT in this file binds`.
    fn insert_columns(rel: &str) -> BTreeMap<String, BTreeSet<String>> {
        let text = std::fs::read_to_string(manifest_dir().join(rel)).expect("read backend source");
        let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        // Assembled so this module's own doc text is not a match.
        let marker = ["INSERT", "INTO"].join(" ");
        for blob in rust_string_literals(&text) {
            let upper = blob.to_ascii_uppercase();
            let mut from = 0usize;
            while let Some(p) = upper[from..].find(&marker) {
                let start = from + p + marker.len();
                from = start;
                let rest = blob[start..].trim_start();
                let Some(open) = rest.find('(') else { continue };
                let name = norm_name(rest[..open].trim());
                let name = name.rsplit('.').next().unwrap_or(&name).to_owned();
                if name.is_empty() || name.contains(' ') {
                    continue;
                }
                let Some(close) = rest[open..].find(')') else {
                    continue;
                };
                let cols: BTreeSet<String> = rest[open + 1..open + close]
                    .split(',')
                    .map(norm_name)
                    .filter(|c| {
                        !c.is_empty()
                            && c.chars().all(|ch| {
                                ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_'
                            })
                    })
                    .collect();
                if !cols.is_empty() {
                    out.entry(name).or_default().extend(cols);
                }
            }
        }
        out
    }

    /// **CIRISPersist#656 as a gate.** Where one dialect's INSERT binds a
    /// column the other never does, the omitting dialect must declare a
    /// `DEFAULT` for it — otherwise the row lands NULL on one substrate and
    /// populated on the other, and nothing says so.
    ///
    /// The pinned reasons are not taken on trust: the DEFAULT is re-derived
    /// from the migrations every run.
    #[test]
    fn a_column_one_dialect_omits_from_its_insert_has_a_default_there() {
        let (pg_schema, sq_schema) = trees();
        let pg_ins = insert_columns("src/store/postgres.rs");
        let sq_ins = insert_columns("src/store/sqlite.rs");
        assert!(
            pg_ins.len() > 40 && sq_ins.len() > 40,
            "the INSERT scan collapsed (postgres {} tables, sqlite {}) — it would pass vacuously",
            pg_ins.len(),
            sq_ins.len()
        );

        let declared: BTreeMap<&str, &WriteColumnDivergence> = WRITE_COLUMN_DIVERGENCES
            .iter()
            .map(|d| (d.table, d))
            .collect();
        let mut failures = Vec::new();
        let mut seen: BTreeSet<&str> = BTreeSet::new();

        for (table, pcols) in &pg_ins {
            let Some(scols) = sq_ins.get(table) else {
                continue;
            };
            if pcols == scols {
                continue;
            }
            let Some(d) = declared.get(table.as_str()) else {
                let pg_only: Vec<&String> = pcols.difference(scols).collect();
                let sq_only: Vec<&String> = scols.difference(pcols).collect();
                failures.push(format!(
                    "{table} — the two dialects bind different column sets.\n    postgres only: \
                     {pg_only:?}\n    sqlite only:   {sq_only:?}\n    This is the shape of \
                     CIRISPersist#656. Either bind the same columns, or declare it in \
                     WRITE_COLUMN_DIVERGENCES — and the omitting dialect must have a schema \
                     DEFAULT, which this test then checks."
                ));
                continue;
            };
            seen.insert(d.table);

            let (omitted, present) = match d.omitted_by {
                "postgres" => (pcols, scols),
                "sqlite" => (scols, pcols),
                other => {
                    failures.push(format!("{table} — unknown `omitted_by` {other:?}"));
                    continue;
                }
            };
            let actual: BTreeSet<&String> = present.difference(omitted).collect();
            let pinned: BTreeSet<String> = d.columns.iter().map(|s| (*s).to_owned()).collect();
            let actual_owned: BTreeSet<String> = actual.into_iter().cloned().collect();
            if actual_owned != pinned {
                failures.push(format!(
                    "{table} — the declared write-column divergence pins {pinned:?} but the \
                     sources now differ on {actual_owned:?}. An exemption pins ONE shape."
                ));
                continue;
            }
            // And the omitting side really must have a DEFAULT. This is the
            // half that makes the exemption a claim rather than a note.
            let schema = if d.omitted_by == "postgres" {
                &pg_schema
            } else {
                &sq_schema
            };
            for col in d.columns {
                let found = schema
                    .iter()
                    .find(|(t, _)| {
                        t.rsplit('.').next().unwrap_or(t) == table.as_str() || *t == table
                    })
                    .and_then(|(_, cols)| cols.get(*col));
                match found {
                    Some(c) if c.default.is_some() => {}
                    Some(_) => failures.push(format!(
                        "{table}.{col} — {} omits it from its INSERT and its schema declares NO \
                         DEFAULT. The row lands NULL on {} and populated on the other backend, \
                         and nothing in the type system says so. This is exactly \
                         CIRISPersist#656 without the default that made #656 survivable.",
                        d.omitted_by, d.omitted_by
                    )),
                    None => failures.push(format!(
                        "{table}.{col} — declared as omitted by {}, but the column is not in that \
                         dialect's schema at all. The pin is stale.",
                        d.omitted_by
                    )),
                }
            }
        }
        for d in WRITE_COLUMN_DIVERGENCES {
            if !seen.contains(d.table) {
                failures.push(format!(
                    "{} is declared in WRITE_COLUMN_DIVERGENCES but the two dialects now bind the \
                     same columns — delete the entry.",
                    d.table
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "write-column parity (CIRISPersist#670) — {} finding(s):\n\n{}",
            failures.len(),
            failures.join("\n\n")
        );
    }

    /// Reasons are prose a reviewer reads. A label is not a reason.
    #[test]
    fn every_schema_exemption_states_a_substantive_reason() {
        for e in DIALECT_ENCODINGS {
            let words = e.reason.split_whitespace().count();
            // "Identical." is the whole story for a same-class pair.
            let floor = if e.postgres == e.sqlite { 1 } else { 15 };
            assert!(
                words >= floor,
                "encoding {}/{} — reason is {words} words",
                e.postgres,
                e.sqlite
            );
        }
        for d in NULLABILITY_DIVERGENCES {
            assert!(
                d.reason.split_whitespace().count() >= 25,
                "{}.{} — reason is {} words; say what makes the difference unobservable",
                d.table,
                d.column,
                d.reason.split_whitespace().count()
            );
        }
        for d in WRITE_COLUMN_DIVERGENCES {
            assert!(
                d.reason.split_whitespace().count() >= 25,
                "{} — reason is {} words",
                d.table,
                d.reason.split_whitespace().count()
            );
            assert!(
                d.omitted_by == "postgres" || d.omitted_by == "sqlite",
                "{} — omitted_by must name a dialect",
                d.table
            );
            assert!(!d.columns.is_empty(), "{} — pins no columns", d.table);
        }
        assert!(
            !PG_NARROWED_ID_COLUMNS.is_empty(),
            "the narrowed-id pin is empty; if that is real, delete the mechanism"
        );
        // Sorted + unique, so a duplicate pin cannot mask a second column.
        let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
        for k in PG_NARROWED_ID_COLUMNS {
            assert!(seen.insert(*k), "duplicate pin {k:?}");
        }
    }

    // Silence "field never read" for the doc-bearing structs whose fields the
    // gates above consume by reference only.
    #[allow(dead_code)]
    fn _fields_are_read(e: &Encoding, n: &NullabilityDivergence, w: &WriteColumnDivergence) {
        let _ = (e.postgres, e.sqlite, e.reason);
        let _ = (n.table, n.column, n.postgres_not_null, n.reason);
        let _ = (w.table, w.columns, w.omitted_by, w.reason);
    }
}
