//! v62.0.0 (slice E2b, CC rc20 "nothing carries") — **the edition-2 baseline
//! and the witness that it builds edition 1's schema.**
//!
//! Edition 1 was V001..V216 (197 SQLite files, 205 PostgreSQL files). Edition
//! 2 is ONE baseline per dialect, `migrations/{sqlite,postgres}/lens/V300__edition2_baseline.sql`,
//! then whatever appends after it (V301, V302, ...). The baseline's first part
//! is edition 1's schema as V216 left it, object for object; its last part is
//! the edition-2 additions, [`EDITION_TWO_ADDITIONS`], and the columns
//! [`KEYS_EDITION_TWO_SQLITE`] / [`KEYS_EDITION_TWO_POSTGRES`] add to
//! `federation_keys`.
//!
//! The witness (I1950) compares a normalized catalog of what the baseline
//! builds with the catalog edition 1 built, frozen in
//! `tests/fixtures/edition1_schema/` from a real V001..V216 run (the open path
//! of v62-int, `6a9e88eb`, repairs included) before the edition-1 files were
//! removed. The catalog is the stored DDL itself on SQLite (`sqlite_schema`'s
//! text, byte for byte) and, on PostgreSQL, every column (type, nullability,
//! default, generation, identity, collation), constraint, index, sequence,
//! trigger, view, function, ACL, default ACL, comment and seeded row in
//! persist's schemas.

/// The version of the edition-2 baseline. An edition-1 history holds versions
/// 1..=216 only; nothing of edition 2 is numbered below this.
#[cfg_attr(not(any(feature = "sqlite", feature = "postgres")), allow(dead_code))]
pub(crate) const EDITION_TWO_BASELINE: i32 = 300;

/// The highest version edition 1 ever shipped (V216, v62-int).
#[cfg_attr(not(any(feature = "sqlite", feature = "postgres")), allow(dead_code))]
pub(crate) const EDITION_ONE_HEAD: i32 = 216;

/// The tables the baseline adds to edition 1's schema. Each later edition-2
/// table either joins this list (when it goes into the baseline before v62
/// ships) or arrives as V301+.
///
/// - `store_edition_deletions` — the local-tier record of an earlier store's
///   deletion ([`crate::store::edition_upgrade`]).
/// - `ceg_statements`, `ceg_row_names` — slice E2a's edition-2 statements.
/// - `federation_group_tips` — kernel pass 2 (K1, I2812): a group version
///   held as a tip beside the head (CC 2.7.8).
/// - `ceg_roster_proposals` — v62.0.0 (wave O1, S1): this node's receipts of
///   edition-2 self-roster proposals.
/// - `ceg_fold_state`, `ceg_fold_reads` — wave G0 (CC 2.7.3): each folded
///   row's arrival, plane and slot, why a held row concludes nothing, and
///   what each row's fold read.
/// - `ceg_accord_rescan` — RL-fix1 (lead ruling (B); CC 5.4): the feed
///   watermarks of accord rows a node holding no accord root skipped.
/// - `ceg_dial_hints` — RL-fix2: the local, unsigned dial hints decoded from
///   a contact's node code.
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) const EDITION_TWO_ADDITIONS: &[&str] = &[
    "store_edition_deletions",
    "ceg_statements",
    "ceg_row_names",
    "federation_group_tips",
    "ceg_roster_proposals",
    "ceg_fold_state",
    "ceg_fold_reads",
    "ceg_accord_rescan",
    "ceg_dial_hints",
];

/// The columns edition 2 adds to edition 1's `federation_keys`: the
/// projection of a verified edition-2 key:record (slice E2a) keeps every FK to
/// `federation_keys` valid. `edition` (1 or 2), `record_row_id` and `kid` (32
/// bytes each), and an edition-2 row must carry both ids. The baseline
/// appends them with ALTER, so edition 1's DDL stays as it was; the I1950
/// witness applies exactly these statements to the edition-1 catalog and
/// checks the baseline carries them verbatim.
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) const KEYS_EDITION_TWO_SQLITE: &[&str] = &[
    "ALTER TABLE federation_keys ADD COLUMN edition SMALLINT NOT NULL DEFAULT 1 CHECK (edition IN (1, 2));",
    "ALTER TABLE federation_keys ADD COLUMN record_row_id BLOB CHECK (record_row_id IS NULL OR (typeof(record_row_id) = 'blob' AND length(record_row_id) = 32));",
    "ALTER TABLE federation_keys ADD COLUMN kid BLOB CHECK (kid IS NULL OR (typeof(kid) = 'blob' AND length(kid) = 32)) CHECK (edition <> 2 OR (record_row_id IS NOT NULL AND kid IS NOT NULL));",
];

/// v62.0.0 (P8-fix14; lead ruling (a)) — the column edition 2 adds to edition
/// 1's `federation_attestations` (an edition-2 row's restatement key,
/// `crossing::restatement_key_of_row`, written by the row writers beside the
/// row and never in the envelope), appended with ALTER as the
/// `federation_keys` columns are; and its index, an edition-2 object on an
/// edition-1 table. The I1950 witness applies the ALTER to the frozen
/// catalog's DDL and expects the index beside it.
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) const ATTESTATIONS_EDITION_TWO_SQLITE: &[&str] =
    &["ALTER TABLE federation_attestations ADD COLUMN restatement_key TEXT;"];
/// The index [`ATTESTATIONS_EDITION_TWO_SQLITE`]'s column is read through
/// (its name, and its SQLite DDL as `sqlite_schema` stores it).
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) const ATTESTATIONS_RESTATEMENT_INDEX: (&str, &str) = (
    "federation_attestations_restatement",
    "CREATE INDEX federation_attestations_restatement ON federation_attestations (attesting_key_id, restatement_key) WHERE restatement_key IS NOT NULL",
);
/// The PostgreSQL twin: the column and the index, as V300 states them.
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) const ATTESTATIONS_EDITION_TWO_POSTGRES: &[&str] = &[
    "ALTER TABLE cirislens.federation_attestations ADD COLUMN restatement_key text;",
    "CREATE INDEX federation_attestations_restatement ON cirislens.federation_attestations USING btree (attesting_key_id, restatement_key) WHERE (restatement_key IS NOT NULL);",
];
/// The column [`ATTESTATIONS_EDITION_TWO_POSTGRES`] adds.
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) const ATTESTATIONS_EDITION_TWO_COLUMNS: &[&str] = &["restatement_key"];

/// The PostgreSQL twin of [`KEYS_EDITION_TWO_SQLITE`], one statement.
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) const KEYS_EDITION_TWO_POSTGRES: &str = "ALTER TABLE cirislens.federation_keys\n    ADD COLUMN edition smallint DEFAULT 1 NOT NULL CONSTRAINT federation_keys_edition_check CHECK (edition IN (1, 2)),\n    ADD COLUMN record_row_id bytea CONSTRAINT federation_keys_record_row_id_check CHECK (octet_length(record_row_id) = 32),\n    ADD COLUMN kid bytea CONSTRAINT federation_keys_kid_check CHECK (octet_length(kid) = 32),\n    ADD CONSTRAINT federation_keys_edition_two_ids CHECK (edition <> 2 OR (record_row_id IS NOT NULL AND kid IS NOT NULL));";

/// The columns and (PostgreSQL) constraints [`KEYS_EDITION_TWO_POSTGRES`] adds.
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) const KEYS_EDITION_TWO_COLUMNS: &[&str] = &["edition", "record_row_id", "kid"];
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) const KEYS_EDITION_TWO_PG_CONSTRAINTS: &[&str] = &[
    "federation_keys_edition_check",
    "federation_keys_record_row_id_check",
    "federation_keys_kid_check",
    "federation_keys_edition_two_ids",
];

/// v62.0.0 (F0-cp5; RULINGS "composite signatures only") — the CIRISNode
/// delivery attestation's change, made IN V300's edition-1 `CREATE TABLE`
/// (V300 is unshipped; no `ALTER … DROP COLUMN`, which a system SQLite older
/// than 3.35 cannot run): the earlier denormalised peer pubkey and the
/// classical / PQC signature pair give way to ONE composite
/// (`signature_composite`, 3373 bytes). The I1950 witness reads it as the
/// one table whose edition-1 DDL edition 2 changes: on SQLite this text
/// replaces the frozen catalog's; on PostgreSQL the columns and constraints
/// below are excluded from each side.
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) const DELIVERY_SQLITE_DDL: &str = "CREATE TABLE cirisnode_federation_delivery_attestations (\n    announcement_id              TEXT NOT NULL,\n    announcement_canonical_hash  BLOB NOT NULL\n        CHECK (length(announcement_canonical_hash) = 32),\n    peer_key_id                  TEXT NOT NULL,\n    received_at                  TEXT NOT NULL,\n    transport_id                 TEXT NOT NULL\n        CHECK (transport_id IN ('reticulum', 'tcp_tls', 'http_over_tls', 'other')),\n    signature_composite          BLOB NOT NULL\n        CHECK (length(signature_composite) = 3373),\n    inserted_at                  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),\n    signature_verified           INTEGER NOT NULL DEFAULT 0,\n    persist_row_hash             TEXT NOT NULL,\n    PRIMARY KEY (announcement_id, peer_key_id)\n)";

/// The delivery-attestation table: its SQLite name, its PostgreSQL name.
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) const DELIVERY_TABLE: (&str, &str) = (
    "cirisnode_federation_delivery_attestations",
    "cirisnode.federation_delivery_attestations",
);
/// The columns edition 2 removed from the table, and the (PostgreSQL)
/// constraints that went with them.
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) const DELIVERY_DROPPED_COLUMNS: &[&str] = &[
    "peer_pubkey_ed25519_base64",
    "signature_classical",
    "signature_pqc",
];
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) const DELIVERY_DROPPED_PG_CONSTRAINTS: &[&str] = &[
    "federation_delivery_attestations_signature_classical_check",
    "federation_delivery_attestations_signature_pqc_check",
];
/// The column, and the (PostgreSQL) constraint, it adds.
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) const DELIVERY_ADDED_COLUMNS: &[&str] = &["signature_composite"];
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) const DELIVERY_ADDED_PG_CONSTRAINTS: &[&str] =
    &["federation_delivery_attestations_signature_composite_check"];

/// v62.0.0 (P1-fix8; CC 2.6.1.5, the lead's ruling) — **the ledger facts
/// edition 2 makes exact.** Edition 1 stored a credits `balance` and an
/// `expertise` as floats; the baseline stores them as postgres `numeric` and
/// sqlite canonical decimal `TEXT` (with the expertise range check and the
/// routable index's predicate restated for that form). V300 is unshipped, so
/// the baseline's own DDL says it; I1950 sets exactly these catalog facts
/// aside on both sides and [`exact_ledger_fact`]'s callers check the
/// baseline's form of each.
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) fn exact_ledger_fact(line: &str) -> bool {
    const PREFIXES: &[&str] = &[
        // sqlite: the two tables' DDL, and the routable index.
        "object\ttable\tcirisnode_credits_ledger\t",
        "object\ttable\tcirisnode_expertise_ledger\t",
        "object\tindex\texpertise_routable\t",
        // postgres: the two columns, the range check, the routable index.
        "col\tcirisnode.credits_ledger\t5\tbalance\t",
        "col\tcirisnode.expertise_ledger\t4\texpertise\t",
        "con\tcirisnode.expertise_ledger\texpertise_ledger_expertise_check\t",
        "idx\tCREATE INDEX expertise_routable ON cirisnode.expertise_ledger ",
    ];
    PREFIXES.iter().any(|p| line.starts_with(p))
}

/// The signer FKs edition 1 had and edition 2 keeps (I1950 checks them
/// present): an edition-2 signer is projected into `federation_keys`.
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) const SIGNER_FKS: &[(&str, &str)] = &[
    ("federation_attestations", "attesting_key_id"),
    ("federation_attestations", "scrub_key_id"),
];

#[cfg(test)]
pub(crate) mod catalog {
    //! The normalized catalogs the I1950 witness compares.

    /// Where the frozen edition-1 catalogs live.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) fn fixture_path(dialect: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/edition1_schema")
            .join(format!("{dialect}.catalog"))
    }

    /// One line per catalog fact, newlines escaped.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('\n', "\\n")
            .replace('\t', "\\t")
    }

    #[cfg(feature = "sqlite")]
    fn is_addition(table: &str) -> bool {
        super::EDITION_TWO_ADDITIONS.contains(&table)
    }

    /// SQLite: every `sqlite_schema` row (type, name, table, DDL text) but the
    /// history table, SQLite's own statistics and sequence tables, and the
    /// edition-2 additions; then every row a fresh store holds.
    #[cfg(feature = "sqlite")]
    pub(crate) fn sqlite(conn: &rusqlite::Connection) -> Vec<String> {
        let mut out = Vec::new();
        let mut st = conn
            .prepare(
                "SELECT type, name, tbl_name, sql FROM sqlite_master \
                 WHERE name NOT LIKE 'sqlite_stat%' AND name <> 'sqlite_sequence' \
                 AND tbl_name <> 'refinery_schema_history'",
            )
            .expect("sqlite_master");
        let rows: Vec<(String, String, String, Option<String>)> = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .expect("query")
            .collect::<Result<_, _>>()
            .expect("rows");
        let mut tables = Vec::new();
        for (ty, name, tbl, sql) in rows {
            if is_addition(&tbl) {
                continue;
            }
            if ty == "table" {
                tables.push(name.clone());
            }
            out.push(format!(
                "object\t{ty}\t{name}\t{tbl}\t{}",
                esc(sql.as_deref().unwrap_or("<auto>"))
            ));
        }
        for t in tables {
            let mut st = conn
                .prepare(&format!("SELECT * FROM \"{t}\""))
                .expect("select");
            let n = st.column_count();
            let rows: Vec<String> = st
                .query_map([], |r| {
                    let mut cells = Vec::new();
                    for i in 0..n {
                        cells.push(format!("{:?}", r.get::<_, rusqlite::types::Value>(i)?));
                    }
                    Ok(cells.join(","))
                })
                .expect("rows")
                .collect::<Result<_, _>>()
                .expect("rows");
            for r in rows {
                out.push(format!("row\t{t}\t{}", esc(&r)));
            }
        }
        out.sort();
        out
    }

    /// The relations of persist's schemas and the two tables in the
    /// connection's current schema, as a SQL predicate over `n` (namespace)
    /// and `c` (class).
    #[cfg(feature = "postgres")]
    const PG_SCOPE: &str = "(n.nspname IN ('cirislens','cirislens_derived','cirislens_secrets',\
        'cirisnode','cirisgraph') OR (n.nspname = current_schema() \
        AND c.relname IN ('cirislens_pseudonyms')))";

    /// PostgreSQL: the facts listed in the module docs, in persist's schemas
    /// and for `cirislens_pseudonyms`; the history table and the edition-2
    /// additions excluded.
    #[cfg(feature = "postgres")]
    pub(crate) async fn postgres(c: &tokio_postgres::Client) -> Vec<String> {
        let rel = |c2: &str| {
            format!(
                "(SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
                 WHERE {PG_SCOPE} {adds} {c2})",
                adds = super::EDITION_TWO_ADDITIONS
                    .iter()
                    .map(|a| format!(
                        "AND c.relname <> '{a}' AND left(c.relname, {}) <> '{a}_'",
                        a.len() + 1
                    ))
                    .collect::<String>()
            )
        };
        let tables = rel("AND c.relkind IN ('r','p','v','m','f','S')");
        let queries: Vec<(&str, String)> = vec![
            (
                "schema",
                "SELECT nspname::text, coalesce(nspacl::text,'') FROM pg_namespace WHERE nspname IN \
                 ('cirislens','cirislens_derived','cirislens_secrets','cirisnode','cirisgraph')"
                    .to_owned(),
            ),
            (
                "rel",
                format!(
                    "SELECT c.oid::regclass::text, c.relkind::text, c.relpersistence::text, \
                     coalesce(c.reloptions::text,''), coalesce(c.relacl::text,''), \
                     coalesce(obj_description(c.oid,'pg_class'),'') \
                     FROM pg_class c WHERE c.oid IN {tables}"
                ),
            ),
            (
                "col",
                format!(
                    "SELECT a.attrelid::regclass::text, \
                     (row_number() OVER (PARTITION BY a.attrelid ORDER BY a.attnum))::text, \
                     a.attname::text, format_type(a.atttypid, a.atttypmod), a.attnotnull::text, \
                     coalesce(pg_get_expr(d.adbin, d.adrelid),''), a.attgenerated::text, \
                     a.attidentity::text, coalesce(co.collname::text,''), \
                     coalesce(col_description(a.attrelid, a.attnum),''), \
                     coalesce(a.attacl::text,'') \
                     FROM pg_attribute a \
                     LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum \
                     LEFT JOIN pg_collation co ON co.oid = a.attcollation \
                       AND a.attcollation <> (SELECT oid FROM pg_collation WHERE collname = 'default') \
                     WHERE a.attrelid IN {tables} AND a.attnum > 0 AND NOT a.attisdropped"
                ),
            ),
            (
                "con",
                format!(
                    "SELECT conrelid::regclass::text, conname::text, contype::text, \
                     pg_get_constraintdef(oid), convalidated::text, condeferrable::text, \
                     condeferred::text FROM pg_constraint WHERE conrelid IN {tables}"
                ),
            ),
            (
                "idx",
                format!(
                    "SELECT pg_get_indexdef(i.indexrelid), \
                     coalesce(obj_description(i.indexrelid,'pg_class'),'') \
                     FROM pg_index i WHERE i.indrelid IN {tables}"
                ),
            ),
            (
                "trg",
                format!(
                    "SELECT pg_get_triggerdef(oid) FROM pg_trigger \
                     WHERE tgrelid IN {tables} AND NOT tgisinternal"
                ),
            ),
            (
                "view",
                format!(
                    "SELECT c.oid::regclass::text, pg_get_viewdef(c.oid) FROM pg_class c \
                     WHERE c.oid IN {tables} AND c.relkind IN ('v','m')"
                ),
            ),
            (
                "seq",
                format!(
                    "SELECT s.seqrelid::regclass::text, format_type(s.seqtypid, NULL), \
                     s.seqstart::text, s.seqincrement::text, s.seqmax::text, s.seqmin::text, \
                     s.seqcache::text, s.seqcycle::text, \
                     coalesce((SELECT d.refobjid::regclass::text || '.' || d.refobjsubid::text \
                       FROM pg_depend d WHERE d.objid = s.seqrelid AND d.classid = 'pg_class'::regclass \
                       AND d.refclassid = 'pg_class'::regclass AND d.deptype IN ('a','i') LIMIT 1),'') \
                     FROM pg_sequence s WHERE s.seqrelid IN {tables}"
                ),
            ),
            (
                "func",
                "SELECT p.oid::regprocedure::text, pg_get_functiondef(p.oid) FROM pg_proc p \
                 JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname IN \
                 ('cirislens','cirislens_derived','cirislens_secrets','cirisnode','cirisgraph')"
                    .to_owned(),
            ),
            (
                "type",
                "SELECT t.oid::regtype::text, t.typtype::text FROM pg_type t \
                 JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname IN \
                 ('cirislens','cirislens_derived','cirislens_secrets','cirisnode','cirisgraph') \
                 AND t.typtype IN ('e','d','r','m')"
                    .to_owned(),
            ),
            (
                "defacl",
                "SELECT n.nspname::text, d.defaclobjtype::text, d.defaclacl::text \
                 FROM pg_default_acl d JOIN pg_namespace n ON n.oid = d.defaclnamespace \
                 WHERE n.nspname IN \
                 ('cirislens','cirislens_derived','cirislens_secrets','cirisnode','cirisgraph')"
                    .to_owned(),
            ),
        ];
        let mut out = Vec::new();
        for (tag, q) in &queries {
            for r in c.query(q.as_str(), &[]).await.expect(tag) {
                let mut cells = Vec::new();
                for i in 0..r.len() {
                    cells.push(esc(&r.get::<_, String>(i)));
                }
                out.push(format!("{tag}\t{}", cells.join("\t")));
            }
        }
        // Every row a fresh store holds.
        let rels = c
            .query(
                &format!(
                    "SELECT c.oid::regclass::text FROM pg_class c WHERE c.oid IN {} ",
                    rel("AND c.relkind IN ('r','p')")
                ),
                &[],
            )
            .await
            .expect("tables");
        for r in rels {
            let t: String = r.get(0);
            for row in c
                .query(&format!("SELECT row_to_json(x)::text FROM {t} x"), &[])
                .await
                .expect("rows")
            {
                out.push(format!("row\t{t}\t{}", esc(&row.get::<_, String>(0))));
            }
        }
        out.sort();
        out
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    use super::catalog;

    /// The frozen edition-1 catalog; on SQLite with
    /// [`super::KEYS_EDITION_TWO_SQLITE`] applied to `federation_keys`' DDL
    /// (SQLite rewrites the stored text), executed on a scratch connection.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn fixture(dialect: &str) -> Vec<String> {
        let text = std::fs::read_to_string(catalog::fixture_path(dialect))
            .expect("the frozen edition-1 catalog");
        #[cfg_attr(not(feature = "sqlite"), allow(unused_mut))]
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        #[cfg(feature = "sqlite")]
        if dialect == "sqlite" {
            for (table, alters) in [
                ("federation_keys", super::KEYS_EDITION_TWO_SQLITE),
                (
                    "federation_attestations",
                    super::ATTESTATIONS_EDITION_TWO_SQLITE,
                ),
            ] {
                let head = format!("object\ttable\t{table}\t{table}\t");
                let line = lines
                    .iter_mut()
                    .find(|l| l.starts_with(&head))
                    .unwrap_or_else(|| panic!("{table} in the fixture"));
                let ddl = unesc(&line[head.len()..]);
                let c = rusqlite::Connection::open_in_memory().unwrap();
                c.execute_batch(&ddl).unwrap();
                for alter in alters {
                    c.execute_batch(alter).unwrap();
                }
                let after: String = c
                    .query_row(
                        "SELECT sql FROM sqlite_master WHERE name = ?1",
                        [table],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_ne!(after, ddl, "the edition-2 change to {table} applied");
                *line = format!("{head}{}", esc(&after));
            }
            // v62.0.0 (F0-cp5) — the delivery table's edition-2 DDL, edited in
            // V300's CREATE TABLE: its text replaces the frozen one.
            let table = super::DELIVERY_TABLE.0;
            let head = format!("object\ttable\t{table}\t{table}\t");
            let line = lines
                .iter_mut()
                .find(|l| l.starts_with(&head))
                .unwrap_or_else(|| panic!("{table} in the fixture"));
            assert_ne!(
                unesc(&line[head.len()..]),
                super::DELIVERY_SQLITE_DDL,
                "the frozen edition-1 delivery DDL differs from edition 2's"
            );
            *line = format!("{head}{}", esc(super::DELIVERY_SQLITE_DDL));
            // v62.0.0 (P8-fix14) — the restatement index, an edition-2 object
            // on an edition-1 table.
            let (name, ddl) = super::ATTESTATIONS_RESTATEMENT_INDEX;
            lines.push(format!(
                "object\tindex\t{name}\tfederation_attestations\t{}",
                esc(ddl)
            ));
            lines.sort();
        }
        lines
    }

    #[cfg(feature = "sqlite")]
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('\n', "\\n")
            .replace('\t', "\\t")
    }

    #[cfg(feature = "sqlite")]
    fn unesc(s: &str) -> String {
        let mut out = String::new();
        let mut it = s.chars();
        while let Some(c) = it.next() {
            if c == '\\' {
                match it.next() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some(o) => out.push(o),
                    None => out.push('\\'),
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    /// Every statement edition 2 adds to edition 1's tables is in the
    /// shipped baseline verbatim (so the constant the witness applies is
    /// the file's own text).
    #[test]
    fn i1950_the_key_columns_are_the_baselines_text() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let sqlite =
            std::fs::read_to_string(root.join("sqlite/lens/V300__edition2_baseline.sql")).unwrap();
        for a in super::KEYS_EDITION_TWO_SQLITE {
            assert_eq!(sqlite.matches(a).count(), 1, "I1950: {a}");
        }
        assert_eq!(
            sqlite.matches(super::DELIVERY_SQLITE_DDL).count(),
            1,
            "I1950: the delivery table's edition-2 DDL is V300's own text"
        );
        let pg = std::fs::read_to_string(root.join("postgres/lens/V300__edition2_baseline.sql"))
            .unwrap();
        assert_eq!(pg.matches(super::KEYS_EDITION_TWO_POSTGRES).count(), 1);
        // v62.0.0 (P8-fix14) — the restatement column and index, verbatim.
        for a in super::ATTESTATIONS_EDITION_TWO_SQLITE {
            assert_eq!(sqlite.matches(a).count(), 1, "I1950: {a}");
        }
        assert_eq!(
            sqlite
                .matches(&format!("{};", super::ATTESTATIONS_RESTATEMENT_INDEX.1))
                .count(),
            1,
            "I1950: the restatement index is V300's own text"
        );
        for a in super::ATTESTATIONS_EDITION_TWO_POSTGRES {
            assert_eq!(pg.matches(a).count(), 1, "I1950: {a}");
        }
        // The PostgreSQL delivery table carries the composite, not the
        // earlier columns (its edition-1 DDL edited in place).
        let at = pg
            .find("CREATE TABLE cirisnode.federation_delivery_attestations (")
            .expect("the delivery table in V300 (postgres)");
        let block = &pg[at..at + pg[at..].find("\n);").expect("its end")];
        for c in super::DELIVERY_DROPPED_COLUMNS {
            assert!(!block.contains(c), "I1950: {c} is gone (postgres)");
        }
        assert!(block.contains("signature_composite bytea NOT NULL"));
        assert!(!pg.contains("DROP COLUMN"), "I1950: no DROP COLUMN in V300");
        assert!(
            !sqlite.contains("DROP COLUMN"),
            "I1950: no DROP COLUMN in V300"
        );
    }

    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn diff(want: &[String], got: &[String]) -> String {
        let (w, g): (std::collections::BTreeSet<_>, std::collections::BTreeSet<_>) =
            (want.iter().collect(), got.iter().collect());
        let mut s = String::new();
        for x in w.difference(&g).take(20) {
            s.push_str(&format!("- edition 1: {}\n", &x[..x.len().min(300)]));
        }
        for x in g.difference(&w).take(20) {
            s.push_str(&format!("+ baseline:  {}\n", &x[..x.len().min(300)]));
        }
        s
    }

    /// **I1950 (sqlite) — the baseline builds edition 1's schema.** A store
    /// opened and migrated through the open path (the baseline alone)
    /// carries every `sqlite_schema` row edition 1's V001..V216 left, DDL
    /// text byte for byte, and V081's seeded row; the edition-2 additions are
    /// the only other objects.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1950_the_baseline_builds_edition_ones_schema_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let all = catalog::sqlite(&b.conn_handle().lock());
        // v62.0.0 (P1-fix8, I4007) — the exact ledger facts, set aside on
        // both sides and checked in the baseline's own form.
        let (exact, got): (Vec<String>, Vec<String>) =
            all.into_iter().partition(|l| super::exact_ledger_fact(l));
        let (was, want): (Vec<String>, Vec<String>) = fixture("sqlite")
            .into_iter()
            .partition(|l| super::exact_ledger_fact(l));
        assert_eq!(
            (exact.len(), was.len()),
            (3, 3),
            "I4007: {exact:?} / {was:?}"
        );
        let joined = exact.join("\n");
        for needle in [
            "balance                       TEXT NOT NULL DEFAULT '0'",
            "expertise                     TEXT NOT NULL DEFAULT '0'",
            "WHERE expertise <> '0' AND is_active = 1",
        ] {
            assert!(
                joined.contains(needle),
                "I4007 (sqlite): {needle} in {joined}"
            );
        }
        assert!(
            !joined.contains("REAL"),
            "I4007 (sqlite): no float ledger column"
        );
        assert!(want.len() > 500, "I1950: the fixture is edition 1's");
        assert!(got == want, "I1950 (sqlite):\n{}", diff(&want, &got));
        for t in super::EDITION_TWO_ADDITIONS {
            let n: i64 = b
                .conn_handle()
                .lock()
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [t],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "I1950: the addition {t} is there");
        }
        for (table, column) in super::SIGNER_FKS {
            let n: i64 = b
                .conn_handle()
                .lock()
                .query_row(
                    "SELECT count(*) FROM pragma_foreign_key_list(?1) WHERE \"from\" = ?2 \
                     AND \"table\" = 'federation_keys'",
                    [table, column],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "I1950: the FK on {table}.{column} stays");
        }
    }

    /// **I1950 (postgres) — the baseline builds edition 1's schema**: every
    /// column, constraint, index, sequence, trigger, view, function, ACL,
    /// default ACL, comment and seeded row in persist's schemas.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1950_the_baseline_builds_edition_ones_schema_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let c = crate::store::postgres::dedicated_connect_to(&dsn)
            .await
            .unwrap();
        let all = catalog::postgres(&c).await;
        // The federation_keys columns and constraints edition 2 adds.
        let added = |l: &String| {
            super::KEYS_EDITION_TWO_COLUMNS.iter().any(|col| {
                l.starts_with("col\tcirislens.federation_keys\t")
                    && l.split('\t').nth(3) == Some(col)
            }) || super::KEYS_EDITION_TWO_PG_CONSTRAINTS
                .iter()
                .any(|k| l.starts_with(&format!("con\tcirislens.federation_keys\t{k}\t")))
        };
        // v62.0.0 (P8-fix14) — the restatement column and its index.
        let restatement = |l: &String| {
            (l.starts_with("col\tcirislens.federation_attestations\t")
                && super::ATTESTATIONS_EDITION_TWO_COLUMNS
                    .iter()
                    .any(|col| l.split('\t').nth(3) == Some(col)))
                || (l.starts_with("idx\t")
                    && l.contains(&format!(
                        "INDEX {} ON cirislens.federation_attestations",
                        super::ATTESTATIONS_RESTATEMENT_INDEX.0
                    )))
        };
        assert_eq!(
            all.iter().filter(|l| restatement(l)).count(),
            super::ATTESTATIONS_EDITION_TWO_COLUMNS.len() + 1,
            "I1950: the restatement column and index are there"
        );
        let all: Vec<String> = all.into_iter().filter(|l| !restatement(l)).collect();
        let n_added = all.iter().filter(|l| added(l)).count();
        assert_eq!(
            n_added,
            super::KEYS_EDITION_TWO_COLUMNS.len() + super::KEYS_EDITION_TWO_PG_CONSTRAINTS.len(),
            "I1950: the federation_keys additions are there"
        );
        // v62.0.0 (F0-cp5) — the delivery attestation's change: its added
        // column and constraint leave `got`, its dropped ones leave `want`,
        // and its columns are compared without their position (a dropped
        // column renumbers the ones after it).
        let (dcol, dcon) = (
            format!("col\t{}\t", super::DELIVERY_TABLE.1),
            format!("con\t{}\t", super::DELIVERY_TABLE.1),
        );
        let delivery = |l: &String, cols: &[&str], cons: &[&str]| {
            (l.starts_with(&dcol) && cols.iter().any(|c| l.split('\t').nth(3) == Some(c)))
                || (l.starts_with(&dcon) && cons.iter().any(|k| l.split('\t').nth(2) == Some(k)))
        };
        let unposition = |l: String| -> String {
            if l.starts_with(&dcol) {
                let mut f: Vec<&str> = l.split('\t').collect();
                f[2] = "_";
                f.join("\t")
            } else {
                l
            }
        };
        let n_delivery = all
            .iter()
            .filter(|l| {
                delivery(
                    l,
                    super::DELIVERY_ADDED_COLUMNS,
                    super::DELIVERY_ADDED_PG_CONSTRAINTS,
                )
            })
            .count();
        assert_eq!(
            n_delivery,
            super::DELIVERY_ADDED_COLUMNS.len() + super::DELIVERY_ADDED_PG_CONSTRAINTS.len(),
            "I1950: the delivery attestation's composite column is there"
        );
        let mut got: Vec<String> = all
            .into_iter()
            .filter(|l| !added(l))
            .filter(|l| {
                !delivery(
                    l,
                    super::DELIVERY_ADDED_COLUMNS,
                    super::DELIVERY_ADDED_PG_CONSTRAINTS,
                )
            })
            .map(unposition)
            .collect();
        let mut want: Vec<String> = fixture("postgres")
            .into_iter()
            .filter(|l| {
                !delivery(
                    l,
                    super::DELIVERY_DROPPED_COLUMNS,
                    super::DELIVERY_DROPPED_PG_CONSTRAINTS,
                )
            })
            .map(unposition)
            .collect();
        // Both sides re-sorted: the unpositioned lines no longer sort as the
        // positioned ones did.
        got.sort();
        want.sort();
        // v62.0.0 (P1-fix8, I4007) — the exact ledger facts, set aside on
        // both sides and checked in the baseline's own form (after the delivery
        // attestation's filter; `partition` keeps each side's sorted order).
        let (exact, got): (Vec<String>, Vec<String>) =
            got.into_iter().partition(|l| super::exact_ledger_fact(l));
        let (was, want): (Vec<String>, Vec<String>) =
            want.into_iter().partition(|l| super::exact_ledger_fact(l));
        assert_eq!(
            (exact.len(), was.len()),
            (4, 4),
            "I4007: {exact:?} / {was:?}"
        );
        let joined = exact.join("\n");
        assert!(
            exact
                .iter()
                .filter(|l| l.starts_with("col\t"))
                .all(|l| l.split('\t').nth(4) == Some("numeric")),
            "I4007 (postgres): the ledger columns are numeric: {joined}"
        );
        assert!(
            !joined.contains("double precision"),
            "I4007 (postgres): no float: {joined}"
        );
        assert!(want.len() > 1500, "I1950: the fixture is edition 1's");
        assert!(got == want, "I1950 (postgres):\n{}", diff(&want, &got));
        for t in super::EDITION_TWO_ADDITIONS {
            let n: i64 = c
                .query_one(
                    "SELECT count(*) FROM pg_class k JOIN pg_namespace n ON n.oid = k.relnamespace \
                     WHERE n.nspname = 'cirislens' AND k.relname = $1",
                    &[t],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(n, 1, "I1950: the addition {t} is there");
        }
        for (table, column) in super::SIGNER_FKS {
            let n: i64 = c
                .query_one(
                    "SELECT count(*) FROM pg_constraint k JOIN pg_attribute a \
                     ON a.attrelid = k.conrelid AND a.attnum = ANY(k.conkey) \
                     WHERE k.contype = 'f' AND k.conrelid = ('cirislens.' || $1)::regclass \
                     AND k.confrelid = 'cirislens.federation_keys'::regclass AND a.attname = $2",
                    &[table, column],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(n, 1, "I1950: the FK on {table}.{column} stays");
        }
    }
}
