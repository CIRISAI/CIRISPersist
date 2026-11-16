//! v62.0.0 (slice E2b, CC rc20 "nothing carries") — **the edition-2 baseline
//! and the witness that it builds edition 1's schema.**
//!
//! Edition 1 was V001..V216 (197 SQLite files, 205 PostgreSQL files). Edition
//! 2 is ONE baseline per dialect, `migrations/{sqlite,postgres}/lens/V300__edition2_baseline.sql`,
//! then whatever appends after it (V301, V302, ...). The baseline's first part
//! is edition 1's schema as V216 left it, object for object; its last part is
//! the edition-2 additions, [`EDITION_TWO_ADDITIONS`].
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

// The constants are wired into the runner in the next commit.
#![allow(dead_code)]

/// The version of the edition-2 baseline. An edition-1 history holds versions
/// 1..=216 only; nothing of edition 2 is numbered below this.
pub(crate) const EDITION_TWO_BASELINE: i32 = 300;

/// The highest version edition 1 ever shipped (V216, v62-int).
pub(crate) const EDITION_ONE_HEAD: i32 = 216;

/// The tables the baseline adds to edition 1's schema. Each later edition-2
/// table either joins this list (when it goes into the baseline before v62
/// ships) or arrives as V301+.
///
/// - `store_edition_deletions` — the local-tier record of an earlier store's
///   deletion ([`crate::store::edition_upgrade`]).
/// - `ceg_statements`, `ceg_row_names` — slice E2a's edition-2 statements.
pub(crate) const EDITION_TWO_ADDITIONS: &[&str] =
    &["store_edition_deletions", "ceg_statements", "ceg_row_names"];

#[cfg(test)]
pub(crate) mod catalog {
    //! The normalized catalogs the I1950 witness compares.

    /// Where the frozen edition-1 catalogs live.
    pub(crate) fn fixture_path(dialect: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/edition1_schema")
            .join(format!("{dialect}.catalog"))
    }

    /// One line per catalog fact, newlines escaped.
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('\n', "\\n")
            .replace('\t', "\\t")
    }

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
