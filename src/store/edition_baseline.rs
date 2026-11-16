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
#[cfg_attr(not(test), allow(dead_code))] // the witnesses read it
pub(crate) const EDITION_TWO_ADDITIONS: &[&str] =
    &["store_edition_deletions", "ceg_statements", "ceg_row_names"];

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

#[cfg(test)]
mod tests {
    use super::catalog;

    /// The frozen edition-1 catalog; on SQLite with
    /// [`super::KEYS_EDITION_TWO_SQLITE`] applied to `federation_keys`' DDL
    /// (SQLite rewrites the stored text), executed on a scratch connection.
    fn fixture(dialect: &str) -> Vec<String> {
        let text = std::fs::read_to_string(catalog::fixture_path(dialect))
            .expect("the frozen edition-1 catalog");
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        #[cfg(feature = "sqlite")]
        if dialect == "sqlite" {
            let head = "object\ttable\tfederation_keys\tfederation_keys\t";
            let line = lines
                .iter_mut()
                .find(|l| l.starts_with(head))
                .expect("federation_keys in the fixture");
            let ddl = unesc(&line[head.len()..]);
            let c = rusqlite::Connection::open_in_memory().unwrap();
            c.execute_batch(&ddl).unwrap();
            for alter in super::KEYS_EDITION_TWO_SQLITE {
                c.execute_batch(alter).unwrap();
            }
            let after: String = c
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE name = 'federation_keys'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_ne!(after, ddl, "the edition-2 columns applied");
            *line = format!("{head}{}", esc(&after));
        }
        lines
    }

    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('\n', "\\n")
            .replace('\t', "\\t")
    }

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
        let pg = std::fs::read_to_string(root.join("postgres/lens/V300__edition2_baseline.sql"))
            .unwrap();
        assert_eq!(pg.matches(super::KEYS_EDITION_TWO_POSTGRES).count(), 1);
    }

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
        let got = catalog::sqlite(&b.conn_handle().lock());
        let want = fixture("sqlite");
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
        let n_added = all.iter().filter(|l| added(l)).count();
        assert_eq!(
            n_added,
            super::KEYS_EDITION_TWO_COLUMNS.len() + super::KEYS_EDITION_TWO_PG_CONSTRAINTS.len(),
            "I1950: the federation_keys additions are there"
        );
        let got: Vec<String> = all.into_iter().filter(|l| !added(l)).collect();
        let want = fixture("postgres");
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
