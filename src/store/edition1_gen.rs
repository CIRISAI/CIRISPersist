//! TEMPORARY (slice E2b) — dump what V001..V216 build today, through the real
//! open path, so the edition-2 baseline can be written from it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(feature = "sqlite")]
#[tokio::test]
#[ignore]
async fn e2b_gen_sqlite() {
    use crate::store::backend::Backend;
    let Ok(out) = std::env::var("E2B_GEN_OUT") else {
        return;
    };
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    let h = b.conn_handle();
    let c = h.lock();
    let mut st = c
        .prepare("SELECT rowid, type, name, tbl_name, sql FROM sqlite_master ORDER BY rowid")
        .unwrap();
    let rows: Vec<(i64, String, String, String, Option<String>)> = st
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let mut s = String::new();
    for r in &rows {
        s.push_str(&serde_json::to_string(&serde_json::json!([r.0, r.1, r.2, r.3, r.4])).unwrap());
        s.push('\n');
    }
    std::fs::write(format!("{out}/sqlite_master.jsonl"), s).unwrap();
    let mut d = String::new();
    for r in rows.iter().filter(|r| r.1 == "table") {
        let n: i64 = c
            .query_row(&format!("SELECT count(*) FROM \"{}\"", r.2), [], |x| {
                x.get(0)
            })
            .unwrap();
        d.push_str(&format!("{}\t{}\n", r.2, n));
    }
    std::fs::write(format!("{out}/sqlite_counts.tsv"), d).unwrap();
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore]
async fn e2b_gen_postgres() {
    use crate::store::backend::Backend;
    let Ok(dsn) = std::env::var("E2B_GEN_PG") else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore]
async fn e2b_gen_postgres_union() {
    let Ok(dsn) = std::env::var("E2B_GEN_PG_UNION") else {
        return;
    };
    let Ok(out) = std::env::var("E2B_GEN_OUT") else {
        return;
    };
    let migs = crate::store::migration_runner::postgres_migrations();
    let mut c = crate::store::postgres::dedicated_connect_to(&dsn)
        .await
        .unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for m in &migs {
        crate::store::migration_runner::run_postgres(
            &mut c,
            &migs,
            Some(m.version),
            &crate::host::clock::now,
        )
        .await
        .unwrap();
        for r in c
            .query(
                "SELECT n.nspname::text, c.relname::text, c.relkind::text FROM pg_class c \
                 JOIN pg_namespace n ON n.oid = c.relnamespace \
                 WHERE n.nspname IN ('cirislens','cirislens_derived','cirislens_secrets','cirisnode','cirisgraph','public') \
                 AND c.relkind IN ('r','p','v','m','f')",
                &[],
            )
            .await
            .unwrap()
        {
            seen.insert((r.get::<_, String>(0), r.get::<_, String>(1), r.get::<_, String>(2)));
        }
    }
    let mut s = String::new();
    for (a, b, k) in seen {
        s.push_str(&format!("{a}\t{b}\t{k}\n"));
    }
    std::fs::write(format!("{out}/pg_union.tsv"), s).unwrap();
}

fn diff(a: &[String], b: &[String]) -> String {
    let sa: std::collections::BTreeSet<_> = a.iter().collect();
    let sb: std::collections::BTreeSet<_> = b.iter().collect();
    let mut s = String::new();
    for x in sa.difference(&sb).take(20) {
        s.push_str(&format!("- {}\n", &x[..x.len().min(400)]));
    }
    for x in sb.difference(&sa).take(20) {
        s.push_str(&format!("+ {}\n", &x[..x.len().min(400)]));
    }
    s
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn e2b_i1950_pre_sqlite() {
    use crate::store::backend::Backend;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    let theirs = crate::store::edition_baseline::catalog::sqlite(&b.conn_handle().lock());
    let c = rusqlite::Connection::open_in_memory().unwrap();
    c.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    c.execute_batch(include_str!(
        "../../migrations/sqlite/edition2/V300__edition2_baseline.sql"
    ))
    .unwrap();
    let ours = crate::store::edition_baseline::catalog::sqlite(&c);
    if let Ok(dir) = std::env::var("E2B_FIXTURE") {
        std::fs::write(format!("{dir}/sqlite.catalog"), theirs.join("\n") + "\n").unwrap();
    }
    assert!(theirs.len() > 500, "{}", theirs.len());
    assert!(
        theirs == ours,
        "sqlite catalogs differ:\n{}",
        diff(&theirs, &ours)
    );
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn e2b_i1950_pre_postgres() {
    use crate::store::backend::Backend;
    let (Some(a), Some(bdsn)) = (crate::test_pg::empty_dsn(), crate::test_pg::empty_dsn()) else {
        panic!("no test postgres");
    };
    let pg = crate::store::postgres::PostgresBackend::connect(&a)
        .await
        .unwrap();
    pg.run_migrations().await.unwrap();
    let ca = crate::store::postgres::dedicated_connect_to(&a)
        .await
        .unwrap();
    let theirs = crate::store::edition_baseline::catalog::postgres(&ca).await;
    let mut cb = crate::store::postgres::dedicated_connect_to(&bdsn)
        .await
        .unwrap();
    let tx = cb.transaction().await.unwrap();
    tx.batch_execute(include_str!(
        "../../migrations/postgres/edition2/V300__edition2_baseline.sql"
    ))
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let ours = crate::store::edition_baseline::catalog::postgres(&cb).await;
    if let Ok(dir) = std::env::var("E2B_FIXTURE") {
        std::fs::write(format!("{dir}/postgres.catalog"), theirs.join("\n") + "\n").unwrap();
    }
    assert!(theirs.len() > 1500, "{}", theirs.len());
    assert!(
        theirs == ours,
        "postgres catalogs differ:\n{}",
        diff(&theirs, &ours)
    );
}
