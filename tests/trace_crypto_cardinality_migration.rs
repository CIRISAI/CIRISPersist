//! CIRISPersist#789 — the V135 backfill must not lose a signature.
//!
//! The migration creates `trace_thought_signatures`, backfills it from
//! `trace_events`, and DROPS the two per-event crypto columns — in that order,
//! inside one refinery transaction. This asserts the property that ordering
//! exists for: after migrating a database that already held per-event
//! signatures, every distinct signature is still present, keyed by the thought
//! it covers.
//!
//! Worth testing rather than reasoning about, because the failure is
//! unrecoverable. The corpus is durable, replicated and kept for posterity; a
//! drop that outran its backfill would destroy 7,264 signatures with nothing
//! to restore them from.

#![cfg(feature = "sqlite")]

/// Build a pre-V135 `trace_events` (the two columns still present), populate
/// it the way the live canonical is — one signature repeated across every
/// event row of a thought — then replay V135's DDL and assert nothing was
/// lost.
#[test]
fn v135_backfill_preserves_every_signature_789() {
    let conn = rusqlite::Connection::open_in_memory().expect("open");
    conn.execute_batch(
        "CREATE TABLE trace_events (
             event_id INTEGER PRIMARY KEY AUTOINCREMENT,
             thought_id TEXT NOT NULL,
             signature_ml_dsa_65 TEXT,
             pubkey_ml_dsa_65 TEXT,
             pqc_key_id TEXT,
             ts TEXT
         );
         CREATE INDEX trace_events_pqc_key
             ON trace_events (pqc_key_id, ts DESC)
             WHERE signature_ml_dsa_65 IS NOT NULL;",
    )
    .expect("pre-V135 schema");

    // Three thoughts, four events each — the shape that produced the waste:
    // one signature per thought, copied onto every event of it.
    for t in 0..3 {
        for _ in 0..4 {
            conn.execute(
                "INSERT INTO trace_events
                     (thought_id, signature_ml_dsa_65, pubkey_ml_dsa_65, pqc_key_id, ts)
                 VALUES (?1, ?2, ?3, ?4, '2027-01-01T00:00:00+00:00')",
                rusqlite::params![
                    format!("thought-{t}"),
                    format!("sig-{t}"),
                    "the-one-shared-pubkey",
                    "key-1",
                ],
            )
            .expect("insert");
        }
    }

    let v135 = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations/sqlite/lens/V135__trace_thought_signatures.sql"
    ))
    .expect("V135 readable");
    conn.execute_batch(&v135).expect("V135 applies cleanly");

    // Every signature survived, exactly once, keyed by its thought.
    let mut stmt = conn
        .prepare("SELECT thought_id, signature_ml_dsa_65, pqc_key_id FROM trace_thought_signatures ORDER BY thought_id")
        .expect("prepare");
    let rows: Vec<(String, String, Option<String>)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("collect");

    assert_eq!(
        rows,
        vec![
            (
                "thought-0".to_owned(),
                "sig-0".to_owned(),
                Some("key-1".to_owned())
            ),
            (
                "thought-1".to_owned(),
                "sig-1".to_owned(),
                Some("key-1".to_owned())
            ),
            (
                "thought-2".to_owned(),
                "sig-2".to_owned(),
                Some("key-1".to_owned())
            ),
        ],
        "#789: every distinct signature must survive the backfill, keyed by the \
         thought it covers — 12 event rows carried 3 signatures, and all 3 are \
         here exactly once"
    );

    // …and the per-event columns are GONE, which is the 679 MB.
    let cols: Vec<String> = conn
        .prepare("PRAGMA table_info(trace_events)")
        .expect("prepare")
        .query_map([], |r| r.get::<_, String>(1))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("collect");
    assert!(
        !cols.contains(&"signature_ml_dsa_65".to_owned())
            && !cols.contains(&"pubkey_ml_dsa_65".to_owned()),
        "#789: both per-event crypto columns must be dropped; trace_events has {cols:?}"
    );
    assert!(
        cols.contains(&"pqc_key_id".to_owned()),
        "#789: pqc_key_id STAYS — it is how the pubkey is resolved from the \
         directory now that the inline copy is gone"
    );
}

/// The backfill REFUSES rather than silently picking a winner when a thought
/// carries two different signatures.
///
/// That assumption ("the signature is a total function of thought_id",
/// measured as 7,264 signatures over 7,264 thoughts) is the one thing that
/// would make this migration lossy if it were ever false. The PRIMARY KEY is
/// what turns it from an assumption into an enforced precondition: `SELECT
/// DISTINCT` yields two rows for such a thought, the PK is violated, and the
/// migration aborts BEFORE either column is dropped.
#[test]
fn v135_refuses_a_thought_with_two_signatures_789() {
    let conn = rusqlite::Connection::open_in_memory().expect("open");
    conn.execute_batch(
        "CREATE TABLE trace_events (
             event_id INTEGER PRIMARY KEY AUTOINCREMENT,
             thought_id TEXT NOT NULL,
             signature_ml_dsa_65 TEXT,
             pubkey_ml_dsa_65 TEXT,
             pqc_key_id TEXT,
             ts TEXT
         );
         CREATE INDEX trace_events_pqc_key
             ON trace_events (pqc_key_id, ts DESC)
             WHERE signature_ml_dsa_65 IS NOT NULL;
         INSERT INTO trace_events (thought_id, signature_ml_dsa_65, pqc_key_id, ts)
             VALUES ('t1','sigA','k',''), ('t1','sigB','k','');",
    )
    .expect("pre-V135 schema with a contradictory thought");

    let v135 = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations/sqlite/lens/V135__trace_thought_signatures.sql"
    ))
    .expect("V135 readable");

    let err = conn.execute_batch(&v135).expect_err(
        "#789: a thought with two distinct signatures must ABORT the migration — \
         silently keeping one would discard a signature that cannot be \
         reconstructed",
    );
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("unique") || msg.to_lowercase().contains("constraint"),
        "#789: expected a PRIMARY KEY violation from the self-asserting \
         backfill, got: {msg}"
    );

    // And the columns are STILL THERE — the drop never ran.
    let cols: Vec<String> = conn
        .prepare("PRAGMA table_info(trace_events)")
        .expect("prepare")
        .query_map([], |r| r.get::<_, String>(1))
        .expect("query")
        .collect::<Result<_, _>>()
        .expect("collect");
    assert!(
        cols.contains(&"signature_ml_dsa_65".to_owned()),
        "#789: the abort must leave the source columns intact — a failed \
         backfill followed by a completed drop is the unrecoverable case this \
         ordering exists to prevent"
    );
}
