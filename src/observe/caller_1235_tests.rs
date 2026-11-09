//! v61.1.0 (CIRISPersist#1235) — the caller-attribution witnesses.
//!
//! - **I1580** (sqlite, postgres): a door read made under
//!   `caller_scope(c, …)` is credited to `(backend, door, c)` with exactly the
//!   door's reads, rows and bytes, and nothing is left unattributed.
//! - **I1581** (sqlite, postgres): a read made under no scope is reported as
//!   `unattributed`, and a door's caller rows sum to its `reads` entry.
//! - **I1582**: a malformed label is refused (empty, one byte too long, a
//!   leading digit, an upper-case byte, a space, a non-ASCII byte, the
//!   reserved `unattributed`), and every boundary-legal label is accepted.
//! - **I1583**: the label set is capped. The first `MAX_CALLER_LABELS`
//!   distinct labels each get their own row; every label past them is counted
//!   under `other`, as is a host's own `other`; re-making a known label is
//!   its own caller, not a new one.
//! - **I1584** (sqlite, postgres): nested scopes, innermost wins: a read in
//!   the inner scope is the inner caller's, and the outer caller is credited
//!   again once the inner scope ends; a task scope wins over a thread scope,
//!   and the thread scope is credited when no task scope is in force.
//! - **I1585**: the thread scope (the PyO3 `set_caller_scope` path): a guard
//!   credits its thread's reads, a nested guard restores the outer one on
//!   drop, and dropping the last one leaves the thread unattributed.
//! - **I1586**: the snapshot keeps its old keys. Its JSON has exactly
//!   `reads`, `folds` and the additive `callers` at top level; a `reads`
//!   entry has exactly `{backend, door, reads, rows, bytes}` and a `folds`
//!   entry exactly `{fold, calls, reads, rows, bytes}`; the metric samples
//!   carry no caller label.
//! - **I1588**: a door whose every read was attributed lists no
//!   `unattributed` row, and a caller with no read lists no row.
//!
//! **I1587** (the caller scope crosses the directory capsule's worker hop)
//! lives beside the capsule's own witnesses in `ffi/directory_capsule.rs`.

use std::collections::{BTreeSet, HashSet};

use super::{
    caller_scope, current_caller, set_thread_caller, validate_caller_label, Caller,
    CallerLabelError, Door, LocalCounters, StoreBackend, ThreadCallerScope, CALLER_OTHER,
    CALLER_UNATTRIBUTED, MAX_CALLER_LABELS, MAX_CALLER_LABEL_LEN,
};

/// One sqlite read at `door`: one read, `rows` rows, `bytes` bytes, through
/// the counters half every door's `record_read` feeds.
fn read_at(door: Door, rows: u64, bytes: u64) {
    super::count_read(StoreBackend::Sqlite, door, rows, bytes);
}

// ── I1582 ────────────────────────────────────────────────────────────────

#[test]
fn i1582_malformed_labels_are_refused() {
    let longest = format!("a{}", "b".repeat(MAX_CALLER_LABEL_LEN - 1));
    for good in [
        "a",
        "server.sync_loop",
        "edge:peer-sync_2",
        "x0.y1-z2:w3_v4",
        longest.as_str(),
        CALLER_OTHER,
    ] {
        assert_eq!(
            validate_caller_label(good),
            Ok(()),
            "I1582 {good:?} is a legal label"
        );
    }
    let too_long = format!("{longest}c");
    for (bad, want) in [
        ("", CallerLabelError::Empty),
        (
            too_long.as_str(),
            CallerLabelError::TooLong {
                len: MAX_CALLER_LABEL_LEN + 1,
            },
        ),
        ("0loop", CallerLabelError::BadByte { at: 0 }),
        ("_loop", CallerLabelError::BadByte { at: 0 }),
        ("Loop", CallerLabelError::BadByte { at: 0 }),
        ("loOp", CallerLabelError::BadByte { at: 2 }),
        ("sync loop", CallerLabelError::BadByte { at: 4 }),
        ("syncé", CallerLabelError::BadByte { at: 4 }),
        ("a/b", CallerLabelError::BadByte { at: 1 }),
        (CALLER_UNATTRIBUTED, CallerLabelError::Reserved),
    ] {
        assert_eq!(
            validate_caller_label(bad),
            Err(want.clone()),
            "I1582 {bad:?} is refused"
        );
        let _local = LocalCounters::install();
        assert_eq!(
            Caller::new(bad),
            Err(want),
            "I1582 Caller::new refuses {bad:?}"
        );
    }
}

// ── I1583 ────────────────────────────────────────────────────────────────

#[test]
fn i1583_the_label_set_is_capped_and_overflow_is_other() {
    let local = LocalCounters::install();
    // Made BEFORE the cap fills: the host's own `other` is the overflow
    // bucket, and takes none of the capped-in slots.
    let early_other = Caller::new(CALLER_OTHER).expect("legal");
    let callers: Vec<Caller> = (0..MAX_CALLER_LABELS)
        .map(|i| Caller::new(&format!("caller{i}")).expect("legal"))
        .collect();
    let distinct: HashSet<Caller> = callers.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        MAX_CALLER_LABELS,
        "I1583 the first {MAX_CALLER_LABELS} labels are distinct callers"
    );
    for (i, c) in callers.iter().enumerate() {
        assert_eq!(c.label(), format!("caller{i}"), "I1583 a capped-in label");
    }
    assert_eq!(
        Caller::new("caller3").expect("legal"),
        callers[3],
        "I1583 re-making a known label is the same caller"
    );
    let over = Caller::new("one.too.many").expect("legal");
    let over2 = Caller::new("two.too.many").expect("legal");
    assert_eq!(over.label(), CALLER_OTHER, "I1583 past the cap is other");
    assert_eq!(over, over2, "I1583 every label past the cap is one bucket");
    assert_eq!(
        early_other, over,
        "I1583 the host's own `other` is the overflow bucket"
    );
    assert!(
        !distinct.contains(&over),
        "I1583 the overflow bucket is none of the capped-in callers"
    );

    for c in callers.iter().chain([&over, &over2]) {
        let _scope = ThreadCallerScope::enter(Some(*c));
        read_at(Door::GetAttestation, 1, 2);
    }
    let snap = local.snapshot();
    let rows: Vec<&str> = snap
        .callers
        .iter()
        .filter(|r| r.door == Door::GetAttestation.label())
        .map(|r| r.caller.as_str())
        .collect();
    assert_eq!(
        rows.len(),
        MAX_CALLER_LABELS + 1,
        "I1583 {MAX_CALLER_LABELS} labels and one other row: {rows:?}"
    );
    assert_eq!(
        snap.caller(StoreBackend::Sqlite, Door::GetAttestation, CALLER_OTHER),
        (2, 2, 4),
        "I1583 both overflow reads land in other"
    );
    assert_eq!(
        snap.caller(StoreBackend::Sqlite, Door::GetAttestation, "caller31"),
        (1, 1, 2),
        "I1583 the last capped-in label keeps its own row"
    );
    assert_eq!(
        snap.caller(StoreBackend::Sqlite, Door::GetAttestation, "one.too.many"),
        (0, 0, 0),
        "I1583 an overflow label gets no row of its own"
    );
}

// ── I1585 ────────────────────────────────────────────────────────────────

#[test]
fn i1585_the_thread_scope_nests_and_restores() {
    let local = LocalCounters::install();
    let (outer, inner) = (
        Caller::new("py.outer").expect("legal"),
        Caller::new("py.inner").expect("legal"),
    );
    assert_eq!(current_caller(), None, "I1585 a fresh thread has no scope");
    {
        let _o = ThreadCallerScope::enter(Some(outer));
        read_at(Door::GetAttestation, 0, 1);
        {
            let _i = ThreadCallerScope::enter(Some(inner));
            assert_eq!(current_caller(), Some(inner), "I1585 innermost wins");
            read_at(Door::GetAttestation, 0, 1);
            {
                let _cleared = ThreadCallerScope::enter(None);
                read_at(Door::GetAttestation, 0, 1);
            }
            read_at(Door::GetAttestation, 0, 1);
        }
        assert_eq!(current_caller(), Some(outer), "I1585 the outer is restored");
        read_at(Door::GetAttestation, 0, 1);
    }
    assert_eq!(current_caller(), None, "I1585 the last guard clears");
    read_at(Door::GetAttestation, 0, 1);

    // The set/clear form the PyO3 surface uses: it returns what it replaced.
    assert_eq!(set_thread_caller(Some(inner)), None);
    read_at(Door::GetAttestation, 0, 1);
    assert_eq!(set_thread_caller(None), Some(inner));

    let snap = local.snapshot();
    let at = |c: &str| snap.caller(StoreBackend::Sqlite, Door::GetAttestation, c);
    assert_eq!(at("py.outer"), (2, 0, 2), "I1585 outer: before and after");
    assert_eq!(
        at("py.inner"),
        (3, 0, 3),
        "I1585 inner: two in the guard, one set"
    );
    assert_eq!(
        at(CALLER_UNATTRIBUTED),
        (2, 0, 2),
        "I1585 the cleared guard and the read after the last guard"
    );
}

// ── I1586 / I1588 ────────────────────────────────────────────────────────

fn keys(v: &serde_json::Value) -> BTreeSet<String> {
    v.as_object().expect("an object").keys().cloned().collect()
}

fn set_of(ks: &[&str]) -> BTreeSet<String> {
    ks.iter().map(|k| (*k).to_owned()).collect()
}

#[tokio::test(flavor = "current_thread")]
async fn i1586_the_snapshot_keeps_its_old_keys() {
    let local = LocalCounters::install();
    let c = Caller::new("diag.reads").expect("legal");
    caller_scope(c, async { read_at(Door::AttestationQuery, 1, 9) }).await;
    read_at(Door::AttestationQuery, 0, 1);
    super::fold(super::Fold::TrustRootValid, async {
        read_at(Door::GetAttestation, 0, 1);
    })
    .await;
    let snap = local.snapshot();
    let json = serde_json::to_value(&snap).expect("serializes");
    assert_eq!(
        keys(&json),
        set_of(&["reads", "folds", "callers"]),
        "I1586 top level: the two old keys and the additive one"
    );
    for r in json["reads"].as_array().expect("reads") {
        assert_eq!(
            keys(r),
            set_of(&["backend", "door", "reads", "rows", "bytes"]),
            "I1586 a reads entry keeps its shape"
        );
    }
    for f in json["folds"].as_array().expect("folds") {
        assert_eq!(
            keys(f),
            set_of(&["fold", "calls", "reads", "rows", "bytes"]),
            "I1586 a folds entry keeps its shape"
        );
    }
    let callers = json["callers"].as_array().expect("callers");
    assert!(!callers.is_empty());
    for c in callers {
        assert_eq!(
            keys(c),
            set_of(&["backend", "door", "caller", "reads", "rows", "bytes"]),
            "I1586 a callers entry"
        );
    }
    assert_eq!(
        snap.door(StoreBackend::Sqlite, Door::AttestationQuery),
        (2, 1, 10),
        "I1586 the door's own totals still count every read"
    );
    for s in snap.samples() {
        assert!(
            s.labels.iter().all(|(k, _)| *k != "caller"),
            "I1586 {} carries no caller label",
            s.name
        );
    }
}

#[test]
fn i1588_absent_rows_stay_absent() {
    let local = LocalCounters::install();
    let used = Caller::new("used").expect("legal");
    let _never = Caller::new("never.read").expect("legal");
    {
        let _s = ThreadCallerScope::enter(Some(used));
        read_at(Door::GetAttestation, 1, 3);
    }
    let snap = local.snapshot();
    let rows: Vec<&str> = snap.callers.iter().map(|r| r.caller.as_str()).collect();
    assert_eq!(
        rows,
        vec!["used"],
        "I1588 a fully attributed door lists no unattributed row, and a caller \
         that read nothing lists no row"
    );
}

// ── I1580 / I1581 / I1584 on real backends ───────────────────────────────

/// The read under test: `get_attestation` of one seeded row.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) async fn i1580_i1581_i1584(
    d: &dyn crate::federation::FederationDirectory,
    backend: StoreBackend,
    tag: &str,
) {
    use crate::federation::subject_read_1225_invariants::bodies as b;
    let (a, k) = b::keys(d, tag).await;
    let id = b::put_naming(d, &a, &[&k], b::DIM, b::at(10), None).await;
    let local = LocalCounters::install();
    let id: &str = &id;
    let get = move || async move {
        d.get_attestation(id)
            .await
            .expect("I1580 the read")
            .expect("I1580 the seeded row")
    };
    let door = Door::GetAttestation;

    // I1580 — a scoped read is the scope's, whole.
    let sync = Caller::new("server.sync_loop").expect("legal");
    caller_scope(sync, get()).await;
    let snap = local.snapshot();
    let one = snap.door(backend, door);
    assert_eq!((one.0, one.1), (1, 1), "I1580 one read of one row");
    assert!(one.2 > 0, "I1580 the read decoded envelope bytes");
    assert_eq!(
        snap.caller(backend, door, "server.sync_loop"),
        one,
        "I1580 {}: the scoped read is credited to its caller",
        backend.label()
    );
    assert_eq!(
        snap.caller(backend, door, CALLER_UNATTRIBUTED),
        (0, 0, 0),
        "I1580 nothing left unattributed"
    );

    // I1581 — an unscoped read is unattributed, and the rows sum to the door.
    get().await;
    let snap = local.snapshot();
    assert_eq!(
        snap.caller(backend, door, CALLER_UNATTRIBUTED),
        one,
        "I1581 {}: the unscoped read is unattributed",
        backend.label()
    );
    assert_eq!(snap.caller(backend, door, "server.sync_loop"), one);
    let sum = snap
        .callers
        .iter()
        .filter(|r| r.backend == backend.label() && r.door == door.label())
        .fold((0, 0, 0), |s, r| {
            (s.0 + r.reads, s.1 + r.rows, s.2 + r.bytes)
        });
    assert_eq!(
        sum,
        snap.door(backend, door),
        "I1581 the rows sum to the door"
    );

    // I1584 — innermost wins, the outer resumes, task beats thread.
    let (outer, inner, thread) = (
        Caller::new("outer").expect("legal"),
        Caller::new("inner").expect("legal"),
        Caller::new("thread.scope").expect("legal"),
    );
    caller_scope(outer, async {
        get().await;
        caller_scope(inner, get()).await;
        get().await;
    })
    .await;
    {
        let _t = ThreadCallerScope::enter(Some(thread));
        caller_scope(inner, get()).await;
        get().await;
    }
    let snap = local.snapshot();
    let times = |n: u64| (n, n, one.2 * n);
    assert_eq!(
        snap.caller(backend, door, "outer"),
        times(2),
        "I1584 {}: the outer caller before and after the inner scope",
        backend.label()
    );
    assert_eq!(
        snap.caller(backend, door, "inner"),
        times(2),
        "I1584 {}: the inner scope wins over the outer, and over the thread",
        backend.label()
    );
    assert_eq!(
        snap.caller(backend, door, "thread.scope"),
        times(1),
        "I1584 {}: the thread scope where no task scope is in force",
        backend.label()
    );
    assert_eq!(
        snap.caller(backend, door, CALLER_UNATTRIBUTED),
        times(1),
        "I1584 still only the one unscoped read"
    );
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use crate::store::Backend as _;

    #[tokio::test(flavor = "current_thread")]
    async fn i1580_i1581_i1584() {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::i1580_i1581_i1584(&b, super::StoreBackend::Sqlite, "s1580").await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use crate::store::Backend as _;

    #[tokio::test(flavor = "current_thread")]
    async fn i1580_i1581_i1584() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("1235 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        super::i1580_i1581_i1584(&b, super::StoreBackend::Postgres, "p1580").await;
        eprintln!("i1580_i1581_i1584 postgres: RAN");
    }
}
