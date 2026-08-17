//! v35.0.0 (CIRISPersist#713) — `projection_for` baseline, captured BEFORE
//! the per-plane replication projection change lands.
//!
//! #713's acceptance criterion is "correct AND it did not move the publish
//! path" — a MEASURED before/after delta on
//! [`ciris_persist::federation::namespace::projection_for`]. This bench is
//! the "before" half; without it the criterion is unsatisfiable forever.
//!
//! ## Purity claim (the baseline's meaning depends on this)
//!
//! As of this baseline, `projection_for(cohort_scope, authority, is_tombstone)`
//! (`src/federation/namespace/mod.rs:189`) is PURE compute: one `if` on the
//! tombstone flag, then one `match` on the `&str` scope against the seven
//! `cohort_scope::*` constants, calling `AuthorityClass::is_trust_root`
//! (itself a `matches!`) on the commons arm. It returns a `Copy` enum
//! (`Projection`). No I/O, no allocation, no locks, no clock reads —
//! verified by reading the function body at commit b0c24a1. Numbers here
//! are therefore nanoseconds of branchy string comparison, nothing else;
//! any post-#713 delta beyond that scale means the change added real work
//! to the publish path.
//!
//! ## The call mix modeled
//!
//! Edge's future call shape is per envelope-ref on the publish loop
//! (`list_envelope_refs`, delivery-row build) and per announce — a loop
//! sweeping HETEROGENEOUS envelope-refs, not one hot constant. Three cases:
//!
//! 1. `publish_sweep` — the full scope × authority × tombstone
//!    cross-product ((7 known scopes + 1 unknown) × 4 authorities × 2),
//!    64 calls per iteration, `Throughput::Elements` so the chart reads
//!    per-call. This is the branch-predictor-hostile shape a real publish
//!    loop sees.
//! 2. `self_live` — the dominant single case (self-scope, non-trust-root,
//!    live): the floor.
//! 3. `unrecognized_scope` — the negative-default arm (a future scope must
//!    relay Cohort, never silently Global); measures the fall-through cost.
//!
//! Inputs AND outputs pass through `black_box` so the match cannot
//! constant-fold to its answer at compile time.

use ciris_persist::federation::namespace::{projection_for, AuthorityClass, Projection};
use ciris_persist::federation::types::cohort_scope;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

/// Every authority class. `AuthorityClass` is `#[non_exhaustive]`-free and
/// `Copy`; if a fifth class is ever added, extend this list so the sweep
/// stays a true cross-product.
const AUTHORITIES: [AuthorityClass; 4] = [
    AuthorityClass::SelfIdentity,
    AuthorityClass::AccordCoScrub,
    AuthorityClass::SubstrateSelf,
    AuthorityClass::ProducerSteward,
];

/// The 7 closed-set scopes plus one unrecognized future scope, so the sweep
/// exercises the negative-default arm alongside every named arm.
const SCOPES: [&str; 8] = [
    cohort_scope::SELF,
    cohort_scope::FAMILY,
    cohort_scope::COMMUNITY,
    cohort_scope::AFFILIATIONS,
    cohort_scope::SPECIES,
    cohort_scope::BIOSPHERE,
    cohort_scope::FEDERATION,
    "some-future-scope",
];

fn bench_publish_sweep(c: &mut Criterion) {
    // Materialize the cross-product once, outside the timed loop, the way a
    // publish loop holds heterogeneous envelope-refs it resolves one by one.
    let cases: Vec<(&str, AuthorityClass, bool)> = SCOPES
        .iter()
        .flat_map(|&s| {
            AUTHORITIES
                .iter()
                .flat_map(move |&a| [(s, a, false), (s, a, true)])
        })
        .collect();
    assert_eq!(cases.len(), 64);

    let mut group = c.benchmark_group("projection_for");
    group.throughput(Throughput::Elements(cases.len() as u64));
    group.bench_function("publish_sweep", |b| {
        b.iter(|| {
            for &(scope, authority, is_tombstone) in &cases {
                let p = projection_for(
                    black_box(scope),
                    black_box(authority),
                    black_box(is_tombstone),
                );
                black_box(p);
            }
        });
    });
    group.finish();
}

fn bench_single_cases(c: &mut Criterion) {
    let mut group = c.benchmark_group("projection_for");

    // The dominant case: self-scope identity-plane record, live, from a
    // non-trust-root authority — the floor a hot publish loop pays.
    group.bench_function("self_live", |b| {
        b.iter(|| {
            let p = projection_for(
                black_box(cohort_scope::SELF),
                black_box(AuthorityClass::SelfIdentity),
                black_box(false),
            );
            debug_assert_eq!(p, Projection::SelfOwn);
            black_box(p);
        });
    });

    // The negative-default arm: an unrecognized scope falls through every
    // named arm and must resolve to conservative Cohort relay.
    group.bench_function("unrecognized_scope", |b| {
        b.iter(|| {
            let p = projection_for(
                black_box("some-future-scope"),
                black_box(AuthorityClass::ProducerSteward),
                black_box(false),
            );
            debug_assert_eq!(p, Projection::Cohort);
            black_box(p);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_publish_sweep, bench_single_cases);
criterion_main!(benches);
