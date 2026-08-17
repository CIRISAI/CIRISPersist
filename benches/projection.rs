//! v35.0.0 (CIRISPersist#713) — `projection_for` hot-path bench: the
//! `pre-713` baseline was captured on the plane-blind resolver at `44854f0`;
//! this file now measures the PER-PLANE resolver against it.
//!
//! #713's acceptance criterion is "correct AND it did not move the publish
//! path" — a MEASURED before/after delta on
//! [`ciris_persist::federation::namespace::projection_for`]. Compare with
//! `cargo bench --bench projection -- --baseline pre-713`.
//!
//! ## Purity claim (the comparison's meaning depends on this)
//!
//! Post-#713, `projection_for(plane, cohort_scope, authority, is_tombstone)`
//! (`src/federation/namespace/mod.rs`) is still PURE compute: one `if` on the
//! tombstone flag (dispatching the pure `tombstone_ceiling` match), then one
//! exhaustive `match` on the five-variant `ObjectClass` plane whose arms each
//! `match` the `&str` scope against the seven `cohort_scope::*` constants,
//! calling `AuthorityClass::is_trust_root` (a `matches!`) on the ✱ cells. It
//! returns a `Copy` enum. No I/O, no allocation, no locks, no clock reads.
//! Numbers here are therefore nanoseconds of branchy enum + string
//! comparison, nothing else; a significant regression vs `pre-713` beyond
//! branch-predictor noise from the wider match means real work snuck onto the
//! publish path.
//!
//! ## The call mix modeled
//!
//! Edge's call shape is per envelope-ref on the publish loop
//! (`list_envelope_refs`, delivery-row build) and per announce — a loop
//! sweeping HETEROGENEOUS envelope-refs, not one hot constant. Three cases,
//! names unchanged from the baseline so criterion lines them up:
//!
//! 1. `publish_sweep` — the full plane × scope × authority × tombstone
//!    cross-product (5 planes × (7 known scopes + 1 unknown) × 4 authorities
//!    × 2), 320 calls per iteration, `Throughput::Elements` so the chart and
//!    the baseline comparison both read PER-CALL — the same per-element
//!    accounting as the 64-element pre-713 sweep, now crossed with the plane
//!    dimension the resolver gained.
//! 2. `self_live` — the dominant single case (KeyRecord plane, self-scope,
//!    non-trust-root, live): the floor. The pre-713 baseline had no plane
//!    argument; KeyRecord is the identity plane whose row IS the pre-713
//!    behavior, so this is the same semantic case.
//! 3. `unrecognized_scope` — the negative-default arm (a future scope must
//!    relay Cohort, never silently Global), on the KeyRecord plane for the
//!    same reason; measures the fall-through cost.
//!
//! Inputs AND outputs pass through `black_box` so the match cannot
//! constant-fold to its answer at compile time.

use ciris_persist::federation::namespace::{
    projection_for, AuthorityClass, ObjectClass, Projection,
};
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

/// Every projection plane (#713) — the dimension the resolver gained.
const PLANES: [ObjectClass; 5] = ObjectClass::ALL;

fn bench_publish_sweep(c: &mut Criterion) {
    // Materialize the cross-product once, outside the timed loop, the way a
    // publish loop holds heterogeneous envelope-refs it resolves one by one.
    let cases: Vec<(ObjectClass, &str, AuthorityClass, bool)> = PLANES
        .iter()
        .flat_map(|&p| {
            SCOPES.iter().flat_map(move |&s| {
                AUTHORITIES
                    .iter()
                    .flat_map(move |&a| [(p, s, a, false), (p, s, a, true)])
            })
        })
        .collect();
    assert_eq!(cases.len(), 320);

    let mut group = c.benchmark_group("projection_for");
    group.throughput(Throughput::Elements(cases.len() as u64));
    group.bench_function("publish_sweep", |b| {
        b.iter(|| {
            for &(plane, scope, authority, is_tombstone) in &cases {
                let p = projection_for(
                    black_box(plane),
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
                black_box(ObjectClass::KeyRecord),
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
                black_box(ObjectClass::KeyRecord),
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
