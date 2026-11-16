//! Pre-kernel baseline (CIRISKernel PR #1, `ADOPTING.md`): the vote
//! evaluator `federation::consensus::evaluate`, whose private `eligible` and
//! `counted` passes the kernel replaces with `seat::members_at`,
//! `seat::voices` and `seat::met`.
//!
//! Pure compute: no I/O, no clock. `eligible` (one seat per person over the
//! roster, a `BTreeMap`) and `counted` (the signer set mapped to voices, a
//! `BTreeSet`) run on every call, so the curve over roster size is the cost
//! of those two passes plus the protocol arm.
//!
//! Sweep: protocol × roster size × outcome.
//!
//! - protocols: `unanimous`, `majority`, `reverse_quorum:2/3:86400`,
//!   `founder_only`, and `quorum:2/3` beside them;
//! - roster sizes: 3, 16, 128, 1024;
//! - outcome `met`: every member signs (the admit arm);
//!   outcome `short`: fewer than a third sign (the shortfall arm, which
//!   builds the sorted eligible-signer list).
//!
//! The persons view is `PersonsAt::each_key()` (every key its own person).
//! The multi-device persons view (`KeySelves::of_devices`) is `#[cfg(test)]`
//! only and is not reachable from a bench.
//!
//! Re-run against the baseline:
//! `cargo bench --bench consensus_eval -- --baseline pre-kernel`.

use std::collections::BTreeSet;

use ciris_persist::federation::consensus::{evaluate, Ballot, Direction, Seat};
use ciris_persist::federation::key_person::PersonsAt;
use ciris_persist::federation::types::consensus_protocol as cp;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

const ROSTER_SIZES: [usize; 4] = [3, 16, 128, 1024];

const PROTOCOLS: [(&str, &str); 5] = [
    ("unanimous", cp::UNANIMOUS),
    ("majority", cp::MAJORITY),
    ("reverse_quorum", "reverse_quorum:2/3:86400"),
    ("founder_only", cp::FOUNDER_ONLY),
    ("quorum_2_3", "quorum:2/3"),
];

/// A synthetic roster: the first `min(3, n)` seats are founders, the rest
/// members. Key ids are zero-padded so the `BTreeMap` order is the index
/// order.
fn roster(n: usize) -> Vec<Seat> {
    (0..n)
        .map(|i| Seat {
            key_id: format!("bench-seat-{i:05}"),
            role: Some(if i < 3 { "founder" } else { "member" }.to_owned()),
            node_bearing: false,
        })
        .collect()
}

fn signers(roster: &[Seat], count: usize) -> BTreeSet<String> {
    roster
        .iter()
        .take(count)
        .map(|s| s.key_id.clone())
        .collect()
}

fn consensus_eval(c: &mut Criterion) {
    let mut group = c.benchmark_group("consensus_eval");
    for (label, protocol) in PROTOCOLS {
        for n in ROSTER_SIZES {
            let seats = roster(n);
            let all = signers(&seats, n);
            // Below every threshold in the sweep (a third, at least one so the
            // arm is past the "no eligible signer" early return).
            let few = signers(&seats, (n / 3).max(1).min(n.saturating_sub(1)).max(1));
            group.throughput(Throughput::Elements(n as u64));
            for (outcome, signed) in [("met", &all), ("short", &few)] {
                // founder_only with a short ballot of the first seats would
                // still contain a founder (admit); the short case signs with
                // the last seats instead, so the arm walks to its refusal.
                let tail: BTreeSet<String>;
                let signed = if protocol == cp::FOUNDER_ONLY && outcome == "short" {
                    tail = seats
                        .iter()
                        .rev()
                        .take(signed.len())
                        .filter(|s| s.role.as_deref() != Some("founder"))
                        .map(|s| s.key_id.clone())
                        .collect();
                    &tail
                } else {
                    signed
                };
                if signed.is_empty() {
                    continue;
                }
                let ballot = Ballot {
                    protocol,
                    subkind: None,
                    policy_blob: None,
                    roster: &seats,
                    signers: signed,
                    direction: Direction::Add,
                    subject: None,
                    persons: PersonsAt::each_key(),
                    high_water: None,
                };
                group.bench_with_input(
                    BenchmarkId::new(format!("{label}/{outcome}"), n),
                    &ballot,
                    |b, ballot| b.iter(|| black_box(evaluate(black_box(ballot)))),
                );
            }
        }
    }
    group.finish();
}

criterion_group!(benches, consensus_eval);
criterion_main!(benches);
