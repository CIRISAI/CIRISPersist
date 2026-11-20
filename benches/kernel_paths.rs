//! The kernel paths, measured AFTER the kernel move (v62.0.0), against the
//! pre-kernel baseline (`FSD/v62_docs/BENCHMARKS-pre-kernel.md`, persist
//! v61.4.1, sqlite; criterion baseline `pre-kernel`). Sqlite backend,
//! SYNTHETIC keys and rows only (the `test-anchor` fixture surface:
//! deterministic test keys, never a production key or row).
//!
//! v62.0.0 (K1-bench) — **every fixture is edition 2.** The earlier-form JSON
//! doors the baseline built through (`put_attestation_authored`,
//! `SignedAttestation`, `supersede_family_with_quorum`, the accord recovery
//! drafts) are shut or deleted at CP2. Every setup row is now a signed
//! edition-2 statement landed through the real door
//! (`ingest::put_statement`, via `fixture_switch::{land_delegation,
//! land_owner_binding, put_signed, put_statement}` and the group door's
//! `group_fixtures::put_voices`). Keys are `key:record`s (`put_key`), every
//! key id is its identity-ref (`fixture_switch::kid`), and rows a node or
//! agent key signs or voices are dated from that key's own record window
//! (`key_window_start_ms`), never the wall clock. Fixtures are built and
//! signed OUTSIDE the timed region, exactly as the baseline did.
//!
//! | group / cases | path | vs `pre-kernel` |
//! |---|---|---|
//! | `owner_of/{one_owner,cosigned,withdrawn,no_owner}` | `admission::owner_of` (the kernel's owner seat) | **like-for-like**: same path, same case names. `cosigned` is now the same shape as `one_owner` (every counted binding carries the node's own voice, CC 3.2's first binding); kept for the comparison |
//! | `ab_switched/*` | `owner_of` vs `owner_of_pre_kernel`; `trust_edge_leg_ab(kernel)` vs the former fold | **kept**: both legacy sides survive 4d; same-binary A/B over edition-2 stores |
//! | `trust_root_valid/{valid_root,uncharted_root}` | `trust_root::trust_root_valid` | **same path, different root**: the baseline's key-arm root (`establish_trust_root`) is earlier-form; the root is now W1b's ROOTED edition-2 root (`fixture_trust_root::rooted_trust_root`: a bundle-founded `infrastructure` community, its charter self-edge, this node's acceptance). Extra edges are this node's `trust:accepts:v1` edges to uncharted keys |
//! | `delegation_walk/{reach_tip,reach_miss}` | `admission::reachable_under_scope` | **like-for-like** (moderate + `sub_delegation` chains, now persons' edition-2 rows, each with the delegate's voice) |
//! | `held_head/{new_fork_from_root,new_fork_from_parent}` | the group door's supersede → `held_head_verdict` (a fork is HELD as a tip, CC 2.7.8) | **NEW names**: each iteration times a NEW quorum-voiced fork (two voices through `put_statement`); the baseline's `fork_from_*` timed a refusal of one pre-signed fork, different work |
//! | `held_head/reoffer_noop` | the door's idempotent re-offer of a held fork (the no-op fast path) | **NEW name**: it never reaches the verdict |
//! | `accord_recovery/recovery_bundle_v2` | the import door (`genesis::put_genesis_bundle`) over a later bundle carrying one holder's recovery voice (CC 4.2.6, F0-cp3 / I2874) | **NEW case**: a different operation from the baseline's `accord_recovery/*` (the earlier-form JSON recovery, deleted) |
//! | `admission_door/e2_{in_order,reversed,shuffled}` | `ingest::put_statement` of each capability edge and its delegate's voice | **NEW case names**: every admission now verifies composite (ML-DSA-65 + Ed25519) signatures, two statements per edge, so it is not like-for-like with the baseline's `admission_door/*` |
//! | `fold_recompute/{deletion_window,guardianship}` | `deletion_window::run_deletion_window_watch`, `admission::steward_bindings_of` | **like-for-like** shape (half windowed capability edges, half custody bindings), edition-2 rows |
//!
//! Deleted since the baseline: `delegation_walk/cycle_gate_*` (the cycle gate
//! is gone: the kernel's walk visits a cycle once) and the earlier-form
//! `accord_recovery/*` lineage cases.
//!
//! ## Peak memory mode (criterion does not measure memory)
//!
//! `KERNEL_PATHS_PEAK_RSS=<spec>` runs ONE pass instead of criterion and
//! prints `VmHWM` from `/proc/self/status`, after resetting the high-water
//! mark (`echo 5 > /proc/self/clear_refs`) once the fixture is built:
//!
//! - `admission:<in_order|reversed|shuffled>:<rows>` — one admission pass;
//!   also prints rows/s;
//! - `folds:<rows>` — reopen the store cold and run every fold once.
//!
//! ## Smoke mode
//!
//! `KERNEL_PATHS_SMOKE=1` builds EVERY fixture at its smallest size, asks
//! each path once, and reports each failure by name (a fixture check, not a
//! measurement). It is the first thing to run once the tree is green.
//!
//! Re-run against the baseline (see `FSD/v62_docs/BENCHMARKS-v62.md`):
//! `cargo bench --bench kernel_paths --features sqlite,test-anchor -- --baseline pre-kernel`.

use std::cell::OnceCell;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ciris_persist::federation::admission::{
    owner_of, owner_of_pre_kernel, reachable_under_scope, steward_bindings_of,
    truncate_to_substrate_resolution, DelegationTermBounds, DELEGATION_SCOPE_MODERATE,
};
use ciris_persist::federation::deletion_window::run_deletion_window_watch;
use ciris_persist::federation::edition2::fixture_genesis;
use ciris_persist::federation::edition2::fixture_switch as e2;
use ciris_persist::federation::edition2::group::GroupRecord;
use ciris_persist::federation::edition2::ingest::StatementOutcome;
use ciris_persist::federation::edition2::names::RowId;
use ciris_persist::federation::tier_ingest::test_support as ts;
use ciris_persist::federation::trust_root::{trust_edge_leg_ab, trust_root_valid};
use ciris_persist::federation::types::{
    attestation_type, cohort_scope, delegation_scope as ds, owner_binding, Family, FamilyMember,
};
use ciris_persist::federation::{Attestation, FederationDirectory};
use ciris_persist::store::{Backend as _, SqliteBackend};
use criterion::{black_box, criterion_group, BenchmarkId, Criterion, SamplingMode, Throughput};
use serde_json::json;

/// Row counts for the store-size sweeps.
const ROW_SIZES: [usize; 3] = [1_000, 16_000, 64_000];
/// Row counts for the admission-door sweep under criterion (16k and 64k run
/// as ONE pass each, in the peak-RSS mode).
const ADMISSION_SIZES: [usize; 1] = [1_000];
/// Row counts for the fold sweep under criterion (64k runs as ONE pass in
/// the peak-RSS mode: `folds:64000`).
const FOLD_SIZES: [usize; 2] = [1_000, 16_000];
/// Edges per delegation chain in the admission workload.
const CHAIN_LEN: usize = 8;
/// Fixed seed for the shuffled arrival order.
const SHUFFLE_SEED: u64 = 0x5EED_CAFE_F00D_0001;
/// Threads used to SIGN fixtures (never in a timed region).
const SIGN_THREADS: usize = 8;
/// One day, in ms.
const DAY_MS: u64 = 86_400_000;
/// How far into a key's own record window a fixture row is dated: the same
/// offset the owner-binding builder uses
/// (`tier_ingest::test_support::OWNER_BINDING_OFFSET_DAYS`, 150 days into a
/// default node / agent window, i.e. about 30 days before the day the bench
/// runs), so every row sits inside the window of every key that signs or
/// voices it.
const WINDOW_OFFSET_DAYS: u64 = 150;

// ─── shared plumbing ────────────────────────────────────────────────────────

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        // ML-DSA-65 verification overflows a 2 MB stack.
        .thread_stack_size(16 * 1024 * 1024)
        .enable_all()
        .build()
        .expect("tokio runtime")
}

/// A file-backed store in its own temp directory. The directory lives as
/// long as the value.
struct Store {
    _dir: tempfile::TempDir,
    path: PathBuf,
    backend: SqliteBackend,
}

impl Store {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bench.db");
        let backend = SqliteBackend::open(path.to_string_lossy().to_string())
            .await
            .expect("open sqlite");
        backend.run_migrations().await.expect("migrations");
        Self {
            _dir: dir,
            path,
            backend,
        }
    }

    /// A second, cold handle on the same file (fresh connections, empty
    /// sqlite page cache).
    async fn reopen(&self) -> SqliteBackend {
        SqliteBackend::open(self.path.to_string_lossy().to_string())
            .await
            .expect("reopen sqlite")
    }
}

/// Map `f` over `0..n` on [`SIGN_THREADS`] threads with large stacks.
fn par_map<T: Send>(n: usize, f: impl Fn(usize) -> T + Sync) -> Vec<T> {
    let chunk = n.div_ceil(SIGN_THREADS).max(1);
    std::thread::scope(|s| {
        let f = &f;
        let handles: Vec<_> = (0..n)
            .step_by(chunk)
            .map(|start| {
                std::thread::Builder::new()
                    .stack_size(16 * 1024 * 1024)
                    .spawn_scoped(s, move || {
                        (start..(start + chunk).min(n)).map(f).collect::<Vec<T>>()
                    })
                    .expect("spawn signer")
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("signer thread"))
            .collect()
    })
}

/// The instant a row `seed`'s key signs or voices is dated at: inside that
/// key's own record window ([`e2::key_window_start_ms`] +
/// [`WINDOW_OFFSET_DAYS`]), truncated to the substrate's resolution. A key
/// with no end (`user`) reads the default node start, so a row two keys
/// share is inside both windows.
fn window_instant(seed: &str) -> chrono::DateTime<chrono::Utc> {
    let ms = e2::key_window_start_ms(seed) + WINDOW_OFFSET_DAYS * DAY_MS;
    let at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        i64::try_from(ms).expect("a key window instant fits i64"),
    )
    .expect("a key window instant");
    truncate_to_substrate_resolution(at)
}

/// A `delegates_to(granter → grantee)` carrying `envelope`, dated at
/// `at`, sealed as `granter`'s edition-2 statement (the fixture switch is
/// ON: `seal_row_in_place` signs the statement and maps it back).
fn sealed_at(
    granter: &str,
    grantee: &str,
    envelope: &serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> Attestation {
    let mut row = ts::bare_attestation(
        &uuid::Uuid::new_v4().to_string(),
        granter,
        grantee,
        envelope,
    );
    row.attestation_type = attestation_type::DELEGATES_TO.to_owned();
    row.asserted_at = at;
    row.scrub_timestamp = at;
    ts::seal_row_in_place(granter, &mut row);
    row
}

/// A row and the further voices it needs, every statement signed up front.
struct Landing {
    row: Attestation,
    voices: Vec<Vec<u8>>,
}

impl Landing {
    /// `row` with one further voice per seed in `voicers` over its payload.
    fn of(row: Attestation, voicers: &[&str]) -> Self {
        let st = e2::carried_statement(&row).expect("a sealed edition-2 row carries its statement");
        let voices = voicers.iter().map(|s| e2::voice_of(&st, s)).collect();
        Self { row, voices }
    }
}

/// Put a landing through the door: the author's statement, then each voice
/// (`ingest::put_statement`). The last outcome.
async fn land(d: &dyn FederationDirectory, l: &Landing) -> StatementOutcome {
    let mut out = e2::put_signed(d, &l.row)
        .await
        .unwrap_or_else(|e| panic!("fixture row refused: {e}"));
    for v in &l.voices {
        out = e2::put_statement(d, v)
            .await
            .unwrap_or_else(|e| panic!("fixture voice refused: {e}"));
    }
    out
}

/// Did a landing seat its row (rather than be held short of a voice)?
fn landed(out: &StatementOutcome) -> bool {
    matches!(out, StatementOutcome::Row { .. })
}

/// Rows per backend handle before a fixture or the admission loop moves to a
/// fresh handle on the same file: under the node ingest ceiling's burst,
/// which is per backend instance.
const QUOTA_ROTATE: usize = 5_000;

/// [`land`] every landing, rotating to a fresh handle every
/// [`QUOTA_ROTATE`] landings. Panics on a landing that does not seat.
async fn land_many(store: &Store, items: &[Landing], what: &str) {
    let mut handle: Option<SqliteBackend> = None;
    for (i, l) in items.iter().enumerate() {
        if i > 0 && i % QUOTA_ROTATE == 0 {
            handle = Some(store.reopen().await);
        }
        let d: &dyn FederationDirectory = handle.as_ref().unwrap_or(&store.backend);
        let out = land(d, l).await;
        assert!(landed(&out), "{what} {i}: did not seat: {out:?}");
    }
}

/// Reset the process's peak RSS to its current RSS (Linux ≥ 4.0).
fn reset_peak_rss() -> bool {
    std::fs::write("/proc/self/clear_refs", "5").is_ok()
}

fn status_kb(field: &str) -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines()
        .find(|l| l.starts_with(field))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
}

/// xorshift64* — a fixed-seed shuffle without a `rand` dependency.
fn shuffle<T>(v: &mut [T], seed: u64) {
    let mut x = seed;
    for i in (1..v.len()).rev() {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let r = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        v.swap(i, (r % (i as u64 + 1)) as usize);
    }
}

// ─── 2. ownership ───────────────────────────────────────────────────────────

const OWNER_POOL: usize = 64;

struct OwnerFixture {
    store: Store,
    /// The identity-ref of a node bound to one owner.
    bound_node: String,
    cosigned: String,
    withdrawn: String,
    unbound: String,
}

fn owner_node_seed(i: usize) -> String {
    format!("own-node-{i:06}")
}

/// `n` owner bindings: owner `i % 64` → node `i`, each landed as the door
/// counts it (the owner's statement, then the node's own voice, CC 3.2's
/// first binding), plus three probes: `own-cosigned` (one more such binding),
/// `own-withdrawn` (bound, then the owner's `withdraws`) and `own-unbound`
/// (a node key and no binding).
async fn owner_fixture(n: usize) -> OwnerFixture {
    let store = Store::new().await;
    let d: &dyn FederationDirectory = &store.backend;
    let owners: Vec<String> = (0..OWNER_POOL)
        .map(|i| format!("own-user-{i:03}"))
        .collect();
    for o in &owners {
        e2::put_key(d, o, &["user"]).await;
    }
    for i in 0..n {
        e2::put_key(d, &owner_node_seed(i), &["node"]).await;
    }
    for probe in ["own-cosigned", "own-withdrawn", "own-unbound"] {
        e2::put_key(d, probe, &["node"]).await;
    }
    // Signed up front: each binding (dated in its node's window by the
    // builder) and its node's voice.
    let items = par_map(n, |i| {
        let node = owner_node_seed(i);
        let row = ts::owner_binding_attestation(
            &format!("own-binding-{i:06}"),
            &owners[i % OWNER_POOL],
            &node,
        );
        Landing::of(row, &[node.as_str()])
    });
    land_many(&store, &items, "owner binding").await;

    let cosigned = Landing::of(
        ts::owner_binding_attestation("own-binding-cosigned", &owners[0], "own-cosigned"),
        &["own-cosigned"],
    );
    let out = land(d, &cosigned).await;
    assert!(landed(&out), "cosigned owner binding: {out:?}");

    // Bound, then withdrawn by its owner (a composer naming the binding by
    // its node-computed id; it carries the binding's family).
    let bound = Landing::of(
        ts::owner_binding_attestation("own-binding-withdrawn", &owners[1], "own-withdrawn"),
        &["own-withdrawn"],
    );
    let out = land(d, &bound).await;
    assert!(landed(&out), "owner binding to withdraw: {out:?}");
    let withdraws = e2::composer_of(attestation_type::WITHDRAWS, &bound.row, &owners[1]);
    e2::put_signed(d, &withdraws)
        .await
        .unwrap_or_else(|e| panic!("withdraws of the owner binding: {e}"));

    OwnerFixture {
        store,
        bound_node: e2::kid(&owner_node_seed(n / 2)),
        cosigned: e2::kid("own-cosigned"),
        withdrawn: e2::kid("own-withdrawn"),
        unbound: e2::kid("own-unbound"),
    }
}

/// The probe node of an owner case, and whether it has an owner.
fn owner_probe<'a>(f: &'a OwnerFixture, case: &str) -> (&'a str, bool) {
    match case {
        "one_owner" => (f.bound_node.as_str(), true),
        "cosigned" => (f.cosigned.as_str(), true),
        "withdrawn" => (f.withdrawn.as_str(), false),
        _ => (f.unbound.as_str(), false),
    }
}

const OWNER_CASES: [&str; 4] = ["one_owner", "cosigned", "withdrawn", "no_owner"];

fn bench_owner_of(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("owner_of");
    group.sample_size(50);
    for n in ROW_SIZES {
        let cell: OnceCell<OwnerFixture> = OnceCell::new();
        let fx = || cell.get_or_init(|| rt.block_on(owner_fixture(n)));
        for case in OWNER_CASES {
            group.bench_function(BenchmarkId::new(case, n), |b| {
                let f = fx();
                let (node, expect_owner) = owner_probe(f, case);
                let got = rt
                    .block_on(owner_of(&f.store.backend, node))
                    .expect("owner_of");
                assert_eq!(got.is_some(), expect_owner, "{case}: {got:?}");
                b.iter(|| {
                    black_box(
                        rt.block_on(owner_of(&f.store.backend, black_box(node)))
                            .unwrap(),
                    )
                });
            });
        }
    }
    group.finish();
}

// ─── 2b. same-binary A/B of the switched paths (v62.0.0, slice C) ─────────

/// The persist path before the kernel and the kernel's, over the SAME
/// edition-2 store, in one binary, back to back: `owner_of` against
/// `owner_of_pre_kernel`, and the trust edge leg against persist's former
/// fold. Each pair's answers are asserted identical before timing.
fn bench_ab_switched(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("ab_switched");
    group.sample_size(40);
    let ocell: OnceCell<OwnerFixture> = OnceCell::new();
    let ofx = || ocell.get_or_init(|| rt.block_on(owner_fixture(1_000)));
    for case in OWNER_CASES {
        {
            let f = ofx();
            let (node, _) = owner_probe(f, case);
            let new = rt
                .block_on(owner_of(&f.store.backend, node))
                .expect("owner_of");
            let old = rt
                .block_on(owner_of_pre_kernel(&f.store.backend, node))
                .expect("owner_of_pre_kernel");
            assert_eq!(new, old, "{case}: the two answers are identical");
        }
        for (path, kernel) in [
            ("owner_of_kernel", true),
            ("owner_of_pre", false),
            ("owner_of_kernel_again", true),
            ("owner_of_pre_again", false),
        ] {
            group.bench_function(BenchmarkId::new(path, case), |b| {
                let f = ofx();
                let (node, _) = owner_probe(f, case);
                b.iter(|| {
                    if kernel {
                        black_box(
                            rt.block_on(owner_of(&f.store.backend, black_box(node)))
                                .unwrap(),
                        )
                    } else {
                        black_box(
                            rt.block_on(owner_of_pre_kernel(&f.store.backend, black_box(node)))
                                .unwrap(),
                        )
                    }
                });
            });
        }
    }
    for extra in [0usize, 16, 128] {
        let cell: OnceCell<TrustFixture> = OnceCell::new();
        let fx = || cell.get_or_init(|| rt.block_on(trust_fixture(extra)));
        for case in ["valid_root", "uncharted_root"] {
            if extra == 0 && case == "uncharted_root" {
                continue;
            }
            {
                let f = fx();
                let root = f.root_of(case);
                let a = rt
                    .block_on(trust_edge_leg_ab(&f.store.backend, &f.user, root, false))
                    .expect("pre");
                let k = rt
                    .block_on(trust_edge_leg_ab(&f.store.backend, &f.user, root, true))
                    .expect("kernel");
                assert_eq!(a, k, "{case}/{extra}: the two edge legs agree");
            }
            for (path, kernel) in [
                ("edge_leg_kernel", true),
                ("edge_leg_pre", false),
                ("edge_leg_kernel_again", true),
                ("edge_leg_pre_again", false),
            ] {
                group.bench_function(BenchmarkId::new(format!("{path}/{case}"), extra), |b| {
                    let f = fx();
                    let root = f.root_of(case);
                    b.iter(|| {
                        black_box(
                            rt.block_on(trust_edge_leg_ab(
                                &f.store.backend,
                                &f.user,
                                black_box(root),
                                kernel,
                            ))
                            .unwrap(),
                        )
                    });
                });
            }
        }
    }
    group.finish();
}

// ─── 3. trust root and the edge walk ────────────────────────────────────────

/// The node key whose acceptance edges the trust fixture reads (the "user"
/// of `trust_root_valid`).
const TR_NODE: &str = "tr-node";

struct TrustFixture {
    store: Store,
    /// This node's identity-ref (the walk's user).
    user: String,
    /// The rooted root's identity-ref.
    root: String,
    /// An accepted key with no charter.
    uncharted: String,
}

impl TrustFixture {
    fn root_of(&self, case: &str) -> &str {
        if case == "valid_root" {
            &self.root
        } else {
            &self.uncharted
        }
    }
}

fn other_root_seed(k: usize) -> String {
    format!("tr-other-root-{k:04}")
}

/// A ROOTED edition-2 trust root accepted by this node (W1b's
/// `rooted_trust_root`: the bundle in force, an `infrastructure` community
/// founded by its holders 1, 2, 3 at `quorum:2/3`, the charter self-edge,
/// this node's acceptance), plus `extra` further `trust:accepts:v1` edges
/// from this node to keys with no charter.
async fn trust_fixture(extra: usize) -> TrustFixture {
    let store = Store::new().await;
    let d: &dyn FederationDirectory = &store.backend;
    let user = e2::put_key(d, TR_NODE, &["node"]).await;
    store.backend.set_node_key_id(user.clone());
    let r = e2::rooted_trust_root(d, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    let base = e2::ms(window_instant(TR_NODE));
    for k in 0..extra {
        let other = other_root_seed(k);
        e2::put_key(d, &other, &["user"]).await;
        let edge = e2::trust_accepts_statement(
            TR_NODE,
            &other,
            &[],
            None,
            cohort_scope::FEDERATION,
            base + k as u64,
        );
        let out = e2::put_statement(d, &edge)
            .await
            .unwrap_or_else(|e| panic!("extra trust edge {k}: {e}"));
        assert!(landed(&out), "extra trust edge {k}: {out:?}");
    }
    TrustFixture {
        store,
        user,
        root: r.root,
        uncharted: e2::kid(&other_root_seed(0)),
    }
}

fn bench_trust_root(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("trust_root_valid");
    group.sample_size(50);
    for extra in [0usize, 16, 128] {
        let cell: OnceCell<TrustFixture> = OnceCell::new();
        let fx = || cell.get_or_init(|| rt.block_on(trust_fixture(extra)));
        group.bench_function(BenchmarkId::new("valid_root", extra), |b| {
            let f = fx();
            let v = rt
                .block_on(trust_root_valid(&f.store.backend, &f.user, &f.root))
                .expect("walk");
            assert!(v.valid, "the rooted root is valid: {v:?}");
            b.iter(|| {
                black_box(
                    rt.block_on(trust_root_valid(&f.store.backend, &f.user, &f.root))
                        .unwrap(),
                )
            });
        });
        if extra > 0 {
            group.bench_function(BenchmarkId::new("uncharted_root", extra), |b| {
                let f = fx();
                let v = rt
                    .block_on(trust_root_valid(&f.store.backend, &f.user, &f.uncharted))
                    .expect("walk");
                assert!(!v.valid, "a root with no charter is not valid: {v:?}");
                b.iter(|| {
                    black_box(
                        rt.block_on(trust_root_valid(&f.store.backend, &f.user, &f.uncharted))
                            .unwrap(),
                    )
                });
            });
        }
    }
    group.finish();
}

/// Chain depths for the delegation walk. The walks clamp at
/// `MAX_WITHDRAWS_DELEGATION_DEPTH` (16); 32 shows the ceiling.
const CHAIN_DEPTHS: [usize; 4] = [1, 4, 16, 32];

fn walk_key(depth: usize, i: usize) -> String {
    format!("walk-d{depth:02}-k{i:02}")
}

/// A `moderate`-scoped appointment with `sub_delegation`, so a walk may pass
/// it beyond the first hop, dated in the granter's key window with a
/// 300-day term (inside CC 2.4's one-year bound, live today).
fn moderate_edge(granter: &str, grantee: &str) -> Attestation {
    let at = window_instant(granter);
    let mut envelope = json!({
        "kind": "delegates_to",
        "scope": [DELEGATION_SCOPE_MODERATE],
        "sub_delegation": true,
    });
    DelegationTermBounds::until(at + chrono::Duration::days(300)).stamp(&mut envelope);
    sealed_at(granter, grantee, &envelope, at)
}

/// One `moderate` chain `k0 → k1 → … → k_depth` per depth, in one store.
/// Every key is a person's (`user`); each edge lands with the voices its
/// family's model names (`land_delegation`: the delegate's).
async fn walk_fixture() -> Store {
    let store = Store::new().await;
    let d: &dyn FederationDirectory = &store.backend;
    for depth in CHAIN_DEPTHS {
        for i in 0..=depth {
            e2::put_key(d, &walk_key(depth, i), &["user"]).await;
        }
        let rows = par_map(depth, |i| {
            moderate_edge(&walk_key(depth, i), &walk_key(depth, i + 1))
        });
        for (i, row) in rows.iter().enumerate() {
            let (out, missing) = e2::land_delegation(d, row)
                .await
                .unwrap_or_else(|e| panic!("moderate chain edge d{depth} e{i}: {e}"));
            assert!(
                landed(&out),
                "moderate chain edge d{depth} e{i}: {out:?}, unvoiced {missing:?}"
            );
        }
    }
    e2::put_key(d, "walk-outsider", &["user"]).await;
    store
}

fn bench_delegation_walk(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("delegation_walk");
    group.sample_size(50);
    let cell: OnceCell<Store> = OnceCell::new();
    let fx = || cell.get_or_init(|| rt.block_on(walk_fixture()));
    let outsider = e2::kid("walk-outsider");
    for depth in CHAIN_DEPTHS {
        let root = e2::kid(&walk_key(depth, 0));
        let tip = e2::kid(&walk_key(depth, depth));
        // Reach: issuer → tip over the whole chain (a miss past the ceiling).
        group.bench_function(BenchmarkId::new("reach_tip", depth), |b| {
            let s = fx();
            let hit = rt
                .block_on(reachable_under_scope(
                    &s.backend,
                    &root,
                    &tip,
                    DELEGATION_SCOPE_MODERATE,
                    64,
                ))
                .expect("walk");
            if depth <= 4 {
                assert!(hit, "depth {depth}: the tip is reached");
            } else if depth > 16 {
                assert!(!hit, "depth {depth}: past the ceiling");
            }
            b.iter(|| {
                black_box(
                    rt.block_on(reachable_under_scope(
                        &s.backend,
                        &root,
                        &tip,
                        DELEGATION_SCOPE_MODERATE,
                        64,
                    ))
                    .unwrap(),
                )
            });
        });
        // Miss: a target off the chain, so the walk exhausts it.
        group.bench_function(BenchmarkId::new("reach_miss", depth), |b| {
            let s = fx();
            b.iter(|| {
                black_box(
                    rt.block_on(reachable_under_scope(
                        &s.backend,
                        &root,
                        &outsider,
                        DELEGATION_SCOPE_MODERATE,
                        64,
                    ))
                    .unwrap(),
                )
            });
        });
        // v62.0.0: the baseline's `cycle_gate_closing` / `cycle_gate_open`
        // arms measured the v54 cycle gate, which is deleted (the kernel's
        // walk visits a cycle once). Their baselines have no v62 counterpart.
    }
    group.finish();
}

// ─── 4. heads and forks ─────────────────────────────────────────────────────

const LINEAGE_LENGTHS: [usize; 3] = [1, 16, 128];

/// The lineage family's seed (its key id is `e2::kid(BENCH_FAMILY)`).
const BENCH_FAMILY: &str = "bench-lineage-family";

fn holder_seed(i: usize) -> String {
    format!("lin-holder-{i}")
}

/// The family record at a version, named `name` (each version and each fork
/// is a distinct record by its name).
fn lineage_record(name: &str, founded_at: chrono::DateTime<chrono::Utc>) -> GroupRecord {
    GroupRecord::Family(Family {
        family_key_id: e2::kid(BENCH_FAMILY),
        family_name: name.to_owned(),
        members: (0..3)
            .map(|i| FamilyMember {
                key_id: e2::kid(&holder_seed(i)),
                joined_at: founded_at,
                role: None,
            })
            .collect(),
        founded_at,
        consensus_protocol: "quorum:2/3".to_owned(),
        consensus_protocol_entrenched: false,
        dissolved_at: None,
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    })
}

/// The voices of a version of the lineage family (`name` at `version`,
/// extending `head`), signed by `signers` (holder indices).
fn version_voices(
    name: &str,
    version: u64,
    head: Option<&RowId>,
    at_ms: u64,
    founded_at: chrono::DateTime<chrono::Utc>,
    signers: &[usize],
) -> Vec<Vec<u8>> {
    let keys: Vec<_> = signers
        .iter()
        .map(|i| e2::signing_key(&holder_seed(*i)))
        .collect();
    let refs: Vec<&_> = keys.iter().collect();
    e2::roster_voices(
        &lineage_record(name, founded_at),
        version,
        head,
        at_ms,
        &refs,
    )
}

struct LineageFixture {
    store: Store,
    /// The founding version's row id (a fork off the root names it).
    root: RowId,
    /// The held head's parent's row id and version (a fork one back).
    parent: (RowId, u64),
    /// The instant every fixture version is stated at or after.
    base_ms: u64,
    founded_at: chrono::DateTime<chrono::Utc>,
}

/// The lineage family through the group door: founded by all three holders'
/// voices (version 1), then `len` versions of two voices each
/// (`quorum:2/3`), each naming the head before it (`refs.head`).
async fn lineage_fixture(len: usize) -> LineageFixture {
    let store = Store::new().await;
    let d: &dyn FederationDirectory = &store.backend;
    for i in 0..3 {
        e2::put_key(d, &holder_seed(i), &["user"]).await;
    }
    let base_ms = e2::ms(window_instant(&holder_seed(0)));
    let founded_at =
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(i64::try_from(base_ms).expect("ms"))
            .expect("an instant");
    let founding = version_voices("lineage v0", 1, None, base_ms, founded_at, &[0, 1, 2]);
    let root = e2::row_id_of(&founding[0]);
    let out = e2::put_voices(d, &founding).await.expect("founding");
    assert!(landed(&out), "founding: {out:?}");
    let (mut head, mut version) = (root, 1u64);
    let mut parent = (root, 1u64);
    for v in 0..len {
        let voices = version_voices(
            &format!("lineage v{}", v + 1),
            version + 1,
            Some(&head),
            base_ms + 1_000 * (v as u64 + 1),
            founded_at,
            &[0, 1],
        );
        let out = e2::put_voices(d, &voices)
            .await
            .unwrap_or_else(|e| panic!("lineage version {v}: {e}"));
        assert!(landed(&out), "lineage version {v}: {out:?}");
        parent = (head, version);
        head = e2::row_id_of(&voices[0]);
        version += 1;
    }
    LineageFixture {
        store,
        root,
        parent,
        base_ms,
        founded_at,
    }
}

/// `n` forks off `prior` (at `prior_version`), each a distinct record
/// voiced by holders 0 and 1, signed here (never timed).
fn sign_forks(
    f: &LineageFixture,
    case: &str,
    prior: (RowId, u64),
    from: u64,
    n: u64,
) -> Vec<Vec<Vec<u8>>> {
    (from..from + n)
        .map(|i| {
            version_voices(
                &format!("{case} {i}"),
                prior.1 + 1,
                Some(&prior.0),
                f.base_ms + 10_000_000 + i,
                f.founded_at,
                &[0, 1],
            )
        })
        .collect()
}

fn bench_held_head(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("held_head");
    group.sample_size(30);
    for len in LINEAGE_LENGTHS {
        let cell: OnceCell<LineageFixture> = OnceCell::new();
        let fx = || cell.get_or_init(|| rt.block_on(lineage_fixture(len)));
        // A fork: a quorum-voiced version whose prior is the founding version
        // (or the held head's parent), not the held head. The door holds it
        // as a tip (CC 2.7.8; `held_head_verdict` answers through the
        // kernel). Every iteration offers a NEW fork, signed before the clock
        // starts: NEW case names (`new_fork_*`), since the baseline's
        // `fork_from_*` timed the door REFUSING one pre-signed fork, which is
        // different work. The baseline names are not reused.
        for (case, from_root) in [
            ("new_fork_from_root", true),
            ("new_fork_from_parent", false),
        ] {
            group.bench_function(BenchmarkId::new(case, len), |b| {
                let f = fx();
                let d: &dyn FederationDirectory = &f.store.backend;
                let prior = if from_root { (f.root, 1) } else { f.parent };
                let mut next: u64 = 0;
                b.iter_custom(|iters| {
                    let forks = sign_forks(f, case, prior, next, iters);
                    next += iters;
                    let t0 = Instant::now();
                    for voices in &forks {
                        let out = rt.block_on(e2::put_voices(d, voices));
                        black_box(out.is_ok());
                    }
                    t0.elapsed()
                });
            });
        }
        // The re-offer fast path: ONE fork, held as a tip before timing, then
        // offered again and again. Each re-offer is an idempotent no-op at
        // the door (its voices are already held) and never reaches the
        // verdict. Its own NEW name (`reoffer_noop`): it is not the baseline's
        // `fork_from_root` either.
        group.bench_function(BenchmarkId::new("reoffer_noop", len), |b| {
            let f = fx();
            let d: &dyn FederationDirectory = &f.store.backend;
            let fork = sign_forks(f, "reoffer", (f.root, 1), 0, 1).remove(0);
            rt.block_on(e2::put_voices(d, &fork))
                .expect("the fork is held as a tip");
            b.iter(|| black_box(rt.block_on(e2::put_voices(d, &fork)).is_ok()));
        });
    }
    group.finish();
}

// ─── 5. accord recovery (edition 2) ─────────────────────────────────────────
//
// The baseline's `accord_recovery/*` measured the earlier-form (JSON)
// recovery over a seeded accord family; it is deleted (C5-fix1). In edition 2
// a holder's recovery is a LATER genesis bundle carrying the holder's ONE
// recovery voice, judged against the recovery commitment the genesis
// pre-committed for that holder (CC 4.2.6; F0-cp3, I2874). This is a NEW
// case: the timed act is the import door placing that bundle on a store
// holding the genesis.

fn bench_accord_recovery(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("accord_recovery");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    let recovery = fixture_genesis::recover_v2(
        fixture_genesis::bundle_v2(),
        fixture_genesis::HOLDER_SEEDS[0],
    );
    group.bench_function(BenchmarkId::new("recovery_bundle_v2", 1), |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let store = rt.block_on(Store::new());
                rt.block_on(fixture_genesis::install_v2(&store.backend))
                    .expect("the genesis is installed");
                let t0 = Instant::now();
                let placed = rt.block_on(fixture_genesis::install_ceremony_v2(
                    &store.backend,
                    &recovery,
                ));
                total += t0.elapsed();
                placed.expect("the recovery bundle is placed");
            }
            total
        });
    });
    group.finish();
}

// ─── 6. the admission door (edition 2) ──────────────────────────────────────

/// The arrival order. `InOrder` names the order, so the variant keeps the
/// enum's name.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug)]
enum Order {
    InOrder,
    Reversed,
    Shuffled,
}

impl Order {
    const ALL: [Order; 3] = [Order::InOrder, Order::Reversed, Order::Shuffled];
    fn label(self) -> &'static str {
        match self {
            Order::InOrder => "in_order",
            Order::Reversed => "reversed",
            Order::Shuffled => "shuffled",
        }
    }
    /// The criterion case name: NEW (`e2_` prefix), since every admission
    /// now verifies composite signatures over two statements.
    fn case(self) -> String {
        format!("e2_{}", self.label())
    }
    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|o| o.label() == s)
    }
}

fn chain_key(chain: usize, j: usize) -> String {
    format!("adm-c{chain:05}-k{j}")
}

/// `n` capability edges in chains of [`CHAIN_LEN`] (`k0 → … → k8`, persons'
/// keys), each signed by its granter with its delegate's voice, both
/// statements signed up front.
struct AdmissionWorkload {
    keys: Vec<String>,
    items: Vec<Landing>,
}

fn admission_workload(n: usize) -> AdmissionWorkload {
    let chains = n.div_ceil(CHAIN_LEN);
    let keys = (0..chains)
        .flat_map(|c| (0..=CHAIN_LEN).map(move |j| chain_key(c, j)))
        .collect();
    let items = par_map(n, |i| {
        let (c, j) = (i / CHAIN_LEN, i % CHAIN_LEN);
        let (granter, grantee) = (chain_key(c, j), chain_key(c, j + 1));
        let row = sealed_at(
            &granter,
            &grantee,
            &json!({ "scope": ["act_on_behalf"] }),
            window_instant(&granter),
        );
        Landing::of(row, &[grantee.as_str()])
    });
    AdmissionWorkload { keys, items }
}

fn ordered(w: &AdmissionWorkload, order: Order) -> Vec<usize> {
    let mut v: Vec<usize> = (0..w.items.len()).collect();
    match order {
        Order::InOrder => {}
        Order::Reversed => v.reverse(),
        Order::Shuffled => shuffle(&mut v, SHUFFLE_SEED),
    }
    v
}

/// A fresh store with every workload key live (untimed).
async fn admission_store(w: &AdmissionWorkload) -> Store {
    let store = Store::new().await;
    for k in &w.keys {
        e2::put_key(&store.backend, k, &["user"]).await;
    }
    store
}

/// Land every edge in `order`; the elapsed time of the door calls only.
/// Every [`QUOTA_ROTATE`] edges the loop moves to a fresh handle on the same
/// file (the opens are not timed).
async fn admit_all(store: &Store, w: &AdmissionWorkload, order: &[usize]) -> Duration {
    let mut total = Duration::ZERO;
    let mut handle: Option<SqliteBackend> = None;
    for (i, chunk) in order.chunks(QUOTA_ROTATE).enumerate() {
        if i > 0 {
            handle = Some(store.reopen().await);
        }
        let d: &dyn FederationDirectory = handle.as_ref().unwrap_or(&store.backend);
        let t0 = Instant::now();
        for &k in chunk {
            black_box(land(d, &w.items[k]).await);
        }
        total += t0.elapsed();
    }
    total
}

fn bench_admission_door(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("admission_door");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    group.measurement_time(Duration::from_secs(5));
    group.warm_up_time(Duration::from_millis(1));
    for n in ADMISSION_SIZES {
        let cell: OnceCell<AdmissionWorkload> = OnceCell::new();
        let fx = || cell.get_or_init(|| admission_workload(n));
        group.throughput(Throughput::Elements(n as u64));
        for order in Order::ALL {
            group.bench_function(BenchmarkId::new(order.case(), n), |b| {
                let w = fx();
                let seq = ordered(w, order);
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let store = rt.block_on(admission_store(w));
                        total += rt.block_on(admit_all(&store, w, &seq));
                    }
                    total
                });
            });
        }
    }
    group.finish();
}

// ─── 7. fold recompute ──────────────────────────────────────────────────────

const STEWARD_POOL: usize = 32;

/// `n` rows: half custody bindings `delegates_to(steward → agent)` with the
/// ownership marker (the guardianship fold, `steward_bindings_of`, reads
/// each agent's), landed with the agent's voice; half capability edges
/// `producer → agent` carrying a future `deletion_window` (the deletion fold
/// classifies each), landed with the voices their model names (the
/// delegate's owner: the agent's steward).
struct FoldFixture {
    store: Store,
    /// The agents' identity-refs.
    agents: Vec<String>,
}

fn agent_seed(i: usize) -> String {
    format!("fold-agent-{i:06}")
}

async fn fold_fixture(n: usize) -> FoldFixture {
    let store = Store::new().await;
    let d: &dyn FederationDirectory = &store.backend;
    let stewards: Vec<String> = (0..STEWARD_POOL)
        .map(|i| format!("fold-steward-{i:03}"))
        .collect();
    for s in &stewards {
        e2::put_key(d, s, &["user"]).await;
    }
    let producers: Vec<String> = (0..STEWARD_POOL)
        .map(|i| format!("fold-producer-{i:03}"))
        .collect();
    for p in &producers {
        e2::put_key(d, p, &["user"]).await;
    }
    let half = n / 2;
    let n_agents = n - half;
    for i in 0..n_agents {
        e2::put_key(d, &agent_seed(i), &["agent"]).await;
    }
    // The custody bindings first: a windowed edge to a machine delegate
    // needs its bound owner's voice.
    let custody = par_map(n_agents, |k| {
        let agent = agent_seed(k);
        let row = sealed_at(
            &stewards[k % STEWARD_POOL],
            &agent,
            &json!({
                "kind": "delegates_to",
                "dimension": owner_binding::DIMENSION,
                "delegation_purpose": owner_binding::PURPOSE,
                "scope": [ds::AGENCY_ACT_ON_BEHALF],
            }),
            window_instant(&agent),
        );
        Landing::of(row, &[agent.as_str()])
    });
    land_many(&store, &custody, "custody binding").await;
    let windowed = par_map(half, |i| {
        let agent = agent_seed(i % n_agents);
        let steward = &stewards[(i % n_agents) % STEWARD_POOL];
        let row = sealed_at(
            &producers[i % STEWARD_POOL],
            &agent,
            &json!({
                "scope": ["act_on_behalf"],
                "deletion_window": "2099-01-01T00:00:00Z",
            }),
            window_instant(&agent),
        );
        Landing::of(row, &[steward.as_str()])
    });
    land_many(&store, &windowed, "windowed edge").await;
    FoldFixture {
        store,
        agents: (0..n_agents).map(|i| e2::kid(&agent_seed(i))).collect(),
    }
}

/// The deletion fold over every row, from a cold handle.
async fn deletion_fold(d: &SqliteBackend) -> u64 {
    let r = run_deletion_window_watch(d, chrono::Utc::now())
        .await
        .expect("deletion watch");
    r.rows_scanned as u64
}

/// The guardianship fold: every agent's steward set, from a cold handle.
async fn guardianship_fold(d: &SqliteBackend, agents: &[String]) -> usize {
    let mut bound = 0;
    for a in agents {
        bound += steward_bindings_of(d, a).await.expect("stewards").len();
    }
    bound
}

fn bench_fold_recompute(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("fold_recompute");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    group.warm_up_time(Duration::from_millis(1));
    for n in FOLD_SIZES {
        let cell: OnceCell<FoldFixture> = OnceCell::new();
        let fx = || cell.get_or_init(|| rt.block_on(fold_fixture(n)));
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(BenchmarkId::new("deletion_window", n), |b| {
            let f = fx();
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let cold = rt.block_on(f.store.reopen());
                    let t0 = Instant::now();
                    black_box(rt.block_on(deletion_fold(&cold)));
                    total += t0.elapsed();
                }
                total
            });
        });
        group.bench_function(BenchmarkId::new("guardianship", n), |b| {
            let f = fx();
            let sample = rt
                .block_on(steward_bindings_of(&f.store.backend, &f.agents[0]))
                .unwrap();
            assert_eq!(sample.len(), 1, "an agent has its one steward: {sample:?}");
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let cold = rt.block_on(f.store.reopen());
                    let t0 = Instant::now();
                    black_box(rt.block_on(guardianship_fold(&cold, &f.agents)));
                    total += t0.elapsed();
                }
                total
            });
        });
    }
    group.finish();
}

// ─── 8. peak memory mode ────────────────────────────────────────────────────

fn peak_rss(spec: &str) {
    let rt = runtime();
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.as_slice() {
        ["admission", order, rows] => {
            let order = Order::parse(order).expect("order: in_order|reversed|shuffled");
            let n: usize = rows.parse().expect("rows");
            let w = admission_workload(n);
            let seq = ordered(&w, order);
            let store = rt.block_on(admission_store(&w));
            let reset = reset_peak_rss();
            let before = status_kb("VmRSS:").unwrap_or(0);
            let elapsed = rt.block_on(admit_all(&store, &w, &seq));
            let hwm = status_kb("VmHWM:").unwrap_or(0);
            println!(
                "peak_rss admission(e2) order={} rows={n} elapsed_s={:.2} rows_per_s={:.0} \
                 rss_before_kb={before} vm_hwm_kb={hwm} hwm_reset={reset}",
                order.label(),
                elapsed.as_secs_f64(),
                n as f64 / elapsed.as_secs_f64(),
            );
        }
        ["folds", rows] => {
            let n: usize = rows.parse().expect("rows");
            let f = rt.block_on(fold_fixture(n));
            let reset = reset_peak_rss();
            let before = status_kb("VmRSS:").unwrap_or(0);
            let t0 = Instant::now();
            let cold = rt.block_on(f.store.reopen());
            let scanned = rt.block_on(deletion_fold(&cold));
            let t_del = t0.elapsed();
            let t1 = Instant::now();
            let bound = rt.block_on(guardianship_fold(&cold, &f.agents));
            let t_guard = t1.elapsed();
            let hwm = status_kb("VmHWM:").unwrap_or(0);
            println!(
                "peak_rss folds rows={n} deletion_scanned={scanned} deletion_s={:.2} \
                 guardianship_bound={bound} guardianship_s={:.2} rss_before_kb={before} \
                 vm_hwm_kb={hwm} hwm_reset={reset}",
                t_del.as_secs_f64(),
                t_guard.as_secs_f64(),
            );
        }
        _ => panic!("KERNEL_PATHS_PEAK_RSS: admission:<order>:<rows> | folds:<rows>"),
    }
}

criterion_group!(
    benches,
    bench_owner_of,
    bench_ab_switched,
    bench_trust_root,
    bench_delegation_walk,
    bench_held_head,
    bench_accord_recovery,
    bench_admission_door,
    bench_fold_recompute
);

/// One named fixture check of [`smoke`].
type SmokeCheck<'a> = (&'a str, Box<dyn Fn() + 'a>);

/// `KERNEL_PATHS_SMOKE=1`: build every fixture at its smallest size and ask
/// each path once, reporting every failure by name instead of stopping at
/// the first (a fixture check, not a measurement).
fn smoke() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let rt = runtime();
    let checks: Vec<SmokeCheck<'_>> = vec![
        (
            "owner_of",
            Box::new(|| {
                let f = rt.block_on(owner_fixture(64));
                for case in OWNER_CASES {
                    let (node, owned) = owner_probe(&f, case);
                    let got = rt
                        .block_on(owner_of(&f.store.backend, node))
                        .expect("owner_of");
                    assert_eq!(got.is_some(), owned, "{case}: {got:?}");
                }
            }),
        ),
        (
            "ab_switched/owner_of",
            Box::new(|| {
                let f = rt.block_on(owner_fixture(64));
                for case in OWNER_CASES {
                    let (node, _) = owner_probe(&f, case);
                    let new = rt.block_on(owner_of(&f.store.backend, node)).expect("new");
                    let old = rt
                        .block_on(owner_of_pre_kernel(&f.store.backend, node))
                        .expect("old");
                    assert_eq!(new, old, "{case}");
                }
            }),
        ),
        (
            "trust_root_valid",
            Box::new(|| {
                let f = rt.block_on(trust_fixture(2));
                let v = rt
                    .block_on(trust_root_valid(&f.store.backend, &f.user, &f.root))
                    .expect("walk");
                assert!(v.valid, "valid_root: {v:?}");
                let u = rt
                    .block_on(trust_root_valid(&f.store.backend, &f.user, &f.uncharted))
                    .expect("walk");
                assert!(!u.valid, "uncharted_root: {u:?}");
                for root in [f.root.as_str(), f.uncharted.as_str()] {
                    let a = rt
                        .block_on(trust_edge_leg_ab(&f.store.backend, &f.user, root, false))
                        .expect("pre");
                    let k = rt
                        .block_on(trust_edge_leg_ab(&f.store.backend, &f.user, root, true))
                        .expect("kernel");
                    assert_eq!(a, k, "ab_switched edge leg to {root}");
                }
            }),
        ),
        (
            "delegation_walk",
            Box::new(|| {
                let s = rt.block_on(walk_fixture());
                let hit = rt
                    .block_on(reachable_under_scope(
                        &s.backend,
                        &e2::kid(&walk_key(4, 0)),
                        &e2::kid(&walk_key(4, 4)),
                        DELEGATION_SCOPE_MODERATE,
                        64,
                    ))
                    .expect("walk");
                assert!(hit, "depth 4 reach");
            }),
        ),
        (
            "held_head",
            Box::new(|| {
                let f = rt.block_on(lineage_fixture(2));
                let d: &dyn FederationDirectory = &f.store.backend;
                let held = rt
                    .block_on(d.lookup_family(&e2::kid(BENCH_FAMILY)))
                    .expect("lookup")
                    .expect("the family is held");
                for (case, prior) in [
                    ("new_fork_from_root", (f.root, 1)),
                    ("new_fork_from_parent", f.parent),
                ] {
                    let fork = &sign_forks(&f, case, prior, 0, 1)[0];
                    let out = rt
                        .block_on(e2::put_voices(d, fork))
                        .unwrap_or_else(|e| panic!("{case}: the fork is held, not refused: {e}"));
                    println!("    {case}: {out:?}");
                }
                let after = rt
                    .block_on(d.lookup_family(&e2::kid(BENCH_FAMILY)))
                    .expect("lookup")
                    .expect("held");
                assert_eq!(
                    after.persist_row_hash, held.persist_row_hash,
                    "a fork never moves the head"
                );
            }),
        ),
        (
            "accord_recovery",
            Box::new(|| {
                let store = rt.block_on(Store::new());
                rt.block_on(fixture_genesis::install_v2(&store.backend))
                    .expect("the genesis is installed");
                let r = fixture_genesis::recover_v2(
                    fixture_genesis::bundle_v2(),
                    fixture_genesis::HOLDER_SEEDS[0],
                );
                rt.block_on(fixture_genesis::install_ceremony_v2(&store.backend, &r))
                    .expect("the recovery bundle is placed");
            }),
        ),
        (
            "admission_door",
            Box::new(|| {
                let w = admission_workload(64);
                for order in Order::ALL {
                    let store = rt.block_on(admission_store(&w));
                    let d: &dyn FederationDirectory = &store.backend;
                    for k in ordered(&w, order) {
                        let out = rt.block_on(land(d, &w.items[k]));
                        assert!(landed(&out), "{} edge {k}: {out:?}", order.label());
                    }
                }
            }),
        ),
        (
            "fold_recompute",
            Box::new(|| {
                let f = rt.block_on(fold_fixture(64));
                let cold = rt.block_on(f.store.reopen());
                let scanned = rt.block_on(deletion_fold(&cold));
                let bound = rt.block_on(guardianship_fold(&cold, &f.agents));
                assert!(scanned >= 64, "scanned {scanned}");
                assert_eq!(bound, f.agents.len(), "one steward per agent");
            }),
        ),
    ];
    let mut failed = 0;
    for (name, check) in &checks {
        match catch_unwind(AssertUnwindSafe(check)) {
            Ok(()) => println!("smoke {name}: ok"),
            Err(e) => {
                failed += 1;
                let why = e
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                    .unwrap_or_default();
                println!("smoke {name}: FAILED: {why}");
            }
        }
    }
    assert_eq!(failed, 0, "{failed} fixture check(s) failed");
}

fn main() {
    if std::env::var_os("KERNEL_PATHS_SMOKE").is_some() {
        smoke();
        return;
    }
    if let Ok(spec) = std::env::var("KERNEL_PATHS_PEAK_RSS") {
        peak_rss(&spec);
        return;
    }
    benches();
    Criterion::default().configure_from_args().final_summary();
}
