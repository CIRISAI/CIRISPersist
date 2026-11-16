//! Pre-kernel baseline (CIRISKernel PR #1, `crates/ciris-kernel/ADOPTING.md`):
//! the persist paths the kernel crate replaces, on the sqlite backend, with
//! SYNTHETIC keys and rows only (the `test-anchor` fixture surface:
//! deterministic test keypairs, never a production key or row).
//!
//! | group | persist path today | kernel replacement (ADOPTING.md) |
//! |---|---|---|
//! | `owner_of` | `admission::owner_of` | `seat::Seats::one("owner", key)` |
//! | `trust_root_valid` | `trust_root::trust_root_valid` | `trust::honours`, `trust::reaches` |
//! | `delegation_walk` | `admission::reachable_under_scope`, `check_delegation_cycle_admission` | `trust::reaches` (a cycle visited once), the seat walk's depth |
//! | `held_head` | `group_supersede_admit::held_head_verdict` (via the supersede door) | `seat::Seats::tips`, `line::settle` |
//! | `accord_recovery` | `accord_recovery::{recovery_commitment_in_force, verify_accord_recovery}` | `seat::seat_rule` over the lineage |
//! | `admission_door` | `put_attestation_authored` (the `put_attestation` gauntlet, no AV-76 quota) | `layers::kept`, `layers::conclude` |
//! | `fold_recompute` | `deletion_window::run_deletion_window_watch`, `admission::steward_bindings_of` | the folds read from the held set |
//!
//! Every store is a file-backed sqlite database in a temp directory, built
//! through the public door (`put_attestation`, `supersede_family_with_quorum`)
//! so every row is one the gates admitted; signing is done up front, outside
//! the timed region. Fixtures are built lazily, the first time a benchmark
//! that needs them runs, so a criterion filter builds only what it selects.
//!
//! ## Peak memory mode (criterion does not measure memory)
//!
//! `KERNEL_PATHS_PEAK_RSS=<spec>` runs ONE pass instead of criterion and
//! prints `VmHWM` from `/proc/self/status`. The fixture (signed rows) is built
//! first; the high-water mark is then reset (`echo 5 > /proc/self/clear_refs`)
//! so the figure is the pass's own peak, with the pre-pass RSS printed beside
//! it. Specs:
//!
//! - `admission:<in_order|reversed|shuffled>:<rows>` — one admission pass;
//!   also prints rows/s;
//! - `folds:<rows>` — reopen the store cold and run every fold once.
//!
//! Re-run against the baseline:
//! `cargo bench --bench kernel_paths --features sqlite,test-anchor -- --baseline pre-kernel`.
//!
//! v62.0.0 (slice C) — ported from `bench-pre-kernel` (`ba4af20e`) unchanged
//! but for the cycle gate's expectation: the closing edge is admitted at
//! every depth. Fixture owner bindings are co-scrubbed by their node
//! (`ts::seal_row_in_place`, CC 3.2's first binding), so `one_owner` still
//! names its owner.

use std::cell::OnceCell;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ciris_persist::federation::accord_recovery::{
    draft_accord_recovery, recovery_commitment_in_force, recovery_version, verify_accord_recovery,
    AccordRecoveryRequest,
};
use ciris_persist::federation::accord_test_support as ops;
use ciris_persist::federation::admission::{
    check_delegation_cycle_admission, owner_of, reachable_under_scope, steward_bindings_of,
    truncate_to_substrate_resolution, DelegationTermBounds, DELEGATION_SCOPE_MODERATE,
};
use ciris_persist::federation::canonical_community::{accord_family_key_id, NEXT_PERSIST_ROW_HASH};
use ciris_persist::federation::cohort::Cohort;
use ciris_persist::federation::deletion_window::run_deletion_window_watch;
use ciris_persist::federation::tier_ingest::test_support as ts;
use ciris_persist::federation::trust_root::{
    recovery_commitment, test_accord_recovery_commitments, test_committed_key,
    test_pre_rotation_commitment, trust_root_valid, INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE,
    TRUST_CHARTER_DIMENSION,
};
use ciris_persist::federation::types::{
    attestation_type, compute_persist_row_hash, delegation_scope as ds, identity_type,
    owner_binding, Family,
};
use ciris_persist::federation::{
    Attestation, Error, FederationDirectory, SignedAttestation, TierPromotionCustody,
};
use ciris_persist::store::{Backend as _, SqliteBackend};
use criterion::{black_box, criterion_group, BenchmarkId, Criterion, SamplingMode, Throughput};
use serde_json::json;

/// Row counts for the store-size sweeps.
const ROW_SIZES: [usize; 3] = [1_000, 16_000, 64_000];
/// Row counts for the admission-door sweep under criterion. 16k and 64k run
/// as ONE pass each, in the peak-RSS mode: criterion's floor of ten samples
/// is eleven passes, and on the shared host one pass was 20-35 s at 16k and
/// up to 36 s at 4k (reversed, under load), so a criterion run of one order
/// above 1k did not fit a ten-minute command.
const ADMISSION_SIZES: [usize; 1] = [1_000];
/// Row counts for the fold sweep under criterion. 64k runs as ONE pass in
/// the peak-RSS mode (`folds:64000`): its fixture alone is 64k admissions,
/// and the guardianship fold at 64k is ~15-20 s per pass on the shared host.
const FOLD_SIZES: [usize; 2] = [1_000, 16_000];
/// Edges per delegation chain in the admission workload.
const CHAIN_LEN: usize = 8;
/// Fixed seed for the shuffled arrival order.
const SHUFFLE_SEED: u64 = 0x5EED_CAFE_F00D_0001;
/// Threads used to SIGN fixtures (never in a timed region).
const SIGN_THREADS: usize = 8;

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

/// A sealed federation-tier `delegates_to(granter → grantee)` carrying
/// `envelope`, hybrid-signed by `granter`'s deterministic test keys.
fn sealed(
    id: &str,
    granter: &str,
    grantee: &str,
    kind: &str,
    envelope: serde_json::Value,
) -> Attestation {
    let mut row = ts::bare_attestation(id, granter, grantee, &envelope);
    row.attestation_type = kind.to_owned();
    ts::seal_row_in_place(granter, &mut row);
    row
}

/// A plain capability edge, the `put_delegates_to` fixture shape.
fn capability_edge(id: &str, granter: &str, grantee: &str) -> Attestation {
    sealed(
        id,
        granter,
        grantee,
        attestation_type::DELEGATES_TO,
        json!({ "references_attestation_id": id, "scope": ["act_on_behalf"] }),
    )
}

/// The CC 1.13.3.3 owner binding `delegates_to(owner → node)`.
fn owner_binding_row(id: &str, owner: &str, node: &str) -> Attestation {
    sealed(
        id,
        owner,
        node,
        attestation_type::DELEGATES_TO,
        json!({
            "id": id,
            "kind": "delegates_to",
            "dimension": owner_binding::DIMENSION,
            "delegation_purpose": owner_binding::PURPOSE,
            "scope": [ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
        }),
    )
}

/// A `moderate`-scoped appointment with `sub_delegation`, so a walk may pass
/// it beyond the first hop.
fn moderate_edge(id: &str, granter: &str, grantee: &str) -> Attestation {
    let now = truncate_to_substrate_resolution(chrono::Utc::now());
    let mut envelope = json!({
        "id": id,
        "kind": "delegates_to",
        "scope": [DELEGATION_SCOPE_MODERATE],
        "sub_delegation": true,
    });
    DelegationTermBounds::until(now + chrono::Duration::days(180)).stamp(&mut envelope);
    let mut row = sealed(
        id,
        granter,
        grantee,
        attestation_type::DELEGATES_TO,
        envelope,
    );
    row.asserted_at = now;
    row.scrub_timestamp = now;
    ts::seal_row_in_place(granter, &mut row);
    row
}

/// Fixture rows enter through the AUTHORED door: the same admission gauntlet
/// as `put_attestation`, charged to the node's own ceiling only. The wire
/// door meters every attester at 600 rows/min (and every never-seen attester
/// together at the same), which a synthetic store of thousands of rows
/// exceeds by design (AV-76, `PeerQuotaRefusal::UntrackedTailBurst`).
async fn put(d: &dyn FederationDirectory, row: Attestation, what: &str) {
    d.put_attestation_authored(SignedAttestation { attestation: row })
        .await
        .unwrap_or_else(|e| panic!("fixture row refused ({what}): {e}"));
}

/// Rows per backend handle before a fixture or the admission loop moves to a
/// fresh handle: under the node ingest ceiling's 6 000-row burst
/// (`NODE_INGEST_BUDGET_MULTIPLE` × `PER_PEER_ATTESTATION_WRITES_PER_WINDOW`),
/// which is per backend instance.
const QUOTA_ROTATE: usize = 5_000;

/// [`put`] every row, rotating to a fresh handle on the same file every
/// [`QUOTA_ROTATE`] rows (see [`QUOTA_ROTATE`]).
async fn put_many(store: &Store, rows: Vec<Attestation>, what: &str) {
    let mut handle: Option<SqliteBackend> = None;
    for (i, row) in rows.into_iter().enumerate() {
        if i > 0 && i % QUOTA_ROTATE == 0 {
            handle = Some(store.reopen().await);
        }
        let d: &dyn FederationDirectory = handle.as_ref().unwrap_or(&store.backend);
        put(d, row, &format!("{what} {i}")).await;
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
    bound_node: String,
}

/// `n` owner bindings: owner `i % 64` → node `i`, plus three probes:
/// `own-cosigned` (the binding also carries the node's own co-scrub, the
/// two-consent seat the kernel reads), `own-withdrawn` (bound, then the
/// owner's `withdraws`), and `own-unbound` (no binding).
async fn owner_fixture(n: usize) -> OwnerFixture {
    let store = Store::new().await;
    let d: &dyn FederationDirectory = &store.backend;
    let owners: Vec<String> = (0..OWNER_POOL)
        .map(|i| format!("own-user-{i:03}"))
        .collect();
    for o in &owners {
        ts::register_identity_key(d, o, identity_type::USER).await;
    }
    // The door resolves every attested key: each node is registered.
    for i in 0..n {
        ts::register_identity_key(d, &format!("own-node-{i:06}"), identity_type::NODE).await;
    }
    for probe in ["own-withdrawn", "own-unbound"] {
        ts::register_identity_key(d, probe, identity_type::NODE).await;
    }
    let rows = par_map(n, |i| {
        owner_binding_row(
            &format!("own-binding-{i:06}"),
            &owners[i % OWNER_POOL],
            &format!("own-node-{i:06}"),
        )
    });
    put_many(&store, rows, "owner binding").await;

    // The cosigned binding: the owner's seal plus the node's co-scrub.
    let node = "own-cosigned";
    ts::register_identity_key(d, node, identity_type::NODE).await;
    let mut row = owner_binding_row("own-binding-cosigned", &owners[0], node);
    if let TierPromotionCustody::NodeCoScrub(sig) = ts::node_coscrub(node, &row) {
        row.additional_scrubs.push(sig);
    }
    put(d, row, "cosigned owner binding").await;

    // Bound then withdrawn by the owner.
    let wnode = "own-withdrawn";
    put(
        d,
        owner_binding_row("own-binding-withdrawn", &owners[1], wnode),
        "owner binding to withdraw",
    )
    .await;
    put(
        d,
        sealed(
            "own-withdraws-1",
            &owners[1],
            wnode,
            attestation_type::WITHDRAWS,
            json!({ "id": "own-withdraws-1", "references_attestation_id": "own-binding-withdrawn" }),
        ),
        "withdraws of the owner binding",
    )
    .await;

    OwnerFixture {
        store,
        bound_node: format!("own-node-{:06}", n / 2),
    }
}

fn bench_owner_of(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("owner_of");
    group.sample_size(50);
    for n in ROW_SIZES {
        let cell: OnceCell<OwnerFixture> = OnceCell::new();
        let fx = || cell.get_or_init(|| rt.block_on(owner_fixture(n)));
        for (case, expect_owner) in [
            ("one_owner", true),
            ("cosigned", true),
            ("withdrawn", false),
            ("no_owner", false),
        ] {
            group.bench_function(BenchmarkId::new(case, n), |b| {
                let f = fx();
                let node = match case {
                    "one_owner" => f.bound_node.as_str(),
                    "cosigned" => "own-cosigned",
                    "withdrawn" => "own-withdrawn",
                    _ => "own-unbound",
                };
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

// ─── 3. trust root and the edge walk ────────────────────────────────────────

struct TrustFixture {
    store: Store,
}

/// A valid key-arm root for `tr-user` (`establish_trust_root`: the root's
/// charter, its heartbeat, the user's trust edge, the scope edge), plus
/// `extra` further trust edges from the user to roots with no charter.
async fn trust_fixture(extra: usize) -> TrustFixture {
    let store = Store::new().await;
    let d: &dyn FederationDirectory = &store.backend;
    for k in ["tr-user", "tr-subject"] {
        ops::register_typed_key(d, k, identity_type::NODE)
            .await
            .expect("register");
    }
    ops::establish_trust_root(d, "tr-user", "tr-root", "tr-subject", INFRA_SERVE_SCOPE)
        .await
        .expect("establish_trust_root");
    for k in 0..extra {
        ops::register_typed_key(d, &format!("tr-other-root-{k:04}"), identity_type::NODE)
            .await
            .expect("register other root");
        ops::emit_trust_edge(d, "tr-user", &format!("tr-other-root-{k:04}"), None)
            .await
            .expect("extra trust edge");
    }
    TrustFixture { store }
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
                .block_on(trust_root_valid(&f.store.backend, "tr-user", "tr-root"))
                .expect("walk");
            assert!(v.valid, "the established root is valid: {v:?}");
            b.iter(|| {
                black_box(
                    rt.block_on(trust_root_valid(&f.store.backend, "tr-user", "tr-root"))
                        .unwrap(),
                )
            });
        });
        if extra > 0 {
            group.bench_function(BenchmarkId::new("uncharted_root", extra), |b| {
                let f = fx();
                let v = rt
                    .block_on(trust_root_valid(
                        &f.store.backend,
                        "tr-user",
                        "tr-other-root-0000",
                    ))
                    .expect("walk");
                assert!(!v.valid, "a root with no charter is not valid: {v:?}");
                b.iter(|| {
                    black_box(
                        rt.block_on(trust_root_valid(
                            &f.store.backend,
                            "tr-user",
                            "tr-other-root-0000",
                        ))
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

/// One `moderate` chain `k0 → k1 → … → k_depth` per depth, in one store.
async fn walk_fixture() -> Store {
    let store = Store::new().await;
    let d: &dyn FederationDirectory = &store.backend;
    for depth in CHAIN_DEPTHS {
        for i in 0..=depth {
            ts::register_hybrid_key(d, &walk_key(depth, i)).await;
        }
        let rows = par_map(depth, |i| {
            moderate_edge(
                &format!("walk-d{depth:02}-e{i:02}"),
                &walk_key(depth, i),
                &walk_key(depth, i + 1),
            )
        });
        for row in rows {
            put(d, row, "moderate chain edge").await;
        }
    }
    ts::register_hybrid_key(d, "walk-outsider").await;
    store
}

fn bench_delegation_walk(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("delegation_walk");
    group.sample_size(50);
    let cell: OnceCell<Store> = OnceCell::new();
    let fx = || cell.get_or_init(|| rt.block_on(walk_fixture()));
    for depth in CHAIN_DEPTHS {
        let root = walk_key(depth, 0);
        let tip = walk_key(depth, depth);
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
            // Within the ceiling the tip is reached; past it, not.
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
                        "walk-outsider",
                        DELEGATION_SCOPE_MODERATE,
                        64,
                    ))
                    .unwrap(),
                )
            });
        });
        // The cycle gate on a candidate edge tip → root: it closes a cycle
        // of `depth + 1` hops. Pre-kernel it was refused while the chain was
        // within the ceiling; v62.0.0 (slice C) refuses no edge for closing
        // a cycle (the kernel's walk visits it once), so every depth admits.
        // Not written: the gate is asked, the row is not stored.
        let closing = moderate_edge(&format!("walk-close-{depth}"), &tip, &root);
        group.bench_function(BenchmarkId::new("cycle_gate_closing", depth), |b| {
            let s = fx();
            let now = chrono::Utc::now();
            let r = rt.block_on(check_delegation_cycle_admission(&s.backend, &closing, now));
            assert!(
                r.is_ok(),
                "depth {depth}: v62 refuses no cycle-closing edge"
            );
            b.iter(|| {
                black_box(
                    rt.block_on(check_delegation_cycle_admission(&s.backend, &closing, now))
                        .is_err(),
                )
            });
        });
        // The cycle gate on an edge outsider → root: no cycle, the search
        // walks the whole chain from the root.
        let open = moderate_edge(&format!("walk-open-{depth}"), "walk-outsider", &root);
        group.bench_function(BenchmarkId::new("cycle_gate_open", depth), |b| {
            let s = fx();
            let now = chrono::Utc::now();
            rt.block_on(check_delegation_cycle_admission(&s.backend, &open, now))
                .expect("no cycle");
            b.iter(|| {
                black_box(
                    rt.block_on(check_delegation_cycle_admission(&s.backend, &open, now))
                        .is_ok(),
                )
            });
        });
    }
    group.finish();
}

// ─── 4. heads and forks ─────────────────────────────────────────────────────

/// Append a version of `family_key_id` whose `prev_head_digest` is `prev`
/// (the held head when `None`), authorized by every signer's threshold
/// signature over the change envelope (`version_family_naming_charter`'s
/// shape, with the family name changed instead of the charter).
async fn version_family(
    d: &dyn FederationDirectory,
    family_key_id: &str,
    signers: &[String],
    prev: Option<&str>,
    name: &str,
) -> Result<u32, Error> {
    let v = prepare_version(d, family_key_id, signers, prev, name).await?;
    submit_version(d, &v).await
}

/// A signed, quorum-authorized family version, ready to submit (signing is
/// done here, outside any timed region).
#[derive(Clone)]
struct PreparedVersion {
    signed: ciris_persist::federation::SignedFamily,
    env: serde_json::Value,
    sigs: Vec<ciris_verify_core::threshold::ThresholdSignature>,
}

async fn submit_version(d: &dyn FederationDirectory, v: &PreparedVersion) -> Result<u32, Error> {
    let v = v.clone();
    d.supersede_family_with_quorum(v.signed, v.env, v.sigs)
        .await
}

async fn prepare_version(
    d: &dyn FederationDirectory,
    family_key_id: &str,
    signers: &[String],
    prev: Option<&str>,
    name: &str,
) -> Result<PreparedVersion, Error> {
    let held = d
        .lookup_family(family_key_id)
        .await?
        .expect("the family is held");
    let mut next: Family = held.clone();
    next.prev_head_digest = prev.map_or_else(|| held.persist_row_hash.clone(), str::to_owned);
    next.family_name = name.to_owned();
    next.persist_row_hash = String::new();
    let ids: Vec<String> = held.members.iter().map(|m| m.key_id.clone()).collect();
    let mut env = d
        .build_membership_change_envelope(
            Cohort::Family,
            family_key_id,
            &ids,
            held.consensus_protocol_entrenched,
            Some(&held.consensus_protocol),
        )
        .await?;
    env[NEXT_PERSIST_ROW_HASH] = serde_json::Value::String(compute_persist_row_hash(&next)?);
    let bytes = ciris_verify_core::jcs::canonicalize(&env).expect("jcs");
    let sigs = signers
        .iter()
        .map(|k| ts::threshold_sign(k, &bytes))
        .collect();
    Ok(PreparedVersion {
        signed: ts::sign_family(&signers[0], next),
        env,
        sigs,
    })
}

const LINEAGE_LENGTHS: [usize; 3] = [1, 16, 128];

struct LineageFixture {
    store: Store,
    holders: Vec<String>,
    /// The founding version's row hash (a fork names it as its prior).
    root_hash: String,
    /// The held head's parent's row hash.
    parent_hash: String,
}

const BENCH_FAMILY: &str = "bench-lineage-family";

async fn lineage_fixture(len: usize) -> LineageFixture {
    let store = Store::new().await;
    let d: &dyn FederationDirectory = &store.backend;
    let holders: Vec<String> = (0..3).map(|i| format!("lin-holder-{i}")).collect();
    for h in &holders {
        ops::register_typed_key(d, h, identity_type::NODE)
            .await
            .expect("register holder");
    }
    ops::seed_test_family(d, BENCH_FAMILY, &holders, "quorum:2/3")
        .await
        .expect("seed family");
    let root_hash = d
        .lookup_family(BENCH_FAMILY)
        .await
        .unwrap()
        .unwrap()
        .persist_row_hash;
    let mut parent_hash = root_hash.clone();
    for v in 0..len {
        parent_hash = d
            .lookup_family(BENCH_FAMILY)
            .await
            .unwrap()
            .unwrap()
            .persist_row_hash;
        version_family(d, BENCH_FAMILY, &holders, None, &format!("lineage v{v}"))
            .await
            .unwrap_or_else(|e| panic!("lineage version {v}: {e}"));
    }
    LineageFixture {
        store,
        holders,
        root_hash,
        parent_hash,
    }
}

fn bench_held_head(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("held_head");
    group.sample_size(30);
    for len in LINEAGE_LENGTHS {
        let cell: OnceCell<LineageFixture> = OnceCell::new();
        let fx = || cell.get_or_init(|| rt.block_on(lineage_fixture(len)));
        // A forked version: a valid, quorum-signed version whose prior is the
        // founding version, not the held head. The door refuses it (persist's
        // `held_head_verdict`; the kernel holds it as a second tip).
        // Two forks, each signed up front: off the founding version, and off
        // the held head's parent (a stale prior one version back).
        for (case, prior) in [("fork_from_root", 0usize), ("fork_from_parent", 1)] {
            group.bench_function(BenchmarkId::new(case, len), |b| {
                let f = fx();
                let d: &dyn FederationDirectory = &f.store.backend;
                let prev = if prior == 0 {
                    f.root_hash.clone()
                } else {
                    f.parent_hash.clone()
                };
                let v = rt
                    .block_on(prepare_version(
                        d,
                        BENCH_FAMILY,
                        &f.holders,
                        Some(&prev),
                        case,
                    ))
                    .expect("prepare fork");
                let r = rt.block_on(submit_version(d, &v));
                assert!(r.is_err(), "{case}: the fork is refused: {r:?}");
                b.iter(|| black_box(rt.block_on(submit_version(d, &v)).is_err()));
            });
        }
    }
    group.finish();
}

// ─── 5. accord recovery ─────────────────────────────────────────────────────

struct AccordFixture {
    store: Store,
    holder: String,
    signed: ciris_persist::federation::SignedFamily,
    new_holder: String,
}

/// Admit an accord charter committing `roster`'s test recovery keys,
/// scrubbed by every held holder, and a version naming it.
async fn accord_charter_version(d: &dyn FederationDirectory, holders: &[String], tag: &str) {
    let accord = accord_family_key_id();
    let id = format!("bench-accord-charter-{tag}");
    let env = json!({
        "references_attestation_id": id,
        "dimension": TRUST_CHARTER_DIMENSION,
        "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
        "pre_rotation_commitment": test_pre_rotation_commitment(&[
            "accord-succ-a".to_owned(),
            "accord-succ-b".to_owned(),
        ])
        .unwrap(),
        "recovery_commitments": test_accord_recovery_commitments(holders),
    });
    let mut row = sealed(
        &id,
        &holders[0],
        accord,
        attestation_type::DELEGATES_TO,
        env,
    );
    let sealed_env = row.attestation_envelope.clone();
    row.additional_scrubs = holders[1..]
        .iter()
        .map(|k| {
            let (_h, classical, pqc) = ts::sign_envelope(k, &sealed_env);
            ciris_persist::federation::types::ScrubSig {
                scrub_key_id: k.clone(),
                scrub_signature_classical: classical,
                scrub_signature_pqc: pqc,
                cosigned_at: None,
            }
        })
        .collect();
    let digest = ops::charter_digest_of(&row);
    put(d, row, "accord charter").await;
    ops::version_family_naming_charter(d, accord, &digest, holders)
        .await
        .unwrap_or_else(|e| panic!("accord version naming charter {tag}: {e}"));
}

async fn accord_fixture(len: usize) -> AccordFixture {
    let store = Store::new().await;
    let d: &dyn FederationDirectory = &store.backend;
    ops::register_genesis_accord_roster(d)
        .await
        .expect("genesis accord roster");
    ciris_persist::federation::genesis::seed_accord_family(d)
        .await
        .expect("accord family");
    let accord = accord_family_key_id();
    let holders: Vec<String> = d
        .lookup_family(accord)
        .await
        .unwrap()
        .expect("accord held")
        .members
        .iter()
        .map(|m| m.key_id.clone())
        .collect();
    for v in 0..len {
        accord_charter_version(d, &holders, &format!("v{v}")).await;
    }
    // A recovery of holders[0] to a fresh key under its committed recovery
    // key: drafted and signed, judged (not submitted) by the bench.
    let new_holder = "bench-accord-new".to_owned();
    ops::register_accord_holder_as(
        d,
        &ops::Identity::new(&new_holder),
        identity_type::ACCORD_HOLDER,
    )
    .await
    .expect("newcomer");
    let rk = format!("{}-recovery", holders[0]);
    ts::register_hybrid_key_as(d, &rk, &rk, identity_type::NODE).await;
    let draft = draft_accord_recovery(
        d,
        &AccordRecoveryRequest {
            family_key_id: accord.to_owned(),
            old_holder_key_id: holders[0].clone(),
            new_holder_key_id: new_holder.clone(),
            recovery_key_id: rk.clone(),
            next_recovery_commitment: recovery_commitment(&test_committed_key(&format!(
                "{new_holder}-recovery"
            )))
            .unwrap(),
            joined_at: chrono::Utc::now(),
        },
    )
    .await
    .expect("draft recovery");
    let r = ts::threshold_sign(&rk, &draft.statement_bytes);
    let r = (
        r.ed25519_signature_base64,
        r.mldsa65_signature_base64.unwrap(),
    );
    let n = ops::Identity::new(&new_holder).sign_bytes(&draft.record_bytes);
    let held = d.lookup_family(accord).await.unwrap().unwrap();
    let signed = recovery_version(&held.persist_row_hash, &draft, r, n);
    AccordFixture {
        store,
        holder: holders[0].clone(),
        signed,
        new_holder,
    }
}

fn bench_accord_recovery(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("accord_recovery");
    group.sample_size(30);
    for len in LINEAGE_LENGTHS {
        let cell: OnceCell<AccordFixture> = OnceCell::new();
        let fx = || cell.get_or_init(|| rt.block_on(accord_fixture(len)));
        group.bench_function(BenchmarkId::new("commitment_in_force", len), |b| {
            let f = fx();
            let got = rt
                .block_on(recovery_commitment_in_force(
                    &f.store.backend,
                    accord_family_key_id(),
                    &f.holder,
                ))
                .expect("read");
            assert!(got.is_some(), "the holder's commitment is in force");
            b.iter(|| {
                black_box(
                    rt.block_on(recovery_commitment_in_force(
                        &f.store.backend,
                        accord_family_key_id(),
                        &f.holder,
                    ))
                    .unwrap(),
                )
            });
        });
        group.bench_function(BenchmarkId::new("verify_recovery", len), |b| {
            let f = fx();
            let got = rt
                .block_on(verify_accord_recovery(&f.store.backend, &f.signed))
                .expect("a valid recovery");
            assert_eq!(got.as_deref(), Some(f.new_holder.as_str()));
            b.iter(|| {
                black_box(
                    rt.block_on(verify_accord_recovery(&f.store.backend, &f.signed))
                        .unwrap(),
                )
            });
        });
    }
    group.finish();
}

// ─── 6. the admission door ──────────────────────────────────────────────────

/// The arrival order. `InOrder` names the order, so the variant keeps the
/// enum's name (the bench ids read `in_order`).
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
    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|o| o.label() == s)
    }
}

fn chain_key(chain: usize, j: usize) -> String {
    format!("adm-c{chain:05}-k{j}")
}

/// `n` capability edges in chains of [`CHAIN_LEN`]: chain `c` is
/// `k0 → k1 → … → k8`. In order, each edge's grantee has no outgoing edge
/// yet, so the cycle gate's walk is one read; reversed, the walk from the
/// grantee follows the rest of the chain; shuffled is between.
struct AdmissionWorkload {
    keys: Vec<String>,
    rows: Vec<Attestation>,
}

fn admission_workload(n: usize) -> AdmissionWorkload {
    let chains = n.div_ceil(CHAIN_LEN);
    let keys = (0..chains)
        .flat_map(|c| (0..=CHAIN_LEN).map(move |j| chain_key(c, j)))
        .collect();
    let rows = par_map(n, |i| {
        let (c, j) = (i / CHAIN_LEN, i % CHAIN_LEN);
        capability_edge(
            &format!("adm-c{c:05}-e{j}"),
            &chain_key(c, j),
            &chain_key(c, j + 1),
        )
    });
    AdmissionWorkload { keys, rows }
}

fn ordered(rows: &[Attestation], order: Order) -> Vec<Attestation> {
    let mut v = rows.to_vec();
    match order {
        Order::InOrder => {}
        Order::Reversed => v.reverse(),
        Order::Shuffled => shuffle(&mut v, SHUFFLE_SEED),
    }
    v
}

/// A fresh store with every workload key registered (untimed).
async fn admission_store(w: &AdmissionWorkload) -> Store {
    let store = Store::new().await;
    for k in &w.keys {
        ts::register_hybrid_key(&store.backend, k).await;
    }
    store
}

/// Put every row through the door; the elapsed time of the puts only.
///
/// The authored door (`put_attestation_authored`): every gate and the hybrid
/// verify of `put_attestation`, without the AV-76 per-peer quota, which caps
/// the wire door at 600 rows/min per attester and 6 000 rows/min per node
/// and would make the figure the quota's, not the door's.
///
/// Even the authored door spends the NODE ingest ceiling (6 000 rows, then
/// 100 rows/s). The ceiling lives in the backend instance, so every
/// [`QUOTA_ROTATE`] rows the loop moves to a fresh handle on the same file;
/// the opens are not timed. The figure is the gauntlet's cost, not the
/// ceiling's.
async fn admit_all(store: &Store, rows: Vec<Attestation>) -> Duration {
    let mut total = Duration::ZERO;
    let mut handle: Option<SqliteBackend> = None;
    let mut rows = rows.into_iter();
    for i in 0.. {
        let chunk: Vec<Attestation> = rows.by_ref().take(QUOTA_ROTATE).collect();
        if chunk.is_empty() {
            break;
        }
        if i > 0 {
            handle = Some(store.reopen().await);
        }
        let d: &dyn FederationDirectory = handle.as_ref().unwrap_or(&store.backend);
        let t0 = Instant::now();
        for row in chunk {
            d.put_attestation_authored(SignedAttestation { attestation: row })
                .await
                .expect("admitted");
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
            group.bench_function(BenchmarkId::new(order.label(), n), |b| {
                let w = fx();
                let rows = ordered(&w.rows, order);
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let store = rt.block_on(admission_store(w));
                        total += rt.block_on(admit_all(&store, rows.clone()));
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

/// `n` rows: half capability edges carrying a future `deletion_window` (the
/// deletion fold classifies each), half custody bindings
/// `delegates_to(steward → agent)` with the ownership marker (the
/// guardianship fold, `steward_bindings_of`, reads each agent's).
struct FoldFixture {
    store: Store,
    agents: Vec<String>,
}

async fn fold_fixture(n: usize) -> FoldFixture {
    let store = Store::new().await;
    let d: &dyn FederationDirectory = &store.backend;
    let stewards: Vec<String> = (0..STEWARD_POOL)
        .map(|i| format!("fold-steward-{i:03}"))
        .collect();
    for s in &stewards {
        ts::register_identity_key(d, s, identity_type::USER).await;
    }
    let half = n / 2;
    let producers: Vec<String> = (0..STEWARD_POOL)
        .map(|i| format!("fold-producer-{i:03}"))
        .collect();
    for p in &producers {
        ts::register_hybrid_key(d, p).await;
    }
    let agents: Vec<String> = (0..n - half)
        .map(|i| format!("fold-agent-{i:06}"))
        .collect();
    for a in &agents {
        ts::register_hybrid_key(d, a).await;
    }
    let rows = par_map(n, |i| {
        if i < half {
            let id = format!("fold-windowed-{i:06}");
            sealed(
                &id,
                &producers[i % STEWARD_POOL],
                &agents[i % agents.len()],
                attestation_type::DELEGATES_TO,
                json!({
                    "references_attestation_id": id,
                    "scope": ["act_on_behalf"],
                    "deletion_window": "2099-01-01T00:00:00Z",
                }),
            )
        } else {
            let k = i - half;
            let id = format!("fold-custody-{k:06}");
            sealed(
                &id,
                &stewards[k % STEWARD_POOL],
                &agents[k],
                attestation_type::DELEGATES_TO,
                json!({
                    "id": id,
                    "kind": "delegates_to",
                    "dimension": owner_binding::DIMENSION,
                    "delegation_purpose": owner_binding::PURPOSE,
                    "scope": [ds::AGENCY_ACT_ON_BEHALF],
                }),
            )
        }
    });
    put_many(&store, rows, "fold row").await;
    FoldFixture { store, agents }
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
            let rows = ordered(&w.rows, order);
            let store = rt.block_on(admission_store(&w));
            let reset = reset_peak_rss();
            let before = status_kb("VmRSS:").unwrap_or(0);
            let elapsed = rt.block_on(admit_all(&store, rows));
            let hwm = status_kb("VmHWM:").unwrap_or(0);
            println!(
                "peak_rss admission order={} rows={n} elapsed_s={:.2} rows_per_s={:.0} \
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
    bench_trust_root,
    bench_delegation_walk,
    bench_held_head,
    bench_accord_recovery,
    bench_admission_door,
    bench_fold_recompute
);

/// `KERNEL_PATHS_SMOKE=1`: build every fixture at its smallest size and
/// ask each path once, reporting every failure instead of stopping at the
/// first (a fixture check, not a measurement).
/// One named fixture check of [`smoke`].
type SmokeCheck<'a> = (&'a str, Box<dyn Fn() + 'a>);

fn smoke() {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    let rt = runtime();
    let checks: Vec<SmokeCheck<'_>> = vec![
        (
            "owner_of",
            Box::new(|| {
                let f = rt.block_on(owner_fixture(64));
                for (node, owned) in [
                    (f.bound_node.as_str(), true),
                    ("own-cosigned", true),
                    ("own-withdrawn", false),
                    ("own-unbound", false),
                ] {
                    let got = rt
                        .block_on(owner_of(&f.store.backend, node))
                        .expect("owner_of");
                    assert_eq!(got.is_some(), owned, "{node}: {got:?}");
                }
            }),
        ),
        (
            "trust_root_valid",
            Box::new(|| {
                let f = rt.block_on(trust_fixture(2));
                let v = rt
                    .block_on(trust_root_valid(&f.store.backend, "tr-user", "tr-root"))
                    .expect("walk");
                assert!(v.valid, "{v:?}");
            }),
        ),
        (
            "delegation_walk",
            Box::new(|| {
                let s = rt.block_on(walk_fixture());
                let hit = rt
                    .block_on(reachable_under_scope(
                        &s.backend,
                        &walk_key(4, 0),
                        &walk_key(4, 4),
                        DELEGATION_SCOPE_MODERATE,
                        64,
                    ))
                    .expect("walk");
                assert!(hit, "depth 4 reach");
                let closing = moderate_edge("smoke-close", &walk_key(4, 4), &walk_key(4, 0));
                let r = rt.block_on(check_delegation_cycle_admission(
                    &s.backend,
                    &closing,
                    chrono::Utc::now(),
                ));
                assert!(r.is_err(), "cycle refused: {r:?}");
            }),
        ),
        (
            "held_head",
            Box::new(|| {
                let f = rt.block_on(lineage_fixture(2));
                let r = rt.block_on(version_family(
                    &f.store.backend,
                    BENCH_FAMILY,
                    &f.holders,
                    Some(&f.root_hash),
                    "fork",
                ));
                assert!(r.is_err(), "fork refused: {r:?}");
                println!("    fork refusal: {}", r.unwrap_err());
            }),
        ),
        (
            "accord_recovery",
            Box::new(|| {
                let f = rt.block_on(accord_fixture(2));
                let c = rt
                    .block_on(recovery_commitment_in_force(
                        &f.store.backend,
                        accord_family_key_id(),
                        &f.holder,
                    ))
                    .expect("read");
                assert!(c.is_some(), "commitment in force");
                let v = rt
                    .block_on(verify_accord_recovery(&f.store.backend, &f.signed))
                    .expect("verify");
                assert_eq!(v.as_deref(), Some(f.new_holder.as_str()));
            }),
        ),
        (
            "admission_door",
            Box::new(|| {
                let w = admission_workload(64);
                for order in Order::ALL {
                    let store = rt.block_on(admission_store(&w));
                    rt.block_on(admit_all(&store, ordered(&w.rows, order)));
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
            Err(_) => {
                failed += 1;
                println!("smoke {name}: FAILED");
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
