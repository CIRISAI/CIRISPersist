# Pre-kernel benchmark baseline

Before-numbers for the persist paths that the kernel crate replaces (CIRISKernel PR #1,
`crates/ciris-kernel/ADOPTING.md` on branch `kernel-crate`). The same benches re-run after
the move with `--baseline pre-kernel` to compare.

**The host is shared, so these numbers are indicative only.** The runs shared the machine with
other agents' builds. An unrelated process held about 30 of the 32 hardware threads for a stretch
(load average up to 35), and the first runs of the database benches were made then. Every
figure below comes from a re-run at load average 1–3 (the one 64k fold pass ran at 3–9), and the
saved `pre-kernel` baseline holds those re-runs. Under load, the same benches ran 1.5–2.5× slower. Before comparing, check
`uptime` on the comparison run.

## What was measured, and against what

| | |
|---|---|
| Code under test | persist **v61.4.1** (tag `v61.4.1` = `32e19ede`). The bench branch `bench-pre-kernel` changes only `Cargo.toml` (two `[[bench]]` entries) and `benches/`: `git diff --stat v61.4.1 ba4af20e` lists only those three files. |
| Bench commit | `ba4af20ebb6358a8965669cecaca8ed905507844` (branch `bench-pre-kernel`) |
| Machine | 13th Gen Intel Core i9-13900HX, 1 socket, 24 cores / 32 threads; 31 GiB RAM; Linux 7.0.0-42-generic |
| Toolchain | `rustc 1.97.0 (2d8144b78 2026-07-07)`, host `x86_64-unknown-linux-gnu`, LLVM 22.1.6; `cargo 1.97.0 (c980f4866 2026-06-30)` |
| Profile | `bench`, which inherits `release` (thin LTO, `codegen-units = 1`) |
| Backend | sqlite, file-backed, one temp directory per store. **No postgres variants** (see Gaps) |
| Data | Synthetic only. All keys come from the `test-anchor` deterministic test keypairs, and all rows are built and signed by the bench. No production key, row or bundle is read. |

## How to run

Every cargo command goes through the guard. The shared-host runs used these commands. Each one
fits within ten minutes.

```sh
# 1. vote evaluation (pure compute, no features)
CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh cargo bench --bench consensus_eval \
  -- --save-baseline pre-kernel --warm-up-time 1 --measurement-time 2

# 2-7. database paths (sqlite + the test-anchor fixture surface), split by filter
K="cargo bench --bench kernel_paths --features sqlite,test-anchor --"
CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh $K --save-baseline pre-kernel --warm-up-time 1 --measurement-time 3 \
  'trust_root_valid|delegation_walk|held_head|accord_recovery'
CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh $K --save-baseline pre-kernel --warm-up-time 1 --measurement-time 3 \
  'owner_of/.*/(1000|16000)$|admission_door|fold_recompute/.*/1000$'
CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh $K --save-baseline pre-kernel --warm-up-time 1 --measurement-time 3 \
  'owner_of/.*/64000$'
CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh $K --save-baseline pre-kernel 'fold_recompute/.*/16000$'

# 6 + 8. one pass at 16k / 64k: rows/s and peak RSS (criterion is not used)
B=$(ls -t target/release/deps/kernel_paths-* | grep -v '\.d$' | head -1)   # built by the commands above
for o in in_order reversed shuffled; do for n in 16000 64000; do
  KERNEL_PATHS_PEAK_RSS=admission:$o:$n CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh /usr/bin/time -v $B
done; done
KERNEL_PATHS_PEAK_RSS=folds:64000 CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh /usr/bin/time -v $B

# fixture self-check: builds every fixture small and reports each failure, no measurement
KERNEL_PATHS_SMOKE=1 CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh cargo bench --bench kernel_paths --features sqlite,test-anchor
```

**Re-run against the baseline after the kernel move.** Use the same commands, with
`--save-baseline pre-kernel` replaced by `--baseline pre-kernel`. Criterion then prints the
change against these numbers. The baseline lives in `target/criterion/**/pre-kernel/` of this
worktree. For the one-pass runs, compare the printed `rows_per_s` and `vm_hwm_kb` with the tables
below by hand.

The `pre-kernel` baseline also holds three entries that no longer exist in the sweep. Ignore
them: `held_head/fork_refused/*` (an early version that signed inside the timed loop), and
`admission_door/in_order/{4000,16000}` (made under the heavy load, before those sizes moved to
the one-pass mode).

## Coverage

| # | Path | Bench | Status |
|---|---|---|---|
| 1 | `federation::consensus::evaluate`, including the private `eligible`/`counted` passes | `consensus_eval` | **Covered.** `eligible`/`counted` are private and are reached through `evaluate`, which runs both on every call. Protocols: `unanimous`, `majority`, `reverse_quorum:2/3:86400`, `founder_only`, plus `quorum:2/3`. Rosters: 3, 16, 128, 1024. Two outcomes: `met` (every member signs) and `short` (a third sign). Persons are `PersonsAt::each_key()`. The multi-device persons view (`KeySelves::of_devices`) is `#[cfg(test)]` and cannot be reached. `founder_only/short/3` has no case, because every short ballot at 3 seats contains a founder. |
| 2 | `admission::owner_of` | `kernel_paths` `owner_of/*` | **Covered.** Real owner bindings sealed by the owner, admitted through the door. Probes: `one_owner`, `cosigned` (the binding also carries the **node's own co-scrub** in `additional_scrubs`, the two-consent seat that ADOPTING.md says the kernel reads; the door admits it), `withdrawn` (binding plus the owner's `withdraws`), and `no_owner`. Background stores of 1k / 16k / 64k bindings: 64 owners, one node each. |
| 3 | `trust_root::trust_root_valid` and the edge walk | `trust_root_valid/*`, `delegation_walk/*` | **Covered.** `trust_root_valid` runs on an `establish_trust_root` key-arm root, with 0 / 16 / 128 extra trust edges on the user, and on an uncharted root (`valid: false`). The walk: `moderate` + `sub_delegation` chains of depth 1 / 4 / 16 / 32 through `reachable_under_scope` (`reach_tip`, plus `reach_miss`, which exhausts the chain), and the cycle gate `check_delegation_cycle_admission` on a closing edge (`cycle_gate_closing`, refused for a cycle of depth + 1) and on an open edge (`cycle_gate_open`). **A cycle cannot be stored**, because the door refuses the closing edge. So "a cycle" is measured as the gate finding it, not as a walk over a held cycle. Every walk clamps at `MAX_WITHDRAWS_DELEGATION_DEPTH` = 16, which is why 16 and 32 cost the same. |
| 4 | `group_supersede_admit::held_head_verdict` over a forked lineage | `held_head/*` | **Covered through the door only.** `held_head_verdict` and its module are `pub(crate)`. The bench submits a quorum-signed fork through `supersede_family_with_quorum` (signed once, outside the timed loop) over lineages of 1 / 16 / 128 versions: a fork off the founding version, and a fork off the head's parent. The refusal is `lineage_prev_head_mismatch`. The figure is the **whole door's** refusal, including verification of the three quorum signatures, not the verdict alone. |
| 5 | `accord_recovery::{recovery_commitment_in_force, verify_accord_recovery}` | `accord_recovery/*` | **Covered.** A synthetic accord (`register_genesis_accord_roster` + `seed_accord_family`) with a lineage of 1 / 16 / 128 versions, each naming a fresh co-scrubbed charter. `verify_accord_recovery` judges a drafted and signed (not submitted) recovery of holder 0 to a new key. |
| 6 | Admission door end to end, rows/s by arrival order | `admission_door/*` (1k) + one-pass mode (16k, 64k) | **Covered, with the quota bypassed by design. See Notes.** Workload: chains of 8 `delegates_to` capability edges (`k0 → … → k8`), arriving in order, reversed, or shuffled (xorshift64*, seed `0x5EED_CAFE_F00D_0001`). In order, each edge's grantee has no out-edge yet. Reversed, the cycle gate walks the rest of the chain. |
| 7 | Fold recompute from cold (takedown, deletion, guardianship) | `fold_recompute/*` (1k, 16k) + `folds:64000` | **Partly covered.** **Deletion:** `run_deletion_window_watch` over the whole store, where half the rows carry a future `deletion_window`. **Guardianship:** `steward_bindings_of` for every agent, where the other half of the rows are custody bindings `delegates_to(steward → agent)` with the ownership marker. Each pass first opens a new handle on the file (fresh connections, empty sqlite page cache; the OS page cache stays warm), and the open is not timed. **Takedown is not covered** (see Gaps). |
| 8 | Peak memory for 6 and 7 at 64k | `KERNEL_PATHS_PEAK_RSS` | **Covered.** One pass. The process resets its high-water mark (`echo 5 > /proc/self/clear_refs`) after building the fixture, so `VmHWM` is the pass's own peak. The pre-pass RSS is reported beside it, and `/usr/bin/time -v` gives the whole-process maximum. |

### Gaps, and the smallest hooks that would close them (none added)

- **`held_head_verdict` directly (item 4).** The function is `pub(crate)` in a `pub(crate)` module.
  To time only the verdict, the smallest hook would be a
  `#[cfg(feature = "test-anchor")] pub fn held_head_verdict_for_bench(cohort, snapshot_json, held_row_hash) -> Result<(), Error>`
  in `federation::group_supersede_admit` (or a `test_support` re-export). It would wrap
  `decode_planned_head` and `held_head_verdict`. **Not added**, because the brief rules out widening
  the API. The door-level number is what a caller sees in any case.
- **Takedown fold (item 7).** `takedown_authority`, `takedown_terms` and `takedown_tombstone` are
  public, but a takedown that gets past them needs a content binding, a duty-holder reached over a
  live `takedown`-scoped chain, and a signed `takedown_notice:{basis}:v1`. No `test-anchor` helper
  assembles that, and `list_takedowns` is only a paged list, not a fold. Building it through the
  public door is possible but was not done here. No hook is needed, only a larger fixture.
- **Multi-device persons in the vote count (item 1).** `KeySelves::of_devices` is `#[cfg(test)]`.
  The smallest hook would be to gate it `#[cfg(any(test, feature = "test-anchor"))]` with `pub`.
  **Not added.** Without it, the bench counts every key as its own person.
- **The wire door's throughput (item 6).** `put_attestation` meters each attester at 600 rows/min,
  never-seen attesters together at the same rate, and the node at 6 000 rows/min burst, then
  100 rows/s (AV-76). At 1k rows or more the wire door refuses with `RateLimited`
  (`UntrackedTailBurst`, then `NodeBurst`). Its rows/s is therefore the quota, by design. See Notes.
- **Postgres.** Not added. A postgres variant needs a second release build of the lib with
  `--features postgres` (about 7 minutes, plus an LTO link per bench binary), a backend-generic
  `Store`, and `scripts/pg_test_db.sh` around each run. That did not come cheaply in this pass. The
  benches are written against `&dyn FederationDirectory` apart from `Store`, so the variant is a
  `Store` enum and a `pg_test_db.sh` wrapper.
- **`admission_door` at 16k / 64k and `fold_recompute` at 64k under criterion.** Criterion's floor
  of ten samples means eleven passes. On the shared host, one admission pass took 20–35 s at 16k,
  and a 64k fold fixture is 64k admissions. These sizes run once each in the one-pass mode instead.

## Notes on reading the numbers

- **Fixtures and the admission bench use the authored door** (`put_attestation_authored`). It runs
  the same gauntlet as `put_attestation`: plan, every gate, hybrid verify, write. It is charged only
  to the node's own ingest ceiling, not to the per-attester AV-76 buckets. That ceiling also binds
  (6 000 rows, then 100 rows/s), but it is held per backend instance, so the loop opens a fresh
  handle on the same file every 5 000 rows. The opens are not timed. **The admission figures are
  the gauntlet's cost, not the quota's.** Through one handle, persist admits at most 6 000 rows and
  then 100 rows/s, and the kernel move does not change that (the quota is in "Keep",
  ADOPTING.md).
- **Signing is never timed.** Rows are signed up front on 8 threads with 16 MB stacks. Every timed
  call is a read, a verdict, or a door call on pre-signed input.
- `held_head` (about 2.5 ms) is dominated by verifying the three hybrid quorum signatures. It is
  flat over lineage length, because the head check reads only the held head.
- `accord_recovery` grows with the lineage, because `recorded_statements` reads every stored
  version (`list_group_versions`).

## Headline numbers (median)

Re-run at load average 1–3. Times are criterion medians unless the table says otherwise.

### 1. Vote evaluation: `consensus::evaluate` (µs)

| protocol / outcome | 3 | 16 | 128 | 1024 |
|---|---:|---:|---:|---:|
| unanimous / met | 0.129 | 0.910 | 10.06 | 153.0 |
| unanimous / short | 0.176 | 1.000 | 12.35 | 146.7 |
| majority / met | 0.130 | 0.914 | 10.26 | 149.3 |
| majority / short | 0.177 | 1.005 | 12.42 | 140.9 |
| reverse_quorum / met | 0.160 | 0.968 | 10.27 | 149.9 |
| reverse_quorum / short | 0.210 | 1.054 | 12.54 | 148.9 |
| founder_only / met | 0.135 | 0.924 | 10.34 | 153.4 |
| founder_only / short | n/a | 0.664 | 7.60 | 108.6 |
| quorum:2/3 / met | 0.135 | 0.916 | 10.14 | 145.0 |
| quorum:2/3 / short | 0.184 | 0.688 | 8.53 | 115.6 |

The cost grows faster than linearly in roster size (about 150 ns per seat at 1024, against
about 45 ns at 3). That is `eligible`'s `BTreeMap` keyed by person plus `counted`'s `BTreeSet`.

### 2. Ownership: `owner_of` (µs), by store size (owner bindings held)

| probe | 1k | 16k | 64k |
|---|---:|---:|---:|
| one_owner | 90.6 | 93.4 | 87.6 |
| cosigned (owner seal + node co-scrub) | 93.6 | 100.9 | 89.6 |
| withdrawn | 73.0 | 73.2 | 67.9 |
| no_owner | 17.0 | 17.9 | 16.6 |

Flat in store size: the read is indexed on the node.

### 3. Trust root and the edge walk (µs)

`trust_root_valid`, by the number of extra trust edges on the user:

| case | 0 | 16 | 128 |
|---|---:|---:|---:|
| valid_root | 259.6 | 416.6 | 1 527.2 |
| uncharted_root | n/a | 241.6 | 1 461.0 |

Delegation walk, by chain depth (the ceiling is 16 hops):

| case | 1 | 4 | 16 | 32 |
|---|---:|---:|---:|---:|
| reach_tip (`reachable_under_scope`) | 36.8 | 163.5 | 626.7 | 612.8 |
| reach_miss | 47.9 | 182.9 | 631.7 | 670.0 |
| cycle_gate_closing (refused) | 33.2 | 156.6 | 633.1 | 639.6 |
| cycle_gate_open | 41.5 | 167.3 | 650.9 | 647.9 |

About 40 µs per hop: one indexed read per node visited.

### 4. Heads and forks: the supersede door refusing a fork (ms)

| case | lineage 1 | 16 | 128 |
|---|---:|---:|---:|
| fork_from_root | 2.63 | 2.46 | 2.39 |
| fork_from_parent | 2.56 | 2.53 | 2.57 |

### 5. Accord recovery (ms), by lineage length (versions)

| case | 1 | 16 | 128 |
|---|---:|---:|---:|
| recovery_commitment_in_force | 0.097 | 0.467 | 3.99 |
| verify_accord_recovery | 0.389 | 1.012 | 5.29 |

### 6. Admission door: rows/s (authored door, quota bypassed by handle rotation)

| arrival order | 1k (criterion median) | 16k (one pass) | 64k (one pass) |
|---|---:|---:|---:|
| in order | 1 239 | 1 274 | 1 228 |
| reversed | 913 | 880 | 872 |
| shuffled | 1 127 | 1 030 | 954 |

The 1k figure is rows ÷ median pass time (807 / 1 095 / 888 ms). Reversed arrival is about 30 %
slower, because the cycle gate walks the rest of each chain before admitting an edge. Under the
heavy load seen earlier, the same passes ran at 240–800 rows/s.

### 7. Fold recompute from cold (ms per full pass)

| fold | 1k | 16k | 64k (one pass) |
|---|---:|---:|---:|
| deletion (`run_deletion_window_watch`, all rows) | 7.8 | 108.8 | 490 |
| guardianship (`steward_bindings_of`, every agent: n/2 agents) | 77.1 | 1 222 | 5 130 |

The 64k pass ran at load average 3–9. Deletion scans 64 032 rows (the 64 000 fixture rows and 32
the store holds besides), and guardianship resolves 32 000 agents, one steward each.

### 8. Peak memory at 64k (KiB)

| pass | RSS before the pass | VmHWM of the pass | pass's own growth | `/usr/bin/time` max RSS |
|---|---:|---:|---:|---:|
| admission, in order | 969 200 | 1 151 796 | +182 596 | 1 151 796 |
| admission, reversed | 969 332 | 1 146 876 | +177 544 | 1 146 876 |
| admission, shuffled | 969 180 | 1 389 000 | +419 820 | 1 389 000 |
| folds (deletion + guardianship) | 558 696 | 1 202 060 | +643 364 | 1 197 196 |

"RSS before" is the fixture held in memory: 64k signed rows, held twice for the admission passes
(the workload and its ordered copy), plus the key list. The pass's own growth is the figure to
compare after the move. At 16k the admission passes peaked at 383 700–427 156 KiB (VmHWM), from a
start of about 286 300 KiB.
