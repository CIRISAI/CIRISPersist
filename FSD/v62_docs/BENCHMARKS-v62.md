# Kernel benchmark, after the move (v62)

These are the after-numbers to compare with `BENCHMARKS-pre-kernel.md`, which holds the persist
v61.4.1 sqlite baseline, saved as criterion baseline `pre-kernel` under
`FSD/v62_docs/criterion-pre-kernel/`. The benches are `benches/kernel_paths.rs` (ported to
edition 2 by K1-bench) and `benches/consensus_eval.rs` (unchanged). **No v62 numbers are recorded
here yet.** Fill in the tables below from the first run on a green tree.

## The quiet-host rule

**The host is shared, so a number is only as good as the load it ran under.**

- Run `uptime` immediately before and after each command, and paste both load averages beside the
  numbers.
- A run started at a load average above 3 is not a comparison. Re-run it when the host is quiet.
- The baseline's re-runs were made at load 1–3. Under load the same benches ran 1.5–2.5× slower.
- Check that no other agent's cargo build is running (`pgrep -a rustc`) before starting.

## How to run

Every cargo command goes through the guard, and each fits within ten minutes. First copy the
baseline into the target directory, so criterion compares against it:

```sh
mkdir -p target/criterion && cp -r FSD/v62_docs/criterion-pre-kernel/* target/criterion/
```

```sh
# 0. FIRST, the fixture self-check: builds every fixture small, asks each path once, and reports
#    each failure by name. No measurement.
KERNEL_PATHS_SMOKE=1 CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh \
  cargo bench --bench kernel_paths --features sqlite,test-anchor

# 1. vote evaluation (pure compute)
uptime; CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh cargo bench --bench consensus_eval \
  -- --baseline pre-kernel --warm-up-time 1 --measurement-time 2; uptime

# 2-7. database paths, split by filter (the same splits as the baseline)
K="cargo bench --bench kernel_paths --features sqlite,test-anchor --"
uptime; CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh $K --baseline pre-kernel --warm-up-time 1 \
  --measurement-time 3 'trust_root_valid|delegation_walk|held_head|accord_recovery'; uptime
uptime; CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh $K --baseline pre-kernel --warm-up-time 1 \
  --measurement-time 3 'owner_of/.*/(1000|16000)$|admission_door|fold_recompute/.*/1000$'; uptime
uptime; CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh $K --baseline pre-kernel --warm-up-time 1 \
  --measurement-time 3 'owner_of/.*/64000$'; uptime
uptime; CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh $K --baseline pre-kernel \
  'fold_recompute/.*/16000$'; uptime
uptime; CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh $K --baseline pre-kernel 'ab_switched'; uptime

# 6 + 8. one pass at 16k / 64k: rows/s and peak RSS (not criterion)
B=$(ls -t target/release/deps/kernel_paths-* | grep -v '\.d$' | head -1)
for o in in_order reversed shuffled; do for n in 16000 64000; do
  uptime; KERNEL_PATHS_PEAK_RSS=admission:$o:$n CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh /usr/bin/time -v $B
done; done
uptime; KERNEL_PATHS_PEAK_RSS=folds:64000 CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh /usr/bin/time -v $B
```

Use `--save-baseline v62` in place of `--baseline pre-kernel` to keep this run as the next
baseline.

## Which comparisons are like-for-like

| group / case | vs `pre-kernel` | what changed |
|---|---|---|
| `consensus_eval/{unanimous,majority,founder_only,quorum_2_3}/*` | **like-for-like** | Same ballots. |
| `consensus_eval/reverse_quorum_refused/*` | **NEW name** | `reverse_quorum:*` is no longer a membership rule (RULINGS, "Kernel departures adopted"), so `evaluate` refuses it before any count. These cases time that refusal. The baseline's `consensus_eval/reverse_quorum/*` (an evaluation) has no counterpart. |
| `owner_of/{one_owner,cosigned,withdrawn,no_owner}/{1000,16000,64000}` | **like-for-like** | Same path (`admission::owner_of`) and same probes. Bindings are edition-2 `ownership:*` rows landed with the node's own voice. `cosigned` is now the same shape as `one_owner`, because every counted binding carries the node's voice. The fixture registers each node as a `key:record`, so building it is slower; the timed read is not affected. |
| `trust_root_valid/{valid_root,uncharted_root}/{0,16,128}` | **like-for-like work; the root is BUILT differently** | Same function (`trust_root_valid`), same reads per call, same names. Only the root's construction differs. The baseline's key-arm root (`establish_trust_root`: charter, heartbeat, user edge, scope edge) went through earlier-form doors. The root is now W1b's rooted edition-2 root: an `infrastructure` community founded by the bundle's holders through `group:roster` voices, its `trust:charter:v1` self-edge, and this node's `trust:accepts:v1` acceptance naming the held head. The extra edges are this node's acceptance edges to uncharted keys. A difference in the answer's inputs (a community root's head versus a key root) can move the figure, so read the growth with extra edges as well as the absolute value. |
| `delegation_walk/{reach_tip,reach_miss}/{1,4,16,32}` | **like-for-like** | Same chains (`moderate` + `sub_delegation`), now persons' edition-2 rows. |
| `delegation_walk/cycle_gate_*` | **gone** | The cycle gate is deleted, so these baseline entries have no counterpart. Ignore them. |
| `held_head/{new_fork_from_root,new_fork_from_parent}/{1,16,128}` | **NEW names** | Each iteration offers a NEW fork, signed before the clock starts, as two voices through `put_statement`: two composite verifications, the verdict (the fork is HELD as a tip, CC 2.7.8), and the tip write. The baseline's `held_head/fork_from_*` timed the door REFUSING one pre-signed fork, which is different work, so those entries have no counterpart. |
| `held_head/reoffer_noop/{1,16,128}` | **NEW name** | The re-offer fast path: one fork held as a tip before timing, then offered again. Each re-offer is an idempotent no-op at the door and never reaches the verdict. |
| `accord_recovery/recovery_bundle_v2/1` | **NEW** | The import door placing a later genesis bundle that carries one holder's recovery voice (CC 4.2.6; F0-cp3 / I2874), on a store holding the genesis. The baseline's `accord_recovery/*` (the earlier-form JSON recovery) is deleted, so its entries have no counterpart. |
| `admission_door/e2_{in_order,reversed,shuffled}/1000` and the one-pass `admission:*` | **NEW** | Each edge is now two statements (the author's and the delegate's voice), each with a composite (ML-DSA-65 + Ed25519) verification, through `ingest::put_statement`. The cycle gate that made `reversed` slower is gone. The baseline's `admission_door/{in_order,reversed,shuffled}` entries have no counterpart. |
| `fold_recompute/{deletion_window,guardianship}/{1000,16000}` and `folds:64000` | **like-for-like** | Same shape: half custody bindings (now landed with the agent's voice), half capability edges carrying `deletion_window`. |
| `ab_switched/*` | **kept** | Both legacy sides survive 4d (`owner_of_pre_kernel`, and `trust_edge_leg_ab(kernel = false)`), so this is still a same-binary A/B. It now runs over edition-2 stores. |

## Results

*(to be filled from the first run on a green tree, with the `uptime` load beside each table)*
