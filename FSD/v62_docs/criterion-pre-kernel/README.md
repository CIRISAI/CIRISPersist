# Criterion baseline `pre-kernel`

These are the saved criterion baseline files (`<group>/<bench>/<size>/pre-kernel/{benchmark,estimates,sample,tukey}.json`) for the benches in `benches/consensus_eval.rs` and `benches/kernel_paths.rs`. The code under test was persist v61.4.1; the report is `../BENCHMARKS-pre-kernel.md`.

Restore before an after-run:

```sh
mkdir -p target/criterion
cp -r FSD/v62_docs/criterion-pre-kernel/. target/criterion/
cargo bench --bench consensus_eval --features sqlite -- --baseline pre-kernel
cargo bench --bench kernel_paths   --features sqlite -- --baseline pre-kernel
```

**Caveat: these numbers are tied to the machine that recorded them** (a shared 32-thread host; see the report). A ratio against them taken on different hardware is not evidence. For a proof of "no slower" on any other machine, re-record the baseline there first:
1. check out tag `v61.4.1` with the bench files from branch `bench-pre-kernel`;
2. run each bench with `-- --save-baseline pre-kernel`;
3. run the v62 tree with `--baseline pre-kernel`.

Better still, run the same-binary A/B that slice C used (bench group `ab_switched`), which compares the old and new paths in one process.

The baseline also holds three leftover entries from earlier attempts: `held_head/fork_refused/*` and `admission_door/in_order/{4000,16000}`. Ignore them.
