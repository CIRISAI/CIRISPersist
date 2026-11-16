# Building persist into a WASM node module

v62.0.0 (CIRISServer `FSD/WASM_NODE.md` §4.1; CIRISVerify `ciris-host-abi`).

A node module is ONE `wasm32-unknown-unknown` core module whose imports are
only `ciris:node/*` functions. The same bytes run in a browser Worker, under
wasmtime with a WASI-backed `ciris:node` host, and in EFI through wasm2c.

## Persist's features

| Build | Features | What it pulls |
|---|---|---|
| **node** | `--no-default-features --features sqlite,host-abi` (plus any domain axes) | verify-core `std`+`pqc`, slim keyring (no `fs`), tokio `rt, sync, macros, time` |
| **native host** | add `host` (implied by `postgres`, `server`, `queue`, `secrets-client`, the PyO3 shapes) | tokio `rt-multi-thread` + `signal`, fs4, verify-core `host`, keyring defaults (`fs`, `keyring-storage`, `tpm-plugin`) |

`host-abi` gives persist `host::abi::{AbiClock, AbiFreeBytes}`: the clock seam
over `ciris:node/clock` and the disk-pressure free-bytes source over
`ciris:node/storage`. Install them at `init`:

```rust
ciris_persist::host::HostSeams::single_thread()
    .with_clock(std::sync::Arc::new(ciris_persist::host::abi::AbiClock))
    .install();
```

Do not build an Engine (or stamp anything) before the host's `clock-trusted`
event: `AbiClock::now()` answers the Unix epoch while `wall-ms` is `none`.

## Randomness: the node crate's job, never persist's

Persist draws through `getrandom` (uuid `rng-getrandom`, `rand_core::OsRng`,
the key paths). Persist defines **no** getrandom symbol. The top-level node
crate (the one with `crate-type = ["cdylib"]` and `export_node!`):

1. depends on `ciris-host-abi` with feature **`getrandom-backend`**: on
   wasm32 it registers getrandom 0.2's custom backend and defines
   `__getrandom_v03_custom` (getrandom 0.3 and 0.4) over
   `ciris:node/random.fill`;
2. builds with the cfg getrandom 0.3 / 0.4 need, for the wasm target only:

```
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="custom"' \
  cargo build --target wasm32-unknown-unknown --release
```

or in the node crate's `.cargo/config.toml`:

```toml
[target.wasm32-unknown-unknown]
rustflags = ['--cfg', 'getrandom_backend="custom"']
```

Never enable getrandom `js` / `wasm_js`, uuid `js`, chrono `wasmbind` or time
`wasm-bindgen` anywhere in the graph.

## SQLite on wasm32

rusqlite 0.41 selects `sqlite-wasm-rs` on `wasm32-unknown-unknown` by itself.
sqlite-wasm-rs needs five C ABI symbols the node crate defines
(`rust_sqlite_wasm_host_{sleep,random,epoch_timestamp_in_ms,fill_entropy,localtime}`)
over `ciris:node/{clock,random}`; `tools/wasm_node_probe/src/lib.rs` is a
working example. Building the SQLite amalgamation and ring's AEAD C needs a
C compiler for wasm32: clang with the wasm32 backend, or `zig cc`
(`scripts/wasm/zig-cc.sh`, passed as `CC_wasm32_unknown_unknown`).

## The gate

`scripts/wasm_node_gate.sh` (CI job `wasm-node-gate`):

1. the node feature graph pulls no host-only or JS-shaped crate or feature;
2. the probe module links;
3. every import of the module is a `ciris:node/*` function.

The fourth rule, no `cfg(target_*)` in node code, is the from-disk gate
I1796 / I1852 in `src/store/host_seams_gate.rs`.
