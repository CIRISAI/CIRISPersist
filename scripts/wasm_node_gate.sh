#!/usr/bin/env bash
# wasm_node_gate.sh — v62.0.0 (slice D, readiness P12; FSD WASM_NODE §4.1).
#
# The node build's three gates, in order. Each one fails the script; nothing
# here passes by not running.
#
#   1. GRAPH. Persist's NODE feature set (`--no-default-features --features
#      sqlite,host-abi`) resolved for wasm32-unknown-unknown pulls none of the
#      host-only or JS-shaped crates and features: mio, socket2, reqwest,
#      hickory-*, fs4, redb, libloading, keyring, wasm-bindgen, js-sys,
#      web-sys; tokio's rt-multi-thread / signal / net / process / fs;
#      getrandom's js / wasm_js; chrono's wasmbind; time's wasm-bindgen;
#      uuid's js. (`cargo tree`, no build.)
#   2. LINK. The probe node module (tools/wasm_node_probe: persist's node set
#      + ciris-host-abi's getrandom backend + sqlite-wasm-rs's host hooks)
#      builds for wasm32-unknown-unknown with
#      `--cfg getrandom_backend="custom"`.
#   3. IMPORTS. Every import of the built module is a function from a
#      `ciris:node/*` interface (no `env`, no `wasi:*`, no
#      `__wbindgen_placeholder__`). The import list is printed either way.
#
# The fourth rule, "no cfg(target_*) in node code", is the from-disk gate
# I1796/I1852 (src/store/host_seams_gate.rs), which runs with the lib tests;
# `--with-cfg-gate` runs it here too.
#
# A C compiler for wasm32 is needed (ring's aead, the SQLite amalgamation):
# clang with a wasm32 backend if one is on PATH, else `zig cc`
# (scripts/wasm/zig-cc.sh). Run under scripts/cargo_guard.sh:
#
#   CARGO_GUARD_MAX_GB=15 scripts/cargo_guard.sh scripts/wasm_node_gate.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
TARGET=wasm32-unknown-unknown
NODE_FEATURES="sqlite,host-abi"
PROBE="$ROOT/tools/wasm_node_probe"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
WITH_CFG_GATE=0
for a in "$@"; do
  case "$a" in
    --with-cfg-gate) WITH_CFG_GATE=1 ;;
    *) echo "usage: $0 [--with-cfg-gate]" >&2; exit 2 ;;
  esac
done

fail=0
say() { printf '%s\n' "$*"; }

# UPSTREAM exceptions, each with its reason and its removal condition. A
# listed pair is reported loudly, never silently; a listed pair that no longer
# occurs is RED (remove it here), so the list cannot outlive its cause.
#   referencing 0.46 (via jsonschema 0.46, persist's trace-format validator)
#   declares `[target.'cfg(target_arch = "wasm32")'.dependencies]
#   getrandom = { features = ["wasm_js"] }`, which brings the wasm-bindgen
#   crate into the graph. `--cfg getrandom_backend="custom"` selects the
#   custom backend BEFORE wasm_js, so none of it links: gate 3 proves the
#   module imports no wasm-bindgen symbol. Remove when referencing stops
#   forcing wasm_js (an upstream ask).
UPSTREAM_ACCEPTED_CRATES="wasm-bindgen"
UPSTREAM_ACCEPTED_FEATURES="getrandom:wasm_js"
accepted_crate() { case " $UPSTREAM_ACCEPTED_CRATES " in *" $1 "*) return 0 ;; esac; return 1; }
accepted_feature() { case " $UPSTREAM_ACCEPTED_FEATURES " in *" $1 "*) return 0 ;; esac; return 1; }

# ── 1. GRAPH ────────────────────────────────────────────────────────────
say "─── wasm node gate 1/3: the node feature graph ───"
tree_normal="$(cargo tree --target "$TARGET" --no-default-features --features "$NODE_FEATURES" \
  -e normal --prefix none --format '{p}' | sort -u)"
for crate in mio socket2 reqwest hickory-proto hickory-resolver fs4 redb libloading keyring \
             wasm-bindgen js-sys web-sys; do
  present=0; grep -Eq "^${crate} v" <<<"$tree_normal" && present=1
  if accepted_crate "$crate"; then
    if [ "$present" -eq 1 ]; then
      say "! ACCEPTED UPSTREAM: the node graph pulls ${crate} (see UPSTREAM_ACCEPTED_CRATES):"
      cargo tree --target "$TARGET" --no-default-features --features "$NODE_FEATURES" -e normal \
        -i "$crate" --depth 3 | sed 's/^/    /' || true
    else
      say "✗ ${crate} is listed as an accepted upstream crate but no longer occurs: remove it"
      fail=1
    fi
    continue
  fi
  if [ "$present" -eq 1 ]; then
    say "✗ the node graph pulls ${crate}:"
    cargo tree --target "$TARGET" --no-default-features --features "$NODE_FEATURES" -e normal \
      -i "$crate" --depth 4 | sed 's/^/    /' || true
    fail=1
  fi
done
# Feature-level: the full `-e normal,features` tree prints a node
# `<crate> feature "<f>"` for every feature turned on (all versions at once:
# `-i getrandom` would refuse, there are three getrandoms).
tree_features="$(cargo tree --target "$TARGET" --no-default-features --features "$NODE_FEATURES" \
  -e normal,features --prefix none | sort -u)"
for pair in 'tokio:rt-multi-thread' 'tokio:signal' 'tokio:net' 'tokio:process' 'tokio:fs' \
            'getrandom:js' 'getrandom:wasm_js' 'chrono:wasmbind' 'time:wasm-bindgen' 'uuid:js'; do
  crate="${pair%%:*}"; feat="${pair#*:}"
  present=0
  grep -Fq "${crate} feature \"${feat}\"" <<<"$tree_features" && present=1
  if accepted_feature "$pair"; then
    if [ "$present" -eq 1 ]; then
      say "! ACCEPTED UPSTREAM: the node graph turns on ${crate}/${feat} (see UPSTREAM_ACCEPTED_FEATURES)"
    else
      say "✗ ${pair} is listed as an accepted upstream feature but no longer occurs: remove it"
      fail=1
    fi
    continue
  fi
  if [ "$present" -eq 1 ]; then
    say "✗ the node graph turns on ${crate}/${feat}"
    fail=1
  fi
done
[ "$fail" -eq 0 ] && say "✓ no host-only or JS-shaped crate or feature in the node graph beyond the accepted upstream ones ($(wc -l <<<"$tree_normal") crates)"

# ── 2. LINK ─────────────────────────────────────────────────────────────
say "─── wasm node gate 2/3: link the probe node module ───"
if command -v clang >/dev/null 2>&1 && clang --print-targets 2>/dev/null | grep -q wasm32; then
  say "  C compiler: clang"
else
  command -v zig >/dev/null 2>&1 || { say "✗ no clang with a wasm32 backend and no zig on PATH"; exit 1; }
  export CC_wasm32_unknown_unknown="$ROOT/scripts/wasm/zig-cc.sh"
  export AR_wasm32_unknown_unknown="$ROOT/scripts/wasm/zig-ar.sh"
  say "  C compiler: zig cc ($(zig version))"
fi
# sccache cannot wrap the zig wrapper; the probe is a one-off build.
unset RUSTC_WRAPPER
# `--allow-undefined`: persist's own [lib] is `cdylib` + `rlib` (the wheel), so
# cargo links a persist .wasm on the way to the probe, and that one has no
# sqlite-wasm-rs hooks (the probe defines them). An undefined symbol in the
# PROBE becomes an `env` import, which gate 3 refuses: nothing is hidden.
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS='--cfg getrandom_backend="custom" -C link-arg=--allow-undefined'
# The probe resolves against persist's own lock (gitignored in tools/).
cp "$ROOT/Cargo.lock" "$PROBE/Cargo.lock"
if ! cargo build --manifest-path "$PROBE/Cargo.toml" --target "$TARGET" --release; then
  say "✗ the probe node module does not build for $TARGET"
  exit 1
fi
MODULE="$CARGO_TARGET_DIR/$TARGET/release/ciris_persist_wasm_node_probe.wasm"
[ -f "$MODULE" ] || { say "✗ no module at $MODULE"; exit 1; }
say "✓ built $MODULE ($(stat -c %s "$MODULE") bytes raw, $(gzip -9c "$MODULE" | wc -c) gzip)"

# ── 3. IMPORTS ──────────────────────────────────────────────────────────
say "─── wasm node gate 3/3: the module's imports ───"
IMPORTS="$(python3 -I "$ROOT/scripts/wasm/wasm_imports.py" "$MODULE")"
say "$IMPORTS" | sed 's/^/    /'
bad="$(grep -Ev '^ciris:node/[a-z-]+@[0-9.]+ [^ ]+ func$' <<<"$IMPORTS" || true)"
if [ -n "$bad" ]; then
  say "✗ imports outside ciris:node/* (FSD WASM_NODE §4.1 rule 1):"
  say "$bad" | sed 's/^/    /'
  fail=1
else
  say "✓ every import is a ciris:node/* function ($(grep -c . <<<"$IMPORTS") imports)"
fi

if [ "$WITH_CFG_GATE" -eq 1 ]; then
  say "─── no target cfg in node code (I1796 / I1852) ───"
  cargo test --lib --no-default-features --features sqlite -- \
    host_seams_gate --test-threads 1 || fail=1
fi

exit "$fail"
