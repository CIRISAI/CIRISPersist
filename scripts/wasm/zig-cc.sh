#!/usr/bin/env bash
# v62.0.0 (slice D, P12) — a C compiler for wasm32-unknown-unknown when no
# clang with a wasm32 backend is installed: `zig cc` (bundles clang + libc
# headers). ring's aead C and sqlite-wasm-rs's SQLite amalgamation build with
# it. Rewrites the triple cc-rs passes (zig names it wasm32-freestanding).
set -euo pipefail
args=()
for a in "$@"; do
  case "$a" in
    --target=wasm32-unknown-unknown|--target=wasm32-unknown-unknown-*) args+=("-target" "wasm32-freestanding") ;;
    *) args+=("$a") ;;
  esac
done
exec zig cc "${args[@]}"
