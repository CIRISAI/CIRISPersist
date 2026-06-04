#!/usr/bin/env bash
# Live all-thread call-stack snapshot of a hung process (CIRISPersist#156).
#
# Usage: tools/debug_attach.sh <pid>
#
# Mirrors the CIRISEdge tools/debug_attach.sh shape — same gdb batch
# invocation; the only difference is the diagnostic output is filtered
# for persist-side stack frames (the panic-hook in src/debug/mod.rs
# captures the same shape on the persist side as the edge side).
#
# Requires either:
#   - kernel.yama.ptrace_scope=0 (system-wide; persists until reboot)
#   - running as root / with CAP_SYS_PTRACE
#   - target opted in via prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)
#
# rust-gdb is preferred (loads Rust pretty-printers); falls back to
# stock gdb if rust-gdb is not on PATH.

set -euo pipefail

PID="${1:-}"
if [[ -z "${PID}" ]]; then
  echo "usage: $0 <pid>" >&2
  exit 2
fi

GDB="$(command -v rust-gdb || command -v gdb || true)"
if [[ -z "${GDB}" ]]; then
  echo "error: rust-gdb / gdb not found on PATH" >&2
  exit 3
fi

# Default filter: keep tokio frames; flip CIRIS_GDB_FILTER_TOKIO=1 to drop them.
FILTER_CMD="cat"
if [[ "${CIRIS_GDB_FILTER_TOKIO:-0}" == "1" ]]; then
  FILTER_CMD="grep -v -E '(tokio::|tokio_util::|core::future::)'"
fi

"${GDB}" \
  -batch \
  -quiet \
  -ex "set pagination off" \
  -ex "set print thread-events off" \
  -ex "attach ${PID}" \
  -ex "info threads" \
  -ex "thread apply all bt 80" \
  -ex "detach" \
  -ex "quit" \
  2>&1 | eval "${FILTER_CMD}"
