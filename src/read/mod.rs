//! Façade shim — the v3.x `read` surface re-exported from its v4.0 home
//! under [`crate::ceg`].
//!
//! # v4.0 module reorganization (FSD §3)
//!
//! v4.0 rehomes the read primitives under topic-named `src/ceg/`
//! namespaces (FSD §3.1/§3.3). This shim preserves every `crate::read::*`
//! / `ciris_persist::read::*` import path the v3.x surface exposed so the
//! "module reorg" commit is a behaviour-neutral move: existing consumers
//! and internal call sites keep compiling against `read::` while the
//! types live under `ceg::`.
//!
//! **This shim is removed in a LATER v4.0 commit** (FSD §3.3 — "`src/read/mod.rs`
//! is removed in v4.0"). At that point consumers re-import from
//! `ciris_persist::ceg::*` or `ciris_persist::prelude::*`. It exists in
//! this commit only to keep the cut hard-break-free per-commit.

pub use crate::ceg::*;
