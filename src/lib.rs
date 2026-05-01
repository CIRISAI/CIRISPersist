//! ciris-persist — unified Rust persistence for the CIRIS Trinity.
//!
//! Owns: signed-event persistence (with Ed25519 hash chain), time-series
//! storage, and (Phase 3) the agent's runtime-state, memory-graph, and
//! governance tables. The destination is a single persistence binary shared
//! by both lens and agent, per the Proof-of-Benefit Federation FSD §3.1.
//!
//! Status: pre-implementation. See `FSD/CIRIS_PERSIST.md` for scope and
//! sequencing across Phases 1, 2, and 3.

// Phase 1 surfaces (not yet implemented):
//   pub mod schema;
//   pub mod verify;
//   pub mod scrub;
//   pub mod store;
//   #[cfg(feature = "server")]
//   pub mod server;
//   #[cfg(feature = "pyo3")]
//   pub mod ffi;
