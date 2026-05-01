//! Foreign-function interface shells.
//!
//! # Mission alignment (MISSION.md §2 — `ffi/`)
//!
//! Every CIRIS deployment target reaches the same Rust core. The
//! agent's iOS bundled-Python persistence is a debt against M-1
//! because every divergence between iOS and server reasoning is a
//! place the Federated Ratchet can be silently broken — different
//! bug surfaces, different invariants, different PII boundaries.
//! One core; many shells.
//!
//! Phase 1: PyO3 (Phase 1.9 — for the lens FastAPI integration per
//! FSD §3.5).
//! Phase 2: swift-bridge (iOS) + uniffi (Android).
//! Phase 3: optional uniffi unification.

#[cfg(feature = "pyo3")]
pub mod pyo3;
