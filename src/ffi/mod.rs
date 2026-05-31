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

// v3.8.0 (CIRISPersist#151) — wheel-surface modules wrapping
// CIRISVerify v4.7.0's #50 wheel surfaces. Each module is a thin
// PyO3 wrapper exposed via PyEngine methods (and, where stateful,
// via a PyClass). Per Eric's "if it ain't on the FFI/Python
// interface, it doesn't exist" rule, the substrate exposes every
// verify primitive its own ABI uses so downstream Python consumers
// can call them through `ciris-persist` natively.

#[cfg(feature = "pyo3")]
pub mod wheel_hybrid_kex;

#[cfg(feature = "pyo3")]
pub mod wheel_key_grant;

#[cfg(feature = "pyo3")]
pub mod wheel_locale_merkle;

#[cfg(feature = "pyo3")]
pub mod wheel_reconsider_dos;

#[cfg(feature = "pyo3")]
pub mod wheel_skill_import;
