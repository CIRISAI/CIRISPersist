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

// v3.13.0 (CIRISPersist#157) — ABI-stable async-executor capsule.
// C-ABI vtable + opaque data; consumer cohabitating wheels (edge,
// nodecore, lenscore) get an executor handle that dispatches through
// persist's tokio regardless of which crate's tokio called. Closes
// the cross-tokio aliasing class behind CIRISEdge#58 / CIRISPersist#156.
//
// Available without the `pyo3` feature so non-Python consumers (Rust
// binaries linking persist as an rlib) can also use the capsule shape
// — though the only current packaging surface is the PyCapsule on
// PyEngine in src/ffi/pyo3.rs.
pub mod executor_capsule;

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
