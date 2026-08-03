//! v3.7.0 (CIRISPersist follow-up to verify v4.7.0 / CIRISVerify#50) —
//! PyO3 surface for CIRISVerify v4.7.0's `ReconsiderDosGuard`.
//!
//! CIRISVerify v4.7.0 shipped a Python sidecar
//! (`ciris_verify/_wheel_reconsider_dos.py`) that grafts a
//! handle-based `ReconsiderDosGuard` class onto its own `CIRISVerify`
//! Python wrapper. Per Eric's discipline — "if it ain't on the
//! FFI/Python interface, it doesn't exist" — persist exposes a
//! parallel surface so callers who hold a `ciris_persist.PyEngine`
//! get the same DoS-defense primitive natively without having to
//! reach across into the verify wheel.
//!
//! The Rust core (`ciris_verify_core::reconsider_dos`) is sync and
//! stateful — per-event rate limits, per-actor rolling-window
//! budgets, and per-(requester, target) harassment cluster scores
//! live in process memory. PyO3's `#[pyclass]` ownership model maps
//! naturally: each Python `ReconsiderDosGuard` instance owns one
//! `InnerGuard` behind a `std::sync::Mutex` (verify's guard is `!Sync`,
//! so concurrent access from Python threads needs a lock; the verify
//! sidecar punts that to the caller via a `threading.Lock`, but a
//! PyO3-side `Mutex` is essentially free and keeps the surface
//! foot-gun-proof).
//!
//! # Wiring (orchestrator task — not done here)
//!
//! After this file lands the integrator MUST add two lines:
//!
//! 1. In `src/ffi/mod.rs`, under the `#[cfg(feature = "pyo3")]` block,
//!    add:
//!
//!    ```ignore
//!    #[cfg(feature = "pyo3")]
//!    pub mod wheel_reconsider_dos;
//!    ```
//!
//! 2. In `src/ffi/pyo3.rs`, inside the `#[pymodule] fn ciris_persist`
//!    function (currently around line 19054), next to the existing
//!    `m.add_class::<PyEngine>()?;` line, add:
//!
//!    ```ignore
//!    m.add_class::<crate::ffi::wheel_reconsider_dos::PyReconsiderDosGuard>()?;
//!    ```
//!
//! After that Python callers can do:
//!
//! ```python
//! from ciris_persist import ReconsiderDosGuard
//! g = ReconsiderDosGuard()
//! decision = g.admit_filing("evt-A", "alice", "bob", 1_700_000_000_000)
//! # decision is a JSON string: '{"admitted": true}' or
//! # '{"admitted": false, "rejection": {"HarassmentClusterDetected": {...}}}'
//! ```
//!
//! # JSON-string return shape
//!
//! Persist's existing PyO3 convention (see
//! `cirisnode_process_takedown_admission_json` in `pyo3.rs`) is to
//! return `PyResult<String>` carrying serde-encoded JSON rather than
//! building a `PyDict` directly. Callers `json.loads(...)` on the
//! Python side. This module follows that convention so the surface
//! reads consistently with the rest of `PyEngine`.

use std::sync::Mutex;

use ciris_verify_core::reconsider_dos::{
    FilingOutcome, ReconsiderDosGuard as InnerGuard, ReconsiderRejection,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use serde::Serialize;

/// PyO3 wrapper around `ciris_verify_core::reconsider_dos::ReconsiderDosGuard`.
///
/// Stateful — holds per-event rate-limit counters, per-actor
/// rolling-window budget timestamps, and per-(requester, target)
/// harassment cluster scores. Construct one per logical defense
/// domain (e.g. one per CIRISNodeCore P11 dispatcher in-process).
///
/// The inner guard is wrapped in a `std::sync::Mutex` so the class
/// is safe to call from multiple Python threads. The verify-side
/// sidecar leaves locking to the caller; the PyO3 surface defaults
/// to lock-on-each-call because the cost is trivial relative to the
/// admit-time HashMap ops.
#[pyclass(name = "ReconsiderDosGuard", module = "ciris_persist")]
pub struct PyReconsiderDosGuard {
    inner: Mutex<InnerGuard>,
}

/// Serializable envelope for [`PyReconsiderDosGuard::admit_filing`].
///
/// Mirrors the Python sidecar's documented return shape:
///
/// - `{"admitted": true}` on success.
/// - `{"admitted": false, "rejection": {<variant>: {...}}}` on
///   rejection, where `<variant>` is one of `EventRateLimited`,
///   `ActorBudgetExhausted`, `HarassmentClusterDetected` (serde's
///   default tagging on the `ReconsiderRejection` enum).
#[derive(Debug, Serialize)]
struct AdmitEnvelope<'a> {
    admitted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    rejection: Option<&'a ReconsiderRejection>,
}

#[pymethods]
impl PyReconsiderDosGuard {
    /// Construct a fresh guard with the verify-core default
    /// thresholds:
    ///
    /// - `DEFAULT_EVENT_RATE_LIMIT = 10` concurrent reconsiderations
    ///   per moderation event.
    /// - `DEFAULT_ACTOR_BUDGET = 30` filings per actor rolling over
    ///   `DEFAULT_BUDGET_WINDOW_MS = 7 days`.
    /// - `DEFAULT_HARASSMENT_CLUSTER_THRESHOLD = 2.0` distinct events
    ///   per `(requester, target)` pair within the window.
    #[new]
    fn new() -> Self {
        Self {
            inner: Mutex::new(InnerGuard::new()),
        }
    }

    /// Run the composed admit-time check (harassment cluster →
    /// actor budget → per-event rate limit).
    ///
    /// On admission, commits the filing across all three trackers
    /// and returns `'{"admitted": true}'`.
    ///
    /// On rejection, no state is mutated (the guard is atomic — a
    /// rate-limit failure rolls back the budget commit) and returns
    /// `'{"admitted": false, "rejection": {"<variant>": {...}}}'`
    /// where `<variant>` is one of `EventRateLimited`,
    /// `ActorBudgetExhausted`, `HarassmentClusterDetected`.
    ///
    /// Args:
    ///     event_id: The moderation event being reconsidered.
    ///     requester_id: The actor filing the reconsideration.
    ///     target_id: The actor moderated by the underlying event.
    ///     now_ms: Caller-injected wall-clock (milliseconds since
    ///         epoch). The Rust core never reads the wall clock;
    ///         callers pass `int(time.time() * 1000)`.
    ///
    /// Returns:
    ///     JSON string. Callers `json.loads(...)` to consume.
    fn admit_filing(
        &self,
        event_id: &str,
        requester_id: &str,
        target_id: &str,
        now_ms: u64,
    ) -> PyResult<String> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PyRuntimeError::new_err("ReconsiderDosGuard mutex poisoned"))?;
        match guard.admit_filing(event_id, requester_id, target_id, now_ms) {
            Ok(()) => {
                let env = AdmitEnvelope {
                    admitted: true,
                    rejection: None,
                };
                serde_json::to_string(&env).map_err(|e| {
                    PyRuntimeError::new_err(format!(
                        "ReconsiderDosGuard.admit_filing serialize: {e}"
                    ))
                })
            }
            Err(rej) => {
                let env = AdmitEnvelope {
                    admitted: false,
                    rejection: Some(&rej),
                };
                serde_json::to_string(&env).map_err(|e| {
                    PyRuntimeError::new_err(format!(
                        "ReconsiderDosGuard.admit_filing serialize: {e}"
                    ))
                })
            }
        }
    }

    /// Record the outcome of a previously-admitted filing.
    ///
    /// - `"successful"` releases the per-event rate-limit slot AND
    ///   refills one budget slot for `requester_id` (the filing
    ///   reversed a moderation decision — the actor regains a slot).
    /// - `"rejected"` releases the per-event rate-limit slot only.
    /// - `"withdrawn"` is treated as `"rejected"` (releases the
    ///   rate-limit slot, no budget refill) — the verify-core
    ///   `FilingOutcome` enum only distinguishes Successful /
    ///   Rejected; "withdrawn" is a callsite courtesy alias that
    ///   maps to Rejected for budget purposes.
    ///
    /// Args:
    ///     event_id: Same identifier passed to `admit_filing`.
    ///     requester_id: Same identifier passed to `admit_filing`.
    ///     outcome: One of `"successful"`, `"rejected"`,
    ///         `"withdrawn"`.
    ///
    /// Raises:
    ///     ValueError: If `outcome` is not one of the three known
    ///         strings.
    fn record_outcome(&self, event_id: &str, requester_id: &str, outcome: &str) -> PyResult<()> {
        let parsed = match outcome {
            "successful" => FilingOutcome::Successful,
            "rejected" | "withdrawn" => FilingOutcome::Rejected,
            other => {
                return Err(PyValueError::new_err(format!(
                    "outcome must be 'successful', 'rejected', or 'withdrawn', got {other:?}"
                )));
            }
        };
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PyRuntimeError::new_err("ReconsiderDosGuard mutex poisoned"))?;
        guard.record_outcome(event_id, requester_id, parsed);
        Ok(())
    }

    /// A constant `"ReconsiderDosGuard()"`. Deliberately reports NOTHING about
    /// the guard's state: it never takes the lock, so it cannot deadlock when
    /// called from inside a panic, and it cannot leak filing contents.
    fn __repr__(&self) -> String {
        // Don't lock for repr — the guard's internal HashMaps don't
        // expose a public count surface anyway, and we'd rather not
        // deadlock if repr is called from within a panic.
        "ReconsiderDosGuard()".to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR_MS: u64 = 60 * 60 * 1000;
    const T0: u64 = 1_700_000_000_000;

    /// Two filings against the SAME event from different actors
    /// against different victims should both admit (no harassment
    /// cluster, no per-event rate-limit hit at default cap=10, no
    /// per-actor budget hit at default cap=30). The third filing
    /// from one actor against the same victim trips the harassment
    /// cluster threshold (default 2.0).
    #[test]
    fn admit_filing_rejects_on_harassment_cluster() {
        let g = PyReconsiderDosGuard::new();

        let d1 = g.admit_filing("evt-A", "alice", "bob", T0).unwrap();
        let v1: serde_json::Value = serde_json::from_str(&d1).unwrap();
        assert_eq!(v1["admitted"], serde_json::Value::Bool(true));

        let d2 = g
            .admit_filing("evt-B", "alice", "bob", T0 + HOUR_MS)
            .unwrap();
        let v2: serde_json::Value = serde_json::from_str(&d2).unwrap();
        assert_eq!(v2["admitted"], serde_json::Value::Bool(true));

        // Third — harassment cluster fires.
        let d3 = g
            .admit_filing("evt-C", "alice", "bob", T0 + 2 * HOUR_MS)
            .unwrap();
        let v3: serde_json::Value = serde_json::from_str(&d3).unwrap();
        assert_eq!(v3["admitted"], serde_json::Value::Bool(false));
        assert!(v3["rejection"]
            .as_object()
            .map(|o| o.contains_key("HarassmentClusterDetected"))
            .unwrap_or(false));
    }

    /// Default per-event rate limit is 10. The 11th distinct filer
    /// against the same event hits `EventRateLimited`.
    #[test]
    fn admit_filing_rejects_on_event_rate_limit() {
        let g = PyReconsiderDosGuard::new();
        // 10 distinct filers against one event, each against a
        // different victim (so harassment cluster doesn't fire).
        for i in 0..10u64 {
            let actor = format!("filer-{i}");
            let target = format!("victim-{i}");
            let out = g
                .admit_filing("evt-X", &actor, &target, T0 + i * 1000)
                .unwrap();
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(
                v["admitted"],
                serde_json::Value::Bool(true),
                "iteration {i} should admit"
            );
        }
        // 11th filer — rate limit fires.
        let out = g
            .admit_filing("evt-X", "filer-11", "victim-11", T0 + 100_000)
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["admitted"], serde_json::Value::Bool(false));
        assert!(v["rejection"]
            .as_object()
            .map(|o| o.contains_key("EventRateLimited"))
            .unwrap_or(false));
    }

    /// `record_outcome("successful", ...)` refills one budget slot,
    /// re-admitting a previously budget-exhausted actor. Smoke-tests
    /// the str→FilingOutcome mapping for the successful path.
    #[test]
    fn record_outcome_successful_refills_budget() {
        let g = PyReconsiderDosGuard::new();
        // Burn the full default budget (30) with fresh targets and
        // events so harassment + rate-limit don't fire first.
        for i in 0..30u64 {
            let evt = format!("event-{i}");
            let tgt = format!("target-{i}");
            let out = g
                .admit_filing(&evt, "high-vol", &tgt, T0 + i * 1000)
                .unwrap();
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(v["admitted"], serde_json::Value::Bool(true));
        }
        // 31st — actor budget exhausted.
        let out = g
            .admit_filing("event-next", "high-vol", "target-next", T0 + 100_000)
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["admitted"], serde_json::Value::Bool(false));
        assert!(v["rejection"]
            .as_object()
            .map(|o| o.contains_key("ActorBudgetExhausted"))
            .unwrap_or(false));

        // Record a successful outcome — budget refills by one.
        g.record_outcome("event-0", "high-vol", "successful")
            .unwrap();
        let out = g
            .admit_filing("event-next-2", "high-vol", "target-next-2", T0 + 200_000)
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["admitted"], serde_json::Value::Bool(true));
    }

    /// `record_outcome` rejects unknown outcome strings (PyValueError).
    /// PyErr content isn't introspectable from `cargo test` without
    /// a Python interpreter in PyO3 0.28+; message-text checks happen
    /// at the Python-pytest layer.
    #[test]
    fn record_outcome_invalid_string_rejected() {
        let g = PyReconsiderDosGuard::new();
        let _err = g
            .record_outcome("evt", "alice", "nonsense")
            .expect_err("should reject unknown outcome");
    }

    /// `__repr__` is constant — no lock acquisition required.
    #[test]
    fn repr_is_stable() {
        let g = PyReconsiderDosGuard::new();
        assert_eq!(g.__repr__(), "ReconsiderDosGuard()");
    }
}
