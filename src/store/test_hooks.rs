//! v50.0.0 (PR #921 review, Codex) — test-only hooks INSIDE a backend, for
//! the two shapes a wrapping double cannot reach.
//!
//! [`crate::federation::directory_double::FaultInjectingDirectory`] wraps a
//! directory from the OUTSIDE, so it faults the calls a composition makes
//! through the trait object it was handed. A backend's own door calls
//! `self`: the gates `put_community_at_door` runs, and the write it ends in,
//! never pass through the double. Two review findings live exactly there:
//!
//! - a read that fails ONCE (a transient backend failure) inside a gate,
//!   while every later read succeeds — a persistent fault cannot witness it,
//!   because the later quorum fold rereads the same plane and fails too;
//! - a rival write that lands between what a door read and what it wrote.
//!
//! Both are armed by a test and consumed by the backend at a fixed point, and
//! both are compiled out of every non-test build.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Where in a community write a rival lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RivalPoint {
    /// The door's first line: after anything the caller read, before the
    /// door's gates and its occupied-id decision.
    DoorStart,
    /// After the occupied-id decision said "insert", before the insert.
    BeforeInsert,
    /// A community supersede's first line: after the proof was admitted
    /// against the version the route read, before the backend re-checks the
    /// prior under its write serialization.
    BeforeSupersede,
}

/// The per-backend hook table. Default: nothing armed, no behaviour change.
#[derive(Default)]
pub(crate) struct TestHooks {
    /// Method name → how many more calls fail with a generic backend error.
    fail: Mutex<BTreeMap<&'static str, u32>>,
    /// A community record the backend applies to ITSELF through the
    /// replicated door when its next community write reaches `RivalPoint` —
    /// a rival that won the race at exactly that point.
    rival_community_write: Mutex<Option<(RivalPoint, crate::federation::SignedCommunity)>>,
}

// The witnesses that arm these are cfg'd on a database feature; under the
// `server`-only axis the hooks are compiled but unarmed, and `-D warnings` must
// not read that as dead code (v50.0.0, the gate's server axis).
#[allow(dead_code)]
impl TestHooks {
    /// The next `times` calls of `method` fail.
    pub(crate) fn fail_next(&self, method: &'static str, times: u32) {
        self.fail.lock().expect("test hooks").insert(method, times);
    }

    /// Called by the backend at the top of `method`: `Err` while armed.
    pub(crate) fn fail_if_armed(
        &self,
        method: &'static str,
    ) -> Result<(), crate::federation::Error> {
        let mut fail = self.fail.lock().expect("test hooks");
        match fail.get_mut(method) {
            Some(n) if *n > 0 => {
                *n -= 1;
                Err(crate::federation::Error::Backend(format!(
                    "injected transient backend failure: {method}"
                )))
            }
            _ => Ok(()),
        }
    }

    /// Arm a rival write: when the next community write reaches `at`, the
    /// backend applies `rival` first.
    pub(crate) fn arm_rival_community_write(
        &self,
        at: RivalPoint,
        rival: crate::federation::SignedCommunity,
    ) {
        *self.rival_community_write.lock().expect("test hooks") = Some((at, rival));
    }

    /// Taken (once) by the backend at `at`: the rival armed for that point.
    pub(crate) fn take_rival_at(
        &self,
        at: RivalPoint,
    ) -> Option<crate::federation::SignedCommunity> {
        let mut armed = self.rival_community_write.lock().expect("test hooks");
        match armed.as_ref() {
            Some((p, _)) if *p == at => armed.take().map(|(_, r)| r),
            _ => None,
        }
    }
}
