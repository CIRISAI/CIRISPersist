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

/// The per-backend hook table. Default: nothing armed, no behaviour change.
#[derive(Default)]
pub(crate) struct TestHooks {
    /// Method name → how many more calls fail with a generic backend error.
    fail: Mutex<BTreeMap<&'static str, u32>>,
    /// A community record the backend applies to ITSELF through the
    /// replicated door at the start of its next community write, before that
    /// write's own gates and reads — a rival that won the race.
    rival_community_write: Mutex<Option<crate::federation::SignedCommunity>>,
}

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

    /// Arm a rival write: the next community write applies `rival` first.
    pub(crate) fn arm_rival_community_write(&self, rival: crate::federation::SignedCommunity) {
        *self.rival_community_write.lock().expect("test hooks") = Some(rival);
    }

    /// Taken (once) by the backend at the start of a community write.
    pub(crate) fn take_rival_community_write(&self) -> Option<crate::federation::SignedCommunity> {
        self.rival_community_write
            .lock()
            .expect("test hooks")
            .take()
    }
}
