//! `SequenceService` trait surface (v1.7.1, CIRISPersist#83).
//!
//! 2 methods. Same `impl Future<...> + Send` GAT pattern as the
//! rest of the v0.8.x / v1.x substrate traits.

use std::future::Future;

use super::Error;

/// Atomic per-identity monotonic sequence substrate trait.
///
/// Backs the CIRIS 3.0 one-key cohabitation model: a CIRIS runtime
/// holds one Ed25519 identity and every in-process consumer + every
/// agent occurrence signs with it. Anything emitting ordered signed
/// output needs a counter atomic across all of them; this trait is
/// that counter.
pub trait SequenceService: Send + Sync {
    /// Atomically bump and return the next monotonic value for
    /// `(identity, stream)`. First call for a pair returns 1, then
    /// 2, 3, … Durable, monotonic, correct under concurrent
    /// callers.
    fn next_sequence(
        &self,
        identity: &str,
        stream: &str,
    ) -> impl Future<Output = Result<u64, Error>> + Send;

    /// Read the last-issued value WITHOUT bumping. Returns 0 if the
    /// `(identity, stream)` pair has never been issued.
    fn peek_sequence(
        &self,
        identity: &str,
        stream: &str,
    ) -> impl Future<Output = Result<u64, Error>> + Send;
}
