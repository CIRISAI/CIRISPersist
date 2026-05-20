//! Atomic per-identity monotonic sequence substrate wire types
//! (v1.7.1, CIRISPersist#83).
//!
//! The substrate's trait surface ([`super::SequenceService`])
//! exchanges plain `u64` counters keyed on borrowed `&str`
//! `(identity, stream)` pairs — there is no multi-column row type
//! to project across the FFI. The persisted row shape lives in
//! `cirislens.identity_sequences` (Postgres) /
//! `cirislens_identity_sequences` (SQLite); see V038.

#![allow(missing_docs)]
