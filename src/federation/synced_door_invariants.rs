//! v62.0.0 (JSON-cut slice E4) — **I189 retired.** The attributed sync door
//! (`put_attestation_synced`, CIRISPersist#917) and its unattributed twin
//! (`apply_replicated_attestation`) take earlier-form JSON rows and are shut
//! by the cut; their witnesses asserted earlier-form behaviour and were
//! deleted, not rewritten:
//!
//! - a decoration-only re-delivery (the same signed envelope re-signed, a
//!   later `scrub_timestamp`) and a rival signed row under a peer-chosen id
//!   cannot exist for an edition-2 statement: its row id is computed over its
//!   own bytes, so a re-delivery is the same statement (`Unchanged`) and a
//!   different statement is a different row;
//! - the capsule arm drove the same JSON door.
//!
//! The replicated statement door's outcomes are
//! `edition2::ingest::apply_replicated_statement`'s
//! (`ReplicatedStatementOutcome`). GAP for the synthesis lane: the per-peer
//! metering arm (`shares_cohort_with(peer)`, `Error::RateLimited`, nothing
//! stored) has no edition-2 witness yet; it also needs the community plane
//! (`group:roster` typed projection) to seat the cohort. The module stays
//! empty so the `mod` line in `federation/mod.rs` needs no foreign hunk.
