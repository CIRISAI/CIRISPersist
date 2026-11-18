//! v62 (E3): the I1155 legacy occurrence-revocation carrier witnesses are
//! deleted.
//!
//! They exercised the earlier form end to end: a framed JSON revocation
//! signed with standalone hybrid signatures, its carrier row, hybrid
//! co-scrubs as the roster quorum, and the open's rehome of legacy framed
//! rows. Under the clean mesh nothing carries (the earlier store is deleted
//! at upgrade), and an edition-2 `identity:occurrence_revocation` row is
//! counted by its statements (the door and ingest witnesses in
//! `edition2::*_invariants`). The module stays empty until slice F removes
//! the legacy carrier and this file with it.
