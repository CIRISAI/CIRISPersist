//! v62 (E3): the I953 re-seal race witness is deleted.
//!
//! `reseal_attestation_v31` re-signs an earlier-form JSON envelope in place
//! (a new seal over canonical-at-rest bytes, a new `original_content_hash`).
//! An edition-2 row IS its statement: there is no re-seal of a held row, so
//! the race it guarded has no edition-2 counterpart. The module stays empty
//! until slice F removes the earlier-form re-seal door and this file with it.
