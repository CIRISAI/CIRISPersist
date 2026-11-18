//! v53.0.0 (CC 4.2.6 / CC 3.2 T6) — **the accord's roster change**, the
//! door's third shape. I450e–I450h.
//!
//! - **I450e** the local door: a version adding a holder is admitted under a
//!   strict majority of the STANDING roster, covering one authorized, closed
//!   decision binding exactly that change, signed by the added holder, naming
//!   a re-scrubbed charter that commits the new holder's recovery key. Each
//!   leg missing refuses by name; the admitted version moves the head, clears
//!   the decision's lag, and its roster is the fold's.
//! - **I450f** replicated: a peer judges the same predicate — it refuses the
//!   version while it holds no decision, and admits it once the decision is
//!   held.
//! - **I450g** a removal: the charter must drop the removed holder (a charter
//!   still committing them is a stray at the version), then it is admitted.
//! - **I450j** a seat goes only to an `accord_holder` key record (both the
//!   roster change and the recovery door).
//! - **I450i** deleted in v62.0.0 (json-cut C5) with the bundle/1 ceremony
//!   verifier it read from disk.
//! - **I450h** the standing roster is the HELD head's: cosigns from the holder
//!   being added do not count toward the majority.
//! - **I509** (v53.1.2, CIRISPersist#984 row 3) a recovery's exception
//!   expires with its charter: a version naming a new charter must commit the
//!   holder a recovery seated under the old one.
//! - **I510** (#984 row 5) the charter a version names must be a LIVE charter
//!   row: a withdrawn one is `accord_charter_not_held`.
//! - **I511** (#984 row 6) a roster listing a seat twice is refused by name.
//!
//! v62.0.0 (JSON cut, wave 3, E5) — **every witness here is deleted** (lead's
//! ruling 1: the accord's earlier-form planes do not come back). The accord's
//! roster, charter, decision and recovery are genesis bundle/2: a roster change
//! is a later bundle counted at the holders' strict majority, a recovery is a
//! recovery bundle. Covered by C1/C2's bundle witnesses: I450e/f/g/h/j and
//! I511 → I2315 (`later_minority` → `genesis_bundle_count_unmet`), I2316
//! (`later_valid` becomes head), I2333 (a later bundle counts a strict
//! majority), I2334 (every accepted holder seed has a custody chain);
//! I509/I510 (recovery commitments) → I2319, I2339, I2340, I2341; I450i (the
//! bundle coverage rule from disk) → I2338 / C1's door (I2310–I2320).
