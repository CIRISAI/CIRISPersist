//! v62.0.0 (slice C) — **the kernel adapter.** Persist's decisions answer
//! through `ciris-kernel` (CIRISKernel, `crates/ciris-kernel`): pure,
//! `no_std`, zero-dependency functions over an abstract row graph whose rules
//! the Constitution states and has modelled (CC 2.7 "The kernel";
//! `FSD/KERNEL_SEAMS.md` §5). Persist keeps storage, verification, encoding,
//! replication and effects (KERNEL_SEAMS §8): it reads the rows an answer
//! needs, presents each as a [`view::KRow`], and asks the kernel.
//!
//! | module | what it presents | kernel |
//! |---|---|---|
//! | [`view`] | a verified row: id = `persist_row_hash`, names, signer, and the seat / window / key-end readings | `Row`, `SeatRow`, `WindowRow`, `KeyEndRow`, a `CutSpec` |
//! | [`law`] | the tables, from the vendored policy files | `SeatLaw`, `WindowSpec` |
//! | [`consensus`] | a ballot as a founding version, its founders and the counted row | `seat::seat_rule` (`Conf::Group`) |
//! | [`owner`] | a node's owner bindings as offers of the `owner` seat over its key | `seat::Seats::holders` |
//! | [`trust`] | a user's acceptance edges | `derived::fold_default`, `trust::reaches` |
//! | [`head`] | a group's held head and an offered version | `head::Entry`, `graph::Graph::frontier` |
//! | [`content`] | one member's held rows in one room as Head / Content / End / Tips, the member's keys and the room's count, the held causal past | `content::answers`, `content::changed` |
//! | [`key_end`] | an edition-2 key's records and its own revocations | `key_end::KeyEndRow`, `well_formed`, `conclude_rule`, `live`, `ended` |
//!
//! Every answer carries the rows it rests on, the dependency keys it read
//! and the rule that gave it ([`Answer`], KERNEL_SEAMS §5.3's `Answer`: its
//! `rows`, `reads` and `rule`). v62.0.0 (kernel pass 2, I2810): the read set
//! is carried; `valid_until` and the digest are not yet.

pub mod consensus;
pub mod content;
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod content_invariants;
pub mod head;
pub mod key_end;
pub mod law;
pub mod owner;
pub mod trust;
pub mod view;

#[cfg(test)]
pub(crate) mod differential;

/// The differential's hooks where a from-disk gate scans the caller's body
/// (`store::parity`): a call that compiles to nothing outside a test build,
/// so the scanned body carries no `#[cfg(test)]` statement.
pub(crate) mod witness {
    /// [`super::differential::held_head`], in a test build.
    #[inline]
    #[allow(unused_variables)]
    pub(crate) fn held_head(
        group: &str,
        held: &str,
        offered_prev: &str,
        birth: bool,
        persist_ok: bool,
    ) {
        #[cfg(test)]
        super::differential::held_head(group, Some(held), offered_prev, true, birth, persist_ok);
    }
}

/// What the kernel answered, and what it read (KERNEL_SEAMS §5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer<T> {
    /// The answer.
    pub value: T,
    /// The rows the value rests on.
    pub rows: Vec<view::RowId>,
    /// v62.0.0 (kernel pass 2, I2810) — **the read set**: the dependency
    /// keys the answer read (KERNEL_SEAMS §5.4, "the light cone"). A row
    /// whose write set ([`DepKey`]s it can change) meets this set may change
    /// the answer; a row whose write set does not, cannot. Sorted, each key
    /// once ([`Answer::reading`]).
    pub reads: Vec<DepKey>,
    /// The kernel rule that gave it.
    pub rule: &'static str,
}

impl<T> Answer<T> {
    /// An answer over `rows`, having read `reads` (sorted and deduplicated
    /// here, so two answers that read the same keys carry the same set).
    #[must_use]
    pub fn reading(
        value: T,
        rows: Vec<view::RowId>,
        mut reads: Vec<DepKey>,
        rule: &'static str,
    ) -> Self {
        reads.sort();
        reads.dedup();
        Answer {
            value,
            rows,
            reads,
            rule,
        }
    }

    /// Whether a row that can change `writes` may change this answer: the
    /// write set meets the read set (KERNEL_SEAMS §5.4's invalidation test).
    #[must_use]
    pub fn read_any(&self, writes: &[DepKey]) -> bool {
        writes.iter().any(|w| self.reads.binary_search(w).is_ok())
    }
}

/// v62.0.0 (kernel pass 2, I2810) — **a dependency key** (KERNEL_SEAMS
/// §5.4): what an answer reads by, and what a row writes by. Persist's
/// keys are its own identifiers (a key id, a group key id, a row's
/// digest), carried as they are stored.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DepKey {
    /// One object's lifecycle: a row and what composes it.
    Object(view::RowId),
    /// The rows that cite a row (its composers, the versions naming it).
    Refs(view::RowId),
    /// A group's head, membership and protocol, by its group key id.
    Roster(String),
    /// A key's standing: the seats over it, the edges it signs or receives.
    Standing(String),
    /// A key's records and its own revocations (the key plane), by key id.
    Keys(String),
}
