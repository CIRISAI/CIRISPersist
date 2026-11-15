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
//!
//! Every answer carries the rows it rests on and the rule that gave it
//! ([`Answer`], KERNEL_SEAMS §5.3's `Answer`, its `rows` and `rule`; the
//! read set, `valid_until` and the digest are the next slice's).

pub mod consensus;
pub mod head;
pub mod law;
pub mod owner;
pub mod trust;
pub mod view;

/// What the kernel answered, and what it read (KERNEL_SEAMS §5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer<T> {
    /// The answer.
    pub value: T,
    /// The rows the value rests on.
    pub rows: Vec<view::RowId>,
    /// The kernel rule that gave it.
    pub rule: &'static str,
}
