//! v62.0.0 (slice C) — **a group's head, as entries**: the held version and
//! an offered one, as the kernel's `head::Entry` rows (kind `Seat`: a roster
//! version names the versions it extends).
//!
//! CC 2.7.8: "Two versions of one head wait as tips. The roster is then the
//! members common to all tips, until a version naming the tips makes one head
//! again." Persist's `held_head_verdict` refuses an offered version that does
//! not name the held head; the kernel holds it, as a tip beside the held head
//! (it names a version this node holds) or as a row waiting for the head it
//! names. This slice WITNESSES that departure ([`super::differential`]); the
//! switch to forks-as-tips is the next slice's (I1837).
//!
//! What stays persist's: a `supersede_proof` that names another prior is a
//! contradiction inside one row, refused for its shape before the kernel.

use super::view::{Micros, RowId};
use ciris_kernel::head::{Entry, Kind};
use ciris_kernel::Row;

/// A head entry with the [`Row`] view the kernel's graph reads.
#[derive(Clone, Debug)]
pub struct HeadRow(pub Entry<RowId, String, Micros>);

impl Row for HeadRow {
    type Id = RowId;
    type Key = String;
    fn id(&self) -> &RowId {
        &self.0.id
    }
    fn names(&self) -> &[RowId] {
        &self.0.names
    }
    fn signer(&self) -> &String {
        &self.0.signer
    }
}

/// What the kernel reads of an offered version against the held head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadReading {
    /// No head is held: nothing for the version to extend in place.
    NothingHeld,
    /// The version names the held head: one head again, the version.
    Extends,
    /// The version names another version: two tips (or a row waiting for
    /// the head it names). Held, never refused (CC 2.7.8).
    Tip,
}

/// The entries of the held head and the offered version. An empty
/// `prev_head_digest` (a lineage's first version) names nothing.
#[must_use]
pub fn head_entries(
    group: &str,
    held: &str,
    offered_prev: &str,
    offered_signer: &str,
) -> [HeadRow; 2] {
    let h = Entry::new(
        RowId::of_hash(held),
        Kind::Seat,
        group.to_owned(),
        Vec::new(),
    );
    let names = if offered_prev.is_empty() {
        Vec::new()
    } else {
        vec![RowId::of_hash(offered_prev)]
    };
    let v = Entry::new(
        RowId::of_label(&["offered-version", group, offered_prev]),
        Kind::Seat,
        offered_signer.to_owned(),
        names,
    );
    [HeadRow(h), HeadRow(v)]
}

/// **The kernel's reading of a supersede**: the frontier of the two
/// versions is one head (the version extends the held head) or two tips.
#[must_use]
pub fn head_reading(
    group: &str,
    held: Option<&str>,
    offered_prev: &str,
    offered_signer: &str,
) -> HeadReading {
    let Some(held) = held else {
        return HeadReading::NothingHeld;
    };
    let rows = head_entries(group, held, offered_prev, offered_signer);
    let g = ciris_kernel::graph::Graph::new(rows.iter());
    match g.frontier(&[0, 1]).as_slice() {
        [one] if *one == 1 => HeadReading::Extends,
        _ => HeadReading::Tip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i1837_a_version_naming_the_held_head_extends_it_and_any_other_is_a_tip() {
        let h = "aa".repeat(32);
        let other = "bb".repeat(32);
        assert_eq!(head_reading("g", Some(&h), &h, "k"), HeadReading::Extends);
        assert_eq!(head_reading("g", Some(&h), &other, "k"), HeadReading::Tip);
        assert_eq!(head_reading("g", Some(&h), "", "k"), HeadReading::Tip);
        assert_eq!(head_reading("g", None, &h, "k"), HeadReading::NothingHeld);
    }
}
