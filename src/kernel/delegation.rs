//! v62.0.0 (R2-delegation; CC 3.2 T2, Constitution 11-24 "CONSTITUTION RULED
//! THE DELEGATION ARM"; Kernel's answer, P/KERNEL-delegation-encoding.md) —
//! **the DELEGATION plane, through the kernel.** Does `key` hold `scope`
//! through a chain from the root's counted grant? Persist presents the rows
//! and `ciris_kernel::seat::Seats::stands` walks them. Persist has no walk of
//! its own for this question.
//!
//! The presentation, as Kernel gave it:
//! - the counted grant (the TOP): an Offer, `Conf::Group`, over the bundle's
//!   object, `to` the grantee, its scope, `sub()` where it carries
//!   sub-delegation; the grantee's acceptance an Accept row naming it;
//! - each `delegates_to` below it: an Offer, `Conf::Seat`, `under()` = the
//!   offer that seats the delegator, signer the delegator, `to` the delegate,
//!   the SAME object, its scope, `sub()` where it carries sub-delegation, and
//!   the delegate's own statement a cosignature;
//! - a withdrawal by an edge's own signer (or by a holder of its own
//!   acceptance) a Withdraw row naming it.
//!
//! What is persist's, not the kernel's (Kernel): the TERM of each edge (the
//! kernel reads only the seating offer's own instants, so persist drops an
//! edge whose term has ended before presenting it; everything below it then
//! falls with it); "inside the charter's scope at the top" (the counted
//! grant is presented only when `admission::root_grant_of` reads it, which
//! checks the charter); the depth cap, which persist sets
//! ([`DELEGATION_DEPTH`], the reader's cap, CC 4.1.1).
//!
//! Not covered by the crate (Kernel): a chain across two objects, and the tips
//! fold over a chain. Persist presents ONE object per top (the bundle its
//! counted grant names) and no counted act with a head below it, so neither
//! arises here.

use super::view::{KRow, NoCut, RowId, SeatFields};
use ciris_kernel::graph::Graph;
use ciris_kernel::layers::Concluded;
use ciris_kernel::seat::{Conf, Obj, Root, SeatKind, SeatLaw, Seats};
use std::collections::BTreeSet;

/// The reader's depth cap (CC 4.1.1: "Consumer policy MUST cap traversal
/// depth at 5 hops by default"): the kernel's `SeatLaw::depth`, links below
/// the root. The earlier scoped walk persist read (`admission::
/// scoped_delegation_reach_at`) capped at `MAX_WITHDRAWS_DELEGATION_DEPTH`
/// (16); this plane does not use it.
pub const DELEGATION_DEPTH: usize = crate::federation::topology::DEFAULT_DELEGATION_DEPTH;

/// The scope element that marks a grant as carrying sub-delegation (the
/// ruled form: an element of `scope`, never a member of its own).
pub const SUB_DELEGATION: &str = crate::federation::self_at_login::SCOPE_SUB_DELEGATION;

/// The top of a chain: the root's counted grant, as persist read it.
#[derive(Clone, Debug)]
pub struct Top {
    /// The grant's row id.
    pub id: RowId,
    /// The object every seat of the chain is over: the bundle the grant names.
    pub object: RowId,
    /// The grant's first voice (a holder).
    pub signer: String,
    /// The grantee.
    pub grantee: String,
    /// One scope the grant confers.
    pub scope: String,
    /// The grant carries sub-delegation.
    pub sub: bool,
    /// The grantee's acceptance (its row id), when held.
    pub acceptance: Option<RowId>,
}

/// One `delegates_to` below the top.
#[derive(Clone, Debug)]
pub struct Edge {
    /// Its row id.
    pub id: RowId,
    /// The delegator (its signer).
    pub delegator: String,
    /// The delegate.
    pub delegate: String,
    /// One scope it delegates.
    pub scope: String,
    /// It carries sub-delegation.
    pub sub: bool,
    /// The delegate's own statement over it is held (CC 2.6.1.9).
    pub voiced: bool,
}

/// A withdrawal of a presented row (the top, its acceptance or an edge) by
/// `by`.
#[derive(Clone, Debug)]
pub struct Withdrawal {
    /// Its row id.
    pub id: RowId,
    /// Who signed it.
    pub by: String,
    /// The row it withdraws.
    pub target: RowId,
}

/// The seat rows for one top and the edges below it. An edge is presented
/// once per offer that seats its delegator (its `under()`), so one row of
/// persist's can be several seat rows; each gets its own id. Bounded by
/// `depth + 1` levels, each (edge, under) pair once.
fn present(top: &Top, edges: &[Edge], withdrawals: &[Withdrawal], depth: usize) -> Vec<KRow> {
    let obj = Obj::Row(top.object);
    let mut rows = vec![
        KRow::new(top.id, Vec::new(), top.signer.clone()).with_seat(SeatFields {
            to: vec![top.grantee.clone()],
            scope: Some(top.scope.clone()),
            obj: Some(obj.clone()),
            conf: Some(Conf::Group),
            sub: top.sub,
            ..SeatFields::of(SeatKind::Offer)
        }),
    ];
    if let Some(a) = top.acceptance {
        rows.push(
            KRow::new(a, vec![top.id], top.grantee.clone()).with_seat(SeatFields {
                of: Some(top.id),
                ..SeatFields::of(SeatKind::Accept)
            }),
        );
    }
    // persist's row id → the seat rows presented for it
    let mut presented: Vec<(RowId, RowId)> = vec![(top.id, top.id)];
    let mut frontier: Vec<(RowId, String)> = vec![(top.id, top.grantee.clone())];
    let mut seen: BTreeSet<(RowId, RowId)> = BTreeSet::new();
    for _ in 0..=depth {
        let mut next = Vec::new();
        for (under, holder) in &frontier {
            for e in edges.iter().filter(|e| e.delegator == *holder) {
                if !seen.insert((e.id, *under)) {
                    continue;
                }
                let id = RowId::of_label(&[
                    "r2-delegation",
                    &hex::encode(e.id.0),
                    &hex::encode(under.0),
                ]);
                rows.push(
                    KRow::new(id, vec![*under], e.delegator.clone()).with_seat(SeatFields {
                        to: vec![e.delegate.clone()],
                        scope: Some(e.scope.clone()),
                        obj: Some(obj.clone()),
                        conf: Some(Conf::Seat),
                        under: Some(*under),
                        cosigners: if e.voiced {
                            vec![e.delegate.clone()]
                        } else {
                            Vec::new()
                        },
                        sub: e.sub,
                        ..SeatFields::of(SeatKind::Offer)
                    }),
                );
                presented.push((e.id, id));
                next.push((id, e.delegate.clone()));
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    for w in withdrawals {
        let targets: Vec<RowId> = if top.acceptance == Some(w.target) {
            vec![w.target]
        } else {
            presented
                .iter()
                .filter(|(of, _)| *of == w.target)
                .map(|(_, id)| *id)
                .collect()
        };
        for t in targets {
            let id = RowId::of_label(&[
                "r2-delegation-withdraw",
                &hex::encode(w.id.0),
                &hex::encode(t.0),
            ]);
            rows.push(KRow::new(id, vec![t], w.by.clone()).with_seat(SeatFields {
                target: Some(t),
                ..SeatFields::of(SeatKind::Withdraw)
            }));
        }
    }
    rows
}

/// **Does `key` hold `scope` through the chain from `top`?** Persist's rows
/// as seat rows (`present`), every row concluded (persist judged each before
/// presenting it), walked by `Seats::stands` at the depth cap `depth`, over
/// the top's object and rooted at the top's group.
#[must_use]
pub fn stands(
    top: &Top,
    edges: &[Edge],
    withdrawals: &[Withdrawal],
    key: &str,
    scope: &str,
    depth: usize,
) -> bool {
    let rows = present(top, edges, withdrawals, depth);
    let c = Concluded::with(Graph::new(rows.iter()), None);
    let law = SeatLaw {
        depth,
        ..SeatLaw::default()
    };
    let obj = Obj::Row(top.object);
    let root = Root::Group(obj.clone());
    Seats::new(&c, &law, &NoCut, None).stands(&key.to_owned(), scope, &obj, Some(&root))
}

/// Does a scope set carry sub-delegation (the ruled element)?
#[must_use]
pub fn carries_sub_delegation(scope: &[&str]) -> bool {
    scope.contains(&SUB_DELEGATION)
}

#[cfg(test)]
mod tests {
    //! **Kernel's nine probe lines** (P/KERNEL-delegation-encoding.md), one by
    //! one, through [`stands`]: I6421–I6429 (claimed). Pure.
    use super::*;

    fn id(n: u8) -> RowId {
        RowId::of_label(&["r2-delegation-probe", &n.to_string()])
    }
    const BUNDLE: u8 = 0;
    const H: &str = "holder";
    const A: &str = "a";
    const B: &str = "b";
    const C: &str = "c";
    const D: &str = "d";

    fn top() -> Top {
        Top {
            id: id(1),
            object: id(BUNDLE),
            signer: H.into(),
            grantee: A.into(),
            scope: "infra".into(),
            sub: true,
            acceptance: Some(id(2)),
        }
    }
    fn edge(n: u8, from: &str, to: &str, scope: &str, sub: bool) -> Edge {
        Edge {
            id: id(n),
            delegator: from.into(),
            delegate: to.into(),
            scope: scope.into(),
            sub,
            voiced: true,
        }
    }
    fn chain() -> Vec<Edge> {
        vec![
            edge(10, A, B, "infra:detect", true),
            edge(11, B, C, "infra:detect:x", false),
            edge(12, C, D, "infra:detect:x", false),
        ]
    }
    fn at(key: &str, scope: &str, edges: &[Edge], w: &[Withdrawal], depth: usize) -> bool {
        stands(&top(), edges, w, key, scope, depth)
    }

    /// I6421 (probe 1): A holds `infra` by the counted grant.
    #[test]
    fn i6421_the_grantee_holds_the_granted_scope() {
        assert!(at(A, "infra", &[], &[], DELEGATION_DEPTH));
    }

    /// I6422 (probe 2): B holds `infra:detect` by A's onward grant (A's grant
    /// carries sub-delegation); B does not hold the wider `infra`.
    #[test]
    fn i6422_a_delegate_holds_the_delegated_scope_and_no_wider() {
        let e = chain();
        assert!(at(B, "infra:detect", &e, &[], DELEGATION_DEPTH));
        assert!(!at(B, "infra", &e, &[], DELEGATION_DEPTH));
    }

    /// I6423 (probe 3): C holds `infra:detect:x` two hops down.
    #[test]
    fn i6423_two_hops_down() {
        assert!(at(C, "infra:detect:x", &chain(), &[], DELEGATION_DEPTH));
    }

    /// I6424 (probe 4): D, granted onward by C whose own grant carries no
    /// sub-delegation: no.
    #[test]
    fn i6424_no_onward_hop_without_sub_delegation() {
        assert!(!at(D, "infra:detect:x", &chain(), &[], DELEGATION_DEPTH));
    }

    /// I6425 (probe 5): B with no acceptance of its own (no voice on the edge
    /// to it): no.
    #[test]
    fn i6425_a_delegate_with_no_statement_of_its_own() {
        let mut e = chain();
        e[0].voiced = false;
        assert!(!at(B, "infra:detect", &e, &[], DELEGATION_DEPTH));
    }

    /// I6426 (probe 6): A grants a scope its own grant does not cover: no.
    #[test]
    fn i6426_no_amplification() {
        let e = vec![edge(13, A, B, "assure:age", true)];
        assert!(!at(B, "assure:age", &e, &[], DELEGATION_DEPTH));
    }

    /// I6427 (probe 7): the depth cap at 1, C two hops down: no (B, one hop,
    /// still holds).
    #[test]
    fn i6427_the_readers_depth_cap() {
        let e = chain();
        assert!(at(B, "infra:detect", &e, &[], 1));
        assert!(!at(C, "infra:detect:x", &e, &[], 1));
    }

    /// I6428 (probe 8): A withdraws its grant to B: B no, and C (whose seat
    /// hung under B's) no.
    #[test]
    fn i6428_a_withdrawn_edge_drops_everything_below() {
        let e = chain();
        let w = [Withdrawal {
            id: id(20),
            by: A.into(),
            target: id(10),
        }];
        assert!(!at(B, "infra:detect", &e, &w, DELEGATION_DEPTH));
        assert!(!at(C, "infra:detect:x", &e, &w, DELEGATION_DEPTH));
    }

    /// I6429 (probe 9): A withdraws its own acceptance of the counted grant:
    /// everything below falls.
    #[test]
    fn i6429_a_withdrawn_acceptance_drops_the_chain() {
        let e = chain();
        let w = [Withdrawal {
            id: id(21),
            by: A.into(),
            target: id(2),
        }];
        assert!(!at(A, "infra", &e, &w, DELEGATION_DEPTH));
        assert!(!at(B, "infra:detect", &e, &w, DELEGATION_DEPTH));
        assert!(!at(C, "infra:detect:x", &e, &w, DELEGATION_DEPTH));
    }
}
