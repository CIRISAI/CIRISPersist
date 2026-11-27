//! The row id and what a row names (CC 2.6.1.3), for the store and for the
//! kernel adapter.
//!
//! **Why this is its own module (the kernel name-cycle).** The kernel's
//! `Row::names()` walks the rows a row names. Before this slice the adapter
//! fed it `persist_row_hash` values and `references_attestation_id` strings, and
//! a peer could choose those strings: a row naming its own id, or two rows
//! naming each other, was a cycle the walk had to survive. Under edition 2
//! every id is node-computed. [`RowId::of_statement`] is SHA-256 over the
//! row's own bytes (CC 2.6.1.3), and a row's names are read from its signed
//! `refs` alone ([`names_of`]). A row cannot name its own row id: the id
//! hashes the payload, which holds the names, so a name equal to it would be
//! a SHA-256 preimage. A cycle of named rows needs the same, so the named
//! graph is acyclic by construction.
//!
//! For slice C's adapter: build `KRow::new(RowId(id.0), names, signer)` from
//! [`RowId`] and [`names_of`]'s ids. Never from a string a peer sent.
//! v62.0.0 (slice J0): `kernel::view::row_id` and `kernel::view::row_names`
//! do so for a row that carries its statement ([`of_statement_names`]).

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::{self, Digest32};

/// An edition-2 row id (or object id): 32 bytes this node computed from the
/// statement it holds. There is no constructor from a peer-chosen string.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RowId(pub Digest32);

impl std::fmt::Debug for RowId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RowId({})", hex::encode(&self.0[..6]))
    }
}

impl RowId {
    /// The row id of a row: SHA-256 over
    /// `CDE(["CEG-row/2", type, family, sub, author / null, payload])`
    /// (CC 2.6.1.3), with `payload` the bytes as signed.
    #[must_use]
    pub fn of_row(
        row_type: &str,
        family: &str,
        sub: &str,
        author: Option<&str>,
        payload: &[u8],
    ) -> Self {
        RowId(edition2::row_id(row_type, family, sub, author, payload))
    }

    /// v62.0.0 (slice J0) — the row id of a held row statement, computed from
    /// its own bytes: the header's row type and family, the CWT `sub`, the
    /// payload's `author`, and the payload as signed. `None` for bytes that
    /// are not a row statement. Nothing a peer states about the row is read.
    #[must_use]
    pub fn of_statement(statement: &[u8]) -> Option<Self> {
        let (protected, payload) = super::liveness::statement_parts(statement)?;
        let row_type = protected.get_int(-70001)?.as_text()?;
        let family = protected.get_int(-70002)?.as_text()?;
        let sub = protected.get_int(15)?.get_int(2)?.as_text()?;
        let author = payload.get_text("author").and_then(Value::as_text);
        let raw = super::door::raw_payload(statement)?;
        Some(Self::of_row(row_type, family, sub, author, &raw))
    }

    /// The object id of a signed object that is not a row (CC 2.6.1.11).
    #[must_use]
    pub fn of_object(typ: &str, author: Option<&str>, payload: &[u8]) -> Self {
        RowId(edition2::object_id(typ, author, payload))
    }

    /// The lowercase hex of the id (CC 2.6.3), as persist's columns that
    /// carry text spell it (`attestation_id`, `persist_row_hash`).
    #[must_use]
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// One name a row carries: the `refs` member it stands under and the row id
/// it names. `role` is the member path: `head`, `further_heads`, `prev`,
/// `answers`, `target`, `trusted_through`, `further_prev` (CONTENT-K2),
/// `also:ack`, `also:cites`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Name {
    /// The `refs` member path.
    pub role: String,
    /// The row id it names.
    pub row: RowId,
}

/// Why a `refs` member cannot be read as names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameError {
    /// A `row-ref` of edition 1 (`[1, [-16, name]]`): an earlier-form name.
    EditionOne {
        /// The `refs` member path.
        role: String,
    },
    /// A member that is not an edition-2 `row-ref` (or a set of them).
    Malformed {
        /// The `refs` member path.
        role: String,
    },
}

/// The edition of a `row-ref` and its digest: `[edition, [-16, digest]]`.
fn row_ref(v: &Value) -> Option<(u64, Digest32)> {
    match v.as_array()? {
        [ed, d] => {
            let ed = ed.as_u64()?;
            match d.as_array()? {
                [alg, b] if alg.as_i64() == Some(-16) => {
                    Some((ed, <[u8; 32]>::try_from(b.as_bytes()?).ok()?))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn push_ref(out: &mut Vec<Name>, role: &str, v: &Value) -> Result<(), NameError> {
    match row_ref(v) {
        Some((2, d)) => {
            out.push(Name {
                role: role.to_owned(),
                row: RowId(d),
            });
            Ok(())
        }
        Some((1, _)) => Err(NameError::EditionOne {
            role: role.to_owned(),
        }),
        _ => Err(NameError::Malformed {
            role: role.to_owned(),
        }),
    }
}

fn push_value(out: &mut Vec<Name>, role: &str, v: &Value) -> Result<(), NameError> {
    // A single row-ref, or a set of them. A set's first element is itself
    // an array whose first element is an array; a row-ref's first element
    // is an unsigned integer.
    match v.as_array() {
        Some([first, ..]) if first.as_array().is_some() => v
            .as_array()
            .into_iter()
            .flatten()
            .try_for_each(|r| push_ref(out, role, r)),
        _ => push_ref(out, role, v),
    }
}

/// The names a payload's `refs` carries, in `refs` order, edition 2 only.
/// A payload without `refs` names nothing.
///
/// # Errors
/// [`NameError::EditionOne`] for an edition-1 `row-ref` anywhere in `refs`
/// (CC 2.6.1.3); [`NameError::Malformed`] for a member that is no row-ref.
pub fn names_of(payload: &Value) -> Result<Vec<Name>, NameError> {
    let mut out = Vec::new();
    let Some(refs) = payload.get_text("refs") else {
        return Ok(out);
    };
    let Some(map) = refs.as_map() else {
        return Err(NameError::Malformed {
            role: "refs".into(),
        });
    };
    for (k, v) in map {
        let Some(member) = k.as_text() else {
            return Err(NameError::Malformed {
                role: "refs".into(),
            });
        };
        if member == "also" {
            let Some(roles) = v.as_map() else {
                return Err(NameError::Malformed {
                    role: "also".into(),
                });
            };
            for (r, set) in roles {
                let role = format!("also:{}", r.as_text().unwrap_or("?"));
                push_value(&mut out, &role, set)?;
            }
        } else {
            push_value(&mut out, member, v)?;
        }
    }
    Ok(out)
}

/// The row id a name of `role` carries, if the payload names exactly one
/// row under that member (`head`, `prev`, `target`, ...).
#[must_use]
pub fn single(names: &[Name], role: &str) -> Option<RowId> {
    let mut it = names.iter().filter(|n| n.role == role);
    let first = it.next()?;
    it.next().is_none().then_some(first.row)
}

/// v62.0.0 (slice J0) — a held row statement's node-computed id and the names
/// its signed `refs` carry, for the kernel adapter. `None` for bytes that are
/// not a row statement, or whose `refs` do not read.
#[must_use]
pub fn of_statement_names(statement: &[u8]) -> Option<(RowId, Vec<Name>)> {
    let id = RowId::of_statement(statement)?;
    let (_, payload) = super::liveness::statement_parts(statement)?;
    Some((id, names_of(&payload).ok()?))
}
