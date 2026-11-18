//! The accord's halt and invocation door (v62.0.0, JSON-cut slice A; CC
//! 4.2.1.1, CC 4.2.1.3, CC 4.2.6).
//!
//! An invocation (`accord:invoke:{constitutional,notify,drill}:…`) is ONE
//! row with ONE composite statement from a SINGLE accord holder: no count.
//! Its signer is judged against the holders of the genesis bundle in force
//! for its `accord_root` ([`HaltRoster`]); the halt names no head.
//!
//! v62.0.0 (slice C3) — the reader is CIRISVerify 23.3.0's
//! `edition2::accord_halt` ([`verify_invocation_row`]), re-exported here with
//! its types; persist keeps only the store door around it. It answers in
//! three ways ([`HaltReading`], `#[must_use]`):
//! - `valid`;
//! - `waiting:{kid,bundle,kid+bundle}`: the statement's key is not one the
//!   roster holds (a later bundle may seat it). A halt is never refused while
//!   the roster that would judge it is unknown;
//! - `refused:{token}` ([`HaltRefusal`]): `iss_not_holder` (the key is a
//!   holder's, but `iss` is not that holder), `statement_invalid:*`,
//!   `family:*`, `member:*`, `wrong_row_type`, `wrong_family`,
//!   `other_accord`, `valid_until_not_after_asserted_at`.
//!
//! With no bundle in force held for the accord, [`put_invocation`] waits on
//! the bundle itself, before any reading (Verify's reader takes a roster).
//!
//! [`put_invocation`] is the store door: a valid invocation is deduplicated
//! (`accord_invocation_replayed`: an `invocation_id` or a `nonce` already
//! held for the accord within its `valid_until`), kept in `ceg_statements`,
//! and a constitutional halt latches the accord's active halt.
//!
//! Not here: the counted lifecycle rows (`confirmed`, `active`; Verify's
//! `verify_lifecycle_row`) and the fuse (`HaltLatch::apply_forward`).
//! TODO(cut-a-halt-lifecycle).

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::identity_ref;

pub use ciris_verify_core::edition2::accord_halt::{
    named_accord_root, verify_invocation_row, HaltReading, HaltRefusal, HaltRoster, HaltWaiting,
    InvocationRow, InvokeKind, RosterHolder, ACCORD_ROW_TYPE, FAMILY_CONSTITUTIONAL, FAMILY_DRILL,
    FAMILY_NOTIFY,
};

use super::door::AdmittedRow;
use super::liveness::statement_parts;
use super::names::RowId;
use crate::federation::{malformed_row, Error, FederationDirectory};

/// The plane name the halt door's refusals carry.
pub const PLANE: &str = "accord_halt";
/// The `typ` a waiting halt names when it waits on the accord's bundle.
const GENESIS_BUNDLE_TYP: &str = "ceg-genesis-bundle/2";
/// The three invocation families.
pub const INVOCATION_FAMILIES: [&str; 3] = [FAMILY_CONSTITUTIONAL, FAMILY_NOTIFY, FAMILY_DRILL];

/// Is `statement` of an invocation family (by its header, unverified)?
#[must_use]
pub fn is_invocation(statement: &[u8]) -> bool {
    statement_parts(statement).is_some_and(|(h, _)| {
        h.get_int(-70002)
            .and_then(Value::as_text)
            .is_some_and(|f| InvokeKind::from_family(f).is_some())
    })
}

/// The roster of the genesis bundle in force for `accord_root`, if held:
/// the holders Verify's bundle reader places, each at its placed key
/// ([`super::genesis::GenesisInForce::halt_roster`]). `None` with no bundle
/// held, on a fork of the genesis, or when the accord in force is another:
/// every invocation at the store door then waits on its bundle.
///
/// # Errors
/// Directory read failures.
pub async fn roster_in_force<F>(dir: &F, accord_root: &str) -> Result<Option<HaltRoster>, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(super::genesis::genesis_in_force(dir)
        .await?
        .halt_roster(accord_root))
}

/// What [`put_invocation`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationOutcome {
    /// The invocation.
    pub invocation: InvocationRow,
    /// Was the statement new here.
    pub new: bool,
    /// Did it latch the accord's active halt (a constitutional halt).
    pub latched: bool,
}

/// The retryable error of a waiting reading, naming the first key the
/// roster does not hold, else the bundle it waits on.
fn waiting_error(w: &HaltWaiting) -> Error {
    let named = w.kids.first().map_or_else(
        || {
            w.bundles.first().map_or_else(
                || GENESIS_BUNDLE_TYP.to_owned(),
                |b| format!("{GENESIS_BUNDLE_TYP}:{}", hex::encode(b)),
            )
        },
        identity_ref,
    );
    Error::unknown_signer(&named, PLANE)
}

/// The terminal error of a refused reading: `iss_not_holder` by that name,
/// every other refusal `accord_invocation_invalid` with the reader's token.
fn refusal_error(r: &HaltRefusal) -> Error {
    match r {
        HaltRefusal::IssNotHolder => Error::malformed_row(
            PLANE,
            malformed_row::ISS_NOT_HOLDER,
            "the statement's key is an accord holder's, but its iss is not that holder \
             (CC 4.2.1.1)",
        ),
        other => Error::malformed_row(
            PLANE,
            malformed_row::ACCORD_INVOCATION_INVALID,
            format!("refused:{}", other.token()),
        ),
    }
}

/// Is a held invocation statement a replay of `inv`: another row of the
/// same accord naming the same `invocation_id` or `nonce`, still within its
/// own `valid_until` at `inv`'s instant?
fn replays(held: &[u8], inv: &InvocationRow) -> bool {
    let Some((_, p)) = statement_parts(held) else {
        return false;
    };
    if RowId::of_statement(held).is_some_and(|r| r.0 == *inv.row_id()) {
        return false;
    }
    let same_id = p.get_text("invocation_id").and_then(Value::as_text) == Some(inv.invocation_id());
    let same_nonce = p.get_text("nonce").and_then(Value::as_bytes) == Some(&inv.nonce()[..]);
    let live = p
        .get_text("valid_until")
        .and_then(Value::as_u64)
        .is_some_and(|u| inv.asserted_at() < u);
    (same_id || same_nonce) && live
}

/// **The invocation store door.** `roster` is the bundle in force for the
/// statement's accord ([`roster_in_force`]); `None` waits on that bundle.
///
/// - a waiting reading is the retryable `federation_attester_key_unknown`,
///   naming the key or the bundle;
/// - `iss_not_holder` is refused by that name; every other refusal is
///   `accord_invocation_invalid` with the reader's token;
/// - an invocation whose `invocation_id` or `nonce` a held invocation of the
///   same accord already carries, within that one's `valid_until`, is
///   refused `accord_invocation_replayed`;
/// - a valid invocation is kept in `ceg_statements`; a constitutional halt
///   latches the accord's active halt (`set_active_halt(accord_root, row
///   id)`): ONE holder's statement, no count.
///
/// # Errors
/// As above; directory failures.
pub async fn put_invocation<F>(
    dir: &F,
    bytes: &[u8],
    roster: Option<&HaltRoster>,
) -> Result<InvocationOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    super::door::require_statement_form(bytes)?;
    let Some(roster) = roster else {
        // No bundle in force is held for the accord: wait on it.
        return Err(Error::unknown_signer(
            &format!(
                "{GENESIS_BUNDLE_TYP}:{}",
                named_accord_root(bytes).unwrap_or_default()
            ),
            PLANE,
        ));
    };
    let inv = match verify_invocation_row(bytes, roster) {
        HaltReading::Valid(inv) => inv,
        HaltReading::Waiting(w) => return Err(waiting_error(&w)),
        HaltReading::Refused(r) => return Err(refusal_error(&r)),
    };
    let accord_root = roster.accord_root();
    for family in INVOCATION_FAMILIES {
        for held in dir.edition2_statements_about(family, accord_root).await? {
            if replays(&held, &inv) {
                return Err(Error::malformed_row(
                    PLANE,
                    malformed_row::ACCORD_INVOCATION_REPLAYED,
                    format!(
                        "invocation {} (row {}) repeats the invocation_id or nonce of a held \
                         invocation of {accord_root} still within its valid_until (CC 4.2.1.1)",
                        inv.invocation_id(),
                        hex::encode(inv.row_id()),
                    ),
                ));
            }
        }
    }
    let admitted: AdmittedRow =
        super::door::admit_row(bytes, roster, None, SelectContext::default())?;
    let new = dir.put_edition2_statement(&admitted).await?;
    let latched = inv.kind() == InvokeKind::Constitutional;
    if latched {
        dir.set_active_halt(accord_root, &hex::encode(inv.row_id()))
            .await?;
    }
    Ok(InvocationOutcome {
        invocation: inv,
        new,
        latched,
    })
}
