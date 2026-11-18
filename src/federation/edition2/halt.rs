//! The accord's halt and invocation door (v62.0.0, JSON-cut slice A; CC
//! 4.2.1.1, CC 4.2.1.3, CC 4.2.6).
//!
//! An invocation (`accord:invoke:{constitutional,notify,drill}:…`) is ONE
//! row with ONE composite statement from a SINGLE accord holder: no count.
//! Its signer is judged against the holders of the genesis bundle in force
//! for its `accord_root` ([`HaltRoster`]); the halt names no head.
//!
//! [`read_invocation`] answers in three ways ([`HaltReading`]), with the
//! tokens CIRISVerify 23.3.0's halt reader uses:
//! - `valid`;
//! - `waiting:{kid,bundle,kid+bundle}`: no bundle in force is held for the
//!   accord, or the statement's key is not one the roster holds. A halt is
//!   never refused while the roster that would judge it is unknown;
//! - `refused:{token}`: `iss_not_holder` (the key is a holder's, but `iss`
//!   is not that holder), `statement_invalid:*`, `family:*`, `member:*`,
//!   `wrong_row_type`, `wrong_family`, `other_accord`,
//!   `valid_until_not_after_asserted_at`.
//!
//! [`put_invocation`] is the store door: a valid invocation is deduplicated
//! (`accord_invocation_replayed`: an `invocation_id` or a `nonce` already
//! held for the accord within its `valid_until`), kept in `ceg_statements`,
//! and a constitutional halt latches the accord's active halt.
//!
//! TODO(verify-23.3-pin): at slice C's pin this reads Verify's
//! `edition2::accord_halt` reader (`HaltReading`), and replays
//! `accord_halt_v2.json`.

use ciris_crypto::composite::CompositePublicKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::family::{
    select::Act, verify_row_in_family_with, FamilyVerdict, SelectContext, VendoredFamilyModel,
};
use ciris_verify_core::edition2::{
    identity_ref, Digest32, KeyDirectory, KeyLookup, MissingKey, VerifiedRow,
};

use super::door::{invalid_label, AdmittedRow};
use super::liveness::{statement_parts, KeyOf, KeyOwnership};
use super::names::RowId;
use crate::federation::{malformed_row, Error, FederationDirectory};

/// The plane name the halt door's refusals carry.
pub const PLANE: &str = "accord_halt";
/// The row type of every accord row.
pub const ACCORD_ROW_TYPE: &str = "scores";
/// `accord:invoke:constitutional:{halt_id}`.
pub const FAMILY_CONSTITUTIONAL: &str = "accord:invoke:constitutional:.halt_id";
/// `accord:invoke:notify:{notify_id}`.
pub const FAMILY_NOTIFY: &str = "accord:invoke:notify:.notify_id";
/// `accord:invoke:drill:{drill_id}`.
pub const FAMILY_DRILL: &str = "accord:invoke:drill:.drill_id";
/// The three invocation families.
pub const INVOCATION_FAMILIES: [&str; 3] = [FAMILY_CONSTITUTIONAL, FAMILY_NOTIFY, FAMILY_DRILL];

const INVOCATION_MEMBERS: [&str; 7] = [
    "author",
    "accord_root",
    "invocation_id",
    "nonce",
    "asserted_at",
    "valid_until",
    "payload_digest",
];

/// Which invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvokeKind {
    /// The halt.
    Constitutional,
    /// A notification (carries `payload_digest`).
    Notify,
    /// A drill.
    Drill,
}

impl InvokeKind {
    /// The kind of a family id, if it is an invocation's.
    #[must_use]
    pub fn from_family(family: &str) -> Option<Self> {
        match family {
            FAMILY_CONSTITUTIONAL => Some(Self::Constitutional),
            FAMILY_NOTIFY => Some(Self::Notify),
            FAMILY_DRILL => Some(Self::Drill),
            _ => None,
        }
    }
}

/// The holders an invocation is judged against: those of the genesis bundle
/// in force for one accord, each with the key the bundle places for it.
#[derive(Clone, Debug)]
pub struct HaltRoster {
    accord_root: String,
    bundle: Digest32,
    holders: Vec<(String, Digest32, CompositePublicKey)>,
    halt_fuse_secs: Option<u32>,
}

impl HaltRoster {
    /// A roster from the bundle in force: its accord, its object id, each
    /// holder's identity-ref and placed key, and the charter's
    /// `halt_fuse_secs`.
    #[must_use]
    pub fn new(
        accord_root: impl Into<String>,
        bundle: Digest32,
        holders: impl IntoIterator<Item = (String, CompositePublicKey)>,
        halt_fuse_secs: Option<u32>,
    ) -> Self {
        let mut hs: Vec<(String, Digest32, CompositePublicKey)> = Vec::new();
        for (iss, key) in holders {
            if hs.iter().any(|(i, _, _)| *i == iss) {
                continue;
            }
            let kid = ciris_verify_core::edition2::thumbprint(&key);
            hs.push((iss, kid, key));
        }
        HaltRoster {
            accord_root: accord_root.into(),
            bundle,
            holders: hs,
            halt_fuse_secs,
        }
    }

    /// The accord's `family_key_id` (`accord_root`).
    #[must_use]
    pub fn accord_root(&self) -> &str {
        &self.accord_root
    }

    /// The bundle's object id.
    #[must_use]
    pub fn bundle(&self) -> &Digest32 {
        &self.bundle
    }

    /// The charter's `halt_fuse_secs`, where it states one.
    #[must_use]
    pub fn halt_fuse_secs(&self) -> Option<u32> {
        self.halt_fuse_secs
    }

    /// The holder whose placed key is `kid`.
    #[must_use]
    pub fn holder_of_kid(&self, kid: &Digest32) -> Option<&str> {
        self.holders
            .iter()
            .find(|(_, k, _)| k == kid)
            .map(|(i, _, _)| i.as_str())
    }
}

/// The roster is the whole key directory of an invocation: a key it does
/// not place waits (a later bundle may place it).
impl KeyDirectory for HaltRoster {
    fn lookup(&self, kid: &Digest32, _asserted_at: u64) -> KeyLookup {
        self.holders
            .iter()
            .find(|(_, k, _)| k == kid)
            .map_or(KeyLookup::NotHeld, |(_, _, key)| {
                KeyLookup::Held(Box::new(key.clone()))
            })
    }
}

/// A placed key is its holder's.
impl KeyOwnership for HaltRoster {
    fn key_of(&self, kid: &Digest32, iss: &Digest32) -> KeyOf {
        if self.holder_of_kid(kid) == Some(identity_ref(iss).as_str()) {
            KeyOf::Yes
        } else {
            KeyOf::No
        }
    }
}

/// What an invocation waits on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HaltWaiting {
    /// Keys the roster does not place.
    pub kids: Vec<Digest32>,
    /// Accords (`accord_root`) with no bundle in force held.
    pub bundles: Vec<String>,
}

/// The three answers of the halt reader (Verify 23.3.0's shape).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HaltReading<T> {
    /// Valid.
    Valid(T),
    /// Retryable: a key or a bundle is not held.
    Waiting(HaltWaiting),
    /// Final, with the reader's token.
    Refused(String),
}

impl<T> HaltReading<T> {
    /// The reading's token: `valid`, `waiting:{kid,bundle,kid+bundle}`,
    /// `refused:{token}`.
    #[must_use]
    pub fn token(&self) -> String {
        match self {
            Self::Valid(_) => "valid".into(),
            Self::Waiting(w) => match (w.kids.is_empty(), w.bundles.is_empty()) {
                (false, false) => "waiting:kid+bundle".into(),
                (false, true) => "waiting:kid".into(),
                _ => "waiting:bundle".into(),
            },
            Self::Refused(t) => format!("refused:{t}"),
        }
    }
}

/// A valid invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationRow {
    /// Which invocation.
    pub kind: InvokeKind,
    /// The row id.
    pub row_id: Digest32,
    /// The statement id.
    pub statement_id: Digest32,
    /// The holder (`author` = `iss`).
    pub author: String,
    /// The accord.
    pub accord_root: String,
    /// `invocation_id`.
    pub invocation_id: String,
    /// `nonce`, 32 bytes.
    pub nonce: [u8; 32],
    /// `asserted_at`, POSIX ms.
    pub asserted_at: u64,
    /// `valid_until`, POSIX ms, after `asserted_at`.
    pub valid_until: u64,
    /// `payload_digest`, on a notify only.
    pub payload_digest: Option<Digest32>,
}

/// The `accord_root` a statement names, read without verifying it: the key
/// for choosing the roster. The reader checks it again (`other_accord`).
#[must_use]
pub fn named_accord_root(statement: &[u8]) -> Option<String> {
    let (_, p) = statement_parts(statement)?;
    p.get_text("accord_root")?.as_text().map(str::to_owned)
}

/// Is `statement` of an invocation family (by its header, unverified)?
#[must_use]
pub fn is_invocation(statement: &[u8]) -> bool {
    statement_parts(statement).is_some_and(|(h, _)| {
        h.get_int(-70002)
            .and_then(Value::as_text)
            .is_some_and(|f| InvokeKind::from_family(f).is_some())
    })
}

fn member(m: &str) -> String {
    format!("member:{m}")
}

fn hash_digest(v: &Value) -> Option<Digest32> {
    match v.as_array()? {
        [alg, d] if alg.as_i64() == Some(-16) => d.as_bytes()?.try_into().ok(),
        _ => None,
    }
}

fn fault_label(f: &ciris_verify_core::edition2::family::FamilyFault) -> &'static str {
    use ciris_verify_core::edition2::family::FamilyFault as F;
    match f {
        F::UnregisteredFamily => "unregistered_family",
        F::AuthorColumn => "author_column",
        F::IssNotInRole => "iss_not_in_role",
        F::DimensionMissing => "dimension_missing",
        F::AuthorshipUndetermined => "authorship_undetermined",
        F::NoArmHolds => "no_arm_holds",
        _ => "other",
    }
}

/// One statement through the row reader, the family model and the roster.
fn read_statement(bytes: &[u8], roster: &HaltRoster) -> Result<VerifiedRow, HaltReading<()>> {
    let ctx = SelectContext {
        act: statement_parts(bytes).map(|(_, p)| {
            if p.get_text("author").is_some() {
                Act::Own
            } else {
                Act::Group
            }
        }),
        ..SelectContext::default()
    };
    let row = match verify_row_in_family_with(bytes, roster, &VendoredFamilyModel, &ctx) {
        FamilyVerdict::Valid { row, .. } => *row,
        FamilyVerdict::Invalid(i) => {
            return Err(HaltReading::Refused(format!(
                "statement_invalid:{}",
                invalid_label(&i)
            )))
        }
        FamilyVerdict::FamilyInvalid(f) => {
            return Err(HaltReading::Refused(format!("family:{}", fault_label(&f))))
        }
        FamilyVerdict::Waiting(missing) => {
            return Err(HaltReading::Waiting(HaltWaiting {
                kids: missing
                    .iter()
                    .filter_map(|m| match m {
                        MissingKey::Kid(k) => Some(*k),
                        _ => None,
                    })
                    .collect(),
                bundles: Vec::new(),
            }))
        }
    };
    if roster.holder_of_kid(&row.kid) != Some(row.iss.as_str()) {
        return Err(HaltReading::Refused("iss_not_holder".into()));
    }
    if row.row_type != ACCORD_ROW_TYPE {
        return Err(HaltReading::Refused("wrong_row_type".into()));
    }
    Ok(row)
}

/// **Read one invocation statement** against the roster of the bundle in
/// force for its accord (`None`: no bundle held, so it waits).
#[must_use]
pub fn read_invocation(bytes: &[u8], roster: Option<&HaltRoster>) -> HaltReading<InvocationRow> {
    let Some(roster) = roster else {
        return HaltReading::Waiting(HaltWaiting {
            kids: Vec::new(),
            bundles: vec![named_accord_root(bytes).unwrap_or_default()],
        });
    };
    let row = match read_statement(bytes, roster) {
        Ok(r) => r,
        Err(HaltReading::Waiting(w)) => return HaltReading::Waiting(w),
        Err(HaltReading::Refused(t)) => return HaltReading::Refused(t),
        Err(HaltReading::Valid(())) => unreachable!("read_statement never errs Valid"),
    };
    match invocation_of(&row, roster) {
        Ok(inv) => HaltReading::Valid(inv),
        Err(t) => HaltReading::Refused(t),
    }
}

fn invocation_of(row: &VerifiedRow, roster: &HaltRoster) -> Result<InvocationRow, String> {
    let kind = InvokeKind::from_family(&row.family).ok_or_else(|| "wrong_family".to_owned())?;
    let p = &row.payload;
    let m = p.as_map().ok_or_else(|| member("payload"))?;
    if m.iter()
        .any(|(k, _)| !k.as_text().is_some_and(|n| INVOCATION_MEMBERS.contains(&n)))
    {
        return Err(member("closed_map"));
    }
    let author = row.author.clone().ok_or_else(|| member("author"))?;
    let text = |k: &str| {
        p.get_text(k)
            .and_then(Value::as_text)
            .map(str::to_owned)
            .ok_or_else(|| member(k))
    };
    let accord_root = text("accord_root")?;
    if accord_root != roster.accord_root {
        return Err("other_accord".into());
    }
    let invocation_id = text("invocation_id")?;
    let nonce = p
        .get_text("nonce")
        .and_then(Value::as_bytes)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| member("nonce"))?;
    if row.sub != roster.accord_root {
        return Err(member("sub"));
    }
    let valid_until = p
        .get_text("valid_until")
        .and_then(Value::as_u64)
        .ok_or_else(|| member("valid_until"))?;
    if valid_until <= row.asserted_at {
        return Err("valid_until_not_after_asserted_at".into());
    }
    let payload_digest = match (kind, p.get_text("payload_digest")) {
        (InvokeKind::Notify, Some(d)) => {
            Some(hash_digest(d).ok_or_else(|| member("payload_digest"))?)
        }
        (InvokeKind::Notify, None) | (_, Some(_)) => return Err(member("payload_digest")),
        (_, None) => None,
    };
    Ok(InvocationRow {
        kind,
        row_id: row.row_id,
        statement_id: row.statement_id,
        author,
        accord_root,
        invocation_id,
        nonce,
        asserted_at: row.asserted_at,
        valid_until,
        payload_digest,
    })
}

/// The roster of the genesis bundle in force for `accord_root`, if held.
///
/// TODO(verify-bundle-reader): the bundle's placement (its holders and the
/// key it places for each) is Verify's bundle reader's; until slice C
/// adopts it, no roster is held and every invocation at the store door
/// waits on its bundle.
///
/// # Errors
/// Directory read failures.
pub async fn roster_in_force<F>(dir: &F, accord_root: &str) -> Result<Option<HaltRoster>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let _ = (dir, accord_root);
    Ok(None)
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

/// The error of a reading that is not valid.
fn reading_error(r: &HaltReading<InvocationRow>) -> Error {
    match r {
        HaltReading::Valid(_) => unreachable!("a valid reading is no error"),
        HaltReading::Waiting(w) => {
            let named = w.kids.first().map_or_else(
                || format!("ceg-genesis-bundle/2:{}", w.bundles.join(",")),
                identity_ref,
            );
            Error::unknown_signer(&named, PLANE)
        }
        HaltReading::Refused(t) if t == "iss_not_holder" => Error::malformed_row(
            PLANE,
            malformed_row::ISS_NOT_HOLDER,
            "the statement's key is an accord holder's, but its iss is not that holder \
             (CC 4.2.1.1)",
        ),
        HaltReading::Refused(t) => Error::malformed_row(
            PLANE,
            malformed_row::ACCORD_INVOCATION_INVALID,
            format!("refused:{t}"),
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
    if RowId::of_statement(held).is_some_and(|r| r.0 == inv.row_id) {
        return false;
    }
    let same_id = p.get_text("invocation_id").and_then(Value::as_text) == Some(&inv.invocation_id);
    let same_nonce = p.get_text("nonce").and_then(Value::as_bytes) == Some(&inv.nonce[..]);
    let live = p
        .get_text("valid_until")
        .and_then(Value::as_u64)
        .is_some_and(|u| inv.asserted_at < u);
    (same_id || same_nonce) && live
}

/// **The invocation store door.** `roster` is the bundle in force for the
/// statement's accord ([`roster_in_force`]); `None` waits.
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
    let reading = read_invocation(bytes, roster);
    let HaltReading::Valid(inv) = reading else {
        return Err(reading_error(&reading));
    };
    let Some(roster) = roster else {
        unreachable!("a valid reading has a roster");
    };
    for family in INVOCATION_FAMILIES {
        for held in dir
            .edition2_statements_about(family, &inv.accord_root)
            .await?
        {
            if replays(&held, &inv) {
                return Err(Error::malformed_row(
                    PLANE,
                    malformed_row::ACCORD_INVOCATION_REPLAYED,
                    format!(
                        "invocation {} (row {}) repeats the invocation_id or nonce of a held \
                         invocation of {} still within its valid_until (CC 4.2.1.1)",
                        inv.invocation_id,
                        hex::encode(inv.row_id),
                        inv.accord_root
                    ),
                ));
            }
        }
    }
    let admitted: AdmittedRow =
        super::door::admit_row(bytes, roster, None, SelectContext::default())?;
    let new = dir.put_edition2_statement(&admitted).await?;
    let latched = inv.kind == InvokeKind::Constitutional;
    if latched {
        dir.set_active_halt(&inv.accord_root, &hex::encode(inv.row_id))
            .await?;
    }
    Ok(InvocationOutcome {
        invocation: inv,
        new,
        latched,
    })
}
