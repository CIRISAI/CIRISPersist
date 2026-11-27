//! v62.0.0 (SEAT-1; CC 4.5.4 "What the five lines give", pre4) — **the
//! founding duty holders**: the `group:roster` member `duty_holders` and
//! the founding cases as ONE pure predicate.
//!
//! The text (part_4 l.1721, READ at `v1.0-rc22-pre4`): "A founding record
//! seats the duty holders it names, each by their own signature on it. …
//! The record names them in `duty_holders`, a map from a duty to the set of
//! members who hold it, each a listed member who signed the record. Every
//! duty the record declares has a holder there. A record one person signs
//! MAY name none, and that person then holds every declared duty. A record
//! several people sign that names none, or that leaves a declared duty
//! unheld, is refused. `duty_holders` stands on a community's first version
//! alone. No later version and no family's record carries it". The CDDL
//! (`family_payloads_v2.cddl`, `group-roster`): `? "duty_holders": { + tstr
//! => [+ identity-ref] }`, "A duty name (moderate, or one the record
//! declares in policy.duties)". FREEZE 753 (CC rc22 e02cd30): "AT FOUNDING
//! an agent named in duty_holders is admitted ONLY if its OWNER signed the
//! record, else refused; nodes refused"; CC 4.5.5 (part_4 l.1078): a `node`
//! key "cannot hold a judgment duty at all".
//!
//! The text names NO token for any of these refusals (pre4
//! `refusal_tokens.tsv`; P/SEAT-plan.md §1c). So [`founding_duty_holders`]
//! answers a typed [`FoundingDutyFault`] and NOTHING here is wired to a
//! door or spelled as a refusal string: the wiring and the names are one
//! step once Constitution names them.
//!
//! The codec (`payloads::FAMILIES`' `duty_holders`, `group::roster_payload`
//! on version 1 only, `group::policy_blob_of`) keeps the map in the typed
//! record's `policy_blob[DUTY_HOLDERS]`, like `membership` and
//! `cohort_subkind`; on the wire it is a top-level member of the FIRST
//! version and of no other.

use std::collections::{BTreeMap, BTreeSet};

use ciris_verify_core::cde::Value;

use crate::federation::group_plane::GroupKind;

/// The member's name, on the wire and in `policy_blob`.
pub const DUTY_HOLDERS: &str = "duty_holders";

/// A duty → the keys that hold it at founding.
pub type DutyHolders = BTreeMap<String, BTreeSet<String>>;

/// The `duty_holders` a roster payload states, as text. `None` when the
/// member is absent or does not read as a map of text to arrays of text
/// (the payload table's type check, `payloads::Ty::DutyHolders`, refuses
/// that shape at the door).
#[must_use]
pub fn duty_holders_of(payload: &Value) -> Option<DutyHolders> {
    holders_of_value(payload.get_text(DUTY_HOLDERS)?)
}

/// The `duty_holders` a typed record's `policy_blob` carries (the codec's
/// in-memory home). `None` when absent or ill-shaped.
#[must_use]
pub fn duty_holders_of_blob(blob: Option<&serde_json::Value>) -> Option<DutyHolders> {
    let obj = blob?.get(DUTY_HOLDERS)?.as_object()?;
    let mut out = DutyHolders::new();
    for (duty, keys) in obj {
        let set: Option<BTreeSet<String>> = keys
            .as_array()?
            .iter()
            .map(|k| k.as_str().map(str::to_owned))
            .collect();
        out.insert(duty.clone(), set?);
    }
    Some(out)
}

fn holders_of_value(v: &Value) -> Option<DutyHolders> {
    let mut out = DutyHolders::new();
    for (duty, keys) in v.as_map()? {
        let set: Option<BTreeSet<String>> = keys
            .as_array()?
            .iter()
            .map(|k| k.as_text().map(str::to_owned))
            .collect();
        out.insert(duty.as_text()?.to_owned(), set?);
    }
    Some(out)
}

/// The duties a community's record declares: `moderate` (CC 4.5.4 rule 1:
/// every community's record declares it) and each text of its policy's
/// `duties` member (the CDDL: "moderate, or one the record declares in
/// policy.duties"; `admission::COMMUNITY_DECLARED_DUTIES_MEMBER`).
#[must_use]
pub fn declared_duties(policy_blob: Option<&serde_json::Value>) -> BTreeSet<String> {
    let mut set: BTreeSet<String> =
        std::iter::once(crate::federation::admission::DELEGATION_SCOPE_MODERATE.to_owned())
            .collect();
    if let Some(serde_json::Value::Array(d)) = policy_blob
        .and_then(|b| b.get(crate::federation::admission::COMMUNITY_DECLARED_DUTIES_MEMBER))
    {
        set.extend(d.iter().filter_map(|v| v.as_str().map(str::to_owned)));
    }
    set
}

/// What a signer of the founding is, as the founding rule reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HolderKind {
    /// A person's key: may hold a duty, and is a person who signs.
    Person,
    /// An agent's key: may hold a duty only where its owner signed the
    /// record (FREEZE 753); its signature is no person's.
    Agent,
    /// A node's key: holds no judgment duty (CC 4.5.5).
    Node,
}

/// What the founding rule reads, every fact resolved by the caller (the
/// rule reads no store and no clock).
pub struct FoundingFacts<'a> {
    /// Family or community.
    pub group_kind: GroupKind,
    /// The roster version (`version`).
    pub version: u64,
    /// The duties the record declares ([`declared_duties`]).
    pub declared: &'a BTreeSet<String>,
    /// The keys the record lists (`members`).
    pub listed: &'a BTreeSet<String>,
    /// The listed keys whose own statement is on the record.
    pub signers: &'a BTreeSet<String>,
    /// The `duty_holders` the record states, if any ([`duty_holders_of`]).
    pub stated: Option<&'a DutyHolders>,
    /// What each key is.
    pub kind_of: &'a dyn Fn(&str) -> HolderKind,
    /// An agent key's owner (its owner-binding's owner), `None` when the
    /// caller holds none.
    pub owner_of: &'a dyn Fn(&str) -> Option<String>,
}

/// Why a founding's duty holders conclude nothing. NOT a wire token: the
/// text names none (P/SEAT-plan.md §1c); the door maps each to a name once
/// Constitution gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FoundingDutyFault {
    /// `duty_holders` on a version after the first ("stands on a
    /// community's first version alone").
    NotOnFirstVersion,
    /// `duty_holders` on a family's record ("no family's record carries
    /// it").
    OnFamily,
    /// Several persons sign and the record names no holder.
    NoneNamedBySeveral,
    /// No person signs the founding, and it names no holder: it seats none
    /// (CC 4.5.4 rule 1 "Its founding record seats one, who signs it").
    NoPersonSigned,
    /// A duty the record does not declare.
    DutyUndeclared(String),
    /// A declared duty the map leaves unheld.
    DutyUnheld(String),
    /// A named holder the record does not list.
    HolderNotListed {
        /// The duty.
        duty: String,
        /// The key.
        key: String,
    },
    /// A named holder whose own statement is not on the record.
    HolderNotSigner {
        /// The duty.
        duty: String,
        /// The key.
        key: String,
    },
    /// A named holder that is a node key.
    HolderNode {
        /// The duty.
        duty: String,
        /// The key.
        key: String,
    },
    /// A named agent whose owner did not sign the record.
    AgentOwnerUnsigned {
        /// The duty.
        duty: String,
        /// The key.
        key: String,
    },
}

/// **The founding duty holders** of one roster version: the map the
/// version seats (empty for a version that seats none: a family's, a later
/// version's, each without the member), or the first fault, in a fixed
/// order: placement, then each named duty and its keys in sorted order,
/// then each declared duty left unheld.
///
/// # Errors
/// The [`FoundingDutyFault`] that decides it.
pub fn founding_duty_holders(f: &FoundingFacts<'_>) -> Result<DutyHolders, FoundingDutyFault> {
    if f.stated.is_some() {
        if f.group_kind != GroupKind::Community {
            return Err(FoundingDutyFault::OnFamily);
        }
        if f.version != 1 {
            return Err(FoundingDutyFault::NotOnFirstVersion);
        }
    }
    if f.group_kind != GroupKind::Community || f.version != 1 {
        return Ok(DutyHolders::new());
    }
    let Some(stated) = f.stated else {
        // "A record one person signs MAY name none, and that person then
        // holds every declared duty."
        let persons: Vec<&String> = f
            .signers
            .iter()
            .filter(|k| (f.kind_of)(k) == HolderKind::Person)
            .collect();
        return match persons.as_slice() {
            [] => Err(FoundingDutyFault::NoPersonSigned),
            [one] => Ok(f
                .declared
                .iter()
                .map(|d| (d.clone(), std::iter::once((*one).clone()).collect()))
                .collect()),
            _ => Err(FoundingDutyFault::NoneNamedBySeveral),
        };
    };
    for (duty, keys) in stated {
        if !f.declared.contains(duty) {
            return Err(FoundingDutyFault::DutyUndeclared(duty.clone()));
        }
        for key in keys {
            let at = || (duty.clone(), key.clone());
            if !f.listed.contains(key) {
                let (duty, key) = at();
                return Err(FoundingDutyFault::HolderNotListed { duty, key });
            }
            if !f.signers.contains(key) {
                let (duty, key) = at();
                return Err(FoundingDutyFault::HolderNotSigner { duty, key });
            }
            match (f.kind_of)(key) {
                HolderKind::Person => {}
                HolderKind::Node => {
                    let (duty, key) = at();
                    return Err(FoundingDutyFault::HolderNode { duty, key });
                }
                HolderKind::Agent => {
                    if !(f.owner_of)(key).is_some_and(|o| f.signers.contains(&o)) {
                        let (duty, key) = at();
                        return Err(FoundingDutyFault::AgentOwnerUnsigned { duty, key });
                    }
                }
            }
        }
    }
    if let Some(d) = f
        .declared
        .iter()
        .find(|d| stated.get(*d).is_none_or(BTreeSet::is_empty))
    {
        return Err(FoundingDutyFault::DutyUnheld(d.clone()));
    }
    Ok(stated.clone())
}
