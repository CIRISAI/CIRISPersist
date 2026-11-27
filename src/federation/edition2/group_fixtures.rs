//! v62.0.0 (wave T1) — **the edition-2 twins of the typed-plane builders.**
//!
//! The typed-plane builders (`tier_ingest::test_support::sign_family`,
//! `sign_community`, `sign_{family,community}_membership_{revocation,
//! widening}`, `sign_*_by_consensus`, `*_naming_held`) return earlier-form
//! `Signed*` structs. Each function here turns one of those structs into the
//! edition-2 statements it is: the payload ([`super::group::roster_payload`],
//! [`super::group::membership_payload`]) signed once per signer (the
//! struct's authority, then each co-signer), so a held test keeps its
//! builder and swaps `dir.put_family(s)` for
//! `put_voices(dir, &family_voices(&s, 1, None, at)).await`.
//!
//! Ids follow E0's fixture model (`fixture_switch`): a key id in the struct
//! is a SEED or an identity-ref E0 minted; the statement carries
//! `kid_or_keep(..)` of it, and each signer signs with `signing_key(..)`.
//! So the typed row lands under `kid(seed)`: assert with `e2::kid(..)`.
//!
//! A membership change names the roster version it is counted over
//! (`refs.head`, required by CC's payload table): pass the row id of the
//! roster's statement ([`row_id_of`]).

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::{identity_ref, sign_row_statement, thumbprint};
use ciris_verify_core::namespace_match;

use super::fixture_switch::{kid_or_keep, signing_key};
use super::group::{
    membership_payload, prev_head_digest, record_of_roster, roster_payload,
    roster_view_of_statement, GroupRecord, MembershipRecord, GROUP_ROSTER_PREFIX,
    MEMBERSHIP_PREFIX,
};
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::names::RowId;
use crate::federation::group_plane::GroupKind;
use crate::federation::types::{
    Community, CommunityMember, Family, FamilyMember, RosterCosignature, SignedCommunity,
    SignedCommunityMembershipRevocation, SignedCommunityMembershipWidening, SignedFamily,
    SignedFamilyMembershipRevocation, SignedFamilyMembershipWidening,
};
use crate::federation::{Error, FederationDirectory};

/// Sign a group payload as `key`'s voice: row type `scores`, the family's
/// header id (`namespace_match::family_id` of `family_prefix`), `sub` the
/// row's subject.
///
/// # Panics
/// A payload with no `asserted_at`.
#[must_use]
pub fn sign_group_payload(
    key: &CompositeSigningKey,
    sub: &str,
    family_prefix: &str,
    payload: &Value,
) -> Vec<u8> {
    let iss = identity_ref(&thumbprint(key.public_key()));
    sign_row_statement(
        key,
        &iss,
        sub,
        "scores",
        &namespace_match::family_id(family_prefix),
        payload,
        vec![],
    )
    .expect("group_fixtures: sign a group statement")
}

/// The row id every voice of `statement` shares (a counted row).
///
/// # Panics
/// Not a row statement.
#[must_use]
pub fn row_id_of(statement: &[u8]) -> RowId {
    RowId::of_statement(statement).expect("group_fixtures: not a row statement")
}

/// One voice per signer of a roster version (`record` at `version`,
/// extending `head`), stated at `asserted_at_ms`.
///
/// # Panics
/// A record that does not encode (an instant before the epoch, a float in a
/// policy blob).
#[must_use]
pub fn roster_voices(
    record: &GroupRecord,
    version: u64,
    head: Option<&RowId>,
    asserted_at_ms: u64,
    signers: &[&CompositeSigningKey],
) -> Vec<Vec<u8>> {
    let (group, p) = if version == 1 && head.is_none() {
        fixture_founding(record, asserted_at_ms)
    } else {
        // v62.0.0 (GID-fixtures-mech.rev2) — a later version of a room a
        // fixture founded carries the `founded_at` it was founded at.
        let record = &with_fixture_founded_at(record, false);
        let group = match record {
            GroupRecord::Family(f) => f.family_key_id.clone(),
            GroupRecord::Community(c) => c.community_key_id.clone(),
        };
        let p = roster_payload(record, version, head, asserted_at_ms)
            .expect("group_fixtures: roster payload");
        (group, p)
    };
    signers
        .iter()
        .map(|k| sign_group_payload(k, &group, GROUP_ROSTER_PREFIX, &p))
        .collect()
}

/// v62.0.0 (GID-fixtures) — **a fixture's FIRST version**: `record`'s id is
/// the NAME the fixture gave the room (a seed's identity-ref, or the derived
/// id when it was founded before); the payload is founded under the DERIVED
/// id with the name's fixture nonce ([`fixture_group_nonce`](super::fixture_switch::fixture_group_nonce)),
/// and the name is recorded so `kid(name)` answers the derived id after.
/// Returns the derived id and the payload.
///
/// v62.0.0 (GID-fixtures-mech.rev2) — the record's `founded_at` is REPLACED
/// by the name's fixture instant
/// ([`fixture_founded_at`](super::fixture_switch::fixture_founded_at)):
/// it is an input of the derived id, so the wall-clock instant a fixture
/// builds its record with would derive a different id on each node.
/// `asserted_at_ms` (the row's instant, the test's clock seam) is kept.
///
/// # Panics
/// A record that does not encode.
#[must_use]
pub fn fixture_founding(record: &GroupRecord, asserted_at_ms: u64) -> (String, Value) {
    let mut rec = with_fixture_founded_at(record, true);
    let alias = match &rec {
        GroupRecord::Family(f) => f.family_key_id.clone(),
        GroupRecord::Community(c) => c.community_key_id.clone(),
    };
    let nonce = super::fixture_switch::fixture_group_nonce(&alias);
    let founded_at_ms = super::fixture_switch::fixture_founded_at_ms(&alias);
    let (gid, p) = super::group::founding_payload(&mut rec, &nonce, asserted_at_ms)
        .expect("group_fixtures: founding payload");
    super::fixture_switch::note_founded_group(&[&alias], &gid, nonce, founded_at_ms);
    (gid, p)
}

/// v62.0.0 (GID-fixtures-mech.rev2) — `record` with its `founded_at` set to
/// the fixture instant of the room it names: always when `founding`; for a
/// later version, only when a fixture founded that room in this process (a
/// room no fixture founded keeps its own).
#[must_use]
pub fn with_fixture_founded_at(record: &GroupRecord, founding: bool) -> GroupRecord {
    use super::fixture_switch::{fixture_founded_at, founded_group_id};
    let mut rec = record.clone();
    let alias = match &rec {
        GroupRecord::Family(f) => f.family_key_id.clone(),
        GroupRecord::Community(c) => c.community_key_id.clone(),
    };
    if founding || founded_group_id(&alias).is_some() {
        let at = fixture_founded_at(&alias);
        match &mut rec {
            GroupRecord::Family(f) => f.founded_at = at,
            GroupRecord::Community(c) => c.founded_at = at,
        }
    }
    rec
}

/// One voice per signer of a MERGE version (CC 2.7.8): `record` at
/// `version`, naming `head` and the further tips `further`.
///
/// # Panics
/// A record that does not encode.
#[must_use]
pub fn merge_voices(
    record: &GroupRecord,
    version: u64,
    head: &RowId,
    further: &[RowId],
    asserted_at_ms: u64,
    signers: &[&CompositeSigningKey],
) -> Vec<Vec<u8>> {
    let p =
        super::group::roster_payload_merging(record, version, Some(head), further, asserted_at_ms)
            .expect("group_fixtures: merge payload");
    let group = match record {
        GroupRecord::Family(f) => &f.family_key_id,
        GroupRecord::Community(c) => &c.community_key_id,
    };
    signers
        .iter()
        .map(|k| sign_group_payload(k, group, GROUP_ROSTER_PREFIX, &p))
        .collect()
}

/// One voice per signer of a counted membership change, counted over the
/// roster version `head`.
///
/// # Panics
/// A record that does not encode.
#[must_use]
pub fn membership_voices(
    record: &MembershipRecord,
    head: Option<&RowId>,
    signers: &[&CompositeSigningKey],
) -> Vec<Vec<u8>> {
    let p = membership_payload(record, head).expect("group_fixtures: membership payload");
    let member = match record {
        MembershipRecord::FamilyRemoval(r) => &r.removed_identity_key_id,
        MembershipRecord::CommunityRemoval(r) => &r.removed_identity_key_id,
        MembershipRecord::FamilyWidening(w) => &w.member_key_id,
        MembershipRecord::CommunityWidening(w) => &w.member_key_id,
    };
    signers
        .iter()
        .map(|k| sign_group_payload(k, member, MEMBERSHIP_PREFIX, &p))
        .collect()
}

/// Put each voice through the one entry (`ingest::put_statement`, tier
/// `federation`), in order; the last outcome. The first refusal returns.
///
/// # Errors
/// The first refusal.
///
/// # Panics
/// No voice given.
pub async fn put_voices<D: FederationDirectory + ?Sized>(
    dir: &D,
    voices: &[Vec<u8>],
) -> Result<StatementOutcome, Error> {
    let mut last = None;
    for v in voices {
        last = Some(put_statement(dir, v, None, INGEST_TIER).await?);
    }
    Ok(last.expect("group_fixtures: put_voices of no voice"))
}

// ── The typed-struct twins (E0's seed model) ──────────────────────────────

fn signer_keys(authority: &str, cosignatures: &[RosterCosignature]) -> Vec<CompositeSigningKey> {
    std::iter::once(authority)
        .chain(cosignatures.iter().map(|c| c.authority_key_id.as_str()))
        .map(signing_key)
        .collect()
}

/// v62.0.0 (GID-fixtures) — the voices of a roster: [`signer_keys`], except
/// that a record "signed by the group's own key" (its authority names the
/// group itself: a fixture fiction, since a group has no key) is signed by
/// its FIRST listed member (`first_members[0]`), deduplicated.
fn roster_signer_keys(
    authority: &str,
    cosignatures: &[RosterCosignature],
    group: &str,
    members: &[&str],
) -> Vec<CompositeSigningKey> {
    let is_group = authority == group || kid_or_keep(authority) == kid_or_keep(group);
    // The first member the record lists (`first_members[0]`).
    let first = members.first().copied();
    let lead = if is_group {
        first.unwrap_or(authority)
    } else {
        authority
    };
    let mut ids: Vec<&str> = vec![lead];
    for c in cosignatures {
        let id = c.authority_key_id.as_str();
        if !ids.contains(&id) && kid_or_keep(id) != kid_or_keep(group) {
            ids.push(id);
        }
    }
    ids.into_iter().map(signing_key).collect()
}

fn voices_with(
    keys: &[CompositeSigningKey],
    f: impl Fn(&[&CompositeSigningKey]) -> Vec<Vec<u8>>,
) -> Vec<Vec<u8>> {
    let refs: Vec<&CompositeSigningKey> = keys.iter().collect();
    f(&refs)
}

/// A family record with every key id as its identity-ref.
#[must_use]
pub fn family_with_kids(f: &Family) -> Family {
    Family {
        family_key_id: kid_or_keep(&f.family_key_id),
        members: f
            .members
            .iter()
            .map(|m| FamilyMember {
                key_id: kid_or_keep(&m.key_id),
                joined_at: m.joined_at,
                role: m.role.clone(),
            })
            .collect(),
        ..f.clone()
    }
}

/// A community record with every key id as its identity-ref.
#[must_use]
pub fn community_with_kids(c: &Community) -> Community {
    Community {
        community_key_id: kid_or_keep(&c.community_key_id),
        members: c
            .members
            .iter()
            .map(|m| CommunityMember {
                key_id: kid_or_keep(&m.key_id),
                joined_at: m.joined_at,
                role: m.role.clone(),
            })
            .collect(),
        ..c.clone()
    }
}

/// **`sign_family`'s twin**: the roster voices of `signed` (its authority,
/// then each co-signer) at `version`, extending `head`.
#[must_use]
pub fn family_voices(
    signed: &SignedFamily,
    version: u64,
    head: Option<&RowId>,
    asserted_at_ms: u64,
) -> Vec<Vec<u8>> {
    let record = GroupRecord::Family(family_with_kids(&signed.family));
    let f = &signed.family;
    let members: Vec<&str> = f.members.iter().map(|m| m.key_id.as_str()).collect();
    voices_with(
        &roster_signer_keys(
            &signed.authority_key_id,
            &signed.cosignatures,
            &f.family_key_id,
            &members,
        ),
        |k| roster_voices(&record, version, head, asserted_at_ms, k),
    )
}

/// **`sign_community`'s twin**: as [`family_voices`].
#[must_use]
pub fn community_voices(
    signed: &SignedCommunity,
    version: u64,
    head: Option<&RowId>,
    asserted_at_ms: u64,
) -> Vec<Vec<u8>> {
    let record = GroupRecord::Community(community_with_kids(&signed.community));
    let c = &signed.community;
    let members: Vec<&str> = c.members.iter().map(|m| m.key_id.as_str()).collect();
    voices_with(
        &roster_signer_keys(
            &signed.authority_key_id,
            &signed.cosignatures,
            &c.community_key_id,
            &members,
        ),
        |k| roster_voices(&record, version, head, asserted_at_ms, k),
    )
}

/// **`sign_family_membership_revocation`'s twin** (and the
/// `*_by_consensus` one: its co-signers are voices too).
#[must_use]
pub fn family_revocation_voices(
    signed: &SignedFamilyMembershipRevocation,
    head: Option<&RowId>,
) -> Vec<Vec<u8>> {
    let mut r = signed.family_membership_revocation.clone();
    r.family_key_id = kid_or_keep(&r.family_key_id);
    r.removed_identity_key_id = kid_or_keep(&r.removed_identity_key_id);
    r.witness_set = r.witness_set.iter().map(|k| kid_or_keep(k)).collect();
    let record = MembershipRecord::FamilyRemoval(r);
    voices_with(
        &signer_keys(&signed.authority_key_id, &signed.cosignatures),
        |k| membership_voices(&record, head, k),
    )
}

/// **`sign_community_membership_revocation`'s twin**.
#[must_use]
pub fn community_revocation_voices(
    signed: &SignedCommunityMembershipRevocation,
    head: Option<&RowId>,
) -> Vec<Vec<u8>> {
    let mut r = signed.community_membership_revocation.clone();
    r.community_key_id = kid_or_keep(&r.community_key_id);
    r.removed_identity_key_id = kid_or_keep(&r.removed_identity_key_id);
    r.witness_set = r.witness_set.iter().map(|k| kid_or_keep(k)).collect();
    let record = MembershipRecord::CommunityRemoval(r);
    voices_with(
        &signer_keys(&signed.authority_key_id, &signed.cosignatures),
        |k| membership_voices(&record, head, k),
    )
}

/// **`sign_family_membership_widening`'s twin**.
#[must_use]
pub fn family_widening_voices(
    signed: &SignedFamilyMembershipWidening,
    head: Option<&RowId>,
) -> Vec<Vec<u8>> {
    let mut w = signed.family_membership_widening.clone();
    w.family_key_id = kid_or_keep(&w.family_key_id);
    w.member_key_id = kid_or_keep(&w.member_key_id);
    let record = MembershipRecord::FamilyWidening(w);
    voices_with(
        &signer_keys(&signed.authority_key_id, &signed.cosignatures),
        |k| membership_voices(&record, head, k),
    )
}

/// **`sign_community_membership_widening`'s twin**.
#[must_use]
pub fn community_widening_voices(
    signed: &SignedCommunityMembershipWidening,
    head: Option<&RowId>,
) -> Vec<Vec<u8>> {
    let mut w = signed.community_membership_widening.clone();
    w.community_key_id = kid_or_keep(&w.community_key_id);
    w.member_key_id = kid_or_keep(&w.member_key_id);
    let record = MembershipRecord::CommunityWidening(w);
    voices_with(
        &signer_keys(&signed.authority_key_id, &signed.cosignatures),
        |k| membership_voices(&record, head, k),
    )
}

// ── The `*_naming_held` twins ─────────────────────────────────────────────

/// **The held head of `group`** (an identity-ref): the row id of the
/// `group:roster` version whose typed record is the one `federation_families`
/// / `federation_communities` holds, and its version. `None` when the group
/// is not held, or no held statement maps to its head (an earlier-form
/// record).
///
/// # Panics
/// A directory read failure.
pub async fn held_head<D: FederationDirectory + ?Sized>(
    dir: &D,
    group: &str,
) -> Option<(RowId, u64)> {
    let family_hash = dir
        .lookup_family(group)
        .await
        .expect("lookup_family")
        .map(|f| f.persist_row_hash);
    let held = match family_hash {
        Some(h) => Some(h),
        None => dir
            .lookup_community(group)
            .await
            .expect("lookup_community")
            .map(|c| c.persist_row_hash),
    }?;
    let statements = dir
        .edition2_statements_about(&namespace_match::family_id(GROUP_ROSTER_PREFIX), group)
        .await
        .expect("edition2_statements_about");
    for st in statements {
        let Ok(view) = roster_view_of_statement(&st) else {
            continue;
        };
        let id = row_id_of(&st);
        let Ok(prev) = prev_head_digest(dir, &view, &id).await else {
            continue;
        };
        let Ok(hash) = record_of_roster(&view, prev).and_then(|r| r.persist_row_hash()) else {
            continue;
        };
        if hash == held {
            return Some((id, view.version));
        }
    }
    None
}

/// **`family_naming_held`'s twin**: [`family_voices`] at the version after
/// the held head, naming it by `refs.head` (version 1 with no head when the
/// family is not held).
pub async fn family_voices_naming_held<D: FederationDirectory + ?Sized>(
    dir: &D,
    signed: &SignedFamily,
    asserted_at_ms: u64,
) -> Vec<Vec<u8>> {
    match held_head(dir, &kid_or_keep(&signed.family.family_key_id)).await {
        Some((id, v)) => family_voices(signed, v + 1, Some(&id), asserted_at_ms),
        None => family_voices(signed, 1, None, asserted_at_ms),
    }
}

/// **`community_naming_held`'s twin**: as [`family_voices_naming_held`].
pub async fn community_voices_naming_held<D: FederationDirectory + ?Sized>(
    dir: &D,
    signed: &SignedCommunity,
    asserted_at_ms: u64,
) -> Vec<Vec<u8>> {
    match held_head(dir, &kid_or_keep(&signed.community.community_key_id)).await {
        Some((id, v)) => community_voices(signed, v + 1, Some(&id), asserted_at_ms),
        None => community_voices(signed, 1, None, asserted_at_ms),
    }
}

/// The kind of group a held roster statement is (for a caller choosing the
/// membership twin).
///
/// # Panics
/// Not a `group:roster` statement.
#[must_use]
pub fn group_kind_of_roster(statement: &[u8]) -> GroupKind {
    roster_view_of_statement(statement)
        .expect("group_fixtures: not a roster")
        .kind
}
