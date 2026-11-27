//! v62.0.0 (DUTY-D7; Constitution "confers-by-naming, the four", 11-24; CC
//! 2.4.1.1 "An act names its head", CC 3.1.2.1, CC 3.2) — **a root grant
//! confers BY NAMING, never by instants.**
//!
//! The chain: act → `refs.also.stands_on` → the ACCEPTANCE of that grant →
//! `refs.answers` → the GRANT → `refs.head` → the BUNDLE. "A row that names
//! the bundle alone, or names a binding, stands on no acceptance and counts
//! for nobody." No stamped instant is consulted.
//!
//! Two entry points, kept apart by TYPE so that a door can never take the
//! reading for a verdict:
//!
//! - [`confers_on_act`] → [`ConfersOnAct`]: for EVERY door with an act row in
//!   hand. Which conferral the act stands on is the naming chain
//!   ([`stands_on_acceptance`]); whether it COUNTS at its head and is IN FORCE
//!   is the kernel's (`ciris_kernel::conferral::answers`, one end per call,
//!   through v62-resign's adapter row [`CRow`]), for each end this node holds
//!   of that conferral: the owner's withdrawal of the acceptance, the
//!   holders' counted withdrawal or successor of the grant, and a held owner
//!   binding by ANOTHER owner that replaced the one the acceptance cites (the
//!   handover: "in force for nobody unless it was receipted"). A door that
//!   needs one bit reads [`ConfersOnAct::in_force`].
//! - [`holds_now`] → [`HoldsNow`]: the LIVE-STATE READING for a caller with
//!   no act (a host, the serve tier, `is_trust_root`): a counted grant held;
//!   an acceptance by the grantee's consenter answering it (for a machine,
//!   citing a binding of its owner now); nothing ended. No instant is
//!   compared but a row's own stated bound (`expires_at`) against now. No
//!   row's verdict rests on it (the gate `P/tools/act_not_reading.py`).
//!
//! The shared resolver [`acceptance_to_stand_on`] is the PRODUCER's (v62-head
//! HEAD-fix6 states `refs.also.stands_on` with it); [`stands_on_acceptance`]
//! is the READER's (HEAD-fix4's build-row reading calls it too).
//!
//! **Shaped for the crate.** [`confers_on_act`] is one function whose body is
//! (1) the naming chain, (2) the rows of the standing as [`CRow`]s and (3)
//! `conferral::answers`. When Kernel puts the naming rule in the crate, (1)
//! is the part handed over: the act's `stands_on`, the acceptance's
//! `answers` and `cites`, the grant's `head` and sub, as rows, and the
//! answer "which standing does this act stand on, or none, or wait on row
//! X".
//!
//! **Unmodelled by the text** (CC 3.2: "This entry does not say what a new
//! owner's decline or withdrawal of an acceptance does to acts already
//! signed"): that case is left exactly as the crate answers it.

use ciris_kernel::conferral::{answers, Answer, Kind, Role, Standing, Who};

use super::names::{of_statement_names, RowId};
use crate::federation::types::attestation_type;
use crate::federation::{Attestation, Error, FederationDirectory};
use crate::kernel::receipts::{receipts_of, CRow};

/// The `refs` role an act names its acceptance under.
pub const STANDS_ON_ROLE: &str = "also:stands_on";

/// What the naming chain of an act reaches.
#[derive(Clone, Debug, PartialEq)]
pub enum StandsOn {
    /// The act stands on this acceptance of this counted root grant (and,
    /// for a machine grantee, the owner binding the acceptance cites).
    Acceptance {
        /// The acceptance the act names.
        acceptance: Attestation,
        /// The counted root grant it answers.
        grant: Attestation,
        /// The owner binding it cites (a machine grantee).
        binding: Option<Attestation>,
    },
    /// It stands on nothing: the reason (no new token; a fold detail).
    Nothing(&'static str),
    /// A row of the chain is not held: the verdict waits on it.
    Waits(RowId),
}

fn names(statement: &[u8]) -> Option<Vec<super::names::Name>> {
    of_statement_names(statement).map(|(_, n)| n)
}

fn row_id(hex_id: &str) -> Option<RowId> {
    super::store::id_of_hex(hex_id).map(RowId)
}

async fn is_machine<F>(dir: &F, key: &str) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::types::identity_type as it;
    Ok(dir.lookup_public_key(key).await?.is_some_and(|r| {
        it::set_contains(&r.identity_type, it::NODE)
            || it::set_contains(&r.identity_type, it::AGENT)
    }))
}

/// **The reader's half of the shared resolver**: which acceptance (of which
/// counted root grant) the act whose statement is `act_statement` stands on.
/// Exactly one `refs.also.stands_on`; a held root-grant acceptance answering
/// a held counted grant; signed by the grantee's consenter: a person grantee's
/// own person, a machine grantee's OWNER, whose acceptance cites (Q2 ruling)
/// exactly one held owner binding of the grantee's key BY THAT OWNER (the
/// test "the cited row is a held binding of the grantee's key by the owner
/// who signed the acceptance"; to be checked against Verify's answer).
///
/// # Errors
/// Directory reads.
pub async fn stands_on_acceptance<F>(dir: &F, act_statement: &[u8]) -> Result<StandsOn, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(names) = names(act_statement) else {
        return Ok(StandsOn::Nothing("act_refs_unreadable"));
    };
    let stands: Vec<RowId> = names
        .iter()
        .filter(|n| n.role == STANDS_ON_ROLE)
        .map(|n| n.row)
        .collect();
    let [acc_id] = stands.as_slice() else {
        return Ok(StandsOn::Nothing("stands_on_names_not_one_acceptance"));
    };
    Box::pin(acceptance_standing(dir, *acc_id)).await
}

/// The acceptance-side checks of [`stands_on_acceptance`] for the acceptance
/// `acc_id` (shared with the reading, [`holds_now`]).
async fn acceptance_standing<F>(dir: &F, acc_id: RowId) -> Result<StandsOn, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::admission::{consenting_person, owner_binding_marker};
    use crate::federation::edition2::fold::{reads, Dep};
    let acc_id = &acc_id;
    reads(Dep::Row(*acc_id));
    let Some(acceptance) = dir.get_attestation(&acc_id.hex()).await? else {
        return Ok(StandsOn::Waits(*acc_id));
    };
    let grant_hex = acceptance
        .attestation_envelope
        .get("references_attestation_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let Some(grant_id) = row_id(&grant_hex) else {
        return Ok(StandsOn::Nothing("acceptance_answers_no_grant"));
    };
    reads(Dep::Row(grant_id));
    let Some(grant) = dir.get_attestation(&grant_hex).await? else {
        return Ok(StandsOn::Waits(grant_id));
    };
    if !crate::federation::membership_acceptance::is_root_grant_acceptance(dir, &acceptance).await?
    {
        return Ok(StandsOn::Nothing("not_a_root_grant_acceptance"));
    }
    let grantee = grant.attested_key_id.clone();
    let signer = consenting_person(dir, &acceptance.attesting_key_id).await?;
    if !is_machine(dir, &grantee).await? {
        if signer.is_none() || signer != consenting_person(dir, &grantee).await? {
            return Ok(StandsOn::Nothing("acceptance_not_the_grantees"));
        }
        return Ok(StandsOn::Acceptance {
            acceptance,
            grant,
            binding: None,
        });
    }
    let Some(cite) = acceptance
        .attestation_envelope
        .get(super::payloads::OWNER_BINDING_REF_MEMBER)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
    else {
        // DUTY-D7a2: a machine's acceptance that cites nothing LANDS (no
        // refusal on the row alone) and stands nowhere.
        return Ok(StandsOn::Nothing("acceptance_cites_no_binding"));
    };
    let Some(cite_id) = row_id(&cite) else {
        return Ok(StandsOn::Nothing("acceptance_cites_no_binding"));
    };
    reads(Dep::Row(cite_id));
    let Some(binding) = dir.get_attestation(&cite).await? else {
        // Q2: a cited binding this reader does not hold makes the verdict WAIT.
        return Ok(StandsOn::Waits(cite_id));
    };
    let binding_owner = consenting_person(dir, &binding.attesting_key_id).await?;
    if binding.attestation_type != attestation_type::DELEGATES_TO
        || binding.attested_key_id != grantee
        || !owner_binding_marker(&binding.attestation_envelope)
        || signer.is_none()
        || binding_owner != signer
    {
        return Ok(StandsOn::Nothing("acceptance_other_binding"));
    }
    Ok(StandsOn::Acceptance {
        acceptance,
        grant,
        binding: Some(binding),
    })
}

/// **The producer's half of the shared resolver** (v62-head HEAD-fix6
/// states `refs.also.stands_on` with it): the acceptance an act by
/// `signer_iss` exercising `scope` stands on. The live acceptances
/// ([`holds_now`]) of the signer's key; where several stand, the one whose
/// grant names the newest bundle of the lineage in force, ties to the lowest
/// acceptance row id (deterministic on every node). `act_at_ms` is the act's
/// own instant: a grant or acceptance whose stated end (`expires_at`) is at
/// or before it is not offered. `None`: nothing to stand on (the producer
/// refuses; HEAD-fix6 names the token).
///
/// # Errors
/// Directory reads.
pub async fn acceptance_to_stand_on<F>(
    dir: &F,
    signer_iss: &str,
    scope: &str,
    act_at_ms: u64,
) -> Result<Option<RowId>, Error>
where
    F: FederationDirectory + ?Sized,
{
    // An edition-2 key id IS its identity-ref (`fixture_switch::kid`).
    let at = i64::try_from(act_at_ms)
        .ok()
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .unwrap_or_else(crate::host::clock::now);
    let mut live = live_acceptances(dir, signer_iss, scope, at).await?;
    live.sort_by(|a, b| {
        b.bundle_in_force
            .cmp(&a.bundle_in_force)
            .then(a.acceptance.cmp(&b.acceptance))
    });
    Ok(live.first().map(|h| h.acceptance))
}

/// The live-state reading's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HoldsNow {
    /// The counted root grant.
    pub grant: RowId,
    /// The acceptance answering it.
    pub acceptance: RowId,
    /// Does the grant name the bundle in force (not a superseded one)?
    pub bundle_in_force: bool,
}

/// **The live-state reading** (no act in hand): the first live
/// [`HoldsNow`] of `key` for `scope`, or `None`. ONLY a reading: no row's
/// verdict rests on it.
///
/// # Errors
/// Directory reads.
pub async fn holds_now<F>(dir: &F, key: &str, scope: &str) -> Result<Option<HoldsNow>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut live = live_acceptances(dir, key, scope, crate::host::clock::now()).await?;
    live.sort_by(|a, b| a.acceptance.cmp(&b.acceptance));
    Ok(live.into_iter().next())
}

/// Every [`HoldsNow`] of `key` for `scope` (the reading; for the walk's
/// bundle-root arm, `trust_root::capability_roots_to_trusted_root_over_roster`).
///
/// # Errors
/// Directory reads.
pub(crate) async fn holds_now_all<F>(
    dir: &F,
    key: &str,
    scope: &str,
) -> Result<Vec<HoldsNow>, Error>
where
    F: FederationDirectory + ?Sized,
{
    live_acceptances(dir, key, scope, crate::host::clock::now()).await
}

/// **A door's question** for an act row: does a root grant confer on it BY
/// NAMING, in force? The door's row carries its statement
/// (`emit::carried_statement`). `false` when it stands on nothing or waits
/// (every row of the chain read is declared to the fold: a wait re-folds).
///
/// # Errors
/// Directory reads.
pub(crate) async fn door_confers<F>(dir: &F, act: &Attestation, scope: &str) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(st) = super::emit::carried_statement(act) else {
        return Ok(false);
    };
    Ok(Box::pin(confers_on_act(dir, act, &st, scope))
        .await?
        .in_force())
}

/// Every live acceptance of a live counted root grant of `scope` to `key`,
/// judged against `at` only through the rows' own stated bounds.
async fn live_acceptances<F>(
    dir: &F,
    key: &str,
    scope: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<HoldsNow>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::attestation_query::{AttestationQuery, FOLD_PAGE};
    use crate::federation::membership_acceptance::{is_root_grant_acceptance, MembershipRow};
    let mut out = Vec::new();
    let mut pages = AttestationQuery::to(key, FOLD_PAGE)
        .types(&[attestation_type::DELEGATES_TO])
        .pages();
    let mut grants = Vec::new();
    while let Some(page) = pages.next(dir).await? {
        grants.extend(page.into_iter().filter(|g| {
            crate::federation::admission::is_counted_root_grant_row(g)
                && crate::federation::trust_root::scope_confers(&g.attestation_envelope, scope)
                && g.expires_at.is_none_or(|e| e > at)
        }));
    }
    for grant in grants {
        let Some(gid) = row_id(&grant.attestation_id) else {
            continue;
        };
        let Some(root) =
            crate::federation::admission::root_grant_of(dir.as_dyn_directory(), &grant, at).await?
        else {
            continue;
        };
        if !ends_of(dir, &gid, None).await?.is_empty() {
            continue;
        }
        for aid in dir.edition2_rows_naming(&gid, "answers").await? {
            let Some(acc) = dir.get_attestation(&aid.hex()).await? else {
                continue;
            };
            if crate::federation::membership_acceptance::membership_row(&acc)
                != Some(MembershipRow::Acceptance)
                || !is_root_grant_acceptance(dir, &acc).await?
                || !super::verdict::row_state(dir, &aid).await?.is_concluded()
            {
                continue;
            }
            // The same checks as an act's chain, without an act.
            if !matches!(
                Box::pin(acceptance_standing(dir, aid)).await?,
                StandsOn::Acceptance { .. }
            ) {
                continue;
            }
            if !ends_of(dir, &aid, Some(&acc)).await?.is_empty() {
                continue;
            }
            out.push(HoldsNow {
                grant: gid,
                acceptance: aid,
                bundle_in_force: root.bundle_in_force,
            });
        }
    }
    Ok(out)
}

/// The ends this node holds of a conferral, as rows the kernel reads: the
/// concluded `withdraws` / `supersedes` naming `named` (the grant: its
/// holders' counted end or successor; the acceptance: its own signer's
/// withdrawal), and for the acceptance of a machine grantee, a concluded
/// owner binding of the grantee's key by ANOTHER owner (the handover).
async fn ends_of<F>(
    dir: &F,
    named: &RowId,
    acceptance: Option<&Attestation>,
) -> Result<Vec<CRow>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::admission::consenting_person;
    let mut out = Vec::new();
    for e in dir.edition2_rows_naming(named, "target").await? {
        let Some(row) = dir.get_attestation(&e.hex()).await? else {
            continue;
        };
        if row.attestation_type != attestation_type::WITHDRAWS
            && row.attestation_type != attestation_type::SUPERSEDES
        {
            continue;
        }
        if !super::verdict::row_state(dir, &e).await?.is_concluded() {
            continue;
        }
        if let Some(acc) = acceptance {
            if row.attestation_type != attestation_type::WITHDRAWS
                || !crate::federation::membership_acceptance::same_consenting_party(
                    dir,
                    &row.attesting_key_id,
                    &acc.attesting_key_id,
                )
                .await?
            {
                continue;
            }
        }
        out.push(end_row(dir, e).await?);
    }
    if let Some(acc) = acceptance {
        // The handover (CC 3.2: "Once a reader holds the binding that
        // replaced an act's own, that act is in force for nobody unless it
        // was receipted"): the owner bindings of the grantee's key in force
        // that are by ANOTHER owner than the acceptance's.
        let grantee = acc.attested_key_id.as_str();
        if is_machine(dir, grantee).await? {
            let owner = consenting_person(dir, &acc.attesting_key_id).await?;
            let bound = crate::federation::edition2::fold::unmarked(
                crate::federation::admission::machine_owner_binding_at(
                    dir,
                    grantee,
                    crate::host::clock::now(),
                ),
            )
            .await;
            if let Ok(crate::federation::admission::MachineOwner::Bound { bindings, .. }) = bound {
                for b in bindings {
                    let Some(bid) = row_id(&b) else { continue };
                    let Some(row) = dir.get_attestation(&b).await? else {
                        continue;
                    };
                    if consenting_person(dir, &row.attesting_key_id).await? == owner {
                        continue;
                    }
                    out.push(end_row(dir, bid).await?);
                }
            }
        }
    }
    Ok(out)
}

/// An end as the kernel reads it: its id, its signer's identity-ref, the
/// head it names.
async fn end_row<F>(dir: &F, id: RowId) -> Result<CRow, Error>
where
    F: FederationDirectory + ?Sized,
{
    let st = super::head_rule::held_statement(dir, &id).await?;
    let signer = st
        .as_deref()
        .and_then(super::occurrence::statement_iss)
        .unwrap_or_default();
    let head = st
        .as_deref()
        .and_then(names)
        .and_then(|n| super::names::single(&n, "head"));
    Ok(CRow {
        id,
        kind: Kind::End,
        signer,
        head,
        of: None,
        target: None,
        via: None,
        lifts: false,
    })
}

/// The verdict of [`confers_on_act`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfersOnAct {
    /// The act stands on this conferral: counted at its head and in force,
    /// each the AND over the ends held (one kernel call per end).
    Stands {
        /// Counted at the head it names.
        counted: bool,
        /// In force now.
        in_force: bool,
        /// The kernel's rule per call, in order.
        rules: Vec<&'static str>,
        /// The counted root grant.
        grant: RowId,
        /// The acceptance the act names.
        acceptance: RowId,
    },
    /// It counts for nobody: the reason.
    Nothing(&'static str),
    /// The verdict waits on this row.
    Waits(RowId),
}

impl ConfersOnAct {
    /// The one bit a door reads: the act is IN FORCE under its conferral.
    #[must_use]
    pub fn in_force(&self) -> bool {
        matches!(self, Self::Stands { in_force: true, .. })
    }
}

/// **Does the root grant confer on this ACT?** `act` is the door's row,
/// `act_statement` its statement, `scope` the scope its family needs. See
/// the module doc. The one function the crate call replaces.
///
/// # Errors
/// Directory reads.
pub async fn confers_on_act<F>(
    dir: &F,
    act: &Attestation,
    act_statement: &[u8],
    scope: &str,
) -> Result<ConfersOnAct, Error>
where
    F: FederationDirectory + ?Sized,
{
    // (1) The naming chain.
    let (acceptance, grant) = match Box::pin(stands_on_acceptance(dir, act_statement)).await? {
        StandsOn::Acceptance {
            acceptance, grant, ..
        } => (acceptance, grant),
        StandsOn::Nothing(why) => return Ok(ConfersOnAct::Nothing(why)),
        StandsOn::Waits(id) => return Ok(ConfersOnAct::Waits(id)),
    };
    if grant.attested_key_id != act.attesting_key_id {
        return Ok(ConfersOnAct::Nothing("act_signer_is_not_the_grantee"));
    }
    if !crate::federation::trust_root::scope_confers(&grant.attestation_envelope, scope) {
        return Ok(ConfersOnAct::Nothing("grant_scope_does_not_cover_the_act"));
    }
    let now = crate::host::clock::now();
    let Some(root) =
        crate::federation::admission::root_grant_of(dir.as_dyn_directory(), &grant, now).await?
    else {
        return Ok(ConfersOnAct::Nothing("grant_not_counted"));
    };
    let Some(node) = dir.node_key_id() else {
        return Ok(ConfersOnAct::Nothing("no_node_identity"));
    };
    if !crate::federation::trust_root::trust_root_valid(dir, &node, &root.family_key_id, now)
        .await?
        .valid
    {
        return Ok(ConfersOnAct::Nothing("root_not_accepted_by_this_node"));
    }
    let (Some(gid), Some(aid), Some(act_id)) = (
        row_id(&grant.attestation_id),
        row_id(&acceptance.attestation_id),
        RowId::of_statement(act_statement),
    ) else {
        return Ok(ConfersOnAct::Nothing("row_id_unreadable"));
    };
    // (2) The rows of the standing.
    let act_names = names(act_statement).unwrap_or_default();
    let act_head = super::names::single(&act_names, "head");
    let act_signer = super::occurrence::statement_iss(act_statement).unwrap_or_default();
    let mut ends = ends_of(dir, &gid, None).await?;
    ends.extend(ends_of(dir, &aid, Some(&acceptance)).await?);
    let receipts = receipts_of(dir, &act_id).await?;
    let mut heads: Vec<CRow> = Vec::new();
    for h in act_head
        .iter()
        .chain(ends.iter().filter_map(|e| e.head.as_ref()))
    {
        if !heads.iter().any(|x| x.id == *h) {
            heads.push(CRow {
                id: *h,
                kind: Kind::Head,
                signer: String::new(),
                head: None,
                of: None,
                target: None,
                via: None,
                lifts: false,
            });
        }
    }
    let act_row = CRow {
        id: act_id,
        kind: Kind::Act,
        signer: act_signer.clone(),
        head: act_head,
        of: None,
        target: None,
        via: None,
        lifts: false,
    };
    let grant_st = super::head_rule::held_statement(dir, &gid).await?;
    let holders = match &grant_st {
        Some(st) => {
            crate::federation::admission::root_grant_voice_parties(dir.as_dyn_directory(), st)
                .await?
                .unwrap_or_default()
        }
        None => Vec::new(),
    };
    let acc_signer = super::head_rule::held_statement(dir, &aid)
        .await?
        .as_deref()
        .and_then(super::occurrence::statement_iss)
        .unwrap_or_default();
    let role = |k: &String| {
        if holders.contains(k) {
            Role::Conferrer
        } else if *k == act_signer || *k == acc_signer {
            Role::Grantee
        } else {
            Role::Other
        }
    };
    let standing = Standing {
        role: &role,
        other_standing: false,
        who: Who::ConferrerOnly,
        reader_acks: &[],
    };
    let mut ids: Vec<RowId> = vec![act_id];
    ids.extend(heads.iter().map(|h| h.id));
    ids.extend(ends.iter().map(|e| e.id));
    ids.extend(receipts.iter().map(|r| r.id));
    let past =
        crate::kernel::content::HeldPast::preload(dir, &ids, &[act_statement.to_vec()]).await?;
    let p = |a: &RowId, b: &RowId| past.in_past(a, b);
    // (3) The kernel, one end per call.
    let mut calls: Vec<Option<&CRow>> = ends.iter().map(Some).collect();
    if calls.is_empty() {
        calls.push(None);
    }
    let (mut counted, mut in_force, mut rules) = (true, true, Vec::new());
    for end in calls {
        let mut rows: Vec<&CRow> = vec![&act_row];
        rows.extend(heads.iter());
        rows.extend(receipts.iter());
        rows.extend(end);
        let out = answers(&rows, &standing, &p).map_err(|e| {
            Error::Backend(format!(
                "confers_on_act: the kernel refused the rows: {e:?}"
            ))
        })?;
        match out.get(&act_id) {
            Some(Answer::Judged(j)) => {
                counted &= j.counted;
                in_force &= j.in_force;
                rules.push(j.rule.as_str());
            }
            Some(Answer::Undecided(id)) => return Ok(ConfersOnAct::Waits(*id)),
            None => return Ok(ConfersOnAct::Nothing("kernel_gave_no_answer")),
        }
    }
    Ok(ConfersOnAct::Stands {
        counted,
        in_force,
        rules,
        grant: gid,
        acceptance: aid,
    })
}
