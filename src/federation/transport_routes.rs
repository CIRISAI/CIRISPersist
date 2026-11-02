//! v61 (CIRISPersist#1122; steward ruling 2026-10-24) — **one
//! destination, one live key**, and agents do not announce a route.
//!
//! # Agents reach the mesh through their node
//!
//! A route (`TransportDestination`) whose `occurrence_key_id` is an
//! `agent`-typed key is refused at both doors, the signed put/apply and the
//! unsigned local put ([`check_route_key_not_agent`],
//! [`TRANSPORT_DESTINATION_AGENT_KEY`]). An agent is reached through its
//! node's binding (CC 3.4.7.3 Clause A: the node key is the transport
//! identity). A key this node does not hold cannot be typed and is admitted.
//! A route an agent key published before v61 is deleted at open
//! ([`sweep_agent_routes`]): a peer that re-offers it is refused by the door.
//!
//! # A newer route supersedes on its destination
//!
//! A split home (an actor key, then the node split from it) can leave two
//! live, signed routes for one Reticulum destination, and the stale one keeps
//! winning attribution. Persist cannot sign a retirement for another key, and
//! stamping `retired_at` on a row someone else signed would make the row
//! diverge from its own envelope (#541). So the rule is a READ-TIME fold
//! ([`fold_one_live_key`]): among live routes on one `(transport_kind,
//! destination)`, a route is displaced when a newer `(epoch, asserted_at)`
//! route on the same destination is held by a key TIED to it, meaning the
//! same live owner ([`owner_of`](super::admission::owner_of)). Keys the
//! directory cannot tie together still coexist, so a spoofer announcing
//! another key's destination displaces nothing (AV-42: preference, never a
//! substrate reject). The signed replication read serves every row; each
//! receiver folds over its own directory. A key retires its own route by the
//! signed retirement it always had (`retired_at` in a signed put).

use super::self_at_login::TransportDestination;
use super::{Error, FederationDirectory};

/// The refusal a route announced at an `agent`-typed key carries
/// (`Error::InvalidArgument`, Python `ValueError`).
pub const TRANSPORT_DESTINATION_AGENT_KEY: &str = "transport_destination_agent_key";

/// Is `key_id` held here as an `agent`-typed key? `false` when the key is not
/// held: it cannot be typed.
pub async fn is_agent_key<F: FederationDirectory + ?Sized>(
    dir: &F,
    key_id: &str,
) -> Result<bool, Error> {
    Ok(dir.lookup_public_key(key_id).await?.is_some_and(|k| {
        super::types::identity_type::set_contains(
            &k.identity_type,
            super::types::identity_type::AGENT,
        )
    }))
}

/// Refuse a route whose `occurrence_key_id` is an `agent`-typed key.
///
/// # Errors
/// [`Error::InvalidArgument`] carrying [`TRANSPORT_DESTINATION_AGENT_KEY`].
pub async fn check_route_key_not_agent<F: FederationDirectory + ?Sized>(
    dir: &F,
    route: &TransportDestination,
) -> Result<(), Error> {
    if is_agent_key(dir, &route.occurrence_key_id).await? {
        return Err(Error::InvalidArgument(format!(
            "{TRANSPORT_DESTINATION_AGENT_KEY}: {:?} is an agent key; an agent does not announce \
             a route, it is reached through its node's binding (CC 3.4.7.3 Clause A)",
            route.occurrence_key_id
        )));
    }
    Ok(())
}

/// The route an occurrence's transport binding projects, written through the
/// unsigned local door, unless the occurrence key is an agent's: an agent is
/// reached through its node's binding, so its occurrence projects no route.
/// The one projection step every backend's occurrence write takes.
///
/// # Errors
/// A directory read or the put's own error.
pub async fn project_occurrence_route<F: FederationDirectory + ?Sized>(
    dir: &F,
    route: &TransportDestination,
) -> Result<(), Error> {
    if is_agent_key(dir, &route.occurrence_key_id).await? {
        return Ok(());
    }
    dir.put_transport_destination(route).await
}

/// The live owner of `key_id`, or `None` when it has none or more than one.
async fn single_owner<F: FederationDirectory + ?Sized>(
    dir: &F,
    key_id: &str,
) -> Result<Option<String>, Error> {
    match super::admission::owner_of(dir, key_id).await {
        Ok(owner) => Ok(owner),
        Err(Error::AmbiguousNodeOwner { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Is `older` displaced by `newer`: the same destination and kind, a
/// different key, a strictly newer `(epoch, asserted_at)`, and the two keys
/// share one live owner?
async fn displaces<F: FederationDirectory + ?Sized>(
    dir: &F,
    newer: &TransportDestination,
    older: &TransportDestination,
) -> Result<bool, Error> {
    if newer.occurrence_key_id == older.occurrence_key_id
        || newer.transport_kind != older.transport_kind
        || newer.destination != older.destination
        || newer.retired_at.is_some()
        || (newer.epoch, newer.asserted_at) <= (older.epoch, older.asserted_at)
    {
        return Ok(false);
    }
    let Some(a) = single_owner(dir, &newer.occurrence_key_id).await? else {
        return Ok(false);
    };
    Ok(single_owner(dir, &older.occurrence_key_id).await? == Some(a))
}

/// The routes of `rows` no other route displaces, judged against every live
/// route this node holds on each row's destination. Order is kept.
///
/// # Errors
/// A directory read error.
pub async fn fold_one_live_key<F: FederationDirectory + ?Sized>(
    dir: &F,
    rows: Vec<TransportDestination>,
) -> Result<Vec<TransportDestination>, Error> {
    let mut by_destination: std::collections::HashMap<String, Vec<TransportDestination>> =
        std::collections::HashMap::new();
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        if !by_destination.contains_key(&row.destination) {
            let held = dir
                .list_transport_destinations_by_destination_unfolded(&row.destination)
                .await?;
            by_destination.insert(row.destination.clone(), held);
        }
        let mut displaced = false;
        for other in &by_destination[&row.destination] {
            if displaces(dir, other, &row).await? {
                displaced = true;
                break;
            }
        }
        if !displaced {
            out.push(row);
        }
    }
    Ok(out)
}

/// Delete every stored route whose key is `agent`-typed; the count deleted.
///
/// # Errors
/// A directory read or delete error.
pub async fn sweep_agent_routes<F: FederationDirectory + ?Sized>(dir: &F) -> Result<u64, Error> {
    let mut removed = 0u64;
    for route in dir.list_all_transport_destinations_unfolded().await? {
        if is_agent_key(dir, &route.occurrence_key_id).await?
            && dir
                .remove_transport_destination(
                    &route.occurrence_key_id,
                    &route.transport_kind,
                    &route.destination,
                )
                .await?
        {
            removed += 1;
        }
    }
    Ok(removed)
}
