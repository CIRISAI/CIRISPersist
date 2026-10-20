//! v59.0.0 (CIRISPersist#1106; CC 5.3.4 rc9 `0edac07`, CC 3.3.6.2) — **a
//! seated serve node's transit pair rotates by holder quorum, not alone.**
//!
//! The pinned genesis bundle (version ≥ 4) carries each seated serve node's
//! signed transport destination, and the open seeds it `Rooted`
//! ([`genesis::seed_serve_transport_destinations`](super::genesis::seed_serve_transport_destinations)).
//! A rotation of that pair is a QUORUM act: the accord holders' canonical
//! address update.
//!
//! # The quorum re-bind
//!
//! The update is an attestation row, [`REBIND_DIMENSION`] (`scores`,
//! federation tier and scope), attested ABOUT the serve node, authored by an
//! accord holder and cosigned by others in `additional_scrubs` — every scrub
//! over the same canonical envelope, which the generic federation-tier verify
//! already checks one by one. Its envelope carries, under
//! [`REBIND_MEMBER`], the node's own new signed transport destination. It is
//! admitted ([`check_rebind_admission`]) when:
//!
//! - the node is a seated serve node of the pinned bundle;
//! - the carried row is the node's own (`signer_acts_for`, its hybrid
//!   signature, the in-row separation rule — the ordinary transport door's
//!   checks, [`admission::verify_signed_transport_destination`](super::admission::verify_signed_transport_destination));
//! - the row's distinct, verified accord-holder signers reach the accord
//!   family charter's threshold (`trust_root::family_quorum_over`: the
//!   family's `consensus_protocol`, floored at a strict majority of the
//!   node's OWN roster — never hardcoded).
//!
//! Otherwise it is refused [`REBIND_WITHOUT_HOLDER_QUORUM`]. An admitted
//! re-bind applies the carried row through the ordinary transport door, where
//! it SUPERSEDES the bundle-seeded binding by the monotonic
//! `(epoch, asserted_at)` apply. The re-bind replicates like any attestation
//! row (global reach), so every node that holds the root re-binds.
//!
//! # The unilateral rotation is refused
//!
//! [`check_serve_rotation`] (run by the transport door): while a seated serve
//! node's live binding of a kind still carries the pair the pinned bundle
//! pinned for it (or it holds none yet), a row signed by the node alone that
//! would replace that pair — a different pair, no pair, or a retirement — is
//! refused [`SERVE_TRANSIT_PAIR_ROTATION_BEFORE_REBIND`], unless a held,
//! admitted re-bind carries exactly that row. Re-asserting the pinned pair
//! (the open's seed, a new epoch with the same pair) is unaffected, and a node
//! that is not a seated serve node is unaffected.
//!
//! # The resolver during supersession
//!
//! One live binding per `(occurrence_key_id, transport_kind)`: the re-bind's
//! row supersedes the bundle-seeded row in that slot (the seeded row is no
//! longer live), so `self_at_login::transit_kex_pair_for` never sees the
//! pinned pair and the re-bound pair live at once. A pinned row offered again
//! later (a re-open) is `Refused` by the same apply — it is older.
//!
//! **State used:** "seated serve node" is the PINNED bundle this build reads
//! (`genesis::canonical_genesis_bundle`: its `serve_nodes` and
//! `serve_transport_destinations`), not a directory fold.

use super::self_at_login::{SignedTransportDestination, TransitKexPair};
use super::types::{attestation_type, Attestation};
use super::{Error, FederationDirectory};

/// The re-bind row's dimension (persist-named; CC 5.3.4 names the act, the
/// holders' accord-signed canonical address update).
pub const REBIND_DIMENSION: &str = "transport:canonical_rebind:v1";
/// The envelope member the node's new signed transport destination rides
/// under.
pub const REBIND_MEMBER: &str = "transport_destination";
/// The refusal token of a re-bind row without the holder quorum
/// (`Error::InvalidArgument`, Python `ValueError`).
pub const REBIND_WITHOUT_HOLDER_QUORUM: &str = "transport_rebind_without_holder_quorum";
/// The refusal token of a seated serve node's UNILATERAL rotation that would
/// retire its bundle-pinned transit pair before a quorum re-bind is held
/// (`Error::InvalidArgument`, Python `ValueError`).
pub const SERVE_TRANSIT_PAIR_ROTATION_BEFORE_REBIND: &str =
    "serve_transit_pair_rotation_before_rebind";

/// Is `row` a re-bind (by its signed dimension)?
#[must_use]
pub fn is_rebind_row(row: &Attestation) -> bool {
    row.attestation_type == attestation_type::SCORES
        && super::admission::envelope_dimension(&row.attestation_envelope) == Some(REBIND_DIMENSION)
}

/// The signed transport destination a re-bind row carries.
#[must_use]
pub fn carried_row(row: &Attestation) -> Option<SignedTransportDestination> {
    if !is_rebind_row(row) {
        return None;
    }
    serde_json::from_value(row.attestation_envelope.get(REBIND_MEMBER)?.clone()).ok()
}

/// The pinned bundle's transport row for a seated serve node's `kind`, if the
/// node is seated and the bundle pinned one.
fn pinned_row(occurrence_key_id: &str, kind: &str) -> Option<&'static SignedTransportDestination> {
    let bundle = super::genesis::canonical_genesis_bundle();
    if !bundle
        .serve_nodes
        .iter()
        .any(|n| n.record.key_id == occurrence_key_id)
    {
        return None;
    }
    bundle.serve_transport_destinations.iter().find(|r| {
        r.transport_destination.occurrence_key_id == occurrence_key_id
            && r.transport_destination.transport_kind == kind
    })
}

fn pair_of(row: &SignedTransportDestination) -> Result<Option<TransitKexPair>, Error> {
    if row.transport_destination.retired_at.is_some() {
        return Ok(None);
    }
    row.rooted_transit_kex_pair()
}

/// **The re-bind's admission rule** (run by `put_attestation` on every
/// backend; a no-op off the dimension).
///
/// # Errors
///
/// [`REBIND_WITHOUT_HOLDER_QUORUM`] without the quorum (or for a node that is
/// not a seated serve node, or a carried row that is not its own); the
/// transport door's refusals of the carried row.
pub async fn check_rebind_admission<D>(dir: &D, row: &Attestation) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    if !is_rebind_row(row) {
        return Ok(());
    }
    let refuse = |why: String| {
        Error::InvalidArgument(format!(
            "{REBIND_WITHOUT_HOLDER_QUORUM}: re-bind row {}: {why} (CC 5.3.4, CIRISPersist#1106)",
            row.attestation_id
        ))
    };
    let carried = carried_row(row).ok_or_else(|| {
        refuse(format!(
            "carries no readable `{REBIND_MEMBER}` signed transport destination"
        ))
    })?;
    let node = &carried.transport_destination.occurrence_key_id;
    if *node != row.attested_key_id {
        return Err(refuse(format!(
            "the carried row is about {node:?}, the re-bind about {:?}",
            row.attested_key_id
        )));
    }
    let bundle = super::genesis::canonical_genesis_bundle();
    if !bundle.serve_nodes.iter().any(|n| n.record.key_id == *node) {
        return Err(refuse(format!(
            "{node:?} is not a seated serve node of the pinned bundle"
        )));
    }
    super::admission::verify_signed_transport_destination(dir.as_dyn_directory(), &carried).await?;
    let Some(family) = dir
        .lookup_family(ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID)
        .await?
    else {
        return Err(refuse(
            "this node holds no accord family to count against".into(),
        ));
    };
    let quorum =
        super::trust_root::family_quorum_over(dir.as_dyn_directory(), row, &family).await?;
    if quorum.distinct_holders < quorum.required {
        return Err(refuse(format!(
            "{} distinct verified accord holder(s) signed it; the charter requires {}",
            quorum.distinct_holders, quorum.required
        )));
    }
    Ok(())
}

/// After an admitted re-bind: apply the carried row through the ordinary
/// transport door, where it supersedes the bundle-seeded binding.
///
/// # Errors
///
/// The transport door's refusal; a backend error.
pub(crate) async fn after_admission<D>(dir: &D, row: &Attestation) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    if let Some(carried) = carried_row(row) {
        dir.put_signed_transport_destination(&carried).await?;
    }
    Ok(())
}

/// **The unilateral-rotation rule** (the transport door asks it after the
/// row's own checks): see the module doc.
///
/// # Errors
///
/// [`SERVE_TRANSIT_PAIR_ROTATION_BEFORE_REBIND`].
pub async fn check_serve_rotation(
    dir: &dyn FederationDirectory,
    signed: &SignedTransportDestination,
) -> Result<(), Error> {
    let td = &signed.transport_destination;
    let Some(pinned) = pinned_row(&td.occurrence_key_id, &td.transport_kind) else {
        return Ok(());
    };
    let pinned_pair = pair_of(pinned)?;
    let incoming = pair_of(signed)?;
    if incoming == pinned_pair {
        return Ok(());
    }
    // The live binding of this kind: does it still carry the pinned pair?
    let live = dir
        .list_signed_transport_destinations_for(&td.occurrence_key_id)
        .await?
        .into_iter()
        .find(|b| {
            b.transport_destination.transport_kind == td.transport_kind
                && b.transport_destination.retired_at.is_none()
        });
    let live_pair = match &live {
        Some(b) => pair_of(b)?,
        None => pinned_pair.clone(),
    };
    if live_pair != pinned_pair {
        // A replacement is already Rooted (a quorum re-bind landed).
        return Ok(());
    }
    // A held re-bind carrying exactly this row authorizes it.
    let mut pages = super::attestation_query::AttestationQuery::to(
        &td.occurrence_key_id,
        super::attestation_query::FOLD_PAGE,
    )
    .types(&[attestation_type::SCORES])
    .dimension(REBIND_DIMENSION)
    .pages();
    while let Some(page) = pages.next(dir).await? {
        if page
            .iter()
            .filter_map(carried_row)
            .any(|c| c.signed_envelope == signed.signed_envelope)
        {
            return Ok(());
        }
    }
    Err(Error::InvalidArgument(format!(
        "{SERVE_TRANSIT_PAIR_ROTATION_BEFORE_REBIND}: {} is a seated serve node whose \
         {} transit pair the pinned genesis bundle carries; a rotation signed by the node \
         alone would retire it before a replacement is Rooted — rotate by the holders' \
         quorum re-bind (`{REBIND_DIMENSION}`, CC 5.3.4)",
        td.occurrence_key_id, td.transport_kind
    )))
}
