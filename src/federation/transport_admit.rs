//! v61 (CIRISPersist#934, S4b) — **the transport-destination writes, decided
//! once.**
//!
//! `put_transport_destination` (the unsigned route-table put) and
//! `put_signed_transport_destination` (the signed record's admission) were
//! written twice, in `store/{sqlite,postgres}.rs`, with the same gates in the
//! same order. Each door is now one function here; a backend implements
//! [`TransportStore`]: the SQL, the serve position (V130) and the signed wire
//! index. The signed write's verdict against the held row
//! ([`held_destination_verdict`]) is shared: the executor reads the held row
//! and applies the verdict in its write.
//!
//! # Which instant each plan reads
//!
//! None: both writes are judged on the record's own `(epoch, asserted_at)`
//! against the held row's.

use super::self_at_login::{SignedTransportDestination, TransportDestination};
use super::{Error, FederationDirectory, TransportDestinationApplyOutcome as Outcome};

/// An unsigned route-table put the plan admitted, its epoch checked into the
/// stored width.
#[derive(Debug, Clone)]
pub(crate) struct PlannedDestination<'a> {
    /// The destination.
    pub(crate) destination: &'a TransportDestination,
    /// `epoch`, as stored.
    pub(crate) epoch_i64: i64,
}

/// A signed transport destination the plan admitted.
#[derive(Debug, Clone)]
pub(crate) struct PlannedSignedDestination<'a> {
    /// The admitted record.
    pub(crate) signed: &'a SignedTransportDestination,
    /// `signed_envelope`, JSON text.
    pub(crate) envelope_json: String,
    /// `signature`, JSON text.
    pub(crate) signature_json: String,
    /// `epoch`, as stored.
    pub(crate) epoch_i64: i64,
    /// The signed wire index key the record is indexed under.
    pub(crate) wire_index_key: String,
}

/// The row held under `(occurrence_key_id, transport_kind)`, as the signed
/// write found it.
#[derive(Debug, Clone)]
pub(crate) struct HeldDestination {
    /// The typed row (retired rows included: a tombstone keeps winning).
    pub(crate) destination: TransportDestination,
    /// Whether the held row is itself signed.
    pub(crate) signed: bool,
    /// The held row's signed envelope, JSON text.
    pub(crate) envelope: Option<String>,
}

/// What the signed write does against the held row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DestinationVerdict {
    /// Answer without writing.
    Answer(Outcome),
    /// Write; `fresh` when no row was held.
    Write {
        /// No row was held under the key.
        fresh: bool,
    },
}

/// **The signed write's verdict against the held row**, asked by the
/// executor between its read and its write.
///
/// - v21.4.0 (#515) — SIGNED WINS THE SHARED KEY: the monotonic-clock refusal
///   applies only against a held row that is itself signed; a signed write
///   always reclaims an unsigned row.
/// - v56.0.0 (#1077) — the transit KEX pair is envelope-only: an equal typed
///   projection is `Unchanged` only when the held envelope carries the same
///   pair; a same-clock re-sign that changes it is refused.
#[must_use]
pub(crate) fn held_destination_verdict(
    signed: &SignedTransportDestination,
    held: Option<&HeldDestination>,
) -> DestinationVerdict {
    let d = &signed.transport_destination;
    let Some(held) = held else {
        return DestinationVerdict::Write { fresh: true };
    };
    let ex = &held.destination;
    let same_pair = held
        .envelope
        .as_deref()
        .and_then(|e| serde_json::from_str::<serde_json::Value>(e).ok())
        .is_some_and(|stored| {
            super::self_at_login::same_transit_kex_member(&stored, &signed.signed_envelope)
        });
    if ex == d && held.signed && same_pair {
        return DestinationVerdict::Answer(Outcome::Unchanged);
    }
    if held.signed && (d.epoch, d.asserted_at) <= (ex.epoch, ex.asserted_at) {
        return DestinationVerdict::Answer(Outcome::Refused {
            reason: format!(
                "incoming (epoch {}, asserted_at {}) does not supersede stored SIGNED (epoch {}, \
                 asserted_at {})",
                d.epoch,
                d.asserted_at.to_rfc3339(),
                ex.epoch,
                ex.asserted_at.to_rfc3339()
            ),
        });
    }
    DestinationVerdict::Write { fresh: false }
}

/// **A stored row's `binding_provenance`, read back** — every backend's
/// transport row mapper asks this. An absent token (NULL, a pre-#413 row) is
/// the back-compat `Rooted`; v52.0.0 — a present token that is neither
/// `rooted` nor `advisory` refuses (malformed is a refusal, not absence).
/// The backend maps the refusal into its row decoder's error.
pub(crate) fn stored_binding_provenance(
    token: Option<&str>,
) -> Result<super::self_at_login::BindingProvenance, Error> {
    let provenance = super::self_at_login::BindingProvenance::from_token(token)?;
    Ok(provenance)
}

/// The transport executor. Storage only.
#[async_trait::async_trait]
pub(crate) trait TransportStore: FederationDirectory + Sized {
    /// The monotonic unsigned upsert (#443), which never demotes a signed
    /// row and on one advances only `last_seen_at` (#515, #541).
    async fn store_planned_destination(&self, planned: PlannedDestination<'_>)
        -> Result<(), Error>;

    /// Read the held row, apply [`held_destination_verdict`], write the
    /// signed row at a fresh serve position when it says so, then index it.
    async fn store_planned_signed_destination(
        &self,
        planned: PlannedSignedDestination<'_>,
    ) -> Result<Outcome, Error>;
}

fn stored_epoch(epoch: u64) -> Result<i64, Error> {
    i64::try_from(epoch)
        .map_err(|_| Error::InvalidArgument("transport_destination epoch exceeds i64".into()))
}

/// The door: every backend's `put_transport_destination`.
pub(crate) async fn put_transport_destination_planned<D: TransportStore>(
    dir: &D,
    destination: &TransportDestination,
) -> Result<(), Error> {
    // v61 (CIRISPersist#1122) — an agent announces no route.
    super::transport_routes::check_route_key_not_agent(dir, destination).await?;
    let epoch_i64 = stored_epoch(destination.epoch)?;
    dir.store_planned_destination(PlannedDestination {
        destination,
        epoch_i64,
    })
    .await
}

/// The door: every backend's `put_signed_transport_destination`.
pub(crate) async fn put_signed_transport_destination_planned<D: TransportStore>(
    dir: &D,
    signed: &SignedTransportDestination,
) -> Result<Outcome, Error> {
    // v52.0.0 (CIRISPersist#672) — a re-offer of a held record settles here,
    // before any verification.
    if super::replication_policy::settle_if_held(
        dir,
        super::replication_policy::EnvelopeKind::TransportDestination,
        signed,
    )
    .await?
    {
        return Ok(Outcome::Unchanged);
    }
    // #443 — the admission gate BEFORE any write: hybrid 1-of-1 over
    // JCS(signed_envelope) against the pinned key of attesting_key_id, typed
    // projection ≡ envelope, signer_acts_for.
    super::admission::verify_signed_transport_destination(dir, signed).await?;
    // v59.0.0 (CIRISPersist#1106, CC 5.3.4) — a seated serve node's
    // bundle-pinned transit pair rotates by holder quorum, not alone.
    super::transport_rebind::check_serve_rotation(dir, signed).await?;
    let d = &signed.transport_destination;
    let envelope_json = serde_json::to_string(&signed.signed_envelope)
        .map_err(|e| Error::Backend(format!("signed_envelope: {e}")))?;
    let signature_json = serde_json::to_string(&signed.signature)
        .map_err(|e| Error::Backend(format!("signature: {e}")))?;
    let epoch_i64 = stored_epoch(d.epoch)?;
    // v21.1.0 (CIRISPersist#507b) — the stored row is byte-identical to
    // `signed`, so `signed` IS the value the signed read re-serializes.
    let wire_index_key = super::wire_index::record_key(&[
        ("occurrence_key_id", &d.occurrence_key_id),
        ("transport_kind", &d.transport_kind),
    ]);
    dir.store_planned_signed_destination(PlannedSignedDestination {
        signed,
        envelope_json,
        signature_json,
        epoch_i64,
        wire_index_key,
    })
    .await
}
