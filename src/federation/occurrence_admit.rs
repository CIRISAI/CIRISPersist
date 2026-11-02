//! v61 (CIRISPersist#934, S4b) — **the identity-occurrence writes, decided
//! once.**
//!
//! `put_identity_occurrence` (the signed door) and
//! `put_identity_occurrence_local` (the trusted-local self-write) were
//! written twice, in `store/{sqlite,postgres}.rs`, with the same gates in the
//! same order. Each door is now one function here; a backend implements
//! [`OccurrenceStore`]: the last-signed-wins upsert, the #930 history, the
//! pair's `identity:occurrence:v1` row, the serve position. It decides
//! nothing.
//!
//! # Which instant each plan reads
//!
//! None: the upsert is ordered by the record's own `asserted_at`.

use super::types::{IdentityOccurrence, SignedIdentityOccurrence};
use super::{Error, FederationDirectory};

/// An occurrence row the plan admitted: its hash derived and its columns
/// encoded.
#[derive(Debug, Clone)]
pub(crate) struct PlannedOccurrence {
    /// The row, `persist_row_hash` set.
    pub(crate) row: IdentityOccurrence,
    /// `pubkey_x25519_base64`.
    pub(crate) enc_x25519: Option<String>,
    /// `pubkey_ml_kem_768_base64`.
    pub(crate) enc_ml_kem: Option<String>,
    /// `transport_binding`, JSON text.
    pub(crate) transport_binding_json: Option<String>,
    /// The signature container (the signed door only).
    pub(crate) signed: Option<PlannedOccurrenceSignature>,
}

/// The signed door's container columns.
#[derive(Debug, Clone)]
pub(crate) struct PlannedOccurrenceSignature {
    /// `attesting_key_id`.
    pub(crate) attesting_key_id: String,
    /// The signed envelope as signed.
    pub(crate) signed_envelope: serde_json::Value,
    /// `signature`, JSON text.
    pub(crate) signature_json: String,
}

/// What the signed upsert did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OccurrenceWrite {
    /// The current-state upsert took the record (it is strictly newer).
    pub(crate) applied: bool,
    /// The pair's `identity:occurrence:v1` row, when applied and the key
    /// plane is present.
    pub(crate) row_id: Option<String>,
}

/// The occurrence executor. Storage only.
#[async_trait::async_trait]
pub(crate) trait OccurrenceStore: FederationDirectory + Sized {
    /// v58.0.0 (#991) — re-home pre-V198 key-plane rows before a key-plane
    /// write.
    async fn rehome_key_plane_before_write(&self) -> Result<(), Error>;

    /// In ONE transaction: the last-signed-wins upsert (strictly newer
    /// `asserted_at` only, at a fresh serve position), the #930 history row
    /// whether or not it applied, the pair's `identity:occurrence:v1` row;
    /// then, when applied, the row's pointer.
    async fn store_planned_occurrence(
        &self,
        planned: PlannedOccurrence,
    ) -> Result<OccurrenceWrite, Error>;

    /// In ONE transaction: the trusted-local upsert, which never mutates a
    /// SIGNED row (#541), and its #930 history row.
    async fn store_planned_local_occurrence(&self, planned: PlannedOccurrence)
        -> Result<(), Error>;

    /// The wire-index entry of the pair's `identity:occurrence:v1` row.
    async fn index_occurrence_row(&self, row_id: Option<&str>) -> Result<(), Error>;
}

/// The device-class and encryption-key gates, the row hash, the column
/// encodings, and the #446 route the binding projects.
fn plan_occurrence(
    mut row: IdentityOccurrence,
    signed: Option<PlannedOccurrenceSignature>,
) -> Result<(PlannedOccurrence, Option<super::TransportDestination>), Error> {
    super::check_device_class(&row.device_class)?;
    super::check_encryption_pubkeys(row.encryption_pubkeys.as_ref())?;
    row.persist_row_hash = super::types::compute_persist_row_hash(&row)?;
    let (enc_x25519, enc_ml_kem) = match &row.encryption_pubkeys {
        Some(k) => (
            Some(k.x25519_base64.clone()),
            Some(k.ml_kem_768_base64.clone()),
        ),
        None => (None, None),
    };
    let transport_binding_json = row
        .transport_binding
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| Error::Backend(format!("transport_binding: {e}")))?;
    // #446 — the binding's route is materialized into the
    // `transport_destinations` read model AFTER the write (only when it
    // applied, for the signed door).
    let projected_route = row
        .transport_binding
        .as_ref()
        .map(|tb| tb.project_route(&row.occurrence_key_id, row.asserted_at))
        .transpose()?;
    Ok((
        PlannedOccurrence {
            row,
            enc_x25519,
            enc_ml_kem,
            transport_binding_json,
            signed,
        },
        projected_route,
    ))
}

/// The door: every backend's `put_identity_occurrence`.
pub(crate) async fn put_identity_occurrence_planned<D: OccurrenceStore>(
    dir: &D,
    occurrence: SignedIdentityOccurrence,
) -> Result<(), Error> {
    // v14.0.0 (CIRISPersist#418) — the hybrid signature over the exact
    // producer envelope, the signer's authority and §5.6.8.8.2 C4 key
    // separation, BEFORE any write. One gate for HTTP and the wire.
    super::admission::verify_signed_identity_occurrence(dir, &occurrence).await?;
    // v59.0.0 (CIRISPersist#1099, CC 3.3.6.3) — a roster change lands by the
    // two-path door or is held as a proposal.
    super::self_roster::gate_occurrence(dir, &occurrence).await?;
    dir.rehome_key_plane_before_write().await?;
    let SignedIdentityOccurrence {
        identity_occurrence: row,
        attesting_key_id,
        signed_envelope,
        signature,
    } = occurrence;
    // v50.0.0 (CIRISPersist#916) — who, through what, for the re-wrap below.
    let rewrap_for = (row.identity_key_id.clone(), row.occurrence_key_id.clone());
    let signature_json =
        serde_json::to_string(&signature).map_err(|e| Error::Backend(format!("signature: {e}")))?;
    let (planned, projected_route) = plan_occurrence(
        row,
        Some(PlannedOccurrenceSignature {
            attesting_key_id,
            signed_envelope,
            signature_json,
        }),
    )?;
    let written = dir.store_planned_occurrence(planned).await?;
    if written.applied {
        if let Some(route) = &projected_route {
            super::transport_routes::project_occurrence_route(dir, route).await?;
        }
        // v58.0.0 (#991) — the pair's row is a wire-index entry too.
        dir.index_occurrence_row(written.row_id.as_deref()).await?;
    }
    // v50.0.0 (CIRISPersist#916) — a member's device occurrence arriving: this
    // node re-wraps its own epochs to it. The row stands whatever the re-wrap
    // does.
    if rewrap_for.0 != rewrap_for.1 {
        super::rewrap_after_admission(dir, &rewrap_for.0, &rewrap_for.1).await;
    }
    Ok(())
}

/// The door: every backend's `put_identity_occurrence_local` (#418, the
/// grandfathered trusted-local write: no signature gate, signed columns
/// NULL, engine-internal self-writes only).
pub(crate) async fn put_identity_occurrence_local_planned<D: OccurrenceStore>(
    dir: &D,
    occurrence: IdentityOccurrence,
) -> Result<(), Error> {
    let (planned, projected_route) = plan_occurrence(occurrence, None)?;
    dir.store_planned_local_occurrence(planned).await?;
    // #446 — the trusted-local path projects too: it is an accepted write.
    if let Some(route) = &projected_route {
        super::transport_routes::project_occurrence_route(dir, route).await?;
    }
    Ok(())
}
