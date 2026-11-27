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
    /// v62.0.0 (wave O1; the CC 2.7 ruling) — an edition-2 bind's roster
    /// receipt, `(row id hex, identity)`: the transaction-level write
    /// records it LANDED (`lands_quorum`, first-settled wins), so the door's
    /// landing and the genesis import (a seat binding is landed by
    /// definition) both leave a receipt the next roster row's head can name.
    pub(crate) roster_row: Option<(String, String)>,
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
    /// In ONE transaction: the last-signed-wins upsert (strictly newer
    /// `asserted_at` only, at a fresh serve position), the #930 history row
    /// whether or not it applied, the pair's `identity:occurrence:v1` row;
    /// then, when applied, the row's pointer.
    async fn store_planned_occurrence(
        &self,
        planned: PlannedOccurrence,
    ) -> Result<OccurrenceWrite, Error>;

    /// In ONE transaction: the trusted-local upsert, which never mutates a
    /// SIGNED row (#541), and its #930 history row. v62.0.0 (WD-fix9): the
    /// storage of the TEST seam only (the trusted-local verb is retired).
    #[cfg_attr(not(test), allow(dead_code))]
    async fn store_planned_local_occurrence(&self, planned: PlannedOccurrence)
        -> Result<(), Error>;

    /// The wire-index entry of the pair's `identity:occurrence:v1` row.
    async fn index_occurrence_row(&self, row_id: Option<&str>) -> Result<(), Error>;

    /// v62.0.0 (wave O1) — in ONE transaction: an edition-2 bind's
    /// last-signed-wins upsert (strictly newer `asserted_at` only, at a fresh
    /// serve position), `attesting_key_id` and `signed_envelope` from
    /// `planned.signed`, `signature` NULL, and its #930 history row whether
    /// or not it applied. No earlier-form `identity:occurrence:v1` row is
    /// minted: the bind is its edition-2 statements. Returns whether the
    /// upsert took the record.
    async fn store_edition2_occurrence(&self, planned: PlannedOccurrence) -> Result<bool, Error>;
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
    // v62.0.0 (wave O1; E8's finding) — an occurrence already out of its
    // half-open window at write projects no route (the read side filters
    // one that expires later: `transport_routes::fold_one_live_key`).
    // The end of the half-open window only: an assertion stamped within the
    // clock-skew tolerance ahead of now still projects.
    let now = crate::host::clock::now();
    let in_window = row.valid_until.is_none_or(|u| now < u);
    let projected_route = row
        .transport_binding
        .as_ref()
        .filter(|_| in_window)
        .map(|tb| tb.project_route(&row.occurrence_key_id, row.asserted_at))
        .transpose()?;
    Ok((
        PlannedOccurrence {
            row,
            enc_x25519,
            enc_ml_kem,
            transport_binding_json,
            signed,
            roster_row: None,
        },
        projected_route,
    ))
}

/// The door: every backend's `put_identity_occurrence`.
pub(crate) async fn put_identity_occurrence_planned<D: OccurrenceStore>(
    dir: &D,
    occurrence: SignedIdentityOccurrence,
) -> Result<(), Error> {
    // v62.0.0 (WD-fix7) — refused by name, pointing at the edition-2 path:
    // a device joins or leaves a self's roster only by its edition-2
    // statement (the earlier-form roster gate and its proposal row are
    // retired).
    super::edition2::door::refuse_earlier_form("identity_occurrence").map_err(|_| {
        Error::malformed_row(
            "identity_occurrence",
            super::edition2::token::EARLIER_FORM_OBJECT,
            "a signed identity_occurrence object (the earlier form, CC 8.11): a node of this \
             form binds or evicts a device only by its edition-2 statement, an \
             `identity:occurrence` bind or an `identity:occurrence_revocation`, put through \
             the statement door (`Engine::put_edition2_statement`, or a hardware signer's \
             `Engine::statement_draft` + `Engine::submit_voice`); CC 2.6.1.12, 3.3.6.4"
                .to_owned(),
        )
    })?;
    // v62.0.0 (wave O1) — the identity-set exclusion on every occurrence
    // door: no machine key under a person, no person key under a machine
    // (`occurrence_mixes_person_and_machine`), as the edition-2 door.
    super::edition2::occurrence::check_identity_set_exclusion(
        dir,
        &occurrence.identity_occurrence.identity_key_id,
        &occurrence.identity_occurrence.occurrence_key_id,
        &occurrence.identity_occurrence.device_class,
    )
    .await?;
    // v14.0.0 (CIRISPersist#418) — the hybrid signature over the exact
    // producer envelope, the signer's authority and §5.6.8.8.2 C4 key
    // separation, BEFORE any write. One gate for HTTP and the wire.
    super::admission::verify_signed_identity_occurrence(dir, &occurrence).await?;
    // v62.0.0 (WD-fix7) — the earlier-form roster gate is retired with the
    // door above it: a roster change is an edition-2 `identity:occurrence`
    // bind (`self_roster::gate_edition2`).
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

/// The storage of every backend's `test_seam_put_identity_occurrence`
/// (v62.0.0 WD-fix9: the retired #418 trusted-local write, kept for tests
/// only: no signature gate, signed columns NULL).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn put_identity_occurrence_local_planned<D: OccurrenceStore>(
    dir: &D,
    occurrence: IdentityOccurrence,
) -> Result<(), Error> {
    // v62.0.0 (wave O1) — the trusted-local door keeps the identity-set
    // exclusion too: a local write binds no machine key under a person and
    // no person key under a machine (`occurrence_mixes_person_and_machine`).
    super::edition2::occurrence::check_identity_set_exclusion(
        dir,
        &occurrence.identity_key_id,
        &occurrence.occurrence_key_id,
        &occurrence.device_class,
    )
    .await?;
    let (planned, projected_route) = plan_occurrence(occurrence, None)?;
    dir.store_planned_local_occurrence(planned).await?;
    // #446 — the trusted-local path projects too: it is an accepted write.
    if let Some(route) = &projected_route {
        super::transport_routes::project_occurrence_route(dir, route).await?;
    }
    Ok(())
}

/// v62.0.0 (wave O1) — the route an accepted occurrence projects into
/// `transport_destinations` (#446): written AFTER the occurrence's own
/// transaction commits ([`after_edition2_occurrence`]).
pub(crate) type ProjectedRoute = super::TransportDestination;

/// v62.0.0 (wave O1; C1's atomic genesis import) — **the edition-2 bind's
/// plan, pure**: the JSON door's plan (device class, encryption keys, the
/// row hash, the route), with the bind's author and its statements as the
/// stored container. No I/O. The writes are the backends' tx-level helpers
/// (`sqlite::sqlite_store_edition2_occurrence`,
/// `PostgresBackend::pg_store_edition2_occurrence`), which a caller runs
/// inside its own transaction; the follow-on steps are
/// [`after_edition2_occurrence`], after that transaction commits.
///
/// # Errors
/// `federation_device_class_rejected`; a malformed encryption key; the row
/// hash or route encoding.
pub(crate) fn plan_edition2_occurrence(
    bind: super::edition2::occurrence::OccurrenceBind,
) -> Result<(PlannedOccurrence, Option<ProjectedRoute>), Error> {
    let envelope = bind.envelope();
    let super::edition2::occurrence::OccurrenceBind {
        occurrence: row,
        author_key_id,
        row_id,
        ..
    } = bind;
    let roster_row = Some((row_id.hex(), row.identity_key_id.clone()));
    let (mut planned, route) = plan_occurrence(
        row,
        Some(PlannedOccurrenceSignature {
            attesting_key_id: author_key_id,
            signed_envelope: envelope,
            // Not written: the bind's authority is its held statements.
            signature_json: String::new(),
        }),
    )?;
    planned.roster_row = roster_row;
    Ok((planned, route))
}

/// v62.0.0 (SR-fix1) — **does the held occurrence of the pair project
/// exactly `route`?** The row held under `(identity, occurrence)` carries a
/// transport binding whose projection at the row's own `asserted_at` equals
/// `route` in every member, and the row is inside its half-open window now
/// (the write-side rule of [`plan_occurrence`]). A held row that is newer or
/// carries another binding projects another route and answers `false`: a
/// stale offer re-projects nothing.
///
/// # Errors
/// The directory read.
async fn held_occurrence_projects<D: FederationDirectory + ?Sized>(
    dir: &D,
    identity: &str,
    occurrence: &str,
    route: &ProjectedRoute,
) -> Result<bool, Error> {
    let now = crate::host::clock::now();
    Ok(dir
        .list_identity_occurrences_by_occurrence_key(occurrence)
        .await?
        .iter()
        .filter(|o| o.identity_key_id == identity)
        .any(|o| {
            o.valid_until.is_none_or(|u| now < u)
                && o.transport_binding.as_ref().is_some_and(|tb| {
                    tb.project_route(&o.occurrence_key_id, o.asserted_at)
                        .is_ok_and(|p| p == *route)
                })
        }))
}

/// v62.0.0 (wave O1) — **what follows an edition-2 bind's commit**, never
/// inside a transaction: the route projection, and when the upsert
/// `applied` the owner's epoch re-wrap (`identity != occurrence` only; a
/// genesis seat's self pair has none).
///
/// v62.0.0 (SR-fix1; I2111, I2113) — the route is projected when the upsert
/// `applied`, and also when it did not apply but the HELD occurrence of the
/// pair projects exactly this route ([`held_occurrence_projects`]). The
/// projection runs after the commit, so a failure or a crash between the two
/// leaves the occurrence held with no route; the same statement offered
/// again does not apply (the upsert takes a strictly newer record only), and
/// before this fix nothing projected its route again. The projection is the
/// route table's monotonic upsert (`put_transport_destination`: a write
/// applies only at a strictly newer `(epoch, asserted_at)`), so repeating it
/// over a held route changes nothing and it never replaces a newer route
/// (I2112). The agent-key and ended-window skips are unchanged
/// ([`super::transport_routes::project_occurrence_route`],
/// [`plan_occurrence`]).
///
/// # Errors
/// The held occurrence's read; the route projection's write.
pub(crate) async fn after_edition2_occurrence<D: FederationDirectory + ?Sized>(
    dir: &D,
    applied: bool,
    identity: &str,
    occurrence: &str,
    route: Option<&ProjectedRoute>,
) -> Result<(), Error> {
    if let Some(route) = route {
        if applied || held_occurrence_projects(dir, identity, occurrence, route).await? {
            super::transport_routes::project_occurrence_route(dir, route).await?;
        }
    }
    if applied && identity != occurrence {
        super::rewrap_after_admission(dir, identity, occurrence).await;
    }
    Ok(())
}

/// v62.0.0 (SR-fix2; I2111) — **project again the route of every occurrence
/// held under `occurrence`**: each held row inside its half-open window now
/// (the write-side rule of [`plan_occurrence`]) that carries a transport
/// binding projects its route at its own `asserted_at`, through the same
/// step a fresh write takes
/// ([`super::transport_routes::project_occurrence_route`]: no route for an
/// agent key). For a caller whose offer wrote no occurrence because the bind
/// is already held (the genesis import skips a named row it holds), so
/// [`after_edition2_occurrence`] never runs for it. The projection is the
/// route table's monotonic upsert: over a held route it changes nothing,
/// and it never replaces a newer route (I2112).
///
/// # Errors
/// The held occurrences' read; a binding's route encoding; the projection's
/// write.
pub(crate) async fn reproject_held_occurrence_routes<D: FederationDirectory + ?Sized>(
    dir: &D,
    occurrence: &str,
) -> Result<(), Error> {
    let now = crate::host::clock::now();
    for o in dir
        .list_identity_occurrences_by_occurrence_key(occurrence)
        .await?
    {
        if !o.valid_until.is_none_or(|u| now < u) {
            continue;
        }
        if let Some(tb) = &o.transport_binding {
            let route = tb.project_route(&o.occurrence_key_id, o.asserted_at)?;
            super::transport_routes::project_occurrence_route(dir, &route).await?;
        }
    }
    Ok(())
}

/// v62.0.0 (wave O1; CC 3.3.6) — the door's write: every backend's
/// `put_identity_occurrence_edition2`. The gates ran in
/// [`super::edition2::occurrence::put_occurrence_voice`]; this plans
/// ([`plan_edition2_occurrence`]), writes in the backend's own transaction
/// (`store_edition2_occurrence`, which wraps the tx-level helper), then runs
/// [`after_edition2_occurrence`].
pub(crate) async fn put_identity_occurrence_edition2_planned<D: OccurrenceStore>(
    dir: &D,
    bind: super::edition2::occurrence::OccurrenceBind,
) -> Result<bool, Error> {
    let pair = (
        bind.occurrence.identity_key_id.clone(),
        bind.occurrence.occurrence_key_id.clone(),
    );
    let (planned, route) = plan_edition2_occurrence(bind)?;
    let applied = dir.store_edition2_occurrence(planned).await?;
    after_edition2_occurrence(dir, applied, &pair.0, &pair.1, route.as_ref()).await?;
    Ok(applied)
}
