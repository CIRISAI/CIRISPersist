//! v59.0.0 (CIRISPersist#1106; CC 5.3.4 rc9 `0edac07`) — **the AMEND
//! ceremony: a pinned bundle plus the serve nodes' transport rows, authorized
//! by the charter's quorum.**
//!
//! A full ceremony ([`super::ceremony`]) is unanimity: every holder signs
//! every item. An amend changes nothing a full ceremony decides — the
//! charter, the grants, the roster, the heads — it only adds the v4 member
//! [`GenesisBundle::serve_transport_destinations`]. So its one signing item is
//! the authorization over the new [`authorization_digest`], and it finishes at
//! exactly what [`verify_bundle_quorum`](super::verify_bundle_quorum) needs:
//! `max(charter M, strict_majority(roster))` DISTINCT holder authorizations.
//!
//! - **Input**: the pinned bundle's JSON, verified first with the existing
//!   doors ([`verify_ceremony_outputs`](super::verify_ceremony_outputs)), and
//!   the serve nodes' signed transport destinations.
//! - **Output**: a v4 bundle whose `family_key_id`, `holders`, `serve_nodes`,
//!   `consensus_protocol`, `attestations`, roster records and `produced_at`
//!   are the pinned input's BYTE FOR BYTE, plus the new member and the
//!   authorizations; then [`AmendState::finish`] runs
//!   `verify_ceremony_outputs` over it.
//! - **Refused**: [`AMEND_CARRIED_BYTES_CHANGED`] when a carried member differs
//!   from the pinned input (the charter, grants, roster and heads need the full
//!   ceremony); [`AMEND_QUORUM_NOT_MET`] below the distinct-holder threshold.

use super::bundle::{
    authorization_digest, parse_genesis_bundle, parse_quorum, GenesisAuthorization, GenesisBundle,
    SERVE_TRANSPORT_DESTINATIONS_VERSION,
};
use crate::federation::self_at_login::SignedTransportDestination;

/// Refusal token: a carried member of the amended bundle is not the pinned
/// input's, byte for byte.
pub const AMEND_CARRIED_BYTES_CHANGED: &str = "genesis_amend_carried_bytes_changed";
/// Refusal token: fewer distinct holder authorizations than the charter needs.
pub const AMEND_QUORUM_NOT_MET: &str = "genesis_amend_quorum_not_met";
/// Refusal token: the pinned input does not verify, or an authorization does
/// not (a non-holder, a bad signature).
pub const AMEND_INPUT_REFUSED: &str = "genesis_amend_input_refused";

/// Why an amend refused; `token` is one of the module's constants.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{token}: {detail}")]
pub struct AmendRefused {
    /// The stable token.
    pub token: &'static str,
    /// The finding.
    pub detail: String,
}

fn refused(token: &'static str, detail: impl Into<String>) -> AmendRefused {
    AmendRefused {
        token,
        detail: detail.into(),
    }
}

/// The members an amend carries byte for byte.
fn carried(b: &GenesisBundle) -> Result<serde_json::Value, AmendRefused> {
    let v = |x: serde_json::Result<serde_json::Value>| {
        x.map_err(|e| refused(AMEND_INPUT_REFUSED, format!("encode: {e}")))
    };
    Ok(serde_json::json!({
        "family_key_id": b.family_key_id,
        "holders": v(serde_json::to_value(&b.holders))?,
        "serve_nodes": v(serde_json::to_value(&b.serve_nodes))?,
        "consensus_protocol": b.consensus_protocol,
        "attestations": v(serde_json::to_value(&b.attestations))?,
        "roster_records": v(serde_json::to_value(&b.roster_records))?,
        "produced_at": b.produced_at,
    }))
}

/// An amend in progress.
#[derive(Debug, Clone)]
pub struct AmendState {
    /// The pinned input, as given.
    pinned_json: String,
    /// The carried copy the amended bundle is built from.
    pub base: GenesisBundle,
    /// The member the amend adds.
    pub serve_transport_destinations: Vec<SignedTransportDestination>,
    /// Every authorization received (a holder may resend; the count is of
    /// DISTINCT holders).
    pub authorizations: Vec<GenesisAuthorization>,
}

/// What a finished amend produced.
#[derive(Debug, Clone)]
pub struct AmendFinished {
    /// The v4 bundle.
    pub bundle: GenesisBundle,
    /// The bundle as the JSON a node bakes.
    pub bundle_json: String,
    /// What the ordinary doors admitted.
    pub verified: super::CeremonyOutputsVerified,
}

impl AmendState {
    /// Start an amend: verify the pinned bundle with the existing doors, then
    /// hold it and the new member.
    ///
    /// # Errors
    ///
    /// [`AMEND_INPUT_REFUSED`] when the pinned input does not verify or does
    /// not parse.
    /// `scratch` provisions the directory the doors run on (any backend:
    /// [`GenesisScratch`](super::scratch::GenesisScratch)).
    pub async fn plan(
        pinned_json: &str,
        serve_transport_destinations: Vec<SignedTransportDestination>,
        scratch: &dyn super::scratch::GenesisScratch,
    ) -> Result<Self, AmendRefused> {
        super::verify_ceremony_outputs(pinned_json, scratch)
            .await
            .map_err(|e| refused(AMEND_INPUT_REFUSED, format!("the pinned bundle: {e}")))?;
        let base = parse_genesis_bundle(pinned_json)
            .map_err(|e| refused(AMEND_INPUT_REFUSED, e.to_string()))?;
        Ok(Self {
            pinned_json: pinned_json.to_owned(),
            base,
            serve_transport_destinations,
            authorizations: Vec::new(),
        })
    }

    /// The amended bundle, unauthorized: the carried members, version 4, the
    /// new member.
    #[must_use]
    pub fn unsigned(&self) -> GenesisBundle {
        let mut b = self.base.clone();
        b.version = SERVE_TRANSPORT_DESTINATIONS_VERSION.max(b.version);
        b.serve_transport_destinations = self.serve_transport_destinations.clone();
        b.authorizations = Vec::new();
        b
    }

    /// The one signing item: the bytes each holder's authorization signs.
    ///
    /// # Errors
    ///
    /// [`AMEND_INPUT_REFUSED`] if the digest cannot be computed.
    pub fn authz_bytes(&self) -> Result<Vec<u8>, AmendRefused> {
        authorization_digest(&self.unsigned())
            .map_err(|e| refused(AMEND_INPUT_REFUSED, e.to_string()))
    }

    /// The distinct holder authorizations the amend needs:
    /// `max(charter M, strict_majority(roster))`, as `verify_bundle_quorum`.
    #[must_use]
    pub fn needed(&self) -> usize {
        let m = parse_quorum(&self.base.consensus_protocol).map_or(usize::MAX, |(m, _)| m);
        m.max(ciris_verify_core::accord_genesis::strict_majority(
            self.base.holders.len(),
        ))
    }

    /// Add one holder's authorization: the holder is one of the bundle's, and
    /// its hybrid signature verifies over [`Self::authz_bytes`] against the
    /// carried record's keys.
    ///
    /// # Errors
    ///
    /// [`AMEND_INPUT_REFUSED`].
    pub fn add_authorization(&mut self, auth: GenesisAuthorization) -> Result<(), AmendRefused> {
        let holder = self
            .base
            .holders
            .iter()
            .find(|h| h.record.key_id == auth.holder_key_id)
            .ok_or_else(|| {
                refused(
                    AMEND_INPUT_REFUSED,
                    format!("{} is not one of the bundle's holders", auth.holder_key_id),
                )
            })?;
        crate::verify::hybrid::verify_hybrid(
            &self.authz_bytes()?,
            &auth.signature_classical,
            Some(&auth.signature_pqc),
            &holder.record.pubkey_ed25519_base64,
            holder.record.pubkey_ml_dsa_65_base64.as_deref(),
            crate::verify::hybrid::HybridPolicy::Strict,
            None,
        )
        .map_err(|e| {
            refused(
                AMEND_INPUT_REFUSED,
                format!(
                    "{}: the authorization does not verify: {e}",
                    auth.holder_key_id
                ),
            )
        })?;
        self.authorizations.push(auth);
        Ok(())
    }

    fn distinct(&self) -> Vec<GenesisAuthorization> {
        let mut seen = std::collections::BTreeSet::new();
        self.authorizations
            .iter()
            .filter(|a| seen.insert(a.holder_key_id.clone()))
            .cloned()
            .collect()
    }

    /// The amended v4 bundle with its distinct authorizations.
    ///
    /// # Errors
    ///
    /// [`AMEND_QUORUM_NOT_MET`] below [`Self::needed`];
    /// [`AMEND_CARRIED_BYTES_CHANGED`] when a carried member is not the pinned
    /// input's.
    pub fn assemble(&self) -> Result<GenesisBundle, AmendRefused> {
        let distinct = self.distinct();
        if distinct.len() < self.needed() {
            return Err(refused(
                AMEND_QUORUM_NOT_MET,
                format!(
                    "{} distinct holder authorization(s); the charter needs {}",
                    distinct.len(),
                    self.needed()
                ),
            ));
        }
        let mut bundle = self.unsigned();
        bundle.authorizations = distinct;
        let pinned = parse_genesis_bundle(&self.pinned_json)
            .map_err(|e| refused(AMEND_INPUT_REFUSED, e.to_string()))?;
        if carried(&bundle)? != carried(&pinned)? {
            return Err(refused(
                AMEND_CARRIED_BYTES_CHANGED,
                "an amend carries the charter, grants, roster, heads and produced_at of the \
                 pinned bundle byte for byte; changing any of them needs the full ceremony",
            ));
        }
        Ok(bundle)
    }

    /// Assemble and run the existing doors over the result.
    ///
    /// # Errors
    ///
    /// As [`Self::assemble`]; [`AMEND_INPUT_REFUSED`] when the amended bundle
    /// does not verify.
    /// `scratch` as in [`Self::plan`].
    pub async fn finish(
        &self,
        scratch: &dyn super::scratch::GenesisScratch,
    ) -> Result<AmendFinished, AmendRefused> {
        let bundle = self.assemble()?;
        let bundle_json = serde_json::to_string_pretty(&bundle)
            .map_err(|e| refused(AMEND_INPUT_REFUSED, format!("encode: {e}")))?;
        let verified = super::verify_ceremony_outputs(&bundle_json, scratch)
            .await
            .map_err(|e| refused(AMEND_INPUT_REFUSED, format!("the amended bundle: {e}")))?;
        Ok(AmendFinished {
            bundle,
            bundle_json,
            verified,
        })
    }
}
