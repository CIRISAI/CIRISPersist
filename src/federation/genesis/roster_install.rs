//! v53.1.0 — **a genesis bundle's roster records, installed through one
//! function by the boot seed and by the import door.**
//!
//! A version-3 bundle carries the accord family's genesis head and the
//! `ciris-canonical` birth (CC rc7 T5). Before this module only the boot seed
//! installed them, and only from the bundle compiled into the build; a node
//! importing a verified bundle (CIRISServer's `/v1/trust-root/import`) had no
//! door for them, so a labelled `trust:accepts` edge naming the imported head
//! deferred for ever as "head not yet held".
//!
//! # The successor rule for a genesis head
//!
//! CC 3.2 T6: a genesis head carries an empty `prev_head_digest`, so a second
//! ceremony by the same holders is a new genesis head, not a version of the
//! first. Before v53.1.0 the boot seed left any held accord head that named a
//! charter standing. A node seeded from one ceremony and re-booted with the
//! next therefore kept the first head, whose charter the re-bake had
//! superseded: no charter row matched the head, the accord root read invalid
//! (`root_self_declares: false`), and the posture still said `Entrenched`
//! (witness I497). That is the path every v53.0.x node takes when the final
//! ceremony is baked.
//!
//! A held head is replaced by the bundle's genesis head only when ALL hold:
//! the held head is itself a genesis head (no predecessor: a version chain is
//! never overwritten); it is the same accord (name, seats, founding instant,
//! protocol, entrenchment, dissolution); and either it names no charter (the
//! v52 upgrade, I428) or the charter it names is no longer a live row of the
//! family while the bundle's charter is. A head whose charter still stands is
//! a working root and is never replaced; which ceremony is newer is decided by
//! the delegation plane's own successor rule, which installed (or refused) the
//! bundle's charter row before this runs.
//!
//! The community birth is installed when the id is free and reported when a
//! different record is held: a rooted birth is never replaced here (the #926
//! ruling — the accord's lever over a rooted community is its founders).

use super::{bundle_family_charter_digest, GenesisBakeReport, GenesisBundle};
use crate::federation::types::{Family, SignedFamily};
use crate::federation::{Attestation, Error, FederationDirectory};
use serde::{Deserialize, Serialize};

/// What happened to one roster record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RosterRecordOutcome {
    /// The id was free; the record was stored.
    Installed,
    /// This node already holds exactly this record.
    AlreadyHeld,
    /// A held genesis head was replaced under the successor rule (module doc).
    Successor,
    /// Nothing was written; the held record stands. `reason` names why.
    Refused {
        /// Why, by name.
        reason: String,
    },
}

/// One roster record's report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterRecordReport {
    /// `family` or `community`.
    pub kind: String,
    /// The record's key id.
    pub id: String,
    /// What happened.
    #[serde(flatten)]
    pub outcome: RosterRecordOutcome,
}

/// What [`install_genesis_bundle_roster`] did.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosterInstall {
    /// The serve-node and delegation-plane bake (`bake_assembled_genesis`).
    pub bake: GenesisBakeReport,
    /// The roster records, in bundle order (family, then community).
    pub records: Vec<RosterRecordReport>,
}

/// The accord family's genesis head a bundle puts in force: the signed record
/// a version-3 bundle carries, else (version 2) the record the boot seed has
/// always built, naming the bundle's charter.
#[must_use]
pub fn bundle_accord_genesis(bundle: &GenesisBundle) -> SignedFamily {
    let accord = ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
    if let Some(carried) = bundle.family_record(accord) {
        return carried.clone();
    }
    let family = super::accord_family_genesis_record_for(
        accord,
        ciris_verify_core::accord_genesis::ACCORD_CONSENSUS_PROTOCOL,
        super::effective_accord_holder_records()
            .iter()
            .map(|r| r.record.key_id.as_str()),
        &bundle_family_charter_digest(bundle),
    );
    SignedFamily {
        family,
        authority_key_id: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        supersede_proof: None,
        cosignatures: Vec::new(),
    }
}

/// Is the charter `digest` names a live charter of `family` here — a held,
/// unretired `delegates_to` toward the family with the charter reading, whose
/// direction reading stands (the same test `charter_members_for` applies)? An
/// empty digest names nothing and is never live.
async fn charter_row_live<D>(dir: &D, family: &str, digest: &str) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    if digest.is_empty() {
        return Ok(false);
    }
    let is_charter = |a: &Attestation| {
        a.attestation_type == crate::federation::types::attestation_type::DELEGATES_TO
            && a.attested_key_id == family
            && crate::federation::trust_root::job_dimension_admits(
                &a.attestation_envelope,
                crate::federation::trust_root::TRUST_CHARTER_DIMENSION,
            )
    };
    let rows = dir.list_attestations_for(family).await?;
    let refs: Vec<&Attestation> = rows.iter().collect();
    let retired = crate::federation::precedence::retired_ids(&refs);
    let denied = crate::federation::trust_root::direction_denied_ids(
        dir,
        rows.iter().filter(|a| is_charter(a)),
    )
    .await?;
    Ok(rows.iter().any(|a| {
        a.persist_row_hash == digest
            && is_charter(a)
            && !denied.contains(&a.attestation_id)
            && !retired.contains(&a.attestation_id)
    }))
}

/// Everything a head does not carry is equal: the same accord.
fn same_accord(held: &Family, genesis: &Family) -> bool {
    held.family_name == genesis.family_name
        && held.members == genesis.members
        && held.founded_at == genesis.founded_at
        && held.consensus_protocol == genesis.consensus_protocol
        && held.consensus_protocol_entrenched == genesis.consensus_protocol_entrenched
        && held.dissolved_at == genesis.dissolved_at
}

/// The successor rule (module doc). `Ok(None)` — not replaceable.
async fn genesis_head_replaceable<D>(
    dir: &D,
    held: &Family,
    genesis: &Family,
) -> Result<Option<&'static str>, Error>
where
    D: FederationDirectory + ?Sized,
{
    if !held.prev_head_digest.is_empty()
        || !genesis.prev_head_digest.is_empty()
        || genesis.charter_digest.is_empty()
        || !same_accord(held, genesis)
    {
        return Ok(None);
    }
    if held.charter_digest.is_empty() {
        return Ok(Some("names_no_charter"));
    }
    let family = genesis.family_key_id.as_str();
    if !charter_row_live(dir, family, &held.charter_digest).await?
        && charter_row_live(dir, family, &genesis.charter_digest).await?
    {
        return Ok(Some("charter_superseded"));
    }
    Ok(None)
}

/// **The accord family's genesis head, installed from `bundle`** — the ONE
/// function the boot seed (before and after the delegation plane) and the
/// import door use. See the module doc for the successor rule.
///
/// # Errors
///
/// Directory failures and a refused write.
pub async fn install_accord_genesis_head<D>(
    dir: &D,
    bundle: &GenesisBundle,
) -> Result<RosterRecordOutcome, Error>
where
    D: FederationDirectory + ?Sized,
{
    let signed = bundle_accord_genesis(bundle);
    let genesis = &signed.family;
    let Some(held) = dir.lookup_family(&genesis.family_key_id).await? else {
        // The keyless accord has no key to sign with: the trusted-local door,
        // exactly as the boot seed always used.
        dir.put_family_local(genesis.clone()).await?;
        return Ok(RosterRecordOutcome::Installed);
    };
    if held.signing_envelope() == genesis.signing_envelope() {
        return Ok(RosterRecordOutcome::AlreadyHeld);
    }
    let Some(why) = genesis_head_replaceable(dir, &held, genesis).await? else {
        return Ok(RosterRecordOutcome::Refused {
            reason: format!(
                "accord_head_held_differs: this node holds head {} (prev {:?}, charter {:?}); the \
                 bundle's genesis head names charter {:?} — a version chain, another accord, or a \
                 head whose charter still stands is never replaced",
                held.persist_row_hash,
                held.prev_head_digest,
                held.charter_digest,
                genesis.charter_digest
            ),
        });
    };
    let snapshot = serde_json::to_value(&signed)
        .map_err(|e| Error::Backend(format!("accord genesis snapshot: {e}")))?;
    dir.supersede_group_row(
        crate::federation::cohort::Cohort::Family,
        snapshot,
        Some(serde_json::json!({
            crate::federation::canonical_community::BIRTH_REPLACES_UNROOTED: held.persist_row_hash,
        })),
    )
    .await?;
    tracing::info!(
        family_key_id = %genesis.family_key_id,
        replaced = %held.persist_row_hash,
        why,
        "genesis roster: the held accord head is replaced by the bundle's genesis head"
    );
    Ok(RosterRecordOutcome::Successor)
}

/// **Install a bundle's roster records** — the accord family's genesis head
/// ([`install_accord_genesis_head`]) and the `ciris-canonical` birth (the boot
/// seed's [`seed_canonical_community_from`](super::seed_canonical_community_from)).
/// A record the bundle does not carry is not reported.
///
/// # Errors
///
/// Directory failures.
pub async fn install_bundle_roster_records<D>(
    dir: &D,
    bundle: &GenesisBundle,
) -> Result<Vec<RosterRecordReport>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut out = Vec::new();
    let signed = bundle_accord_genesis(bundle);
    out.push(RosterRecordReport {
        kind: "family".to_owned(),
        id: signed.family.family_key_id.clone(),
        outcome: install_accord_genesis_head(dir, bundle).await?,
    });
    let canon = crate::federation::canonical_community::CIRIS_CANONICAL_COMMUNITY_KEY_ID;
    if let Some(birth) = bundle.community_record(canon) {
        use super::CommunityLegOutcome as C;
        let outcome = match super::seed_canonical_community_from(dir, Some(birth)).await {
            Ok(C::Installed) => RosterRecordOutcome::Installed,
            Ok(C::AlreadyHeld) => RosterRecordOutcome::AlreadyHeld,
            Ok(C::HeldDiffers) => RosterRecordOutcome::Refused {
                reason: "community_held_differs: this node holds another record under the id; a \
                         held birth is never replaced here"
                    .to_owned(),
            },
            Ok(C::NotBaked) => unreachable!("an asset was passed"),
            Err(f) => RosterRecordOutcome::Refused {
                reason: format!("community_birth_refused: {f:?}"),
            },
        };
        out.push(RosterRecordReport {
            kind: "community".to_owned(),
            id: canon.to_owned(),
            outcome,
        });
    }
    Ok(out)
}

/// v53.1.0 — **install a verified genesis bundle on a live node** (the import
/// door; CIRISServer's `/v1/trust-root/import`).
///
/// 1. [`verify_ceremony_outputs`](super::verify_ceremony_outputs) — the
///    bundle's holders must be this build's accord roster, its quorum, family
///    record and birth must verify on a throwaway directory. A refusal writes
///    NOTHING ([`Error::GenesisBundleInvalid`] naming the stage).
/// 2. [`bake_assembled_genesis`](super::bake_assembled_genesis) — serve nodes
///    and the delegation plane, with its own anti-rollback rule.
/// 3. [`install_bundle_roster_records`] — the same function the boot seed
///    uses.
///
/// This node's own genesis posture is not touched: the posture is computed
/// against the compiled bundle on every read, and nothing here changes what is
/// compiled in. Re-importing the same bundle writes nothing and reports
/// `AlreadyPresent` / `AlreadyHeld`.
///
/// A bundle of ANOTHER accord (other holders) is refused at step 1: a
/// version-3 bundle names the reserved `humanity-accord` / `ciris-canonical`
/// ids, and this node verifies those against its own roster.
///
/// # Errors
///
/// [`Error::GenesisBundleInvalid`] on a refused bundle; the bake's errors;
/// directory failures.
pub async fn install_genesis_bundle_roster<D>(
    dir: &D,
    bundle: &GenesisBundle,
) -> Result<RosterInstall, Error>
where
    D: FederationDirectory + ?Sized,
{
    let json = serde_json::to_string(bundle)
        .map_err(|e| Error::Backend(format!("serialize the bundle: {e}")))?;
    super::verify_ceremony_outputs(&json)
        .await
        .map_err(|r| Error::GenesisBundleInvalid {
            detail: r.to_string(),
        })?;
    let bake = super::bake_assembled_genesis(dir, &json).await?;
    let records = install_bundle_roster_records(dir, bundle).await?;
    Ok(RosterInstall { bake, records })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::accord_test_support as ops;

    /// A co-signed `trust:charter:v1` of the accord under a fresh id, admitted
    /// through the ordinary door (it is NOT named by a family version).
    async fn put_charter(d: &dyn FederationDirectory) -> String {
        use crate::federation::trust_root::{
            test_pre_rotation_commitment, INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE,
            TRUST_CHARTER_DIMENSION,
        };
        let family = ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
        let id = uuid::Uuid::new_v4().to_string();
        let env = serde_json::json!({
            "references_attestation_id": id,
            "dimension": TRUST_CHARTER_DIMENSION,
            "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
            "pre_rotation_commitment": test_pre_rotation_commitment(&[
                "accord-succ-a".to_owned(),
                "accord-succ-b".to_owned(),
            ])
            .unwrap(),
            "recovery_commitments":
                crate::federation::trust_root::test_accord_recovery_commitments_held(d).await,
        });
        let charter = ops::co_signed_trust_attestation(
            &id,
            "A1",
            family,
            crate::federation::types::attestation_type::DELEGATES_TO,
            env,
            &["B1", "C1"],
        );
        d.put_attestation(crate::federation::SignedAttestation {
            attestation: charter,
        })
        .await
        .expect("the accord charters itself");
        d.get_attestation(&id)
            .await
            .unwrap()
            .expect("held")
            .persist_row_hash
    }

    /// The compiled bundle, carrying a genesis head naming `digest`.
    fn bundle_naming(digest: &str) -> GenesisBundle {
        let mut b = super::super::canonical_genesis_bundle().clone();
        let family = super::super::accord_family_genesis_record_for(
            ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID,
            ciris_verify_core::accord_genesis::ACCORD_CONSENSUS_PROTOCOL,
            super::super::effective_accord_holder_records()
                .iter()
                .map(|r| r.record.key_id.as_str()),
            digest,
        );
        b.roster_records = vec![super::super::GenesisRosterRecord::Family(SignedFamily {
            family,
            authority_key_id: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            supersede_proof: None,
            cosignatures: Vec::new(),
        })];
        b
    }

    /// **I499b — a genesis head whose charter still stands is a working root
    /// and is never replaced**, even when the bundle's charter is live too. The
    /// held head first moves (through the door) from the compiled charter,
    /// which this node does not hold, to charter X; a bundle naming charter Y
    /// is then refused while X stands.
    #[tokio::test]
    async fn i499b_a_head_whose_charter_stands_is_never_replaced() {
        let d = crate::store::memory::MemoryBackend::new();
        ops::register_genesis_accord_roster(&d).await.unwrap();
        super::super::seed_accord_family(&d).await.unwrap();
        let x = put_charter(&d).await;
        let y = put_charter(&d).await;
        assert_ne!(x, y);
        assert_eq!(
            install_accord_genesis_head(&d, &bundle_naming(&x))
                .await
                .unwrap(),
            RosterRecordOutcome::Successor,
            "the held head named a charter this node does not hold"
        );
        let held = d
            .lookup_family(ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(held.charter_digest, x);
        let second = install_accord_genesis_head(&d, &bundle_naming(&y))
            .await
            .unwrap();
        assert!(
            matches!(&second, RosterRecordOutcome::Refused { reason } if reason.starts_with("accord_head_held_differs")),
            "X still stands: {second:?}"
        );
        assert_eq!(
            d.lookup_family(ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID)
                .await
                .unwrap()
                .unwrap(),
            held,
            "the working root is untouched"
        );
    }
}
