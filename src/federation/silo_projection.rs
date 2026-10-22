//! v57.0.0 (CIRISPersist#988 items 2 and 3; CC 2.4.2,
//! CLM-silo-projection-rebuildable) — **a table that mirrors a plane is a
//! projection rebuilt from the rows alone.**
//!
//! `hard_case_events` and `detection_events` were silos: tables written
//! directly, the only copy of what they held. From v57.0.0 each is the
//! projection of rows on the attestation plane (`hard_case:{kind}:v1` rows,
//! `detection:*` rows), written by the row's executor in the same step as the
//! row, and nothing else writes it.
//!
//! The gate is [`check_projection_rebuild`]: a from-rows rebuild of the
//! projection, through the same writer into a scratch table of the same
//! shape, is BYTE-EQUAL to the live table, row for row in primary-key order,
//! each row rendered in the backend's own column encoding (sqlite's `quote()`
//! of every column, postgres's `row_to_json(..)::text`, memory's serde form).
//! A row the live table holds that no row produces, a row it lacks, or one
//! column that differs is a red.
//!
//! The invariant witness is `silo_projection_invariants` (I960/I961), on
//! memory, sqlite and postgres.

/// The projections that mirror a plane (CC 2.4.2's list, as far as persist
/// has moved it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiloProjection {
    /// `hard_case_events` ← `hard_case:{kind}:v1` rows (#988 item 2).
    HardCaseEvents,
    /// `detection_events` ← `detection:*` rows (#988 item 3).
    DetectionEvents,
    /// v58.0.0 (CIRISPersist#991, CC 3.1.3) — `federation_keys` ←
    /// `key:record:v1` rows. Rendered as each record's claim and the row it
    /// names (`key_plane::render_key_projection`); a key held without its row
    /// (one that verifies under neither the proof-of-possession rule nor a
    /// held base signer: hybrid-pending, unsigned, a bad scrub) is a red.
    FederationKeys,
    /// v58.0.0 (CIRISPersist#991, CC 2.4.1.1) — `federation_revocations` ←
    /// `key:revocation:v1` rows. A revocation held without its row (a pre-v58
    /// Ed25519-only one) is a red.
    FederationRevocations,
    /// v58.0.0 (CIRISPersist#991, CC 3.3.6) — the SIGNED rows of
    /// `federation_identity_occurrences` ← `identity:occurrence:v1` rows. A
    /// trusted-local (unsigned) occurrence is the node's own self-write, not a
    /// claim, and is outside the projection; a signed one held without its row
    /// (Ed25519-only) is a red.
    IdentityOccurrences,
    /// v60.0.0 (CIRISPersist#988 item 1, CC 3.1.9.6) — `credits_ledger` ←
    /// this node's `credits:{domain}:{language}:{subject}` rows, the latest
    /// per key ([`super::ledger_projection`]). A pre-V203 balance with no row
    /// is a red until the rehome re-emits it.
    CreditsLedger,
    /// v60.0.0 (CIRISPersist#988 item 1, CC 3.1.9.6) — `expertise_ledger` ←
    /// this node's `expertise:{domain}:{language}` rows, the latest per key.
    ExpertiseLedger,
}

impl SiloProjection {
    /// Every projection, in declaration order.
    pub const ALL: [SiloProjection; 7] = [
        Self::HardCaseEvents,
        Self::DetectionEvents,
        Self::FederationKeys,
        Self::FederationRevocations,
        Self::IdentityOccurrences,
        Self::CreditsLedger,
        Self::ExpertiseLedger,
    ];

    /// The stable name: the projection's table name without a schema.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HardCaseEvents => "hard_case_events",
            Self::DetectionEvents => "detection_events",
            Self::FederationKeys => "federation_keys",
            Self::FederationRevocations => "federation_revocations",
            Self::IdentityOccurrences => "federation_identity_occurrences",
            Self::CreditsLedger => "credits_ledger",
            Self::ExpertiseLedger => "expertise_ledger",
        }
    }
}

/// A projection's live rows and its from-rows rebuild, each row rendered as
/// one string in the backend's own column encoding, in primary-key order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectionRebuild {
    /// The live table.
    pub live: Vec<String>,
    /// The table rebuilt from the rows.
    pub rebuilt: Vec<String>,
}

impl ProjectionRebuild {
    /// The first divergence, described, or `None` when byte-equal.
    #[must_use]
    pub fn divergence(&self) -> Option<String> {
        if self.live == self.rebuilt {
            return None;
        }
        let n = self.live.len().max(self.rebuilt.len());
        for i in 0..n {
            let (l, r) = (self.live.get(i), self.rebuilt.get(i));
            if l != r {
                return Some(format!(
                    "row {i}: live {l:?} vs rebuilt {r:?} ({} live rows, {} rebuilt)",
                    self.live.len(),
                    self.rebuilt.len()
                ));
            }
        }
        None
    }
}

/// **The gate** (CLM-silo-projection-rebuildable): the projection rebuilt
/// from the rows is byte-equal to the live table, or a refusal naming the
/// first row that differs.
// The no-backend builds hold only the memory backend, whose caller is the
// test witness; the live predicate is `Engine::check_silo_projection`.
#[cfg_attr(not(any(feature = "sqlite", feature = "postgres")), allow(dead_code))]
pub(crate) async fn check_projection_rebuild<D>(
    dir: &D,
    projection: SiloProjection,
) -> Result<ProjectionRebuild, super::Error>
where
    D: super::attestation_admit::AttestationStore,
{
    let rebuild = dir.projection_rebuild(projection).await?;
    if let Some(diff) = rebuild.divergence() {
        return Err(super::Error::Backend(format!(
            "{} is not its from-rows rebuild (CLM-silo-projection-rebuildable): {diff}",
            projection.as_str()
        )));
    }
    Ok(rebuild)
}
