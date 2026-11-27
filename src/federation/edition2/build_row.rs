//! v62.0.0 (HEAD-fix4; CC 3.1.2.1, rule `build-manifest-row`; the
//! Constitution's two-standings ruling, Kernel branch two-standings section
//! J) — **a build-manifest row's two standings.**
//!
//! A pipeline signs its `provenance:build_manifest:{target}` row in exercise
//! of a ROOT GRANT, so the row names two things (CC 3.1.2.1, "The row"):
//!
//! - `refs.head`: the bundle in force when it is signed, which is the one the
//!   pipeline's grant names or a later bundle of the same lineage. A row
//!   whose head is on another lineage, or is older than the grant's, is
//!   refused `build_row_other_head` ([`BUILD_ROW_OTHER_HEAD`]).
//! - `refs.also.stands_on`: exactly one row, the owner's acceptance of the
//!   grant. A row that names none, or names a row that is not a valid
//!   acceptance of this grant, confers nothing: `build_row_stands_on_nothing`
//!   ([`BUILD_ROW_STANDS_ON_NOTHING`], class `concludes_nothing`).
//!
//! The producer states the head through the head rule
//! (`head_rule::state_head`: the family's `names_head` cell is `standing`,
//! and the pipeline signs as a root grantee). `produce::check_refs` admits
//! the `stands_on` set of exactly one.
//!
//! **ONE call site for the standing.** [`evaluate_build_row_standing`] is
//! the only reading of a build row's standing in persist. At the Verify 23.6.0
//! pin its body becomes the call to
//! `ciris_verify_core::edition2::build_standing::evaluate_build_standing`,
//! and persist's interim reading below is deleted. The door
//! ([`check_build_row_admission`]) reads the same function.
//!
//! What the door does (CC 3.1.2.1: "A reader refuses only where a row it
//! holds is the wrong one"):
//!
//! - refuses `build_row_other_head` only when it HOLDS the pipeline's grant,
//!   the grant's bundle and the row's bundle, and the row's bundle neither is
//!   the grant's nor descends from it;
//! - holds the row `build_row_stands_on_nothing` when it names no
//!   `stands_on`. The row is kept and concludes nothing: its bytes never gain
//!   one;
//! - leaves every other answer (no grant, a named row not held, an acceptance
//!   that is not this grant's) to the reader. Its verdict is
//!   [`BuildRowStanding`].

use ciris_verify_core::cde::Value;

use super::names::{names_of, single, RowId};
use crate::federation::{Attestation, Error, FederationDirectory};

/// The family a build-manifest row is in (CC 3.1.2.1). Its locale twin,
/// `provenance:build_manifest:{target}:locale:{lang_code}`, is another family
/// and is not read here.
pub const BUILD_MANIFEST_FAMILY_PREFIX: &str = "provenance:build_manifest:{target}";

/// CC 3.1.2.1 (`refusal_tokens.tsv`, class `refusal`): the row's `refs.head`
/// is on another lineage than the bundle its pipeline's grant names, or is
/// older than it.
pub const BUILD_ROW_OTHER_HEAD: &str = "build_row_other_head";

/// CC 3.1.2.1 (`refusal_tokens.tsv`, class `concludes_nothing`): the row
/// carries no `refs.also.stands_on`, or the row it names is not a valid
/// acceptance of this grant.
pub const BUILD_ROW_STANDS_ON_NOTHING: &str = "build_row_stands_on_nothing";

/// Is `dimension` a build-manifest row's (`provenance:build_manifest:{target}`
/// with its version, never the locale twin)?
#[must_use]
pub fn is_build_row_dimension(dimension: &str) -> bool {
    dimension.starts_with("provenance:build_manifest:") && !dimension.contains(":locale:")
}

/// A build row's standing, as [`evaluate_build_row_standing`] reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildRowStanding {
    /// Both standings hold: the counted grant (its row id) and the owner's
    /// acceptance of it the row stands on.
    Stands {
        /// The grant's row id (hex).
        grant: String,
        /// The acceptance the row names in `refs.also.stands_on`.
        acceptance: RowId,
    },
    /// No grant reaches the row's family at its instant: the pipeline has
    /// no standing (the reading `admission::pipeline_has_infra_attest_standing`
    /// gives).
    NoGrant,
    /// A row the verdict reads is not held (the grant's statement, a bundle,
    /// the acceptance): the verdict waits (CC 3.1.2.1, "A row not yet held").
    Waiting,
    /// [`BUILD_ROW_OTHER_HEAD`].
    OtherHead,
    /// [`BUILD_ROW_STANDS_ON_NOTHING`].
    StandsOnNothing,
}

impl BuildRowStanding {
    /// The text's token for a verdict that names one.
    #[must_use]
    pub fn token(&self) -> Option<&'static str> {
        match self {
            Self::OtherHead => Some(BUILD_ROW_OTHER_HEAD),
            Self::StandsOnNothing => Some(BUILD_ROW_STANDS_ON_NOTHING),
            Self::Stands { .. } | Self::NoGrant | Self::Waiting => None,
        }
    }
}

/// The head a payload names in `refs.head`, and the one row it names in
/// `refs.also.stands_on` (`None` for none, or for a set that is not one).
fn heads_of(payload: &Value) -> (Option<RowId>, Option<RowId>) {
    let names = names_of(payload).unwrap_or_default();
    (single(&names, "head"), single(&names, "also:stands_on"))
}

/// **THE reading of a build-manifest row's standing** (CC 3.1.2.1; the ONE
/// call site: the Verify 23.6.0 pin swaps this body for
/// `build_standing::evaluate_build_standing`). `statement` is the row's
/// statement; `received_at` is the instant this node received it (the act
/// window's other end).
///
/// The order: the grant (none: [`BuildRowStanding::NoGrant`]), then the head
/// against the grant's bundle, then `stands_on` against the grant.
///
/// # Errors
/// `edition2_payload_invalid` for bytes that are not a build-manifest row
/// statement; directory reads.
pub async fn evaluate_build_row_standing<F>(
    dir: &F,
    statement: &[u8],
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<BuildRowStanding, Error>
where
    F: FederationDirectory + ?Sized,
{
    let invalid = |why: &str| {
        Error::malformed_row(
            "edition2_payload",
            crate::federation::malformed_row::EDITION2_PAYLOAD_INVALID,
            format!("build-manifest row: {why}"),
        )
    };
    let (_, payload) =
        super::liveness::statement_parts(statement).ok_or_else(|| invalid("not a statement"))?;
    let iss = super::occurrence::statement_iss(statement).ok_or_else(|| invalid("no iss"))?;
    let dimension = payload
        .get_text("dimension")
        .and_then(Value::as_text)
        .filter(|d| is_build_row_dimension(d))
        .ok_or_else(|| invalid("not a provenance:build_manifest:{target} row"))?
        .to_owned();
    let act_at = payload
        .get_text("asserted_at")
        .and_then(Value::as_u64)
        .and_then(|ms| i64::try_from(ms).ok())
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .ok_or_else(|| invalid("no asserted_at"))?;
    let (head, stands_on) = heads_of(&payload);

    // 1. The grant, read by the one conferral walk at the act's instant
    //    (as `admission::pipeline_has_infra_attest_standing` reads it).
    let Some(node) = dir.node_key_id() else {
        return Ok(BuildRowStanding::NoGrant);
    };
    let Ok(scope) = crate::federation::trust_root::attest_scope_for_dimension(&dimension) else {
        return Ok(BuildRowStanding::NoGrant);
    };
    let grant = match super::fold::unmarked(crate::federation::trust_root::conferred_for_act(
        dir,
        &node,
        &iss,
        &scope,
        act_at,
        received_at,
    ))
    .await
    {
        Ok(Some(g)) => g,
        Ok(None) | Err(Error::AssertedAtStale { .. }) => return Ok(BuildRowStanding::NoGrant),
        Err(e) => return Err(e),
    };
    let Some(grant_id) = hex::decode(&grant.grant_attestation_id)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .map(RowId)
    else {
        // A conferral carried by no row (not the delegation plane) names no
        // bundle the head can be read against.
        return Ok(BuildRowStanding::Waiting);
    };

    // 2. The head: the grant's bundle, or a later bundle of its lineage.
    let Some(grant_statement) = super::head_rule::held_statement(dir, &grant_id).await? else {
        return Ok(BuildRowStanding::Waiting);
    };
    let grant_head =
        super::liveness::statement_parts(&grant_statement).and_then(|(_, p)| heads_of(&p).0);
    // A row naming no bundle is the head rule's refusal at the door
    // (`act_names_no_head`): read here, it stands on no bundle of the grant's.
    let Some(head) = head else {
        return Ok(BuildRowStanding::OtherHead);
    };
    // A grant whose head does not read is not this row's fault: wait.
    let Some(grant_head) = grant_head else {
        return Ok(BuildRowStanding::Waiting);
    };
    if head != grant_head {
        // Both read as Valid placements of the held lineage (the one named
        // bundle reader, `genesis::named_bundle`); one not held: wait.
        let (Some(row_bundle), Some(grant_bundle)) = (
            super::genesis::named_bundle(dir, &head.0).await?,
            super::genesis::named_bundle(dir, &grant_head.0).await?,
        ) else {
            return Ok(BuildRowStanding::Waiting);
        };
        if row_bundle.family_key_id != grant_bundle.family_key_id
            || !super::genesis::bundle_descends(dir, &head.0, &grant_head.0).await?
        {
            return Ok(BuildRowStanding::OtherHead);
        }
    }

    // 3. stands_on: one held, concluded acceptance that answers this grant.
    let Some(acceptance) = stands_on else {
        return Ok(BuildRowStanding::StandsOnNothing);
    };
    let Some(acc_statement) = super::head_rule::held_statement(dir, &acceptance).await? else {
        return Ok(BuildRowStanding::Waiting);
    };
    let answers = super::liveness::statement_parts(&acc_statement)
        .map(|(_, p)| names_of(&p).unwrap_or_default())
        .and_then(|n| single(&n, "answers"));
    // Concluded: the door stored it (a kept voice, or a held row, is not).
    let concluded = dir.get_attestation(&acceptance.hex()).await?.is_some();
    if answers != Some(grant_id) || !concluded {
        return Ok(BuildRowStanding::StandsOnNothing);
    }
    Ok(BuildRowStanding::Stands {
        grant: grant.grant_attestation_id,
        acceptance,
    })
}

/// **The build-manifest row's door rule** (CC 3.1.2.1), run in the
/// attestation gate stack (`attestation_admit::plan_put_attestation`) for a
/// row that carries its statement. A row of another family, or one with no
/// statement, passes.
///
/// - No `refs.also.stands_on`: HELD [`BUILD_ROW_STANDS_ON_NOTHING`] (kept,
///   concludes nothing).
/// - [`evaluate_build_row_standing`] answers [`BuildRowStanding::OtherHead`]:
///   REFUSED [`BUILD_ROW_OTHER_HEAD`]. That answer needs the grant and both
///   bundles held, so the door refuses only on rows it holds.
/// - Every other answer is the reader's, and the door admits the row.
///
/// # Errors
/// The two above; directory reads.
pub async fn check_build_row_admission<F>(dir: &F, row: &Attestation) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(statement) = super::emit::carried_statement(row) else {
        return Ok(());
    };
    let Some((_, payload)) = super::liveness::statement_parts(&statement) else {
        return Ok(());
    };
    if !payload
        .get_text("dimension")
        .and_then(Value::as_text)
        .is_some_and(is_build_row_dimension)
    {
        return Ok(());
    }
    if heads_of(&payload).1.is_none() {
        return Err(super::fold::hold(
            super::fold::reason::BUILD_ROW_STANDS_ON_NOTHING,
            Error::malformed_row(
                super::door::PLANE,
                BUILD_ROW_STANDS_ON_NOTHING,
                format!(
                    "build-manifest row {} names no refs.also.stands_on: it confers nothing \
                     until a row naming the owner's acceptance of its grant (CC 3.1.2.1)",
                    row.attestation_id
                ),
            ),
        ));
    }
    if evaluate_build_row_standing(dir, &statement, crate::host::clock::now()).await?
        == BuildRowStanding::OtherHead
    {
        return Err(Error::malformed_row(
            super::door::PLANE,
            crate::federation::malformed_row::BUILD_ROW_OTHER_HEAD,
            format!(
                "build-manifest row {} names a head on another lineage than its grant's \
                 bundle, or older than it (CC 3.1.2.1)",
                row.attestation_id
            ),
        ));
    }
    Ok(())
}
