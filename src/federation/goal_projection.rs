//! v60.0.0 (CIRISPersist#988 item 4; CC 3.1.9.7, CC 2.4.2,
//! CLM-silo-projection-rebuildable) — **the `goals` table is the projection
//! of the goal rows this node holds.**
//!
//! # The fold, per declaration
//!
//! A goal is its declaration `D` (a `scores` row on `goal:{scale}:v1`,
//! admitted by [`super::goal::check_goal_row_admission`]) and the structural
//! rows that name it:
//!
//! 1. **the head** — follow the amendment chain from `D`: at each link, the
//!    declarer's `supersedes` naming that link and carrying a well-formed goal
//!    body ([`chain_next`]); the §6.1 replay rule leaves at most one per link,
//!    and a tie is broken as §6.1 breaks it. The body projected is the head's;
//! 2. **the retractions** — the `withdraws` / `recants` naming `D` whose
//!    attester is entitled to retract it
//!    ([`retraction_entitled`](super::precedence::retraction_entitled)); the
//!    §6.1 [`precedence_winner`](super::precedence::precedence_winner) of
//!    them decides: a `recants` winner removes the goal (never mine), a
//!    `withdraws` winner retires it at its signed instant.
//!
//! The goal's id, declarer and `declared_at` are `D`'s; `attestation_id` and
//! `persist_row_hash` are the head's. Every column is a pure function of held
//! rows, so the table is byte-equal to its from-rows rebuild, and the order
//! rows arrive in never changes it: whichever row of a chain lands last, the
//! executor refolds the whole declaration ([`refold_goal`]) in that row's
//! transaction.
//!
//! # Who decides
//!
//! [`goal_to_refold`] (which declaration a put touches; read through the
//! directory in the shared plan), [`chain_next`] and [`fold_goal`] are the
//! whole decision. The backends' executors only read the declaration and the
//! rows naming each link, and write what [`fold_goal`] returns.

use super::goal::{canonicalize_goal_text, goal_body_of, GoalBody};
use super::precedence::references_attestation_id_from_envelope;
use super::precedence::{precedence_winner, retraction_entitled};
use super::types::{attestation_type, Attestation};

/// The longest amendment chain the fold follows (a bound on the reads one
/// refold makes; a chain past it projects the link reached).
pub const MAX_GOAL_CHAIN: usize = 256;

/// One `goals` row, as the fold writes it.
#[derive(Debug, Clone, PartialEq)]
pub struct GoalProjection {
    /// The declaration's id.
    pub goal_id: String,
    /// The declaration's attester.
    pub declared_by_key_id: String,
    /// The declaration's signed instant.
    pub declared_at: chrono::DateTime<chrono::Utc>,
    /// The head's body.
    pub body: GoalBody,
    /// The winning `withdraws`' signed instant.
    pub retired_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The head's id.
    pub attestation_id: String,
    /// The head's `persist_row_hash`.
    pub persist_row_hash: String,
}

impl GoalProjection {
    /// `goal_text_canonical`.
    #[must_use]
    pub fn goal_text_canonical(&self) -> String {
        canonicalize_goal_text(&self.body.goal_text)
    }

    /// `meta_deliberation`, as the column stores it (JSON text).
    #[must_use]
    pub fn meta_deliberation(&self) -> Option<String> {
        self.body
            .meta_goal_alignment
            .deliberation_ref
            .as_ref()
            .map(|d| serde_json::json!(d).to_string())
    }

    /// The read type.
    #[must_use]
    pub fn to_goal(&self) -> super::goal::Goal {
        super::goal::Goal {
            goal_id: self.goal_id.clone(),
            declared_by_key_id: self.declared_by_key_id.clone(),
            declared_at: self.declared_at,
            goal_text: self.body.goal_text.clone(),
            scope: self.body.scope.clone(),
            meta_goal_alignment: self.body.meta_goal_alignment.clone(),
            score: self.body.score,
            retired_at: self.retired_at,
            attestation_id: self.attestation_id.clone(),
        }
    }

    /// The row as the memory backend renders it for the rebuild comparison:
    /// every column, in the SQL table's column order.
    #[must_use]
    pub fn render(&self) -> String {
        let at = super::ledger_projection::render_instant;
        serde_json::json!([
            self.goal_id,
            self.declared_by_key_id,
            at(self.declared_at),
            self.body.goal_text,
            self.goal_text_canonical(),
            self.body.scope.scale(),
            self.body.scope.cohort_id(),
            self.body.meta_goal_alignment.dimension.as_str(),
            self.body.meta_goal_alignment.rationale,
            self.meta_deliberation(),
            self.retired_at.map(at),
            self.persist_row_hash,
            self.attestation_id,
            self.body.score,
        ])
        .to_string()
    }
}

/// Is `row` a goal declaration (a `scores` row on the goal family with a
/// well-formed body)?
#[must_use]
pub fn is_goal_declaration(row: &Attestation) -> bool {
    row.attestation_type == attestation_type::SCORES && goal_body_of(row).is_some()
}

/// Is `c` an amendment of `decl`'s goal: its declarer's `supersedes`
/// carrying a well-formed goal body?
fn is_amendment_of(decl: &Attestation, c: &Attestation) -> bool {
    c.attestation_type == attestation_type::SUPERSEDES
        && c.attesting_key_id == decl.attesting_key_id
        && goal_body_of(c).is_some()
}

/// **The next link**: among `naming_link` (the rows naming the current link),
/// the declarer's amendment; of several (only a §6.1 replay slot could hold
/// more than one), the latest signed instant, then the smallest id.
#[must_use]
pub fn chain_next<'a>(
    decl: &Attestation,
    naming_link: &'a [Attestation],
) -> Option<&'a Attestation> {
    let amendments: Vec<&Attestation> = naming_link
        .iter()
        .filter(|c| is_amendment_of(decl, c))
        .collect();
    let winner: *const Attestation = precedence_winner(&amendments)?;
    naming_link.iter().find(|c| std::ptr::eq(*c, winner))
}

/// **The fold.** `decl`'s projection given the rows naming it
/// (`naming_decl`) and the head of its chain (`head`, `decl` itself when
/// unamended). `None` when `decl` is not a goal declaration, the head carries
/// no body, or an entitled `recants` wins.
#[must_use]
pub fn fold_goal(
    decl: &Attestation,
    naming_decl: &[Attestation],
    head: &Attestation,
) -> Option<GoalProjection> {
    if !is_goal_declaration(decl) {
        return None;
    }
    let body = goal_body_of(head)?;
    let retractions: Vec<&Attestation> = naming_decl
        .iter()
        .filter(|c| {
            (c.attestation_type == attestation_type::WITHDRAWS
                || c.attestation_type == attestation_type::RECANTS)
                && references_attestation_id_from_envelope(&c.attestation_envelope)
                    == Some(decl.attestation_id.as_str())
                && retraction_entitled(c, decl)
        })
        .collect();
    let retired_at = match precedence_winner(&retractions) {
        Some(w) if w.attestation_type == attestation_type::RECANTS => return None,
        Some(w) => Some(w.asserted_at),
        None => None,
    };
    Some(GoalProjection {
        goal_id: decl.attestation_id.clone(),
        declared_by_key_id: decl.attesting_key_id.clone(),
        declared_at: decl.asserted_at,
        body,
        retired_at,
        attestation_id: head.attestation_id.clone(),
        persist_row_hash: head.persist_row_hash.clone(),
    })
}

/// **The refold**, over two synchronous reads: `get` a held row by id, and
/// `naming` the federation-tier structural rows naming an id. The sqlite and
/// memory executors call this; postgres runs the same three steps over its
/// async client.
///
/// # Errors
///
/// A read's.
pub fn refold_goal<E>(
    goal_id: &str,
    mut get: impl FnMut(&str) -> Result<Option<Attestation>, E>,
    mut naming: impl FnMut(&str) -> Result<Vec<Attestation>, E>,
) -> Result<Option<GoalProjection>, E> {
    let Some(decl) = get(goal_id)? else {
        return Ok(None);
    };
    if !is_goal_declaration(&decl) {
        return Ok(None);
    }
    let naming_decl = naming(goal_id)?;
    let mut head = decl.clone();
    let mut naming_head = naming_decl.clone();
    for _ in 0..MAX_GOAL_CHAIN {
        let Some(next) = chain_next(&decl, &naming_head).cloned() else {
            break;
        };
        naming_head = naming(&next.attestation_id)?;
        head = next;
    }
    Ok(fold_goal(&decl, &naming_decl, &head))
}

/// **Which declaration a put touches** (read in the shared plan, through the
/// directory): a declaration touches itself; a structural row touches the
/// declaration at the root of the chain its target belongs to, walked back
/// through held goal amendments. `None` for every other row, and for a row
/// whose chain does not resolve yet (the missing row refolds it when it
/// lands).
///
/// # Errors
///
/// A directory read.
pub async fn goal_to_refold(
    dir: &dyn super::FederationDirectory,
    row: &Attestation,
) -> Result<Option<String>, super::Error> {
    if is_goal_declaration(row) {
        return Ok(Some(row.attestation_id.clone()));
    }
    if !super::precedence::is_structural_composer(&row.attestation_type) {
        return Ok(None);
    }
    let Some(mut cur) =
        references_attestation_id_from_envelope(&row.attestation_envelope).map(str::to_owned)
    else {
        return Ok(None);
    };
    for _ in 0..MAX_GOAL_CHAIN {
        let Some(target) = dir.get_attestation(&cur).await? else {
            return Ok(None);
        };
        if is_goal_declaration(&target) {
            return Ok(Some(target.attestation_id));
        }
        // Not a declaration: a link only if it carries a goal body (which,
        // for a row that is not a `scores` declaration, means a goal
        // `supersedes`).
        if goal_body_of(&target).is_none() {
            return Ok(None);
        }
        match references_attestation_id_from_envelope(&target.attestation_envelope) {
            Some(prev) => cur = prev.to_owned(),
            None => return Ok(None),
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(min: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::UNIX_EPOCH + chrono::Duration::minutes(min)
    }

    fn body(text: &str) -> serde_json::Value {
        serde_json::json!({
            "dimension": "goal:self:v1",
            "score": 0.5,
            "goal_text": text,
            "meta_goal_alignment": {"dimension": "justice", "rationale": "r"},
        })
    }

    fn row(id: &str, ty: &str, by: &str, env: serde_json::Value, t: i64) -> Attestation {
        Attestation {
            attestation_id: id.into(),
            attesting_key_id: by.into(),
            attested_key_id: by.into(),
            attestation_type: ty.into(),
            weight: None,
            asserted_at: at(t),
            expires_at: None,
            attestation_envelope: env,
            original_content_hash: "00".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: by.into(),
            scrub_timestamp: at(t),
            pqc_completed_at: None,
            persist_row_hash: format!("h-{id}"),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".into(),
            tier: crate::federation::types::attestation_tier::FEDERATION.into(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    fn naming(target: &str, mut env: serde_json::Value) -> serde_json::Value {
        env["references_attestation_id"] = serde_json::json!(target);
        env
    }

    fn retraction(target: &str, ty: &str) -> serde_json::Value {
        serde_json::json!({"kind": ty, "references_attestation_id": target})
    }

    /// I1177 (unit) — the fold: the head is the end of the declarer's
    /// amendment chain; a foreign or body-less supersedes is no link; an
    /// entitled `withdraws` retires at its instant; an entitled `recants`
    /// wins over it and removes the goal; an unentitled retraction is
    /// ignored; the result never depends on the order rows are listed in.
    #[test]
    fn i1177_the_fold_follows_the_chain_and_the_retractions() {
        let d = row("d", "scores", "alice", body("v0"), 0);
        let s1 = row("s1", "supersedes", "alice", naming("d", body("v1")), 1);
        let s2 = row("s2", "supersedes", "alice", naming("s1", body("v2")), 2);
        let foreign = row("sx", "supersedes", "mallory", naming("s1", body("vx")), 9);
        let bodyless = row(
            "sb",
            "supersedes",
            "alice",
            naming("s1", serde_json::json!({"kind": "supersedes"})),
            9,
        );
        let all = [
            d.clone(),
            s1.clone(),
            s2.clone(),
            foreign.clone(),
            bodyless.clone(),
        ];
        let naming_of = |id: &str| -> Result<Vec<Attestation>, ()> {
            Ok(all
                .iter()
                .filter(|r| {
                    crate::federation::precedence::is_structural_composer(&r.attestation_type)
                        && references_attestation_id_from_envelope(&r.attestation_envelope)
                            == Some(id)
                })
                .cloned()
                .collect())
        };
        let get = |id: &str| -> Result<Option<Attestation>, ()> {
            Ok(all.iter().find(|r| r.attestation_id == id).cloned())
        };
        let p = refold_goal("d", get, naming_of).unwrap().unwrap();
        assert_eq!(p.goal_id, "d");
        assert_eq!(p.declared_by_key_id, "alice");
        assert_eq!(p.declared_at, at(0));
        assert_eq!(p.body.goal_text, "v2", "the head is the chain's end");
        assert_eq!(p.attestation_id, "s2");
        assert_eq!(p.persist_row_hash, "h-s2");
        assert_eq!(p.retired_at, None);
        // Order-independent: the rows named, reversed.
        let mut rev = vec![s1.clone(), foreign.clone(), bodyless.clone()];
        assert_eq!(chain_next(&d, &rev).unwrap().attestation_id, "s1");
        rev.reverse();
        assert_eq!(chain_next(&d, &rev).unwrap().attestation_id, "s1");
        assert!(chain_next(&d, &[foreign.clone(), bodyless.clone()]).is_none());
        // Two amendments of one link (a replay slot): the latest wins.
        let s1b = row("s1b", "supersedes", "alice", naming("d", body("v1b")), 5);
        assert_eq!(
            chain_next(&d, &[s1.clone(), s1b.clone()])
                .unwrap()
                .attestation_id,
            "s1b"
        );

        // Retractions.
        let w = row("w", "withdraws", "alice", retraction("d", "withdraws"), 7);
        let p = fold_goal(&d, std::slice::from_ref(&w), &s2).unwrap();
        assert_eq!(
            p.retired_at,
            Some(at(7)),
            "retired at the withdraws' instant"
        );
        let r = row("r", "recants", "alice", retraction("d", "recants"), 3);
        assert!(fold_goal(&d, &[w.clone(), r.clone()], &s2).is_none());
        assert!(fold_goal(&d, &[r.clone(), w.clone()], &s2).is_none());
        let mw = row(
            "mw",
            "withdraws",
            "mallory",
            retraction("d", "withdraws"),
            8,
        );
        let mr = row("mr", "recants", "mallory", retraction("d", "recants"), 8);
        let p = fold_goal(&d, &[mw, mr], &d).unwrap();
        assert_eq!(p.retired_at, None, "an unentitled retraction is ignored");
        // A retraction naming a link, not the declaration, retires nothing.
        let wl = row("wl", "withdraws", "alice", retraction("s1", "withdraws"), 8);
        assert_eq!(fold_goal(&d, &[wl], &s2).unwrap().retired_at, None);
        // Not a declaration; a head without a body.
        assert!(fold_goal(&s1, &[], &s1).is_none());
        assert!(fold_goal(&d, &[], &bodyless).is_none());
        let not_goal = row(
            "n",
            "scores",
            "alice",
            serde_json::json!({"dimension": "config:x:v1", "score": 1.0}),
            0,
        );
        assert!(!is_goal_declaration(&not_goal));
        let none = refold_goal(
            "n",
            |_| Ok::<_, ()>(Some(not_goal.clone())),
            |_| Ok(Vec::new()),
        )
        .unwrap();
        assert!(none.is_none());
        assert!(
            refold_goal("gone", |_| Ok::<_, ()>(None), |_| Ok(Vec::new()))
                .unwrap()
                .is_none()
        );
    }

    /// I1177 (unit) — the rendering carries every column in the table's
    /// order, so two projections differing in any column render differently.
    #[test]
    fn i1177_the_rendering_carries_every_column() {
        let d = row("d", "scores", "alice", body("  two   words "), 0);
        let p = fold_goal(&d, &[], &d).unwrap();
        let v: serde_json::Value = serde_json::from_str(&p.render()).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 14);
        assert_eq!(v[0], "d");
        assert_eq!(v[1], "alice");
        assert_eq!(v[2], "1970-01-01T00:00:00.000000Z");
        assert_eq!(v[3], "  two   words ");
        assert_eq!(v[4], "two words");
        assert_eq!(v[5], "self");
        assert_eq!(v[6], serde_json::Value::Null);
        assert_eq!(v[7], "justice");
        assert_eq!(v[8], "r");
        assert_eq!(v[9], serde_json::Value::Null);
        assert_eq!(v[10], serde_json::Value::Null);
        assert_eq!(v[11], "h-d");
        assert_eq!(v[12], "d");
        assert_eq!(v[13], serde_json::json!(0.5));
        let mut with_ref = body("t");
        with_ref["meta_goal_alignment"]["deliberation_ref"] =
            serde_json::json!({"artifact_type": "pdma", "artifact_id": "p"});
        let d2 = row("d2", "scores", "alice", with_ref, 0);
        let p2 = fold_goal(&d2, &[], &d2).unwrap();
        assert_eq!(
            p2.meta_deliberation().as_deref(),
            Some(r#"{"artifact_id":"p","artifact_type":"pdma"}"#)
        );
        let g = p2.to_goal();
        assert_eq!(
            (g.goal_id.as_str(), g.attestation_id.as_str()),
            ("d2", "d2")
        );
        assert_eq!(g.score, 0.5);
    }
}
