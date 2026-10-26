//! v60.0.0 (CIRISPersist#988 item 1; CC 3.1.9.6, CC 2.4.2,
//! CLM-silo-projection-rebuildable) — **the credits and expertise ledgers are
//! projections of rows.**
//!
//! Until v60 `cirisnode.credits_ledger` and `cirisnode.expertise_ledger` were
//! written directly by `update_credits_ledger` / `update_expertise_ledger`:
//! the table WAS the balance. CC 3.1.9.6 registers both as dimensions —
//! `credits:{domain}:{language}:{subject}` and `expertise:{domain}:{language}`
//! — so a balance is now a signed `scores` row, and each table holds the fold
//! of THIS node's rows (a balance is what this node computed; a peer's row
//! about the same contributor replicates and is held, but it is the peer's
//! balance, not this node's, and does not overwrite it).
//!
//! # The fold
//!
//! For one key — `(contributor, domain, language, subject)` for credits,
//! `(contributor, domain, language)` for expertise — the ledger row is the
//! projection of the row with the greatest `(asserted_at, attestation_id)`
//! among this node's rows on that key ([`supersedes`]). The ledger row is a
//! pure function of that one row: `last_updated_at` and `created_at` are both
//! its signed instant, `last_update_contribution` its `source_contribution`
//! member, `attestation_id` its id. So the table is byte-equal to its
//! from-rows rebuild ([`super::silo_projection::check_projection_rebuild`]),
//! and a pre-V203 ledger row (no `attestation_id`) is a red until the rehome
//! re-emits it as a row.
//!
//! # Who decides
//!
//! [`project_ledger_row`] and [`supersedes`] are the whole decision; the three
//! backends' executors only read the held key and write what these say.

use super::types::attestation_type;
use super::Attestation;

/// The `credits:` family stem (CC 3.1.9.6). A leaf is
/// `credits:{domain}:{language}:{subject}:v1`.
pub const CREDITS_PREFIX: &str = "credits:";
/// The `expertise:` family stem (CC 3.1.9.6). A leaf is
/// `expertise:{domain}:{language}:v1`.
pub const EXPERTISE_PREFIX: &str = "expertise:";
/// The envelope member a `credits:` row carries its balance in (the `score`
/// is the CC 2.1 scalar; a balance is not bounded to `[-1, 1]`).
pub const BALANCE_MEMBER: &str = "balance";
/// The envelope member an `expertise:` row carries its expertise in, `[0, 1]`
/// (also its `score`).
pub const EXPERTISE_MEMBER: &str = "expertise";
/// The envelope member an `expertise:` row carries the active-tier flag in.
pub const IS_ACTIVE_MEMBER: &str = "is_active";
/// The envelope member naming the Contribution row whose outcome moved the
/// balance (optional).
pub const SOURCE_CONTRIBUTION_MEMBER: &str = "source_contribution";

/// One credits-ledger row, as the fold writes it.
#[derive(Debug, Clone, PartialEq)]
pub struct CreditsProjection {
    /// The contributor (the row's `attested_key_id`).
    pub contributor_id: String,
    /// `{domain}`.
    pub domain: String,
    /// `{language}`.
    pub language: String,
    /// `{subject}`.
    pub subject: String,
    /// The balance.
    pub balance: f64,
    /// The `source_contribution` member.
    pub source_contribution: Option<String>,
}

/// One expertise-ledger row, as the fold writes it.
#[derive(Debug, Clone, PartialEq)]
pub struct ExpertiseProjection {
    /// The contributor (the row's `attested_key_id`).
    pub contributor_id: String,
    /// `{domain}`.
    pub domain: String,
    /// `{language}`.
    pub language: String,
    /// Expertise in `[0, 1]`.
    pub expertise: f64,
    /// The active-tier flag.
    pub is_active: bool,
    /// The `source_contribution` member.
    pub source_contribution: Option<String>,
}

/// What one ledger row projects to.
#[derive(Debug, Clone, PartialEq)]
pub enum LedgerBody {
    /// A `credits:` row.
    Credits(CreditsProjection),
    /// An `expertise:` row.
    Expertise(ExpertiseProjection),
}

/// A ledger projection: the body and the row it came from.
#[derive(Debug, Clone, PartialEq)]
pub struct LedgerProjection {
    /// The body.
    pub body: LedgerBody,
    /// The row's id (the ledger's `attestation_id`).
    pub attestation_id: String,
    /// The row's signed instant (`last_updated_at` and `created_at`).
    pub asserted_at: chrono::DateTime<chrono::Utc>,
}

/// Which ledger a projection writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ledger {
    /// `credits_ledger`.
    Credits,
    /// `expertise_ledger`.
    Expertise,
}

impl LedgerProjection {
    /// The ledger this projection writes.
    #[must_use]
    pub fn ledger(&self) -> Ledger {
        match self.body {
            LedgerBody::Credits(_) => Ledger::Credits,
            LedgerBody::Expertise(_) => Ledger::Expertise,
        }
    }

    /// The ledger key: `(contributor, domain, language, subject)`, the subject
    /// empty for expertise.
    #[must_use]
    pub fn key(&self) -> (String, String, String, String) {
        match &self.body {
            LedgerBody::Credits(c) => (
                c.contributor_id.clone(),
                c.domain.clone(),
                c.language.clone(),
                c.subject.clone(),
            ),
            LedgerBody::Expertise(e) => (
                e.contributor_id.clone(),
                e.domain.clone(),
                e.language.clone(),
                String::new(),
            ),
        }
    }
}

/// `(domain, language, subject?)` of a ledger dimension, or `None` for a
/// dimension that is not a ledger leaf: `credits:{domain}:{language}:{subject}:v1`
/// or `expertise:{domain}:{language}:v1` (CC 3.1.7's trailing version
/// segment), every segment non-empty.
#[must_use]
pub fn parse_ledger_dimension(dimension: &str) -> Option<(Ledger, String, String, Option<String>)> {
    let segs: Vec<&str> = dimension.split(':').collect();
    if segs.iter().any(|s| s.is_empty()) {
        return None;
    }
    match segs.as_slice() {
        ["credits", d, l, s, "v1"] => Some((
            Ledger::Credits,
            (*d).to_owned(),
            (*l).to_owned(),
            Some((*s).to_owned()),
        )),
        ["expertise", d, l, "v1"] => {
            Some((Ledger::Expertise, (*d).to_owned(), (*l).to_owned(), None))
        }
        _ => None,
    }
}

/// **The projection rule.** `Some` iff `row` is a `scores` row on a ledger
/// leaf, signed by this node (`node_key_id`), naming a contributor
/// (`attested_key_id`) other than the empty string, and carrying a well-formed
/// body: a finite `balance` (credits); an `expertise` in `[0, 1]` and a
/// boolean `is_active` (expertise). Tier-agnostic. `None` for everything
/// else, so a malformed row is held but never projected.
#[must_use]
pub fn project_ledger_row(
    row: &Attestation,
    node_key_id: Option<&str>,
) -> Option<LedgerProjection> {
    if row.attestation_type != attestation_type::SCORES {
        return None;
    }
    if node_key_id != Some(row.attesting_key_id.as_str()) {
        return None;
    }
    if row.attested_key_id.is_empty() {
        return None;
    }
    let env = &row.attestation_envelope;
    let dimension = env.get("dimension").and_then(serde_json::Value::as_str)?;
    let (ledger, domain, language, subject) = parse_ledger_dimension(dimension)?;
    let source_contribution = match env.get(SOURCE_CONTRIBUTION_MEMBER) {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(v.as_str()?.to_owned()),
    };
    let body = match ledger {
        Ledger::Credits => {
            let balance = env.get(BALANCE_MEMBER)?.as_f64()?;
            if !balance.is_finite() {
                return None;
            }
            LedgerBody::Credits(CreditsProjection {
                contributor_id: row.attested_key_id.clone(),
                domain,
                language,
                subject: subject?,
                balance,
                source_contribution,
            })
        }
        Ledger::Expertise => {
            let expertise = env.get(EXPERTISE_MEMBER)?.as_f64()?;
            if !(0.0..=1.0).contains(&expertise) {
                return None;
            }
            let is_active = env.get(IS_ACTIVE_MEMBER)?.as_bool()?;
            LedgerBody::Expertise(ExpertiseProjection {
                contributor_id: row.attested_key_id.clone(),
                domain,
                language,
                expertise,
                is_active,
                source_contribution,
            })
        }
    };
    Some(LedgerProjection {
        body,
        attestation_id: row.attestation_id.clone(),
        asserted_at: row.asserted_at,
    })
}

/// **The fold's order.** Does `offered` replace what the ledger holds on its
/// key? `held` is the held row's `(attestation_id, last_updated_at)`, `None`
/// when nothing is held. A held row with no `attestation_id` (pre-V203, not
/// yet rehomed) is always replaced by a row; otherwise the greater
/// `(asserted_at, attestation_id)` wins, so the order rows arrive in never
/// changes the ledger.
#[must_use]
pub fn supersedes(
    held: Option<(Option<&str>, chrono::DateTime<chrono::Utc>)>,
    offered: &LedgerProjection,
) -> bool {
    match held {
        None | Some((None, _)) => true,
        Some((Some(id), at)) => (offered.asserted_at, offered.attestation_id.as_str()) > (at, id),
    }
}

/// The fixed-width UTC instant a ledger row stores on sqlite: microseconds,
/// `Z`. Fixed width, so the text orders as
/// the instant does.
#[must_use]
pub fn render_instant(at: chrono::DateTime<chrono::Utc>) -> String {
    at.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

/// Parse [`render_instant`]'s form, or any RFC 3339 instant (a pre-V203 row's
/// space-separated SQLite default text is not RFC 3339 and is read as the
/// epoch, which every row supersedes anyway: a legacy row has no
/// `attestation_id`).
#[must_use]
pub fn parse_instant(s: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&chrono::Utc))
        .unwrap_or(chrono::DateTime::<chrono::Utc>::UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(dimension: &str, attester: &str, members: serde_json::Value) -> Attestation {
        let mut env = serde_json::json!({"dimension": dimension, "score": 1.0, "confidence": 1.0});
        if let (Some(e), Some(m)) = (env.as_object_mut(), members.as_object()) {
            for (k, v) in m {
                e.insert(k.clone(), v.clone());
            }
        }
        Attestation {
            attestation_id: "a1".into(),
            attesting_key_id: attester.into(),
            attested_key_id: "contrib".into(),
            attestation_type: "scores".into(),
            weight: None,
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: env,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: attester.into(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".into(),
            tier: "federation".into(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// I1166 (unit) — the projection rule: this node's well-formed ledger rows
    /// project; another signer's, a malformed body, or a non-ledger leaf do
    /// not.
    #[test]
    fn i1166_only_this_nodes_well_formed_ledger_rows_project() {
        let credits = row(
            "credits:health:en:arc:v1",
            "node",
            serde_json::json!({"balance": 12.5}),
        );
        let p = project_ledger_row(&credits, Some("node")).expect("projects");
        assert_eq!(p.ledger(), Ledger::Credits);
        assert_eq!(
            p.key(),
            ("contrib".into(), "health".into(), "en".into(), "arc".into())
        );
        assert!(
            project_ledger_row(&credits, Some("peer")).is_none(),
            "a peer's row"
        );
        assert!(project_ledger_row(&credits, None).is_none(), "no node key");
        let bad = row(
            "credits:health:en:arc:v1",
            "node",
            serde_json::json!({"balance": "x"}),
        );
        assert!(project_ledger_row(&bad, Some("node")).is_none());
        let short = row(
            "credits:health:en:arc",
            "node",
            serde_json::json!({"balance": 1.0}),
        );
        assert!(project_ledger_row(&short, Some("node")).is_none());
        let exp = row(
            "expertise:health:en:v1",
            "node",
            serde_json::json!({"expertise": 0.5, "is_active": true}),
        );
        assert_eq!(
            project_ledger_row(&exp, Some("node")).unwrap().ledger(),
            Ledger::Expertise
        );
        let over = row(
            "expertise:health:en:v1",
            "node",
            serde_json::json!({"expertise": 1.5, "is_active": true}),
        );
        assert!(project_ledger_row(&over, Some("node")).is_none());
        let no_flag = row(
            "expertise:health:en:v1",
            "node",
            serde_json::json!({"expertise": 0.5}),
        );
        assert!(project_ledger_row(&no_flag, Some("node")).is_none());
        let mut not_scores = credits.clone();
        not_scores.attestation_type = "withdraws".into();
        assert!(project_ledger_row(&not_scores, Some("node")).is_none());
    }

    /// I1166 (unit) — the fold's order is total and arrival-independent.
    #[test]
    fn i1166_the_fold_keeps_the_greatest_instant_then_id() {
        let t0 = chrono::DateTime::<chrono::Utc>::UNIX_EPOCH + chrono::Duration::days(1);
        let mk = |id: &str, at| LedgerProjection {
            body: LedgerBody::Credits(CreditsProjection {
                contributor_id: "c".into(),
                domain: "d".into(),
                language: "l".into(),
                subject: "s".into(),
                balance: 1.0,
                source_contribution: None,
            }),
            attestation_id: id.into(),
            asserted_at: at,
        };
        let later = t0 + chrono::Duration::seconds(1);
        assert!(supersedes(None, &mk("b", t0)));
        assert!(
            supersedes(Some((None, later)), &mk("b", t0)),
            "a legacy row always goes"
        );
        assert!(supersedes(Some((Some("b"), t0)), &mk("a", later)));
        assert!(!supersedes(Some((Some("b"), later)), &mk("z", t0)));
        assert!(
            supersedes(Some((Some("a"), t0)), &mk("b", t0)),
            "tie: the greater id"
        );
        assert!(!supersedes(Some((Some("b"), t0)), &mk("a", t0)));
        assert!(
            !supersedes(Some((Some("b"), t0)), &mk("b", t0)),
            "the same row is not newer"
        );
        assert_eq!(parse_instant(&render_instant(later)), later);
    }
}
