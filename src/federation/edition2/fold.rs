//! v62.0.0 (wave G0; CC 2.7.3) — **the held/concluded fold.**
//!
//! CC 2.7.3: "A row waits for what it names. It is never refused for what
//! another row says: a check that reads another row concludes nothing." The
//! edition-2 door refuses a statement only on its own bytes and on its
//! signer's own key plane. Everything else is decided HERE, by the fold:
//!
//! - **held**: every door-valid row's statement is kept in `ceg_statements`;
//! - **concluded**: its typed projection (`federation_attestations`, a group
//!   table, ...) exists only while every fold condition it reads holds.
//!   Readers read the typed tables, so they see exactly the concluded set;
//! - **held, concluding nothing**: no typed row, and its `ceg_fold_state`
//!   row names the REASON (a [`reason`] token) and the refusal the gate
//!   would have raised.
//!
//! v4: every folded row (held or concluded) has a `ceg_fold_state` row
//! carrying its ORIGINAL arrival (replicated or local, tier), its plane and
//! its projection slot. A re-fold replays that arrival ([`Arrival`]); a
//! concluded row un-concludes through its plane's hook ([`Plane`]).
//!
//! **The dependency index.** Each evaluation of a row's gates (an
//! [`attempt`]) records every input it read, as a [`Dep`] read key, in
//! `ceg_fold_reads`. When a statement lands, concludes, un-concludes or adds
//! a voice, the read keys it [`touches`] select the rows whose folds read it,
//! and [`refold_touched`] re-runs exactly those, in row-id order, cascading
//! until nothing changes. Write-time re-folding keeps readers simple (the
//! typed tables are the concluded set; no reader re-derives a verdict), at
//! the cost of a dependency lookup per stored statement, which is one indexed
//! read when nothing depends on it.
//!
//! **Arrival order.** A fold's answer is a function of the held set: the
//! worklist re-folds every row an input change can reach, so whichever order
//! a row and its inputs arrive in, the row is re-evaluated after the last of
//! them, against all of them. For monotone conditions (a count, a binding
//! present, an owner seated) the fixpoint is unique; a withdrawal is itself a
//! held row whose conclusion un-concludes what read its target.
//!
//! **Gates** convert by declaring their reads ([`reads`]) and wrapping the
//! refusal they already return in [`hold`]. Outside an attempt both are
//! no-ops / plain refusals, so the earlier-form door and read-time folds keep
//! their behaviour. See `FSD/v62_wip/parallel/G0.api.md` for the recipe.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use super::door::AdmittedRow;
use super::ingest::StatementOutcome;
use super::names::RowId;
use super::voices::Voice;
use crate::federation::types::Attestation;
use crate::federation::{Error, FederationDirectory};

/// The reason tokens a held row may carry. **Appended, never reordered**:
/// adopters key on the text ([`reason::ALL`]).
pub mod reason {
    /// The row's voices are short of its count (a group's
    /// `consensus_protocol`, an owner binding's node voice, a charter's
    /// quorum): T1's, V1b's, O1's and W1's `Pending`.
    pub const COUNT_SHORT: &str = "count_short";
    /// The row is a third party's word about a subject whose live owner the
    /// signer is not (yet): `owner_of(subject)` does not name the signer.
    pub const OWNER_UNSEATED: &str = "owner_unseated";
    /// A steward binding of a person whose minority (or whose granter's
    /// adulthood) no held witness proves.
    pub const STEWARD_UNPROVEN: &str = "steward_unproven";
    /// An amendment whose approvals name another digest (reserved for the
    /// identity-amendment conversion).
    pub const AMENDMENT_DIGEST_MISMATCH: &str = "amendment_digest_mismatch";
    /// A re-fold met a refusal no gate marked as a fold condition: the row
    /// stays held, and the refusal is its detail.
    pub const REFOLD_REFUSED: &str = "refold_refused";
    /// Transient: a concluded row is being taken out of its typed table. A
    /// row left in this state (a crash mid-refold) is repaired by
    /// [`super::refold_all`].
    pub const REFOLDING: &str = "refolding";
    /// v2 — the subject node has more than one counted owner
    /// (`AmbiguousNodeOwner`): whatever read its owner concludes nothing
    /// until one binding is withdrawn. Raised by `admission::owner_of`
    /// itself, so no gate that calls it with `?` refuses on it.
    pub const OWNER_AMBIGUOUS: &str = "owner_ambiguous";
    /// Every token, in append order.
    pub const ALL: &[&str] = &[
        COUNT_SHORT,
        OWNER_UNSEATED,
        STEWARD_UNPROVEN,
        AMENDMENT_DIGEST_MISMATCH,
        REFOLD_REFUSED,
        REFOLDING,
        OWNER_AMBIGUOUS,
    ];
}

/// The most rows one re-fold pass evaluates. A pass that reaches it logs and
/// stops; the remainder re-folds on the next touch or [`refold_all`].
pub const MAX_REFOLD_STEPS: usize = 4096;

/// The most held reasons one page returns.
pub const MAX_HELD_PAGE: u32 = 1000;

/// One input a fold read, by the key `ceg_fold_reads.read_key` stores.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Dep {
    /// A row by id: its voices, a withdrawal or approval naming it.
    Row(RowId),
    /// Any row about or by this key id / identity-ref: a binding, a seat, an
    /// age witness, an owner binding.
    Key(String),
    /// The coarse fallback: any row of this family.
    Family(String),
}

impl Dep {
    /// `Dep::Key` of `id`.
    #[must_use]
    pub fn key(id: &str) -> Self {
        Self::Key(id.to_owned())
    }

    /// The stored text: `row:<hex>`, `key:<id>` or `family:<family>`.
    #[must_use]
    pub fn read_key(&self) -> String {
        match self {
            Self::Row(r) => format!("row:{}", r.hex()),
            Self::Key(k) => format!("key:{k}"),
            Self::Family(f) => format!("family:{f}"),
        }
    }
}

/// The planes a folded row projects into ([`Plane`]); stored as text in
/// `ceg_fold_state.plane`.
pub mod plane {
    /// A row through the attestation gates (`voices::put_counted_row`).
    pub const ATTESTATION: &str = "attestation";
    /// T2's families stored as attestation rows (takedown, custody, key grant).
    pub const TYPED_ATTESTATION: &str = "typed_attestation";
    /// T2's trust edges (an attestation row plus the v1.3 trust projection).
    pub const TRUST: &str = "trust";
    /// The key plane (`key:record`, `key:revocation`): a read model re-derived
    /// from the held, not-held-back key statements.
    pub const KEY: &str = "key";
    /// O1's occurrence binds (one projection per (identity, occurrence)).
    pub const OCCURRENCE: &str = "occurrence";
    /// T1's group planes (roster versions, counted membership changes).
    pub const GROUP: &str = "group";
    /// W1's counted re-bind.
    pub const REBIND: &str = "rebind";
    /// T2's own-store families (revocation, occurrence revocation, delivery
    /// receipt, cosign state, the steward purge notice).
    pub const TYPED_FINAL: &str = "typed_final";
}

/// Why a held row concludes nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldReason {
    /// The row id.
    pub row_id: RowId,
    /// The row's family.
    pub family: String,
    /// The tier the row concludes at.
    pub tier: String,
    /// v4 — did the row first arrive through the replicated door?
    pub replicated: bool,
    /// v4 — its [`plane`].
    pub plane: String,
    /// A [`reason`] token.
    pub reason: String,
    /// The refusal the gate would have raised, as text.
    pub detail: String,
    /// THIS node's clock (POSIX µs) when the row was first held for this
    /// reason. Node-local; never replicated, never read by a rule.
    pub since_us: i64,
}

impl HeldReason {
    /// The JSON the adopter surfaces return.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "row_id": self.row_id.hex(),
            "family": self.family,
            "tier": self.tier,
            "replicated": self.replicated,
            "plane": self.plane,
            "reason": self.reason,
            "detail": self.detail,
            "since_us": self.since_us,
        })
    }
}

/// v4 — the fold's whole record of one row, held or concluded
/// (`ceg_fold_state`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldState {
    /// The row id.
    pub row_id: RowId,
    /// The row's family.
    pub family: String,
    /// The tier it first arrived at.
    pub tier: String,
    /// Did it first arrive through the replicated door?
    pub replicated: bool,
    /// Its [`plane`].
    pub plane: String,
    /// Its projection slot: rows sharing one slot project into one typed
    /// record (an occurrence pair); a row alone in its slot names itself.
    pub slot: String,
    /// `None`: concluded. `Some`: why it concludes nothing.
    pub held: Option<HeldReason>,
}

/// What one fold evaluation recorded for a row: the storage unit
/// ([`FederationDirectory::put_fold_record`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldRecord {
    /// The row id.
    pub row_id: RowId,
    /// The row's family.
    pub family: String,
    /// The tier the row concludes at (its first arrival's).
    pub tier: String,
    /// v4 — did it first arrive through the replicated door?
    pub replicated: bool,
    /// v4 — its [`plane`].
    pub plane: String,
    /// v4 — its projection slot ([`FoldState::slot`]).
    pub slot: String,
    /// `None`: concluded. `Some((reason, detail))`: held, concluding nothing.
    pub held: Option<(String, String)>,
    /// Every input the evaluation read ([`Dep::read_key`]), always including
    /// the row's own `row:<id>`.
    pub reads: BTreeSet<String>,
}

/// v4 — **the arrival a row is folded under**: how it FIRST arrived. The
/// door (`ingest::put_admitted_row`) runs under it, every record written
/// inside reads it, and a re-fold replays it exactly (T1: a replicated
/// membership change re-folds under the replicated door's gates).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arrival {
    /// The row.
    pub row_id: RowId,
    /// The replicated door (a peer offered it under an id) or the local one.
    pub replicated: bool,
    /// The tier.
    pub tier: String,
    /// Its [`plane`].
    pub plane: &'static str,
    /// Its projection slot.
    pub slot: String,
}

tokio::task_local! {
    static ARRIVAL: Arrival;
}

/// Run `fut` under `arrival` (the door's own use).
pub(crate) async fn arriving<T, Fut>(arrival: Arrival, fut: Fut) -> T
where
    Fut: std::future::Future<Output = T>,
{
    ARRIVAL.scope(arrival, fut).await
}

fn current_arrival(row_id: &RowId) -> Option<Arrival> {
    ARRIVAL
        .try_with(|a| (a.row_id == *row_id).then(|| a.clone()))
        .ok()
        .flatten()
}

/// What one re-fold pass changed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RefoldReport {
    /// Held, now concluded.
    pub concluded: Vec<RowId>,
    /// Concluded, now held.
    pub unconcluded: Vec<RowId>,
    /// Re-folded and still held (the reason may have changed).
    pub still_held: Vec<RowId>,
    /// Rows evaluated.
    pub steps: usize,
}

// ─────────────────────────────────────────────────────────────────────────
//  The attempt (task-local): what gates mark
// ─────────────────────────────────────────────────────────────────────────

/// One evaluation of a row's gates.
struct Attempt {
    row_id: RowId,
    /// The voice the door is offering now (counted with the held ones while
    /// the gates run; kept only if the row concludes or is held).
    offered: Option<Voice>,
    /// The first fold condition a gate found unmet: `(reason, detail)`.
    held: Mutex<Option<(String, String)>>,
    /// Every input declared.
    reads: Mutex<BTreeSet<String>>,
}

tokio::task_local! {
    static ATTEMPT: Arc<Attempt>;
}

/// **Declare an input** the running fold read. A no-op outside an attempt.
pub fn reads(dep: Dep) {
    let _ = ATTEMPT.try_with(|a| {
        if let Ok(mut r) = a.reads.lock() {
            r.insert(dep.read_key());
        }
    });
}

/// Is a fold attempt running on this task?
#[must_use]
pub fn in_attempt() -> bool {
    ATTEMPT.try_with(|_| ()).is_ok()
}

fn mark(reason: &'static str, detail: String) {
    let _ = ATTEMPT.try_with(|a| {
        if let Ok(mut h) = a.held.lock() {
            if h.is_none() {
                *h = Some((reason.to_owned(), detail));
            }
        }
    });
}

/// **A fold condition is unmet**: mark the running attempt held with
/// `reason` (the error's text is the detail) and return `err` unchanged. The
/// door then keeps the voice and concludes nothing. Outside an attempt this
/// is the plain refusal it wraps.
#[must_use]
pub fn hold(reason: &'static str, err: Error) -> Error {
    mark(reason, err.to_string());
    err
}

/// Mark the running attempt held with `reason`, without an error in hand
/// (V1b's `note_short`). The door fills the detail from the refusal the gate
/// returns.
pub(crate) fn note(reason: &'static str) {
    mark(reason, String::new());
}

/// The offered voice of the running attempt, when it is an attempt for
/// `row_id` (`voices::voices_of_row` counts it with the held ones).
pub(crate) fn offered_voice(row_id: &RowId) -> Option<Voice> {
    ATTEMPT
        .try_with(|a| {
            if a.row_id == *row_id {
                a.offered.clone()
            } else {
                None
            }
        })
        .ok()
        .flatten()
}

/// What an attempt recorded: the first unmet condition and every read.
pub(crate) struct Attempted {
    /// `(reason, detail)` of the first unmet condition, if any.
    pub(crate) held: Option<(String, String)>,
    /// Every read, including `row:<row id>`.
    pub(crate) reads: BTreeSet<String>,
}

/// Run `fut` (the row's gates) as a fold attempt for `row_id`, with
/// `offered` counted as one of its voices.
pub(crate) async fn attempt<T, Fut>(
    row_id: RowId,
    offered: Option<Voice>,
    fut: Fut,
) -> (T, Attempted)
where
    Fut: std::future::Future<Output = T>,
{
    let a = Arc::new(Attempt {
        row_id,
        offered,
        held: Mutex::new(None),
        reads: Mutex::new(BTreeSet::new()),
    });
    let out = ATTEMPT.scope(a.clone(), fut).await;
    let held = a.held.lock().ok().and_then(|g| g.clone());
    let mut reads = a.reads.lock().map(|g| g.clone()).unwrap_or_default();
    reads.insert(Dep::Row(row_id).read_key());
    (out, Attempted { held, reads })
}

// ─────────────────────────────────────────────────────────────────────────
//  Recording
// ─────────────────────────────────────────────────────────────────────────

/// Store what an evaluation found for `row_id`. The arrival context (the
/// replicated flag, the tier, the plane, the slot) is the running door's
/// ([`Arrival`]); outside one, the row's stored state's; for a row never
/// folded, the local attestation plane at `tier`. A directory with no fold
/// store (the capsule proxy, whose owner runs the fold) answers
/// `Unsupported`, which is logged and skipped.
///
/// # Errors
/// Storage failures.
pub(crate) async fn record<F>(
    dir: &F,
    row_id: RowId,
    family: &str,
    tier: &str,
    held: Option<(String, String)>,
    reads: BTreeSet<String>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let (tier, replicated, plane_name, slot) = match current_arrival(&row_id) {
        Some(a) => (a.tier, a.replicated, a.plane.to_owned(), a.slot),
        None => match dir.fold_state(&row_id).await {
            Ok(Some(s)) => (s.tier, s.replicated, s.plane, s.slot),
            Ok(None) | Err(Error::Unsupported { .. }) => (
                tier.to_owned(),
                false,
                plane::ATTESTATION.to_owned(),
                Dep::Row(row_id).read_key(),
            ),
            Err(e) => return Err(e),
        },
    };
    let rec = FoldRecord {
        row_id,
        family: family.to_owned(),
        tier,
        replicated,
        plane: plane_name,
        slot,
        held,
        reads,
    };
    match dir.put_fold_record(&rec).await {
        Ok(()) => Ok(()),
        Err(Error::Unsupported { method }) => {
            tracing::debug!(method, row_id = %row_id.hex(), "no fold store on this directory");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// v4 — **is this held statement held BACK** (its row concludes nothing)?
/// The key plane's reader (`ingest::held_keys_for_kid`) skips such a
/// statement, so a held `key:revocation` or `key:record` is not read as
/// key plane until it concludes.
///
/// # Errors
/// Storage failures.
pub async fn is_held_back<F>(dir: &F, statement: &[u8]) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    match RowId::of_statement(statement) {
        Some(id) => Ok(dir.fold_held(&id).await?.is_some()),
        None => Ok(false),
    }
}

/// v4 — the boot hook: a re-fold interrupted between taking a row out of
/// its typed table and recording why (`refolding`) is repaired by
/// [`refold_all`]. One indexed probe when none is.
///
/// # Errors
/// Storage failures; the re-fold's.
pub async fn repair_at_open<F>(dir: &F) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if dir.fold_any_refolding().await? {
        let report = Box::pin(refold_all(dir)).await?;
        tracing::info!(
            steps = report.steps,
            concluded = report.concluded.len(),
            unconcluded = report.unconcluded.len(),
            "fold: repaired an interrupted re-fold at open"
        );
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
//  The reason API
// ─────────────────────────────────────────────────────────────────────────

/// **Why `row_id` concludes nothing.** `None` when it is concluded, or not
/// held here.
///
/// # Errors
/// Storage failures.
pub async fn why_held<F>(dir: &F, row_id: &RowId) -> Result<Option<HeldReason>, Error>
where
    F: FederationDirectory + ?Sized,
{
    dir.fold_held(row_id).await
}

/// The held rows that conclude nothing, in row-id order after `after`, at
/// most `limit` (clamped to [`MAX_HELD_PAGE`]).
///
/// # Errors
/// Storage failures.
pub async fn held_rows<F>(
    dir: &F,
    after: Option<&RowId>,
    limit: u32,
) -> Result<Vec<HeldReason>, Error>
where
    F: FederationDirectory + ?Sized,
{
    dir.fold_held_page(after, limit.min(MAX_HELD_PAGE)).await
}

// ─────────────────────────────────────────────────────────────────────────
//  What a statement touches
// ─────────────────────────────────────────────────────────────────────────

/// The read keys a statement touches: its own row, every row it names, its
/// signer (`iss`, the kid), its subject, its author, and its family.
#[must_use]
pub fn touches(admitted: &AdmittedRow) -> BTreeSet<String> {
    let mut t = BTreeSet::new();
    t.insert(Dep::Row(admitted.row_id).read_key());
    for n in &admitted.names {
        t.insert(Dep::Row(n.row).read_key());
    }
    t.insert(Dep::key(&admitted.iss).read_key());
    t.insert(Dep::key(&admitted.sub).read_key());
    t.insert(Dep::key(&hex::encode(admitted.kid)).read_key());
    if let Some(a) = &admitted.author {
        t.insert(Dep::key(a).read_key());
    }
    t.insert(Dep::Family(admitted.family.clone()).read_key());
    t
}

/// The read keys a typed attestation row touches: its id (when it is an
/// edition-2 row id), its attester, its attested key and its subjects.
#[must_use]
pub fn touches_of_attestation(row: &Attestation) -> BTreeSet<String> {
    let mut t = BTreeSet::new();
    if let Some(id) = super::voices::carried_row_id(row) {
        t.insert(Dep::Row(id).read_key());
    }
    t.insert(Dep::key(&row.attesting_key_id).read_key());
    t.insert(Dep::key(&row.attested_key_id).read_key());
    for s in &row.subject_key_ids {
        t.insert(Dep::key(s).read_key());
    }
    if let Some(f) = family_of_row(row) {
        t.insert(Dep::Family(f).read_key());
    }
    t
}

/// The family of the statement a typed row carries.
fn family_of_row(row: &Attestation) -> Option<String> {
    let h = row
        .attestation_envelope
        .get(super::ingest::STATEMENT_MEMBER)?
        .as_str()?;
    let bytes = hex::decode(h).ok()?;
    let (protected, _) = super::liveness::statement_parts(&bytes)?;
    protected.get_int(-70002)?.as_text().map(str::to_owned)
}

/// Every read key of `admitted`, widened by one hop: the touches of every
/// typed row it names (a withdrawal's target's attester and subject), and of
/// its own typed projection.
async fn touched_by<F>(dir: &F, admitted: &AdmittedRow) -> Result<BTreeSet<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut t = touches(admitted);
    for n in &admitted.names {
        if let Some(a) = dir.get_attestation(&n.row.hex()).await? {
            t.extend(touches_of_attestation(&a));
        }
    }
    if let Some(a) = dir.get_attestation(&admitted.row_id.hex()).await? {
        t.extend(touches_of_attestation(&a));
    }
    Ok(t)
}

// ─────────────────────────────────────────────────────────────────────────
//  The door's tail
// ─────────────────────────────────────────────────────────────────────────

/// **After `put_statement` stored a statement**: every held or concluded
/// row whose fold read what it touches is re-folded ([`refold_touched`]).
/// (v4: the hold/conclusion bookkeeping moved into the door,
/// `ingest::put_admitted_row`, where the arrival is known.) This runs on a
/// re-offer too, so a caller that retries after a failed re-fold heals it.
///
/// # Errors
/// Storage failures (the statement itself is already kept).
pub(crate) async fn after_statement<F>(
    dir: &F,
    admitted: &AdmittedRow,
    tier: &str,
    outcome: &StatementOutcome,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let _ = tier;
    match outcome {
        StatementOutcome::Pending { .. } => Ok(()),
        StatementOutcome::Row { .. }
        | StatementOutcome::Voice { .. }
        | StatementOutcome::KeyPlane { .. } => {
            let touched = touched_by(dir, admitted).await?;
            refold_touched(dir, touched).await.map(|_| ())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  The planes: how a concluded row leaves its typed table
// ─────────────────────────────────────────────────────────────────────────

/// v4 — **one plane's un-project hook.** The fold concludes a row on every
/// plane the same way (it re-runs the door, `ingest::put_admitted_row`,
/// under the row's [`Arrival`]); un-concluding differs per plane:
///
/// - a plane with a dry re-check ([`Plane::recheck`]: the attestation plan)
///   re-asks its gates without writing, and takes the row out only when a
///   gate marks a fold condition;
/// - otherwise the fold takes the row's whole SLOT out
///   ([`Plane::unconclude`]) and re-concludes every concluded row of the
///   slot, the row itself included, under each one's own arrival: the
///   slot's typed record is rebuilt from the rows that still conclude (an
///   occurrence pair's newest-signed concluded bind wins again);
/// - a FINAL plane ([`Plane::is_final`]) never un-concludes: its rows are
///   counted acts final once the count is met, or acts read only from their
///   own signer (CC 2.7.5: "A count once met is final"; "a revocation never
///   lapses"). Its gates must read only the row's named past
///   (`Dep::Row(named)`), which no later row changes.
#[async_trait::async_trait]
pub trait Plane: Send + Sync {
    /// The [`plane`] name.
    fn name(&self) -> &'static str;

    /// A FINAL plane: nothing un-concludes its rows.
    fn is_final(&self) -> bool {
        false
    }

    /// Re-ask the plane's gates about a concluded row WITHOUT writing.
    /// `None`: this plane has no dry re-check (the fold un-projects the
    /// slot and re-concludes it instead).
    async fn recheck(
        &self,
        dir: &dyn FederationDirectory,
        row: &AdmittedRow,
    ) -> Option<Result<(), Error>> {
        let _ = (dir, row);
        None
    }

    /// Take the projection of `row`'s slot out of the plane's typed tables.
    /// Its statements stay held.
    ///
    /// # Errors
    /// Storage failures.
    async fn unconclude(
        &self,
        dir: &dyn FederationDirectory,
        row: &AdmittedRow,
    ) -> Result<(), Error>;
}

/// The attestation plane (and T2's attestation-backed families).
struct AttestationPlane(&'static str);

#[async_trait::async_trait]
impl Plane for AttestationPlane {
    fn name(&self) -> &'static str {
        self.0
    }

    async fn recheck(
        &self,
        dir: &dyn FederationDirectory,
        row: &AdmittedRow,
    ) -> Option<Result<(), Error>> {
        match dir.get_attestation(&row.row_id.hex()).await {
            Ok(Some(a)) => Some(dir.recheck_attestation(&a).await),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }

    async fn unconclude(
        &self,
        dir: &dyn FederationDirectory,
        row: &AdmittedRow,
    ) -> Result<(), Error> {
        dir.unconclude_attestation(&row.row_id.hex())
            .await
            .map(|_| ())
    }
}

/// T2's trust edges: the attestation row, then the v1.3 trust rows of the
/// edge's two ends re-derived (`typed::project_trust_for`).
struct TrustPlane;

#[async_trait::async_trait]
impl Plane for TrustPlane {
    fn name(&self) -> &'static str {
        plane::TRUST
    }

    async fn recheck(
        &self,
        dir: &dyn FederationDirectory,
        row: &AdmittedRow,
    ) -> Option<Result<(), Error>> {
        AttestationPlane(plane::TRUST).recheck(dir, row).await
    }

    async fn unconclude(
        &self,
        dir: &dyn FederationDirectory,
        row: &AdmittedRow,
    ) -> Result<(), Error> {
        let ends = dir
            .get_attestation(&row.row_id.hex())
            .await?
            .map(|a| (a.attesting_key_id, a.attested_key_id));
        dir.unconclude_attestation(&row.row_id.hex()).await?;
        if let Some((from, to)) = ends {
            Box::pin(super::typed::project_trust_for(dir, &from)).await?;
            Box::pin(super::typed::project_trust_for(dir, &to)).await?;
        }
        Ok(())
    }
}

/// The key plane: its read model is re-derived from the key statements not
/// held back (`ingest::put_admitted_row` re-projects after a change), so
/// there is nothing to delete.
struct KeyPlane;

#[async_trait::async_trait]
impl Plane for KeyPlane {
    fn name(&self) -> &'static str {
        plane::KEY
    }

    async fn unconclude(
        &self,
        dir: &dyn FederationDirectory,
        row: &AdmittedRow,
    ) -> Result<(), Error> {
        let _ = (dir, row);
        Ok(())
    }
}

/// O1's occurrence binds: the pair's current-state row leaves; the pair's
/// concluded binds re-conclude (newest signed wins, the upsert's own rule).
struct OccurrencePlane;

#[async_trait::async_trait]
impl Plane for OccurrencePlane {
    fn name(&self) -> &'static str {
        plane::OCCURRENCE
    }

    async fn unconclude(
        &self,
        dir: &dyn FederationDirectory,
        row: &AdmittedRow,
    ) -> Result<(), Error> {
        let Some((identity, occurrence)) = occurrence_pair(row) else {
            return Ok(());
        };
        dir.clear_occurrence_projection(&identity, &occurrence)
            .await
            .map(|_| ())
    }
}

/// A plane whose concluded rows are final (CC 2.7.5).
struct FinalPlane(&'static str);

#[async_trait::async_trait]
impl Plane for FinalPlane {
    fn name(&self) -> &'static str {
        self.0
    }

    fn is_final(&self) -> bool {
        true
    }

    async fn unconclude(
        &self,
        dir: &dyn FederationDirectory,
        row: &AdmittedRow,
    ) -> Result<(), Error> {
        let _ = (dir, row);
        Ok(())
    }
}

static ATTESTATION_PLANE: AttestationPlane = AttestationPlane(plane::ATTESTATION);
static TYPED_ATTESTATION_PLANE: AttestationPlane = AttestationPlane(plane::TYPED_ATTESTATION);
static TRUST_PLANE: TrustPlane = TrustPlane;
static KEY_PLANE: KeyPlane = KeyPlane;
static OCCURRENCE_PLANE: OccurrencePlane = OccurrencePlane;
static GROUP_PLANE: FinalPlane = FinalPlane(plane::GROUP);
static REBIND_PLANE: FinalPlane = FinalPlane(plane::REBIND);
static TYPED_FINAL_PLANE: FinalPlane = FinalPlane(plane::TYPED_FINAL);

/// The [`Plane`] stored under `name` (an unknown name reads as the
/// attestation plane, the earliest records' default).
#[must_use]
pub fn plane_for(name: &str) -> &'static dyn Plane {
    match name {
        plane::TYPED_ATTESTATION => &TYPED_ATTESTATION_PLANE,
        plane::TRUST => &TRUST_PLANE,
        plane::KEY => &KEY_PLANE,
        plane::OCCURRENCE => &OCCURRENCE_PLANE,
        plane::GROUP => &GROUP_PLANE,
        plane::REBIND => &REBIND_PLANE,
        plane::TYPED_FINAL => &TYPED_FINAL_PLANE,
        _ => &ATTESTATION_PLANE,
    }
}

/// An occurrence bind's `(identity_key_id, occurrence_key_id)`, from its
/// payload.
#[must_use]
pub fn occurrence_pair(row: &AdmittedRow) -> Option<(String, String)> {
    let text = |k: &str| {
        row.payload
            .get_text(k)
            .and_then(ciris_verify_core::cde::Value::as_text)
            .map(str::to_owned)
    };
    Some((text("identity_key_id")?, text("occurrence_key_id")?))
}

// ─────────────────────────────────────────────────────────────────────────
//  Re-folding
// ─────────────────────────────────────────────────────────────────────────

/// What re-folding one row did.
enum Change {
    /// Held, now concluded: these keys are touched.
    Concluded(BTreeSet<String>),
    /// Concluded, now held: these keys are touched.
    Unconcluded(BTreeSet<String>),
    /// Held before and after.
    StillHeld,
    /// Nothing to do (concluded and still concluding, or not held here).
    Unchanged,
}

/// The voice that projects a held row: the author's own voice for an
/// authored row, else the first held voice (statement-id order) still
/// admitted under the key plane as it stands. `None` when no held voice
/// admits.
async fn held_primary<F>(dir: &F, row_id: &RowId) -> Result<Option<AdmittedRow>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut first = None;
    for st in dir.edition2_voices(row_id).await? {
        if RowId::of_statement(&st) != Some(*row_id) {
            continue;
        }
        let keys = super::ingest::held_keys_for(dir, &st).await?;
        let Ok(a) = super::door::admit_row(
            &st,
            &keys,
            Some(&row_id.0),
            ciris_verify_core::edition2::family::SelectContext::default(),
        ) else {
            continue;
        };
        if a.author.as_deref() == Some(a.iss.as_str()) {
            return Ok(Some(a));
        }
        if first.is_none() {
            first = Some(a);
        }
    }
    Ok(first)
}

/// Re-run the door for a held or concluded row under its own stored
/// arrival (v4).
async fn reconclude<F>(
    dir: &F,
    primary: &AdmittedRow,
    state: &FoldState,
) -> Result<StatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    // X2 build fix: a re-conclusion re-judges a row this node already holds
    // (metered at its first receipt), so it writes as the node's own act.
    Box::pin(super::ingest::put_admitted_row(
        dir,
        primary,
        &state.tier,
        state.replicated,
        crate::federation::replication::admission::WriteOrigin::Authored,
    ))
    .await
}

/// Re-fold one row.
async fn refold_row<F>(dir: &F, row_id: &RowId) -> Result<Change, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(state) = dir.fold_state(row_id).await? else {
        return Ok(Change::Unchanged);
    };
    let Some(primary) = held_primary(dir, row_id).await? else {
        return Ok(if state.held.is_some() {
            Change::StillHeld
        } else {
            Change::Unchanged
        });
    };
    // Held: re-run the door under the row's own arrival.
    if state.held.is_some() {
        return match reconclude(dir, &primary, &state).await {
            Ok(StatementOutcome::Pending { .. }) => Ok(Change::StillHeld),
            Ok(_) => Ok(Change::Concluded(touched_by(dir, &primary).await?)),
            Err(e) => {
                let mut reads = BTreeSet::new();
                reads.insert(Dep::Row(*row_id).read_key());
                record(
                    dir,
                    *row_id,
                    &state.family,
                    &state.tier,
                    Some((reason::REFOLD_REFUSED.to_owned(), e.to_string())),
                    reads,
                )
                .await?;
                Ok(Change::StillHeld)
            }
        };
    }
    // Concluded.
    let pl = plane_for(&state.plane);
    if pl.is_final() {
        return Ok(Change::Unchanged);
    }
    let ddir = dir.as_dyn_directory();
    let (checked, att) = attempt(*row_id, None, pl.recheck(ddir, &primary)).await;
    if let Some(out) = checked {
        return match (out, att.held) {
            (Ok(()), _) => {
                record(dir, *row_id, &state.family, &state.tier, None, att.reads).await?;
                Ok(Change::Unchanged)
            }
            (Err(e), Some((r, d))) => {
                let d = if d.is_empty() { e.to_string() } else { d };
                // The marker first: a crash between it and the final record
                // leaves a row `refolding`, which the boot hook repairs.
                record(
                    dir,
                    *row_id,
                    &state.family,
                    &state.tier,
                    Some((reason::REFOLDING.to_owned(), d.clone())),
                    att.reads.clone(),
                )
                .await?;
                // What the projection touched, read before it leaves.
                let touched = touched_by(dir, &primary).await?;
                pl.unconclude(ddir, &primary).await?;
                record(
                    dir,
                    *row_id,
                    &state.family,
                    &state.tier,
                    Some((r, d)),
                    att.reads,
                )
                .await?;
                Ok(Change::Unconcluded(touched))
            }
            (Err(e), None) => {
                // A refusal no gate marked: not a fold condition. The row
                // keeps its conclusion (CC: never refused retroactively).
                tracing::warn!(
                    row_id = %row_id.hex(),
                    error = %e,
                    "fold re-check met an unmarked refusal; the row stays concluded"
                );
                Ok(Change::Unchanged)
            }
        };
    }
    // No dry re-check: take the slot out, then re-conclude every concluded
    // row of it, this one included, each under its own arrival.
    record(
        dir,
        *row_id,
        &state.family,
        &state.tier,
        Some((reason::REFOLDING.to_owned(), String::new())),
        [Dep::Row(*row_id).read_key()].into_iter().collect(),
    )
    .await?;
    let touched = touched_by(dir, &primary).await?;
    pl.unconclude(ddir, &primary).await?;
    let mut slot: BTreeSet<RowId> = dir.fold_slot_rows(&state.slot).await?.into_iter().collect();
    slot.insert(*row_id);
    let mut this = Change::Unchanged;
    for id in slot {
        let (Some(st), Some(p)) = (dir.fold_state(&id).await?, held_primary(dir, &id).await?)
        else {
            continue;
        };
        let out = reconclude(dir, &p, &st).await;
        if id == *row_id {
            this = match out {
                Ok(StatementOutcome::Pending { .. }) => Change::Unconcluded(touched.clone()),
                Ok(_) => Change::Unchanged,
                Err(e) => {
                    record(
                        dir,
                        id,
                        &st.family,
                        &st.tier,
                        Some((reason::REFOLD_REFUSED.to_owned(), e.to_string())),
                        [Dep::Row(id).read_key()].into_iter().collect(),
                    )
                    .await?;
                    Change::Unconcluded(touched.clone())
                }
            };
        } else if let Err(e) = out {
            tracing::warn!(
                row_id = %id.hex(),
                error = %e,
                "fold: a slot sibling did not re-conclude"
            );
        }
    }
    Ok(this)
}

/// The rows whose folds read any of `touched`.
async fn dependents<F>(dir: &F, touched: &BTreeSet<String>) -> Result<BTreeSet<RowId>, Error>
where
    F: FederationDirectory + ?Sized,
{
    if touched.is_empty() {
        return Ok(BTreeSet::new());
    }
    let keys: Vec<String> = touched.iter().cloned().collect();
    Ok(dir.fold_dependents(&keys).await?.into_iter().collect())
}

/// The worklist: re-fold in row-id order, cascading each change.
async fn run<F>(dir: &F, mut queue: BTreeSet<RowId>) -> Result<RefoldReport, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut report = RefoldReport::default();
    while let Some(id) = queue.pop_first() {
        if report.steps >= MAX_REFOLD_STEPS {
            tracing::warn!(
                remaining = queue.len() + 1,
                "fold re-fold pass reached MAX_REFOLD_STEPS; the rest re-folds on the next touch"
            );
            break;
        }
        report.steps += 1;
        match Box::pin(refold_row(dir, &id)).await? {
            Change::Concluded(t) => {
                report.concluded.push(id);
                let mut next = dependents(dir, &t).await?;
                next.remove(&id);
                queue.extend(next);
            }
            Change::Unconcluded(t) => {
                report.unconcluded.push(id);
                let mut next = dependents(dir, &t).await?;
                next.remove(&id);
                queue.extend(next);
            }
            Change::StillHeld => report.still_held.push(id),
            Change::Unchanged => {}
        }
    }
    Ok(report)
}

/// **The re-fold hook.** Re-fold every row whose fold read any of
/// `touched`, then every row those changes touch, until nothing changes.
///
/// # Errors
/// Storage failures.
pub async fn refold_touched<F>(dir: &F, touched: BTreeSet<String>) -> Result<RefoldReport, Error>
where
    F: FederationDirectory + ?Sized,
{
    let queue = dependents(dir, &touched).await?;
    if queue.is_empty() {
        return Ok(RefoldReport::default());
    }
    run(dir, queue).await
}

/// Re-fold exactly `rows`, and cascade.
///
/// # Errors
/// Storage failures.
pub async fn refold_rows<F>(dir: &F, rows: BTreeSet<RowId>) -> Result<RefoldReport, Error>
where
    F: FederationDirectory + ?Sized,
{
    run(dir, rows).await
}

/// Re-fold every held row: the repair sweep (a crash mid-refold, a rule
/// change).
///
/// # Errors
/// Storage failures.
pub async fn refold_all<F>(dir: &F) -> Result<RefoldReport, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut rows = BTreeSet::new();
    let mut after: Option<RowId> = None;
    loop {
        let page = dir.fold_held_page(after.as_ref(), MAX_HELD_PAGE).await?;
        let Some(last) = page.last().map(|h| h.row_id) else {
            break;
        };
        rows.extend(page.iter().map(|h| h.row_id));
        if page.len() < MAX_HELD_PAGE as usize {
            break;
        }
        after = Some(last);
    }
    run(dir, rows).await
}

// ─────────────────────────────────────────────────────────────────────────
//  Storage (both dialects; the backends call these)
// ─────────────────────────────────────────────────────────────────────────

/// The `ceg_fold_state` columns, in the baseline's order (v4; it replaces
/// v1's `ceg_fold_held`).
pub const STATE_COLUMNS: [&str; 9] = [
    "row_id",
    "family",
    "tier",
    "replicated",
    "plane",
    "slot",
    "reason",
    "detail",
    "since_us",
];

/// The `ceg_fold_reads` columns.
pub const READS_COLUMNS: [&str; 2] = ["read_key", "row_id"];

#[cfg(any(feature = "sqlite", feature = "postgres"))]
const STATE_SELECT: &str =
    "row_id, family, tier, replicated, plane, slot, reason, detail, since_us";

#[cfg(any(feature = "sqlite", feature = "postgres"))]
fn row_id_of(b: &[u8], table: &str) -> Result<RowId, Error> {
    <[u8; 32]>::try_from(b)
        .map(RowId)
        .map_err(|_| Error::Backend(format!("{table}: row_id length")))
}

/// One `ceg_fold_state` row as read.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
struct StateCols {
    row_id: Vec<u8>,
    family: String,
    tier: String,
    replicated: bool,
    plane: String,
    slot: String,
    reason: Option<String>,
    detail: Option<String>,
    since_us: Option<i64>,
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
impl StateCols {
    fn into_state(self) -> Result<FoldState, Error> {
        let row_id = row_id_of(&self.row_id, "ceg_fold_state")?;
        let held = self.reason.map(|reason| HeldReason {
            row_id,
            family: self.family.clone(),
            tier: self.tier.clone(),
            replicated: self.replicated,
            plane: self.plane.clone(),
            reason,
            detail: self.detail.unwrap_or_default(),
            since_us: self.since_us.unwrap_or_default(),
        });
        Ok(FoldState {
            row_id,
            family: self.family,
            tier: self.tier,
            replicated: self.replicated,
            plane: self.plane,
            slot: self.slot,
            held,
        })
    }
}

/// sqlite: store a fold record in one transaction.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn put_record_sqlite(conn: &mut rusqlite::Connection, rec: &FoldRecord) -> Result<(), Error> {
    let be = |e: rusqlite::Error| Error::Backend(format!("ceg_fold: {e}"));
    let tx = crate::store::sqlite_conn_model::write_tx(conn).map_err(be)?;
    let id = &rec.row_id.0[..];
    tx.execute(
        "DELETE FROM ceg_fold_reads WHERE row_id = ?1",
        rusqlite::params![id],
    )
    .map_err(be)?;
    for k in &rec.reads {
        tx.execute(
            "INSERT OR IGNORE INTO ceg_fold_reads (read_key, row_id) VALUES (?1, ?2)",
            rusqlite::params![k, id],
        )
        .map_err(be)?;
    }
    let (reason, detail) = match &rec.held {
        Some((r, d)) => (Some(r.as_str()), Some(d.as_str())),
        None => (None, None),
    };
    let now = crate::host::clock::now().timestamp_micros();
    tx.execute(
        "INSERT INTO ceg_fold_state (row_id, family, tier, replicated, plane, slot, reason, \
         detail, since_us) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, \
         CASE WHEN ?7 IS NULL THEN NULL ELSE ?9 END) \
         ON CONFLICT (row_id) DO UPDATE SET family = excluded.family, tier = excluded.tier, \
         replicated = excluded.replicated, plane = excluded.plane, slot = excluded.slot, \
         since_us = CASE WHEN excluded.reason IS NULL THEN NULL \
         WHEN ceg_fold_state.reason = excluded.reason THEN ceg_fold_state.since_us \
         ELSE excluded.since_us END, \
         reason = excluded.reason, detail = excluded.detail",
        rusqlite::params![
            id,
            rec.family,
            rec.tier,
            i64::from(rec.replicated),
            rec.plane,
            rec.slot,
            reason,
            detail,
            now
        ],
    )
    .map_err(be)?;
    tx.commit().map_err(be)
}

#[cfg(feature = "sqlite")]
fn state_of_sqlite(r: &rusqlite::Row<'_>) -> rusqlite::Result<StateCols> {
    Ok(StateCols {
        row_id: r.get(0)?,
        family: r.get(1)?,
        tier: r.get(2)?,
        replicated: r.get::<_, i64>(3)? != 0,
        plane: r.get(4)?,
        slot: r.get(5)?,
        reason: r.get(6)?,
        detail: r.get(7)?,
        since_us: r.get(8)?,
    })
}

/// sqlite: the fold state of one row.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn state_sqlite(
    conn: &rusqlite::Connection,
    row_id: &RowId,
) -> Result<Option<FoldState>, Error> {
    use rusqlite::OptionalExtension as _;
    let got = conn
        .query_row(
            &format!("SELECT {STATE_SELECT} FROM ceg_fold_state WHERE row_id = ?1"),
            rusqlite::params![&row_id.0[..]],
            state_of_sqlite,
        )
        .optional()
        .map_err(|e| Error::Backend(format!("ceg_fold_state: {e}")))?;
    got.map(StateCols::into_state).transpose()
}

/// sqlite: the held reason of one row (`None` when concluded or unknown).
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn held_sqlite(
    conn: &rusqlite::Connection,
    row_id: &RowId,
) -> Result<Option<HeldReason>, Error> {
    Ok(state_sqlite(conn, row_id)?.and_then(|s| s.held))
}

/// sqlite: a page of held reasons in row-id order after `after`.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn held_page_sqlite(
    conn: &rusqlite::Connection,
    after: Option<&RowId>,
    limit: u32,
) -> Result<Vec<HeldReason>, Error> {
    let be = |e: rusqlite::Error| Error::Backend(format!("ceg_fold_state: {e}"));
    let after: Vec<u8> = after.map_or_else(Vec::new, |a| a.0.to_vec());
    let mut st = conn
        .prepare(&format!(
            "SELECT {STATE_SELECT} FROM ceg_fold_state WHERE reason IS NOT NULL AND row_id > ?1 \
             ORDER BY row_id LIMIT ?2"
        ))
        .map_err(be)?;
    let rows = st
        .query_map(
            rusqlite::params![after, i64::from(limit.min(MAX_HELD_PAGE))],
            state_of_sqlite,
        )
        .map_err(be)?;
    let mut out = Vec::new();
    for r in rows {
        if let Some(h) = r.map_err(be)?.into_state()?.held {
            out.push(h);
        }
    }
    Ok(out)
}

/// sqlite: the CONCLUDED rows of one projection slot, in row-id order.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn slot_rows_sqlite(conn: &rusqlite::Connection, slot: &str) -> Result<Vec<RowId>, Error> {
    let be = |e: rusqlite::Error| Error::Backend(format!("ceg_fold_state: {e}"));
    let mut st = conn
        .prepare(
            "SELECT row_id FROM ceg_fold_state WHERE slot = ?1 AND reason IS NULL ORDER BY row_id",
        )
        .map_err(be)?;
    let rows = st
        .query_map(rusqlite::params![slot], |r| r.get::<_, Vec<u8>>(0))
        .map_err(be)?;
    let mut out = Vec::new();
    for r in rows {
        out.push(row_id_of(&r.map_err(be)?, "ceg_fold_state")?);
    }
    Ok(out)
}

/// sqlite: is any row left `refolding` (an interrupted re-fold)?
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn any_refolding_sqlite(conn: &rusqlite::Connection) -> Result<bool, Error> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM ceg_fold_state WHERE reason = ?1)",
        rusqlite::params![reason::REFOLDING],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n != 0)
    .map_err(|e| Error::Backend(format!("ceg_fold_state: {e}")))
}

/// sqlite: the rows whose folds read any of `read_keys`, distinct, in
/// row-id order.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn dependents_sqlite(
    conn: &rusqlite::Connection,
    read_keys: &[String],
) -> Result<Vec<RowId>, Error> {
    let be = |e: rusqlite::Error| Error::Backend(format!("ceg_fold_reads: {e}"));
    let mut st = conn
        .prepare("SELECT row_id FROM ceg_fold_reads WHERE read_key = ?1")
        .map_err(be)?;
    let mut out = BTreeSet::new();
    for k in read_keys {
        let rows = st
            .query_map(rusqlite::params![k], |r| r.get::<_, Vec<u8>>(0))
            .map_err(be)?;
        for r in rows {
            out.insert(row_id_of(&r.map_err(be)?, "ceg_fold_reads")?);
        }
    }
    Ok(out.into_iter().collect())
}

/// sqlite: take one occurrence pair's current-state row out
/// (`federation_identity_occurrences`); its history rows stay.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn clear_occurrence_sqlite(
    conn: &mut rusqlite::Connection,
    identity: &str,
    occurrence: &str,
) -> Result<bool, Error> {
    conn.execute(
        "DELETE FROM federation_identity_occurrences \
         WHERE identity_key_id = ?1 AND occurrence_key_id = ?2",
        rusqlite::params![identity, occurrence],
    )
    .map(|n| n > 0)
    .map_err(|e| Error::Backend(format!("federation_identity_occurrences: {e}")))
}

/// postgres: store a fold record in one transaction.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn put_record_postgres(
    client: &mut deadpool_postgres::Object,
    rec: &FoldRecord,
) -> Result<(), Error> {
    let be = |e: tokio_postgres::Error| Error::Backend(format!("ceg_fold: {e}"));
    let tx = client.transaction().await.map_err(be)?;
    let id: &[u8] = &rec.row_id.0[..];
    tx.execute(
        "DELETE FROM cirislens.ceg_fold_reads WHERE row_id = $1",
        &[&id],
    )
    .await
    .map_err(be)?;
    for k in &rec.reads {
        tx.execute(
            "INSERT INTO cirislens.ceg_fold_reads (read_key, row_id) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
            &[k, &id],
        )
        .await
        .map_err(be)?;
    }
    let (reason, detail): (Option<&str>, Option<&str>) = match &rec.held {
        Some((r, d)) => (Some(r.as_str()), Some(d.as_str())),
        None => (None, None),
    };
    let since: Option<i64> = reason.map(|_| crate::host::clock::now().timestamp_micros());
    tx.execute(
        "INSERT INTO cirislens.ceg_fold_state AS s (row_id, family, tier, replicated, plane, \
         slot, reason, detail, since_us) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (row_id) DO UPDATE SET family = EXCLUDED.family, tier = EXCLUDED.tier, \
         replicated = EXCLUDED.replicated, plane = EXCLUDED.plane, slot = EXCLUDED.slot, \
         since_us = CASE WHEN EXCLUDED.reason IS NULL THEN NULL \
         WHEN s.reason = EXCLUDED.reason THEN s.since_us ELSE EXCLUDED.since_us END, \
         reason = EXCLUDED.reason, detail = EXCLUDED.detail",
        &[
            &id,
            &rec.family,
            &rec.tier,
            &rec.replicated,
            &rec.plane,
            &rec.slot,
            &reason,
            &detail,
            &since,
        ],
    )
    .await
    .map_err(be)?;
    tx.commit().await.map_err(be)
}

#[cfg(feature = "postgres")]
fn state_of_postgres(r: &tokio_postgres::Row) -> Result<FoldState, Error> {
    StateCols {
        row_id: r.get(0),
        family: r.get(1),
        tier: r.get(2),
        replicated: r.get(3),
        plane: r.get(4),
        slot: r.get(5),
        reason: r.get(6),
        detail: r.get(7),
        since_us: r.get(8),
    }
    .into_state()
}

/// postgres: the fold state of one row.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn state_postgres<C>(client: &C, row_id: &RowId) -> Result<Option<FoldState>, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let sql = format!("SELECT {STATE_SELECT} FROM cirislens.ceg_fold_state WHERE row_id = $1");
    let row = client
        .query_opt(sql.as_str(), &[&&row_id.0[..]])
        .await
        .map_err(|e| Error::Backend(format!("ceg_fold_state: {e}")))?;
    row.as_ref().map(state_of_postgres).transpose()
}

/// postgres: the held reason of one row.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn held_postgres<C>(client: &C, row_id: &RowId) -> Result<Option<HeldReason>, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    Ok(state_postgres(client, row_id).await?.and_then(|s| s.held))
}

/// postgres: a page of held reasons in row-id order after `after`.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn held_page_postgres<C>(
    client: &C,
    after: Option<&RowId>,
    limit: u32,
) -> Result<Vec<HeldReason>, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let after: Vec<u8> = after.map_or_else(Vec::new, |a| a.0.to_vec());
    let limit = i64::from(limit.min(MAX_HELD_PAGE));
    let sql = format!(
        "SELECT {STATE_SELECT} FROM cirislens.ceg_fold_state WHERE reason IS NOT NULL \
         AND row_id > $1 ORDER BY row_id LIMIT $2"
    );
    let rows = client
        .query(sql.as_str(), &[&after, &limit])
        .await
        .map_err(|e| Error::Backend(format!("ceg_fold_state: {e}")))?;
    let mut out = Vec::new();
    for r in &rows {
        if let Some(h) = state_of_postgres(r)?.held {
            out.push(h);
        }
    }
    Ok(out)
}

/// postgres: the CONCLUDED rows of one projection slot, in row-id order.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn slot_rows_postgres<C>(client: &C, slot: &str) -> Result<Vec<RowId>, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let rows = client
        .query(
            "SELECT row_id FROM cirislens.ceg_fold_state WHERE slot = $1 AND reason IS NULL \
             ORDER BY row_id",
            &[&slot],
        )
        .await
        .map_err(|e| Error::Backend(format!("ceg_fold_state: {e}")))?;
    rows.iter()
        .map(|r| {
            let b: Vec<u8> = r.get(0);
            row_id_of(&b, "ceg_fold_state")
        })
        .collect()
}

/// postgres: is any row left `refolding`?
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn any_refolding_postgres<C>(client: &C) -> Result<bool, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let row = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM cirislens.ceg_fold_state WHERE reason = $1)",
            &[&reason::REFOLDING],
        )
        .await
        .map_err(|e| Error::Backend(format!("ceg_fold_state: {e}")))?;
    Ok(row.get::<_, bool>(0))
}

/// postgres: the rows whose folds read any of `read_keys`, distinct, in
/// row-id order.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn dependents_postgres<C>(client: &C, read_keys: &[String]) -> Result<Vec<RowId>, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let keys: Vec<String> = read_keys.to_vec();
    let rows = client
        .query(
            "SELECT DISTINCT row_id FROM cirislens.ceg_fold_reads WHERE read_key = ANY($1) \
             ORDER BY row_id",
            &[&keys],
        )
        .await
        .map_err(|e| Error::Backend(format!("ceg_fold_reads: {e}")))?;
    rows.iter()
        .map(|r| {
            let b: Vec<u8> = r.get(0);
            row_id_of(&b, "ceg_fold_reads")
        })
        .collect()
}

/// postgres: take one occurrence pair's current-state row out; its history
/// rows stay.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn clear_occurrence_postgres<C>(
    client: &C,
    identity: &str,
    occurrence: &str,
) -> Result<bool, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    client
        .execute(
            "DELETE FROM cirislens.federation_identity_occurrences \
             WHERE identity_key_id = $1 AND occurrence_key_id = $2",
            &[&identity, &occurrence],
        )
        .await
        .map(|n| n > 0)
        .map_err(|e| Error::Backend(format!("federation_identity_occurrences: {e}")))
}
