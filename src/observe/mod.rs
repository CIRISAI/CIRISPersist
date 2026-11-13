//! v53.1.8 (CIRISPersist#1014, CIRISServer#746 §4 P0) — **read telemetry,
//! always on.**
//!
//! Two families of process-wide counters, both relaxed atomics in statics:
//! no allocation, no lock and no key string on the read path.
//!
//! - **Per door** (`(backend, door)`): every attestation-returning read of a
//!   [`Door`] counts one read, the rows it returned and the envelope bytes it
//!   decoded. Fed by [`record_read`], the one helper every backend's door
//!   calls. Under `cfg(test)` the same call also feeds
//!   [`crate::federation::read_probe`], so the witnesses' probe and these
//!   counters cannot drift.
//! - **Per fold** ([`Fold`]): [`fold`] counts each entry into a fold and,
//!   through a task-local mask, credits every door read made while the fold
//!   runs to that fold. Attribution is **inclusive**, like a span: a fold
//!   nested in another credits both, so fold totals are not additive across
//!   folds. A fold entered again inside itself is credited once per read.
//!
//! **What "bytes" means, per backend.** The length of the stored
//! `attestation_envelope` TEXT of every row the backend decoded to answer the
//! read — never a re-serialization.
//! - sqlite: the TEXT length `sqlite_row_to_attestation` reads before parsing,
//!   accumulated on the reader thread and drained by
//!   `SqliteBackend::read_measured`.
//! - postgres: the octet length of the TEXT column (V122) as received, read
//!   from the row buffer before decode (`pg_envelope_bytes`).
//!
//! A door that filters after decode (the live consent-grant reads drop rows
//! whose envelope names another dimension) counts the bytes it decoded, which
//! is the cost; `rows` is always what it returned.
//!
//! - **Per caller** (v61.1.0, CIRISPersist#1235): a host names the caller a
//!   read is made for with a bounded [`Caller`] label, through
//!   [`caller_scope`] (a task-local, for Rust hosts) or a
//!   [`ThreadCallerScope`] (a thread scope, for a synchronous boundary such
//!   as the PyO3 surface, whose `block_on` polls the read on the calling
//!   thread). Every door read made under a scope is credited to
//!   `(backend, door, caller)` as well as to `(backend, door)`. The
//!   **innermost scope wins**: a nested scope replaces the label for its
//!   extent, and a task scope wins over a thread scope. A read under no
//!   scope is reported as [`CALLER_UNATTRIBUTED`], derived at [`snapshot`]
//!   time as the door's total minus its attributed reads, so a read with no
//!   scope set costs one task-local probe and one thread-local `Cell` read,
//!   and no atomic. Labels are validated (see [`Caller::new`]) and interned
//!   per counter set; past [`MAX_CALLER_LABELS`] distinct labels every new
//!   label is counted under [`CALLER_OTHER`]. The per-caller rows are a
//!   [`snapshot`] field only (`callers`): host-chosen labels are not a
//!   closed set, so they are not catalogued metric labels and
//!   [`emit_metrics`] does not write them.
//!
//! The counters are process-wide: two Engines in one process share them, as a
//! `metrics` recorder would. [`snapshot`] (and `Engine::telemetry_snapshot`)
//! reads them; [`catalog::TELEMETRY_CATALOG`] names every metric they back.
//! [`emit_metrics`] (v53.2.0, CIRISPersist#1027, CIRISServer#746 §4 P1)
//! writes these same counters through the `metrics` facade at the host's
//! scrape, so the read path stays free of the facade. The catalogue's source
//! is the OpenTelemetry Weaver registry in `telemetry/registry/`.

use std::cell::Cell;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

pub mod catalog;

/// One closed set of label values: the enum, its `ALL` list and the label
/// value each variant renders as.
macro_rules! label_set {
    (
        $(#[$meta:meta])*
        $name:ident { $( $(#[$vmeta:meta])* $variant:ident => $label:literal, )+ }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )+
        }

        impl $name {
            /// Every value, in declaration order (the counters' index order).
            pub const ALL: &'static [$name] = &[$($name::$variant,)+];
            /// How many values the set holds.
            pub const COUNT: usize = Self::ALL.len();

            /// The label value this variant renders as.
            #[must_use]
            pub const fn label(self) -> &'static str {
                match self {
                    $($name::$variant => $label,)+
                }
            }

            /// `(variant identifier, label)` for each value, for the
            /// from-disk catalogue gate.
            #[cfg(test)]
            pub(crate) const IDENTS: &'static [(&'static str, &'static str)] =
                &[$((stringify!($variant), $label),)+];
        }
    };
}

label_set! {
    /// The storage backend a door read ran on.
    ///
    /// Serde: carried inside a [`QueryRows`](crate::federation::attestation_query::QueryRows)
    /// across the directory capsule (CIRISPersist#1162), so a proxied read is
    /// counted against the backend that ran it.
    #[derive(serde::Serialize, serde::Deserialize)]
    StoreBackend {
        /// The SQLite backend.
        Sqlite => "sqlite",
        /// The PostgreSQL backend.
        Postgres => "postgres",
    }
}

label_set! {
    /// An attestation-returning read. The label is the method name.
    Door {
        /// `ReadEngine::list_attestations` (the cursor-paged filter read).
        ListAttestations => "list_attestations",
        /// `FederationDirectory::list_attestations_by_dimension_citing`.
        ListAttestationsByDimensionCiting => "list_attestations_by_dimension_citing",
        /// `FederationDirectory::list_attestations_referencing`.
        ListAttestationsReferencing => "list_attestations_referencing",
        /// `FederationDirectory::list_composers_referencing_any`.
        ListComposersReferencingAny => "list_composers_referencing_any",
        /// `FederationDirectory::list_targeted_by_dimension_prefix`.
        ListTargetedByDimensionPrefix => "list_targeted_by_dimension_prefix",
        /// `FederationDirectory::list_live_consent_grants_by`.
        ListLiveConsentGrantsBy => "list_live_consent_grants_by",
        /// `FederationDirectory::list_live_consent_grants_for`.
        ListLiveConsentGrantsFor => "list_live_consent_grants_for",
        /// `FederationDirectory::list_local_tier_attestations`.
        ListLocalTierAttestations => "list_local_tier_attestations",
        /// `FederationDirectory::list_widening_candidates`.
        ListWideningCandidates => "list_widening_candidates",
        /// `FederationDirectory::list_attestations_for_migration`.
        ListAttestationsForMigration => "list_attestations_for_migration",
        /// `FederationDirectory::attestations_binding_content`.
        AttestationsBindingContent => "attestations_binding_content",
        /// v61.4.0 (CIRISPersist#1260) —
        /// `FederationDirectory::attestations_binding_content_with_placements`.
        AttestationsBindingContentWithPlacements => "attestations_binding_content_with_placements",
        /// `FederationDirectory::get_attestation`.
        GetAttestation => "get_attestation",
        /// `FederationDirectory::list_attestations_since`.
        ListAttestationsSince => "list_attestations_since",
        /// `FederationDirectory::list_attestation_log`.
        ListAttestationLog => "list_attestation_log",
        /// v61.0.5 (CIRISPersist#1225) —
        /// `FederationDirectory::list_attestations_naming_by_dimension`.
        ListAttestationsNamingByDimension => "list_attestations_naming_by_dimension",
        /// v61.1.0 (CIRISPersist#1190) —
        /// `FederationDirectory::list_attestations_since_by_prefixes`.
        ListAttestationsSinceByPrefixes => "list_attestations_since_by_prefixes",
        /// v61.1.0 (CIRISPersist#1163) —
        /// `FederationDirectory::list_owner_bindings_since` (its candidate
        /// rows; the per-node fold's reads count under their own doors).
        ListOwnerBindingsSince => "list_owner_bindings_since",
        /// v56.0.0 (CIRISPersist#1001) — `AttestationReads::query_attestations`,
        /// the typed bounded read; recorded once, in its shared wrapper. It
        /// replaces the `list_attestations_{by,for}` doors and their six
        /// narrowed siblings, whose labels are retired with them.
        AttestationQuery => "attestation_query",
    }
}

label_set! {
    /// A fold entry point: the walk a host attributes door reads to.
    Fold {
        /// `consent_by_humans::resolve_scoped_stance_by_principals`.
        ResolveScopedStanceByPrincipals => "resolve_scoped_stance_by_principals",
        /// `FederationDirectory::resolve_scoped_stance` (default body).
        ResolveScopedStance => "resolve_scoped_stance",
        /// `trust_root::trusted_roots_of`.
        TrustedRootsOf => "trusted_roots_of",
        /// `trust_root::trust_root_valid`.
        TrustRootValid => "trust_root_valid",
        /// `trust_root::resolve_serve_tier_over_roster` (and `resolve_serve_tier`).
        ResolveServeTier => "resolve_serve_tier",
        /// `trust_root::owner_granted_scope`.
        OwnerGrantedScope => "owner_granted_scope",
        /// `replication_audience::owner_allow_list`.
        OwnerAllowList => "owner_allow_list",
        /// `replication_audience::is_public_group`.
        IsPublicGroup => "is_public_group",
        /// `replication_audience::OwnerAudience::read`.
        OwnerAudience => "owner_audience",
        /// The attestation admission gauntlet, entered through
        /// `put_attestation`, `put_attestation_authored` and the replicated
        /// apply path.
        AttestationAdmission => "attestation_admission",
    }
}

const _: () = assert!(Fold::COUNT <= 32, "the active-fold mask is a u32");

impl Fold {
    const fn bit(self) -> u32 {
        1 << (self as u32)
    }
}

/// A row a door returns: the attestation it carries.
pub trait ReadRow {
    /// The attestation row.
    fn attestation(&self) -> &crate::federation::Attestation;
}

impl ReadRow for crate::federation::Attestation {
    fn attestation(&self) -> &crate::federation::Attestation {
        self
    }
}

impl ReadRow for crate::federation::types::ServedAttestation {
    fn attestation(&self) -> &crate::federation::Attestation {
        &self.attestation
    }
}

struct Tally {
    reads: AtomicU64,
    rows: AtomicU64,
    bytes: AtomicU64,
}

impl Tally {
    const fn new() -> Self {
        Tally {
            reads: AtomicU64::new(0),
            rows: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        }
    }

    fn add(&self, rows: u64, bytes: u64) {
        self.reads.fetch_add(1, Relaxed);
        self.rows.fetch_add(rows, Relaxed);
        self.bytes.fetch_add(bytes, Relaxed);
    }

    fn load(&self) -> (u64, u64, u64) {
        (
            self.reads.load(Relaxed),
            self.rows.load(Relaxed),
            self.bytes.load(Relaxed),
        )
    }
}

/// One tally per interned caller label, plus [`CALLER_OTHER`]'s at
/// [`OTHER_SLOT`].
type CallerTallies = [Tally; CALLER_SLOTS];

pub(crate) struct Counters {
    doors: [[Tally; Door::COUNT]; StoreBackend::COUNT],
    fold_reads: [Tally; Fold::COUNT],
    fold_calls: [AtomicU64; Fold::COUNT],
    /// v61.1.0 (CIRISPersist#1235) — `(backend, door, caller slot)`.
    callers: [[CallerTallies; Door::COUNT]; StoreBackend::COUNT],
    /// The interned caller labels, slot `i` at index `i`; never longer than
    /// [`MAX_CALLER_LABELS`]. Locked only when a [`Caller`] is made and at
    /// [`snapshot`], never on the read path.
    caller_labels: std::sync::Mutex<Vec<String>>,
}

impl Counters {
    const fn new() -> Self {
        Counters {
            doors: [const { [const { Tally::new() }; Door::COUNT] }; StoreBackend::COUNT],
            fold_reads: [const { Tally::new() }; Fold::COUNT],
            fold_calls: [const { AtomicU64::new(0) }; Fold::COUNT],
            callers: [const { [const { [const { Tally::new() }; CALLER_SLOTS] }; Door::COUNT] };
                StoreBackend::COUNT],
            caller_labels: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn labels(&self) -> std::sync::MutexGuard<'_, Vec<String>> {
        self.caller_labels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The slot `label` (already validated) is counted under: its own when
    /// it is interned or there is room to intern it, else [`OTHER_SLOT`].
    fn intern(&self, label: &str) -> u8 {
        if label == CALLER_OTHER {
            return OTHER_SLOT;
        }
        let mut labels = self.labels();
        if let Some(i) = labels.iter().position(|l| l == label) {
            return i as u8;
        }
        if labels.len() < MAX_CALLER_LABELS {
            labels.push(label.to_owned());
            return (labels.len() - 1) as u8;
        }
        OTHER_SLOT
    }

    /// The label slot `slot` renders as.
    fn slot_label(labels: &[String], slot: usize) -> String {
        if slot == OTHER_SLOT as usize {
            return CALLER_OTHER.to_owned();
        }
        labels
            .get(slot)
            .cloned()
            .unwrap_or_else(|| CALLER_OTHER.to_owned())
    }

    fn snapshot(&self) -> TelemetrySnapshot {
        let labels = self.labels().clone();
        let mut reads = Vec::new();
        let mut callers = Vec::new();
        for backend in StoreBackend::ALL {
            for door in Door::ALL {
                // The caller tallies are read BEFORE the door's total, and a
                // read adds to the total first: a read racing this snapshot
                // can show as unattributed for one snapshot, but an
                // attributed share is never larger than the total it is
                // subtracted from (and the subtraction saturates).
                let per_caller = &self.callers[*backend as usize][*door as usize];
                let attributed: Vec<(usize, (u64, u64, u64))> = per_caller
                    .iter()
                    .enumerate()
                    .map(|(slot, t)| (slot, t.load()))
                    .filter(|(_, (n, _, _))| *n > 0)
                    .collect();
                let (n, rows, bytes) = self.doors[*backend as usize][*door as usize].load();
                if n > 0 {
                    reads.push(DoorReads {
                        backend: backend.label(),
                        door: door.label(),
                        reads: n,
                        rows,
                        bytes,
                    });
                }
                let (mut a_reads, mut a_rows, mut a_bytes) = (0u64, 0u64, 0u64);
                for (slot, (c_reads, c_rows, c_bytes)) in attributed {
                    a_reads += c_reads;
                    a_rows += c_rows;
                    a_bytes += c_bytes;
                    callers.push(CallerReads {
                        backend: backend.label(),
                        door: door.label(),
                        caller: Self::slot_label(&labels, slot),
                        reads: c_reads,
                        rows: c_rows,
                        bytes: c_bytes,
                    });
                }
                let unattributed = n.saturating_sub(a_reads);
                if unattributed > 0 {
                    callers.push(CallerReads {
                        backend: backend.label(),
                        door: door.label(),
                        caller: CALLER_UNATTRIBUTED.to_owned(),
                        reads: unattributed,
                        rows: rows.saturating_sub(a_rows),
                        bytes: bytes.saturating_sub(a_bytes),
                    });
                }
            }
        }
        let folds = Fold::ALL
            .iter()
            .map(|fold| {
                let (n, rows, bytes) = self.fold_reads[*fold as usize].load();
                FoldReads {
                    fold: fold.label(),
                    calls: self.fold_calls[*fold as usize].load(Relaxed),
                    reads: n,
                    rows,
                    bytes,
                }
            })
            .collect();
        TelemetrySnapshot {
            reads,
            folds,
            callers,
        }
    }
}

static GLOBAL: Counters = Counters::new();

#[cfg(test)]
thread_local! {
    static LOCAL: std::cell::Cell<Option<&'static Counters>> = const { std::cell::Cell::new(None) };
}

/// The counters this read feeds: the process-wide set, or under `cfg(test)`
/// the current thread's [`LocalCounters`] when one is installed (the
/// `metrics::with_local_recorder` pattern), so a witness sees only its own
/// reads while the harness runs other tests in parallel.
fn counters() -> &'static Counters {
    #[cfg(test)]
    if let Some(local) = LOCAL.with(std::cell::Cell::get) {
        return local;
    }
    &GLOBAL
}

tokio::task_local! {
    /// The folds the current task is inside, one bit per [`Fold`].
    static ACTIVE_FOLDS: u32;
}

// ── v61.1.0 (CIRISPersist#1235) — caller attribution ─────────────────────

/// The most distinct caller labels one counter set interns. Every label
/// past them is counted under [`CALLER_OTHER`].
pub const MAX_CALLER_LABELS: usize = 32;

/// The longest caller label, in bytes.
pub const MAX_CALLER_LABEL_LEN: usize = 48;

/// The bucket every caller label past [`MAX_CALLER_LABELS`] is counted under.
/// A host may also name it directly.
pub const CALLER_OTHER: &str = "other";

/// What the snapshot names the reads made under no caller scope. Reserved: a
/// host cannot set it as a label.
pub const CALLER_UNATTRIBUTED: &str = "unattributed";

/// The tally slots per `(backend, door)`: one per label, then `other`.
const CALLER_SLOTS: usize = MAX_CALLER_LABELS + 1;

/// [`CALLER_OTHER`]'s slot.
const OTHER_SLOT: u8 = MAX_CALLER_LABELS as u8;

const _: () = assert!(CALLER_SLOTS <= u8::MAX as usize, "a caller slot is a u8");

/// Why a caller label was refused. A malformed label is a refusal, never a
/// read counted as unattributed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerLabelError {
    /// The label is empty.
    Empty,
    /// The label is longer than [`MAX_CALLER_LABEL_LEN`] bytes.
    TooLong {
        /// Its length in bytes.
        len: usize,
    },
    /// The byte at `at` is outside the charset: the first byte is `a-z`, the
    /// rest are `a-z`, `0-9`, `_`, `.`, `:` or `-`.
    BadByte {
        /// The byte's offset.
        at: usize,
    },
    /// The label is [`CALLER_UNATTRIBUTED`], which the snapshot reserves.
    Reserved,
}

impl std::fmt::Display for CallerLabelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallerLabelError::Empty => write!(f, "caller label is empty"),
            CallerLabelError::TooLong { len } => write!(
                f,
                "caller label is {len} bytes, longer than {MAX_CALLER_LABEL_LEN}"
            ),
            CallerLabelError::BadByte { at } => {
                write!(f, "caller label byte {at} is outside [a-z][a-z0-9_.:-]*")
            }
            CallerLabelError::Reserved => {
                write!(f, "caller label {CALLER_UNATTRIBUTED:?} is reserved")
            }
        }
    }
}

impl std::error::Error for CallerLabelError {}

/// Check `label` against the caller-label grammar: 1 to
/// [`MAX_CALLER_LABEL_LEN`] bytes, `[a-z][a-z0-9_.:-]*`, not
/// [`CALLER_UNATTRIBUTED`].
///
/// # Errors
/// The [`CallerLabelError`] naming the first rule `label` breaks.
pub fn validate_caller_label(label: &str) -> Result<(), CallerLabelError> {
    let b = label.as_bytes();
    if b.is_empty() {
        return Err(CallerLabelError::Empty);
    }
    if b.len() > MAX_CALLER_LABEL_LEN {
        return Err(CallerLabelError::TooLong { len: b.len() });
    }
    for (at, &c) in b.iter().enumerate() {
        let ok = c.is_ascii_lowercase()
            || (at > 0 && (c.is_ascii_digit() || matches!(c, b'_' | b'.' | b':' | b'-')));
        if !ok {
            return Err(CallerLabelError::BadByte { at });
        }
    }
    if label == CALLER_UNATTRIBUTED {
        return Err(CallerLabelError::Reserved);
    }
    Ok(())
}

/// A validated, interned caller label: who a read is made for. Cheap to copy;
/// make one per label and reuse it (making one takes a short lock, reading
/// under one takes none).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Caller {
    slot: u8,
}

impl Caller {
    /// Validate and intern `label`. A label past the [`MAX_CALLER_LABELS`]
    /// cap is accepted and counted under [`CALLER_OTHER`].
    ///
    /// # Errors
    /// [`validate_caller_label`]'s refusal.
    pub fn new(label: &str) -> Result<Self, CallerLabelError> {
        validate_caller_label(label)?;
        Ok(Caller {
            slot: counters().intern(label),
        })
    }

    /// The label this caller is counted under: its own, or [`CALLER_OTHER`]
    /// when the cap bucketed it.
    #[must_use]
    pub fn label(self) -> String {
        Counters::slot_label(&counters().labels(), self.slot as usize)
    }
}

tokio::task_local! {
    /// The caller slot the current task's reads are credited to.
    static ACTIVE_CALLER: u8;
}

thread_local! {
    /// The caller slot this thread's reads are credited to when no task scope
    /// is in force ([`ThreadCallerScope`], [`set_thread_caller`]).
    static THREAD_CALLER: Cell<Option<u8>> = const { Cell::new(None) };
}

/// The caller slot in force here: the innermost task scope, else this
/// thread's scope. With neither set this is one failed task-local probe and
/// one `Cell` read.
#[inline]
fn active_caller() -> Option<u8> {
    match ACTIVE_CALLER.try_with(|s| *s) {
        Ok(slot) => Some(slot),
        Err(_) => THREAD_CALLER.with(Cell::get),
    }
}

/// The caller in force here (the innermost task scope, else this thread's
/// scope), so a host can carry it into a task it spawns:
/// `caller_scope(c, fut)`.
#[must_use]
pub fn current_caller() -> Option<Caller> {
    active_caller().map(|slot| Caller { slot })
}

/// Run `fut` with every door read it makes (on its task) credited to
/// `caller`. Nested scopes: the innermost wins for its extent. A task the
/// future spawns does not inherit the scope; carry it with
/// [`current_caller`].
pub fn caller_scope<F: Future>(caller: Caller, fut: F) -> impl Future<Output = F::Output> {
    ACTIVE_CALLER.scope(caller.slot, fut)
}

/// Run `fut` under the caller in force where this is CALLED (not where `fut`
/// is polled): the hop for a future persist builds on the caller's thread and
/// polls on its own worker (the directory capsule's `build_op`).
pub(crate) fn carry_caller<F: Future>(fut: F) -> impl Future<Output = F::Output> {
    let slot = active_caller();
    async move {
        match slot {
            Some(slot) => ACTIVE_CALLER.scope(slot, fut).await,
            None => fut.await,
        }
    }
}

/// Set this thread's caller scope to `caller` (`None` clears it) and return
/// the one it replaces. The set/clear form of [`ThreadCallerScope`], for a
/// boundary that cannot hold a guard (the PyO3 `set_caller_scope`).
///
/// A thread scope is for a thread that drives persist's futures itself
/// (`block_on`); setting one on an async runtime's worker would credit every
/// task that worker polls.
pub fn set_thread_caller(caller: Option<Caller>) -> Option<Caller> {
    THREAD_CALLER
        .with(|c| c.replace(caller.map(|c| c.slot)))
        .map(|slot| Caller { slot })
}

/// A thread caller scope: while it lives, door reads polled on this thread
/// with no task scope in force are credited to its caller; on drop the
/// previous thread scope is restored, so guards nest innermost-wins. Not
/// `Send`, so it cannot be held across an `.await` in a spawned task.
#[must_use = "the scope ends when the guard is dropped"]
pub struct ThreadCallerScope {
    previous: Option<Caller>,
    _not_send: PhantomData<*const ()>,
}

impl ThreadCallerScope {
    /// Enter `caller`'s scope on this thread (`None` clears the scope for
    /// the guard's life).
    pub fn enter(caller: Option<Caller>) -> Self {
        ThreadCallerScope {
            previous: set_thread_caller(caller),
            _not_send: PhantomData,
        }
    }
}

impl Drop for ThreadCallerScope {
    fn drop(&mut self) {
        set_thread_caller(self.previous);
    }
}

/// Record one door read: `rows` returned, `bytes` of envelope decoded (see
/// the module doc for each backend's definition). The single helper every
/// backend's door calls; `key` reaches only the test probe.
pub fn record_read<R: ReadRow>(
    backend: StoreBackend,
    door: Door,
    key: &str,
    rows: &[R],
    bytes: u64,
) {
    count_read(backend, door, rows.len() as u64, bytes);
    #[cfg(test)]
    crate::federation::read_probe::record(door.label(), key, rows);
    #[cfg(not(test))]
    let _ = key;
}

/// The counters half of a door read: the `(backend, door)` totals and every
/// fold active on this task.
///
/// v60.0.0 (CIRISPersist#1112) — the walk over the mask is bounded by its
/// popcount, not by `mask != 0`. Each of the three operator mutants on the
/// clear-lowest-bit step (`&=` to `|=`, `-` to `+`, `-` to `/`) made the
/// loop infinite: every witness that read inside a fold hung until nextest's
/// 60 s leash, seventeen of them per mutant, and the run outlived the tool's
/// 300 s timeout, which credits no witness. A witness cannot end an
/// infinite loop; the bound makes the same mutants return at once with the
/// wrong fold credited, which I692 and I1164 count.
fn count_read(backend: StoreBackend, door: Door, n: u64, bytes: u64) {
    let c = counters();
    c.doors[backend as usize][door as usize].add(n, bytes);
    // v61.1.0 (CIRISPersist#1235) — after the door's total (the snapshot
    // reads them in the other order). No scope set: no atomic here.
    if let Some(slot) = active_caller() {
        c.callers[backend as usize][door as usize][slot as usize].add(n, bytes);
    }
    if let Ok(mut mask) = ACTIVE_FOLDS.try_with(|m| *m) {
        for _ in 0..mask.count_ones() {
            let i = mask.trailing_zeros() as usize;
            c.fold_reads[i].add(n, bytes);
            mask &= mask - 1;
        }
    }
}

/// v56.0.0 (CIRISPersist#1001) — record one typed bounded read
/// ([`Door::AttestationQuery`]). Called from exactly one place,
/// [`crate::federation::attestation_query::AttestationReads::query_attestations`],
/// whatever backend ran the statement; under `cfg(test)` the probe also
/// records the query's shape (its pinned keys, narrowing and limit).
///
/// `fetched` is every row the backend decoded (at most `limit + 1`: the
/// statement fetches one row past the page to learn whether another page
/// exists); `returned` is how many of them the page serves. `bytes` covers
/// all of `fetched` (the decode cost, this module's "bytes"), and the read
/// counts `returned` rows.
pub(crate) fn record_query_read(
    backend: StoreBackend,
    q: &crate::federation::attestation_query::AttestationQuery,
    fetched: &[crate::federation::Attestation],
    returned: usize,
    bytes: u64,
) {
    count_read(backend, Door::AttestationQuery, returned as u64, bytes);
    #[cfg(test)]
    crate::federation::read_probe::record_query(q, fetched, returned);
    #[cfg(not(test))]
    let _ = (q, fetched);
}

/// Run `fut` as one entry into `fold`: count the call, and credit every door
/// read `fut` makes (on this task) to `fold` and to every fold already
/// active on it.
///
/// v54.0.0 (CIRISPersist#1017) — `fut` is BOXED. Each fold wrapped its whole
/// inner future inline, so nested folds (serve tier → trust_root_valid →
/// owner_granted_scope) stacked into a 29 KB public future that every caller
/// had to box for `clippy::large_futures`. One allocation per fold entry, at
/// the door, instead of one per caller; I578 pins the doors under 16 KiB.
///
/// Boxed EAGERLY, when the wrapper is built: an un-polled `async fn` keeps
/// its arguments inline, so a box taken inside the body would still leave
/// the whole inner future in the caller's state until the first poll.
pub fn fold<F: Future>(fold: Fold, fut: F) -> impl Future<Output = F::Output> {
    let fut = Box::pin(fut);
    async move {
        counters().fold_calls[fold as usize].fetch_add(1, Relaxed);
        let mask = ACTIVE_FOLDS.try_with(|m| *m).unwrap_or(0) | fold.bit();
        ACTIVE_FOLDS.scope(mask, fut).await
    }
}

thread_local! {
    static DECODED_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Note `len` envelope bytes decoded on this thread (sqlite's row mapper, on
/// the reader thread).
#[cfg_attr(not(feature = "sqlite"), allow(dead_code))]
pub(crate) fn note_decoded_bytes(len: usize) {
    DECODED_BYTES.with(|b| b.set(b.get().wrapping_add(len as u64)));
}

/// Take (and zero) this thread's decoded-envelope byte count.
#[cfg_attr(not(feature = "sqlite"), allow(dead_code))]
pub(crate) fn take_decoded_bytes() -> u64 {
    DECODED_BYTES.with(|b| b.replace(0))
}

/// A point-in-time read of every counter.
#[must_use]
pub fn snapshot() -> TelemetrySnapshot {
    counters().snapshot()
}

/// v53.2.0 (CIRISPersist#1027) — write every counter of [`snapshot`] to the
/// `metrics` facade, under its catalogued name and labels, as the counter's
/// current value (`Counter::absolute`). A host calls it when it scrapes. With
/// no recorder installed every call is a no-op, and the read path never
/// touches the facade: these counters stay the one source, and a recorder sees
/// exactly what [`snapshot`] reads. Each counter is described with its
/// catalogued unit (`By` as bytes, `{row}`/`{read}`/`{call}` as a count): the
/// two-argument `describe_counter!` forwards no unit, and the exported metadata
/// then contradicted the catalogue (Codex round 2 on PR #1039).
pub fn emit_metrics() {
    for entry in catalog::TELEMETRY_CATALOG {
        match entry.metrics_unit() {
            Some(unit) => metrics::describe_counter!(entry.name, unit, entry.description),
            None => metrics::describe_counter!(entry.name, entry.description),
        }
    }
    for sample in snapshot().samples() {
        let labels: Vec<metrics::Label> = sample
            .labels
            .iter()
            .map(|(k, v)| metrics::Label::from_static_parts(k, v))
            .collect();
        metrics::counter!(sample.name, labels).absolute(sample.value);
    }
}

/// Every read-telemetry counter, read once (relaxed; monotone per field, not
/// one atomic instant). Plain data, serializable, the same before and after
/// P1's facade emission.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct TelemetrySnapshot {
    /// One entry per `(backend, door)` that has served at least one read.
    pub reads: Vec<DoorReads>,
    /// One entry per [`Fold`], every fold listed.
    pub folds: Vec<FoldReads>,
    /// v61.1.0 (CIRISPersist#1235) — per `(backend, door)` that served a
    /// read, one entry per caller label its reads were credited to, then one
    /// [`CALLER_UNATTRIBUTED`] entry for the reads made under no scope (each
    /// listed only when it counts a read). A door's entries sum to its
    /// `reads` entry. Additive: `reads` and `folds` keep their shape.
    pub callers: Vec<CallerReads>,
}

/// v61.1.0 (CIRISPersist#1235) — the counters of one `(backend, door,
/// caller)`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CallerReads {
    /// [`StoreBackend::label`].
    pub backend: &'static str,
    /// [`Door::label`].
    pub door: &'static str,
    /// The caller label, [`CALLER_OTHER`], or [`CALLER_UNATTRIBUTED`].
    pub caller: String,
    /// Reads served.
    pub reads: u64,
    /// Rows returned.
    pub rows: u64,
    /// Envelope bytes decoded.
    pub bytes: u64,
}

/// The counters of one `(backend, door)`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DoorReads {
    /// [`StoreBackend::label`].
    pub backend: &'static str,
    /// [`Door::label`].
    pub door: &'static str,
    /// Reads served.
    pub reads: u64,
    /// Rows returned.
    pub rows: u64,
    /// Envelope bytes decoded.
    pub bytes: u64,
}

/// The counters of one fold.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FoldReads {
    /// [`Fold::label`].
    pub fold: &'static str,
    /// Entries into the fold.
    pub calls: u64,
    /// Door reads made inside it (inclusive of nested folds).
    pub reads: u64,
    /// Rows those reads returned.
    pub rows: u64,
    /// Envelope bytes those reads decoded.
    pub bytes: u64,
}

/// One metric sample of a snapshot: a catalogued name, its labels, a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    /// The metric name ([`catalog::TELEMETRY_CATALOG`]).
    pub name: &'static str,
    /// `(label key, label value)` pairs.
    pub labels: Vec<(&'static str, &'static str)>,
    /// The counter's value.
    pub value: u64,
}

impl TelemetrySnapshot {
    /// The counters of `(backend, door)`; zeros when it served no read.
    #[must_use]
    pub fn door(&self, backend: StoreBackend, door: Door) -> (u64, u64, u64) {
        self.reads
            .iter()
            .find(|r| r.backend == backend.label() && r.door == door.label())
            .map_or((0, 0, 0), |r| (r.reads, r.rows, r.bytes))
    }

    /// v61.1.0 (CIRISPersist#1235) — the counters of `(backend, door,
    /// caller)` as `(reads, rows, bytes)`; zeros when none. `caller` is a
    /// label, [`CALLER_OTHER`] or [`CALLER_UNATTRIBUTED`].
    #[must_use]
    pub fn caller(&self, backend: StoreBackend, door: Door, caller: &str) -> (u64, u64, u64) {
        self.callers
            .iter()
            .find(|r| r.backend == backend.label() && r.door == door.label() && r.caller == caller)
            .map_or((0, 0, 0), |r| (r.reads, r.rows, r.bytes))
    }

    /// The counters of `fold` as `(calls, reads, rows, bytes)`.
    #[must_use]
    pub fn fold(&self, fold: Fold) -> (u64, u64, u64, u64) {
        self.folds
            .iter()
            .find(|f| f.fold == fold.label())
            .map_or((0, 0, 0, 0), |f| (f.calls, f.reads, f.rows, f.bytes))
    }

    /// The snapshot as metric samples, named per the catalogue. The
    /// per-caller rows are not samples (see the module doc).
    #[must_use]
    pub fn samples(&self) -> Vec<Sample> {
        let mut out = Vec::with_capacity(self.reads.len() * 3 + self.folds.len() * 4);
        for r in &self.reads {
            let labels = vec![
                (catalog::LABEL_BACKEND, r.backend),
                (catalog::LABEL_DOOR, r.door),
            ];
            for (name, value) in [
                (catalog::READ_CALLS, r.reads),
                (catalog::READ_ROWS, r.rows),
                (catalog::READ_BYTES, r.bytes),
            ] {
                out.push(Sample {
                    name,
                    labels: labels.clone(),
                    value,
                });
            }
        }
        for f in &self.folds {
            for (name, value) in [
                (catalog::FOLD_CALLS, f.calls),
                (catalog::FOLD_READS, f.reads),
                (catalog::FOLD_ROWS, f.rows),
                (catalog::FOLD_BYTES, f.bytes),
            ] {
                out.push(Sample {
                    name,
                    labels: vec![(catalog::LABEL_FOLD, f.fold)],
                    value,
                });
            }
        }
        out
    }
}

/// Under `cfg(test)`: a private counter set this thread's reads and folds
/// feed while the guard lives (restored on drop). A `#[tokio::test]` runs on
/// one thread, and every backend records on the task's thread after its
/// await, so the guard sees exactly the test's own reads.
#[cfg(test)]
pub(crate) struct LocalCounters {
    counters: &'static Counters,
    previous: Option<&'static Counters>,
}

#[cfg(test)]
impl LocalCounters {
    /// Install a fresh, zeroed set on this thread.
    pub(crate) fn install() -> Self {
        let counters: &'static Counters = Box::leak(Box::new(Counters::new()));
        let previous = LOCAL.with(|l| l.replace(Some(counters)));
        Self { counters, previous }
    }

    /// Read the private set.
    pub(crate) fn snapshot(&self) -> TelemetrySnapshot {
        self.counters.snapshot()
    }
}

#[cfg(test)]
impl Drop for LocalCounters {
    fn drop(&mut self) {
        LOCAL.with(|l| l.set(self.previous));
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod caller_1235_tests;
