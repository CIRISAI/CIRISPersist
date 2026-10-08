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
//! - memory: `0`. The memory backend holds parsed envelopes, no serialized
//!   form, and measuring one would mean re-serializing.
//!
//! A door that filters after decode (the live consent-grant reads drop rows
//! whose envelope names another dimension) counts the bytes it decoded, which
//! is the cost; `rows` is always what it returned.
//!
//! The counters are process-wide: two Engines in one process share them, as a
//! `metrics` recorder would. [`snapshot`] (and `Engine::telemetry_snapshot`)
//! reads them; [`catalog::TELEMETRY_CATALOG`] names every metric they back.
//! [`emit_metrics`] (v53.2.0, CIRISPersist#1027, CIRISServer#746 §4 P1)
//! writes these same counters through the `metrics` facade at the host's
//! scrape, so the read path stays free of the facade. The catalogue's source
//! is the OpenTelemetry Weaver registry in `telemetry/registry/`.

use std::future::Future;
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
    StoreBackend {
        /// The in-process memory backend.
        Memory => "memory",
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
        /// `FederationDirectory::list_attestations_by`.
        ListAttestationsBy => "list_attestations_by",
        /// `FederationDirectory::list_attestations_by_dimension_citing`.
        ListAttestationsByDimensionCiting => "list_attestations_by_dimension_citing",
        /// `FederationDirectory::list_attestations_by_dimension_prefix`.
        ListAttestationsByDimensionPrefix => "list_attestations_by_dimension_prefix",
        /// `FederationDirectory::list_attestations_by_type`.
        ListAttestationsByType => "list_attestations_by_type",
        /// `FederationDirectory::list_attestations_by_types`.
        ListAttestationsByTypes => "list_attestations_by_types",
        /// `FederationDirectory::list_attestations_for`.
        ListAttestationsFor => "list_attestations_for",
        /// `FederationDirectory::list_attestations_for_dimension_prefix`.
        ListAttestationsForDimensionPrefix => "list_attestations_for_dimension_prefix",
        /// `FederationDirectory::list_attestations_for_type`.
        ListAttestationsForType => "list_attestations_for_type",
        /// `FederationDirectory::list_attestations_for_types`.
        ListAttestationsForTypes => "list_attestations_for_types",
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
        /// `FederationDirectory::get_attestation`.
        GetAttestation => "get_attestation",
        /// `FederationDirectory::list_attestations_since`.
        ListAttestationsSince => "list_attestations_since",
        /// `FederationDirectory::list_attestation_log`.
        ListAttestationLog => "list_attestation_log",
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

pub(crate) struct Counters {
    doors: [[Tally; Door::COUNT]; StoreBackend::COUNT],
    fold_reads: [Tally; Fold::COUNT],
    fold_calls: [AtomicU64; Fold::COUNT],
}

impl Counters {
    const fn new() -> Self {
        Counters {
            doors: [const { [const { Tally::new() }; Door::COUNT] }; StoreBackend::COUNT],
            fold_reads: [const { Tally::new() }; Fold::COUNT],
            fold_calls: [const { AtomicU64::new(0) }; Fold::COUNT],
        }
    }

    fn snapshot(&self) -> TelemetrySnapshot {
        let mut reads = Vec::new();
        for backend in StoreBackend::ALL {
            for door in Door::ALL {
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
        TelemetrySnapshot { reads, folds }
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
    let n = rows.len() as u64;
    let c = counters();
    c.doors[backend as usize][door as usize].add(n, bytes);
    if let Ok(mut mask) = ACTIVE_FOLDS.try_with(|m| *m) {
        while mask != 0 {
            let i = mask.trailing_zeros() as usize;
            c.fold_reads[i].add(n, bytes);
            mask &= mask - 1;
        }
    }
    #[cfg(test)]
    crate::federation::read_probe::record(door.label(), key, rows);
    #[cfg(not(test))]
    let _ = key;
}

/// Run `fut` as one entry into `fold`: count the call, and credit every door
/// read `fut` makes (on this task) to `fold` and to every fold already
/// active on it.
pub async fn fold<F: Future>(fold: Fold, fut: F) -> F::Output {
    counters().fold_calls[fold as usize].fetch_add(1, Relaxed);
    let mask = ACTIVE_FOLDS.try_with(|m| *m).unwrap_or(0) | fold.bit();
    ACTIVE_FOLDS.scope(mask, fut).await
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
/// exactly what [`snapshot`] reads.
pub fn emit_metrics() {
    for entry in catalog::TELEMETRY_CATALOG {
        metrics::describe_counter!(entry.name, entry.description);
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

    /// The counters of `fold` as `(calls, reads, rows, bytes)`.
    #[must_use]
    pub fn fold(&self, fold: Fold) -> (u64, u64, u64, u64) {
        self.folds
            .iter()
            .find(|f| f.fold == fold.label())
            .map_or((0, 0, 0, 0), |f| (f.calls, f.reads, f.rows, f.bytes))
    }

    /// The snapshot as metric samples, named per the catalogue.
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
