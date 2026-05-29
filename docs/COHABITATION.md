# Cohabitation Doctrine — persist as the runtime keyring authority

**Status:** authoritative architecture for v0.1.14+. Companion to
CIRISVerify's
[`HOW_IT_WORKS.md` § "Cohabitation Contract"](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/HOW_IT_WORKS.md#cohabitation-contract)
and `THREAT_MODEL.md` § AV-14.

---

## TL;DR

**Persist is a Python wheel — not a daemon.** Every consumer
(lens, agent, bridge, registry-client) imports it as a library
and constructs `Engine(...)` in their own process. There is no
`persist.service`. Three rules for hosts where multiple consumers
import persist:

1. **First `Engine::__init__` on the host bootstraps the keyring.**
   Subsequent calls (other workers, other consumers) see the existing
   key. POSIX `flock` serializes cold-start across processes.
2. **One keyring identity per host/container.** Different consumers
   on the same host using the same `signing_key_id` resolve to the
   same identity by construction (PoB §3.2 one-key-three-roles).
3. **Persist's library code is the canonical bootstrap path on a
   host.** Other primitives that go through persist (lens, agent's
   PyO3 path, bridge) inherit the cohabitation guarantee for free.
   Direct ciris-keyring callers (a hypothetical Rust binary that
   skips persist) need verify's planned v1.9 keyring-layer flock.

---

## What "persist as authority" actually means

Persist isn't a *process* that other primitives wait on. It's a
*library* whose `Engine` constructor performs the canonical
keyring bootstrap. The architectural claim is:

> Persist is the lowest stateful CIRIS substrate above verify. Its
> `Engine::__init__` is the canonical entry point for keyring
> resolution on a host. Any consumer importing persist gets the
> serialized-bootstrap guarantee for free; the flock makes
> cold-start safe regardless of how many consumers race the
> import.

There's no daemon. There's no `Requires=After=persist.service`.
There's no init container that runs persist-the-binary before the
workload. The doctrine is purely about **library code paths**:

```
┌────────────────────────────────────────────────────────────┐
│                        Host / Container                    │
│                                                            │
│  ┌─────────────────────────┐  ┌──────────────────────────┐ │
│  │ uvicorn worker 1        │  │ uvicorn worker 2         │ │
│  │   from ciris_persist    │  │   from ciris_persist     │ │
│  │       import Engine     │  │       import Engine      │ │
│  │   Engine(...) ──┐       │  │   Engine(...) ──┐        │ │
│  │                 │       │  │                 │        │ │
│  └─────────────────┼───────┘  └─────────────────┼────────┘ │
│                    ▼                            ▼          │
│       ┌────────────────────────────────────────────┐       │
│       │ flock(${CIRIS_DATA_DIR}/.persist-          │       │
│       │       bootstrap.lock)                      │       │
│       │   → get_platform_signer(alias) [keyring]   │       │
│       └────────────────────────────────────────────┘       │
│                    │                                       │
│                    ▼                                       │
│       ┌────────────────────────────────────────────┐       │
│       │ OS keyring backend (TPM / Secure Enclave / │       │
│       │   StrongBox / DPAPI / SoftwareSigner file) │       │
│       └────────────────────────────────────────────┘       │
└────────────────────────────────────────────────────────────┘
```

Worker 1 acquires the flock, hits `get_platform_signer(alias)` —
which generates the key on cold-start or returns the existing one.
Worker 2 blocks on the flock briefly; by the time it gets through,
worker 1 has released it and the key already exists in the keyring
backend. Worker 2's `get_platform_signer` returns the existing key
without generating.

Both workers proceed to operate as read-only consumers of the same
identity. There is no separate persist process.

---

## Why "lowest stateful library above verify" lands persist as the authority

PoB §3.2 names a single Ed25519 key as identity-and-address-and-
signer. Some library on each host has to be the canonical entry
point for resolving that key, because:

- **CIRISVerify** is pure crypto + keyring backend. It's a library
  loaded by something else; it has no inherent "first call" timing
  on a host. Multiple consumers loading verify directly would each
  call `get_platform_signer()` independently — exactly the AV-14
  race verify v1.9's keyring-side flock will close generally.
- **CIRISAgent / CIRISLens / CIRISBridge** are higher-level
  primitives that *consume* persistence + crypto. They don't have
  a natural "owner of the keyring" claim — putting the bootstrap
  authority in any one of them creates asymmetry across primitives.
- **CIRISPersist** is the lowest stateful library above verify.
  Every higher primitive that needs durable state imports persist.
  Its `Engine::__init__` is naturally the first point on a host
  where state initialization happens; pinning the keyring
  bootstrap there means *every consumer that uses persist*
  inherits the guarantee for free.

This is doctrinal, not operational. Persist is the authority
**because it's the canonical first-stateful-library**, not because
it runs as a daemon. Future primitives (CIRISReticulum, sovereign-
mode mesh-relay) that also touch state can either go through
persist's Engine (and inherit), or implement their own
flock-on-the-same-path convention until verify v1.9 generalizes.

---

## Multi-worker semantics

Each worker spawns a Python process; each imports persist; each
calls `Engine::__init__`. Pre-v0.1.14 these would race on
`key_exists() → generate_key()` per CIRISVerify's AV-14.

**v0.1.14 fix**: filesystem `flock` around `Engine::__init__`'s
`get_platform_signer()` call.

```
worker 1:  flock acquired → get_platform_signer (bootstrap if cold) → release
worker 2:  flock blocks  → ...waits ~50ms... → release seen → get_platform_signer (sees existing key) → release
worker 3:  flock blocks  → ...waits ~50ms... → release seen → get_platform_signer (sees existing key) → release
worker 4:  flock blocks  → ...waits ~50ms... → release seen → get_platform_signer (sees existing key) → release
```

POSIX `flock` auto-releases on FD close (including process panic).
A worker crash mid-bootstrap doesn't strand the lock; the next
worker acquires immediately.

**Lock path**:

```
${CIRIS_DATA_DIR}/.persist-bootstrap.lock     (preferred — co-located with seed)
/tmp/ciris-persist-bootstrap.lock              (fallback when CIRIS_DATA_DIR unset)
```

The `/tmp` fallback is acceptable because the lock is ephemeral
by design.

---

## Multi-primitive on one host

Common case: one container or VM running both an agent and a
lens, or a bridge + lens, or any combination. **All of them
import persist** (because all of them need durable state). Each
constructs `Engine(...)` — same alias, same `CIRIS_DATA_DIR`,
same flock path → same identity by construction.

**docker-compose example** (lens + bridge sharing one identity):

```yaml
services:
  lens:
    image: ghcr.io/cirisai/cirislens:latest    # imports ciris-persist
    volumes:
      - ciris-keyring:/var/lib/ciris/keyring
    environment:
      - CIRIS_DATA_DIR=/var/lib/ciris/keyring
      - CIRIS_PERSIST_SIGNING_KEY_ID=lens-bridge-v1

  bridge:
    image: ghcr.io/cirisai/cirisbridge:latest  # imports ciris-persist
    volumes:
      - ciris-keyring:/var/lib/ciris/keyring   # SAME volume
    environment:
      - CIRIS_DATA_DIR=/var/lib/ciris/keyring
      - CIRIS_PERSIST_SIGNING_KEY_ID=lens-bridge-v1   # SAME alias

volumes:
  ciris-keyring:
    driver: local
```

The shared volume + shared alias is the whole story. Whichever
container's `Engine::__init__` runs first does the bootstrap; the
other sees the existing key. No `depends_on`, no service ordering,
no init container — the flock handles ordering implicitly.

**Per-replica scaling** (k8s `replicas: N`): each replica is a
separate pod, each imports persist, each calls `Engine::__init__`.
The shared persistent volume means all replicas see the same
keyring backend; the flock serializes any replica that hits the
cold-start path.

---

## In-process cohabitation — one process, multiple consumers (v1.6.8)

Everything above addresses **multi-process** cohabitation on a host
(uvicorn workers, separate lens/bridge containers) — the keyring
flock serializes cold-start identity creation across processes.

CIRIS 3.0 introduces a different shape: **one process** (the
CIRISAgent runtime) hosting the agent **plus** CIRISNodeCore **plus**
CIRISLensCore as always-on in-process adapters, all consuming
persist. Pre-v1.6.8 this deadlocked — `Engine(...)` built a fresh
multi-thread tokio runtime on every construction, so two consumers
in one process produced two runtimes contending on the shared DB
(CIRISPersist#75: a 39-minute hang in the CIRISAgent 2.9.0 auth
suite).

### The v1.6.8 contract

**`Engine` is a process-singleton.** The tokio runtime + connection
pool are built exactly once per process. The lifecycle rules:

1. **One owner constructs.** Whoever boots the process (the
   CIRISAgent runtime) calls `Engine(dsn, signing_key_id, …)` first.
   That call builds the runtime + pool.

2. **Adapters attach, never rebuild.** NodeCore / LensCore (and any
   other in-process consumer) call `Engine(...)` with the **same
   config**. They get a cheap handle to the already-built engine —
   no second runtime. A different DSN / signing-key-id raises
   `EngineConfigMismatch` (CIRISPersist#76): a process hosts exactly
   one persist engine, and a silent rebind to a different backend
   would corrupt data, not just hang.

3. **One owner closes.** At process shutdown / test teardown the
   owner calls `engine.close()` (CIRISPersist#77). Adapters do
   **not** call `close()` — they attached, they don't own the
   lifecycle. After `close()` every method raises `EngineClosed`
   instead of running against a torn-down runtime; a fresh
   `Engine(...)` afterward rebuilds.

4. **Construct after forking.** A tokio runtime does **not** survive
   `fork()` — the child inherits worker threads that don't exist and
   mutexes that may be held. Construct `Engine` **after** all
   forking is done (after uvicorn/gunicorn spawn their workers), or
   set the process-wide `multiprocessing` start method to `"spawn"`.
   Every `Engine` method verifies the calling pid against the
   construction pid; a mismatch raises `EngineUsedAcrossFork`
   (CIRISPersist#78) rather than deadlocking silently.

`EngineConfigMismatch`, `EngineClosed`, and `EngineUsedAcrossFork`
all derive from `PersistError` — `except PersistError:` catches the
umbrella, or branch on the specific subclass.

### Relationship to the multi-process flock

The two mechanisms are orthogonal and compose:

- **Multi-process** (uvicorn workers, separate containers) — the
  keyring flock serializes cold-start identity creation. Each
  process still has its own singleton engine.
- **In-process** (3.0 agent + NodeCore + LensCore) — the
  process-singleton ensures the *one* process has *one* runtime,
  shared by all in-process consumers.

A 3.0 deployment uses both: N worker processes, each flock-serialized
for keyring convergence, and within each worker a single shared
engine for the co-resident adapters.

The richer in-process model — an explicit consumer registry, a
lifecycle refcount so the engine tears down only when the *last*
consumer detaches, and an injected-engine handle so adapters never
even call the `Engine(...)` constructor — is tracked as the
CIRISPersist#79–#84 enabler set for 3.0. v1.6.8 ships the
deadlock-ending floor those build on.

## Consumer → substrate ownership (v1.7.4, CIRISPersist#82)

Under the process-singleton, the *one* engine owns *all* substrate
schemas: whichever consumer constructs `Engine(...)` first runs the
full refinery migration set (V001–V039) for every substrate, and
every co-resident consumer then shares that schema. There is no
per-consumer schema partition and no per-call write enforcement —
the singleton has no caller identity to enforce against.

What persist *does* provide is a **cooperative ownership
declaration**. A consumer calls `register_consumer(name,
substrates=[...])` to declare which substrate families it owns;
`substrate_owner(substrate)` lets any consumer ask who owns a given
family before writing to it. This is advisory: it catches
mis-wiring and double-ownership in diagnostics, not a write
firewall.

The declared substrate names are validated against persist's five
substrate families (`register_consumer` raises `ValueError` on a
typo). The ownership contract — which consumer-class *should*
declare which family — is:

| Substrate family | Postgres schema | Owning consumer | Absorbs |
|---|---|---|---|
| `cirisgraph` | `cirisgraph` | CIRISAgent (3.0) | MemoryService, ConfigService |
| `cirislens` | `cirislens` | CIRISLensCore | observability ingest, tasks/thoughts/correlations/tickets/etc. |
| `cirislens_secrets` | `cirislens_secrets` | CIRISLensCore | SecretsService |
| `cirislens_derived` | `cirislens_derived` | CIRISLensCore | telemetry rollups, derived audit views |
| `cirisnode` | `cirisnode` | CIRISNodeCore | federation-consensus substrate |

Audit, incident, telemetry, sequence, and occurrence substrate
tables live within `cirislens` / `cirislens_derived` and are owned
transitively by the LensCore declaration. A consumer that touches
no substrate of its own (a pure reader) may register with an empty
`substrates=[]` purely for the lifecycle refcount.

Hard per-call write-rejection — refusing a write to a substrate the
*calling* consumer didn't declare — is a deliberate **non-goal** of
the 1.7.x line. It requires consumer-scoped engine handles (each
adapter holding a handle that carries its own identity), which is
the injected-engine-handle item still tracked in the #79–#84 set.
Until that lands, ownership is a cooperative contract enforced by
this table and by code review, not by the engine.

## Cross-cdylib cohabitation — separately-built wheels (v2.7+ capsule family)

The in-process model above assumes every co-resident consumer
**statically links the same persist source** through its Cargo
`[dependencies]`. That holds for the agent's own internal modules,
but a sibling Python wheel (e.g. CIRISEdge's `ciris_edge.abi3.so`)
also linking `ciris-persist` produces **two distinct PyO3
extension modules** in the same Python process — and PyO3 registers
`#[pyclass]` types per-extension-module, not per-process. The
`PyEngine` from `ciris_persist.abi3.so` and the `PyEngine` from
`ciris_edge.abi3.so` are the same Rust struct (same source, same
git tag) but distinct `PyTypeInfo`'s; `isinstance(engine, PyEngine)`
fails across modules. CIRISEdge#22 caught this in production
cohabitation init: `'Engine' object is not an instance of 'Engine'`.

Persist 2.7+ ships a family of **`PyCapsule` accessors** on
`PyEngine` that sidestep the per-module identity check entirely.
A capsule is an opaque pointer with a name tag; any module can
extract the wrapped value via `unsafe { cap.pointer_checked(name)
?.cast().as_ref() }`. No `PyTypeInfo` lookup happens, so the
cross-module identity problem evaporates.

| Capsule (on `PyEngine`) | Wraps | Issue | Released |
|---|---|---|---|
| `federation_directory_capsule` | `Arc<dyn FederationDirectory>` | #109 | 2.7.0 |
| `outbound_queue_capsule` | `BackendDispatch` (OutboundQueue is RPITIT) | #109 | 2.7.0 |
| `keyring_signer_capsule` | `KeyringSignerHandle` (reuses host's signer per rule 1 above) | #109 | 2.7.0 |
| `runtime_handle_capsule` | `tokio::runtime::Handle` (statics-duplication counterpart) | #111 | 2.8.0 |
| `blob_storage_capsule` | `BackendDispatch` (BlobStorage is RPITIT) | #115 | 2.11.0 |

Consumer pattern from a sibling wheel (e.g. CIRISEdge):

```rust
let cap: Bound<PyCapsule> = engine
    .call_method0("federation_directory_capsule")?
    .downcast_into()?;
let arc: &Arc<dyn FederationDirectory> = unsafe {
    cap.pointer_checked(Some(c"ciris_persist::federation_directory"))?
       .cast()
       .as_ref()
};
// Now call FederationDirectory trait methods directly in Rust.
```

`runtime_handle_capsule` (#111, 2.8.0) is the statics-duplication
counterpart: when persist is linked into both wheels, each `.so`
gets its own copy of `static ENGINE_SINGLETON`. The consumer
wheel's copy is never populated by the agent's
`ciris_persist.Engine(...)` bootstrap, so
`ciris_persist::current_runtime_handle()` called from the consumer
side returns `None`. The capsule wraps a clone of
`self.runtime.handle()` — sourced from `self`, not from the
static — sidestepping the static entirely.

### When Python disappears — Phase 3 endpoint

The cohabitation accessor family is the bridge for the
**Python-orchestrated phase**: every co-resident consumer reaches
persist via Python attribute access + capsule extraction. The
trajectory endpoint is **Rust-native** — `Engine::federation_directory()`
(#106, 2.6.0) returns `Arc<dyn FederationDirectory>` directly to a
Rust caller via `current_rust_engine()`, no PyO3 surface in the
loop. Sibling cdylibs that compile `ciris-persist` as a Cargo
dependency call the Rust-trait surface directly; the capsule layer
collapses to a one-line marshalling shim, deletable when the host
process goes Rust-native.

The two paths coexist forever: capsules for Python-orchestrated
cohabitation, the Rust-trait accessors for the Rust-native
endpoint. Both backed by the same singleton `EngineCell` — there
is only ever one engine, one pool, one runtime, one keyring per
process.

### Higher-level Engine facades shipped 2.6.0+

The capsule family delivers raw substrate handles; persist also
ships **higher-level Engine facades** that compose the substrate
into common cohabitation operations:

- `Engine::receive_and_persist` (#89, 2.x baseline) — ingest path.
- `Engine::storage_summary` / `delete_traces_older_than` /
  `archive_audit_range` (#107, 2.6.0) — retention primitives.
- `Engine::node_core_service()` / `audit_service()` (#90, #93) —
  per-substrate Rust accessors.
- `Engine::sign_hybrid(message) -> Result<HybridSignature, SignError>`
  (#112, 2.12.0) — hybrid Ed25519 + ML-DSA-65 signing facade. Reaches
  the underlying `LocalSigner::sign_hybrid` via the propagated
  `local_signer` field; pre-2.12 `current_rust_engine()` lost the
  `LocalSigner` at the cohabitation boundary. 2.12 added
  `Engine::from_shared_with_local` so the singleton's LocalSigner
  propagates through.
- `Engine::get_detection_events` / `get_edge_detection_events` /
  `subscribe_detection_events` (#113, 2.13.0) — detection-events
  read + v0.1 polling change feed. LensCore client-mode trace
  signing on `ACTION_RESULT` (#11) + v0.4 EgressFilter re-sign
  (#14) compose against `sign_hybrid` + the new read facades.

Same closure pattern throughout: **persist owns the primitive;
persist exposes the Engine facade** so cohabiting consumers don't
reach past `Arc<dyn HardwareSigner>` / `BackendDispatch` / etc.

---

## What v0.1.14 does NOT do

- **Doesn't add a daemon.** Persist is and remains a Python wheel.
  Doctrine is about library code paths, not process lifecycle.
- **Doesn't replace verify's planned v1.9 flock** (in
  `ciris-keyring`). Verify's flock targets the keyring layer for
  consumers that don't go through persist (e.g. a hypothetical
  Rust binary that uses `ciris-keyring` directly). The two locks
  compose cleanly: persist's lock serializes persist consumers;
  verify's will serialize verify-direct consumers; both target
  the same identity by PoB §3.2.
- **Doesn't move to an out-of-process verify daemon.** That's
  verify's planned v2.0 architecture. When it lands, persist's
  library will likely become a thin client of that daemon — the
  cohabitation guarantee gets stronger (singleton by construction)
  while persist's API stays the same.

---

## Threat model implications

| AV | Status before v0.1.14 | Status after v0.1.14 |
|---|---|---|
| AV-26 (multi-worker boot race — Postgres migrations) | ✓ Mitigated v0.1.5 (`pg_advisory_lock`) | unchanged |
| AV-27 (identity churn via ephemeral keyring storage) | ✓ Mitigated v0.1.7 (predicted), v0.1.9 (authoritative `storage_descriptor`) | unchanged |
| **AV-14** (cross-instance keyring contention) | ⚠ Open — race on cold-start `get_platform_signer` | ✓ **Mitigated v0.1.14** for persist consumers (library flock); ⚠ residual for direct `ciris-keyring` callers until verify v1.9 |

The v0.1.14 flock closes AV-14 for any host where the consumers
go through persist's library. The "go through persist" qualifier
covers everything that imports `ciris-persist` — which, per the
doctrine, is every higher-level CIRIS primitive that needs state.

---

## Implementation reference

| Component | Path | Notes |
|---|---|---|
| Bootstrap-lock helpers | `src/ffi/pyo3.rs::{bootstrap_lock_path, acquire_bootstrap_lock}` | POSIX flock via `fs4` crate; auto-released on FD close |
| Lock acquisition site | `src/ffi/pyo3.rs::PyEngine::new` | Wraps `get_platform_signer()` only; not held for the lifetime of the Engine |
| Unit tests | `src/ffi/pyo3.rs::tests::bootstrap_lock_*` | Smoke tests; cross-process contention tested via integration on real deployments |

---

## Cross-references

- **CIRISVerify** [`HOW_IT_WORKS.md` § Cohabitation Contract](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/HOW_IT_WORKS.md#cohabitation-contract) — operator rules + roadmap
- **CIRISVerify** [`THREAT_MODEL.md` § AV-14](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/THREAT_MODEL.md) — threat-model angle
- **CIRISPersist** [`docs/THREAT_MODEL.md` § AV-26](THREAT_MODEL.md) — companion advisory-lock pattern (Postgres migrations)
- **CIRISPersist** [`docs/INTEGRATION_LENS.md` § 11](INTEGRATION_LENS.md) — keyring-storage operator guidance
- **PoB FSD** § 3.2 — one-key-three-roles single-identity rationale
