# Cohabitation Doctrine — persist as the runtime keyring authority

How several CIRIS consumers share one persist engine and one identity — across
processes on a host, inside one process, and across separately-built wheels in
one process. Companion to CIRISVerify's
[`HOW_IT_WORKS.md` § "Cohabitation Contract"](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/HOW_IT_WORKS.md#cohabitation-contract)
and CIRISVerify's `THREAT_MODEL.md` § AV-14.

---

## TL;DR

**Persist is a Python wheel and a Rust crate — not a daemon.** Every consumer
(lens, agent, edge, node, registry client) imports it as a library and
constructs `Engine(...)` in its own process. There is no `persist.service`.
Three rules for hosts where multiple consumers import persist:

1. **The first `Engine::__init__` on the host bootstraps the keyring.**
   Later calls (other workers, other consumers) see the existing key. A POSIX
   `flock` serializes cold start across processes.
2. **One keyring identity per host/container.** Consumers on the same host
   using the same `signing_key_id` resolve to the same identity by
   construction (PoB §3.2 one-key-three-roles).
3. **Persist's library code is the canonical bootstrap path on a host.**
   Every primitive that goes through persist (lens, the agent's PyO3 path,
   edge) inherits the cohabitation guarantee. A caller that uses
   `ciris-keyring` directly, skipping persist, is outside this lock.

---

## What "persist as authority" means

Persist is not a *process* that other primitives wait on. It is a *library*
whose `Engine` constructor performs the canonical keyring bootstrap:

> Persist is the lowest stateful CIRIS substrate above verify. Its
> `Engine::__init__` is the canonical entry point for keyring resolution on a
> host. Any consumer importing persist gets the serialized-bootstrap
> guarantee; the flock makes cold start safe no matter how many consumers
> race the import.

There is no daemon, no `Requires=After=persist.service`, and no init container
that runs persist before the workload. The doctrine is about **library code
paths**:

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

Worker 1 takes the flock and calls `get_platform_signer(alias)`, which
generates the key on cold start or returns the existing one. Worker 2 blocks
on the flock briefly; when it gets through, the key already exists and its
`get_platform_signer` returns it without generating. Both workers then use the
same identity.

---

## Why the lowest stateful library is the authority

PoB §3.2 names a single Ed25519 key as identity, address and signer. Some
library on each host has to be the canonical entry point for resolving that
key:

- **CIRISVerify** is crypto plus the keyring backend. It is loaded by
  something else and has no inherent "first call" on a host. Consumers
  loading verify directly would each call `get_platform_signer()`
  independently — the race CIRISVerify's AV-14 names.
- **CIRISAgent / CIRISLens / CIRISEdge / CIRISNodeCore** *consume*
  persistence and crypto. None has a natural claim to own the keyring;
  putting the bootstrap in one of them creates asymmetry.
- **CIRISPersist** is the lowest stateful library above verify. Every higher
  primitive that needs durable state imports it, so its `Engine::__init__` is
  the first point on a host where state initialization happens. Pinning the
  keyring bootstrap there means every consumer that uses persist inherits the
  guarantee.

Persist is the authority **because it is the canonical first stateful
library**, not because it runs as a daemon.

---

## Multi-worker semantics

Each worker is a Python process that imports persist and calls
`Engine::__init__`. Without coordination they would race on
`key_exists() → generate_key()`. Persist wraps `Engine::__init__`'s
`get_platform_signer()` call in a filesystem `flock`:

```
worker 1:  flock acquired → get_platform_signer (bootstrap if cold) → release
worker 2:  flock blocks  → ...waits... → get_platform_signer (sees existing key) → release
worker 3:  flock blocks  → ...waits... → get_platform_signer (sees existing key) → release
```

POSIX `flock` releases on FD close, including on process panic, so a worker
crash mid-bootstrap does not strand the lock.

**Lock path:**

```
${CIRIS_DATA_DIR}/.persist-bootstrap.lock     (preferred — co-located with the seed)
/tmp/ciris-persist-bootstrap.lock              (fallback when CIRIS_DATA_DIR is unset)
```

The `/tmp` fallback is acceptable because the lock is ephemeral by design.

---

## Multi-primitive on one host

A container or VM may run an agent and a lens, an edge and a lens, or any
combination. All of them import persist. Each constructs `Engine(...)` with
the same alias and the same `CIRIS_DATA_DIR`, so the same flock path → the
same identity.

**docker-compose example** (two services sharing one identity):

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

The shared volume and shared alias are the whole story. Whichever container's
`Engine::__init__` runs first does the bootstrap; the other sees the existing
key. No `depends_on`, no service ordering, no init container.

**Per-replica scaling** (k8s `replicas: N`): each replica imports persist and
calls `Engine::__init__`. A shared persistent volume means every replica sees
the same keyring backend; the flock serializes any replica that hits the cold
path.

---

## In-process cohabitation — one process, several consumers

The sections above cover **multi-process** cohabitation. Persist also supports
**one process** hosting several consumers — the agent runtime plus
CIRISNodeCore plus CIRISLensCore as in-process adapters, all using persist.
Two tokio runtimes contending on one database in one process deadlock
(CIRISPersist#75), so the engine is a process singleton.

### The singleton contract

**`Engine` is a process singleton.** The tokio runtime and connection pool
are built exactly once per process (`ENGINE_SINGLETON` in `src/ffi/pyo3.rs`).

1. **One owner constructs.** Whoever boots the process calls
   `Engine(dsn, signing_key_id, …)` first. That call builds the runtime and
   pool.

2. **Adapters attach, never rebuild.** An in-process adapter either receives
   a handle from the owner (`engine.engine_handle()` — an `Arc`-clone sharing
   the runtime, pool, signer, closed flag and consumer registry, with no DSN
   or key needed) or calls `Engine(...)` with the **same config** and gets the
   same cell. A different DSN / signing-key-id raises `EngineConfigMismatch`
   (CIRISPersist#76): a process hosts exactly one persist engine, and a silent
   rebind to a different backend would corrupt data.

3. **Consumers register; one owner closes.** An adapter calls
   `register_consumer(name, substrates=[...])` on bring-up and
   `deregister_consumer(name)` on teardown; `consumer_count` and
   `list_consumers()` report who is attached. The owner calls
   `engine.close()` at shutdown, which refuses with `RuntimeError` while any
   consumer is still registered unless `force=True`. `close_blocking()` and
   the module-level `reset_engine()` / `engine_teardown_wait()` wait for
   teardown with the GIL released and report `drained` / `deferred` /
   `timed_out` / `no_engine` — `deferred` means another live handle still
   holds the cell. After close every method raises `EngineClosed`; a fresh
   `Engine(...)` afterwards rebuilds.

4. **Construct after forking.** A tokio runtime does **not** survive
   `fork()` — the child inherits worker threads that do not exist and mutexes
   that may be held. Construct `Engine` **after** all forking (after
   uvicorn/gunicorn spawn their workers), or set the `multiprocessing` start
   method to `"spawn"`. Every `Engine` method checks the calling pid against
   the construction pid; a mismatch raises `EngineUsedAcrossFork`
   (CIRISPersist#78) instead of deadlocking.

`EngineConfigMismatch`, `EngineClosed`, and `EngineUsedAcrossFork` all derive
from `PersistError`.

**In-process change feed.** `subscribe(substrate, callback)` /
`publish_change(substrate, event_json)` / `unsubscribe(id)` give co-resident
consumers a synchronous, in-process notification channel keyed by substrate
family (CIRISPersist#84). It has no persistence or replay: a subscriber that
attaches after a publish does not see that event.

### Relationship to the multi-process flock

The two mechanisms are orthogonal and compose:

- **Multi-process** (uvicorn workers, separate containers) — the keyring
  flock serializes cold-start identity creation. Each process has its own
  singleton engine.
- **In-process** (agent + NodeCore + LensCore) — the singleton gives the one
  process one runtime, shared by every in-process consumer.

A typical deployment uses both: N worker processes, each flock-serialized for
keyring convergence, and inside each worker one shared engine for the
co-resident adapters.

## Consumer → substrate ownership (CIRISPersist#82)

Under the singleton, the one engine owns every substrate schema: whichever
consumer constructs `Engine(...)` first runs the full migration set, and every
co-resident consumer shares that schema. There is no per-consumer schema
partition and no per-call write enforcement — the singleton has no caller
identity to enforce against.

Persist provides a **cooperative ownership declaration**. A consumer declares
the substrate families it owns in `register_consumer(name, substrates=[...])`;
`substrate_owner(substrate)` tells any consumer who owns a family before it
writes there. This is advisory: it catches mis-wiring and double ownership in
diagnostics; it is not a write firewall.

Declared names are validated against persist's five substrate families
(`register_consumer` raises `ValueError` on an unknown name). The ownership
contract is:

| Substrate family | Postgres schema | Owning consumer | Absorbs |
|---|---|---|---|
| `cirisgraph` | `cirisgraph` | CIRISAgent | MemoryService, ConfigService |
| `cirislens` | `cirislens` | CIRISLensCore | observability ingest, tasks/thoughts/correlations/tickets/etc. |
| `cirislens_secrets` | `cirislens_secrets` | CIRISLensCore | SecretsService |
| `cirislens_derived` | `cirislens_derived` | CIRISLensCore | telemetry rollups, derived audit views |
| `cirisnode` | `cirisnode` | CIRISNodeCore | federation-consensus substrate |

Audit, incident, telemetry, sequence and occurrence tables live within
`cirislens` / `cirislens_derived` and are owned transitively by the LensCore
declaration. A consumer that owns no substrate (a pure reader) registers with
`substrates=[]` for the lifecycle count.

Hard per-call write rejection — refusing a write to a substrate the *calling*
consumer did not declare — is a **non-goal**: it would need each adapter's
handle to carry its own identity. Ownership is a cooperative contract enforced
by this table and by code review, not by the engine.

## Cross-cdylib cohabitation — separately-built wheels

A sibling Python wheel (e.g. CIRISEdge's `ciris_edge.abi3.so`) that also links
`ciris-persist` produces **two distinct PyO3 extension modules** in one Python
process. PyO3 registers `#[pyclass]` types per extension module, so the
`PyEngine` from each `.so` is the same Rust struct but a distinct
`PyTypeInfo`, and `isinstance(engine, PyEngine)` fails across modules
(CIRISEdge#22: `'Engine' object is not an instance of 'Engine'`). Each `.so`
also carries its own copy of `static ENGINE_SINGLETON`, so the consumer
wheel's copy is never populated by the host's `Engine(...)`.

Persist hands shared state across that boundary as **`PyCapsule` accessors**
on `PyEngine`. A capsule is an opaque pointer with a name tag; the receiving
cdylib extracts it by name with no `PyTypeInfo` lookup. A capsule is **not a
Python object**: its only legal consumer is another CIRIS cdylib in the same
process, and holding it past `close()` is undefined behaviour.

The ABI-stable capsules pass a serialised-op handle, so the two cdylibs never
share a Rust vtable layout (a raw `Arc<dyn>` vtable's order is not guaranteed
by the compiler — CIRISPersist#320). Prefer them:

| Capsule (on `PyEngine`) | Hands over | Issue |
|---|---|---|
| `directory_ops_capsule` | the federation directory, ABI-stable | #320 |
| `outbound_queue_ops_capsule` | the outbound queue, ABI-stable | #320 |
| `signer_ops_capsule` | the node's signer, ABI-stable — **security-critical**: it lets the holder sign as this node | #320 |
| `executor_capsule` | the async executor, ABI-stable | #157 |
| `runtime_handle_capsule` | a clone of the engine's own `tokio::runtime::Handle`, sourced from `self` rather than the static | #111 |
| `local_signer_capsule` | the transport-identity `LocalSigner` | #119 |
| `trust_scoring_capsule` | `Arc<dyn TrustScoring>` from the installed admission gate | #129 |
| `blob_storage_capsule` | the blob-storage substrate | #115 |
| `federation_directory_capsule` | `Arc<dyn FederationDirectory>` (raw vtable; use `directory_ops_capsule`) | #109 |
| `outbound_queue_capsule` | outbound-queue substrate (raw; use `outbound_queue_ops_capsule`) | #109 |
| `keyring_signer_capsule` | `KeyringSignerHandle`, reusing the host's signer per rule 1 (raw; use `signer_ops_capsule`) | #109 |

### Rust-native consumers

A Rust caller that compiles `ciris-persist` as a Cargo dependency in the same
binary reaches the engine through the Rust API with no PyO3 in the loop:
`current_rust_engine()` returns the shared engine, and
`Engine::federation_directory()` returns `Arc<dyn FederationDirectory>`
directly. Capsules serve Python-orchestrated cohabitation; the Rust accessors
serve Rust-native hosts. Both are backed by the same singleton `EngineCell` —
one engine, one pool, one runtime, one keyring per process.

### Engine facades for cohabiting consumers

Persist owns each primitive and exposes an `Engine` facade for it, so
cohabiting consumers never reach past `Arc<dyn HardwareSigner>` /
`BackendDispatch`:

- `Engine::receive_and_persist` — the ingest path.
- `Engine::storage_summary` / `delete_traces_older_than` /
  `archive_audit_range` — retention primitives.
- `Engine::node_core_service()` / `audit_service()` — per-substrate
  accessors.
- `Engine::sign_hybrid(message)` — hybrid Ed25519 + ML-DSA-65 signing through
  the engine's `LocalSigner`; `Engine::from_shared_with_local` carries that
  signer through the cohabitation boundary.
- `Engine::get_detection_events` / `get_edge_detection_events` /
  `subscribe_detection_events` — detection-event reads and a polling change
  feed.

---

## Limits

- **No daemon.** Persist is a library. The doctrine is about library code
  paths, not process lifecycle.
- **Direct keyring callers are outside the lock.** The bootstrap flock
  serializes consumers that go through persist. A binary that calls
  `ciris-keyring` directly does not take it; keyring-layer locking for those
  callers is CIRISVerify's concern. Both target the same identity under PoB
  §3.2.
- **Not an out-of-process verify client.** Persist links CIRISVerify in
  process.

---

## Threat model

| AV | Status |
|---|---|
| Persist AV-26 (multi-worker boot race — Postgres migrations) | ✓ Mitigated (`pg_advisory_lock`) |
| Persist AV-27 (identity churn via ephemeral keyring storage) | ✓ Mitigated (authoritative `storage_descriptor`) |
| CIRISVerify **AV-14** (cross-instance keyring contention) | ✓ Mitigated for persist consumers (library flock); residual for direct `ciris-keyring` callers |

The flock closes the keyring race on any host where consumers go through
persist's library — every higher-level CIRIS primitive that imports
`ciris-persist`.

---

## Implementation reference

| Component | Path | Notes |
|---|---|---|
| Bootstrap-lock helpers | `src/ffi/pyo3.rs::{bootstrap_lock_path, acquire_bootstrap_lock}` | POSIX flock via `fs4`; released on FD close |
| Lock acquisition site | `src/ffi/pyo3.rs::PyEngine::new` | Wraps `get_platform_signer()` only; not held for the Engine's lifetime |
| Process singleton | `src/ffi/pyo3.rs::ENGINE_SINGLETON` | `OnceLock<Mutex<Option<Arc<EngineCell>>>>` |
| Unit tests | `src/ffi/pyo3.rs::tests::bootstrap_lock_*` | Path resolution and smoke tests |

---

## Cross-references

- **CIRISVerify** [`HOW_IT_WORKS.md` § Cohabitation Contract](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/HOW_IT_WORKS.md#cohabitation-contract) — operator rules
- **CIRISVerify** [`THREAT_MODEL.md` § AV-14](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/THREAT_MODEL.md) — keyring contention
- **CIRISPersist** [`docs/THREAT_MODEL.md` § AV-26](THREAT_MODEL.md) — companion advisory-lock pattern (Postgres migrations)
- **CIRISPersist** [`docs/INTEGRATION_LENS.md` § 11](INTEGRATION_LENS.md) — keyring-storage operator guidance
- **PoB FSD** § 3.2 — one-key-three-roles single-identity rationale
