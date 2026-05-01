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
