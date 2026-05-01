# Cohabitation Doctrine — persist as the runtime keyring authority

**Status:** authoritative architecture for v0.1.14+. This doc is
the persist-side complement to CIRISVerify's
[`HOW_IT_WORKS.md` § "Cohabitation Contract"](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/HOW_IT_WORKS.md#cohabitation-contract)
and `THREAT_MODEL.md` § AV-14. Read both.

---

## TL;DR

Three rules:

1. **Persist owns runtime keyring bootstrap.** Other CIRIS primitives on the same host *cede* to persist for `get_platform_signer()`-class operations.
2. **One keyring bootstrap per host/container.** Multi-worker deployments (e.g. `uvicorn --workers 4`) serialize cold-start through a filesystem `flock`; first worker bootstraps, others see the existing key.
3. **Same-alias = same identity.** Per Proof-of-Benefit Federation §3.2 (one-key-three-roles), a host with both an agent and a persist daemon should use the same alias to share one identity.

---

## Why persist is the right runtime authority

PoB §3.2 names a single Ed25519 key as identity-and-address-and-signer. That key has to exist on the host before any primitive can use it. Three primitives could be the bootstrap authority:

- **CIRISVerify** — pure crypto + keyring backend. Library, not a service. Has no process of its own at runtime; it's loaded as a static library by something else. So verify can't *own* the bootstrap; whoever loads verify first does.
- **CIRISAgent** — has a process, but the agent depends on persistence. If persist isn't up, the agent has nothing to write to. Agent-as-bootstrap means the keyring exists but the substrate doesn't, which is operationally awkward.
- **CIRISPersist** — has a process, has state, is the lowest CIRIS substrate primitive above verify. Already does Postgres bootstrap (advisory-lock-protected per AV-26), already has a process model with explicit `Engine::__init__`, already lifetime-manages the runtime. Adding "owns keyring bootstrap" is a natural extension of "owns persistence bootstrap."

Persist is the cleanest authority. The three rules above formalize what's structurally true: persist is the first stateful CIRIS primitive to come up on any host, so it owns the runtime keyring bootstrap.

---

## What this means for deployments

### Single-process, single-worker

The simplest case. Persist's `Engine::__init__` calls `get_platform_signer(alias)` exactly once. No race, no contention. Already worked at v0.1.13 and earlier.

### Multi-worker (uvicorn / gunicorn / k8s replicas)

Each worker spawns a Python process; each imports persist; each calls `Engine::__init__`. Pre-v0.1.14 these would race on `key_exists() → generate_key()` per CIRISVerify's AV-14.

**v0.1.14 fix**: filesystem `flock` around `Engine::__init__`'s `get_platform_signer()` call. Multi-worker semantics:

```
worker 1:  flock acquired → get_platform_signer (bootstrap if cold) → release
worker 2:  flock blocks  → ...waits ~50ms... → release seen → get_platform_signer (sees existing key) → release
worker 3:  flock blocks  → ...waits ~50ms... → release seen → get_platform_signer (sees existing key) → release
worker 4:  flock blocks  → ...waits ~50ms... → release seen → get_platform_signer (sees existing key) → release
```

POSIX `flock` auto-releases on FD close (including process panic). A worker crash mid-bootstrap doesn't strand the lock; the next worker acquires immediately.

**Lock path**:

```
${CIRIS_DATA_DIR}/.persist-bootstrap.lock     (preferred — co-located with seed)
/tmp/ciris-persist-bootstrap.lock              (fallback when CIRIS_DATA_DIR unset)
```

The `/tmp` fallback is acceptable because the lock is ephemeral by design. Cross-container coordination is out of scope (use orchestrator-level ordering — see below).

### Multi-primitive on one host

Common case: a single container or VM running both an agent and a lens, or a bridge + lens, or any combination. Each primitive is its own daemon. **Deployment ordering rule:**

```
persist.service
agent.service (Requires=persist.service, After=persist.service)
lens.service (Requires=persist.service, After=persist.service)
bridge.service (Requires=persist.service, After=persist.service)
```

By the time the dependent services start, persist has already bootstrapped the keyring. They become read-only consumers (their own ciris-keyring imports find the existing key and don't try to generate one).

**docker-compose equivalent:**

```yaml
services:
  persist:
    image: ghcr.io/cirisai/cirispersist:0.1.14
    volumes:
      - ciris-keyring:/var/lib/ciris/keyring
    environment:
      - CIRIS_DATA_DIR=/var/lib/ciris/keyring

  lens:
    image: ghcr.io/cirisai/cirislens:latest
    depends_on:
      persist:
        condition: service_started
    volumes:
      - ciris-keyring:/var/lib/ciris/keyring  # SAME volume, same alias
    environment:
      - CIRIS_DATA_DIR=/var/lib/ciris/keyring

volumes:
  ciris-keyring:
    driver: local
```

The shared volume + shared `CIRIS_DATA_DIR` ensures both primitives see the same keyring; the `depends_on` ordering ensures persist bootstraps first.

**k8s equivalent (init container)**:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cirislens
spec:
  template:
    spec:
      initContainers:
      - name: persist-bootstrap
        image: ghcr.io/cirisai/cirispersist:0.1.14
        command: ["python", "-c", "from ciris_persist import Engine; Engine(dsn='${DSN}', signing_key_id='lens-scrub-v1')"]
        env:
        - name: CIRIS_DATA_DIR
          value: /var/lib/ciris/keyring
        volumeMounts:
        - name: keyring
          mountPath: /var/lib/ciris/keyring
      containers:
      - name: lens
        # ... rest of pod spec, mounting the same volume
```

The init container runs to completion (bootstraps the keyring + runs Postgres migrations + exits), then the main container starts. Multi-replica deployments share the persistent volume; the init container's lock serializes across replicas at scheduling time.

### Multi-host

Out of scope for the cohabitation contract. Cross-host identity goes through CIRISRegistry — each host has its own keyring identity; the federation tracks them as distinct primitives.

---

## What v0.1.14 does NOT do

- **Doesn't enforce a strict process singleton.** Multi-worker deployments are a real and supported pattern; the flock just serializes cold-start, not the lifetime of each process.
- **Doesn't replace verify's planned v1.9 flock** (in `ciris-keyring`). Verify's flock targets the keyring layer for non-persist consumers (e.g. a Rust binary that uses `ciris-keyring` directly without going through persist). The two locks compose cleanly: persist's lock serializes persist consumers; verify's lock will serialize verify-direct consumers; both target the same identity by PoB §3.2.
- **Doesn't move to an out-of-process verify daemon.** That's verify's planned v2.0 architecture. When it lands, persist will likely become a thin client of that daemon. Until then, persist holds the runtime authority on each host.

---

## Threat model implications

| AV | Status before v0.1.14 | Status after v0.1.14 |
|---|---|---|
| AV-26 (multi-worker boot race — Postgres migrations) | ✓ Mitigated v0.1.5 (`pg_advisory_lock`) | unchanged |
| AV-27 (identity churn via ephemeral keyring storage) | ✓ Mitigated v0.1.7 (predicted), v0.1.9 (authoritative `storage_descriptor`) | unchanged |
| **AV-14** (cross-instance keyring contention) | ⚠ Open — race on cold-start `get_platform_signer` | ✓ **Mitigated v0.1.14** for persist consumers (flock); ⚠ residual for non-persist consumers until verify v1.9 |

The v0.1.14 flock closes the AV-14 cold-start window for any host where persist is the keyring authority — which, per the doctrine above, is every host with persist running.

---

## Implementation reference

| Component | Path | Notes |
|---|---|---|
| Bootstrap-lock helpers | `src/ffi/pyo3.rs::{bootstrap_lock_path, acquire_bootstrap_lock}` | POSIX flock via `fs4` crate; auto-released on FD close |
| Lock acquisition site | `src/ffi/pyo3.rs::PyEngine::new` | Wraps `get_platform_signer()` only; not held for the lifetime of the Engine |
| Unit tests | `src/ffi/pyo3.rs::tests::bootstrap_lock_*` | Smoke tests; cross-process contention tested via integration |

---

## Cross-references

- **CIRISVerify** [`HOW_IT_WORKS.md` § Cohabitation Contract](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/HOW_IT_WORKS.md#cohabitation-contract) — operator rules + roadmap
- **CIRISVerify** [`THREAT_MODEL.md` § AV-14](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/THREAT_MODEL.md) — threat-model angle
- **CIRISPersist** [`docs/THREAT_MODEL.md` § AV-26](THREAT_MODEL.md) — companion advisory-lock pattern (Postgres migrations)
- **CIRISPersist** [`docs/INTEGRATION_LENS.md` § 11.5](INTEGRATION_LENS.md) — keyring-storage operator guidance
- **PoB FSD** § 3.2 — one-key-three-roles single-identity rationale
