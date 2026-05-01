# TODO — CIRISRegistry persist support + manifest tool refactor

**Status:** tracking. Two upstream items must land before
CIRISPersist's CI can `register` its build manifest with
CIRISRegistry. Until they do, the build-manifest stage in
`.github/workflows/ci.yml` runs `generate` + `sign` and uploads
the artifact, but stops short of `register`.

## 1. CIRISRegistry needs persist-support

The current Registry gRPC service exposes
`RegistryAdminService/RegisterAgent` and `/RegisterBuild` —
both shaped around the Python agent's identity tree.
CIRISPersist isn't an agent; it's a Rust crate / Python wheel that
ships persistence infrastructure. The Registry needs either:

**Option A**: a generic `RegisterProjectBuild` endpoint that accepts
`project_name` + manifest + signature (matches what `tools/ciris_manifest.py`
already produces).

**Option B**: a parallel `RegisterCirisPersistBuild` that mirrors the
agent shape but is keyed off `project="ciris-persist"`.

Lean: **Option A**. Once CIRISLens, CIRISPortal, and other Rust crates
need build registration, a generic shape avoids per-project endpoints
proliferating. The agent's existing `RegisterAgent` stays for
backward compat.

**Owner:** CIRISRegistry team. No tracking issue yet — open one
when the work is scheduled.

## 2. Manifest tool cross-repo refactor

The Python script at `tools/ciris_manifest.py` in this repo is a
**vendored copy** generalizing
`~/CIRISAgent/tools/ops/register_agent_build.py`. The canonical home
should be a single shared location; today's vendoring is
drift-prone.

**Tracking issue**: [CIRISAI/CIRISAgent#707 — Refactor
register_agent_build.py → ciris_manifest.py for cross-project use](https://github.com/CIRISAI/CIRISAgent/issues/707).

When that lands, this repo's CI step will switch from invoking the
vendored copy to fetching the canonical script (e.g.,
`wget https://raw.githubusercontent.com/CIRISAI/CIRISAgent/main/tools/ops/ciris_manifest.py`)
and the local `tools/ciris_manifest.py` will be deleted with a
`git mv` to the trash.

Schema-version pinning (`SCHEMA_VERSION = "1.0"` in the script) is
the contract that holds across the refactor — consumers fail loudly
on mismatch rather than silently accepting drift.

## 3. ciris-keyring-sign-cli helper

Today `tools/ciris_manifest.py sign` reads a 32-byte Ed25519 seed
from `CIRIS_BUILD_SIGN_KEY` env var. That's adequate but loose:

- The seed is a CI secret, not a hardware-backed key.
- Different projects each manage their own CI secret rather than
  sharing CIRISVerify's keyring infrastructure.

CIRISVerify should ship a small Rust binary
(`ciris-keyring-sign-cli` or similar) that:

```bash
ciris-keyring-sign-cli sign \
  --key-id ciris-persist-build-v1 \
  --input /path/to/payload.bin \
  --output /path/to/signature.b64
```

Reads the named key from the OS keyring (TPM / Secure Enclave /
StrongBox / DPAPI where available; software fallback otherwise),
produces an Ed25519 signature, never exposes the seed bytes.

The Python script's `sign` subcommand then becomes a thin shell-out
wrapper instead of carrying its own crypto. Drop-in: the seed
*format* (32 bytes Ed25519) is the same whether the seed comes
from a CI secret or from a hardware-backed keyring — only the
extraction path changes.

**Owner:** CIRISVerify team. No tracking issue yet.

## 4. Sequence

```
v0.1.3  (now)         — CIRISPersist CI: generate + sign + upload
                        artifact. Register stage stub'd with TODO 99.
                        Vendored ciris_manifest.py.
                        Tracking issue: CIRISAI/CIRISAgent#707.
v0.1.x  (next)        — CIRISAgent#707 lands. CIRISPersist CI fetches
                        canonical script. Vendored copy removed.
v0.2.x  (later)       — CIRISRegistry adds RegisterProjectBuild.
                        CIRISPersist CI's register stage actually runs.
                        Coincides with CIRISVerify shipping
                        ciris-keyring-sign-cli — sign step uses
                        hardware-backed key instead of CI secret.
```

Each step is independent of the others; nothing is blocking on the
order. The current CI artifact (signed manifest) is consumable today
by any process that has the lens's published public key, even if
it never lands in the Registry.
