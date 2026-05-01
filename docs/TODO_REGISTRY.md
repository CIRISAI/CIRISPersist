# Registry registration — historical notes

**Status (v0.1.11+):** all the cross-repo TODOs this doc once tracked
have landed. Build-manifest signing + registry registration are
end-to-end in `.github/workflows/ci.yml`. Kept here as a
short audit-trail of what shipped and where.

## What was tracked, and where it landed

| Original ask | Resolved by |
|---|---|
| **CIRISRegistry needs persist support** (`project=ciris-persist`) | CIRISRegistry commit [`254a89e`](https://github.com/CIRISAI/CIRISRegistry/commit/254a89e). `POST /v1/verify/binary-manifest` and `/v1/verify/function-manifest` accept `"project": "ciris-persist"`. GET endpoints accept `?project=ciris-persist`. |
| **Manifest tool cross-repo refactor** (vendored python helper drift) | CIRISVerify v1.8.0 shipped `ciris-build-tool` (Rust crate) with `ciris-build-sign` + `ciris-build-verify` CLIs. Persist's vendored `tools/ciris_manifest.py` moved to `tools/legacy/` in v0.1.9; deleted in v0.2.0. |
| **`ciris-keyring-sign-cli` for hardware-backed signing** | Subsumed by the above. `ciris-build-sign` accepts file-backed secrets (Ed25519 seed + ML-DSA-65 secret) and is the canonical signer for every PoB primitive. Hardware-backed signing is a future ciris-keyring-side enhancement (`HardwareSigner::storage_descriptor()` already exposes the storage class; signing through the trait is the next iteration). |

## What persist's CI does today (v0.1.11+)

Pipeline (`.github/workflows/ci.yml::build-manifest`):

1. **Build wheel** (`pyo3-wheel` job) → `cp311-abi3-manylinux_2_34_x86_64.whl`.
2. **Emit `PersistExtras` JSON** via `cargo run --bin emit_persist_extras` (computes
   `supported_schema_versions`, `migration_set_sha256`, `dep_tree_sha256` deterministically from the
   source tree).
3. **Sign manifest** via `ciris-build-sign sign --primitive persist` (hybrid Ed25519 + ML-DSA-65,
   secrets `CIRIS_BUILD_ED25519_SECRET` + `CIRIS_BUILD_MLDSA_SECRET`).
4. **Pre-flight registry steward-key** — `GET /v1/steward-key` for visibility (logs the active
   key_id; ephemeral mode is operationally observable but not gating).
5. **Register binary manifest** — `POST /v1/verify/binary-manifest` with `project=ciris-persist`,
   admin token via `secrets.REGISTRY_ADMIN_TOKEN`, registry URL via `vars.REGISTRY_URL` (defaults
   to `https://api.registry.ciris-services-1.ai`).
6. **Round-trip verify** — `GET /v1/verify/binary-manifest/<version>?project=ciris-persist` and
   diff the binary hash; CI fails if it doesn't round-trip.
7. **Upload artifacts** — manifest, extras, steward-key snapshot, registry POST response,
   round-trip GET response. 90-day retention.

## What still requires bridge / ops action

These are the only operational gates left; none are code-side:

- **`CIRIS_BUILD_ED25519_SECRET`** and **`CIRIS_BUILD_MLDSA_SECRET`** — generated once via
  `ciris-build-sign generate-keys`, base64-encoded, uploaded as repo secrets.
  Procedure in `docs/BUILD_SIGNING.md`.
- **`REGISTRY_ADMIN_TOKEN`** — issued by the registry team; uploaded as a repo secret.
- **`REGISTRY_URL`** (optional repo variable) — overrides the default
  `https://api.registry.ciris-services-1.ai` for staging / sovereign-mode deployments.

When all three are set, the build-manifest job goes green end-to-end and persist issue #2 closes
on the round-trip evidence.

## What's NOT registered today

- **Function-manifest** (`POST /v1/verify/function-manifest`). Persist doesn't produce
  function-level integrity data (we're a Rust crate + PyO3 surface, not a CIRISVerify-style
  attestation primitive). Binary-manifest is the right shape; function-manifest stays for
  primitives that need it (CIRISVerify itself, agent's runtime functions).
- **gRPC `RegisterBuild`**. Registry exposes both HTTP and gRPC; persist uses HTTP because the
  Rust → curl shape is simpler in CI than wiring a gRPC client. Switch later if there's a
  reason; HTTP is good enough today.
