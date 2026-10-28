# Build manifest signing and registration — operator runbook

Every release is signed with a hybrid Ed25519 + ML-DSA-65 key and registered
with CIRISRegistry, so a peer can confirm "this is CIRISAI's official
ciris-persist build" before it loads it. The signer is CIRISVerify's
`ciris-build-sign`, at the version pinned as `TOOL_VERSION` in
`scripts/build_manifest.sh`.

Each version has five signed manifests (CanonicalBuild v2):

| target | covers |
|---|---|
| `python-source-tree` | a hash over `python/ciris_persist` (what iOS and Android agent rebuilds verify against) |
| `x86_64-unknown-linux-gnu` | the linux x86_64 wheel |
| `aarch64-unknown-linux-gnu` | the linux aarch64 wheel |
| `aarch64-apple-darwin` | the macOS arm64 wheel |
| `x86_64-pc-windows-msvc` | the windows x86_64 wheel |

This document covers the one-time key setup, what CI does with the keys, and
how to verify and rotate. The release-side checks on the signed bytes (the
bits-changed gate, attestations, and repairing a registered row) are in
[RELEASE.md](RELEASE.md).

## One-time setup: the signing key

On a trusted local machine, never on CI:

```bash
# 1. Install the pinned signer (TOOL_VERSION in scripts/build_manifest.sh),
#    from the CIRISVerify release of that tag.

# 2. Generate the hybrid keypair:
mkdir -p ~/.ciris-build-sign-persist && cd ~/.ciris-build-sign-persist
ciris-build-sign generate-keys --output-dir .
# Produces:
#   ed25519.seed       (32 bytes — Ed25519 seed)
#   ed25519.pub        (32 bytes — Ed25519 public key)
#   mldsa65.secret     (32 bytes — ML-DSA-65 seed; full key derived at sign time)
#   mldsa65.pub        (1952 bytes — ML-DSA-65 public)

# 3. Base64-encode the secrets for GitHub-secret upload:
base64 -w0 ed25519.seed   # repo secret CIRIS_BUILD_ED25519_SECRET
base64 -w0 mldsa65.secret # repo secret CIRIS_BUILD_MLDSA_SECRET

# 4. Publish the public keys where peers fetch them (the registry entry).
#    Persist's CI does not need the public keys; verifiers do.

# 5. Move the local copies offline. Never commit any of the four files.
```

The registry side needs two more values from the registry team:

- **`REGISTRY_ADMIN_TOKEN`** (repo secret). Scoped to the persist build
  identity. Without it the register step fails with a message naming the
  missing secret.
- **`REGISTRY_URL`** (repo variable, optional). Defaults to
  `https://api.registry.ciris-services-1.ai`; override it for staging or
  sovereign deployments. It is a variable, not a secret, because it is a public
  endpoint.

### Why hybrid Ed25519 + ML-DSA-65

Every Proof-of-Benefit primitive's signing path is post-quantum-ready
(Proof-of-Benefit Federation §1.4). Ed25519 covers the classical threat model;
ML-DSA-65 (NIST FIPS 204) covers the post-quantum one at NIST Level 3. Both
signatures cover the same canonical bytes, and a verifier requires both: a
manifest where one verifies and the other does not is rejected. A flaw in
either primitive therefore never degrades to "the other one still works".

### Why the key is generated locally

The two secrets are the root build identity. If they leak, an adversary can
sign manifests peers accept as official builds. They are treated like the
lens-scrub key ([THREAT_MODEL.md](THREAT_MODEL.md) AV-25): hardware-backed
where possible, never on shared infrastructure, never in a runner's state. CI
receives them as masked secrets, writes them to short-lived files for one
signing operation, and wipes them. Generating keys on the runner would either
change the public key every release or treat ephemeral runner state as a key
vault.

## What CI does

The `build-manifest` job in `.github/workflows/ci.yml` runs after the wheel
builds. All of its logic is in `scripts/build_manifest.sh`, which
`.github/workflows/reregister-manifests.yml` shares.

| step | command | when |
|---|---|---|
| install the signer | `build_manifest.sh install` (refuses a binary that does not report `TOOL_VERSION`) | every run |
| emit `PersistExtras` | `cargo run --bin emit_persist_extras` (`supported_schema_versions`, `migration_set_sha256`, `dep_tree_sha256`, computed from the source tree) | every run |
| sign | `build_manifest.sh sign`: `scripts/bits_changed.sh` checks 1–4 on each wheel, then `ciris-build-sign`, which itself refuses a wheel whose version or platform tag does not match | every run |
| pre-flight | `build_manifest.sh preflight`: the registry trust-root gate (`scripts/preflight_trust_root.py`) | every run, before register |
| register | `build_manifest.sh register`: per target a `builds` row (`POST /v1/builds`) and a build-manifest row (`POST /v1/verify/build-manifest`) | tag runs only |
| round-trip | `build_manifest.sh roundtrip`: `GET /v1/builds/<version>` must answer for every target | tag runs only |
| after-publish | `build_manifest.sh after-publish`: `bits_changed.sh --after-publish`, each registered row carries this run's wheel | tag runs only |

The signed manifests and every registry response are uploaded as the run's
`ciris-persist-build-manifest-<version>` artifact.

## Verifying a signed manifest

```bash
gh run download <run-id> -n ciris-persist-build-manifest-<version>

ciris-build-verify \
  --manifest ciris-persist-<version>.manifest.json \
  --ed25519-public ed25519.pub \
  --mldsa-public mldsa65.pub
# Exits 0 on success; non-zero with a typed error otherwise.
```

The verifier recomputes the canonical bytes from the manifest's core and
extras, checks both signatures, and dispatches the registered
`PersistExtrasValidator` (`src/manifest/mod.rs`) to validate the extras' typed
shape. A consumer calling
`ciris_verify_core::security::build_manifest::verify_build_manifest` gets the
same result programmatically.

## Rotation

Rotate the signing key when:

- **a compromise is suspected.** Treat it as P0: revoke the public key wherever
  it is published, generate a fresh keypair, re-upload the secrets, and cut a
  release that re-signs the current binaries.
- **on a routine schedule.** Annual rotation is the recommended baseline;
  nothing enforces it.
- **NIST publishes a successor to ML-DSA-65.**

The procedure is the initial setup again, plus a new public-key announcement.
Consumers find the signing key by the manifest's `key_id` (`KEY_ID` in
`scripts/build_manifest.sh`); bumping it (`ciris-persist-build-v1` →
`ciris-persist-build-v2`) makes a rotation visible.

`REGISTRY_ADMIN_TOKEN` rotates on the registry team's policy, or at once if it
leaks. It is scoped to the build identity, not to a crate version, so rotating
it is independent of releases.

## Failure modes

- **A signing secret is missing in CI.** The sign step fails with a message
  naming the secret. There is no unsigned mode.
- **Public-key mismatch at the verifier.** The peer rejects the manifest with
  `SignatureMismatch`. Check that it verifies against the current published
  key, not a cached one.
- **The extras validator rejects.** The caller gets `IntegrityError` naming the
  field (for example `PersistExtras.migration_set_sha256 malformed`). The fix is
  in the source tree: `emit_persist_extras` is computing the wrong shape.
- **A wheel's bits did not change, or are a known-stale build.** The
  bits-changed gate refuses before signing; see [RELEASE.md](RELEASE.md), "The
  bits-changed gate".
