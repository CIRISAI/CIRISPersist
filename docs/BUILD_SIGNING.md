# Build manifest signing — operator runbook

v0.1.9+ uses CIRISVerify v1.8.0's `ciris-build-sign` CLI to produce
hybrid Ed25519 + ML-DSA-65 signatures over each release's
`BuildManifest`. The signed manifest is the artifact peers verify
to confirm "this is CIRISAI's official ciris-persist build."

This doc covers the one-time key generation + CI-secret upload
the bridge team does so subsequent CI runs sign automatically.

---

## TL;DR — bridge team checklist

```bash
# 1. On a trusted local machine (NOT CI):
cargo install --locked --git https://github.com/CIRISAI/CIRISVerify \
  --tag v1.8.0 ciris-build-tool

# 2. Generate the hybrid keypair:
mkdir -p ~/.ciris-build-sign-persist && cd ~/.ciris-build-sign-persist
ciris-build-sign generate-keys --output-dir .
# Produces:
#   ed25519.seed       (32 bytes — Ed25519 seed)
#   ed25519.public     (32 bytes — Ed25519 public key)
#   mldsa65.secret     (~4032 bytes — ML-DSA-65 secret)
#   mldsa65.public     (~1952 bytes — ML-DSA-65 public)

# 3. Base64-encode the secrets for GitHub-secret upload:
base64 -w0 ed25519.seed   # paste into GH repo secret CIRIS_BUILD_ED25519_SECRET
base64 -w0 mldsa65.secret # paste into GH repo secret CIRIS_BUILD_MLDSA_SECRET

# 4. Publish the public keys somewhere peers can fetch (announce file
# in the repo, registry entry, etc.). Persist's CI does NOT need
# the public keys; verify-side consumers do.

# 5. Move the local copies offline (USB key, password manager).
# DO NOT commit any of the four files to git.
```

After step 4, the next push to `main` runs the
`build-manifest` job in `.github/workflows/ci.yml` and produces
a signed manifest as an artifact.

---

## Why hybrid Ed25519 + ML-DSA-65

Per Proof-of-Benefit Federation §1.4, every PoB primitive's signing
path is *post-quantum-ready*. Ed25519 covers today's classical
threat model with 128-bit security; ML-DSA-65 (formerly
CRYSTALS-Dilithium, NIST FIPS 204) covers the post-quantum
threat model at NIST Level 3.

Both signatures cover the same canonical bytes
(`BuildManifest::canonical_bytes()`). At verify time both must check
out — a manifest where Ed25519 verifies but ML-DSA-65 doesn't is
**rejected**, and vice versa. This is the correct posture during
the transition window; a flaw in either primitive doesn't degrade
to "the other one still works." If quantum cryptography arrives
on a timeline that surprises us, the Ed25519 half stops mattering;
the ML-DSA-65 half keeps the manifest provable.

---

## Why the keypair gen happens on a trusted local machine

The Ed25519 seed and ML-DSA-65 secret are the deployment's *root*
build identity. If they leak, an adversary can sign manifests that
peers will accept as official ciris-persist builds. The threat
model treats this the same way it treats the lens-scrub key
(THREAT_MODEL.md AV-25): hardware-backed where possible, never on
shared infrastructure, never in CI runner ephemeral state.

The CI job receives the secrets via GitHub's masked-secret
mechanism, materialises them to short-lived files inside the
runner, runs `ciris-build-sign`, and immediately wipes the files.
The GH masked-secret mechanism prevents accidental log echo. We
don't trust the runner long-term; we trust it for the duration of
one signing operation.

Generating the keys on the runner instead would mean either:
- regenerating per build (worst — public key changes every release,
  breaking peer-side identity), or
- persisting the runner's filesystem state (worse — runner state
  is supposed to be ephemeral; treating it as a key vault is an
  anti-pattern).

The trusted-local-gen + masked-secret-upload pattern is what
GitHub Actions documents for build signing across the OSS
ecosystem (sigstore cosign, npm package provenance, etc.).

---

## Verifying a signed manifest locally

Once a CI run produces a signed manifest:

```bash
# Download from the GH Actions artifact:
gh run download <run-id> -n ciris-persist-build-manifest-<version>

# Verify with the public keys (peer-side workflow):
ciris-build-verify \
  --manifest ciris-persist-<version>.manifest.json \
  --ed25519-public ed25519.public \
  --mldsa-public mldsa65.public
# Exits 0 on success; non-zero with a typed error otherwise.
```

The verifier:
1. Recomputes the canonical bytes from the manifest's universal
   core + extras.
2. Verifies the Ed25519 signature against `ed25519.public`.
3. Verifies the ML-DSA-65 signature against `mldsa65.public`.
4. Dispatches the registered `PersistExtrasValidator` to validate
   the typed extras shape.
5. Returns a structured pass/fail.

A consumer (registry, lens, peer) calling
`ciris_verify_core::security::build_manifest::verify_build_manifest`
gets the same result programmatically; the CLI is just a
convenient front-end.

---

## When to rotate

Rotate when any of these happen:

- **Suspected key compromise.** Treat as P0; revoke the public
  key in any registry that's published it, generate fresh
  keypair, re-upload secrets, push a release that re-signs the
  current binaries with the new keypair.
- **Routine schedule.** Recommend annual rotation as a hygiene
  baseline. Not load-bearing today (no automated rotation
  enforcement); revisit when the registry-side `rotate_public_key`
  API lands (THREAT_MODEL.md AV-11, v0.2.x scope).
- **NIST publishes a successor to ML-DSA-65.** Unlikely before
  several years; ML-DSA is FIPS 204 final.

Rotation procedure: same as the initial gen, plus update the
public-key announcement so peers can find the new key. The
manifest's `key_id` field (passed to `ciris-build-sign --key-id`)
is what consumers use to discover which public key signed a given
manifest; bumping `key_id` (e.g.
`ciris-persist-build-v1` → `ciris-persist-build-v2`) makes the
rotation operationally visible.

---

## Failure modes

- **Either secret missing in CI.** The build-manifest job
  fails fast with a typed message pointing here. Fix: upload the
  missing secret. We do NOT fall back to unsigned-mode at v1.8.0;
  unsigned manifests are not a recognised primitive shape.
- **Public-key mismatch at verify-side.** Peer rejects the
  manifest with a typed `SignatureMismatch`. Fix: confirm the
  peer is checking against the most-recent published public key,
  not a stale cached copy.
- **Extras validator rejects.** Caller gets `IntegrityError`. The
  message will name the offending field (e.g.
  "PersistExtras.migration_set_sha256 malformed"). Fix is
  source-tree-level: the CI emit step (`emit_persist_extras`) is
  computing the wrong shape.
