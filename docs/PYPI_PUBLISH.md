# PyPI publishing — operator runbook

v0.1.12+ publishes `ciris-persist` wheels to PyPI on every tag push
via OIDC trusted publishing (no long-lived API token in CI).

This doc covers the **one-time setup** needed on the PyPI side
before the first tag push triggers a successful publish.

---

## TL;DR — checklist

1. Reserve the project name on PyPI.
2. Configure trusted publisher pointing at this repo + the `ci.yml`
   workflow + the `pypi` environment.
3. Tell persist to push a tag (or push v0.1.12 — it's already
   prepped). Wheel publishes; `pip install ciris-persist` works.

Total time: ~5 minutes if you have a PyPI account already, ~10
otherwise.

---

## Why OIDC trusted publishing (no API token)

Older PyPI publish flows used long-lived API tokens uploaded as
GitHub repo secrets. Tokens leak; rotation is manual; revocation
is reactive.

PyPI's trusted publishing (PEP 740 / OIDC) replaces that:

- GitHub Actions issues a short-lived JWT identifying the workflow run.
- PyPI verifies the JWT against a pre-configured trust policy
  ("only allow uploads from `CIRISAI/CIRISPersist`'s `ci.yml`
  workflow running in the `pypi` environment").
- No persistent credential stored anywhere.

Recommended pattern across the OSS ecosystem (sigstore cosign,
npm provenance, etc.). What the [PyPI docs themselves recommend](https://docs.pypi.org/trusted-publishers/).

---

## Setup steps

### 1. Reserve `ciris-persist` on PyPI

If you've never published anything to PyPI before, you'll need an
account first. Once logged in:

- Go to https://pypi.org/manage/account/publishing/
- Click "Add a new pending publisher" (this works *before* the
  project exists — you reserve the name + configure trust in one
  step)
- Fill in:
  - **PyPI Project Name**: `ciris-persist`
  - **Owner**: `CIRISAI`
  - **Repository name**: `CIRISPersist`
  - **Workflow name**: `ci.yml`
  - **Environment name**: `pypi`

The "Pending Publisher" form publishes the trust policy *before*
the first upload. After the first successful upload, PyPI promotes
it to an active "trusted publisher" on the now-created project.

### 2. (Optional) Add a second publisher for releases from a
       protected ref pattern

If you want to restrict who can trigger publishes (e.g., only
release tags from main, not arbitrary tags from any branch), add a
second pending publisher with the same fields plus a tag-pattern
filter. Skip for v0.1.12; can add later.

### 3. Confirm the GitHub environment exists

GitHub Actions environments are created on demand — the first
workflow run that references `environment: pypi` creates it. Or
preemptively:

- https://github.com/CIRISAI/CIRISPersist/settings/environments
- "New environment" → name `pypi`
- (Optional) Add deployment protection rules (required reviewers,
  wait timer, branch/tag restrictions). Recommended:
  **"Required reviewers"** with the repo maintainer(s) — adds a
  manual approval step before each PyPI publish.

### 4. Push the tag

After steps 1-3, the next `git tag v0.1.12 && git push origin v0.1.12`
triggers `.github/workflows/ci.yml::publish-pypi`. The job:

1. Waits for `pyo3-wheel` + `build-manifest` to succeed.
2. Downloads the abi3 wheel artifact.
3. Sanity-checks shape (rejects non-`cp311-abi3` to prevent
   silent breakage on consumers).
4. Calls `pypa/gh-action-pypi-publish@release/v1` with
   `attestations: true` (PEP 740 sigstore attestation).
5. PyPI accepts the upload via OIDC trusted publishing.
6. `pip install ciris-persist==0.1.12` works within ~30 seconds of
   the workflow finishing.

---

## How this compounds with the BuildManifest signature

The persist build pipeline now has **three** layers of provenance:

| Layer | What it proves | Where it lives |
|---|---|---|
| Source-of-truth git tag | "This commit is what CIRISAI's repo says" | GitHub repo |
| BuildManifest hybrid signature (Ed25519 + ML-DSA-65) | "This binary was built from that commit by CIRISAI's signing key" | CIRISRegistry, fetchable via `GET /v1/verify/binary-manifest/<version>?project=ciris-persist` |
| PEP 740 attestation | "This PyPI artifact was uploaded by CIRISAI's GHA workflow running on that commit" | PyPI, fetchable via `pip install --attestations ...` (when consumers want to verify) |

A consumer pinning `pip install ciris-persist==0.1.12` gets:

- Fast install from PyPI's CDN.
- Optional attestation-verify (if they want defense-in-depth on the
  PyPI distribution channel).
- Cross-check via CIRISRegistry — the wheel's sha256 in PyPI must
  match `binaries["x86_64-unknown-linux-gnu"]` in the registered
  BuildManifest.

The cryptographic root remains the BuildManifest. PyPI is the fast
delivery channel; it's verifiable but not load-bearing on its own.

---

## Failure modes

- **First tag push after setup, publish fails with "trusted
  publisher not found".** PyPI's pending-publisher took longer
  than expected to propagate, or the workflow filename doesn't
  match. Check the values entered in step 1 against the actual
  workflow file `.github/workflows/ci.yml`. Re-run the failed job
  once trust propagates.

- **`skip-existing: true` swallowing a real failure.** If the wheel
  for the tagged version *already exists* on PyPI, the action
  skips silently. That's intentional for re-runs. To actually
  re-publish, bump to a fresh version.

- **Non-cp311-abi3 wheel.** Sanity check rejects it before publish.
  This is the v0.1.10 regression class — silently shipping a wrong
  shape would be worse than failing.

---

## Rotation

Trusted publisher config doesn't rotate — there's no key material
to expire. To revoke (e.g., if the workflow is compromised):

- PyPI project settings → "Trusted publishers" → remove the entry.
- Re-add with the corrected config.

PyPI keeps an audit log of publisher-config changes per project.
