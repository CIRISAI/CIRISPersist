# Registry registration

Persist's build manifests are signed and registered with CIRISRegistry by CI on
every release tag. How it works, the secrets it needs, and how to verify and
rotate are in [BUILD_SIGNING.md](BUILD_SIGNING.md); the release-side checks
(the bits-changed gate, attestations, repairing a registered row) are in
[RELEASE.md](RELEASE.md).

Persist registers binary build manifests only. It does not produce
function-level manifests (`POST /v1/verify/function-manifest`), which are for
primitives that attest their own runtime functions, and it registers over HTTP,
not the registry's gRPC interface.

This file is kept because the retired manifest tool in `tools/legacy/` still
points here.
