# tools/legacy/

One-release transition fallback. The contents here are deprecated and
will be deleted in v0.2.0.

## `ciris_manifest.py`

Vendored manifest generator from the v0.1.3-v0.1.8 era. Replaced in
v0.1.9 by upstream `ciris-build-sign` (CIRISVerify v1.8.0), which
ships:

- A canonical `BuildManifest` shape shared across PoB primitives.
- Hybrid Ed25519 + ML-DSA-65 signing.
- `BuildPrimitive::Persist` as a first-class discriminator (no
  more `--project=ciris-persist` workarounds).
- Typed extras via `register_extras_validator(Box<PersistExtrasValidator>)`.

The CI workflow (`.github/workflows/ci.yml::build-manifest`) no
longer invokes this script. Local one-off manifest experiments can
still use it during the transition; new tooling should target
`ciris-build-sign` directly.

See:
- `docs/BUILD_SIGNING.md` — how operators upload Ed25519 + ML-DSA-65
  secrets and run the CLI.
- `src/manifest/mod.rs` — typed `PersistExtras` + `PersistExtrasValidator`
  registered globally for verify-side dispatch.
- `src/bin/emit_persist_extras.rs` — CI helper that emits the
  primitive-specific extras JSON before invoking `ciris-build-sign`.
