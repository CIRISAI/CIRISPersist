# The CSD/4 topology catalogue, pinned to a CIRISServer release

Source: the TAGGED CIRISServer release `v0.5.234` (published 2026-10-23), its
`csd4-*` release assets, each checked against the release's `SHA256SUMS`
asset before it was copied. The assets' cosign signatures (`*.sig`, `*.pem`)
were not checked: `cosign` is not on PATH here.

| pin | value |
|---|---|
| repo | `CIRISAI/CIRISServer` |
| release tag | `v0.5.234` |
| checksum file | `SHA256SUMS` (sha256 `732af6b866c38ef786b783778578bcde0b5caed935211b92d13b3a272e6e5c91`) |
| catalogue_version | `5` |
| vocabulary owner | `CIRISAI/CIRISConstitution` @ `9f6ff75a7b3c7e2bc8be0d699fe9ee4f4f749f7b` (`manifests/topology_vocabulary.json`, sha256 `871c5dfa…`, byte-identical to CC `v1.0-rc12`'s vocabulary, catalogue v5) |

## Files

| file here | release asset | sha256 (equal to the release's `SHA256SUMS` line) |
|---|---|---|
| `requirements.yaml` | `csd4-requirements.yaml` | `aa38a8c57fbfb41e08c2b75a787ed29eba8ad3f253849986c24010a0f74ac224` |
| `topology_vocabulary.pin` | `csd4-topology_vocabulary.pin` | `39668f46fb87bec4540b2c507c3f89d4e946f300ee8eaf08b4a34a17500e71bb` |
| `traces.json` | `csd4-traces.json` | `c2df891bd3cd57c62daf3618d87b99404bb635b672a5bca4129baad97ac478ee` |

The fourth asset, `csd4-topology_vocabulary.json` (sha256 `871c5dfa…`), is not
copied here: the vocabulary is the Constitution's, vendored at the CC tag in
`src/federation/namespace/topology_vocabulary.json`. The release asset is
byte-identical to CC `v1.0-rc12`'s vocabulary. Persist now vendors `v1.0-rc15`,
whose vocabulary is v6 (`c37f6f96…`), and no tagged CIRISServer release carries
a CSD/4 v6 catalogue yet, so these fixtures stay at `v0.5.234`. I1301
(`namespace::cc_manifests`) asserts that `topology_vocabulary.pin` names the
PREVIOUS vocabulary (`871c5dfa…`) and not the vendored one; it goes red when
the fixtures are re-pinned from a release built on v6.

## Refetch

```
gh release download <tag> -R CIRISAI/CIRISServer -p 'csd4-*' -p SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

Copy the three files above under their names here, move every sha and the tag
in this file, and run `python3 scripts/csd4_coverage.py`. Re-pin only from a
tagged release.
