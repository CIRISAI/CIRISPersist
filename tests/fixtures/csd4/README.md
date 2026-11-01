# The CSD/4 topology catalogue and CC's chain, vendored for `scripts/csd4_coverage.py`

CIRISServer's CSD/4 catalogue (the requirements, the catalogue's vocabulary
pin and the model's traces), the key persist's testing, QA and mutation
scopes join to (docs/V60_TASK_PLAN.md §3b). TEST/REPORT fixtures: no CC tag
carries the catalogue.

- Source: the TAGGED CIRISServer release `v0.5.234`, its `csd4-*` assets,
  checked against the release's `SHA256SUMS`. `PIN.md` names the tag, the
  assets and the checksum file. CIRISServer is the catalogue's owner; an
  earlier copy came through CIRISClient's `packaging/csd4/`, which is
  downstream of the release and is not the source.
- The two CC files are runtime manifests at the vendored CIRISConstitution
  tag, beside the namespace registry in `src/federation/namespace/`, pinned
  in `src/federation/namespace/cc_manifests.rs` and compared with the tag by
  `scripts/check_vendored_cc.sh <tag>`. `topology_vocabulary.pin` stays
  here: it is the catalogue's pin. It names CC `v1.0-rc12`'s vocabulary
  (`871c5dfa…`), not the rc14 one persist vendors, pending a tagged Server
  release carrying CSD/4 v6; I1301 latches that.
- Do not hand-edit. To refresh, follow `PIN.md`'s Refetch, then re-run
  `python3 scripts/csd4_coverage.py --out docs/CSD4_COVERAGE_v<NN>.md`.

sha256 (as copied):

```
5b17aad37845c1aafcdf5fbd86c735321efcbe4301ffcf7efa681160e83bb68d  PIN.md
aa38a8c57fbfb41e08c2b75a787ed29eba8ad3f253849986c24010a0f74ac224  requirements.yaml
39668f46fb87bec4540b2c507c3f89d4e946f300ee8eaf08b4a34a17500e71bb  topology_vocabulary.pin
c2df891bd3cd57c62daf3618d87b99404bb635b672a5bca4129baad97ac478ee  traces.json
```

## `csd4_chain.json` (CIRISConstitution, the chain as data; now `src/federation/namespace/csd4_chain.json`)

CC's `manifests/csd4_chain.json`: per atom its STATE_TABLE rows with the
model transition that enters them, the invariants over those variables with
their claim ids, the claims realised (`join`: `by_invariant` | `by_section`),
each claim's evidence pointers parsed by repo, and the catalogue entries that
promise it; `refusal_tokens` (the tokens the text names, by section, with
`bold` | `after_refusal` confidence); `_meta` (input pins, `not_here`).
`scripts/csd4_coverage.py` reads the join from it instead of matching
`cc_ref` prefixes against `claims.tsv`.

- Source: CIRISConstitution tag `v1.0-rc14` (commit
  `b4da5272413c6b056baa597e537d4aabdcee6902`), copied with `git show
  v1.0-rc14:manifests/csd4_chain.json`.
- `_meta.pins.vocabulary_sha256` equals the vendored
  `topology_vocabulary.json` (`c37f6f96…`, catalogue v6; the script checks it);
  `_meta.pins.evidence_pins.CIRISPersist` is `ee30310f`, so persist rows added
  after that commit are unreached by construction until CC re-pins.
- Do not hand-edit. To refresh, re-vendor at the CC tag (`cc_manifests.rs`).

```
e13510748b6d613c1acd2920f20edab535afd475c917c775fd2bcd682ae8634b  csd4_chain.json
```
