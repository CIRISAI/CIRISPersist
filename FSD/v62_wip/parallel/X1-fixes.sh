#!/usr/bin/env bash
# X1's fixes on top of integrate.sh's tree. No cargo. Usage: fixes.sh <worktree>
set -u
cd "$1" || exit 1
# F1: examples/mint_test_ceremony.rs imports the deleted genesis::mint_test_ceremony (C5).
if [ -f examples/mint_test_ceremony.rs ]; then
  git rm -q examples/mint_test_ceremony.rs
  python3 - <<'EOF'
p='Cargo.toml'; s=open(p).read()
blk='''# CIRISPersist#973 — the software ceremony minter (dry run), test-anchor-gated:
# `cargo run --example mint_test_ceremony --features test-anchor -- <out_dir> <seed>×3 <node_seed>`.
[[example]]
name = "mint_test_ceremony"
required-features = ["test-anchor"]

'''
assert s.count(blk)==1; open(p,'w').write(s.replace(blk,''))
EOF
fi
# F2: C4's evidence rows citing symbols C1/C3 deleted.
python3 - src/federation/namespace/namespace_supersets.json <<'EOF'
import sys
p=sys.argv[1]; s=open(p).read()
R=[('src/federation/edition2/halt.rs#read_invocation','src/federation/edition2/halt.rs#refusal_error'),
('src/federation/edition2/genesis.rs#verify_bundle','src/federation/edition2/genesis.rs#read_lineage'),
('src/federation/edition2/genesis.rs#BundleInForce::is_canonical','src/federation/edition2/genesis.rs#GenesisInForce::is_canonical'),
('src/federation/edition2/genesis.rs#seat_xwing_from_binding','src/federation/edition2/genesis.rs#GenesisInForce::seat')]
for a,b in R:
    if '"'+a+'"' in s: s=s.replace('"'+a+'"','"'+b+'"'); print('repointed',a,'->',b)
open(p,'w').write(s)
EOF
# F4: D1/D2 match T1's StatementOutcome::Pending, which is not in lane 1.
# Remove those arms only while T1 is absent (no `Pending {` in ingest.rs's StatementOutcome).
if ! awk '/pub enum StatementOutcome/,/^}/' src/federation/edition2/ingest.rs | grep -q 'Pending'; then
python3 - <<'EOF'
R=[('src/ffi/directory_capsule.rs','''            S::Pending { row_id, new } => Self::Pending {
                row_id: row_id.0,
                new,
            },
'''),('src/server/edition2.rs','''        StatementOutcome::Pending { row_id, .. } => ("pending", row_id),
'''),('src/server/edition2.rs','''        | StatementOutcome::Row { new, .. }
        | StatementOutcome::Pending { new, .. } => *new,''','''        | StatementOutcome::Row { new, .. } => *new,'''),
('src/ffi/pyo3.rs','''        StatementOutcome::Pending { row_id, new } => ("pending", row_id, *new),
''')]
for r in R:
    p,a=r[0],r[1]; b=r[2] if len(r)>2 else ''
    s=open(p).read(); assert s.count(a)==1,(p,a); open(p,'w').write(s.replace(a,b)); print('F4',p)
EOF
git add -A
fi
# F3: regenerate the generated projections over the combined tree.
python3 scripts/evidence_tsv.py write && python3 scripts/evidence_tsv.py check
python3 scripts/evidence_pointers.py check | tail -1
python3 scripts/pyi_surface.py surface | head -1 && python3 scripts/pyi_surface.py check >/dev/null && echo "pyi check OK"
python3 scripts/gen_directory_double.py --check
git add -A
