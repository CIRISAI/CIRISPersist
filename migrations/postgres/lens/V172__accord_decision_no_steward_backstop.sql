-- V172 (v53.0.0, CC 4.2.6 rc7, CIRISConstitution#139) — the regional-steward
-- backstop is removed, so an accord decision carries no steward signatures.
--
-- Through rc7 CC 4.2.6 required a 2-of-3 quorum of regional stewards
-- (us/eu/apac) to co-sign a roster change when the live set was small or a
-- minority (H6), and gave that body restore (H7) and contest powers. The role
-- no longer exists: a roster change now needs yes-votes from a strict majority
-- of the STANDING roster within W, with no second body. `steward_signatures`
-- held the H6 co-signatures; nothing writes or reads it from v53.
ALTER TABLE cirislens.accord_decision DROP COLUMN IF EXISTS steward_signatures;
