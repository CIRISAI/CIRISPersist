-- V120 — admit the STEWARD-TIER suffix into
-- federation_communities.consensus_protocol
-- CIRISPersist#591
--
-- SQLITE PARITY: none, and that is a finding rather than an omission — see
-- "WHY THERE IS NO SQLITE TWIN" below. Read it before adding one.
--
-- WHAT AND WHY
-- ------------
-- V116 added the act-unless-objected form:
--
--     reverse_quorum:{m}/{n}:{window_secs}
--
-- and left one case undecided: what happens when the people carrying the
-- moderation duty simply do not answer. Today the outcome falls out of
-- whichever default the window resolves to — the brake stands indefinitely on
-- one member's word, or it lapses with nobody having judged it. Both are
-- decisions and neither was made by anybody. Non-response is the NORMAL failure
-- mode (moderator burnout is the fediverse's dominant cause of instance death),
-- and the adversarial case is a duty-holder unreachable precisely because the
-- objection concerns them.
--
-- V120 admits the optional steward tier:
--
--     reverse_quorum:{m}/{n}:{window}+escalate:{steward_secs}:{floor}
--       e.g. reverse_quorum:2/9:86400+escalate:172800:3
--
-- The appointed moderators get `steward_secs` after the objection window closes
-- to reach an upholding ruling. If they do not, the objection escalates to a
-- quorum of RESPONDENTS — counted from whoever actually answers, not from the
-- full roster, because m-of-n over a roster means the more members have gone
-- quiet the more impossible any decision becomes, which inverts exactly when it
-- is needed. `{floor}` is the cohort's own absolute floor on that respondent
-- count and may only ever be RAISED: the Rust parser refuses a string declaring
-- fewer than 3, and the fold clamps at 3 again at use. Without that floor
-- `strict_majority(1) == 1` and the escalated undo would be a 1-of-N capability
-- grant, which the repo's standing accord-ops invariant forbids outright.
--
-- A SUFFIX, not a new prefix. Every string written against V116 keeps parsing
-- to exactly what it meant — no steward tier, no deadline, no escalation — so
-- adopting the tier is a visible, deliberate edit to a cohort's own
-- declaration and no stored row changes meaning. Nothing is removed: all seven
-- existing forms remain admissible, identically.
--
-- WHY THERE IS NO SQLITE TWIN
-- ---------------------------
-- V116 closed this vocabulary in three places (Rust shape gate, this CHECK, and
-- its sqlite counterpart) and warns that all three move together. Two of the
-- three move here; the sqlite arm needs no edit, because V116 wrote it as
--
--     consensus_protocol GLOB 'reverse_quorum:*/*:*'
--
-- and GLOB's `*` spans BOTH `:` and `+`. Verified against the real engine
-- rather than argued from the shape:
--
--     sqlite3 :memory: "select
--       'reverse_quorum:2/9:3600+escalate:600:3' GLOB 'reverse_quorum:*/*:*';"
--     -> 1
--
-- That is V116's own documented design ("GLOB has no `[0-9]+`, so the sqlite
-- arm is the same shape check at coarser resolution"), and it is why the
-- STRICTNESS deliberately lives in one place on both backends:
-- `ReverseQuorumPolicy::parse`, the single parser the Rust shape gate and the
-- fold both run. The sqlite CHECK gates the SHAPE; the parser gates the
-- SEMANTICS (digits only, `0 < m <= n`, a window that reads as seconds, and now
-- a floor that cannot be declared below 3).
--
-- This matters because the alternative was expensive and wrong: sqlite bakes
-- table-level CHECKs into CREATE TABLE and has no DROP CONSTRAINT, so a sqlite
-- twin means REBUILDING federation_communities — a central table — with an
-- INSERT...SELECT that CI structurally cannot cover (every test database
-- migrates before any row exists, so the data path is never exercised). Taking
-- an irreversible rebuild of a live table on a premise that is false would be
-- the worst kind of migration. The sqlite backend witness puts a real community
-- carrying the new protocol string through `put_community`, so the claim above
-- is load-bearing-tested on every run rather than asserted in a comment.
--
-- THE REGEX
-- ---------
-- The suffix group is optional and every part is digit-only, so a malformed
-- steward window or floor can never reach a row and be silently read as "no
-- tier". `+` is written as the bracket expression `[+]` rather than `\+`: it is
-- unambiguous under POSIX AREs and immune to a future escape-processing change.
-- The semantic constraint a regex cannot express — floor >= 3 — lives in
-- `ReverseQuorumPolicy::parse`, which refuses the whole string LOUDLY rather
-- than clamping it silently, so a cohort learns its declaration is wrong
-- instead of quietly running a policy it did not write.
--
-- Dropped by DISCOVERY, not by name — the V114/V115/V116 lesson. A deployment
-- restored from a dump under a different constraint name would otherwise be
-- left silently enforcing the V116 form, making the steward tier a runtime
-- 23514 on exactly the deployments that took the trouble to rename things.
-- Matched on the COLUMN it constrains, which is stable.
--
-- The V060 GIN index on `members` is untouched: DROP CONSTRAINT does not affect
-- indexes. Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here.

DO $$
DECLARE
    conname_to_drop text;
BEGIN
    SELECT c.conname INTO conname_to_drop
    FROM pg_constraint c
    JOIN pg_class t     ON t.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = 'cirislens'
      AND t.relname = 'federation_communities'
      AND c.contype = 'c'
      AND c.conkey = ARRAY[
            (SELECT a.attnum FROM pg_attribute a
              WHERE a.attrelid = t.oid AND a.attname = 'consensus_protocol')
          ]::smallint[];

    IF conname_to_drop IS NOT NULL THEN
        EXECUTE format(
            'ALTER TABLE cirislens.federation_communities DROP CONSTRAINT %I',
            conname_to_drop);
    END IF;
END
$$;

ALTER TABLE cirislens.federation_communities
    ADD CONSTRAINT federation_communities_consensus_protocol_form
    CHECK (consensus_protocol ~ '^(founder_only|unanimous|majority|quorum:[0-9]+/[0-9]+|reverse_quorum:[0-9]+/[0-9]+:[0-9]+([+]escalate:[0-9]+:[0-9]+)?|weighted:.+|custom:.+)$');
