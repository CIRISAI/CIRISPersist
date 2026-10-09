-- V188 (CIRISPersist#1047) — the server-issued accord nonce set is retired.
-- SQLite dialect. Postgres parity: postgres/lens/V188.
--
-- V091 kept `accord_issued_nonce` for M4: an `accord_proposal` was admitted
-- only if a server had issued its nonce first. CIRISConstitution#146 and
-- verify 20 make the nonce the PROPOSER's ("a server is part of what a halt
-- may need to stop, and no accord act depends on one", CC 4.2.6). Persist
-- no longer reads or writes the set; single use is checked against
-- `accord_proposal` itself (a nonce names one proposal per family).
DROP TABLE IF EXISTS accord_issued_nonce;
