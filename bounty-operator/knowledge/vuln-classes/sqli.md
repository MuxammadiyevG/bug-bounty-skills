# SQL Injection

> User input alters SQL structure. Reads/writes the whole database, often auth bypass or RCE. Rarer on modern stacks — pays big where it survives.

## Root cause
Query built by string concatenation instead of parameterized binding. The gap: an ORM escape-hatch (raw query, `ORDER BY`/column names can't be bound), a "safe" numeric field, a second-order value trusted on re-use, or a JSON/`LIKE`/`IN` clause assembled by hand.

## Where it hides
- Non-bindable positions: `ORDER BY {col}`, `LIMIT`, column/table names, `IN (...)` lists.
- Search/filter/sort params, report generators, export/CSV endpoints, legacy SOAP/XML APIs.
- Second-order: value stored then used unparameterized later (username in a later admin query).
- Headers used in queries: `User-Agent`, `X-Forwarded-For`, `Referer` (logging/analytics tables).
- ORM raw fragments: `.raw()`, `.extra()`, `$where`, string-built `whereRaw`.

## Detection
- Inject `'`, `"`, `)`, `--`, and observe: error, differential, or 500. Then confirm logic: `' AND 1=1--` vs `' AND 1=2--` (boolean differential).
- Time-based on blind: `';SELECT pg_sleep(5)--`, `' OR SLEEP(5)--`, `WAITFOR DELAY '0:0:5'` — measure delta.
- OOB (OAST) where output & timing are dead: `xp_dirtree`/`LOAD_FILE`/`UTL_HTTP`/`master..xp_cmdshell` DNS callback.
- `sqlmap` for confirmation/fingerprint after manual signal — never blind-fire destructive tamper on production.

## Minimum-evidence bar
A reliable **differential (boolean)** or **time** proof, or a benign extracted fact (`@@version`, `current_user`, one non-sensitive metadata row) via authorized, non-destructive probing. Mirror `../../references/validation-gate.md`: a 500 alone is not proof; prove injection then **stop** — never dump real user tables, never `DROP`/`UPDATE`.

## Depth ladder
1. Error-based: coerce the DB to leak data in an error message (`extractvalue`, `cast`, `convert`).
2. Boolean-blind: char-by-char via `SUBSTRING`+`ASCII` differentials.
3. Time-blind: same, gated on `SLEEP`/`pg_sleep`/`WAITFOR`.
4. UNION: match column count/types, pull `version()`, `current_database()`, one row of `information_schema`.
5. Stacked queries (where the driver allows `;`) — write path, `INTO OUTFILE`.
6. OOB exfil via DNS/HTTP for fully-blind.
7. Second-order: store payload, trigger the downstream query.
8. → RCE: `xp_cmdshell` (MSSQL), `sys_exec`/UDF (MySQL), `COPY ... PROGRAM` (Postgres), `LOAD_FILE`/`INTO OUTFILE` for file read/webshell.
See `../payloads/sqli.md`; NoSQL variants in `../payloads/nosqli.md`.

## Bypass notes
- Keyword filter: inline comments `UN/**/ION`, case, `%00`, double-encoding, `SEL%0bECT`.
- Quotes filtered → `CHAR()`/`0x` hex literals, no-quote numeric context.
- Space filtered → `/**/`, `%09`, `%0a`, parentheses.
- WAF: scientific-notation, `LIKE` instead of `=`, alternate functions (`PRINTF`, `MID` vs `SUBSTRING`). See `../bypass-tables.md`.

## Chain potential
SQLi → creds/hashes → ATO/admin. SQLi → `xp_cmdshell` → RCE. SQLi read of session table → session hijack. SQLi → SSRF/file-read via DB functions. See `../../references/chaining.md`.

## Real paid example
Real disclosed reports:
- **SQL Injection in report_xml.php through countryFilter[] parameter** (Valve, $25,000) — hackerone.com/reports/383127 — injection through an array/report filter param on a reporting endpoint.
- **Time-Based SQL injection at city-mobil.ru** (Mail.ru, $15,000) — hackerone.com/reports/868436 — blind, confirmed purely by time differential.
- **SQL injection at fleet.city-mobil.ru** (Mail.ru, $10,000) — hackerone.com/reports/881901 — injectable param on a secondary/fleet app surface.
- **SQL injection on contactws.contact-sys.com in TScenObject action ScenObjects leads to remote code execution** (QIWI, bounty undisclosed) — hackerone.com/reports/816254 — SQLi escalated to RCE via DB primitives.

**The recurring tell:** biggest payouts come from filter/report/sort params and legacy secondary apps, proven by boolean/time differential; escalation to RCE (QIWI) or a full DB read multiplies the reward.

## Rejected variants
- A 500/stack trace with no confirmed injection (that's an error-disclosure at best).
- WAF-blocked payloads reported as "SQLi attempt".
- Time delay from network jitter, not reproduced with a controlled differential.
- Dumping real customer data — that's over-collection, not a better report.
