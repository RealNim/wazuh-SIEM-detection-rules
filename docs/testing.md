# Test campaign and results

I validated every rule by performing the activity it targets against the lab
environment and confirming the expected alert appeared at the expected level.
Attack traffic came from a dedicated workstation inside the lab, so it arrived
through the same collection path as any other event.

Validation ran in the lab mirror first, then again against the production
hosts once the agents were enrolled there. Thresholds were retuned on live
traffic, since a lab gives you no false positive rate.

`[TARGET]`, `[HOST]` and `[SID]` are placeholders throughout. No real address,
host name or instance name appears in this repository.

## Nginx

Generated with `curl` against the lab web server.

```bash
# SQL injection, URL-encoded UNION SELECT
curl "http://[TARGET]/?id=1%20UNION%20SELECT%201"

# Boolean-based injection
curl "http://[TARGET]/?id=1 OR 1=1"

# XSS, URL-encoded script tag
curl "http://[TARGET]/?q=%3Cscript%3Ealert(1)%3C/script%3E"

# Repeated XSS, to cross the correlation threshold for 100308
for i in $(seq 1 5); do curl "http://[TARGET]/?q=<script>alert($i)</script>"; done

# Sensitive path and traversal
curl "http://[TARGET]/.env"
curl "http://[TARGET]/../../etc/passwd"
```

| Scenario | Rules fired | Levels | Result |
| -------- | ----------- | ------ | ------ |
| Access to `.env` | `100300` then `100301` | 1 then 10 | Detected |
| SQL injection, `UNION SELECT` | `100303` | 13 | Detected |
| Boolean injection, `OR 1=1` | `100303` | 13 | Detected |
| Repeated XSS | `100307` then `100308` | 13 then 15 | Detected |
| Traversal to `/etc/passwd` | `100304` | 13 | Detected |
| Automated scanning | `100305` then `100306` | 3 then 12 | Detected |

The two-stage cases are the interesting ones. A single `.env` request produced a
level 1 event that wrote no alert. The fifth request inside two minutes produced
one level 10 alert rather than five separate level 1 events, which is the
behaviour the correlation was written for.

## SQL Server 2016

```sql
-- Login creation, triggers the database principal change audit
CREATE LOGIN test_user WITH PASSWORD = '[REDACTED]';

-- Read query
SELECT * FROM sys.databases;

-- Deliberate error, non-existent table
SELECT * FROM table_inexistante;
```

For the brute force case I connected repeatedly with a wrong password until the
18456 threshold was crossed.

| Scenario | Rules fired | Levels | Result |
| -------- | ----------- | ------ | ------ |
| Repeated logon failures (18456) | `100401` then `100402` | 5 then 10 | Detected |
| Logon with the built-in SA account | `100405` | 12 | Detected |
| Login creation | `100409` | 10 | Detected |
| DDL operation, CREATE then DROP | `100411` | 8 | Detected |
| `xp_cmdshell` execution | `100413` | 14 | Detected |
| Security log cleared (1102) | `100417` | 14 | Detected |

## Oracle Database

```bash
# Authentication failure, ORA-01017
sqlplus wrong_user/wrong_password@[HOST]/[SID]

# Brute force, crosses the threshold for 100502
for i in $(seq 1 6); do sqlplus wrong_user/wrong_password@[HOST]/[SID]; done

# Bulk export, Data Pump
expdp [USER]/[PASSWORD]@[SID] schemas=TEST directory=DATA_PUMP_DIR dumpfile=test.dmp
```

```sql
-- DDL and privilege changes
CREATE TABLE test_wazuh (id NUMBER);
DROP TABLE test_wazuh;
GRANT DBA TO test_user;
```

| Scenario | Rules fired | Levels | Result |
| -------- | ----------- | ------ | ------ |
| Authentication failure (ORA-01017) | `100501` | 5 | Detected |
| Brute force, 6 attempts | `100502` | 10 | Detected |
| SYSDBA logon | `100506` | 8 | Detected |
| DDL operation, CREATE then DROP | `100508` | 6 | Detected |
| Privilege change, GRANT | `100509` | 10 | Detected |
| Data Pump export | `100517` | 8 | Detected |

## Active Directory

Run from the lab attack workstation against the domain controller.

| Scenario | Rules fired | Levels | Result |
| -------- | ----------- | ------ | ------ |
| Brute force, repeated 4625 | `100600` then `100601` | 5 then 10 | Detected |
| Password spraying | `100602` | 10 | Detected |
| Kerberoasting, RC4 service ticket request | `100606` | 12 | Detected |
| DCSync, directory replication | `100609` | 12 | Detected |
| Addition to Domain Admins | `100614` then `100615` | 8 then 13 | Detected |
| Security log cleared (1102) | `100617` | 14 | Detected |

Clearing the security log is the one scenario worth running last, since it
destroys the evidence of everything before it. In the lab that is the point:
the alert fires on the clearing itself, and the events leading up to it survive
in `wazuh-archives-*` because archiving is enabled on the manager.

## Reproducing the tests

The commands above are the ones I used. They are simple and non-destructive,
and several are indistinguishable from a careless administrator, which is part
of the point: these rules detect behaviour, not tools.

Do not run any of this against infrastructure you do not own and have
permission to test.

To check a rule without generating live traffic, paste a sample log line into
`/var/ossec/bin/wazuh-logtest -v`, which reports the decoder and rule that
matched and the level raised. That is the faster way to confirm a rule after
editing it, and the only safe way to check one against production hosts.
