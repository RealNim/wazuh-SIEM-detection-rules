# Oracle Database

19 rules and 6 decoders, `100500-100518`. Files:
[`rules/oracle/local_rules.xml`](../../rules/oracle/local_rules.xml),
[`rules/oracle/local_decoder.xml`](../../rules/oracle/local_decoder.xml)

Oracle was the only component where I had to write decoders before any rule
was possible, which made it the most instructive of the four.

## Why decoders came first

Oracle writes three log formats, none of which any native Wazuh decoder parses:

- the **alert log**, free text carrying `ORA-NNNNN` error codes and instance
  lifecycle messages
- **OS-mode audit files**, a labelled block format with lines like
  `ACTION :[7] 'CONNECT'` and `DATABASE USER:[1] '/'`
- the **TNS listener log**, its own format with `TNS-NNNNN` codes and
  `* establish *` connection records

Until a decoder matches, a rule cannot reference a field, so there is nothing to
write a rule against. Six decoders solve it:

| Decoder | Role |
| ------- | ---- |
| `oracle-alert` | Parent, prematches `ORA-\d+`, instance start and shutdown |
| `oracle-alert-errcode` | Child, extracts the code into `oracle.error_code` |
| `oracle-audit` | Parent, prematches `ACTION :`, `DATABASE USER:`, `PRIVILEGE :` |
| `oracle-audit-action` | Child, extracts `oracle.action` |
| `oracle-audit-dbuser` | Child, extracts `oracle.db_user` |
| `oracle-listener` | Parent, prematches `TNS-\d+`, `* establish *`, `* CONNECT_DATA` |

The parent and child split is what lets one prematch identify the log family
cheaply and the children do the field extraction only on records that already
matched. The three rule families then chain onto the three parents, which is why
the rule file has three base rules at level 0 (`100500`, `100505`, `100513`)
rather than one.

If an Oracle rule is not firing, check the decoder first with
`/var/ossec/bin/wazuh-logtest -v`. If no decoder matches, the rules are not the
problem.

## Telemetry

| Source | Path pattern | Carries |
| ------ | ------------ | ------- |
| Alert log | `.../diag/rdbms/[DB_NAME]/[SID]/trace/alert_[SID].log` | ORA errors, instance lifecycle |
| Audit files | `.../admin/[SID]/adump/*.aud` | Logons, privilege use, DDL, GRANT |
| Listener log | `.../diag/tnslsnr/[hostname]/listener/trace/listener.log` | TNS errors, connection attempts |

Configuration:
[`agent-config/oracle-ossec.conf`](../../agent-config/oracle-ossec.conf).
Confirm the real paths with
`SELECT value FROM v$diag_info WHERE name = 'Diag Trace';` and
`SHOW PARAMETER audit_file_dest;`

**Audit must go to OS files, not to the database.** Oracle's default
`audit_trail` writes to `SYS.AUD$`, a table, and a Wazuh agent reads files. With
the default in place the `adump` directory stays empty and every audit-based rule
is dead. [`setup/oracle-audit.sql`](../../setup/oracle-audit.sql) sets
`audit_trail = 'OS'`, which is a static parameter and so requires an instance
restart.

## Threat analysis

| Threat | Observable indicator | Source |
| ------ | -------------------- | ------ |
| Credential brute force | Repeated `ORA-01017` | Alert log |
| Default account use | Logon as `SCOTT`, `DBSNMP`, `OUTLN`, `CTXSYS`, `MDSYS`, `ORDSYS` | Audit |
| Privileged logon | `SYSDBA`, `SYSOPER` | Audit |
| Privilege escalation | `GRANT`, `REVOKE` | Audit |
| Code execution | `UTL_FILE`, `UTL_HTTP`, `UTL_TCP`, `DBMS_JAVA`, `DBMS_SCHEDULER` | Audit |
| OS command execution | `EXTERNAL_SCRIPT`, `DBMS_JAVA.RUNJAVA`, `java.lang.Runtime`, `host command` | Audit |
| Data exfiltration | `expdp`, `impdp`, Data Pump activity | Audit |
| Anti-forensics | `NOAUDIT`, audit trail cleanup, `DBMS_AUDIT_MGMT.CLEAN_AUDIT_TRAIL` | Audit |
| Listener attack | Repeated `TNS-12541`, `TNS-12514`, admin commands | Listener log |
| Availability | Instance startup and shutdown | Alert log |

Default accounts get their own rule because they ship with known passwords and
nobody should be using them. `SCOTT` in particular is a sample schema; a logon
as `SCOTT` on a real instance means either the sample data was never removed or
someone is working through a default credential list.

The dangerous-package rule is the Oracle equivalent of `xp_cmdshell`. `UTL_TCP`
and `UTL_HTTP` let the database open outbound network connections, `DBMS_JAVA`
and `EXTERNAL_SCRIPT` reach the operating system, and `DBMS_SCHEDULER` can run
OS commands on a timer. Each is a documented feature and each is also a route
out of the database.

## Rules

Full table in the [rule index](../rule-index.md). Three families, one per log
source:

| Base rule | Log source | Children |
| --------- | ---------- | -------- |
| `100500` level 0 | Alert log | `100501` to `100504` |
| `100505` level 0 | Audit files | `100506` to `100512`, `100517`, `100518` |
| `100513` level 0 | Listener log | `100514` to `100516` |

Severity peaks at 14 twice, for the two events that mean the situation has
already gone badly:

| Rule | Level | Why |
| ---- | ----- | --- |
| `100511` | 14 | OS command execution from inside the database |
| `100518` | 14 | Audit trail erased, so the rest of the timeline is suspect |

`100516` at level 12 is worth noting as well. It fires on administrative
commands against the listener, which is exactly what
`lsnrctl set admin_restrictions on` is meant to prevent. Hardening the listener
and detecting attempts to reconfigure it are two halves of the same control.

## Scope and next steps

- **Unified auditing is not used.** The configuration uses statement-level
  `AUDIT` because it works on both 11g and 12c. On 12c and later,
  `CREATE AUDIT POLICY` is the supported mechanism and gives finer control.
- **Data Pump detection is broad.** `100517` matches `expdp`, `impdp`,
  `Data Pump` and `DATAPUMP`, so a scheduled nightly export raises a level 8
  alert too. Suppressing the known backup window, or adding a volume threshold,
  is the refinement this one wants.
- **No row-level or volume awareness.** A query reading an entire table looks
  the same as a report. The audit log records that a statement ran, not how much
  it returned.
- **`100503` is pitched high on purpose.** `ORA-00600`, `ORA-07445` and
  `ORA-04031` are internal errors that can indicate exploitation but more often
  indicate a bug or memory pressure. It sits at level 10 so an analyst sees it,
  which means it needs correlating with other signals rather than acting on
  alone.
