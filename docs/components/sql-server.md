# Microsoft SQL Server 2016

19 rules, `100400-100418`. Rule file:
[`rules/sqlserver/local_rules.xml`](../../rules/sqlserver/local_rules.xml)

A database server holds the data an attacker is usually after, so detection here
is about the last step of an intrusion rather than the first. The signals that
matter are authentication, privilege change, and anything touching the audit
configuration itself.

## Telemetry

| Source | Carries |
| ------ | ------- |
| `ERRORLOG` | Logon success and failure, severity 16+ errors |
| SQL Server Audit | Role and permission changes, DDL, principal changes |
| Windows Security channel | 4624, 4625, 4672, 1102 |
| `SQLAGENT.OUT` | Job activity and failures |

Configuration:
[`agent-config/sqlserver-ossec.conf`](../../agent-config/sqlserver-ossec.conf)

**The audit specifications are not optional.** The ERRORLOG alone carries logon
events but records nothing about a role membership change, a permission grant or
a DDL operation. Without
[`setup/sqlserver-audit.sql`](../../setup/sqlserver-audit.sql) applied first,
roughly half of these rules can never fire. The audit groups map to rules as
follows:

| Audit action group | Rules |
| ------------------ | ----- |
| `FAILED_LOGIN_GROUP` | `100401`, `100402`, `100403` |
| `SUCCESSFUL_LOGIN_GROUP` | `100404`, `100405` |
| `SERVER_ROLE_MEMBER_CHANGE_GROUP` | `100406` |
| `SERVER_PERMISSION_CHANGE_GROUP` | `100407` |
| `AUDIT_CHANGE_GROUP` | `100410` |
| `DATABASE_OBJECT_PERMISSION_CHANGE_GROUP` | `100408` |
| `DATABASE_PRINCIPAL_CHANGE_GROUP` | `100409` |
| `DATABASE_OBJECT_CHANGE_GROUP`, `SCHEMA_OBJECT_CHANGE_GROUP` | `100411` |
| `SCHEMA_OBJECT_ACCESS_GROUP` | `100412`, `100413` |

## Threat analysis

| Threat | Observable indicator | Source |
| ------ | -------------------- | ------ |
| Credential brute force | Repeated 18456 from one address or against one login | `ERRORLOG` |
| Password spraying | 18456 across many logins | `ERRORLOG` |
| Built-in SA account use | 18454 where the login is `sa` | `ERRORLOG` |
| Privilege escalation | Server role and permission changes | SQL Server Audit |
| Account creation | Database principal change | SQL Server Audit |
| OS command execution | `xp_cmdshell` in a stored procedure call | SQL Server Audit |
| Data destruction | DDL on database objects | SQL Server Audit |
| Anti-forensics | Audit configuration change, security log cleared | Audit, Security channel |

The `sa` account gets its own rule at level 12 because it is the one login whose
use is almost always worth a question. It is the built-in sysadmin, it is the
first name in every credential list, and in a well-run instance nobody signs in
with it day to day.

## Rules

Full table in the [rule index](../rule-index.md). Structure:

**One base rule, many children.** `100400` matches any event whose
`win.system.providerName` is `MSSQLSERVER`, sits at level 0 with
`<options>no_log</options>`, and exists so that the field matching in its 11
children only runs against events already known to be SQL Server's. It chains
onto native `60009`.

**Two brute force variants from the same parent.** Both chain off `100401`
(logon failure, 18456) with a 5-in-120s threshold, differing only in what they
group by:

| Rule | Groups by | Detects |
| ---- | --------- | ------- |
| `100402` | `same_srcip` | One source attacking, classic brute force |
| `100403` | login name | One account attacked from anywhere, spraying or distributed guessing |

Writing both matters because they catch opposite shapes of the same attack, and
either alone leaves a blind spot.

**Escalating pairs.** `100404` (successful logon, level 3) is the parent of
`100405` (that logon was `sa`, level 12). `100412` (stored procedure executed,
level 5) is the parent of `100413` (`xp_cmdshell`, level 14). In both cases the
parent is routine and the child is not.

`100413` is the highest-severity rule in this component. `xp_cmdshell` runs
operating system commands from inside the database engine, so it turns a
database compromise into a host compromise. It is disabled by default in SQL
Server, which makes its use a strong signal.

## Locale handling

The instance this was built against was French-language, and SQL Server writes
audit action group names in the installed language. Three rules therefore match
either form:

```xml
<match>SERVER_ROLE_MEMBER_CHANGE_GROUP|GROUPE_MODIFICATION_MEMBRE</match>
```

`100406`, `100407` and `100410` all do this, so the same rule file works on an
English or a French instance without editing. Anyone deploying on a third
locale will need to add that locale's strings.

## Scope

- **No detection of data exfiltration by query.** A large `SELECT` reading an
  entire table looks identical to a legitimate report. Catching that needs row
  count or volume analysis the audit log does not provide.
- **Stored procedure auditing is deliberately narrow.** `100412` sits at level
  5 and exists mainly to parent `100413`. Auditing every procedure execution on
  a busy OLTP instance produces more volume than it is worth, so the detection
  is scoped to the calls that matter.
