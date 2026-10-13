# Rule index

68 custom detection rules across four components, plus 6 Oracle decoders.

Rule IDs, levels, correlation windows and MITRE mappings in the tables below are read directly from the XML, so they cannot drift from the rules. The `Detects` column is an English reading of each rule; the deployed `<description>` fields are in French, because the platform was built for a French-speaking operations team.

Levels follow the Wazuh 0 to 16 scale. Level 0 means the rule is a base or suppression rule and raises no alert of its own.

### Nginx

Allocated range `100300-100399`, 10 rules, 0 carrying an explicit `<mitre>` block.

| Rule | Level | Severity | Correlation | MITRE | Detects |
| ---- | ----- | -------- | ----------- | ----- | ------- |
| `100300` | 1 | informational |  |  | Access to a sensitive path (base rule) |
| `100301` | 10 | medium | 5 in 120s |  | Repeated access to sensitive paths from the same IP |
| `100302` | 12 | high |  |  | Probable brute force against an authentication endpoint |
| `100303` | 13 | high |  |  | Confirmed SQL injection (HTTP 200 response) |
| `100304` | 13 | high |  |  | System file access or path traversal attempt (HTTP 200 response) |
| `100305` | 3 | informational |  |  | Scanning tool detected (base rule) |
| `100306` | 12 | high | 3 in 60s |  | Confirmed automated scanning activity |
| `100307` | 13 | high |  |  | XSS payload detected (base rule) |
| `100308` | 15 | critical | 3 in 120s |  | Repeated XSS attack attempts |
| `100309` | 12 | high |  |  | Probable webshell access or command execution |

### SQL Server 2016

Allocated range `100400-100499`, 19 rules, 13 carrying an explicit `<mitre>` block.

| Rule | Level | Severity | Correlation | MITRE | Detects |
| ---- | ----- | -------- | ----------- | ----- | ------- |
| `100400` | 0 | suppressed / base |  |  | SQL Server event detected (base rule) |
| `100401` | 5 | low |  | `T1110` | Logon failure |
| `100402` | 10 | medium | 5 in 120s | `T1110.001` | Brute force (5+ failures in 2 min from the same IP) |
| `100403` | 10 | medium | 5 in 120s | `T1110.001` | Brute force by user name (5+ failures in 2 min) |
| `100404` | 3 | informational |  |  | Successful logon |
| `100405` | 12 | high |  | `T1078.002` | Logon using the built-in SA account |
| `100406` | 10 | medium |  | `T1078.002` | Server role membership changed |
| `100407` | 10 | medium |  | `T1078.002` | Server permissions changed |
| `100408` | 10 | medium |  | `T1078.002` | Database permissions changed |
| `100409` | 10 | medium |  | `T1136` | Database user or role changed |
| `100410` | 12 | high |  | `T1562.002` | Audit configuration changed |
| `100411` | 8 | medium |  | `T1485` | Database object changed (DDL) |
| `100412` | 5 | low |  |  | Stored procedure executed |
| `100413` | 14 | critical |  | `T1059.003` | xp_cmdshell executed, OS command execution possible |
| `100414` | 8 | medium |  |  | High severity error in ERRORLOG |
| `100415` | 6 | low |  |  | SQL Server Agent job activity |
| `100416` | 10 | medium |  |  | SQL Server Agent job failure, check for tampering |
| `100417` | 14 | critical |  | `T1070.001` | Windows security log cleared, possible anti-forensics |
| `100418` | 8 | medium |  | `T1078.002` | Privileged logon on the SQL Server host |

### Oracle Database

Allocated range `100500-100599`, 19 rules, 15 carrying an explicit `<mitre>` block.

| Rule | Level | Severity | Correlation | MITRE | Detects |
| ---- | ----- | -------- | ----------- | ----- | ------- |
| `100500` | 0 | suppressed / base |  |  | Oracle alert log event detected (base rule) |
| `100501` | 5 | low |  | `T1110` | Authentication failure (ORA-01017) |
| `100502` | 10 | medium | 5 in 120s | `T1110.001` | Brute force (5+ failures in 2 min from the same IP) |
| `100503` | 10 | medium |  |  | Critical internal error, possible corruption or exploitation attempt |
| `100504` | 8 | medium |  | `T1529` | Instance startup or shutdown detected |
| `100505` | 0 | suppressed / base |  |  | Audit record detected (base rule) |
| `100506` | 8 | medium |  | `T1078.002` | Logon with SYSDBA or SYSOPER privileges |
| `100507` | 10 | medium |  | `T1078.001` | Logon using a default Oracle account |
| `100508` | 6 | low |  | `T1485` | DDL operation on a database object |
| `100509` | 10 | medium |  | `T1078` | Privilege change (GRANT or REVOKE) |
| `100510` | 12 | high |  | `T1059` | Potentially dangerous package or procedure used |
| `100511` | 14 | critical |  | `T1059.004` | OS command executed from Oracle, probable compromise |
| `100512` | 12 | high |  | `T1562.002` | Audit configuration changed or disabled |
| `100513` | 0 | suppressed / base |  |  | TNS listener event detected (base rule) |
| `100514` | 5 | low |  | `T1110` | TNS listener connection failure |
| `100515` | 10 | medium | 5 in 120s | `T1110.001` | Brute force against the TNS listener (5+ failures in 2 min) |
| `100516` | 12 | high |  | `T1562.001` | Sensitive administrative command run against the listener |
| `100517` | 8 | medium |  | `T1048.003` | Bulk data export or import detected (Data Pump) |
| `100518` | 14 | critical |  | `T1070` | Audit trail erased, possible anti-forensics |

### Active Directory

Allocated range `100600-100699`, 20 rules, 15 carrying an explicit `<mitre>` block.

| Rule | Level | Severity | Correlation | MITRE | Detects |
| ---- | ----- | -------- | ----------- | ----- | ------- |
| `100600` | 5 | low |  | `T1110` | Windows logon failure |
| `100601` | 10 | medium | 8 in 120s | `T1110.001` | Brute force (8+ failures in 2 min from the same source) |
| `100602` | 10 | medium | 8 in 300s | `T1110.003` | Password spraying (same target account) |
| `100603` | 5 | low |  | `T1110` | Kerberos pre-authentication failure |
| `100604` | 10 | medium | 8 in 120s | `T1110.001` | Kerberos brute force (repeated pre-authentication failures) |
| `100605` | 8 | medium |  |  | User account locked out |
| `100606` | 12 | high |  | `T1558.003` | Probable Kerberoasting (RC4-encrypted service ticket) |
| `100607` | 12 | high |  | `T1558.004` | Probable AS-REP roasting (TGT without pre-authentication, RC4) |
| `100608` | 12 | high |  | `T1558.001` | Probable Golden Ticket (logon without LogonGuid) |
| `100609` | 12 | high |  | `T1003.006` | Probable DCSync (directory replication) |
| `100610` | 0 | suppressed / base |  |  | Legitimate replication by a machine account (suppressed) |
| `100611` | 8 | medium |  | `T1136.002` | Domain account created |
| `100612` | 8 | medium |  |  | Domain account deleted |
| `100613` | 8 | medium |  | `T1098` | Account password reset |
| `100614` | 8 | medium |  | `T1098` | Member added to a security group |
| `100615` | 13 | high |  | `T1078.002` | Member added to a sensitive administrative group |
| `100616` | 8 | medium |  |  | Member removed from a security group |
| `100617` | 14 | critical |  | `T1070.001` | Windows security log cleared, possible anti-forensics |
| `100618` | 12 | high |  | `T1207` | DSRM password set attempt |
| `100619` | 6 | low |  |  | Directory service object modified |

### Oracle decoders

6 decoders in `rules/oracle/local_decoder.xml`:

- `oracle-alert`
- `oracle-alert-errcode`
- `oracle-audit`
- `oracle-audit-action`
- `oracle-audit-dbuser`
- `oracle-listener`
