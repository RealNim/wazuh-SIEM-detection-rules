# MITRE ATT&CK coverage

43 of the 68 rules carry an explicit `<mitre>` block, covering 24 distinct
techniques across 7 tactics. The 25 unmapped rules are listed at the end, with
the reason in each case.

Technique IDs below are exactly as written in the rule XML, and the rule lists
are generated from it. Names are from the
[ATT&CK Enterprise matrix](https://attack.mitre.org/matrices/enterprise/).

**A note on ATT&CK versions.** I wrote these rules against the matrix as it
stood in early 2026, and ATT&CK has been reorganised since, so the mappings
want a pass against the current matrix. The Defense
Evasion tactic has been split into **Stealth** (TA0005) and **Defense
Impairment** (TA0112), and the Enterprise matrix now lists 15 tactics. `T1070`
Indicator Removal now sits under Stealth, and `T1207` Rogue Domain Controller
under Defense Impairment. The sub-technique numbering under `T1070` has also
changed, so `T1070.001` as carried by rules `100417` and `100617` should be
re-checked against the current matrix before anyone relies on the mapping.
The groupings below use the tactic a technique sat under when the rule was
written, except where noted.

## By tactic

### Credential Access

| Technique | Name | Rules |
| --------- | ---- | ----- |
| `T1110` | Brute Force | `100401`, `100501`, `100514`, `100600`, `100603` |
| `T1110.001` | Password Guessing | `100402`, `100403`, `100502`, `100515`, `100601`, `100604` |
| `T1110.003` | Password Spraying | `100602` |
| `T1003.006` | OS Credential Dumping: DCSync | `100609` |
| `T1558.003` | Steal or Forge Kerberos Tickets: Kerberoasting | `100606` |
| `T1558.004` | Steal or Forge Kerberos Tickets: AS-REP Roasting | `100607` |

### Privilege Escalation

| Technique | Name | Rules |
| --------- | ---- | ----- |
| `T1078` | Valid Accounts | `100509` |
| `T1078.001` | Valid Accounts: Default Accounts | `100507` |
| `T1078.002` | Valid Accounts: Domain Accounts | `100405`, `100406`, `100407`, `100408`, `100418`, `100506`, `100615` |
| `T1098` | Account Manipulation | `100613`, `100614` |

### Persistence

| Technique | Name | Rules |
| --------- | ---- | ----- |
| `T1136` | Create Account | `100409` |
| `T1136.002` | Create Account: Domain Account | `100611` |
| `T1207` | Rogue Domain Controller (now under Defense Impairment, TA0112) | `100618` |

### Lateral Movement

| Technique | Name | Rules |
| --------- | ---- | ----- |
| `T1558.001` | Steal or Forge Kerberos Tickets: Golden Ticket | `100608` |

### Execution

| Technique | Name | Rules |
| --------- | ---- | ----- |
| `T1059` | Command and Scripting Interpreter | `100510` |
| `T1059.003` | Command and Scripting Interpreter: Windows Command Shell | `100413` |
| `T1059.004` | Command and Scripting Interpreter: Unix Shell | `100511` |

### Defense Evasion, now Stealth (TA0005) and Defense Impairment (TA0112)

| Technique | Name | Rules |
| --------- | ---- | ----- |
| `T1070` | Indicator Removal (now under Stealth) | `100518` |
| `T1070.001` | Indicator Removal: Clear Windows Event Logs | `100417`, `100617` |
| `T1562.001` | Impair Defenses: Disable or Modify Tools | `100516` |
| `T1562.002` | Impair Defenses: Disable Windows Event Logging | `100410`, `100512` |

### Exfiltration

| Technique | Name | Rules |
| --------- | ---- | ----- |
| `T1048.003` | Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol | `100517` |

### Impact

| Technique | Name | Rules |
| --------- | ---- | ----- |
| `T1485` | Data Destruction | `100411`, `100508` |
| `T1529` | System Shutdown/Reboot | `100504` |

## Unmapped rules

### Base and suppression rules, correctly unmapped

These carry no technique because they identify a category of event or suppress
a known-benign one. Attaching a technique to them would be asserting
attribution that the event does not support.

| Rule | Level | Why unmapped |
| ---- | ----- | ------------ |
| `100400` | 0 | Base rule, any SQL Server event |
| `100500` | 0 | Base rule, any Oracle alert log event |
| `100505` | 0 | Base rule, any Oracle audit record |
| `100513` | 0 | Base rule, any TNS listener event |
| `100610` | 0 | Suppression, legitimate machine-account replication |

### Informational rules, reasonably unmapped

Each records an event that is notable in context but is not itself adversary
behaviour.

| Rule | Level | Event |
| ---- | ----- | ----- |
| `100404` | 3 | Successful SQL Server logon |
| `100412` | 5 | Stored procedure executed |
| `100414` | 8 | High severity ERRORLOG entry |
| `100415` | 6 | SQL Server Agent job activity |
| `100416` | 10 | SQL Server Agent job failure |
| `100503` | 10 | Oracle critical internal error |
| `100605` | 8 | Account locked out |
| `100612` | 8 | Domain account deleted |
| `100616` | 8 | Member removed from a security group |
| `100619` | 6 | Directory service object modified |

Some of these are arguable. `100612` and `100616` could reasonably be mapped to
`T1098` Account Manipulation or `T1531` Account Access Removal, and `100416`
could support `T1489` Service Stop. I left them unmapped rather than map them
on a guess.

### Nginx rules, mapped through their parents

The 10 Nginx rules carry no `<mitre>` block of their own. They chain onto
native `31100`, `31106` and `31151`, and the latter two already carry `T1190`
and `T1595.002`, so the technique context arrives from the parent. The
techniques that apply to each child, for reference:

| Rule | Detects | Technique that applies |
| ---- | ------- | ---------------------- |
| `100300` / `100301` | Sensitive path enumeration | `T1595.003` Active Scanning: Wordlist Scanning |
| `100302` | Brute force on an auth endpoint | `T1110` Brute Force |
| `100303` | SQL injection | `T1190` Exploit Public-Facing Application |
| `100304` | Path traversal, system file access | `T1190` Exploit Public-Facing Application |
| `100305` / `100306` | Automated scanning | `T1595.002` Active Scanning: Vulnerability Scanning |
| `100307` / `100308` | XSS payloads | `T1059.007` Command and Scripting Interpreter: JavaScript |
| `100309` | Webshell access, command execution | `T1505.003` Server Software Component: Web Shell |

Mapping each child explicitly would let the dashboards group Nginx alerts by
technique alongside the other three components, which is the next refinement
for this set.

## Tactics not covered

| Tactic | Status |
| ------ | ------ |
| Reconnaissance | Covered in behaviour by the Nginx rules, mapped via their parents |
| Resource Development | Out of scope, not observable in host logs |
| Initial Access | Partly, through the Nginx rules, mapped via their parents |
| Discovery | Not covered. Internal AD enumeration leaves little trace in the collected event set |
| Collection | Not covered |
| Command and Control | Not covered. Needs network telemetry the platform does not collect |

## Sources

- [MITRE ATT&CK Enterprise matrix](https://attack.mitre.org/matrices/enterprise/)
