# Windows Active Directory

20 rules, `100600-100619`. Rule file:
[`rules/active-directory/local_rules.xml`](../../rules/active-directory/local_rules.xml)

The domain controller is the highest-value target on a Windows network. It holds
every credential and decides every authorisation, so compromising it ends the
engagement. This is the largest rule set of the four and the one with the most
specific attack detections.

## Telemetry

Two channels, both filtered at the agent:

| Source | Carries |
| ------ | ------- |
| Windows Security channel | Authentication, Kerberos, account and group management, directory access |
| `Microsoft-Windows-Sysmon/Operational` | Process and network telemetry |

Collection is filtered by event ID rather than taking the whole Security
channel. A domain controller issues Kerberos tickets continuously, and an
unfiltered channel buries the manager in 4768 and 4769 records. Every ID in the
filter is consumed by at least one rule. Configuration:
[`agent-config/domain-controller-ossec.conf`](../../agent-config/domain-controller-ossec.conf)

| Events | Used by |
| ------ | ------- |
| 4624, 4625 | `100600`, `100601`, `100602`, `100608` |
| 4768, 4769, 4771 | `100603`, `100604`, `100606`, `100607` |
| 4662 | `100609`, `100610` |
| 4720, 4724, 4726 | `100611`, `100612`, `100613` |
| 4728, 4729, 4732, 4733, 4756, 4757 | `100614`, `100615`, `100616` |
| 4740 | `100605` |
| 4794 | `100618` |
| 5136 | `100619` |
| 1102 | `100617` |

## Prerequisites

Advanced audit policy must be enabled first. See
[`setup/domain-controller-auditpol.cmd`](../../setup/domain-controller-auditpol.cmd).

**One step cannot be scripted.** DCSync detection depends on event 4662, and
4662 is written only for an object carrying an audit entry for the right being
exercised. Enabling Directory Service Access auditing is necessary but not
sufficient: the domain root object needs a SACL covering the replication
rights. Without it `100609` never sees an event. The exact steps are in the
comments at the bottom of the setup script.

## Threat analysis

| Threat | Observable indicator | Events |
| ------ | -------------------- | ------ |
| Credential brute force | Repeated logon failure from one source | 4625 |
| Password spraying | Failures spread across many accounts | 4625 |
| Kerberos brute force | Repeated pre-authentication failure | 4771 |
| Kerberoasting | Service ticket requested with RC4 encryption | 4769 |
| AS-REP roasting | TGT requested for an account without pre-authentication | 4768 |
| Golden Ticket | Logon with a forged ticket, missing LogonGuid | 4624 |
| DCSync | Directory replication rights exercised | 4662 |
| Account persistence | Account created, password reset | 4720, 4724 |
| Privilege escalation | Member added to a sensitive group | 4728, 4732, 4756 |
| Rogue domain controller | DSRM password set | 4794 |
| Anti-forensics | Security log cleared | 1102 |

## The four advanced detections

These are the rules the component exists for. Each turns a specific attack into
a specific field condition.

**Kerberoasting, `100606`, level 12.** An attacker requests a service ticket for
an account with a Service Principal Name, then cracks it offline. The rule
requires three conditions together: event 4769, `ticketOptions` of
`0x40810000`, and `ticketEncryptionType` of `0x17`, which is RC4-HMAC. Modern
Windows issues AES tickets, so a request specifying RC4 is the attacker asking
for the weaker algorithm because it cracks faster. Requiring the ticket options
as well keeps ordinary service ticket traffic out.

**AS-REP roasting, `100607`, level 12.** The same idea against an account with
Kerberos pre-authentication disabled, which yields crackable material without
any credential at all. Event 4768, `preAuthType` of exactly `0`, and the same
RC4 encryption type.

**Golden Ticket, `100608`, level 12.** A ticket forged with the `krbtgt` hash
does not come from a real authentication, so the resulting 4624 carries field
values a genuine logon does not. The rule requires a `logonGuid` of
`{00000000-0000-0000-0000-000000000000}`, the null GUID rather than an absent
one, together with `logonType` of exactly `3`, a network logon. Both conditions
are needed: a null GUID alone appears in benign situations.

**DCSync, `100609`, level 12, with `100610` suppressing it.** An attacker with
replication rights asks the domain controller to hand over password hashes
using the same mechanism controllers use among themselves. The detection matches
GUIDs in the 4662 `Properties` field. Because domain controllers replicate
legitimately and constantly, `100610` matches a requesting account name ending
in `$`, which marks a machine account, and drops the event to level 0 before
`100609` can raise it.

The suppression rule matters as much as the detection. Without it `100609`
produces a level 12 alert every few minutes in normal operation, an analyst
learns to ignore it, and it stops being a detection. Pairing a broad detection
with a narrow suppression kept the signal usable in practice.

## Audit success and failure parents

Wazuh splits decoded Windows Security events by severity before any custom rule
sees them, so each rule has to chain onto the right branch:

| Native rule | Filter |
| ----------- | ------ |
| `60103` | `severityValue` is `AUDIT_SUCCESS` |
| `60104` | `severityValue` is `AUDIT_FAILURE` |

The two failure-based rules, `100600` for 4625 and `100603` for 4771, chain
onto `60104`. The success-based rules chain onto `60103`. Picking the wrong
branch produces a rule that parses and validates but silently never fires,
which makes this the first thing to check when a Windows rule looks inert.

## Scope and next steps

- **Sysmon is collected but has no custom rules yet.** The channel is gathered
  and indexed, which makes pass-the-hash and pass-the-ticket detection beyond
  the Kerberos rules the obvious next piece of work.
- **`100619` is intentionally broad.** Directory object modification at level 6
  covers routine administration as well, so it serves as an audit trail rather
  than an alert to act on. Scoping it to specific object classes or attributes
  would turn it into a detection.
- **No Discovery coverage.** Internal domain enumeration, the reconnaissance an
  attacker performs before any of the above, leaves little trace in the
  collected event set. LDAP query logging would be needed.
- **DCSync detection could be narrowed further.** `100609` matches the
  `DS-Replication-Get-Changes` right and the `domainDNS` object class. Adding
  `DS-Replication-Get-Changes-All`
  (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) and
  `DS-Replication-Get-Changes-In-Filtered-Set`
  (`89e95b76-444d-4c62-991a-0facbeda640c`) would let the object-class branch be
  dropped and reduce what `100610` has to suppress.
