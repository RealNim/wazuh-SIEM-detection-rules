# Architecture

## Components

Wazuh is deployed in its standard distributed form. Four agents, one
monitoring server.

```
        monitored hosts                      monitoring server
  ┌──────────────────────────┐          ┌──────────────────────────┐
  │  Nginx          (Ubuntu) │          │                          │
  │  └─ wazuh-agent ─────────┼─────────▶│  wazuh-manager           │
  │                          │   1514   │   ├─ decoders            │
  │  SQL Server 2016 (Win)   │   TLS    │   └─ rules ──▶ alerts    │
  │  └─ wazuh-agent ─────────┼─────────▶│         │                │
  │                          │          │         ▼                │
  │  Oracle DB      (Linux)  │          │  OpenSearch indexer      │
  │  └─ wazuh-agent ─────────┼─────────▶│   ├─ wazuh-alerts-*      │
  │                          │          │   └─ wazuh-archives-*    │
  │  Domain controller (Win) │          │         │                │
  │  ├─ wazuh-agent ─────────┼─────────▶│         ▼                │
  │  └─ Sysmon               │          │  Wazuh dashboard         │
  └──────────────────────────┘          └──────────────────────────┘
            ▲
            │  simulated attacks
  ┌─────────┴────────┐
  │  test workstation│
  └──────────────────┘
```

Each agent reads local log sources and ships records to the manager over an
encrypted channel on port 1514. The manager decodes, evaluates rules, and
raises alerts. OpenSearch stores and indexes both the raw events and the
alerts. The dashboard provides the search interface and the visualisations.

A separate workstation generates the attack traffic used to validate the rules,
so test activity arrives through the same collection path as anything else.

## Event path

A single event follows a fixed route:

1. The agent reads the source, either a log file or a Windows event channel,
   and forwards the record.
2. The manager applies a **decoder**, which extracts fields from the raw text.
   Without a decoder that matches, nothing downstream can reference a field.
3. The manager evaluates **rules** as a tree. A rule can require a parent match
   through `if_sid`, so evaluation narrows from generic to specific.
4. A matching rule produces an **alert** carrying a level and, where mapped, a
   MITRE ATT&CK technique.
5. OpenSearch indexes the raw event and, if one was raised, the alert.

The decoder step is why Oracle needed custom work before any rule could be
written. See [the Oracle component notes](components/oracle.md).

## The two indices

| Index | Contents | Purpose |
| ----- | -------- | ------- |
| `wazuh-alerts-*` | Only events that matched a rule | What the dashboards read |
| `wazuh-archives-*` | Every collected event, matched or not | Forensic replay |

Archiving everything is not the default. I enabled it on the manager with:

```xml
<logall>yes</logall>
<logall_json>yes</logall_json>
```

I turned it on so I could replay the full traffic after a validation run,
including the events that did *not* trigger a rule, which is how you find out a
rule has a gap rather than assuming it has none. It costs a lot of storage, so
it goes together with a retention policy sized for the traffic the manager
actually sees.

## Rule ID allocation

Wazuh reserves rule IDs 0 to 99999 for its own ruleset. Custom rules must sit
at 100000 or above. Each component here owns a 100-wide block:

| Component | Allocated | Used |
| --------- | --------- | ---- |
| Nginx | `100300-100399` | `100300-100309` |
| SQL Server 2016 | `100400-100499` | `100400-100418` |
| Oracle Database | `100500-100599` | `100500-100518` |
| Active Directory | `100600-100699` | `100600-100619` |

Blocks rather than a running sequence mean a rule ID tells you which component
it belongs to, and leave room to add rules to one component without
renumbering another. `tools/rule_index.py --check` fails the build if a rule
lands outside its block or if two rules share an ID.

## Severity levels

Wazuh levels run 0 to 16. The allocation I used:

| Level | Meaning | Example |
| ----- | ------- | ------- |
| 0 | Base or suppression rule, raises nothing | `100610`, machine-account replication |
| 1 to 4 | Informational, usually a parent for correlation | `100300`, one sensitive path request |
| 5 to 7 | Low, single failed or notable event | `100401`, one SQL Server logon failure |
| 8 to 11 | Medium, a pattern or a privileged change | `100402`, brute force threshold met |
| 12 to 13 | High, a specific attack technique identified | `100609`, probable DCSync |
| 14 to 16 | Critical, probable compromise or anti-forensics | `100413`, `xp_cmdshell` executed |

Anti-forensic actions sit at 14 regardless of component. Clearing a security log
or erasing an audit trail is the one signal that is never routine, and it means
the rest of the timeline may no longer be trustworthy.
