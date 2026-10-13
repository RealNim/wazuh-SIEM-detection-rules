# Wazuh detection rules

Centralised security log monitoring for a four-component enterprise stack, built
on [Wazuh](https://wazuh.com/). 68 custom detection rules and 6 custom decoders
covering an Nginx web server, Microsoft SQL Server 2016, Oracle Database and a
Windows Active Directory domain controller, each rule validated by running the
attack it is meant to catch.

I built this during a six-month engineering internship with a public-sector
organisation. Each component was developed and tested against a lab environment
mirroring the target infrastructure, then rolled out to the production hosts
once its rules were validated. This repository holds the detection content and
the configuration needed to stand it up. It contains no addresses, host names,
domain names or account names from any real network, and no part of the
organisation's infrastructure is described here.

## What is in here

| Path | Contents |
| ---- | -------- |
| [`rules/`](rules/) | The 68 detection rules and 6 Oracle decoders, as deployed |
| [`agent-config/`](agent-config/) | Wazuh agent `localfile` blocks per component |
| [`setup/`](setup/) | Audit configuration each component needs before the rules can fire |
| [`docs/`](docs/) | Architecture, methodology, per-component threat analysis, ATT&CK coverage, validation results |
| [`tools/`](tools/) | Rule index generator and validator |

Start with the [rule index](docs/rule-index.md) for the full rule list, or
[architecture](docs/architecture.md) for how the pieces fit together.

## Coverage at a glance

| Component | Rules | ID range | Principal attacks covered |
| --------- | ----- | -------- | ------------------------- |
| [Nginx](docs/components/nginx.md) | 10 | `100300-100309` | Reconnaissance, SQL injection, XSS, path traversal, webshell, brute force |
| [SQL Server 2016](docs/components/sql-server.md) | 19 | `100400-100418` | Brute force, SA account use, privilege change, DDL, `xp_cmdshell`, anti-forensics |
| [Oracle Database](docs/components/oracle.md) | 19 | `100500-100518` | Brute force, SYSDBA logon, dangerous packages, Data Pump exfiltration, anti-forensics |
| [Active Directory](docs/components/active-directory.md) | 20 | `100600-100619` | Kerberoasting, AS-REP roasting, Golden Ticket, DCSync, privilege escalation, persistence |

43 of the 68 rules carry an explicit MITRE ATT&CK technique, covering 24
distinct techniques across 7 tactics. The 10 Nginx rules inherit their
technique context from the native parent rules they chain onto. See
[MITRE ATT&CK coverage](docs/mitre-coverage.md) for the full mapping.

## Design decisions

**Custom rules chain onto native ones rather than replacing them.** Every rule
uses `if_sid` or `if_matched_sid` against a Wazuh native rule. The native engine
keeps doing generic detection; the custom rules classify the specific scenario
and raise its severity. Replacing native rules would have meant maintaining
decoding logic that Wazuh already maintains.

**Two-stage correlation separates a signal from an incident.** A single request
for `/.env` is a level 1 event that writes no alert. Five of them from one
source inside two minutes is a level 10 reconnaissance alert. The same pattern
is used for scanners (`100305` then `100306`), XSS (`100307` then `100308`) and
every brute force rule. This keeps the alert volume proportional to what is
actually happening.

**A suppression rule protects the DCSync detection from its own noise.** Domain
controllers replicate with each other constantly and legitimately, so rule
`100610` matches event 4662 where the requesting account name ends in `$`, which
marks a machine account, and drops it to level 0 before `100609` can raise it.
Without it the detection is unusable.

**Oracle needed decoders before it could have rules.** Oracle writes its alert
log, OS-mode audit files and listener log in three unrelated formats that no
native Wazuh decoder parses. Six decoders in
[`rules/oracle/local_decoder.xml`](rules/oracle/local_decoder.xml) extract the
ORA error code, the audit action and the database user, and the 19 Oracle rules
chain onto them.

**Matchers accept both English and French audit output.** The SQL Server
instance was French-language, so audit action groups appear in the log as
`GROUPE_MODIFICATION_MEMBRE` rather than `SERVER_ROLE_MEMBER_CHANGE_GROUP`.
Rules `100406`, `100407` and `100410` match either form, so the same rule file
works on either locale.

**Rule IDs are allocated per component.** Each component owns a 100-wide block
inside the custom range Wazuh reserves above 100000. `tools/rule_index.py`
enforces it, so a new rule cannot silently collide with another component's.

## Installing the detection content

The rules assume a working Wazuh deployment with agents already enrolled.
See [setup](docs/setup.md) to build the environment from scratch.

On the Wazuh manager. Wazuh reads every `.xml` file in
`/var/ossec/etc/rules/`, and its documentation recommends separate files over
one large `local_rules.xml` for a change of this size, so the four component
files are kept apart:

```bash
# Rules, one file per component
cp rules/nginx/local_rules.xml            /var/ossec/etc/rules/nginx_rules.xml
cp rules/sqlserver/local_rules.xml        /var/ossec/etc/rules/sqlserver_rules.xml
cp rules/oracle/local_rules.xml           /var/ossec/etc/rules/oracle_rules.xml
cp rules/active-directory/local_rules.xml /var/ossec/etc/rules/ad_rules.xml

# Oracle decoders
cp rules/oracle/local_decoder.xml /var/ossec/etc/decoders/local_decoder.xml

# Test the configuration and ruleset before restarting
/var/ossec/bin/wazuh-analysisd -t

systemctl restart wazuh-manager
```

Then check a rule actually fires by pasting a sample log line into
`/var/ossec/bin/wazuh-logtest`, using `-v` to see which decoder and rule
matched.

On each agent, merge the matching `localfile` blocks from
[`agent-config/`](agent-config/) into `ossec.conf`, then restart the agent.

Each component also needs its audit configuration enabled first, otherwise the
events the rules match on are never written at all. That is the most common
reason a rule appears not to work:

| Component | Required first | Script |
| --------- | -------------- | ------ |
| Nginx | Nothing beyond default access and error logging | |
| SQL Server | Server and database audit specifications | [`setup/sqlserver-audit.sql`](setup/sqlserver-audit.sql) |
| Oracle | `audit_trail = 'OS'` plus listener logging | [`setup/oracle-audit.sql`](setup/oracle-audit.sql) |
| Active Directory | Advanced audit policy plus a SACL on the domain root | [`setup/domain-controller-auditpol.cmd`](setup/domain-controller-auditpol.cmd) |

## Validating the rules

```bash
python3 tools/rule_index.py --check   # XML validity, ID collisions, range allocation
python3 tools/rule_index.py           # regenerate docs/rule-index.md
```

This also runs on every push, see
[`.github/workflows/validate.yml`](.github/workflows/validate.yml).

## Results

Every test scenario I defined for the four components triggered its intended
rule. The scenarios and what each produced are in [testing](docs/testing.md).
Validation ran in the lab mirror first and again against the production hosts
after the agents were enrolled there, with levels and correlation windows
retuned on live traffic.

## Reusing this

The rules are written against the log sources and audit configuration described
in [setup](docs/setup.md), so they are portable to any Wazuh deployment
monitoring the same four components. Thresholds like `5 in 120s` reflect the
traffic they were tuned against, so expect to adjust them for a network with a
different shape and volume.

## Technology

Wazuh 4.x (manager, agents, OpenSearch indexer, dashboard) · Nginx on Ubuntu LTS
· SQL Server 2016 and Windows Server · Oracle Database 11g and 12c on Linux ·
Sysmon · VMware · MITRE ATT&CK

## Licence

[MIT](LICENSE). The detection rules are free to reuse. Retune them before you
point them at anything you care about.
