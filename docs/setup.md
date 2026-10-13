# Setup

How to stand up an environment the rules in this repository can run against.
I built the mirror the rules were developed on with VMware; anything that can
run five virtual machines works, and the same steps apply to physical hosts.

Nothing here describes a real network. Addresses below are from the ranges
reserved for documentation and private use, and are examples only.

## Machines

| Role | OS | Purpose |
| ---- | -- | ------- |
| Monitoring server | Linux | Wazuh manager, OpenSearch indexer, dashboard |
| Web server | Ubuntu LTS | Nginx, agent |
| Database server | Windows Server | SQL Server 2016, agent |
| Database server | Linux | Oracle Database 11g or 12c, agent |
| Domain controller | Windows Server | Active Directory, Sysmon, agent |
| Test workstation | Kali Linux or similar | Generates the validation traffic |

The monitoring server is the one to size properly. The indexer holds both the
alert and the archive index, and `logall` archiving makes the archive index grow
fast. 4 CPU and 8 GB RAM is a workable floor at this agent count.

Example addressing on an isolated host-only network:

```
10.0.0.10   monitoring server
10.0.0.20   web server
10.0.0.30   SQL Server
10.0.0.40   Oracle
10.0.0.50   domain controller
10.0.0.100  attack workstation
```

Keep a test environment on an isolated or host-only network. Several of the
validation scenarios generate traffic indistinguishable from a real attack, and
one of them clears a Windows security log.

## 1. Wazuh server

Follow the [Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html),
which installs the three central components, server, indexer and dashboard, on
one host via the installation assistant. It does not install agents; those come
next. Then enable full archiving in `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <global>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
  </global>
</ossec_config>
```

Archiving is optional. It is what makes `wazuh-archives-*` useful for replaying
a campaign, including the events that did not match a rule. Pair it with a
retention policy sized for the traffic the manager actually sees.

## 2. Enrol the agents

Install the agent on each monitored host and register it against the manager.
Confirm all four appear as active before going further:

```bash
/var/ossec/bin/agent_control -l
```

An agent that is connected but sending nothing is almost always a log source
that does not exist yet, which is the next step.

## 3. Enable auditing on each component

This is the step that is easy to skip and expensive to skip. Most of the events
these rules match on are not logged by default.

| Component | What to run | Notes |
| --------- | ----------- | ----- |
| Nginx | Nothing | Default access and error logs are enough |
| SQL Server | [`setup/sqlserver-audit.sql`](../setup/sqlserver-audit.sql) | Creates the audit, server spec and database spec |
| Oracle | [`setup/oracle-audit.sql`](../setup/oracle-audit.sql) | Sets `audit_trail = 'OS'`, requires an instance restart |
| Active Directory | [`setup/domain-controller-auditpol.cmd`](../setup/domain-controller-auditpol.cmd) | Plus a manual SACL step, see below |

**The Active Directory SACL step cannot be scripted away.** Enabling Directory
Service Access auditing is not enough on its own: event 4662 is only written for
an object that carries an audit entry for the right being exercised. Without a
SACL on the domain root covering the replication rights, rule `100609` never
sees anything. The exact steps are in the comments at the bottom of
`setup/domain-controller-auditpol.cmd`.

Install Sysmon on the domain controller separately. The agent collects its
channel, though no custom Sysmon rules are included here.

## 4. Point the agents at the logs

Merge the matching `localfile` blocks from [`agent-config/`](../agent-config/)
into each agent's `ossec.conf`, then restart:

```bash
systemctl restart wazuh-agent              # Linux
Restart-Service -Name wazuh                # Windows, PowerShell
```

Replace the Oracle placeholders with the real values for the instance. Confirm
the paths first:

```sql
SELECT value FROM v$diag_info WHERE name = 'Diag Trace';
SHOW PARAMETER audit_file_dest;
```

## 5. Install the detection content

On the manager:

```bash
cp rules/nginx/local_rules.xml            /var/ossec/etc/rules/nginx_rules.xml
cp rules/sqlserver/local_rules.xml        /var/ossec/etc/rules/sqlserver_rules.xml
cp rules/oracle/local_rules.xml           /var/ossec/etc/rules/oracle_rules.xml
cp rules/active-directory/local_rules.xml /var/ossec/etc/rules/ad_rules.xml
cp rules/oracle/local_decoder.xml         /var/ossec/etc/decoders/local_decoder.xml

/var/ossec/bin/wazuh-analysisd -t
systemctl restart wazuh-manager
```

Wazuh reads every `.xml` file in `/var/ossec/etc/rules/`, and its documentation
recommends separate files over one large `local_rules.xml` for a change this
size.

## 6. Verify before testing

Check a rule matches before generating live traffic. Paste a sample log line
into logtest and read which decoder and rule it hit:

```bash
/var/ossec/bin/wazuh-logtest -v
```

For Oracle this is worth doing first, because the custom decoders have to match
before any Oracle rule can. If logtest shows no decoder, the rules are not the
problem.

Then work through [the validation scenarios](testing.md).

## Common reasons nothing fires

In rough order of how often each one is the answer:

1. **The audit configuration was never enabled.** The agent is reading a file
   that exists but stays empty.
2. **The log path is wrong.** Oracle especially, where the path contains the
   database name, the SID and the host name.
3. **The decoder does not match.** Oracle only. Check with logtest before
   looking at rules.
4. **The manager was not restarted.** Saving a rule file is enough for logtest
   but not for live alerting.
5. **The parent rule does not match.** A custom rule only evaluates if its
   `if_sid` parent matched first, and the parent's own filters apply too. On
   Windows this usually means the rule is chained to the audit-success branch
   when its event is an audit failure, or the reverse.
6. **The event is filtered out at the agent.** The Windows configurations here
   collect specific event IDs. An event not in the query never leaves the host.

## Sources

- [Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html)
- [Wazuh custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [wazuh-logtest reference](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
