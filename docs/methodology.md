# Methodology

I applied the same five steps to each of the four components, in the same
order, so that the resulting rules stay comparable and maintainable rather than
each component becoming its own dialect.

## 1. Threat analysis before configuration

For each component: what attacks target it, and what would each one leave behind
in that component's own logs. The second half is the part that constrains
everything else. An attack with no observable trace in the available telemetry
cannot be detected no matter how the rule is written, so the threat list was
filtered down to the subset that is actually visible.

That gave me, per component, a table of threat, observable indicator, and
source log. Those tables are in the per-component documents:
[Nginx](components/nginx.md), [SQL Server](components/sql-server.md),
[Oracle](components/oracle.md),
[Active Directory](components/active-directory.md).

## 2. Enable the telemetry, then collect it

Most of these events are not logged by default. SQL Server writes logon
failures to the ERRORLOG but will not record a role membership change without
an audit specification. Oracle writes audit records to a database table unless
told to write OS files, and an agent cannot read a table. Active Directory
writes event 4662 only for objects that carry an audit entry for the right in
question.

So each component has two configuration steps, and they go in this order:

1. Turn on the auditing, in the component. See [`setup/`](../setup/).
2. Point the Wazuh agent at the resulting log. See
   [`agent-config/`](../agent-config/).

Doing these the other way round produces an agent reading an empty file, which
looks exactly like a broken rule.

On Windows, collection is filtered by event ID in the agent configuration
rather than taking the whole Security channel. A domain controller issues
Kerberos tickets constantly, and an unfiltered channel buries the manager in
4768 and 4769 events. Every ID in the filter is consumed by at least one rule.

## 3. Write rules that chain onto the native ruleset

Two mechanisms carry most of the detection logic.

**Parent and child chaining.** A base rule identifies a category of event. Child
rules narrow it by event ID or by content, using `if_sid` to require the parent.

```xml
<rule id="100400" level="0">
  <if_sid>60009</if_sid>
  <field name="win.system.providerName">MSSQLSERVER</field>
  <description>SQL Server: evenement detecte</description>
  <options>no_log</options>
</rule>

<rule id="100401" level="5">
  <if_sid>100400</if_sid>
  <field name="win.system.eventID">^18456$</field>
  <description>SQL Server: echec de connexion</description>
  <group>authentication_failed,</group>
  <mitre><id>T1110</id></mitre>
</rule>
```

The base rule sits at level 0 and carries `no_log` so it raises nothing and
writes nothing on its own. It exists to give the children something cheap to
hang off, so the field matching only runs on events already known to come from
SQL Server. It chains onto native rule `60009`, which is where Wazuh has
already done the work of decoding the Windows event channel.

**Temporal correlation.** `frequency` and `timeframe`, narrowed by `same_srcip`
or `same_field`, turn a repeated event into a single alert about a pattern:

```xml
<rule id="100402" level="10" frequency="5" timeframe="120">
  <if_matched_sid>100401</if_matched_sid>
  <same_srcip />
  <description>SQL Server: brute force (5+ echecs en 2 min depuis la meme IP)</description>
  <group>authentication_failed,attack,</group>
  <mitre><id>T1110.001</id></mitre>
</rule>
```

One failed logon is a typo. Five from one address in two minutes is an attempt.
Writing it as two rules rather than one means the operator sees a single level 10
brute force alert instead of five level 5 failures, and the underlying events
are still there in the archive index.

I never replaced a native rule, only chained onto it. Wazuh maintains the
decoding and generic detection; my rules add classification and severity.
Forking the native ruleset would have meant inheriting the maintenance burden
of upstream changes for no benefit.

## 4. Validate by running the attack

A rule that has never fired is a hypothesis. I tested each one by performing
the activity it targets against the lab environment and confirming the expected
alert appeared at the expected level. The scenarios and results are in
[testing](testing.md).

Validating against the real attack rather than a crafted log line is what
separates a rule that matches the behaviour from one that only matches an
example of it. Thresholds were then retuned against live traffic once the
platform was collecting from the production hosts, since a lab gives you no
false positive rate.

## 5. Dashboards last

Per-component dashboards plus one consolidated view, built on the
`wazuh-alerts-*` index: alert volume by severity, distribution by component, top
MITRE techniques, and top source addresses. Built last because a dashboard is a
view over the rules, and building views before the rules exist produces panels
designed around what is easy to chart rather than what an analyst needs to
triage.

## Mapping to MITRE ATT&CK

Rules that identify a specific technique carry a `<mitre>` block:

```xml
<mitre><id>T1558.003</id></mitre>
```

Base rules, suppression rules and informational rules carry none, because
mapping "an event occurred" to a technique would be inventing attribution. 43
of the 68 rules are mapped. See [MITRE ATT&CK coverage](mitre-coverage.md) for
the full mapping and for where it is incomplete.
