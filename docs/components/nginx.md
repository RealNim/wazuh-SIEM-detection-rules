# Nginx web server

10 rules, `100300-100309`. Rule file:
[`rules/nginx/local_rules.xml`](../../rules/nginx/local_rules.xml)

A web server reachable from outside is the first thing an attacker touches, so
its access log is where an intrusion becomes visible earliest, usually well
before anything reaches the database tier. That is the reason this component was
monitored first.

## Telemetry

Two files, both logged by default, which makes this the only component needing
no audit configuration:

| Source | Carries |
| ------ | ------- |
| `/var/log/nginx/access.log` | HTTP method, URL, status code, source address, user agent |
| `/var/log/nginx/error.log` | Application and server errors, 5xx conditions |

Collected with `log_format: apache`, because the Nginx combined format is
compatible with Wazuh's apache decoder, which populates the `url`, `srcip` and
`id` (status code) fields the rules match on. Configuration:
[`agent-config/nginx-ossec.conf`](../../agent-config/nginx-ossec.conf)

## Threat analysis

Attacks against a web server follow a progression: find what is there, find what
is weak, exploit it, keep access. I wrote the rules against the subset of that
progression which leaves a trace in the two log files.

| Threat | Observable indicator | Source |
| ------ | -------------------- | ------ |
| Reconnaissance, directory enumeration | Many 404 responses in a short window | `access.log` |
| Sensitive resource access | `/.env`, `/.git`, `/admin`, `/phpmyadmin`, `/config`, `/backup` | `access.log` |
| SQL injection | `union select`, `or 1=1`, `information_schema`, `sleep()` | `access.log` |
| Cross-site scripting | `<script>`, `onerror=`, `javascript:`, `alert(` | `access.log` |
| Path traversal | `../`, `%2e%2e`, `/etc/passwd`, `/etc/shadow` | `access.log` |
| Webshell, command execution | `/uploads/*.php`, `cmd=`, `exec=`, `system(` | `access.log` |
| Application brute force | Repeated POST to `/login`, 401 and 403 responses | `access.log` |
| Automated scanners | `sqlmap`, `nikto`, `gobuster`, `nmap` in the user agent | `access.log` |
| Denial of service | Request spikes, 503 and 504 responses | both |

I gave `.env` and `.git` their own rule because the consequence is
disproportionate: either one can hand over database credentials,
API keys or the application source outright, and neither produces any other
signal when read successfully.

## Rules

See the [rule index](../rule-index.md) for the full table. The structure:

**Three correlation pairs.** Each pairs a cheap base rule with a threshold rule.

| Base | Correlated | Threshold |
| ---- | ---------- | --------- |
| `100300` sensitive path, level 1 | `100301` level 10 | 5 in 120s, same source IP |
| `100305` scanner signature, level 3 | `100306` level 12 | 3 in 60s |
| `100307` XSS payload, level 13 | `100308` level 15 | 3 in 120s |

`100300` carries `<options>no_log</options>`, so a single request for a sensitive
path writes nothing at all. One probe is noise. Five from one source in two
minutes is someone working through a wordlist.

**Four single-event rules**, where one occurrence is already enough:

| Rule | Level | Why no threshold of its own |
| ---- | ----- | --------------------------- |
| `100302` | 12 | Native `31151` already supplies one, 14 4xx responses in 90s from one source |
| `100303` | 13 | Chains onto native `31106`, which requires HTTP 200. A successful injection needs no second instance |
| `100304` | 13 | Same, a successful read of `/etc/passwd` is one event too many |
| `100309` | 12 | A request to a `.php` file in an uploads directory is not something a legitimate user does |

The HTTP 200 dependency in `100303` and `100304` is the part worth noticing.
Native rule `31106` fires on an attack pattern that returned 200, so these two
rules distinguish an attempt from a result. A blocked injection attempt still
raises the generic native alert; only one that the application answered
successfully reaches level 13.

Rule `100302` works slightly differently from how its description reads. It
narrows native `31151` by URL. `31151` is not an authentication rule: it fires
on 14 HTTP 400-class responses inside 90 seconds from one source address, which
Wazuh classifies as scanning. Restricting that to `/login`, `/signin`, `/auth`
and similar turns it into a brute force signal, since repeated failed logins
produce exactly that pattern of 4xx responses against exactly those paths. It
is a proxy for failed authentication rather than a direct reading of it, and it
inherits `31151`'s threshold rather than setting its own.

## Why these chain onto native rules

Every rule here uses `if_sid` or `if_group` against Wazuh's web ruleset.
Verified against the Wazuh 4.9 ruleset:

| Native rule | Level | What it is |
| ----------- | ----- | ---------- |
| `31100` | 0 | `category: web-log`, access log messages grouped |
| `31106` | 6 | A web attack that returned code 200, already tagged `T1190` |
| `31151` | 10 | 14 web server 400 errors in 90s from one source IP, already tagged `T1595.002` |

Rules `100305`, `100307` and `100309` use `if_group>web` rather than a single
parent ID, so they evaluate against any decoded web event rather than against
one native classification. That is deliberate for scanner and payload matching,
where the signature is in the user agent or the URL regardless of the response
code, and it is the reason `100307` can reach level 13 without needing a 200.

Wazuh already decodes the combined log format and classifies generic web
attacks. Writing the URL matching from scratch would have meant reimplementing
that and keeping it current.

`31106` and `31151` already carry `T1190` and `T1595.002`, so the Nginx
detections inherit their ATT&CK context from the parent rules they chain onto
rather than restating it. See [MITRE ATT&CK coverage](../mitre-coverage.md).

## Scope and next steps

- **Signature matching, not behaviour.** The SQLi and XSS rules match known
  payload shapes in the URL. Payloads obfuscated past those patterns, or sent
  in a POST body rather than the query string, are not caught. The access log
  does not record request bodies, so no rule reading it can.
- **The denial of service row has no rule.** It is in the threat table because
  the indicators are observable, but request-rate analysis is left to the
  reverse proxy and rate limiting rather than the SIEM.
- **ATT&CK context comes from the parent rules.** The Nginx rules carry no
  `<mitre>` block of their own and inherit technique context from native
  `31106` and `31151`. Mapping each child explicitly would make the dashboards
  group them more precisely.
