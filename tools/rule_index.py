#!/usr/bin/env python3
"""Generate docs/rule-index.md from the rule XML, so the tables cannot drift.

    python3 tools/rule_index.py            # print the tables
    python3 tools/rule_index.py --check    # validate only, exit 1 on a problem
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent.parent

COMPONENTS = [
    ("Nginx",            "rules/nginx/local_rules.xml",            "100300-100399"),
    ("SQL Server 2016",  "rules/sqlserver/local_rules.xml",        "100400-100499"),
    ("Oracle Database",  "rules/oracle/local_rules.xml",           "100500-100599"),
    ("Active Directory", "rules/active-directory/local_rules.xml", "100600-100699"),
]

DECODERS = "rules/oracle/local_decoder.xml"

# The deployed descriptions are in French. This table is the English reading
# used in the docs; Wazuh never sees it.
EN = {
    "100300": "Access to a sensitive path (base rule)",
    "100301": "Repeated access to sensitive paths from the same IP",
    "100302": "Probable brute force against an authentication endpoint",
    "100303": "Confirmed SQL injection (HTTP 200 response)",
    "100304": "System file access or path traversal attempt (HTTP 200 response)",
    "100305": "Scanning tool detected (base rule)",
    "100306": "Confirmed automated scanning activity",
    "100307": "XSS payload detected (base rule)",
    "100308": "Repeated XSS attack attempts",
    "100309": "Probable webshell access or command execution",

    "100400": "SQL Server event detected (base rule)",
    "100401": "Logon failure",
    "100402": "Brute force (5+ failures in 2 min from the same IP)",
    "100403": "Brute force by user name (5+ failures in 2 min)",
    "100404": "Successful logon",
    "100405": "Logon using the built-in SA account",
    "100406": "Server role membership changed",
    "100407": "Server permissions changed",
    "100408": "Database permissions changed",
    "100409": "Database user or role changed",
    "100410": "Audit configuration changed",
    "100411": "Database object changed (DDL)",
    "100412": "Stored procedure executed",
    "100413": "xp_cmdshell executed, OS command execution possible",
    "100414": "High severity error in ERRORLOG",
    "100415": "SQL Server Agent job activity",
    "100416": "SQL Server Agent job failure, check for tampering",
    "100417": "Windows security log cleared, possible anti-forensics",
    "100418": "Privileged logon on the SQL Server host",

    "100500": "Oracle alert log event detected (base rule)",
    "100501": "Authentication failure (ORA-01017)",
    "100502": "Brute force (5+ failures in 2 min from the same IP)",
    "100503": "Critical internal error, possible corruption or exploitation attempt",
    "100504": "Instance startup or shutdown detected",
    "100505": "Audit record detected (base rule)",
    "100506": "Logon with SYSDBA or SYSOPER privileges",
    "100507": "Logon using a default Oracle account",
    "100508": "DDL operation on a database object",
    "100509": "Privilege change (GRANT or REVOKE)",
    "100510": "Potentially dangerous package or procedure used",
    "100511": "OS command executed from Oracle, probable compromise",
    "100512": "Audit configuration changed or disabled",
    "100513": "TNS listener event detected (base rule)",
    "100514": "TNS listener connection failure",
    "100515": "Brute force against the TNS listener (5+ failures in 2 min)",
    "100516": "Sensitive administrative command run against the listener",
    "100517": "Bulk data export or import detected (Data Pump)",
    "100518": "Audit trail erased, possible anti-forensics",

    "100600": "Windows logon failure",
    "100601": "Brute force (8+ failures in 2 min from the same source)",
    "100602": "Password spraying (same target account)",
    "100603": "Kerberos pre-authentication failure",
    "100604": "Kerberos brute force (repeated pre-authentication failures)",
    "100605": "User account locked out",
    "100606": "Probable Kerberoasting (RC4-encrypted service ticket)",
    "100607": "Probable AS-REP roasting (TGT without pre-authentication, RC4)",
    "100608": "Probable Golden Ticket (logon without LogonGuid)",
    "100609": "Probable DCSync (directory replication)",
    "100610": "Legitimate replication by a machine account (suppressed)",
    "100611": "Domain account created",
    "100612": "Domain account deleted",
    "100613": "Account password reset",
    "100614": "Member added to a security group",
    "100615": "Member added to a sensitive administrative group",
    "100616": "Member removed from a security group",
    "100617": "Windows security log cleared, possible anti-forensics",
    "100618": "DSRM password set attempt",
    "100619": "Directory service object modified",
}

# Wazuh severity bands
BANDS = [
    (0, 0,   "suppressed / base"),
    (1, 4,   "informational"),
    (5, 7,   "low"),
    (8, 11,  "medium"),
    (12, 13, "high"),
    (14, 16, "critical"),
]


def band(level: int) -> str:
    for lo, hi, name in BANDS:
        if lo <= level <= hi:
            return name
    return "unknown"


def load(path: pathlib.Path, wrap: bool = False) -> ET.Element:
    text = path.read_text(encoding="utf-8")
    if wrap:                      # decoder files have no single root
        text = f"<root>{text}</root>"
    return ET.fromstring(text)


def rules_of(path: pathlib.Path) -> list[dict]:
    out = []
    for r in load(path).iter("rule"):
        desc = re.sub(r"\s+", " ", (r.findtext("description") or "").strip())
        out.append(
            {
                "id": r.get("id"),
                "level": int(r.get("level", 0)),
                "desc": desc,
                "mitre": [m.text.strip() for m in r.findall("./mitre/id") if m.text],
                "frequency": r.get("frequency"),
                "timeframe": r.get("timeframe"),
                "parent": r.findtext("if_sid") or r.findtext("if_matched_sid"),
                "groups": (r.findtext("group") or "").strip(","),
            }
        )
    return out


def table(rules: list[dict]) -> str:
    lines = [
        "| Rule | Level | Severity | Correlation | MITRE | Detects |",
        "| ---- | ----- | -------- | ----------- | ----- | ------- |",
    ]
    for r in rules:
        corr = (
            f"{r['frequency']} in {r['timeframe']}s"
            if r["frequency"] and r["timeframe"]
            else ""
        )
        mitre = ", ".join(f"`{m}`" for m in r["mitre"])
        desc = EN.get(r["id"]) or r["desc"]
        lines.append(
            f"| `{r['id']}` | {r['level']} | {band(r['level'])} | {corr} | "
            f"{mitre} | {desc} |"
        )
    return "\n".join(lines)


def missing_translations(rules: list[dict]) -> list[str]:
    return [r["id"] for r in rules if r["id"] not in EN]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="validate only, print nothing but problems")
    args = ap.parse_args()

    problems: list[str] = []
    seen: dict[str, str] = {}
    total = 0
    blocks: list[str] = []

    for name, rel, allocated in COMPONENTS:
        path = ROOT / rel
        if not path.exists():
            problems.append(f"{rel}: missing")
            continue
        try:
            rules = rules_of(path)
        except ET.ParseError as e:
            problems.append(f"{rel}: XML parse error: {e}")
            continue

        lo, hi = (int(x) for x in allocated.split("-"))
        for r in rules:
            total += 1
            rid = r["id"]
            if rid in seen:
                problems.append(f"{rel}: rule {rid} already defined in {seen[rid]}")
            seen[rid] = rel
            if not lo <= int(rid) <= hi:
                problems.append(f"{rel}: rule {rid} outside allocated range {allocated}")
            if int(rid) < 100000:
                problems.append(f"{rel}: rule {rid} collides with the native Wazuh range")
            if not r["desc"]:
                problems.append(f"{rel}: rule {rid} has no description")

        for rid in missing_translations(rules):
            problems.append(f"{rel}: rule {rid} has no entry in the EN table")

        mapped = sum(1 for r in rules if r["mitre"])
        blocks.append(
            f"### {name}\n\n"
            f"Allocated range `{allocated}`, {len(rules)} rules, "
            f"{mapped} carrying an explicit `<mitre>` block.\n\n"
            + table(rules)
        )

    # decoders
    dpath = ROOT / DECODERS
    if dpath.exists():
        try:
            decs = [d.get("name") for d in load(dpath, wrap=True).iter("decoder")]
            blocks.append(
                "### Oracle decoders\n\n"
                + f"{len(decs)} decoders in `{DECODERS}`:\n\n"
                + "\n".join(f"- `{d}`" for d in decs)
            )
        except ET.ParseError as e:
            problems.append(f"{DECODERS}: XML parse error: {e}")
    else:
        problems.append(f"{DECODERS}: missing")

    if problems:
        print("PROBLEMS", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    if args.check:
        print(f"OK: {total} rules, no ID collisions, all within allocated ranges")
        return 0

    print("# Rule index\n")
    print(
        f"{total} custom detection rules across four components, plus "
        f"{len(decs) if dpath.exists() else 0} Oracle decoders.\n"
    )
    print(
        "Rule IDs, levels, correlation windows and MITRE mappings in the tables "
        "below are read directly from the XML, so they cannot drift from the "
        "rules. The `Detects` column is an English reading of each rule; the "
        "deployed `<description>` fields are in French, because the platform "
        "was built for a French-speaking operations team.\n"
    )
    print(
        "Levels follow the Wazuh 0 to 16 scale. Level 0 means the rule is a "
        "base or suppression rule and raises no alert of its own.\n"
    )
    print("\n\n".join(blocks))
    return 0


if __name__ == "__main__":
    sys.exit(main())
