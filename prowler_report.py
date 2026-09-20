#!/usr/bin/env python3
"""
prowler_report.py
=================

Turn a Prowler scan output into a *reporting friendly* HTML report.

The problem
-----------
Prowler reports one row per affected resource. The same check (same CHECK_ID +
same CHECK_TITLE) therefore appears many times - once for every affected ARN.
That is accurate but not report friendly: 850 failed rows can really be only
~150 unique findings.

What this tool does
-------------------
1. Reads a Prowler output file (auto-detects .html / .csv / .ocsf.json).
2. Keeps only the statuses you care about (default: FAIL).
3. Groups every row that shares the same CHECK_ID + CHECK_TITLE into ONE
   finding and collects *all* affected ARNs (with region / account / name).
4. Assigns each finding a short, human friendly ID (F-0001, F-0002, ...).
5. Writes a self-contained, modern HTML report that supports:
     - full text search
     - filters (severity, service, region, account)
     - sortable columns
     - expandable detail rows (risk, recommendation, remediation, compliance,
       and the full list of affected ARNs)
     - CSV / JSON export and print

No third party packages are required (stdlib only).

Usage
-----
    python prowler_report.py
    python prowler_report.py output/prowler-output-XXXX.html
    python prowler_report.py output/prowler-output-XXXX.csv -o findings.html
    python prowler_report.py output/prowler-output-XXXX.html --status FAIL,MANUAL
    python prowler_report.py --input output --open

Run `python prowler_report.py --help` for all options.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import webbrowser
from collections import OrderedDict, defaultdict
from datetime import datetime
from html import escape as html_escape
from html.parser import HTMLParser
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
    "info": 4,
    "unknown": 9,
}

STATUS_ORDER = ["FAIL", "MANUAL", "PASS", "MUTED"]


def severity_rank(sev: str) -> int:
    return SEVERITY_RANK.get((sev or "").strip().lower(), 9)


def norm_severity(sev: str) -> str:
    sev = (sev or "").strip().lower()
    if sev in ("info", "informational"):
        return "informational"
    if sev in SEVERITY_RANK:
        return sev
    return sev or "unknown"


def parse_arn(arn: str):
    """Return (partition, service, region, account, resource) for an ARN."""
    if not arn:
        return ("", "", "", "", "")
    parts = arn.split(":", 5)
    if len(parts) == 6 and parts[0] == "arn":
        return (parts[1], parts[2], parts[3], parts[4], parts[5])
    return ("", "", "", "", arn)


def stable_key(check_id: str, check_title: str) -> str:
    return f"{(check_id or '').strip()}||{(check_title or '').strip()}"


def fingerprint(check_id: str, check_title: str) -> str:
    h = hashlib.sha1(stable_key(check_id, check_title).encode("utf-8")).hexdigest()
    return h[:8].upper()


def clean_text(text: str) -> str:
    if not text:
        return ""
    text = text.replace("\u2022", "\n\u2022")  # bullet point
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n", text)
    return text.strip()


# ---------------------------------------------------------------------------
# HTML parser (stdlib only) - extracts the Prowler findings table
# ---------------------------------------------------------------------------

class FindingsTableParser(HTMLParser):
    """Extract the <table id="findingsTable"> header + body from Prowler HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_table = False
        self.table_depth = 0
        self.section = None
        self.headers = []
        self.rows = []
        self._cell = None
        self._href = None
        self._row = []

    # -- helpers ---------------------------------------------------------
    def _flush_cell(self, tag):
        if self._cell is None:
            return
        text = clean_text("".join(self._cell))
        if self.section == "thead":
            self.headers.append(text)
        else:
            self._row.append({"text": text, "href": self._href or ""})
        self._cell = None
        self._href = None

    # -- parser callbacks ------------------------------------------------
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "table":
            if not self.in_table and a.get("id") == "findingsTable":
                self.in_table = True
                self.table_depth = 0
            elif self.in_table:
                self.table_depth += 1
            return
        if not self.in_table:
            return
        if tag == "thead":
            self.section = "thead"
        elif tag == "tbody":
            self.section = "tbody"
        elif tag == "tr":
            self._row = []
        elif tag in ("td", "th"):
            self._cell = []
            self._href = None
        elif tag == "a" and self._cell is not None and not self._href:
            self._href = a.get("href", "")

    def handle_startendtag(self, tag, attrs):
        # self closing tags (<wbr />, <br />, ...) contribute no text
        pass

    def handle_data(self, data):
        if self._cell is not None:
            self._cell.append(data)

    def handle_endtag(self, tag):
        if tag == "table":
            if self.in_table:
                if self.table_depth > 0:
                    self.table_depth -= 1
                else:
                    self.in_table = False
            return
        if not self.in_table:
            return
        if tag in ("td", "th"):
            self._flush_cell(tag)
        elif tag == "tr":
            if self.section == "tbody" and self._row:
                self.rows.append(self._row)
            self._row = []
        elif tag in ("thead", "tbody"):
            self.section = None


# ---------------------------------------------------------------------------
# Loaders - each returns a list of normalised records
# ---------------------------------------------------------------------------

def _base_record(**kw):
    rec = {
        "account_id": "",
        "account_name": "",
        "region": "",
        "service": "",
        "check_id": "",
        "check_title": "",
        "severity": "",
        "status": "",
        "status_extended": "",
        "resource_uid": "",
        "resource_name": "",
        "resource_type": "",
        "description": "",
        "risk": "",
        "recommendation": "",
        "recommendation_url": "",
        "remediation_cli": "",
        "remediation_terraform": "",
        "remediation_native_iac": "",
        "remediation_other": "",
        "compliance": [],
        "categories": [],
    }
    rec.update(kw)
    return rec


def load_html(path: Path):
    parser = FindingsTableParser()
    parser.feed(path.read_text(encoding="utf-8", errors="replace"))

    if not parser.rows:
        raise SystemExit(
            f"[!] Could not find the findings table in {path.name}. "
            "Is this a Prowler HTML output file?"
        )

    headers = [h.strip().lower() for h in parser.headers]

    def idx(*names, default=-1):
        for n in names:
            for i, h in enumerate(headers):
                if h == n or h.startswith(n):
                    return i
        return default

    ci = {
        "status": idx("status"),
        "severity": idx("severity"),
        "service": idx("service name", "service"),
        "region": idx("region"),
        "check_id": idx("check id"),
        "check_title": idx("check title"),
        "resource": idx("resource id"),
        "status_extended": idx("status extended"),
        "risk": idx("risk"),
        "recommendation": idx("recomendation", "recommendation"),
        "compliance": idx("compliance"),
    }

    records = []
    for row in parser.rows:
        def cell(name):
            i = ci[name]
            if 0 <= i < len(row):
                return row[i]
            return {"text": "", "href": ""}

        status = cell("status")["text"].upper()
        check_id = cell("check_id")["text"]
        check_title = cell("check_title")["text"]
        resource_uid = cell("resource")["text"]
        region = cell("region")["text"]

        _, _, arn_region, arn_account, arn_resource = parse_arn(resource_uid)
        resource_name = arn_resource or resource_uid

        compliance_text = cell("compliance")["text"]
        compliance = [
            line.strip().lstrip("\u2022").strip()
            for line in compliance_text.splitlines()
            if line.strip().lstrip("\u2022").strip()
        ]

        records.append(
            _base_record(
                account_id=arn_account,
                region=region or arn_region,
                service=cell("service")["text"],
                check_id=check_id,
                check_title=check_title,
                severity=norm_severity(cell("severity")["text"]),
                status=status,
                status_extended=cell("status_extended")["text"],
                resource_uid=resource_uid,
                resource_name=resource_name,
                resource_type="",
                risk=cell("risk")["text"],
                recommendation=cell("recommendation")["text"],
                recommendation_url=cell("recommendation")["href"],
                compliance=compliance,
            )
        )
    return records


def load_csv(path: Path):
    with path.open(encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh, delimiter=";")
        raw = list(reader)

    records = []
    for r in raw:
        def g(*names):
            for n in names:
                if n in r and r[n]:
                    return r[n]
            return ""

        compliance = [
            c.strip() for c in g("COMPLIANCE").split("|") if c.strip()
        ]
        categories = [
            c.strip() for c in g("CATEGORIES").split("|") if c.strip()
        ]
        records.append(
            _base_record(
                account_id=g("ACCOUNT_UID"),
                account_name=g("ACCOUNT_NAME"),
                region=g("REGION"),
                service=g("SERVICE_NAME"),
                check_id=g("CHECK_ID"),
                check_title=g("CHECK_TITLE"),
                severity=norm_severity(g("SEVERITY")),
                status=g("STATUS").upper(),
                status_extended=g("STATUS_EXTENDED"),
                resource_uid=g("RESOURCE_UID"),
                resource_name=g("RESOURCE_NAME"),
                resource_type=g("RESOURCE_TYPE"),
                description=g("DESCRIPTION"),
                risk=g("RISK"),
                recommendation=g("REMEDIATION_RECOMMENDATION_TEXT"),
                recommendation_url=g("REMEDIATION_RECOMMENDATION_URL"),
                remediation_cli=g("REMEDIATION_CODE_CLI"),
                remediation_terraform=g("REMEDIATION_CODE_TERRAFORM"),
                remediation_native_iac=g("REMEDIATION_CODE_NATIVEIAC"),
                remediation_other=g("REMEDIATION_CODE_OTHER"),
                compliance=compliance,
                categories=categories,
            )
        )
    return records


def load_ocsf(path: Path):
    with path.open(encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)

    records = []
    for item in data:
        metadata = item.get("metadata", {}) or {}
        finding_info = item.get("finding_info", {}) or {}
        cloud = item.get("cloud", {}) or {}
        account = cloud.get("account", {}) or {}
        unmapped = item.get("unmapped", {}) or {}
        remediation = item.get("remediation", {}) or {}

        resource = (item.get("resources") or [{}])[0] or {}

        compliance = []
        comp = unmapped.get("compliance") or {}
        if isinstance(comp, dict):
            for framework, values in comp.items():
                if isinstance(values, list):
                    compliance.append(f"{framework}: " + ", ".join(str(v) for v in values))
                else:
                    compliance.append(f"{framework}: {values}")
        elif isinstance(comp, list):
            compliance = [str(c) for c in comp]

        refs = remediation.get("references") or []
        ref_url = ""
        if isinstance(refs, list) and refs:
            first = refs[0]
            ref_url = first if isinstance(first, str) else (first.get("url", "") if isinstance(first, dict) else "")

        records.append(
            _base_record(
                account_id=account.get("uid", ""),
                account_name=account.get("name", ""),
                region=cloud.get("region") or resource.get("region", ""),
                service=(resource.get("group") or {}).get("name", ""),
                check_id=metadata.get("event_code", ""),
                check_title=finding_info.get("title", ""),
                severity=norm_severity(item.get("severity", "")),
                status=(item.get("status_code") or "").upper(),
                status_extended=item.get("status_detail", "") or item.get("message", ""),
                resource_uid=resource.get("uid", ""),
                resource_name=resource.get("name", ""),
                resource_type=resource.get("type", ""),
                risk=item.get("risk_details", ""),
                recommendation=remediation.get("desc", ""),
                recommendation_url=ref_url or unmapped.get("related_url", ""),
                compliance=compliance,
                categories=[str(c) for c in (unmapped.get("categories") or [])],
            )
        )
    return records


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------

def first_non_empty(values):
    for v in values:
        if v and str(v).strip():
            return str(v).strip()
    return ""


def longest(values):
    best = ""
    for v in values:
        if v and len(v) > len(best):
            best = v
    return best


def group_records(records):
    """Group normalised records into findings by CHECK_ID + CHECK_TITLE."""
    groups = OrderedDict()
    for rec in records:
        key = stable_key(rec["check_id"], rec["check_title"])
        groups.setdefault(key, []).append(rec)

    findings = []
    for key, recs in groups.items():
        check_id = recs[0]["check_id"]
        check_title = recs[0]["check_title"]

        # Severity = most severe severity seen in the group.
        severity = min((r["severity"] for r in recs), key=severity_rank)

        # Overall status: FAIL wins, then MANUAL, then whatever.
        statuses = {r["status"] for r in recs}
        if "FAIL" in statuses:
            status = "FAIL"
        elif "MANUAL" in statuses:
            status = "MANUAL"
        else:
            status = sorted(statuses)[0] if statuses else ""

        # Collect unique affected resources.
        resources = []
        seen = set()
        for r in recs:
            uid = r["resource_uid"] or r["resource_name"] or "(unknown)"
            if uid in seen:
                continue
            seen.add(uid)
            _, _, arn_region, arn_account, _ = parse_arn(r["resource_uid"])
            resources.append(
                {
                    "arn": r["resource_uid"] or uid,
                    "name": r["resource_name"],
                    "region": r["region"] or arn_region,
                    "account": r["account_id"] or arn_account,
                    "account_name": r["account_name"],
                    "status_extended": r["status_extended"],
                    "resource_type": r["resource_type"],
                }
            )
        resources.sort(key=lambda x: (x["account"], x["region"], x["arn"]))

        regions = sorted({r["region"] for r in recs if r["region"]})
        accounts = sorted({r["account_id"] for r in recs if r["account_id"]})
        services = [r["service"] for r in recs if r["service"]]

        status_extended = []
        for r in recs:
            if r["status_extended"] and r["status_extended"] not in status_extended:
                status_extended.append(r["status_extended"])

        compliance = []
        for r in recs:
            for c in r["compliance"]:
                if c and c not in compliance:
                    compliance.append(c)

        categories = []
        for r in recs:
            for c in r["categories"]:
                if c and c not in categories:
                    categories.append(c)

        findings.append(
            {
                "id": "",
                "key": key,
                "fingerprint": fingerprint(check_id, check_title),
                "check_id": check_id,
                "check_title": check_title,
                "severity": severity,
                "status": status,
                "service": first_non_empty(services),
                "resource_type": first_non_empty([r["resource_type"] for r in recs]),
                "resource_count": len(resources),
                "regions": regions,
                "accounts": accounts,
                "status_extended": status_extended,
                "risk": longest([r["risk"] for r in recs]),
                "description": longest([r["description"] for r in recs]),
                "recommendation": longest([r["recommendation"] for r in recs]),
                "recommendation_url": first_non_empty([r["recommendation_url"] for r in recs]),
                "remediation": {
                    "cli": first_non_empty([r["remediation_cli"] for r in recs]),
                    "terraform": first_non_empty([r["remediation_terraform"] for r in recs]),
                    "native_iac": first_non_empty([r["remediation_native_iac"] for r in recs]),
                    "other": first_non_empty([r["remediation_other"] for r in recs]),
                },
                "compliance": compliance,
                "categories": categories,
                "resources": resources,
            }
        )

    # Order by severity then check id, then assign friendly sequential IDs.
    findings.sort(key=lambda f: (severity_rank(f["severity"]), f["check_id"].lower(), f["check_title"].lower()))
    for i, f in enumerate(findings, start=1):
        f["id"] = f"F-{i:04d}"
    return findings


# ---------------------------------------------------------------------------
# Input discovery
# ---------------------------------------------------------------------------

def find_default_input(folder: Path):
    if not folder.exists():
        return None
    for ext in (".html", ".csv", ".ocsf.json"):
        files = sorted(
            folder.glob("prowler-output-*" + ext),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if files:
            return files[0]
    return None


def resolve_input(raw_input: str):
    p = Path(raw_input).expanduser()
    if p.is_dir():
        found = find_default_input(p)
        if not found:
            raise SystemExit(f"[!] No Prowler output files found in {p}")
        return found
    if not p.exists():
        raise SystemExit(f"[!] Input file not found: {p}")
    return p


def load_records(path: Path):
    name = path.name.lower()
    if name.endswith(".csv"):
        return load_csv(path), "csv"
    if name.endswith(".ocsf.json") or name.endswith(".json"):
        return load_ocsf(path), "ocsf"
    if name.endswith(".html") or name.endswith(".htm"):
        return load_html(path), "html"
    # fall back to sniffing
    head = path.read_text(encoding="utf-8", errors="replace")[:200].lstrip()
    if head.startswith("{") or head.startswith("["):
        return load_ocsf(path), "ocsf"
    if "findingsTable" in path.read_text(encoding="utf-8", errors="replace")[:200000]:
        return load_html(path), "html"
    return load_csv(path), "csv"


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def render_report(findings, meta) -> str:
    payload = {"meta": meta, "findings": findings}
    payload_json = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")

    html = REPORT_TEMPLATE
    html = html.replace("{{TITLE}}", html_escape(meta["title"]))
    html = html.replace("{{SOURCE}}", html_escape(meta["source"]))
    html = html.replace("{{GENERATED}}", html_escape(meta["generated"]))
    html = html.replace("{{DATA_JSON}}", payload_json)
    return html


REPORT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{{TITLE}}</title>
<style>
:root{
  --bg:#f4f6fb; --panel:#ffffff; --panel-2:#fafbff; --text:#101828; --muted:#667085;
  --border:#e4e7ec; --brand:#4f46e5; --brand-2:#7c3aed; --brand-soft:#eef2ff;
  --critical:#b42318; --high:#e04f5f; --medium:#e08a00; --low:#2f6fed; --info:#64748b;
  --ok:#12b76a; --warn:#f79009;
  --radius:12px; --shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.10);
  --shadow-lg:0 10px 30px rgba(16,24,40,.12);
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:var(--bg); color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,Helvetica,Arial,sans-serif;
  font-size:14px; line-height:1.45; -webkit-font-smoothing:antialiased;
}
a{color:var(--brand); text-decoration:none}
a:hover{text-decoration:underline}
code{font-family:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace; font-size:12.5px}
.muted{color:var(--muted)}

/* ---------- layout ---------- */
.wrap{max-width:1600px; margin:0 auto; padding:18px 22px 60px}
header.top{
  position:sticky; top:0; z-index:40;
  background:linear-gradient(135deg,#4f46e5,#7c3aed 60%,#9333ea);
  color:#fff; border-radius:0 0 var(--radius) var(--radius);
  padding:16px 22px; box-shadow:var(--shadow-lg);
}
header.top h1{margin:0; font-size:19px; letter-spacing:.2px; display:flex; align-items:center; gap:10px}
header.top h1 .logo{
  width:26px;height:26px;border-radius:8px;background:rgba(255,255,255,.2);
  display:grid;place-items:center;font-size:14px
}
header.top .sub{margin-top:4px; font-size:12.5px; color:rgba(255,255,255,.85)}
header.top .sub code{color:#fff; background:rgba(255,255,255,.15); padding:1px 6px; border-radius:6px}
.h-actions{margin-left:auto; display:flex; gap:8px; flex-wrap:wrap}
.toprow{display:flex; align-items:center; gap:14px; flex-wrap:wrap}

/* ---------- buttons ---------- */
.btn{
  border:1px solid var(--border); background:var(--panel); color:var(--text);
  padding:7px 12px; border-radius:9px; cursor:pointer; font-size:13px; font-weight:600;
  display:inline-flex; align-items:center; gap:6px; transition:.15s; white-space:nowrap;
}
.btn:hover{border-color:#c7cdd8; background:var(--panel-2)}
.btn.primary{background:var(--brand); border-color:var(--brand); color:#fff}
.btn.primary:hover{background:#4338ca}
.btn.ghost{background:transparent; border-color:rgba(255,255,255,.4); color:#fff}
.btn.ghost:hover{background:rgba(255,255,255,.15)}
.btn.sm{padding:4px 9px; font-size:12px}

/* ---------- cards ---------- */
.cards{display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin:18px 0}
.card{
  background:var(--panel); border:1px solid var(--border); border-radius:var(--radius);
  padding:13px 15px; box-shadow:var(--shadow);
}
.card .k{font-size:11.5px; text-transform:uppercase; letter-spacing:.5px; color:var(--muted); font-weight:700}
.card .v{font-size:25px; font-weight:800; margin-top:3px}
.card .v.small{font-size:16px; font-weight:700}
.card.crit .v{color:var(--critical)} .card.high .v{color:var(--high)}
.card.med .v{color:var(--medium)} .card.low .v{color:var(--low)} .card.info .v{color:var(--info)}

/* ---------- toolbar ---------- */
.progress-stats{font-size:12.5px; color:var(--muted); font-weight:600}
.toolbar{
  position:sticky; top:96px; z-index:30; background:var(--panel);
  border:1px solid var(--border); border-radius:var(--radius); box-shadow:var(--shadow);
  padding:12px 14px; margin-bottom:14px;
}
.trow{display:flex; gap:10px; flex-wrap:wrap; align-items:center}
.trow + .trow{margin-top:10px}
.search{position:relative; flex:1; min-width:240px}
.search input{
  width:100%; padding:9px 12px 9px 34px; border:1px solid var(--border); border-radius:9px;
  font-size:13.5px; background:var(--panel-2); color:var(--text);
}
.search input:focus{outline:none; border-color:var(--brand); box-shadow:0 0 0 3px var(--brand-soft)}
.search .ico{position:absolute; left:11px; top:50%; transform:translateY(-50%); color:var(--muted)}
select.ctl{
  padding:8px 10px; border:1px solid var(--border); border-radius:9px; background:var(--panel-2);
  font-size:13px; color:var(--text); cursor:pointer; max-width:190px;
}
select.ctl:focus{outline:none; border-color:var(--brand)}
label.fl{display:flex; flex-direction:column; gap:3px; font-size:11px; color:var(--muted); font-weight:700; text-transform:uppercase; letter-spacing:.4px}
.chips{display:flex; gap:6px; flex-wrap:wrap}
.sevchip{
  border:1px solid var(--border); background:var(--panel); border-radius:999px; padding:5px 12px;
  cursor:pointer; font-size:12.5px; font-weight:700; color:var(--muted); display:inline-flex; gap:6px; align-items:center;
  transition:.15s; user-select:none;
}
.sevchip .dot{width:8px;height:8px;border-radius:50%;background:currentColor;opacity:.5}
.sevchip.on{color:#fff; border-color:transparent}
.sevchip[data-sev="critical"].on{background:var(--critical)}
.sevchip[data-sev="high"].on{background:var(--high)}
.sevchip[data-sev="medium"].on{background:var(--medium)}
.sevchip[data-sev="low"].on{background:var(--low)}
.sevchip[data-sev="informational"].on{background:var(--info)}
.sevchip .n{background:rgba(0,0,0,.08); border-radius:999px; padding:0 6px; font-size:11px}
.sevchip.on .n{background:rgba(255,255,255,.25)}
.spacer{flex:1}

/* ---------- table ---------- */
.tablewrap{
  background:var(--panel); border:1px solid var(--border); border-radius:var(--radius);
  box-shadow:var(--shadow); overflow:auto; max-height:calc(100vh - 120px);
}
table.findings{width:100%; border-collapse:separate; border-spacing:0; min-width:1180px}
table.findings thead th{
  position:sticky; top:0; z-index:10; background:#f8f9fc; text-align:left; font-size:11.5px;
  text-transform:uppercase; letter-spacing:.5px; color:#475467; padding:11px 10px; border-bottom:1px solid var(--border);
  white-space:nowrap; cursor:pointer; user-select:none;
}
table.findings thead th.no-sort{cursor:default}
table.findings thead th .arrow{opacity:.35; font-size:10px; margin-left:4px}
table.findings thead th.sorted .arrow{opacity:1; color:var(--brand)}
table.findings tbody td{padding:9px 10px; border-bottom:1px solid #f0f2f6; vertical-align:top}
table.findings tbody tr.frow:hover{background:var(--panel-2)}
table.findings tbody tr.frow.sev-critical{box-shadow:inset 3px 0 0 var(--critical)}
table.findings tbody tr.frow.sev-high{box-shadow:inset 3px 0 0 var(--high)}
table.findings tbody tr.frow.sev-medium{box-shadow:inset 3px 0 0 var(--medium)}
table.findings tbody tr.frow.sev-low{box-shadow:inset 3px 0 0 var(--low)}
table.findings tbody tr.frow.sev-informational{box-shadow:inset 3px 0 0 var(--info)}
.c-id{white-space:nowrap; font-weight:700}
.fid{font-family:Consolas,monospace; color:var(--brand); font-weight:800}
.exp{
  border:1px solid var(--border); background:var(--panel); width:20px; height:20px; border-radius:6px;
  cursor:pointer; line-height:1; font-size:11px; color:var(--muted); padding:0;
}
.exp:hover{border-color:var(--brand); color:var(--brand)}
.c-title{min-width:230px; font-weight:600}
.c-check code{background:#f1f3f9; padding:2px 6px; border-radius:6px; white-space:nowrap}
.badge{
  display:inline-block; padding:2px 9px; border-radius:999px; font-size:11px; font-weight:800;
  text-transform:uppercase; letter-spacing:.3px; color:#fff;
}
.badge.sev-critical{background:var(--critical)} .badge.sev-high{background:var(--high)}
.badge.sev-medium{background:var(--medium)} .badge.sev-low{background:var(--low)}
.badge.sev-informational{background:var(--info)} .badge.sev-unknown{background:#94a3b8}
.num{text-align:center}
.count{
  display:inline-block; min-width:30px; padding:2px 8px; border-radius:999px;
  background:var(--brand-soft); color:var(--brand); font-weight:800; font-size:12px;
}
.tag{
  display:inline-block; background:#f1f3f9; color:#475467; border-radius:6px;
  padding:1px 6px; font-size:11px; margin:1px 3px 1px 0; white-space:nowrap;
}

/* ---------- detail ---------- */
tr.drow td{background:#fbfcfe; padding:0; border-bottom:2px solid var(--border)}
.detail{padding:16px 18px}
.detail h4{margin:0 0 6px; font-size:12px; text-transform:uppercase; letter-spacing:.5px; color:var(--muted)}
.detail h4:not(:first-child){margin-top:16px}
.dgrid{display:grid; grid-template-columns:1.35fr 1fr; gap:26px}
.prose{color:#344054; font-size:13.5px}
.chips .chip{
  display:inline-block; background:var(--brand-soft); color:#3730a3; border-radius:7px;
  padding:3px 8px; font-size:11.5px; margin:2px 4px 2px 0;
}
.statuslist{margin:4px 0 0; padding-left:18px; color:#344054; font-size:13px}
pre.code{
  background:#0f172a; color:#e2e8f0; padding:10px 12px; border-radius:9px; overflow:auto;
  font-size:12px; margin:6px 0 0; white-space:pre-wrap; word-break:break-word;
}
.code-label{font-size:11px; font-weight:700; color:var(--muted); text-transform:uppercase; margin-top:10px}
.pill{background:var(--brand); color:#fff; border-radius:999px; padding:1px 9px; font-size:11px; margin-left:6px}
.restable-wrap{max-height:340px; overflow:auto; border:1px solid var(--border); border-radius:10px; margin-top:8px}
table.restable{width:100%; border-collapse:collapse; font-size:12.5px}
table.restable thead th{
  position:sticky; top:0; background:#f8f9fc; text-align:left; padding:8px 10px;
  font-size:11px; text-transform:uppercase; letter-spacing:.4px; color:#475467; border-bottom:1px solid var(--border);
}
table.restable td{padding:7px 10px; border-bottom:1px solid #f0f2f6}
table.restable tr:hover td{background:#f8faff}
table.restable td code{word-break:break-all}

/* ---------- toast ---------- */
#toast{
  position:fixed; bottom:22px; left:50%; transform:translateX(-50%) translateY(20px);
  background:#101828; color:#fff; padding:10px 18px; border-radius:10px; font-size:13px;
  opacity:0; pointer-events:none; transition:.25s; z-index:200; box-shadow:var(--shadow-lg);
}
#toast.show{opacity:1; transform:translateX(-50%) translateY(0)}

.empty{padding:40px; text-align:center; color:var(--muted)}
.footnote{margin-top:14px; font-size:12px; color:var(--muted); text-align:center}

@media (max-width:1000px){ .dgrid{grid-template-columns:1fr} .toolbar{top:0; position:static} }
@media print{
  header.top{position:static; background:#4f46e5 !important; -webkit-print-color-adjust:exact; print-color-adjust:exact}
  .toolbar,.h-actions,.exp{display:none !important}
  .tablewrap{max-height:none; border:none; box-shadow:none}
  tr.drow{display:table-row}
}
</style>
</head>
<body>
<header class="top">
  <div class="toprow">
    <div>
      <h1><span class="logo">&#128737;</span> Prowler Findings Report</h1>
      <div class="sub">
        Source <code>{{SOURCE}}</code> &nbsp;&bull;&nbsp; Generated {{GENERATED}} &nbsp;&bull;&nbsp;
        grouped by <b>check ID + check title</b>
      </div>
    </div>
    <div class="h-actions">
      <button class="btn ghost" id="btnCsv">&#11015; CSV</button>
      <button class="btn ghost" id="btnJson">&#11015; JSON</button>
      <button class="btn ghost" id="btnPrint">&#128424; Print</button>
    </div>
  </div>
</header>

<div class="wrap">
  <div class="cards" id="cards"></div>

  <div class="toolbar">
    <div class="trow">
      <div class="search">
        <span class="ico">&#128269;</span>
        <input id="q" type="search" placeholder="Search by finding ID, check ID, title, service, ARN, region, account..." />
      </div>
      <div class="chips" id="sevchips"></div>
      <div class="spacer"></div>
      <span class="progress-stats"><b id="shown">0</b> / <span id="total">0</span> findings</span>
    </div>
    <div class="trow">
      <label class="fl">Service<select class="ctl" id="fService"></select></label>
      <label class="fl">Region<select class="ctl" id="fRegion"></select></label>
      <label class="fl">Account<select class="ctl" id="fAccount"></select></label>
      <div class="spacer"></div>
      <button class="btn sm" id="clearFilters" style="align-self:flex-end">Clear filters</button>
    </div>
  </div>

  <div class="tablewrap">
    <table class="findings">
      <thead>
        <tr>
          <th data-sort="id">ID<span class="arrow">&#9650;</span></th>
          <th data-sort="severity">Severity<span class="arrow">&#9650;</span></th>
          <th data-sort="check_id">Check ID<span class="arrow">&#9650;</span></th>
          <th data-sort="title">Check Title<span class="arrow">&#9650;</span></th>
          <th data-sort="service">Service<span class="arrow">&#9650;</span></th>
          <th data-sort="resources">Resources<span class="arrow">&#9650;</span></th>
          <th class="no-sort">Regions</th>
          <th class="no-sort">Accounts</th>
        </tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
  </div>

  <div class="footnote">
    Every finding groups all affected resources that share the same check ID and title.<br />
    Report by <b>Laviru Dilshan</b> &mdash; <a href="https://lavirudilshan.com" target="_blank" rel="noopener">lavirudilshan.com</a>
  </div>
</div>

<div id="toast"></div>
<script id="report-data" type="application/json">{{DATA_JSON}}</script>
<script>
(function(){
  "use strict";
  var PAYLOAD = JSON.parse(document.getElementById("report-data").textContent);
  var FINDINGS = PAYLOAD.findings || [];
  var META = PAYLOAD.meta || {};
  var SEV_ORDER = ["critical","high","medium","low","informational"];
  var SEV_RANK = {critical:0, high:1, medium:2, low:3, informational:4, unknown:9};

  function esc(s){
    return String(s === undefined || s === null ? "" : s)
      .replace(/[&<>"']/g, function(c){
        return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c];
      });
  }
  function prose(s){ return esc(s || "-").replace(/\n/g, "<br>"); }
  function debounce(fn, ms){ var t; return function(){ var a=arguments, self=this; clearTimeout(t); t=setTimeout(function(){ fn.apply(self,a); }, ms); }; }

  /* ---------------- state ---------------- */
  var state = {
    search:"",
    severities:new Set(SEV_ORDER.filter(function(s){ return META.severities && META.severities[s]; })),
    service:"", region:"", account:"",
    sortKey:"severity", sortDir:1,
    expanded:new Set()
  };

  FINDINGS.forEach(function(f){
    f._arns = (f.resources||[]).map(function(r){ return r.arn; }).join(" ");
    f._search = (f.id+" "+f.check_id+" "+f.check_title+" "+f.service+" "+f.severity+" "+
                 (f.regions||[]).join(" ")+" "+(f.accounts||[]).join(" ")+" "+f._arns).toLowerCase();
  });

  /* ---------------- filtering / sorting ---------------- */
  function filtered(){
    var q = state.search.trim().toLowerCase();
    return FINDINGS.filter(function(f){
      if(state.severities.size && !state.severities.has(f.severity)) return false;
      if(state.service && f.service !== state.service) return false;
      if(state.region && (f.regions||[]).indexOf(state.region) === -1) return false;
      if(state.account && (f.accounts||[]).indexOf(state.account) === -1) return false;
      if(q && f._search.indexOf(q) === -1) return false;
      return true;
    });
  }
  function sorted(list){
    var key = state.sortKey, dir = state.sortDir;
    return list.slice().sort(function(a,b){
      var av, bv;
      switch(key){
        case "severity": av = SEV_RANK[a.severity]; bv = SEV_RANK[b.severity]; break;
        case "resources": av = a.resource_count; bv = b.resource_count; break;
        case "service": av = a.service; bv = b.service; break;
        case "check_id": av = a.check_id.toLowerCase(); bv = b.check_id.toLowerCase(); break;
        case "title": av = a.check_title.toLowerCase(); bv = b.check_title.toLowerCase(); break;
        default: av = a.id; bv = b.id;
      }
      if(av < bv) return -1*dir;
      if(av > bv) return 1*dir;
      return a.id < b.id ? -1 : 1;
    });
  }

  /* ---------------- rendering ---------------- */
  function tags(list){
    if(!list || !list.length) return '<span class="muted">-</span>';
    return list.map(function(t){ return '<span class="tag">'+esc(t)+"</span>"; }).join("");
  }
  function rowHtml(f){
    var open = state.expanded.has(f.key);
    var cls = "frow sev-" + f.severity;
    return '<tr class="'+cls+'" data-key="'+esc(f.key)+'">'
      + '<td class="c-id"><button class="exp" data-act="toggle" title="Show details">'+(open?"&#9662;":"&#9656;")+'</button> <span class="fid">'+esc(f.id)+"</span></td>"
      + '<td><span class="badge sev-'+esc(f.severity)+'">'+esc(f.severity)+"</span></td>"
      + '<td class="c-check"><code>'+esc(f.check_id)+"</code></td>"
      + '<td class="c-title">'+esc(f.check_title)+"</td>"
      + "<td>"+esc(f.service||"-")+"</td>"
      + '<td class="num"><span class="count">'+f.resource_count+"</span></td>"
      + "<td>"+tags(f.regions)+"</td>"
      + "<td>"+tags(f.accounts)+"</td>"
      + "</tr>"
      + (open ? detailHtml(f) : "");
  }
  function remediationHtml(f){
    var r = f.remediation || {};
    var parts = "";
    function block(label, code){
      if(code) parts += '<div class="code-label">'+label+'</div><pre class="code">'+esc(code)+"</pre>";
    }
    block("CLI", r.cli); block("Terraform", r.terraform); block("Native IaC", r.native_iac); block("Other", r.other);
    return parts ? '<h4>Remediation</h4>'+parts : "";
  }
  function detailHtml(f){
    var rows = (f.resources||[]).map(function(r,i){
      return "<tr><td class='num'>"+(i+1)+"</td><td><code>"+esc(r.arn)+"</code></td><td>"+
        (r.name?esc(r.name):'<span class="muted">-</span>')+"</td><td>"+esc(r.region||"-")+"</td><td>"+
        esc(r.account||"-")+"</td><td>"+esc(r.status_extended||"-")+"</td></tr>";
    }).join("");
    var comp = (f.compliance||[]).length
      ? '<div class="chips">'+f.compliance.map(function(c){return '<span class="chip">'+esc(c)+"</span>";}).join("")+"</div>"
      : '<span class="muted">-</span>';
    var cats = (f.categories||[]).length
      ? "<h4>Categories</h4><div class='chips'>"+f.categories.map(function(c){return '<span class="chip">'+esc(c)+"</span>";}).join("")+"</div>"
      : "";
    var se = (f.status_extended||[]).length
      ? '<ul class="statuslist">'+f.status_extended.map(function(s){return "<li>"+esc(s)+"</li>";}).join("")+"</ul>"
      : '<span class="muted">-</span>';
    return '<tr class="drow" data-key="'+esc(f.key)+'"><td colspan="8"><div class="detail">'
      + '<div class="dgrid"><div class="dcol">'
      + "<h4>Risk / Description</h4><div class='prose'>"+prose(f.risk || f.description)+"</div>"
      + "<h4>Recommendation</h4><div class='prose'>"+prose(f.recommendation)+
          (f.recommendation_url?' <a href="'+esc(f.recommendation_url)+'" target="_blank" rel="noopener">Reference &#8599;</a>':"")+"</div>"
      + remediationHtml(f)
      + '</div><div class="dcol">'
      + "<h4>Compliance</h4>"+comp+cats
      + "<h4>Status Extended</h4>"+se
      + "</div></div>"
      + "<h4>Affected Resources <span class='pill'>"+f.resource_count+"</span></h4>"
      + '<div class="restable-wrap"><table class="restable"><thead><tr><th>#</th><th>Resource ARN / ID</th><th>Name</th><th>Region</th><th>Account</th><th>Status</th></tr></thead><tbody>'
      + rows + "</tbody></table></div>"
      + "</div></td></tr>";
  }

  function render(){
    var list = sorted(filtered());
    document.getElementById("shown").textContent = list.length;
    document.getElementById("total").textContent = FINDINGS.length;
    var tb = document.getElementById("tbody");
    if(!list.length){
      tb.innerHTML = '<tr><td colspan="8"><div class="empty">No findings match the current filters.</div></td></tr>';
    } else {
      tb.innerHTML = list.map(rowHtml).join("");
    }
  }

  /* ---------------- cards ---------------- */
  function renderCards(){
    var bySev = {};
    FINDINGS.forEach(function(f){ bySev[f.severity] = (bySev[f.severity]||0)+1; });
    var totalResources = FINDINGS.reduce(function(a,f){ return a + f.resource_count; }, 0);
    var html = "";
    var sevClass = {critical:"crit", high:"high", medium:"med", low:"low", informational:"info"};
    html += card("Total findings", FINDINGS.length, "");
    SEV_ORDER.forEach(function(s){ if(bySev[s]) html += card(s, bySev[s], sevClass[s] || ""); });
    html += card("Affected resources", totalResources, "");
    html += card("Regions", (META.regions||[]).length, "");
    html += card("Accounts", (META.accounts||[]).length, "");
    document.getElementById("cards").innerHTML = html;
  }
  function card(k, v, cls){
    return '<div class="card '+cls+'"><div class="k">'+esc(k)+'</div><div class="v'+(String(v).length>7?" small":"")+'">'+esc(v)+"</div></div>";
  }

  /* ---------------- filters UI ---------------- */
  function fillSelect(el, values, placeholder, labeler){
    var html = '<option value="">'+esc(placeholder)+"</option>";
    values.forEach(function(v){ html += '<option value="'+esc(v)+'">'+esc(labeler?labeler(v):v)+"</option>"; });
    el.innerHTML = html;
  }
  function buildFilterSelects(){
    fillSelect(document.getElementById("fService"), META.services||[], "All services");
    fillSelect(document.getElementById("fRegion"), META.regions||[], "All regions");
    fillSelect(document.getElementById("fAccount"), (META.accounts||[]).map(function(a){ return a; }), "All accounts", function(a){ return (META.account_names && META.account_names[a]) ? a+" ("+META.account_names[a]+")" : a; });
  }
  function buildSeverityChips(){
    var bySev = {};
    FINDINGS.forEach(function(f){ bySev[f.severity] = (bySev[f.severity]||0)+1; });
    var order = SEV_ORDER.filter(function(s){ return bySev[s]; });
    Object.keys(bySev).forEach(function(s){ if(order.indexOf(s)===-1) order.push(s); });
    document.getElementById("sevchips").innerHTML = order.map(function(s){
      return '<span class="sevchip'+(state.severities.has(s)?" on":"")+'" data-sev="'+esc(s)+'"><span class="dot"></span>'+esc(s)+'<span class="n">'+bySev[s]+"</span></span>";
    }).join("");
  }

  /* ---------------- events ---------------- */
  function toggle(key){
    if(state.expanded.has(key)) state.expanded.delete(key); else state.expanded.add(key);
    render();
  }
  function bind(){
    document.getElementById("q").addEventListener("input", debounce(function(e){
      state.search = e.target.value; render();
    }, 180));

    document.getElementById("sevchips").addEventListener("click", function(e){
      var chip = e.target.closest(".sevchip"); if(!chip) return;
      var s = chip.dataset.sev;
      if(state.severities.has(s)) state.severities.delete(s); else state.severities.add(s);
      chip.classList.toggle("on"); render();
    });

    ["fService","fRegion","fAccount"].forEach(function(id){
      document.getElementById(id).addEventListener("change", function(e){
        var map = {fService:"service", fRegion:"region", fAccount:"account"};
        state[map[id]] = e.target.value; render();
      });
    });

    document.getElementById("clearFilters").addEventListener("click", function(){
      state.search=""; state.severities=new Set(SEV_ORDER); state.service=""; state.region=""; state.account="";
      document.getElementById("q").value="";
      ["fService","fRegion","fAccount"].forEach(function(id){ document.getElementById(id).value=""; });
      buildSeverityChips(); render();
    });

    document.querySelectorAll("th[data-sort]").forEach(function(th){
      th.addEventListener("click", function(){
        var k = th.dataset.sort;
        if(state.sortKey === k) state.sortDir *= -1; else { state.sortKey = k; state.sortDir = 1; }
        document.querySelectorAll("th[data-sort]").forEach(function(x){ x.classList.remove("sorted"); });
        th.classList.add("sorted");
        render();
      });
    });

    var tb = document.getElementById("tbody");
    tb.addEventListener("click", function(e){
      var btn = e.target.closest('[data-act="toggle"]');
      if(btn){ var tr = btn.closest("tr"); if(tr) toggle(tr.dataset.key); }
    });

    document.getElementById("btnPrint").addEventListener("click", function(){ window.print(); });
    document.getElementById("btnCsv").addEventListener("click", exportCsv);
    document.getElementById("btnJson").addEventListener("click", exportJson);
  }

  /* ---------------- export ---------------- */
  function csvCell(v){ v = String(v===undefined||v===null?"":v); return /[",\n]/.test(v) ? '"'+v.replace(/"/g,'""')+'"' : v; }
  function download(name, content, type){
    var blob = new Blob([content], {type:type||"text/plain;charset=utf-8"});
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a"); a.href=url; a.download=name; document.body.appendChild(a); a.click();
    setTimeout(function(){ document.body.removeChild(a); URL.revokeObjectURL(url); }, 200);
  }
  function stamp(){ var d=new Date(); function p(x){return String(x).padStart(2,"0");} return d.getFullYear()+p(d.getMonth()+1)+p(d.getDate())+"-"+p(d.getHours())+p(d.getMinutes()); }
  function exportCsv(){
    var list = sorted(filtered());
    var cols = ["ID","Fingerprint","Severity","Service","CheckID","CheckTitle","Status","ResourceCount","Regions","Accounts","ARNs"];
    var lines = [cols.join(",")];
    list.forEach(function(f){
      lines.push([
        f.id, f.fingerprint, f.severity, f.service, f.check_id, f.check_title, f.status, f.resource_count,
        (f.regions||[]).join("|"), (f.accounts||[]).join("|"),
        (f.resources||[]).map(function(r){ return r.arn; }).join(" | ")
      ].map(csvCell).join(","));
    });
    download("prowler-findings-" + stamp() + ".csv", lines.join("\n"), "text/csv;charset=utf-8");
    toast("Exported " + list.length + " finding(s) to CSV.");
  }
  function exportJson(){
    var list = sorted(filtered());
    var out = list.map(function(f){ return JSON.parse(JSON.stringify(f)); });
    download("prowler-findings-" + stamp() + ".json", JSON.stringify({meta:META, findings:out}, null, 2), "application/json");
    toast("Exported " + list.length + " finding(s) to JSON.");
  }

  /* ---------------- toast ---------------- */
  var toastTimer;
  function toast(msg){
    var t = document.getElementById("toast");
    t.textContent = msg; t.classList.add("show");
    clearTimeout(toastTimer); toastTimer = setTimeout(function(){ t.classList.remove("show"); }, 2600);
  }

  /* ---------------- init ---------------- */
  function init(){
    renderCards();
    buildSeverityChips();
    buildFilterSelects();
    bind();
    document.querySelector('th[data-sort="severity"]').classList.add("sorted");
    render();
  }
  init();
})();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_meta(findings, source: Path, source_format: str, total_records: int):
    by_sev = defaultdict(int)
    for f in findings:
        by_sev[f["severity"]] += 1

    regions = sorted({r for f in findings for r in f["regions"]})
    accounts = sorted({a for f in findings for a in f["accounts"]})
    services = sorted({f["service"] for f in findings if f["service"]})
    total_resources = sum(f["resource_count"] for f in findings)

    account_names = {}
    for f in findings:
        for res in f["resources"]:
            if res["account"] and res.get("account_name"):
                account_names[res["account"]] = res["account_name"]

    return {
        "title": "Prowler Findings Report",
        "source": str(source),
        "source_format": source_format,
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_records": total_records,
        "total_findings": len(findings),
        "total_resources": total_resources,
        "severities": dict(by_sev),
        "regions": regions,
        "accounts": accounts,
        "services": services,
        "account_names": account_names,
    }


def parse_statuses(raw: str):
    raw = (raw or "FAIL").strip()
    if raw.lower() in ("all", "*"):
        return None
    wanted = {s.strip().upper() for s in raw.split(",") if s.strip()}
    return wanted or {"FAIL"}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Convert Prowler output into a reporting-friendly, grouped HTML report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python prowler_report.py\n"
            "  python prowler_report.py output/prowler-output-XXXX.html\n"
            "  python prowler_report.py output/prowler-output-XXXX.csv -o findings.html\n"
            "  python prowler_report.py output --status FAIL,MANUAL --open\n"
        ),
    )
    parser.add_argument("input", nargs="?", default="output",
                        help="Prowler output file (.html/.csv/.ocsf.json) or a folder (default: ./output)")
    parser.add_argument("-o", "--output", default=None,
                        help="Output HTML path (default: <input-dir>/prowler-findings-report.html)")
    parser.add_argument("--status", default="FAIL",
                        help="Comma separated statuses to include, or 'all' (default: FAIL)")
    parser.add_argument("--open", action="store_true", help="Open the report in the default browser")
    args = parser.parse_args(argv)

    source = resolve_input(args.input)
    records, source_format = load_records(source)

    wanted = parse_statuses(args.status)
    if wanted is not None:
        records = [r for r in records if r["status"] in wanted]

    if not records:
        raise SystemExit(f"[!] No records with status {args.status!r} found in {source.name}")

    findings = group_records(records)
    meta = build_meta(findings, source, source_format, len(records))

    if args.output:
        out_path = Path(args.output).expanduser()
    else:
        out_path = source.parent / "prowler-findings-report.html"

    html = render_report(findings, meta)
    out_path.write_text(html, encoding="utf-8")

    print("=" * 68)
    print("  Prowler reporting-friendly report")
    print("=" * 68)
    print(f"  Source          : {source}")
    print(f"  Format          : {source_format}")
    print(f"  Statuses        : {args.status}")
    print(f"  Rows considered : {len(records)}")
    print(f"  Unique findings : {len(findings)}  (grouped by check ID + title)")
    print(f"  Affected ARNs   : {meta['total_resources']}")
    print(f"  Severity        : " + ", ".join(f"{k}={v}" for k, v in sorted(meta["severities"].items(), key=lambda x: severity_rank(x[0]))))
    print(f"  Output          : {out_path}")
    print("=" * 68)

    if args.open:
        webbrowser.open(out_path.resolve().as_uri())
    return 0


if __name__ == "__main__":
    sys.exit(main())
