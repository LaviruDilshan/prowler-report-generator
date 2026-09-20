# Prowler Report Generator

Turn raw [Prowler](https://github.com/prowler-cloud/prowler) scan output into a
**reporting-friendly, searchable HTML report**.

Prowler reports **one row per affected resource**, so the same check (same
`CHECK_ID` + same `CHECK_TITLE`) is repeated once for every affected ARN. That is
accurate but not report friendly — a scan with 850 failed rows can really be only
~150 unique findings.

This tool groups every row that shares the **same check ID and check title** into
**one finding**, collects **all affected ARNs** (with region / account / name),
assigns each finding a short ID (`F-0001`, `F-0002`, ...) and writes a modern,
self-contained HTML report.

---

## Features

- **Smart grouping** — one finding per check ID + check title, with every affected ARN listed.
- **Auto-detects input format** — Prowler `.html`, `.csv` or `.ocsf.json` output.
- **Modern report UI** — clean, responsive, offline (no CDN, no internet needed).
- **Search** — across finding ID, check ID, title, service, ARN, region, account.
- **Filters** — severity, service, region, account.
- **Sortable columns** — ID, severity, check ID, title, service, resource count.
- **Expandable detail rows** — risk/description, recommendation + reference link,
  remediation code (CLI / Terraform / Native IaC / Other), compliance, and the
  full table of affected resources.
- **Export** — download the current view as CSV or JSON, or print.
- **Zero dependencies** — Python standard library only.

---

## Requirements

- Python **3.8+** (tested on 3.14)
- No third-party packages

---

## Quick start

```bash
# Run from the folder that contains your Prowler "output" directory
python prowler_report.py
```

This finds the newest Prowler output in `./output` and writes
`output/prowler-findings-report.html`.

### Common usage

```bash
# Point at a specific file
python prowler_report.py output/prowler-output-XXXX.html

# Use the CSV or OCSF JSON instead (richer data: description + remediation code)
python prowler_report.py output/prowler-output-XXXX.csv -o findings.html

# Include more than FAIL (or everything)
python prowler_report.py output/prowler-output-XXXX.html --status FAIL,MANUAL
python prowler_report.py output/prowler-output-XXXX.html --status all

# Generate and open the report in your browser
python prowler_report.py output --open
```

### Options

| Option | Description |
| --- | --- |
| `input` | Prowler output file (`.html` / `.csv` / `.ocsf.json`) **or** a folder. Default: `output` |
| `-o, --output` | Output HTML path. Default: `<input-dir>/prowler-findings-report.html` |
| `--status` | Comma-separated statuses to include, or `all`. Default: `FAIL` |
| `--open` | Open the generated report in the default browser |
| `-h, --help` | Show help |

---

## How grouping works

For every row, the script builds a key from:

```
CHECK_ID + "||" + CHECK_TITLE
```

All rows with the same key become **one finding**:

| Field | How it is aggregated |
| --- | --- |
| Severity | Most severe severity in the group |
| Status | `FAIL` wins, then `MANUAL`, then any other |
| Resources | Unique ARNs, sorted by account → region → ARN |
| Regions / Accounts | Unique values across the group |
| Risk / Recommendation | Longest non-empty value in the group |
| Remediation | First non-empty value per code type |
| Compliance / Categories | Unique values, merged |

Findings are sorted by severity (critical → informational) then by check ID, and
numbered `F-0001`, `F-0002`, ... A stable 8-character `fingerprint` is also stored
for each finding (useful if you build automations on top).

---

## Output

A single self-contained `.html` file. Open it in any browser — it works offline
and needs no server.

Example result for a real scan:

```
Rows considered : 850
Unique findings : 151   (grouped by check ID + title)
Affected ARNs   : 841
Severity        : critical=2, high=19, medium=103, low=27
```

---

## Project structure

```
prowler-report-generator/
├── prowler_report.py   # the generator
└── README.md
```

---

## Notes

- The `.html` Prowler output contains only `FAIL` + `MANUAL` rows; the `.csv` and
  `.ocsf.json` outputs contain every status. All three produce identical findings
  for the same status filter, but CSV/OCSF include extra fields such as the check
  description and remediation code.
- The generated report is **static**. It has no login, no database and no saved
  state — just open and read it.

---

## Author

**Laviru Dilshan** — [lavirudilshan.com](https://lavirudilshan.com)
