"""
Output formatters for Suika Hunter scan results.

Supports:
  - JSON    (standard structured output)
  - SARIF   (GitHub Code Scanning / CodeQL compatible)
  - HTML    (human-readable interactive report)

All formatters accept a list of Finding dicts (the dict-based Finding
class from core.module) and return a string.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── severity mapping helpers ─────────────────────────────────────────────────

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

_SARIF_LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}

_CVSS_MAP = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 3.0,
    "INFO": 0.0,
}

_HTML_SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ef4444",
    "MEDIUM": "#f59e0b",
    "LOW": "#3b82f6",
    "INFO": "#6b7280",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ═════════════════════════════════════════════════════════════════════════════
#  JSON Formatter
# ═════════════════════════════════════════════════════════════════════════════

def format_json(
    findings: List[Dict[str, Any]],
    target: str = "",
    modules: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    pretty: bool = True,
) -> str:
    """Return findings as a JSON string.

    Compatible with the existing Reporter JSON format.
    """
    result = {
        "target": target,
        "modules_executed": modules or [],
        "generated_at": _now_iso(),
        "stats": {
            "total_findings": len(findings),
            "by_severity": _count_severity(findings),
        },
        "findings": findings,
    }
    if metadata:
        result["metadata"] = metadata
    return json.dumps(result, indent=2 if pretty else None, default=str)


def save_json(findings: List[Dict[str, Any]], path: str, **kwargs) -> Path:
    """Write JSON report to file and return the Path."""
    p = Path(path)
    p.write_text(format_json(findings, **kwargs))
    return p


# ═════════════════════════════════════════════════════════════════════════════
#  SARIF 2.1.0  (Static Analysis Results Interchange Format)
# ═════════════════════════════════════════════════════════════════════════════
#  Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
#  GitHub import docs: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning

def format_sarif(
    findings: List[Dict[str, Any]],
    target: str = "",
    tool_name: str = "suika-hunter",
    tool_version: str = "2.0.0",
) -> str:
    """Return findings as a SARIF 2.1.0 JSON string.

    Each Finding maps to one SARIF result.  Rules are derived from the
    finding titles so GitHub can group them properly.
    """
    # Build rules from unique titles
    rules: Dict[str, dict] = {}
    for f in findings:
        title = f.get("title", "Unknown")
        rule_id = _title_to_rule_id(title)
        if rule_id not in rules:
            sev = f.get("severity", "INFO").upper()
            rules[rule_id] = {
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": title},
                "fullDescription": {
                    "text": f.get("description", title),
                },
                "help": {
                    "text": f.get("remediation", "No remediation provided."),
                    "markdown": f.get("remediation", "No remediation provided."),
                },
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL_MAP.get(sev, "note"),
                },
                "properties": {
                    "security-severity": str(_CVSS_MAP.get(sev, 0.0)),
                    "tags": ["security", sev.lower()],
                },
            }

    # Build results
    results = []
    for f in findings:
        title = f.get("title", "Unknown")
        rule_id = _title_to_rule_id(title)
        sev = f.get("severity", "INFO").upper()

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL_MAP.get(sev, "note"),
            "message": {
                "text": f.get("description", title),
            },
            "locations": [],
        }

        # Attach location
        loc_properties: Dict[str, Any] = {}
        url = f.get("url") or f.get("endpoint") or target
        if url:
            loc_properties["url"] = url
        result["locations"].append({
            "physicalLocation": {
                "artifactLocation": {
                    "uri": url or target,
                    "uriBaseId": "%SRCROOT%",
                },
            },
            "properties": loc_properties,
        })

        # Attach evidence as a code snippet
        evidence = f.get("evidence") or f.get("payload")
        if evidence:
            result["codeFlows"] = [{
                "threadFlows": [{
                    "locations": [{
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": url or target,
                                },
                                "region": {
                                    "snippet": {"text": str(evidence)[:1000]},
                                },
                            },
                            "message": {"text": "Evidence"},
                        },
                    }],
                }],
            }]

        # Attach fingerprints for deduplication
        result["partialFingerprints"] = {
            "primaryLocationLineHash": f"{rule_id}:{url}:{sev}",
        }

        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/nousresearch/suika-hunter",
                        "rules": list(rules.values()),
                    },
                },
                "results": results,
                "columnKind": "utf16CodeUnits",
            },
        ],
    }
    return json.dumps(sarif, indent=2, default=str)


def save_sarif(findings: List[Dict[str, Any]], path: str, **kwargs) -> Path:
    """Write SARIF report to file and return the Path."""
    p = Path(path)
    p.write_text(format_sarif(findings, **kwargs))
    return p


# ═════════════════════════════════════════════════════════════════════════════
#  HTML Formatter
# ═════════════════════════════════════════════════════════════════════════════

def format_html(
    findings: List[Dict[str, Any]],
    target: str = "",
    modules: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """Return an interactive HTML report.

    Self-contained (inline CSS + minimal JS) – no external dependencies.
    """
    severity_counts = _count_severity(findings)
    sorted_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "INFO").upper(), 0),
        reverse=True,
    )

    # ── finding rows ─────────────────────────────────────────────────────
    finding_rows = []
    for i, f in enumerate(sorted_findings, 1):
        sev = f.get("severity", "INFO").upper()
        color = _HTML_SEVERITY_COLORS.get(sev, "#6b7280")
        url = f.get("url") or f.get("endpoint") or ""
        desc = _escape_html(f.get("description", ""))
        evidence = _escape_html(str(f.get("evidence", f.get("payload", ""))))
        impact = _escape_html(f.get("impact", ""))
        remediation = _escape_html(f.get("remediation", ""))

        details_html = ""
        if url:
            details_html += f'<div class="detail"><span class="label">URL:</span> <code>{_escape_html(url)}</code></div>'
        if desc:
            details_html += f'<div class="detail"><span class="label">Description:</span> {desc}</div>'
        if evidence:
            details_html += f'<div class="detail"><span class="label">Evidence:</span><pre>{evidence}</pre></div>'
        if impact:
            details_html += f'<div class="detail"><span class="label">Impact:</span> {impact}</div>'
        if remediation:
            details_html += f'<div class="detail"><span class="label">Remediation:</span> {remediation}</div>'

        finding_rows.append(f"""
        <div class="finding" data-severity="{sev}">
            <div class="finding-header" onclick="this.parentElement.classList.toggle('open')">
                <span class="badge" style="background:{color}">{sev}</span>
                <span class="title">{_escape_html(f.get('title', 'No title'))}</span>
                <span class="chevron">▶</span>
            </div>
            <div class="finding-body">
                {details_html}
            </div>
        </div>""")

    # ── severity summary bar ─────────────────────────────────────────────
    summary_bars = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count:
            color = _HTML_SEVERITY_COLORS[sev]
            summary_bars += f'<div class="stat" style="border-left:4px solid {color}"><div class="stat-count">{count}</div><div class="stat-label">{sev}</div></div>'

    modules_str = ", ".join(modules) if modules else "N/A"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Suika Hunter – Scan Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem;max-width:1200px;margin:0 auto}}
h1{{color:#f97316;margin-bottom:.5rem;font-size:1.8rem}}
h2{{color:#94a3b8;font-size:1.2rem;margin-bottom:1.5rem;font-weight:400}}
.meta{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:2rem;padding:1rem;background:#1e293b;border-radius:8px}}
.meta-item{{}}.meta-item .label{{color:#64748b;font-size:.8rem;text-transform:uppercase}}.meta-item .value{{color:#f8fafc;font-size:1rem;font-weight:500}}
.summary{{display:flex;gap:1rem;margin-bottom:2rem;flex-wrap:wrap}}
.stat{{background:#1e293b;padding:1rem 1.5rem;border-radius:8px;min-width:100px;text-align:center}}
.stat-count{{font-size:2rem;font-weight:700;color:#f8fafc}}.stat-label{{font-size:.8rem;color:#94a3b8;text-transform:uppercase}}
.filter-bar{{margin-bottom:1rem;display:flex;gap:.5rem;flex-wrap:wrap}}
.filter-btn{{padding:.4rem 1rem;border:1px solid #334155;border-radius:20px;background:transparent;color:#94a3b8;cursor:pointer;font-size:.85rem}}
.filter-btn:hover,.filter-btn.active{{background:#334155;color:#f8fafc}}
.finding{{background:#1e293b;border-radius:8px;margin-bottom:.5rem;overflow:hidden}}
.finding-header{{display:flex;align-items:center;padding:1rem;cursor:pointer;gap:1rem}}
.finding-header:hover{{background:#334155}}
.badge{{padding:.2rem .6rem;border-radius:4px;font-size:.75rem;font-weight:700;color:#fff;min-width:70px;text-align:center}}
.title{{flex:1;font-weight:500}}.chevron{{color:#64748b;transition:transform .2s;font-size:.8rem}}
.finding-body{{display:none;padding:0 1rem 1rem 3rem}}
.finding.open .finding-body{{display:block}}
.finding.open .chevron{{transform:rotate(90deg)}}
.detail{{margin-bottom:.5rem}}.label{{color:#94a3b8;font-weight:600;margin-right:.5rem}}
pre{{background:#0f172a;padding:.5rem;border-radius:4px;overflow-x:auto;font-size:.85rem;margin-top:.25rem;color:#fbbf24}}
code{{background:#0f172a;padding:.15rem .4rem;border-radius:3px;font-size:.9rem}}
footer{{text-align:center;color:#475569;margin-top:3rem;font-size:.8rem}}
</style>
</head>
<body>
<h1>🍉 Suika Hunter – Scan Report</h1>
<h2>vulnerability scan results</h2>

<div class="meta">
    <div class="meta-item"><div class="label">Target</div><div class="value">{_escape_html(target)}</div></div>
    <div class="meta-item"><div class="label">Modules</div><div class="value">{_escape_html(modules_str)}</div></div>
    <div class="meta-item"><div class="label">Generated</div><div class="value">{_now_iso()}</div></div>
    <div class="meta-item"><div class="label">Total Findings</div><div class="value">{len(findings)}</div></div>
</div>

<div class="summary">{summary_bars}</div>

<div class="filter-bar">
    <button class="filter-btn active" onclick="filterFindings('all')">All</button>
    <button class="filter-btn" onclick="filterFindings('CRITICAL')">Critical</button>
    <button class="filter-btn" onclick="filterFindings('HIGH')">High</button>
    <button class="filter-btn" onclick="filterFindings('MEDIUM')">Medium</button>
    <button class="filter-btn" onclick="filterFindings('LOW')">Low</button>
    <button class="filter-btn" onclick="filterFindings('INFO')">Info</button>
</div>

{"".join(finding_rows)}

<footer>Generated by Suika Hunter v2.0 • {_now_iso()}</footer>
<script>
function filterFindings(sev) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    document.querySelectorAll('.finding').forEach(f => {{
        f.style.display = (sev === 'all' || f.dataset.severity === sev) ? '' : 'none';
    }});
}}
</script>
</body>
</html>"""
    return html


def save_html(findings: List[Dict[str, Any]], path: str, **kwargs) -> Path:
    """Write HTML report to file and return the Path."""
    p = Path(path)
    p.write_text(format_html(findings, **kwargs))
    return p


# ═════════════════════════════════════════════════════════════════════════════
#  Multi-format save (convenience)
# ═════════════════════════════════════════════════════════════════════════════

def save_all_formats(
    findings: List[Dict[str, Any]],
    output_dir: str = "reports",
    prefix: str = "scan",
    **kwargs,
) -> Dict[str, Path]:
    """Save findings in all supported formats.

    Returns dict of {format: path}.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{prefix}_{ts}"
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    target = kwargs.get("target", "")
    modules = kwargs.get("modules")
    metadata = kwargs.get("metadata")

    paths = {}
    paths["json"] = save_json(
        findings, str(out / f"{base}.json"),
        target=target, modules=modules, metadata=metadata,
    )
    paths["sarif"] = save_sarif(
        findings, str(out / f"{base}.sarif"),
        target=target,
    )
    paths["html"] = save_html(
        findings, str(out / f"{base}.html"),
        target=target, modules=modules, metadata=metadata,
    )
    return paths


# ═════════════════════════════════════════════════════════════════════════════
#  Utilities
# ═════════════════════════════════════════════════════════════════════════════

def _count_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _title_to_rule_id(title: str) -> str:
    """Convert a finding title to a SARIF-safe rule ID."""
    import re
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", title).strip("-").lower()
    return slug[:100] if slug else "unknown-finding"


def _escape_html(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
