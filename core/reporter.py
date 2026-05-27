"""Report generation - JSON, Markdown, HTML"""
import json
from datetime import datetime
from pathlib import Path
from typing import Dict


class Reporter:
    """Generate scan reports"""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save(self, results: Dict, prefix: str = "scan"):
        """Save results in multiple formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"{prefix}_{timestamp}"

        # JSON
        json_path = self.output_dir / f"{base}.json"
        json_path.write_text(json.dumps(results, indent=2, default=str))

        # Markdown
        md_path = self.output_dir / f"{base}.md"
        md_path.write_text(self._to_markdown(results))

        from rich.console import Console
        console = Console()
        console.print(f"\n[green]Reports saved:[/green]")
        console.print(f"  JSON: {json_path}")
        console.print(f"  Markdown: {md_path}")

    def _to_markdown(self, results: Dict) -> str:
        """Convert results to markdown report"""
        lines = [
            f"# Suika Hunter - Scan Report",
            f"",
            f"**Target:** {results.get('target', 'N/A')}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Duration:** {results.get('stats', {}).get('duration_seconds', 0)}s",
            f"**Modules:** {', '.join(results.get('modules_executed', []))}",
            f"",
            f"## Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]

        for sev, count in results.get("stats", {}).get("by_severity", {}).items():
            lines.append(f"| {sev} | {count} |")

        lines.extend(["", "## Findings", ""])

        for i, finding in enumerate(results.get("findings", []), 1):
            lines.append(f"### {i}. [{finding.get('severity', 'INFO')}] {finding.get('title', 'No title')}")
            lines.append(f"")
            if finding.get("url"):
                lines.append(f"**URL:** `{finding['url']}`")
            if finding.get("description"):
                lines.append(f"**Description:** {finding['description']}")
            if finding.get("evidence"):
                lines.append(f"**Evidence:** {finding['evidence']}")
            if finding.get("impact"):
                lines.append(f"**Impact:** {finding['impact']}")
            if finding.get("remediation"):
                lines.append(f"**Remediation:** {finding['remediation']}")
            lines.append("")

        return "\n".join(lines)
