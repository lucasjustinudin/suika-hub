"""Tests for report formatting (Markdown output from Reporter).

The project doesn't have a separate formatters module; formatting logic
lives in core.reporter._to_markdown.  This test file covers edge cases
in that formatting path.
"""
from suika_hub.core.reporter import Reporter


class TestMarkdownEdgeCases:
    """Edge-case coverage for _to_markdown."""

    def _fmt(self, results):
        r = Reporter.__new__(Reporter)
        return r._to_markdown(results)

    def test_empty_results(self):
        md = self._fmt({})
        assert "# suika-hub Scan Report" in md
        assert "N/A" in md  # target defaults to N/A

    def test_no_stats_key(self):
        md = self._fmt({"target": "t", "findings": []})
        assert "0s" in md  # duration defaults to 0

    def test_no_modules(self):
        md = self._fmt({"target": "t", "stats": {}, "findings": []})
        assert "**Modules:** " in md

    def test_multiple_findings_ordering(self):
        findings = [
            {"severity": "LOW", "title": "Low finding"},
            {"severity": "CRITICAL", "title": "Critical finding"},
            {"severity": "MEDIUM", "title": "Medium finding"},
        ]
        md = self._fmt({"target": "t", "stats": {}, "modules_executed": [], "findings": findings})
        assert "1. [LOW] Low finding" in md
        assert "2. [CRITICAL] Critical finding" in md
        assert "3. [MEDIUM] Medium finding" in md

    def test_finding_with_only_title(self):
        findings = [{"title": "Minimal finding"}]
        md = self._fmt({"target": "t", "stats": {}, "modules_executed": [], "findings": findings})
        assert "Minimal finding" in md
        assert "[INFO]" in md  # defaults to INFO

    def test_finding_with_all_fields(self):
        findings = [
            {
                "severity": "HIGH",
                "title": "Full finding",
                "url": "https://example.com/vuln",
                "description": "Desc text",
                "evidence": "Evidence text",
                "impact": "Impact text",
                "remediation": "Fix text",
            }
        ]
        md = self._fmt({"target": "t", "stats": {}, "modules_executed": [], "findings": findings})
        assert "Full finding" in md
        assert "Desc text" in md
        assert "Evidence text" in md
        assert "Impact text" in md
        assert "Fix text" in md
        assert "https://example.com/vuln" in md

    def test_severity_table_multiple(self):
        stats = {"by_severity": {"CRITICAL": 2, "HIGH": 5, "MEDIUM": 10, "LOW": 3, "INFO": 20}}
        md = self._fmt({"target": "t", "stats": stats, "modules_executed": [], "findings": []})
        assert "| CRITICAL | 2 |" in md
        assert "| HIGH | 5 |" in md
        assert "| INFO | 20 |" in md

    def test_report_structure_sections(self):
        md = self._fmt({"target": "t", "stats": {}, "modules_executed": ["recon"], "findings": []})
        assert "# suika-hub Scan Report" in md
        assert "**Target:**" in md
        assert "**Date:**" in md
        assert "**Duration:**" in md
        assert "**Modules:**" in md
        assert "## Summary" in md
        assert "## Findings" in md
