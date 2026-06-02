"""Tests for core.reporter – JSON + Markdown report generation."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from suika_hub.core.reporter import Reporter
from suika_hub.core.module import Finding


class TestReporter:
    """Tests for the Reporter class."""

    def test_init_creates_dir(self, tmp_path):
        out = tmp_path / "new_reports"
        Reporter(str(out))
        assert out.is_dir()

    def test_save_creates_json(self, tmp_path, sample_findings):
        reporter = Reporter(str(tmp_path))
        results = {
            "target": "https://example.com",
            "modules_executed": ["recon"],
            "findings": sample_findings,
            "stats": {
                "duration_seconds": 5.0,
                "total_findings": len(sample_findings),
                "by_severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 1},
            },
        }
        with patch("rich.console.Console"):
            reporter.save(results, prefix="test")

        json_files = list(tmp_path.glob("test_*.json"))
        assert len(json_files) == 1
        data = json.loads(json_files[0].read_text())
        assert data["target"] == "https://example.com"
        assert len(data["findings"]) == 5

    def test_save_creates_markdown(self, tmp_path, sample_findings):
        reporter = Reporter(str(tmp_path))
        results = {
            "target": "https://example.com",
            "modules_executed": ["idor", "recon"],
            "findings": sample_findings,
            "stats": {
                "duration_seconds": 12.5,
                "total_findings": len(sample_findings),
                "by_severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 1},
            },
        }
        with patch("rich.console.Console"):
            reporter.save(results, prefix="md_test")

        md_files = list(tmp_path.glob("md_test_*.md"))
        assert len(md_files) == 1
        content = md_files[0].read_text()
        assert "# Suika Hunter - Scan Report" in content
        assert "https://example.com" in content
        assert "CRITICAL" in content


class TestMarkdownFormatting:
    """Tests for _to_markdown method."""

    def _get_markdown(self, results):
        reporter = Reporter.__new__(Reporter)
        return reporter._to_markdown(results)

    def test_header_present(self):
        md = self._get_markdown({"target": "t", "stats": {}, "modules_executed": [], "findings": []})
        assert "# Suika Hunter - Scan Report" in md

    def test_target_in_report(self):
        md = self._get_markdown({"target": "https://target.com", "stats": {}, "modules_executed": [], "findings": []})
        assert "https://target.com" in md

    def test_severity_table(self):
        results = {
            "target": "t",
            "stats": {"by_severity": {"HIGH": 3, "LOW": 1}},
            "modules_executed": [],
            "findings": [],
        }
        md = self._get_markdown(results)
        assert "| HIGH | 3 |" in md
        assert "| LOW | 1 |" in md

    def test_findings_in_report(self):
        results = {
            "target": "t",
            "stats": {},
            "modules_executed": [],
            "findings": [
                {
                    "severity": "CRITICAL",
                    "title": "SQL Injection",
                    "url": "https://t.com/login",
                    "description": "SQLi found",
                    "evidence": "Error message",
                    "impact": "Full DB access",
                    "remediation": "Use parameterized queries",
                },
            ],
        }
        md = self._get_markdown(results)
        assert "SQL Injection" in md
        assert "CRITICAL" in md
        assert "https://t.com/login" in md
        assert "Full DB access" in md
        assert "parameterized queries" in md

    def test_empty_findings(self):
        results = {"target": "t", "stats": {}, "modules_executed": [], "findings": []}
        md = self._get_markdown(results)
        assert "## Findings" in md

    def test_duration_in_report(self):
        results = {
            "target": "t",
            "stats": {"duration_seconds": 42.5},
            "modules_executed": ["recon"],
            "findings": [],
        }
        md = self._get_markdown(results)
        assert "42.5" in md
        assert "recon" in md
