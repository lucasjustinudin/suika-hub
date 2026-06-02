"""Tests for CLI integration – suika_hub.cli typer app."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from suika_hub.cli import app, build_engine, banner


runner = CliRunner()


class TestBuildEngine:
    def test_build_engine_registers_all_modules(self):
        engine = build_engine()
        expected = [
            "redstorm_scanner",
            "idor_scanner",
            "recon_scanner",
            "api_fuzzer",
            "auth_bypass",
            "upload_scanner",
            "ssrf_scanner",
        ]
        for name in expected:
            assert name in engine.modules, f"Missing module: {name}"

    def test_aliases_created(self):
        engine = build_engine()
        # Aliases are created by stripping _scanner and _module suffixes
        assert "redstorm" in engine.aliases
        assert "idor" in engine.aliases
        assert "recon" in engine.aliases
        # api_fuzzer, auth_bypass, upload_scanner don't have _scanner suffix for all
        # so their full names are also aliases
        assert "api_fuzzer" in engine.aliases
        assert "auth_bypass" in engine.aliases
        assert "upload_scanner" in engine.aliases
        assert "ssrf" in engine.aliases


class TestBanner:
    def test_banner_runs_without_crash(self):
        """Banner should not raise."""
        with patch("suika_hub.cli.console"):
            banner()


class TestModulesCommand:
    def test_modules_command(self):
        result = runner.invoke(app, ["modules"])
        assert result.exit_code == 0
        # Should list all 7 modules
        assert "redstorm" in result.output
        assert "idor" in result.output
        assert "recon" in result.output


class TestScanCommand:
    @patch("suika_hub.cli.asyncio.run")
    @patch("suika_hub.cli.build_engine")
    def test_scan_basic(self, mock_build, mock_run):
        mock_engine = MagicMock()
        mock_build.return_value = mock_engine

        result = runner.invoke(app, [
            "scan",
            "--target", "https://example.com",
            "--module", "recon",
        ])
        assert result.exit_code == 0
        mock_build.assert_called_once()
        mock_run.assert_called_once()

    @patch("suika_hub.cli.asyncio.run")
    @patch("suika_hub.cli.build_engine")
    def test_scan_with_cookie(self, mock_build, mock_run):
        mock_build.return_value = MagicMock()

        result = runner.invoke(app, [
            "scan",
            "-t", "https://example.com",
            "-m", "recon,idor",
            "--cookie", "session=abc123; csrf=xyz",
        ])
        assert result.exit_code == 0

    @patch("suika_hub.cli.asyncio.run")
    @patch("suika_hub.cli.build_engine")
    def test_scan_with_options(self, mock_build, mock_run):
        mock_build.return_value = MagicMock()

        result = runner.invoke(app, [
            "scan",
            "-t", "https://example.com",
            "-m", "recon",
            "--delay", "0.5",
            "--concurrency", "10",
            "--timeout", "30",
            "--output", "/tmp/reports",
            "--verbose",
        ])
        assert result.exit_code == 0

    @patch("suika_hub.cli.asyncio.run")
    @patch("suika_hub.cli.build_engine")
    def test_scan_multiple_modules(self, mock_build, mock_run):
        mock_build.return_value = MagicMock()

        result = runner.invoke(app, [
            "scan",
            "-t", "https://example.com",
            "-m", "redstorm,idor,recon,api,auth,upload,ssrf",
        ])
        assert result.exit_code == 0


class TestRecommendCommand:
    @patch("suika_hub.cli.console")
    def test_recommend_redstorm(self, mock_console):
        result = runner.invoke(app, ["recommend", "--target", "redstorm"])
        assert result.exit_code == 0

    @patch("suika_hub.cli.console")
    def test_recommend_custom_target(self, mock_console):
        result = runner.invoke(app, ["recommend", "--target", "example.com", "--time", "120"])
        assert result.exit_code == 0


class TestImportHarCommand:
    def test_import_har_missing_file(self):
        result = runner.invoke(app, ["import-har", "/nonexistent/file.har"])
        # Should not crash; error handled internally
        # The command will print an error but exit 0 (typer catches it)
        assert result.exit_code == 0
