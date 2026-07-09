"""Tests for core.engine – SuikaEngine."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from suika_hub.core.engine import SuikaEngine
from suika_hub.core.module import BaseModule, Finding

# ---------------------------------------------------------------------------
# Stub modules
# ---------------------------------------------------------------------------

class StubModuleA(BaseModule):
    name = "stub_a_scanner"
    description = "Stub A"

    async def execute(self, target, client, config):
        self.add_finding("HIGH", "Finding from A", url=target)
        return self.findings


class StubModuleB(BaseModule):
    name = "stub_b"
    description = "Stub B"

    async def execute(self, target, client, config):
        self.add_finding("LOW", "Finding from B", url=target)
        self.add_finding("INFO", "Info from B")
        return self.findings


class ErrorModule(BaseModule):
    name = "error_scanner"
    description = "Always raises"

    async def execute(self, target, client, config):
        raise RuntimeError("Module crashed")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSuikaEngineRegistration:
    def test_register_module(self):
        engine = SuikaEngine()
        engine.register(StubModuleA)
        assert "stub_a_scanner" in engine.modules
        assert engine.modules["stub_a_scanner"].name == "stub_a_scanner"

    def test_auto_alias(self):
        engine = SuikaEngine()
        engine.register(StubModuleA)
        # "stub_a_scanner" -> alias "stub_a" (removing _scanner)
        assert engine.aliases.get("stub_a") == "stub_a_scanner"
        assert engine.aliases.get("stub_a_scanner") == "stub_a_scanner"

    def test_resolve_by_name(self):
        engine = SuikaEngine()
        engine.register(StubModuleA)
        mod = engine.resolve("stub_a_scanner")
        assert mod is not None
        assert mod.name == "stub_a_scanner"

    def test_resolve_by_alias(self):
        engine = SuikaEngine()
        engine.register(StubModuleA)
        mod = engine.resolve("stub_a")
        assert mod is not None

    def test_resolve_unknown(self):
        engine = SuikaEngine()
        assert engine.resolve("nonexistent") is None

    def test_register_multiple(self):
        engine = SuikaEngine()
        engine.register(StubModuleA)
        engine.register(StubModuleB)
        assert len(engine.modules) == 2

    def test_alias_without_suffix(self):
        """Module name without _scanner suffix should still be its own alias."""
        engine = SuikaEngine()
        engine.register(StubModuleB)
        assert engine.aliases.get("stub_b") == "stub_b"


class TestSuikaEngineHelpers:
    def test_count_severity_empty(self):
        engine = SuikaEngine()
        counts = engine._count_severity([])
        assert counts == {}

    def test_count_severity(self, sample_findings):
        engine = SuikaEngine()
        counts = engine._count_severity(sample_findings)
        assert counts["CRITICAL"] == 1
        assert counts["HIGH"] == 1
        assert counts["MEDIUM"] == 1
        assert counts["LOW"] == 1
        assert counts["INFO"] == 1

    def test_count_severity_missing_key(self):
        engine = SuikaEngine()
        f = Finding(severity="HIGH", title="test")
        # Remove severity to test default
        del f["severity"]
        counts = engine._count_severity([f])
        assert counts.get("INFO") == 1  # defaults to INFO


class TestSuikaEngineRun:
    @pytest.mark.asyncio
    async def test_run_single_module(self, tmp_path):
        from suika_hub.core.config import AuthConfig, ScanConfig

        engine = SuikaEngine()
        engine.register(StubModuleA)

        config = ScanConfig(
            target="https://example.com",
            modules=["stub_a"],
            auth=AuthConfig(),
            delay=0,
            concurrency=1,
            output_dir=str(tmp_path),
        )

        # Mock AsyncClient to avoid real HTTP
        with patch("suika_hub.core.engine.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            with patch("suika_hub.core.engine.Reporter") as MockReporter:
                mock_reporter = MagicMock()
                MockReporter.return_value = mock_reporter

                result = await engine.run(config)

        assert result["target"] == "https://example.com"
        assert "stub_a_scanner" in result["modules_executed"]
        assert result["stats"]["total_findings"] == 1
        assert result["stats"]["by_severity"]["HIGH"] == 1

    @pytest.mark.asyncio
    async def test_run_multiple_modules(self, tmp_path):
        from suika_hub.core.config import AuthConfig, ScanConfig

        engine = SuikaEngine()
        engine.register(StubModuleA)
        engine.register(StubModuleB)

        config = ScanConfig(
            target="https://example.com",
            modules=["stub_a", "stub_b"],
            auth=AuthConfig(),
            delay=0,
            concurrency=2,
            output_dir=str(tmp_path),
        )

        with patch("suika_hub.core.engine.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            with patch("suika_hub.core.engine.Reporter"):
                result = await engine.run(config)

        assert len(result["modules_executed"]) == 2
        assert result["stats"]["total_findings"] == 3

    @pytest.mark.asyncio
    async def test_run_unknown_module_skipped(self, tmp_path):
        from suika_hub.core.config import AuthConfig, ScanConfig

        engine = SuikaEngine()
        engine.register(StubModuleA)

        config = ScanConfig(
            target="https://example.com",
            modules=["nonexistent", "stub_a"],
            auth=AuthConfig(),
            delay=0,
            output_dir=str(tmp_path),
        )

        with patch("suika_hub.core.engine.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            with patch("suika_hub.core.engine.Reporter"):
                result = await engine.run(config)

        assert "nonexistent" not in result["modules_executed"]
        assert "stub_a_scanner" in result["modules_executed"]

    @pytest.mark.asyncio
    async def test_run_module_error_caught(self, tmp_path):
        from suika_hub.core.config import AuthConfig, ScanConfig

        engine = SuikaEngine()
        engine.register(ErrorModule)

        config = ScanConfig(
            target="https://example.com",
            modules=["error"],
            auth=AuthConfig(),
            delay=0,
            output_dir=str(tmp_path),
        )

        with patch("suika_hub.core.engine.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            with patch("suika_hub.core.engine.Reporter"):
                result = await engine.run(config)

        # Error module should not crash the engine
        assert result["stats"]["total_findings"] == 0
        assert "error_scanner" not in result["modules_executed"]
