"""Tests for suika_hub package imports and basic functionality."""
import pytest


class TestImports:
    """Test that all package imports work."""

    def test_package_import(self):
        import suika_hub
        assert hasattr(suika_hub, "__version__")
        assert suika_hub.__version__ == "2.0.0"

    def test_core_config(self):
        from suika_hub.core.config import ScanConfig, AuthConfig
        assert ScanConfig is not None
        assert AuthConfig is not None

    def test_core_engine(self):
        from suika_hub.core.engine import SuikaEngine
        assert SuikaEngine is not None

    def test_core_http(self):
        from suika_hub.core.http import AsyncClient
        assert AsyncClient is not None

    def test_core_module(self):
        from suika_hub.core.module import BaseModule, Finding
        assert BaseModule is not None
        assert Finding is not None

    def test_core_reporter(self):
        from suika_hub.core.reporter import Reporter
        assert Reporter is not None

    def test_core_har_parser(self):
        from suika_hub.core.har_parser import HARParser
        assert HARParser is not None

    def test_core_decision_engine(self):
        from suika_hub.core.decision_engine import DecisionEngine
        assert DecisionEngine is not None

    def test_modules_package(self):
        from suika_hub.modules import (
            RedStormScanner, IDORScanner, ReconScanner,
            APIFuzzer, AuthBypassScanner, FileUploadScanner, SSRFScanner,
        )
        assert RedStormScanner is not None
        assert IDORScanner is not None
        assert ReconScanner is not None
        assert APIFuzzer is not None
        assert AuthBypassScanner is not None
        assert FileUploadScanner is not None
        assert SSRFScanner is not None


class TestConfig:
    """Test ScanConfig and AuthConfig."""

    def test_scan_config_defaults(self):
        from suika_hub.core.config import ScanConfig
        config = ScanConfig(target="https://example.com")
        assert config.target == "https://example.com"
        assert config.modules == []
        assert config.delay == 1.5
        assert config.concurrency == 5
        assert config.timeout == 10
        assert config.use_browser is False
        assert config.verbose is False

    def test_scan_config_custom(self):
        from suika_hub.core.config import ScanConfig, AuthConfig
        config = ScanConfig(
            target="https://example.com",
            modules=["recon", "idor"],
            auth=AuthConfig(cookies={"session": "abc123"}),
            delay=2.0,
            concurrency=10,
        )
        assert config.target == "https://example.com"
        assert config.modules == ["recon", "idor"]
        assert config.auth.cookies == {"session": "abc123"}
        assert config.delay == 2.0
        assert config.concurrency == 10

    def test_auth_config_defaults(self):
        from suika_hub.core.config import AuthConfig
        auth = AuthConfig()
        assert auth.cookies == {}
        assert auth.headers == {}
        assert auth.bearer_token is None


class TestFinding:
    """Test Finding data structure."""

    def test_finding_creation(self):
        from suika_hub.core.module import Finding
        finding = Finding(
            severity="HIGH",
            title="Test Finding",
            url="https://example.com/vuln",
            description="Test description",
        )
        assert finding["severity"] == "HIGH"
        assert finding["title"] == "Test Finding"
        assert finding["url"] == "https://example.com/vuln"

    def test_finding_is_dict(self):
        from suika_hub.core.module import Finding
        finding = Finding(severity="INFO", title="Test")
        assert isinstance(finding, dict)
        assert "severity" in finding
        assert "title" in finding


class TestEngine:
    """Test SuikaEngine registration and module resolution."""

    def test_engine_registration(self):
        from suika_hub.core.engine import SuikaEngine
        from suika_hub.modules import RedStormScanner, IDORScanner

        engine = SuikaEngine()
        engine.register(RedStormScanner)
        engine.register(IDORScanner)

        assert len(engine.modules) == 2
        assert "redstorm_scanner" in engine.modules
        assert "idor_scanner" in engine.modules

    def test_engine_alias_resolution(self):
        from suika_hub.core.engine import SuikaEngine
        from suika_hub.modules import RedStormScanner

        engine = SuikaEngine()
        engine.register(RedStormScanner)

        # Should resolve by alias
        module = engine.resolve("redstorm")
        assert module is not None
        assert module.name == "redstorm_scanner"

        # Should resolve by full name
        module = engine.resolve("redstorm_scanner")
        assert module is not None

        # Should return None for unknown
        module = engine.resolve("nonexistent")
        assert module is None

    def test_engine_register_all_modules(self):
        from suika_hub.core.engine import SuikaEngine
        from suika_hub.modules import (
            RedStormScanner, IDORScanner, ReconScanner,
            APIFuzzer, AuthBypassScanner, FileUploadScanner, SSRFScanner,
        )

        engine = SuikaEngine()
        engine.register(RedStormScanner)
        engine.register(IDORScanner)
        engine.register(ReconScanner)
        engine.register(APIFuzzer)
        engine.register(AuthBypassScanner)
        engine.register(FileUploadScanner)
        engine.register(SSRFScanner)

        assert len(engine.modules) == 7

        # All aliases should work
        for alias in ["redstorm", "idor", "recon", "api_fuzzer", "auth_bypass", "upload_scanner", "ssrf"]:
            module = engine.resolve(alias)
            assert module is not None, f"Failed to resolve alias: {alias}"


class TestDecisionEngine:
    """Test the decision engine recommendations."""

    def test_redstorm_recommendations(self):
        from suika_hub.core.decision_engine import DecisionEngine
        engine = DecisionEngine()
        recs = engine.recommend_for_redstorm()
        assert len(recs) > 0
        assert all("module" in r for r in recs)
        assert all("score" in r for r in recs)
        assert all("time_estimate" in r for r in recs)

    def test_custom_target_recommendations(self):
        from suika_hub.core.decision_engine import DecisionEngine, TargetProfile
        engine = DecisionEngine()
        profile = TargetProfile(domain="example.com", stack=["python"])
        recs = engine.recommend_modules(profile, time_budget=300)
        assert len(recs) > 0


class TestReporter:
    """Test report generation."""

    def test_reporter_creation(self, tmp_path):
        from suika_hub.core.reporter import Reporter
        reporter = Reporter(output_dir=str(tmp_path / "reports"))
        assert reporter.output_dir.exists()


class TestCLI:
    """Test CLI entry point exists and is callable."""

    def test_cli_module_has_app(self):
        from suika_hub.cli import app, main
        assert app is not None
        assert callable(main)
