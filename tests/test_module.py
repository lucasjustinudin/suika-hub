"""Tests for core.module – Finding and BaseModule."""
import pytest

from suika_hub.core.module import BaseModule, Finding


class TestFinding:
    """Tests for the Finding dict subclass."""

    def test_create_basic(self):
        f = Finding(severity="HIGH", title="Test")
        assert f["severity"] == "HIGH"
        assert f["title"] == "Test"

    def test_create_with_kwargs(self):
        f = Finding(
            severity="CRITICAL",
            title="SQLi",
            url="https://example.com/login",
            evidence="sql syntax error",
        )
        assert f["url"] == "https://example.com/login"
        assert f["evidence"] == "sql syntax error"

    def test_is_dict(self):
        f = Finding(severity="LOW", title="Info")
        assert isinstance(f, dict)
        f["custom"] = "value"
        assert f["custom"] == "value"

    def test_dict_operations(self):
        f = Finding(severity="MEDIUM", title="XSS")
        assert "severity" in f
        assert len(f) == 2
        assert f.get("missing") is None


class ConcreteModule(BaseModule):
    """Minimal concrete implementation for testing."""
    name = "test_module"
    description = "Test"

    async def execute(self, target, client, config):
        self.add_finding("INFO", "Test finding", url=target)
        return self.findings


class TestBaseModule:
    """Tests for the abstract BaseModule."""

    def test_instantiation(self):
        mod = ConcreteModule()
        assert mod.name == "test_module"
        assert mod.findings == []

    def test_add_finding(self):
        mod = ConcreteModule()
        f = mod.add_finding("HIGH", "Test", url="https://example.com")
        assert isinstance(f, Finding)
        assert len(mod.findings) == 1
        assert mod.findings[0]["severity"] == "HIGH"

    def test_reset(self):
        mod = ConcreteModule()
        mod.add_finding("LOW", "A")
        mod.add_finding("HIGH", "B")
        assert len(mod.findings) == 2
        mod.reset()
        assert len(mod.findings) == 0

    @pytest.mark.asyncio
    async def test_execute(self):
        mod = ConcreteModule()
        # Mock client
        class FakeClient:
            pass
        findings = await mod.execute("https://target.com", FakeClient(), {})
        assert len(findings) == 1
        assert findings[0]["url"] == "https://target.com"

    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            BaseModule()
