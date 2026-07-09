"""Tests for core.config – ScanConfig, AuthConfig."""
import json

import yaml

from suika_hub.core.config import AuthConfig, ScanConfig


class TestAuthConfig:
    """Tests for AuthConfig model."""

    def test_default_empty(self):
        auth = AuthConfig()
        assert auth.cookies == {}
        assert auth.headers == {}
        assert auth.bearer_token is None

    def test_with_cookies(self):
        auth = AuthConfig(cookies={"session": "abc", "csrf": "xyz"})
        assert auth.cookies["session"] == "abc"
        assert len(auth.cookies) == 2

    def test_with_headers(self):
        auth = AuthConfig(headers={"Authorization": "Bearer token123"})
        assert auth.headers["Authorization"] == "Bearer token123"

    def test_with_bearer(self):
        auth = AuthConfig(bearer_token="mytoken")
        assert auth.bearer_token == "mytoken"


class TestScanConfig:
    """Tests for ScanConfig model."""

    def test_minimal_config(self):
        cfg = ScanConfig(target="https://example.com")
        assert cfg.target == "https://example.com"
        assert cfg.modules == []
        assert cfg.delay == 1.5
        assert cfg.concurrency == 5
        assert cfg.timeout == 10
        assert cfg.use_browser is False
        assert cfg.proxy is None
        assert cfg.output_dir == "reports"
        assert cfg.verbose is False

    def test_full_config(self):
        cfg = ScanConfig(
            target="https://example.com",
            modules=["recon", "idor"],
            auth=AuthConfig(cookies={"s": "v"}),
            delay=2.0,
            concurrency=10,
            timeout=30,
            use_browser=True,
            proxy="http://proxy:8080",
            output_dir="/tmp/out",
            verbose=True,
        )
        assert cfg.modules == ["recon", "idor"]
        assert cfg.auth.cookies == {"s": "v"}
        assert cfg.proxy == "http://proxy:8080"
        assert cfg.verbose is True

    def test_model_dump(self):
        cfg = ScanConfig(target="https://x.com", modules=["recon"])
        d = cfg.model_dump()
        assert isinstance(d, dict)
        assert d["target"] == "https://x.com"
        assert "auth" in d
        assert "delay" in d

    def test_from_json_file(self, tmp_path):
        data = {
            "target": "https://test.com",
            "modules": ["recon"],
            "delay": 0.5,
        }
        f = tmp_path / "config.json"
        f.write_text(json.dumps(data))
        cfg = ScanConfig.from_file(str(f))
        assert cfg.target == "https://test.com"
        assert cfg.modules == ["recon"]
        assert cfg.delay == 0.5

    def test_from_yaml_file(self, tmp_path):
        data = {
            "target": "https://yaml.com",
            "modules": ["idor", "ssrf"],
            "concurrency": 3,
        }
        f = tmp_path / "config.yaml"
        f.write_text(yaml.dump(data))
        cfg = ScanConfig.from_file(str(f))
        assert cfg.target == "https://yaml.com"
        assert cfg.concurrency == 3

    def test_from_yml_extension(self, tmp_path):
        data = {"target": "https://yml.com"}
        f = tmp_path / "config.yml"
        f.write_text(yaml.dump(data))
        cfg = ScanConfig.from_file(str(f))
        assert cfg.target == "https://yml.com"

    def test_auth_config_default_factory(self):
        """AuthConfig should be independently allocated per ScanConfig."""
        c1 = ScanConfig(target="https://a.com")
        c2 = ScanConfig(target="https://b.com")
        c1.auth.cookies["k"] = "v"
        assert "k" not in c2.auth.cookies
