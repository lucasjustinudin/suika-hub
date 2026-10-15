"""Configuration management"""

import json
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class AuthConfig(BaseModel):
    """Authentication configuration"""

    cookies: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    bearer_token: str | None = None


class ScanConfig(BaseModel):
    """Scan configuration."""

    target: str
    modules: list[str] = Field(default_factory=list)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    delay: float = 1.5
    concurrency: int = 5
    timeout: int = 10
    use_browser: bool = False
    proxy: str | None = None
    proxies: list[str] = Field(default_factory=list)
    rate_limit: float = 5.0
    output_dir: str = "reports"
    verbose: bool = False
    # Module-specific passthrough (jwt token, graphql endpoints, module
    # endpoints, ...) so a new module does not require editing this model.
    extra: dict = Field(default_factory=dict)

    def module_config(self) -> dict:
        """Return the dict modules receive, with ``extra`` keys merged in."""
        data = self.model_dump()
        data.update(self.extra or {})
        return data

    @classmethod
    def from_file(cls, path: str) -> "ScanConfig":
        """Load config from JSON or YAML file"""
        p = Path(path)
        content = p.read_text()
        if p.suffix in (".yaml", ".yml"):
            data = yaml.safe_load(content)
        else:
            data = json.loads(content)
        return cls(**data)
