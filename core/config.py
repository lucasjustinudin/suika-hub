"""Configuration management"""
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
import yaml
import json


class AuthConfig(BaseModel):
    """Authentication configuration"""
    cookies: Dict[str, str] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)
    bearer_token: Optional[str] = None


class ScanConfig(BaseModel):
    """Scan configuration"""
    target: str
    modules: List[str] = Field(default_factory=list)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    delay: float = 1.5
    concurrency: int = 5
    timeout: int = 10
    use_browser: bool = False
    proxy: Optional[str] = None
    output_dir: str = "reports"
    verbose: bool = False

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
