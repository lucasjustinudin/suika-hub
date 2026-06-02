"""Base module class - async"""
from abc import ABC, abstractmethod

from suika_hub.core.http import AsyncClient


class Finding(dict):
    """Structured finding"""
    def __init__(self, severity: str, title: str, **kwargs):
        super().__init__(
            severity=severity,
            title=title,
            **kwargs
        )


class BaseModule(ABC):
    """Abstract base class for all scanner modules"""

    name: str = "base"
    description: str = "Base module"

    def __init__(self):
        self.findings: list[Finding] = []

    @abstractmethod
    async def execute(self, target: str, client: AsyncClient, config: dict) -> list[Finding]:
        """Execute module against target. Must be implemented by subclass."""
        pass

    def add_finding(self, severity: str, title: str, **kwargs) -> Finding:
        """Add a finding"""
        finding = Finding(severity=severity, title=title, **kwargs)
        self.findings.append(finding)
        return finding

    def reset(self):
        """Reset findings for fresh run"""
        self.findings = []
