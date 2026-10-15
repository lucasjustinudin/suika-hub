"""Tests that the package reports one consistent version everywhere.

Three separate version literals existed at one point (package, core, server),
so the banner, the health endpoint and the distribution metadata could disagree.
These tests pin the single-source behaviour.
"""

from __future__ import annotations

import re
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

import suika_hub
from suika_hub import _version
from suika_hub.core import __version__ as core_version

REPO = Path(__file__).resolve().parent.parent
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


class TestVersionConsistency:
    def test_package_version_matches_single_source(self):
        assert suika_hub.__version__ == _version.__version__

    def test_core_version_matches_single_source(self):
        assert core_version == _version.__version__

    def test_version_is_semver(self):
        assert VERSION_RE.match(_version.__version__), _version.__version__

    def test_no_other_version_literal_in_the_package(self):
        """Only _version.py may contain a version literal.

        A second literal is how the banner ended up advertising 2.0 while the
        package was 2.1.
        """
        offenders = []
        for path in (REPO / "suika_hub").rglob("*.py"):
            if path.name == "_version.py":
                continue
            text = path.read_text(encoding="utf-8")
            for match in re.finditer(r"""__version__\s*=\s*["']([^"']+)["']""", text):
                offenders.append(f"{path.relative_to(REPO)}: {match.group(1)}")
        assert not offenders, f"duplicate version literals: {offenders}"

    def test_pyproject_reads_version_dynamically(self):
        data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
        assert "version" in data["project"]["dynamic"], "project.version should be dynamic"
        assert "version" not in data["project"], "a static version would shadow the dynamic one"
        assert data["tool"]["hatch"]["version"]["path"] == "suika_hub/_version.py"

    def test_health_endpoint_reports_package_version(self):
        """The capture server must not hardcode its own version string."""
        source = (REPO / "suika_hub" / "server.py").read_text(encoding="utf-8")
        assert "__version__" in source
        assert not re.search(r'"version"\s*:\s*"[\d.]+"', source), "server hardcodes a version"
