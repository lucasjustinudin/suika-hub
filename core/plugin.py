"""
Plugin system for Suika Hunter.

Discovery & loading of third-party modules from:
  1. Local plugin directories (~/.suika/plugins/, ./plugins/)
  2. Installed pip packages with entry-point group 'suika.plugins'

Every plugin must export a class that inherits from BaseModule.
"""

import importlib
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Type

from core.module import BaseModule

# ── constants ────────────────────────────────────────────────────────────────
PLUGIN_ENTRY_POINT_GROUP = "suika.plugins"
DEFAULT_PLUGIN_DIRS = [
    Path.home() / ".suika" / "plugins",
    Path.cwd() / "plugins",
]
SUIKA_PLUGINS_DIR = Path.home() / ".suika" / "plugins"


# ── metadata ─────────────────────────────────────────────────────────────────
@dataclass
class PluginInfo:
    """Metadata about a discovered plugin."""
    name: str
    source: str          # "local" | "pip"
    path: Optional[str]  # file path or package name
    module_class: Optional[Type[BaseModule]] = None
    description: str = ""
    version: str = "0.0.0"
    author: str = ""


# ── discovery ────────────────────────────────────────────────────────────────
class PluginManager:
    """Discover, load, list, install and remove plugins."""

    def __init__(self, extra_dirs: Optional[List[str]] = None):
        self.plugins: Dict[str, PluginInfo] = {}
        self._dirs: List[Path] = list(DEFAULT_PLUGIN_DIRS)
        if extra_dirs:
            self._dirs.extend(Path(d) for d in extra_dirs)

    # ── public API ───────────────────────────────────────────────────────
    def discover(self) -> List[PluginInfo]:
        """Run all discovery mechanisms and return found plugins."""
        self._discover_local()
        self._discover_pip()
        return list(self.plugins.values())

    def load(self, name: str) -> Optional[Type[BaseModule]]:
        """Load a plugin by name and return its module class."""
        info = self.plugins.get(name)
        if info and info.module_class:
            return info.module_class

        # Try on-demand loading
        for info in self.plugins.values():
            if info.name == name and not info.module_class:
                cls = self._load_class(info)
                if cls:
                    info.module_class = cls
                    return cls
        return None

    def get_all_classes(self) -> List[Type[BaseModule]]:
        """Return all discovered plugin classes (loads lazily)."""
        classes = []
        for info in list(self.plugins.values()):
            if not info.module_class:
                info.module_class = self._load_class(info)
            if info.module_class:
                classes.append(info.module_class)
        return classes

    def list_plugins(self) -> List[PluginInfo]:
        """Return list of PluginInfo for all discovered plugins."""
        return list(self.plugins.values())

    # ── install / remove ─────────────────────────────────────────────────
    @staticmethod
    def install_package(spec: str) -> PluginInfo:
        """Install a plugin via pip and return its PluginInfo.

        `spec` can be:
          - a PyPI package name  (e.g. "suika-plugin-xss-pro")
          - a git URL            (e.g. "git+https://github.com/user/plugin.git")
          - a local directory    (e.g. "/path/to/plugin/")
        """
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", spec],
        )

        # Try to find it via entry-points right away
        ep_name = spec.split("/")[-1].split(".")[0]  # best-guess name
        info = PluginInfo(name=ep_name, source="pip", path=spec)

        # Look for the actual entry-point
        try:
            eps = importlib.metadata.entry_points()
            group_eps = eps.select(group=PLUGIN_ENTRY_POINT_GROUP) if hasattr(eps, "select") else eps.get(PLUGIN_ENTRY_POINT_GROUP, [])
            for ep in group_eps:
                try:
                    cls = ep.load()
                    if isinstance(cls, type) and issubclass(cls, BaseModule) and cls is not BaseModule:
                        info.name = ep.name
                        info.module_class = cls
                        info.description = cls.__doc__ or ""
                        break
                except Exception:
                    continue
        except Exception:
            pass

        return info

    @staticmethod
    def install_local(plugin_dir: str, symlink: bool = True) -> PluginInfo:
        """Install a local plugin directory into ~/.suika/plugins/."""
        src = Path(plugin_dir).resolve()
        if not src.is_dir():
            raise FileNotFoundError(f"Plugin directory not found: {src}")

        SUIKA_PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
        dest = SUIKA_PLUGINS_DIR / src.name

        if dest.exists():
            shutil.rmtree(dest)

        if symlink:
            dest.symlink_to(src)
        else:
            shutil.copytree(src, dest)

        return PluginInfo(name=src.name, source="local", path=str(dest))

    @staticmethod
    def remove_package(name: str) -> bool:
        """Uninstall a pip-installed plugin."""
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "uninstall", "--yes", name],
            )
            return True
        except subprocess.CalledProcessError:
            return False

    @staticmethod
    def remove_local(name: str) -> bool:
        """Remove a local plugin directory from ~/.suika/plugins/."""
        target = SUIKA_PLUGINS_DIR / name
        if target.exists() or target.is_symlink():
            if target.is_symlink():
                target.unlink()
            else:
                shutil.rmtree(target)
            return True
        return False

    # ── internal ─────────────────────────────────────────────────────────
    def _discover_local(self):
        """Walk plugin directories for Python modules/packages."""
        for pdir in self._dirs:
            if not pdir.is_dir():
                continue
            for item in sorted(pdir.iterdir()):
                if item.name.startswith("_") or item.name.startswith("."):
                    continue

                info = None
                # ── package (directory with __init__.py) ─────────────────
                if item.is_dir() and (item / "__init__.py").exists():
                    info = self._probe_package(item)
                # ── single .py file ──────────────────────────────────────
                elif item.suffix == ".py":
                    info = self._probe_module(item)

                if info:
                    self.plugins[info.name] = info

    def _discover_pip(self):
        """Discover plugins installed as pip packages via entry-points."""
        try:
            eps = importlib.metadata.entry_points()
            group_eps = eps.select(group=PLUGIN_ENTRY_POINT_GROUP) if hasattr(eps, "select") else eps.get(PLUGIN_ENTRY_POINT_GROUP, [])
            for ep in group_eps:
                info = PluginInfo(
                    name=ep.name,
                    source="pip",
                    path=ep.value,
                )
                # Try eager loading to grab metadata
                try:
                    cls = ep.load()
                    if isinstance(cls, type) and issubclass(cls, BaseModule) and cls is not BaseModule:
                        info.module_class = cls
                        info.description = cls.__doc__ or ""
                        instance = cls()
                        info.name = instance.name
                except Exception:
                    pass
                self.plugins[info.name] = info
        except Exception:
            pass

    def _probe_package(self, pkg_dir: Path) -> Optional[PluginInfo]:
        """Try importing a package directory and find BaseModule subclasses."""
        sys.path.insert(0, str(pkg_dir.parent))
        try:
            mod = importlib.import_module(pkg_dir.name)
            cls = self._find_base_module(mod)
            if cls:
                instance = cls()
                return PluginInfo(
                    name=instance.name,
                    source="local",
                    path=str(pkg_dir),
                    module_class=cls,
                    description=cls.__doc__ or "",
                    version=getattr(mod, "__version__", "0.0.0"),
                    author=getattr(mod, "__author__", ""),
                )
        except Exception:
            pass
        finally:
            sys.path.pop(0)
        return None

    def _probe_module(self, py_file: Path) -> Optional[PluginInfo]:
        """Try importing a single .py file and find BaseModule subclasses."""
        spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
        if not spec or not spec.loader:
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(py_file.parent))
        try:
            spec.loader.exec_module(mod)
            cls = self._find_base_module(mod)
            if cls:
                instance = cls()
                return PluginInfo(
                    name=instance.name,
                    source="local",
                    path=str(py_file),
                    module_class=cls,
                    description=cls.__doc__ or "",
                    version=getattr(mod, "__version__", "0.0.0"),
                    author=getattr(mod, "__author__", ""),
                )
        except Exception:
            pass
        finally:
            sys.path.pop(0)
        return None

    def _load_class(self, info: PluginInfo) -> Optional[Type[BaseModule]]:
        """Load module class from PluginInfo."""
        if info.module_class:
            return info.module_class
        if info.source == "local" and info.path:
            p = Path(info.path)
            if p.is_dir():
                return self._probe_package(p).module_class if self._probe_package(p) else None
            elif p.suffix == ".py":
                return self._probe_module(p).module_class if self._probe_module(p) else None
        return None

    @staticmethod
    def _find_base_module(module) -> Optional[Type[BaseModule]]:
        """Find the first BaseModule subclass in a module."""
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseModule)
                and attr is not BaseModule
                and not getattr(attr, "_abstract", False)
            ):
                return attr
        return None


# ── plugin manifest helpers ──────────────────────────────────────────────────
def create_plugin_manifest(
    name: str,
    version: str = "0.1.0",
    author: str = "",
    description: str = "",
    modules: Optional[List[str]] = None,
) -> dict:
    """Create a standard plugin manifest dict."""
    return {
        "name": name,
        "version": version,
        "author": author,
        "description": description,
        "suika_version": ">=2.0.0",
        "modules": modules or [name],
        "entry_point": f"{name}:get_module",
    }


def save_plugin_manifest(manifest: dict, path: str = "plugin.json"):
    """Write manifest to disk."""
    Path(path).write_text(json.dumps(manifest, indent=2) + "\n")
