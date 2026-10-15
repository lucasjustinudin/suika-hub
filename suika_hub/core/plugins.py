"""Plugin discovery and loading.

Two discovery paths, both returning module *classes* (not instances) so the
caller decides what to register:

1. **Installed distributions** -- any package declaring an entry point in the
   ``suika.plugins`` group. This is the path for pip-installed plugins.
2. **Local directories** -- a directory containing a module that exposes
   ``get_module()``. This is the path for development and for plugins you do not
   want to publish.

A plugin that fails to load never aborts discovery: the failure is recorded and
reported, because one broken third-party plugin must not make the scanner
unusable. That is also why loading is explicit (a CLI flag or an API call)
rather than automatic on every run -- untrusted code should not execute merely
because the tool started.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path

from suika_hub.core.module import BaseModule

ENTRY_POINT_GROUP = "suika.plugins"


@dataclass
class PluginLoadResult:
    """Outcome of a discovery attempt.

    ``loaded`` and ``errors`` are both populated rather than raising, so a
    caller can register everything that worked and still surface what did not.
    """

    loaded: list[type[BaseModule]] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)

    def add_error(self, name: str, message: str) -> None:
        self.errors.append((name, message))

    @property
    def ok(self) -> bool:
        return not self.errors


def _validate(candidate: object, source: str) -> type[BaseModule]:
    """Return the class if it is a usable scanner module, else raise."""
    if not isinstance(candidate, type):
        raise TypeError(f"{source} returned {type(candidate).__name__}, expected a class")
    if not issubclass(candidate, BaseModule):
        raise TypeError(f"{source} returned {candidate.__name__}, which does not subclass BaseModule")
    if candidate is BaseModule:
        raise TypeError(f"{source} returned BaseModule itself")
    if not getattr(candidate, "name", "") or candidate.name == "base":
        raise ValueError(f"{source} class {candidate.__name__} does not set a unique 'name' attribute")
    return candidate


def load_from_entry_points() -> PluginLoadResult:
    """Discover plugins installed as distributions in the ``suika.plugins`` group."""
    result = PluginLoadResult()

    try:
        from importlib.metadata import entry_points
    except ImportError:  # pragma: no cover - Python < 3.10
        return result

    try:
        discovered = list(entry_points(group=ENTRY_POINT_GROUP))
    except TypeError:  # pragma: no cover - legacy selectable API (Python < 3.10)
        # On older importlib.metadata, entry_points() returns a dict of group
        # name -> EntryPoints and takes no `group` kwarg.
        legacy = entry_points()
        discovered = list(legacy.get(ENTRY_POINT_GROUP, []))  # type: ignore[attr-defined]

    for entry_point in discovered:
        label = f"entry point '{entry_point.name}'"
        try:
            target = entry_point.load()
        except Exception as exc:
            result.add_error(label, f"failed to import: {exc}")
            continue

        # An entry point may point at the class directly or at a factory.
        candidate = target
        if not isinstance(target, type):
            try:
                candidate = target()
            except Exception as exc:
                result.add_error(label, f"factory call failed: {exc}")
                continue

        try:
            result.loaded.append(_validate(candidate, label))
        except (TypeError, ValueError) as exc:
            result.add_error(label, str(exc))

    return result


def load_from_path(path: str | Path) -> PluginLoadResult:
    """Load plugins from a directory or a single ``.py`` file.

    A directory may contain several plugin files; each is imported in isolation
    under a private module name so two plugins with the same filename cannot
    shadow each other.
    """
    result = PluginLoadResult()
    root = Path(path).expanduser().resolve()

    if not root.exists():
        result.add_error(str(root), "path does not exist")
        return result

    if root.is_file():
        if root.suffix != ".py":
            result.add_error(str(root), "not a Python file")
            return result
        files = [root]
    else:
        files = sorted(p for p in root.glob("*.py") if not p.name.startswith("_"))

    if not files:
        result.add_error(str(root), "no plugin .py files found")
        return result

    for file_path in files:
        label = f"file '{file_path.name}'"
        try:
            module = _import_file(file_path)
        except Exception as exc:
            result.add_error(label, f"failed to import: {exc}")
            continue

        if not hasattr(module, "get_module"):
            result.add_error(label, "no get_module() function")
            continue

        try:
            candidate = module.get_module()
        except Exception as exc:
            result.add_error(label, f"get_module() raised: {exc}")
            continue

        try:
            result.loaded.append(_validate(candidate, label))
        except (TypeError, ValueError) as exc:
            result.add_error(label, str(exc))

    return result


def _import_file(file_path: Path):
    """Import a .py file as a standalone module without touching sys.path.

    Registering the module in ``sys.modules`` before execution is required for
    dataclasses and pickling to work, and must be undone if execution fails.
    """
    module_name = f"suika_plugin_{file_path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot create import spec for {file_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


def discover(
    paths: list[str | Path] | None = None,
    include_entry_points: bool = True,
) -> PluginLoadResult:
    """Run every configured discovery path and merge the results.

    Duplicate module names are dropped rather than overwriting, so loading the
    same plugin twice (e.g. it is both installed and passed via ``--plugin``)
    does not silently replace the first registration.
    """
    result = PluginLoadResult()
    seen: set[str] = set()

    sources: list[PluginLoadResult] = []
    if include_entry_points:
        sources.append(load_from_entry_points())
    for path in paths or []:
        sources.append(load_from_path(path))

    for source in sources:
        for cls in source.loaded:
            if cls.name in seen:
                continue
            seen.add(cls.name)
            result.loaded.append(cls)
        for name, message in source.errors:
            result.add_error(name, message)

    return result


def load_and_register(
    engine, paths: list[str | Path] | None = None, include_entry_points: bool = True
) -> PluginLoadResult:
    """Discover plugins and register every valid one on ``engine``."""
    result = discover(paths=paths, include_entry_points=include_entry_points)
    for cls in result.loaded:
        engine.register(cls)
    return result
