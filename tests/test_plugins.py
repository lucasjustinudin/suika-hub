"""Tests for plugin discovery and loading."""

from __future__ import annotations

import textwrap

import pytest

from suika_hub.core.engine import SuikaEngine
from suika_hub.core.module import BaseModule
from suika_hub.core.plugins import (
    ENTRY_POINT_GROUP,
    PluginLoadResult,
    _validate,
    discover,
    load_and_register,
    load_from_entry_points,
    load_from_path,
)


def write_plugin(directory, filename: str, body: str):
    path = directory / filename
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return path


GOOD = """
    from suika_hub.core.http import AsyncClient
    from suika_hub.core.module import BaseModule, Finding

    class GoodScanner(BaseModule):
        name = "good_one"
        description = "works"

        async def execute(self, target, client, config):
            self.reset()
            return self.findings

    def get_module():
        return GoodScanner
"""

NO_GET_MODULE = """
    class Orphan:
        pass
"""

WRONG_BASE = """
    class NotAModule:
        name = "nope"

    def get_module():
        return NotAModule
"""

GET_MODULE_RAISES = """
    def get_module():
        raise RuntimeError("boom")
"""

BROKEN_IMPORT = """
    import definitely_not_a_real_module_xyz  # noqa: F401

    def get_module():
        return None
"""

GET_MODULE_RETURNS_INSTANCE = """
    from suika_hub.core.module import BaseModule

    class InstScanner(BaseModule):
        name = "inst"

        async def execute(self, target, client, config):
            return []

    def get_module():
        return InstScanner()  # an instance, not the class
"""

NO_NAME = """
    from suika_hub.core.module import BaseModule

    class UnnamedScanner(BaseModule):
        async def execute(self, target, client, config):
            return []

    def get_module():
        return UnnamedScanner
"""


class TestLoadFromPath:
    def test_loads_a_valid_plugin(self, tmp_path):
        write_plugin(tmp_path, "good.py", GOOD)
        result = load_from_path(tmp_path)

        assert result.ok
        assert [c.name for c in result.loaded] == ["good_one"]
        assert issubclass(result.loaded[0], BaseModule)

    def test_missing_path_reports_error(self, tmp_path):
        result = load_from_path(tmp_path / "nope")
        assert not result.ok
        assert "does not exist" in result.errors[0][1]

    def test_directory_without_plugins_reports_error(self, tmp_path):
        (tmp_path / "readme.txt").write_text("nothing here", encoding="utf-8")
        result = load_from_path(tmp_path)
        assert not result.ok
        assert "no plugin .py files" in result.errors[0][1]

    def test_single_file(self, tmp_path):
        path = write_plugin(tmp_path, "solo.py", GOOD)
        result = load_from_path(path)
        assert [c.name for c in result.loaded] == ["good_one"]

    def test_non_python_file_rejected(self, tmp_path):
        path = tmp_path / "thing.txt"
        path.write_text("not python", encoding="utf-8")
        result = load_from_path(path)
        assert not result.ok
        assert "not a Python file" in result.errors[0][1]

    def test_underscore_files_are_skipped(self, tmp_path):
        write_plugin(tmp_path, "_private.py", GOOD)
        write_plugin(tmp_path, "real.py", GOOD)
        result = load_from_path(tmp_path)
        # Only real.py is considered, so one load and no error for _private.py.
        assert len(result.loaded) == 1
        assert result.ok

    @pytest.mark.parametrize(
        ("filename", "body", "needle"),
        [
            ("no_gm.py", NO_GET_MODULE, "no get_module() function"),
            ("wrong_base.py", WRONG_BASE, "does not subclass BaseModule"),
            ("raises.py", GET_MODULE_RAISES, "get_module() raised: boom"),
            ("broken.py", BROKEN_IMPORT, "failed to import"),
            ("instance.py", GET_MODULE_RETURNS_INSTANCE, "expected a class"),
            ("no_name.py", NO_NAME, "does not set a unique 'name'"),
        ],
    )
    def test_each_failure_mode_is_reported_not_raised(self, tmp_path, filename, body, needle):
        """Every malformed plugin must produce a specific message, never a crash.

        A broken third-party plugin that takes down discovery would make the
        whole tool unusable, so these are the cases that matter most.
        """
        write_plugin(tmp_path, filename, body)
        result = load_from_path(tmp_path)
        assert result.loaded == []
        assert len(result.errors) == 1
        assert needle in result.errors[0][1]

    def test_one_bad_plugin_does_not_block_a_good_one(self, tmp_path):
        write_plugin(tmp_path, "a_broken.py", GET_MODULE_RAISES)
        write_plugin(tmp_path, "b_good.py", GOOD)
        result = load_from_path(tmp_path)

        assert [c.name for c in result.loaded] == ["good_one"]
        assert len(result.errors) == 1
        assert not result.ok  # errors present, but a plugin still loaded

    def test_failed_import_is_not_left_in_sys_modules(self, tmp_path):
        """A failed import must not poison sys.modules under its private name."""
        import sys

        write_plugin(tmp_path, "explode.py", BROKEN_IMPORT)
        load_from_path(tmp_path)
        assert "suika_plugin_explode" not in sys.modules

    def test_two_plugins_with_the_same_stem_do_not_collide(self, tmp_path):
        """Loading the same filename from two directories must not shadow."""
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        write_plugin(a, "same.py", GOOD)
        write_plugin(b, "same.py", GOOD.replace("good_one", "other_one"))

        first = load_from_path(a)
        second = load_from_path(b)
        assert [c.name for c in first.loaded] == ["good_one"]
        assert [c.name for c in second.loaded] == ["other_one"]


class TestValidate:
    def test_rejects_non_class(self):
        with pytest.raises(TypeError, match="expected a class"):
            _validate(lambda: None, "factory")

    def test_rejects_plain_class(self):
        class Plain:
            pass

        with pytest.raises(TypeError, match="does not subclass"):
            _validate(Plain, "plain")

    def test_rejects_base_module_itself(self):
        with pytest.raises(TypeError, match="BaseModule itself"):
            _validate(BaseModule, "base")

    def test_rejects_empty_name(self):
        class NoName(BaseModule):
            name = ""

            async def execute(self, target, client, config):
                return []

        with pytest.raises(ValueError, match="unique 'name'"):
            _validate(NoName, "noname")

    def test_accepts_valid_module(self):
        class Fine(BaseModule):
            name = "fine"

            async def execute(self, target, client, config):
                return []

        assert _validate(Fine, "fine") is Fine


class TestDiscover:
    def test_merges_paths(self, tmp_path):
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        write_plugin(a, "one.py", GOOD)
        write_plugin(b, "two.py", GOOD.replace("good_one", "second_one"))

        result = discover(paths=[a, b], include_entry_points=False)
        assert sorted(c.name for c in result.loaded) == ["good_one", "second_one"]

    def test_duplicate_module_name_is_dropped_not_replaced(self, tmp_path):
        """Loading the same plugin twice must not overwrite the first."""
        a = tmp_path / "a"
        b = tmp_path / "b"
        a.mkdir()
        b.mkdir()
        write_plugin(a, "same.py", GOOD)
        write_plugin(b, "same.py", GOOD)

        result = discover(paths=[a, b], include_entry_points=False)
        assert len(result.loaded) == 1

    def test_errors_from_all_sources_are_collected(self, tmp_path):
        a = tmp_path / "a"
        a.mkdir()
        write_plugin(a, "broken.py", GET_MODULE_RAISES)

        result = discover(paths=[a, tmp_path / "missing"], include_entry_points=False)
        assert len(result.errors) == 2

    def test_no_paths_and_no_entry_points_is_empty(self):
        result = discover(paths=None, include_entry_points=False)
        assert result.loaded == []
        assert result.ok


class TestLoadAndRegister:
    def test_registers_loaded_plugins_on_the_engine(self, tmp_path):
        write_plugin(tmp_path, "good.py", GOOD)
        engine = SuikaEngine()

        result = load_and_register(engine, paths=[tmp_path], include_entry_points=False)

        assert [c.name for c in result.loaded] == ["good_one"]
        assert "good_one" in engine.modules
        assert engine.resolve("good_one") is not None

    def test_plugin_is_runnable_through_the_engine(self, tmp_path):
        """A registered plugin must resolve by alias exactly like a built-in."""
        write_plugin(tmp_path, "good.py", GOOD)
        engine = SuikaEngine()
        load_and_register(engine, paths=[tmp_path], include_entry_points=False)

        assert engine.resolve("good_one").name == "good_one"


class TestEntryPoints:
    def test_returns_result_object(self):
        result = load_from_entry_points()
        assert isinstance(result, PluginLoadResult)
        # Whether anything is installed is environment-dependent; the contract
        # is that discovery never raises and always reports usable structure.
        assert isinstance(result.loaded, list)
        assert isinstance(result.errors, list)

    def test_entry_point_group_name_is_stable(self):
        assert ENTRY_POINT_GROUP == "suika.plugins"

    def test_broken_entry_point_is_reported_not_raised(self, monkeypatch):
        """A third-party distribution with a bad entry point must not crash us."""
        import suika_hub.core.plugins as plugins_mod

        class FakeEntryPoint:
            name = "broken"

            def load(self):
                raise ImportError("no such attribute")

        monkeypatch.setattr(
            "importlib.metadata.entry_points",
            lambda **kwargs: [FakeEntryPoint()],
        )
        result = plugins_mod.load_from_entry_points()
        assert result.loaded == []
        assert result.errors
        assert "failed to import" in result.errors[0][1]
