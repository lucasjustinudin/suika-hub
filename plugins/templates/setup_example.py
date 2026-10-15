# ─────────────────────────────────────────────────────────────────────────────
# Example setup.py for a pip-installable suika-hub plugin
# ─────────────────────────────────────────────────────────────────────────────
#
# To install your plugin:
#   pip install .
#
# The entry point below is what makes the plugin discoverable: the
# "suika.plugins" group is scanned by suika_hub.core.plugins, so after
# installing, the scanner appears in `suika-hub modules` like a built-in.
#
# Prefer a PEP 621 pyproject.toml for new plugins; this file is kept as a
# setuptools example because it is the shortest complete one:
#
#   [project.entry-points."suika.plugins"]
#   my_plugin = "my_package.scanner:MyScanner"

from setuptools import find_packages, setup

setup(
    name="suika-plugin-example",
    version="0.1.0",
    description="Example suika-hub plugin",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        # your plugin's pip dependencies here
    ],
    entry_points={
        # Group name must be exactly "suika.plugins".
        # Each entry: <plugin name> = <package.module>:<ClassName>
        "suika.plugins": [
            "example = my_plugin.scanner:MyScanner",
        ],
    },
    python_requires=">=3.10",
)
