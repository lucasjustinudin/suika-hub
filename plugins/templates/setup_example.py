# ─────────────────────────────────────────────────────────────────────────────
# Example setup.py for a Suika Hunter pip-installable plugin
# ─────────────────────────────────────────────────────────────────────────────
#
# To install your plugin:
#   pip install .
#   # or:  suika install .
#
# The entry-point below lets the plugin system auto-discover your scanner.

from setuptools import setup, find_packages

setup(
    name="suika-plugin-example",
    version="0.1.0",
    description="Example Suika Hunter plugin",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        # your plugin's pip dependencies here
    ],
    entry_points={
        # The key "suika.plugins" is the entry-point group.
        # Each entry:  name = package.module:ClassName
        "suika.plugins": [
            "example = my_plugin.scanner:MyScanner",
        ],
    },
    python_requires=">=3.10",
)
