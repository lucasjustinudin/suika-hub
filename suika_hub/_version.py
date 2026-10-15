"""Single source of truth for the package version.

Kept import-free so every other module (including ``core``) can import it
without creating a cycle.
"""

__version__ = "2.1.0"
