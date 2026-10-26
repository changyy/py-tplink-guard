"""
Single source of truth for the package version.

Version scheme: ``1.YYYYmmdd.1HHmmss`` (see CHANGELOG.md).
Consumed by the runtime (``tplink_guard.__version__``) and the build backend
(pyproject.toml ``[tool.hatch.version]``).
"""

__version__ = "1.20261026.1221539"
