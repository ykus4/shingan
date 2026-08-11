"""Single source of truth for the package version.

The version used to be hardcoded in three places that had already drifted
apart (``pyproject.toml`` said 1.0.0, the SARIF driver said 1.0.0 and the
FastAPI app said 1.1.0).  Reading it from installed package metadata keeps
every surface in agreement with ``pyproject.toml``.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

#: Reported when the package is not installed (e.g. running from a source tree).
FALLBACK_VERSION = "0.0.0+unknown"


def get_version() -> str:
    """Return the installed shingan version."""
    try:
        return _pkg_version("shingan")
    except PackageNotFoundError:
        return FALLBACK_VERSION


__version__ = get_version()
