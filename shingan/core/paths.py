"""Single source of truth for on-disk locations.

``SHINGAN_HOME`` is resolved *lazily* on every call rather than captured at
import time.  Import-time capture made the location impossible to override in
tests and in embedding processes, because changing the environment variable
after ``shingan`` had been imported had no effect.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Environment variable that overrides the default data directory.
SHINGAN_HOME_ENV = "SHINGAN_HOME"


def shingan_home() -> Path:
    """Return the shingan data directory (``$SHINGAN_HOME`` or ``~/.shingan``)."""
    override = os.environ.get(SHINGAN_HOME_ENV)
    if override:
        return Path(override).expanduser()
    return Path.home() / ".shingan"


def default_db_path() -> Path:
    """SQLite database holding scan results."""
    return shingan_home() / "shingan.db"


def default_suppressions_path() -> Path:
    """JSON file holding suppression entries."""
    return shingan_home() / "suppressions.json"


def default_rules_dir() -> Path:
    """Directory scanned for custom YAML rules."""
    return shingan_home() / "rules"


def legacy_scans_dir() -> Path:
    """Pre-SQLite scan directory, imported once on first run."""
    return shingan_home() / "scans"
