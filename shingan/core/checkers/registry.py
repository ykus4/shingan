"""Checker discovery and execution.

Checkers used to be wired into ``analyzer.py`` as a 36-line import block plus
two hand-maintained lists, so adding one meant editing three places and the
analyzer grew with every new check.  Instead, every module inside
``checkers/ios`` and ``checkers/android`` that exposes a module-level
``check(ctx)`` callable is discovered automatically.

Discovery is sorted by module name so a scan visits checkers in a stable,
reproducible order.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from types import ModuleType
from typing import Any

from shingan.core.models import Finding

logger = logging.getLogger(__name__)

#: A checker takes a platform check context and returns findings.
CheckFn = Callable[[Any], list[Finding]]


@dataclass(frozen=True)
class Checker:
    """A discovered checker module."""

    #: Short module name, e.g. ``secrets``.
    name: str
    #: Fully-qualified module path, used in log messages.
    module: str
    run: CheckFn

    def __call__(self, ctx: Any) -> list[Finding]:
        return self.run(ctx)


def _discover(package: ModuleType) -> list[Checker]:
    checkers: list[Checker] = []
    for info in sorted(pkgutil.iter_modules(package.__path__), key=lambda i: i.name):
        if info.name.startswith("_"):
            continue
        module_path = f"{package.__name__}.{info.name}"
        try:
            module = importlib.import_module(module_path)
        except Exception:
            logger.exception("Failed to import checker module %s", module_path)
            continue
        fn = getattr(module, "check", None)
        if not callable(fn):
            logger.debug("Skipping %s — no module-level check()", module_path)
            continue
        checkers.append(Checker(name=info.name, module=module_path, run=fn))
    return checkers


def ios_checkers() -> list[Checker]:
    """All discovered iOS checkers, ordered by module name."""
    from shingan.core.checkers import ios

    return _discover(ios)


def android_checkers() -> list[Checker]:
    """All discovered Android checkers, ordered by module name."""
    from shingan.core.checkers import android

    return _discover(android)


def checkers_for(platform: str) -> list[Checker]:
    """Return the checker set for ``platform`` ("ios" or "android")."""
    if platform == "android":
        return android_checkers()
    if platform == "ios":
        return ios_checkers()
    raise ValueError(f"Unknown platform: {platform!r}")


def run_checkers(
    checkers: Iterable[Checker] | Sequence[Checker], ctx: Any
) -> list[Finding]:
    """Run every checker against ``ctx``, isolating failures.

    A checker that raises is logged with its traceback and contributes no
    findings; one broken checker never aborts a scan.
    """
    findings: list[Finding] = []
    for checker in checkers:
        try:
            findings.extend(checker(ctx))
        except Exception:
            logger.exception("Checker %s failed — skipping", checker.module)
    return findings
