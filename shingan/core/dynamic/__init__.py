"""Dynamic analysis module for shingan.

Requires the optional [dynamic] extra:
    pip install "shingan[dynamic]"
    uv sync --extra dynamic
"""

from shingan.core.dynamic.runner import run_dynamic_checks

__all__ = ["run_dynamic_checks"]
