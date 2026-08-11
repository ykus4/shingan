"""Shannon entropy helpers shared by the iOS and Android secrets checkers.

This lived as a private ``_shannon_entropy`` inside the iOS secrets checker,
which the Android checker then imported across the platform boundary.  It is
platform-agnostic maths, so it belongs in core.
"""

from __future__ import annotations

import math
from collections import Counter

from shingan.core.constants import (
    ENTROPY_FALSE_POSITIVE_PREFIXES,
    ENTROPY_MIN_LEN,
    ENTROPY_THRESHOLD,
)


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy of ``value`` in bits per character."""
    if not value:
        return 0.0
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(value).values()
    )


def is_high_entropy_candidate(
    value: str,
    *,
    threshold: float = ENTROPY_THRESHOLD,
    min_length: int = ENTROPY_MIN_LEN,
) -> bool:
    """True when ``value`` looks like an encoded secret rather than prose.

    Short strings and known-noisy prefixes (URLs, reverse-DNS identifiers, JWT
    headers) are excluded because they dominate false positives regardless of
    their entropy score.
    """
    if len(value) < min_length:
        return False
    if value.startswith(ENTROPY_FALSE_POSITIVE_PREFIXES):
        return False
    return shannon_entropy(value) >= threshold
