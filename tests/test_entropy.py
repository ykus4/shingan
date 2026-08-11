"""Tests for the shared entropy helpers."""

from __future__ import annotations

import pytest

from shingan.core.constants import ENTROPY_MIN_LEN
from shingan.core.entropy import is_high_entropy_candidate, shannon_entropy


def test_empty_string_has_zero_entropy() -> None:
    assert shannon_entropy("") == 0.0


def test_single_repeated_character_has_zero_entropy() -> None:
    assert shannon_entropy("aaaaaaaaaa") == 0.0


def test_repeated_text_is_low_entropy() -> None:
    assert shannon_entropy("aaaaaaaaaa") < 1.0


def test_random_looking_string_is_high_entropy() -> None:
    assert shannon_entropy("aB3xQ9mKvP2nLwRjTyUoIeWsZdHfCgA1") > 4.0


def test_two_equally_frequent_characters_is_one_bit() -> None:
    assert shannon_entropy("abab") == pytest.approx(1.0)


def test_entropy_is_length_independent() -> None:
    """Entropy is per-character, so repeating a pattern does not change it."""
    assert shannon_entropy("ab") == pytest.approx(shannon_entropy("abababab"))


# ── Candidate filter ──────────────────────────────────────────────────────────


def test_short_strings_are_never_candidates() -> None:
    assert not is_high_entropy_candidate("aB3xQ9mK")


def test_long_high_entropy_string_is_a_candidate() -> None:
    assert is_high_entropy_candidate("aB3xQ9mKvP2nLwRjTyUoIeWsZdHfCgA1")


def test_long_low_entropy_string_is_not_a_candidate() -> None:
    assert not is_high_entropy_candidate("a" * (ENTROPY_MIN_LEN + 10))


@pytest.mark.parametrize(
    "prefix",
    ["https://", "http://", "com.", "org.", "eyJ"],
)
def test_known_noisy_prefixes_are_excluded(prefix: str) -> None:
    noisy = prefix + "aB3xQ9mKvP2nLwRjTyUoIeWsZdHfCgA1"
    assert not is_high_entropy_candidate(noisy)


def test_threshold_is_overridable() -> None:
    value = "abcdefghijklmnopqrstuvwxyz"
    assert is_high_entropy_candidate(value, threshold=1.0)
    assert not is_high_entropy_candidate(value, threshold=99.0)


def test_min_length_is_overridable() -> None:
    """Entropy is capped at log2(len), so a short string needs a lower threshold
    too — this isolates the length gate rather than the threshold."""
    short = "aB3xQ9mK"  # 8 distinct chars → exactly 3.0 bits
    assert not is_high_entropy_candidate(short, threshold=2.0)
    assert is_high_entropy_candidate(short, threshold=2.0, min_length=4)
