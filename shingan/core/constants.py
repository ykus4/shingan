"""Project-wide constants — all magic numbers live here."""

from __future__ import annotations

# ── Binary string extraction ──────────────────────────────────────────────────

#: Minimum string length passed to the `strings` command.
#: 5 chars is the BSD default; shorter strings generate too much noise.
STRINGS_MIN_LEN: int = 5

#: Longer minimum for the secrets checker — short strings are rarely secrets.
SECRETS_STRINGS_MIN_LEN: int = 8

#: Subprocess timeout (seconds) for `strings` and `codesign` commands.
SUBPROCESS_TIMEOUT: int = 60

# ── Entropy / secrets ─────────────────────────────────────────────────────────

#: Shannon entropy threshold (bits per character) above which a string is
#: considered a candidate secret.  Typical English text ≈ 4.0; base64 ≈ 6.0.
#: 4.2 is a reasonable mid-point that catches base64-encoded keys while
#: keeping false-positive rates low.
ENTROPY_THRESHOLD: float = 4.2

#: Strings shorter than this are skipped in the entropy scan — short strings
#: are almost always false positives regardless of entropy value.
ENTROPY_MIN_LEN: int = 20

# ── Evidence / diff ───────────────────────────────────────────────────────────

#: Maximum evidence length kept in a Finding fingerprint.
#: 120 chars is enough to disambiguate almost all findings while staying
#: short enough that cosmetic evidence changes (e.g. truncated URLs) don't
#: affect fingerprint stability.
FINGERPRINT_EVIDENCE_LEN: int = 120

# ── Checkers ──────────────────────────────────────────────────────────────────

#: Maximum number of ObjC class names included in Finding evidence.
EVIDENCE_OBJC_SAMPLE: int = 30

#: Maximum number of Swift symbols included in Finding evidence.
EVIDENCE_SWIFT_SAMPLE: int = 20

#: Maximum number of debug strings included in Finding evidence.
EVIDENCE_DEBUG_SAMPLE: int = 15

#: Maximum number of secret matches reported per pattern.
SECRETS_MAX_HITS_PER_PATTERN: int = 10

#: Maximum number of high-entropy strings reported.
ENTROPY_SAMPLE_SIZE: int = 10

#: Number of LSApplicationQueriesSchemes entries above which a finding is raised.
LSA_SCHEMES_THRESHOLD: int = 10
