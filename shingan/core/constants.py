"""Project-wide constants — all magic numbers live here."""

from __future__ import annotations

# ── Binary string extraction ──────────────────────────────────────────────────

#: Minimum string length passed to the `strings` command.
#: 5 chars is the BSD default; shorter strings generate too much noise.
STRINGS_MIN_LEN: int = 5

#: Longer minimum for the secrets checker — short strings are rarely secrets.
#: Applied by filtering the shared string corpus rather than by re-running
#: `strings`, so the binary is only ever scanned once.
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

#: Prefixes that dominate high-entropy false positives: URLs, reverse-DNS
#: bundle identifiers, and base64url JWT headers.
ENTROPY_FALSE_POSITIVE_PREFIXES: tuple[str, ...] = (
    "https://",
    "http://",
    "com.",
    "org.",
    "eyJ",
)

# ── Evidence / diff ───────────────────────────────────────────────────────────

#: Maximum evidence length kept in a Finding fingerprint.
#: 120 chars is enough to disambiguate almost all findings while staying
#: short enough that cosmetic evidence changes (e.g. truncated URLs) don't
#: affect fingerprint stability.
FINGERPRINT_EVIDENCE_LEN: int = 120

#: Maximum length of a single evidence line kept in a Finding.
EVIDENCE_LINE_MAX_LEN: int = 200

#: Maximum length of an error/exception string embedded in evidence.
EVIDENCE_ERROR_MAX_LEN: int = 300

# ── Checkers ──────────────────────────────────────────────────────────────────

#: Maximum number of ObjC class names included in Finding evidence.
EVIDENCE_OBJC_SAMPLE: int = 30

#: Maximum number of Swift symbols included in Finding evidence.
EVIDENCE_SWIFT_SAMPLE: int = 20

#: Maximum number of debug strings included in Finding evidence.
EVIDENCE_DEBUG_SAMPLE: int = 15

#: Maximum number of secret matches reported per pattern.
SECRETS_MAX_HITS_PER_PATTERN: int = 10

#: Number of secret matches shown in a Finding's evidence block.
SECRETS_EVIDENCE_SAMPLE: int = 5

#: Maximum number of high-entropy strings reported.
ENTROPY_SAMPLE_SIZE: int = 10

#: Number of LSApplicationQueriesSchemes entries above which a finding is raised.
LSA_SCHEMES_THRESHOLD: int = 10

#: Number of URL schemes listed in a metadata finding title.
URL_SCHEME_TITLE_SAMPLE: int = 5

#: Number of LSApplicationQueriesSchemes entries shown as evidence.
LSA_SCHEMES_EVIDENCE_SAMPLE: int = 15

# ── Custom rules ──────────────────────────────────────────────────────────────

#: Maximum matches recorded per pattern within a single custom rule.
RULE_HITS_PER_PATTERN: int = 3

#: Maximum total matches reported by a single custom rule.
RULE_MAX_HITS: int = 10

# ── Archive extraction limits ─────────────────────────────────────────────────

#: Maximum number of entries accepted in an IPA/APK archive.
MAX_ARCHIVE_MEMBERS: int = 200_000

#: Maximum total uncompressed size (bytes) accepted from one archive — 4 GiB.
MAX_UNCOMPRESSED_BYTES: int = 4 * 1024**3

#: Maximum overall compression ratio accepted before assuming a zip bomb.
MAX_COMPRESSION_RATIO: int = 500

# ── Uploads / web ─────────────────────────────────────────────────────────────

#: Maximum accepted upload size (bytes) for the web API — 2 GiB.
MAX_UPLOAD_BYTES: int = 2 * 1024**3

#: Chunk size used when streaming an upload to disk.
UPLOAD_CHUNK_BYTES: int = 1024 * 1024

#: Default bind address for `shingan serve`.  Loopback by default: the API is
#: unauthenticated unless SHINGAN_API_KEY is set, so it must not be reachable
#: off-host without the operator opting in.
DEFAULT_SERVE_HOST: str = "127.0.0.1"

#: Default port for `shingan serve`.
DEFAULT_SERVE_PORT: int = 8000

#: Timeout (seconds) for outbound HTTP calls (notifications, CLI → server).
HTTP_TIMEOUT: int = 10

# ── Storage ───────────────────────────────────────────────────────────────────

#: Current SQLite schema version, tracked in the `schema_meta` table.
SCHEMA_VERSION: int = 1

#: Default page size for scan listings.
SCAN_LIST_LIMIT: int = 100
