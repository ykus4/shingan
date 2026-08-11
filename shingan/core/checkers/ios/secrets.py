"""IOS-SEC-002: Hardcoded secrets and sensitive strings.

Detection lives in :mod:`shingan.core.checkers.common.secrets_engine`; this
module only supplies the iOS-specific wording and corpus.
"""

from __future__ import annotations

from shingan.core.checkers.common.secrets_engine import SecretsProfile, scan_secrets
from shingan.core.context import CheckContext
from shingan.core.models import Finding

_PROFILE = SecretsProfile(
    rule_base="IOS-SEC-002",
    corpus_label="the binary string table",
    extraction_tools="`strings`",
    secure_storage="iOS Keychain, AWS Secrets Manager",
    artifact_noun="binary",
)


def check(ctx: CheckContext) -> list[Finding]:
    # Secrets scanning benefits from a higher minimum string length to reduce
    # noise; ctx.long_strings filters the already-extracted corpus rather than
    # re-running `strings` over the whole binary.
    return scan_secrets(ctx.long_strings, _PROFILE)
