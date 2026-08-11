"""AND-SEC-002: Hardcoded secrets and sensitive strings in an Android APK.

Detection lives in :mod:`shingan.core.checkers.common.secrets_engine`; this
module only supplies the Android-specific wording and corpus.
"""

from __future__ import annotations

from shingan.core.checkers.common.secrets_engine import SecretsProfile, scan_secrets
from shingan.core.context import AndroidCheckContext
from shingan.core.models import Finding

_PROFILE = SecretsProfile(
    rule_base="AND-SEC-002",
    corpus_label="the APK string table",
    extraction_tools="`apktool` or `jadx`",
    secure_storage="Android Keystore, environment variables",
    artifact_noun="APK",
)


def check(ctx: AndroidCheckContext) -> list[Finding]:
    # DEX string constants plus native .so strings, above the length floor.
    return scan_secrets(ctx.long_strings, _PROFILE)
