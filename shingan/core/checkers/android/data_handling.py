"""AND-CODE-019: Sensitive data handling checks (Android).

Detects patterns that could expose sensitive data through:
  - AND-CODE-019a: ClipboardManager writes (pasteboard equivalent)
  - AND-CODE-019b: Screen capture / FLAG_SECURE not set
  - AND-CODE-019c: Logging sensitive data (Log.d/Log.v with sensitive keywords)
  - AND-CODE-019d: Storing sensitive data in SharedPreferences (unencrypted)

Maps to MASVS-CODE-3.
"""

from __future__ import annotations

from shingan.core.binary import AndroidCheckContext
from shingan.core.models import Finding, Severity

_CLIPBOARD_INDICATORS = (
    "ClipboardManager",
    "setPrimaryClip",
    "ClipData.newPlainText",
)

_FLAG_SECURE_INDICATORS = (
    "FLAG_SECURE",
    "WindowManager.LayoutParams.FLAG_SECURE",
)

_SENSITIVE_LOG_KEYWORDS = (
    "password",
    "passwd",
    "token",
    "secret",
    "apikey",
    "api_key",
    "accesskey",
    "privatekey",
)

_SHARED_PREFS_INDICATORS = (
    "getSharedPreferences",
    "SharedPreferences",
    "putString",
    "putInt",
)

_ENCRYPTED_PREFS_INDICATORS = (
    "EncryptedSharedPreferences",
    "MasterKeys",
    "MasterKey",
    "androidx.security.crypto",
)


def check(ctx: AndroidCheckContext) -> list[Finding]:
    findings: list[Finding] = []
    corpus = ctx.dex_strings | ctx.strings

    # AND-CODE-019a: Clipboard usage
    clipboard_hits = [
        s for s in corpus if any(ind in s for ind in _CLIPBOARD_INDICATORS)
    ]
    if clipboard_hits:
        findings.append(
            Finding(
                rule_id="AND-CODE-019a",
                title="ClipboardManager usage detected",
                severity=Severity.LOW,
                description=(
                    "The app writes to the system clipboard (ClipboardManager). "
                    "Any app with READ_CLIPBOARD permission can read clipboard contents. "
                    "Writing sensitive data such as passwords, tokens, or PII to the clipboard "
                    "risks exposure to malicious apps monitoring the clipboard."
                ),
                evidence="\n".join(sorted(set(clipboard_hits))[:5]),
                recommendation=(
                    "Avoid writing sensitive data to the clipboard. "
                    "If clipboard support is required (e.g. password managers), "
                    "clear the clipboard after a short timeout."
                ),
                masvs="MASVS-CODE-3",
            )
        )

    # AND-CODE-019b: FLAG_SECURE (screenshot suppression)
    flag_secure_hits = [
        s for s in corpus if any(ind in s for ind in _FLAG_SECURE_INDICATORS)
    ]
    if not flag_secure_hits:
        findings.append(
            Finding(
                rule_id="AND-CODE-019b",
                title="FLAG_SECURE not detected — screenshots may not be suppressed",
                severity=Severity.LOW,
                description=(
                    "No usage of `WindowManager.LayoutParams.FLAG_SECURE` was detected. "
                    "Without this flag, the system allows screenshots and screen recordings "
                    "of the app's windows, which may capture sensitive information such as "
                    "passwords, payment details, or private messages."
                ),
                evidence="FLAG_SECURE not found in DEX strings",
                recommendation=(
                    "Set `window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, "
                    "WindowManager.LayoutParams.FLAG_SECURE)` in Activities that display "
                    "sensitive content."
                ),
                masvs="MASVS-CODE-3",
            )
        )

    # AND-CODE-019c: Sensitive data in logs
    log_hits = []
    for s in corpus:
        s_lower = s.lower()
        if ("log.d" in s_lower or "log.v" in s_lower or "log.i" in s_lower) and any(
            kw in s_lower for kw in _SENSITIVE_LOG_KEYWORDS
        ):
            log_hits.append(s.strip()[:200])

    if log_hits:
        findings.append(
            Finding(
                rule_id="AND-CODE-019c",
                title="Potential sensitive data in log statements detected",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(log_hits)} log statement(s) may write sensitive data "
                    "(password, token, key, etc.) to logcat. "
                    "Logcat is readable by any app with READ_LOGS permission on older Android "
                    "versions, and by ADB on any device."
                ),
                evidence="\n".join(sorted(set(log_hits))[:5]),
                recommendation=(
                    "Remove sensitive data from log statements in release builds. "
                    "Use ProGuard/R8 rules to strip all logging calls from release APKs."
                ),
                masvs="MASVS-CODE-3",
            )
        )

    # AND-CODE-019d: Unencrypted SharedPreferences for sensitive data
    prefs_hits = [
        s for s in corpus if any(ind in s for ind in _SHARED_PREFS_INDICATORS)
    ]
    encrypted_hits = [
        s for s in corpus if any(ind in s for ind in _ENCRYPTED_PREFS_INDICATORS)
    ]

    if prefs_hits and not encrypted_hits:
        findings.append(
            Finding(
                rule_id="AND-CODE-019d",
                title="SharedPreferences used without EncryptedSharedPreferences",
                severity=Severity.MEDIUM,
                description=(
                    "The app uses SharedPreferences but no usage of EncryptedSharedPreferences "
                    "was detected. SharedPreferences are stored as plain-text XML on the device. "
                    "On rooted devices, any app can read them. If sensitive data (tokens, "
                    "credentials, settings) is stored there, it should be encrypted."
                ),
                evidence="\n".join(sorted(set(prefs_hits))[:5]),
                recommendation=(
                    "Use `EncryptedSharedPreferences` from the Jetpack Security library "
                    "(`androidx.security.crypto`) to transparently encrypt SharedPreferences. "
                    "For highly sensitive values, use the Android Keystore directly."
                ),
                masvs="MASVS-CODE-3",
            )
        )

    return findings
