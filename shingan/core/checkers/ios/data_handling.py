"""IOS-CODE-019: Sensitive data handling checks (iOS).

Detects patterns that could expose sensitive data through:
  - IOS-CODE-019a: Pasteboard (UIPasteboard) writes with sensitive content
  - IOS-CODE-019b: Keyboard caching not disabled on sensitive fields
  - IOS-CODE-019c: Screenshots / screen recording not suppressed
  - IOS-CODE-019d: Logging of sensitive data (NSLog / os_log with format strings)

Maps to MASVS-CODE-3.
"""

from __future__ import annotations

from shingan.core.context import CheckContext
from shingan.core.models import Finding, Severity

_PASTEBOARD_INDICATORS = (
    "UIPasteboard",
    "generalPasteboard",
    "setString:",
    "setPersistent:",
)

_KEYBOARD_CACHE_INDICATORS = (
    "UITextAutocorrectionTypeNo",
    "UITextSpellCheckingTypeNo",
    "secureTextEntry",
    "isSecureTextEntry",
)

_SCREENSHOT_SUPPRESSION_INDICATORS = (
    "applicationWillResignActive",
    "UIApplicationWillResignActiveNotification",
    "blurEffect",
    "UIVisualEffectView",
    "isHidden",
)

_SENSITIVE_LOG_PATTERNS = (
    'NSLog(@"%@", password',
    'NSLog(@"%@", token',
    'NSLog(@"%@", secret',
    'NSLog(@"%@", key',
    "print(password",
    "print(token",
    "print(secret",
    "os_log.*password",
    "os_log.*token",
)


def check(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    corpus = ctx.all_text

    # IOS-CODE-019a: Pasteboard usage
    pb_hits = [s for s in corpus if any(ind in s for ind in _PASTEBOARD_INDICATORS)]
    if pb_hits:
        findings.append(
            Finding(
                rule_id="IOS-CODE-019a",
                title="UIPasteboard usage detected",
                severity=Severity.LOW,
                description=(
                    "The app uses UIPasteboard, which can expose data to other apps. "
                    "On iOS 14+, apps are notified when they read the pasteboard, but "
                    "writing sensitive data (tokens, passwords, PII) to the shared pasteboard "
                    "can still leak data to other apps via pasteboard monitoring."
                ),
                evidence="\n".join(sorted(set(pb_hits))[:5]),
                recommendation=(
                    "Avoid writing sensitive data to UIPasteboard.generalPasteboard. "
                    "Use a named, non-persistent pasteboard for in-app clipboard operations. "
                    "Set `isPersistent = false` to clear pasteboard data when the app terminates."
                ),
                masvs="MASVS-CODE-3",
            )
        )

    # IOS-CODE-019b: Keyboard cache / secure entry (absence check)
    keyboard_hits = [
        s for s in corpus if any(ind in s for ind in _KEYBOARD_CACHE_INDICATORS)
    ]
    if not keyboard_hits:
        findings.append(
            Finding(
                rule_id="IOS-CODE-019b",
                title="No keyboard cache suppression or secureTextEntry detected",
                severity=Severity.LOW,
                description=(
                    "No indicators of keyboard cache suppression (UITextAutocorrectionTypeNo, "
                    "secureTextEntry) were found. Text fields displaying sensitive data "
                    "(passwords, card numbers) should disable autocorrect and autocomplete "
                    "to prevent caching in the keyboard dictionary."
                ),
                evidence="No secureTextEntry or UITextAutocorrectionTypeNo found",
                recommendation=(
                    "Set `isSecureTextEntry = true` on password fields. "
                    "Set `autocorrectionType = .no` and `spellCheckingType = .no` on "
                    "fields that handle sensitive data."
                ),
                masvs="MASVS-CODE-3",
            )
        )

    # IOS-CODE-019c: Screenshot suppression (absence check)
    screenshot_hits = [
        s for s in corpus if any(ind in s for ind in _SCREENSHOT_SUPPRESSION_INDICATORS)
    ]
    if not screenshot_hits:
        findings.append(
            Finding(
                rule_id="IOS-CODE-019c",
                title="No screenshot suppression detected",
                severity=Severity.LOW,
                description=(
                    "No indicators of screenshot or screen-recording suppression were found "
                    "(applicationWillResignActive handler, UIVisualEffectView overlay). "
                    "When the app moves to the background, iOS captures a screenshot for the "
                    "app switcher, which may expose sensitive screens."
                ),
                evidence="No backgrounding / screenshot suppression indicators found",
                recommendation=(
                    "In `applicationWillResignActive` or `sceneWillDeactivate`, cover sensitive "
                    "content with an opaque view or blur overlay before the screenshot is taken."
                ),
                masvs="MASVS-CODE-3",
            )
        )

    # IOS-CODE-019d: Sensitive data in logs
    log_hits = [s for s in corpus if any(pat in s for pat in _SENSITIVE_LOG_PATTERNS)]
    if log_hits:
        findings.append(
            Finding(
                rule_id="IOS-CODE-019d",
                title="Potential sensitive data in log statements detected",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(log_hits)} log statement(s) found that may write sensitive data "
                    "(password, token, secret, key) to the system log. "
                    "System logs are readable by other apps on jailbroken devices and "
                    "accessible via Xcode / Console on connected devices."
                ),
                evidence="\n".join(sorted(set(log_hits))[:5]),
                recommendation=(
                    "Never log sensitive values. Use os_log with `%{private}@` format specifier "
                    "to prevent sensitive data from appearing in system logs on non-development devices."
                ),
                masvs="MASVS-CODE-3",
            )
        )

    return findings
