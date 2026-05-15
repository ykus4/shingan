"""AND-DBG-004: Debug flags in Android APK.

Checks:
  - AND-DBG-004a: android:debuggable="true" in AndroidManifest.xml
  - AND-DBG-004b: Android logging calls in DEX string table (Log.d, Log.v, System.out.println)
"""

from __future__ import annotations

from shingan.core.context import AndroidCheckContext
from shingan.core.models import Finding, Severity

_DEBUG_LOG_INDICATORS = (
    "Log.d(",
    "Log.v(",
    "Log.i(",
    "System.out.println",
    "System.err.println",
    "e.printStackTrace",
)


def check(ctx: AndroidCheckContext) -> list[Finding]:
    findings: list[Finding] = []

    # AND-DBG-004a: android:debuggable
    apk = ctx.apk
    if apk is not None:
        try:
            debuggable = apk.get_attribute_value("application", "debuggable")
            if str(debuggable).lower() == "true":
                findings.append(
                    Finding(
                        rule_id="AND-DBG-004a",
                        title="android:debuggable=true — app is debuggable in release",
                        severity=Severity.HIGH,
                        description=(
                            'The application manifest sets `android:debuggable="true"`. '
                            "This allows an attacker to attach a debugger via ADB, inspect memory, "
                            "and bypass security controls at runtime."
                        ),
                        evidence="android:debuggable = true",
                        recommendation=(
                            "Remove `android:debuggable` from the manifest or ensure it is set to "
                            "`false`. Release builds should never be debuggable."
                        ),
                        masvs="MASVS-RESILIENCE-2",
                    )
                )
        except Exception:
            pass

    # AND-DBG-004b: debug log calls in DEX strings
    debug_hits = [
        s
        for s in ctx.dex_strings
        if any(indicator in s for indicator in _DEBUG_LOG_INDICATORS)
    ]
    if debug_hits:
        findings.append(
            Finding(
                rule_id="AND-DBG-004b",
                title="Debug logging calls detected in DEX bytecode",
                severity=Severity.LOW,
                description=(
                    f"{len(debug_hits)} debug logging call(s) found in the DEX string table "
                    "(Log.d, Log.v, System.out.println, etc.). These may leak sensitive information "
                    "to logcat in production."
                ),
                evidence="\n".join(sorted(debug_hits)[:10]),
                recommendation=(
                    "Remove or gate debug log calls behind a build flag. "
                    "Use ProGuard/R8 rules to strip logging in release builds."
                ),
                masvs="MASVS-RESILIENCE-2",
            )
        )

    return findings
