"""AND-DEP-011: Third-party SDK fingerprinting (Android SBOM).

Identifies bundled third-party SDKs via DEX package names and native library names.
"""

from __future__ import annotations

from shingan.core.binary import AndroidCheckContext
from shingan.core.models import Finding, Severity

# (package_prefix_or_lib_name, sdk_label)
_SDK_FINGERPRINTS: list[tuple[str, str]] = [
    # Analytics / Crash reporting
    ("com.google.firebase", "Firebase"),
    ("com.google.android.gms", "Google Play Services"),
    ("io.sentry", "Sentry"),
    ("com.crashlytics", "Crashlytics (Firebase)"),
    ("com.bugsnag", "Bugsnag"),
    ("com.datadog", "Datadog"),
    ("com.newrelic", "New Relic"),
    ("com.appsflyer", "AppsFlyer"),
    ("com.amplitude", "Amplitude"),
    ("com.mixpanel", "Mixpanel"),
    ("com.segment", "Segment"),
    # Advertising
    ("com.google.android.gms.ads", "Google Ads (AdMob)"),
    ("com.facebook.ads", "Facebook Audience Network"),
    ("com.unity3d.ads", "Unity Ads"),
    ("com.mopub", "MoPub"),
    ("com.applovin", "AppLovin"),
    # Networking
    ("com.squareup.okhttp3", "OkHttp"),
    ("retrofit2", "Retrofit"),
    ("com.squareup.retrofit2", "Retrofit"),
    ("com.android.volley", "Volley"),
    # Social / Auth
    ("com.facebook.shimmer", "Facebook SDK"),
    ("com.facebook.login", "Facebook Login"),
    ("com.google.android.gms.auth", "Google Sign-In"),
    ("com.twitter.sdk", "Twitter SDK"),
    # UI / Other
    ("com.airbnb.lottie", "Lottie"),
    ("com.squareup.picasso", "Picasso"),
    ("com.bumptech.glide", "Glide"),
    ("io.coil", "Coil"),
    # Security
    ("com.scottyab.rootbeer", "RootBeer"),
    ("com.datatheorem", "Data Theorem"),
]

# Native library name fragments → SDK
_NATIVE_SDK_FINGERPRINTS: list[tuple[str, str]] = [
    ("libil2cpp", "Unity IL2CPP runtime"),
    ("libunity", "Unity Engine"),
    ("libmono", "Mono/.NET runtime"),
    ("libflutter", "Flutter"),
    ("libswiftCore", "Swift runtime"),
    ("libreactnative", "React Native"),
    ("libhermes", "Hermes JS engine (React Native)"),
    ("libbreakpad", "Breakpad crash reporter"),
    ("libsqlcipher", "SQLCipher (encrypted SQLite)"),
]


def check(ctx: AndroidCheckContext) -> list[Finding]:
    findings: list[Finding] = []
    detected: dict[str, str] = {}

    # Scan DEX strings for known package prefixes
    dex_strings = ctx.dex_strings
    for prefix, label in _SDK_FINGERPRINTS:
        if any(s.startswith(prefix) or prefix in s for s in dex_strings):
            detected[label] = prefix

    # Scan native library names
    for so_path in ctx.native_binaries:
        so_name = so_path.name.lower()
        for fragment, label in _NATIVE_SDK_FINGERPRINTS:
            if fragment.lower() in so_name:
                detected[label] = so_path.name

    if detected:
        evidence_lines = [
            f"{label}  ({ref})" for label, ref in sorted(detected.items())
        ]
        findings.append(
            Finding(
                rule_id="AND-DEP-011",
                title=f"{len(detected)} third-party SDK(s) detected",
                severity=Severity.INFO,
                description=(
                    f"The following {len(detected)} third-party SDK(s) were fingerprinted in the APK. "
                    "Each SDK extends the app's attack surface and data collection footprint."
                ),
                evidence="\n".join(evidence_lines),
                recommendation=(
                    "Review each SDK's data collection and security practices. "
                    "Remove SDKs that are no longer used or that introduce unnecessary risk. "
                    "Keep all SDKs updated to their latest versions."
                ),
                extra={"sdk_count": len(detected)},
                masvs="MASVS-SUPPLY-CHAIN-1",
            )
        )

    return findings
