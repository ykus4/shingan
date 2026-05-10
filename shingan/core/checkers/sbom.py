"""IOS-DEP-011: Third-party SDK / embedded library fingerprinting (SBOM).

Identifies known SDKs from bundle structure, Info.plist keys, and string markers.
Flags SDKs with known vulnerability history.
"""

from __future__ import annotations

from pathlib import Path

from shingan.core.binary import CheckContext
from shingan.core.models import Finding, Severity

# (sdk_name, indicators, known_issues)
SDK_SIGNATURES: list[tuple[str, list[str], str | None]] = [
    # Analytics / Tracking
    ("Firebase", ["FirebaseCore", "FIRApp", "GoogleUtilities", "nanopb"], None),
    ("Google Analytics", ["GAI", "GoogleAnalytics", "GAIDictionaryBuilder"], None),
    ("Mixpanel", ["Mixpanel", "MPTweakStore"], None),
    ("Amplitude", ["Amplitude", "AMPRevenue"], None),
    # Ads
    ("Google Mobile Ads", ["GADRequest", "GADBannerView", "GoogleMobileAds"], None),
    ("Facebook Audience Network", ["FBAdView", "FBAudienceNetwork"], None),
    # Networking
    ("AFNetworking", ["AFHTTPSessionManager", "AFNetworking"], None),
    ("Alamofire", ["Alamofire", "_TtC9Alamofire"], None),
    # Security
    ("TrustKit", ["TrustKit", "TSKPinningValidator"], None),
    (
        "OpenSSL",
        ["libssl", "SSLeay", "openssl/ssl.h"],
        "May contain outdated OpenSSL version",
    ),
    # Crash reporting
    ("Crashlytics", ["Crashlytics", "CLSCrashReport", "com.crashlytics"], None),
    ("Sentry", ["SentrySDK", "SentryCrash"], None),
    # Payments
    ("Stripe", ["STPAPIClient", "Stripe", "StripeCore"], None),
    ("Braintree", ["BTAPIClient", "Braintree"], None),
    # Dynamic code / hot patch (App Store risk)
    (
        "JSPatch",
        ["JSPatch", "JPEngine"],
        "JSPatch enables remote code execution — violates App Store Review Guidelines 2.5.2",
    ),
    ("React Native", ["RCTBridge", "ReactNative", "react-native"], None),
    ("Cordova/PhoneGap", ["CDVViewController", "Cordova", "phonegap"], None),
]


def _scan_frameworks(app_dir: Path) -> list[str]:
    names: list[str] = []
    fw_dir = app_dir / "Frameworks"
    if fw_dir.exists():
        names.extend(fw.stem for fw in fw_dir.glob("*.framework"))
    plugins_dir = app_dir / "PlugIns"
    if plugins_dir.exists():
        names.extend(fw.stem for fw in plugins_dir.glob("*.appex"))
    return names


def check(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []

    framework_names = _scan_frameworks(ctx.app_dir) if ctx.app_dir else []
    corpus = ctx.strings | set(framework_names)

    detected: list[tuple[str, str | None]] = []
    for sdk_name, indicators, known_issue in SDK_SIGNATURES:
        if any(ind in t for ind in indicators for t in corpus):
            detected.append((sdk_name, known_issue))

    if not detected:
        return findings

    flagged = [(n, i) for n, i in detected if i]
    clean = [n for n, i in detected if not i]

    for sdk_name, issue in flagged:
        findings.append(
            Finding(
                rule_id="IOS-DEP-011",
                title=f"SDK with known issue detected: {sdk_name}",
                severity=Severity.HIGH,
                description=f"{sdk_name} detected. Known issue: {issue}",
                evidence=sdk_name,
                recommendation=(
                    "Review the SDK's current version and known CVEs. "
                    "If using JSPatch or similar dynamic code execution SDKs, "
                    "remove them — they violate App Store policy."
                ),
                masvs="MASVS-SUPPLY-CHAIN-1",
            )
        )

    if clean:
        findings.append(
            Finding(
                rule_id="IOS-DEP-011",
                title=f"Third-party SDKs detected ({len(clean)})",
                severity=Severity.INFO,
                description=(
                    f"{len(clean)} SDK(s) identified: {', '.join(clean)}. "
                    "No known critical issues flagged statically, but verify versions."
                ),
                evidence="\n".join(clean),
                recommendation=(
                    "Keep all dependencies up to date. "
                    "Use `uv audit` or similar tools to track CVEs in dependencies."
                ),
                extra={"sdks": clean},
                masvs="MASVS-SUPPLY-CHAIN-1",
            )
        )

    return findings
