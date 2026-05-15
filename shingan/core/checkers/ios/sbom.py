"""IOS-DEP-011: Third-party SDK / embedded library fingerprinting (SBOM).

Identifies known SDKs from bundle structure, Info.plist keys, and string markers.
Flags SDKs with known vulnerability history.
"""

from __future__ import annotations

from pathlib import Path

from shingan.core.context import CheckContext
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

# SDKs known for aggressive or privacy-relevant data collection (MASVS-PRIVACY-3)
PRIVACY_SDK_SIGNATURES: list[tuple[str, list[str], str]] = [
    (
        "Facebook SDK",
        ["FBSDKCoreKit", "FBSDKLoginKit", "FacebookCore", "com.facebook.sdk"],
        "Collects device identifiers, app events, and user behaviour for ad targeting.",
    ),
    (
        "Mixpanel",
        ["Mixpanel", "MPTweakStore"],
        "Collects user events and device data for analytics.",
    ),
    (
        "Amplitude",
        ["Amplitude", "AMPRevenue"],
        "Collects user behaviour and device information for analytics.",
    ),
    (
        "AppsFlyer",
        ["AppsFlyerLib", "appsflyer"],
        "Collects attribution and device data for mobile marketing analytics.",
    ),
    (
        "Adjust",
        ["Adjust", "ADJConfig"],
        "Collects attribution and in-app event data.",
    ),
    (
        "Branch",
        ["BranchSDK", "Branch.getInstance"],
        "Collects attribution and deep-link data.",
    ),
    (
        "Kochava",
        ["KochavaTracker", "kvTracker"],
        "Collects device and attribution data for ad measurement.",
    ),
    (
        "Google Mobile Ads / AdMob",
        ["GADRequest", "GADBannerView", "GoogleMobileAds"],
        "Collects device and behavioural data for targeted advertising.",
    ),
    (
        "Segment",
        ["SEGAnalytics", "com.segment.analytics"],
        "Collects and forwards user events to multiple downstream analytics providers.",
    ),
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

    # MASVS-PRIVACY-3: data-collection SDKs
    privacy_detected: list[tuple[str, str]] = []
    for sdk_name, indicators, description in PRIVACY_SDK_SIGNATURES:
        if any(ind in t for ind in indicators for t in corpus):
            privacy_detected.append((sdk_name, description))

    if privacy_detected:
        evidence_lines = [f"{name}: {desc}" for name, desc in privacy_detected]
        findings.append(
            Finding(
                rule_id="IOS-DEP-011-privacy",
                title=f"{len(privacy_detected)} data-collection SDK(s) detected",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(privacy_detected)} SDK(s) known for collecting user or device data "
                    "for analytics, advertising, or attribution were detected. "
                    "Each SDK extends the data shared with third parties and may require "
                    "disclosure in your App Privacy label and privacy policy."
                ),
                evidence="\n".join(evidence_lines),
                recommendation=(
                    "Review each SDK's data collection practices and privacy policy. "
                    "Declare collected data types accurately in the App Store Privacy Nutrition Label. "
                    "Obtain user consent before initialising SDKs that process personal data."
                ),
                masvs="MASVS-PRIVACY-3",
            )
        )

    return findings
