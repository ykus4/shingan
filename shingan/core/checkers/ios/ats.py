"""IOS-ATS-003: App Transport Security and Info.plist configuration checks."""

from __future__ import annotations

from shingan.core.constants import (
    LSA_SCHEMES_EVIDENCE_SAMPLE,
    LSA_SCHEMES_THRESHOLD,
)
from shingan.core.context import CheckContext
from shingan.core.models import Finding, Severity


def check(ctx: CheckContext) -> list[Finding]:
    """Uniform checker entry point — see :func:`check_plist` for the logic."""
    return check_plist(ctx.info_plist)


def check_plist(info_plist: dict) -> list[Finding]:
    findings: list[Finding] = []

    ats = info_plist.get("NSAppTransportSecurity", {})

    # --- 1. Global ATS bypass ---
    if ats.get("NSAllowsArbitraryLoads") is True:
        findings.append(
            Finding(
                rule_id="IOS-ATS-003a",
                title="NSAllowsArbitraryLoads is enabled (ATS fully disabled)",
                severity=Severity.HIGH,
                description=(
                    "NSAllowsArbitraryLoads=YES disables App Transport Security globally, "
                    "allowing plain HTTP connections to any host. This exposes all network "
                    "traffic to interception."
                ),
                evidence="NSAppTransportSecurity.NSAllowsArbitraryLoads = true",
                recommendation=(
                    "Remove NSAllowsArbitraryLoads and use HTTPS for all endpoints. "
                    "If a specific host requires HTTP, use NSExceptionDomains with the "
                    "narrowest possible exception."
                ),
                masvs="MASVS-NETWORK-1",
            )
        )

    # --- 2. Arbitrary loads for media / web content ---
    if ats.get("NSAllowsArbitraryLoadsForMedia") is True:
        findings.append(
            Finding(
                rule_id="IOS-ATS-003b",
                title="NSAllowsArbitraryLoadsForMedia is enabled",
                severity=Severity.MEDIUM,
                description="Media content can be loaded over plain HTTP.",
                evidence="NSAppTransportSecurity.NSAllowsArbitraryLoadsForMedia = true",
                recommendation="Ensure media assets are served over HTTPS.",
                masvs="MASVS-NETWORK-1",
            )
        )

    if ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
        findings.append(
            Finding(
                rule_id="IOS-ATS-003c",
                title="NSAllowsArbitraryLoadsInWebContent is enabled",
                severity=Severity.MEDIUM,
                description="WKWebView and SFSafariViewController can load plain HTTP content.",
                evidence="NSAppTransportSecurity.NSAllowsArbitraryLoadsInWebContent = true",
                recommendation="Remove this exception and serve all web content over HTTPS.",
                masvs="MASVS-NETWORK-1",
            )
        )

    # --- 3. Local networking ---
    if ats.get("NSAllowsLocalNetworking") is True:
        findings.append(
            Finding(
                rule_id="IOS-ATS-003d",
                title="NSAllowsLocalNetworking is enabled",
                severity=Severity.LOW,
                description="Plain HTTP connections to .local domains and link-local addresses are allowed.",
                evidence="NSAppTransportSecurity.NSAllowsLocalNetworking = true",
                recommendation="Acceptable for local device discovery, but verify this is intentional.",
                masvs="MASVS-NETWORK-1",
            )
        )

    # --- 4. Per-domain exceptions ---
    exceptions = ats.get("NSExceptionDomains", {})
    for domain, config in exceptions.items():
        if config.get("NSExceptionAllowsInsecureHTTPLoads") is True:
            findings.append(
                Finding(
                    rule_id="IOS-ATS-003e",
                    title=f"Plain HTTP allowed for domain: {domain}",
                    severity=Severity.MEDIUM,
                    description=f"NSExceptionAllowsInsecureHTTPLoads is set for '{domain}'.",
                    evidence=f"NSExceptionDomains.{domain}.NSExceptionAllowsInsecureHTTPLoads = true",
                    recommendation=f"Migrate '{domain}' to HTTPS and remove this exception.",
                    masvs="MASVS-NETWORK-1",
                )
            )
        if config.get("NSExceptionMinimumTLSVersion") in ("TLSv1.0", "TLSv1.1"):
            ver = config["NSExceptionMinimumTLSVersion"]
            findings.append(
                Finding(
                    rule_id="IOS-ATS-003f",
                    title=f"Weak TLS version allowed for domain: {domain}",
                    severity=Severity.MEDIUM,
                    description=f"Minimum TLS version is set to {ver} for '{domain}'.",
                    evidence=f"NSExceptionDomains.{domain}.NSExceptionMinimumTLSVersion = {ver}",
                    recommendation=f"Require TLSv1.2 or higher for '{domain}'.",
                    masvs="MASVS-NETWORK-1",
                )
            )

    # --- 5. UIFileSharingEnabled ---
    if info_plist.get("UIFileSharingEnabled") is True:
        findings.append(
            Finding(
                rule_id="IOS-ATS-003g",
                title="UIFileSharingEnabled is active (iTunes file sharing)",
                severity=Severity.LOW,
                description=(
                    "iTunes/Files file sharing is enabled. App documents are accessible "
                    "without authentication via a connected computer."
                ),
                evidence="UIFileSharingEnabled = true",
                recommendation="Disable unless your app explicitly requires file sharing.",
                masvs="MASVS-NETWORK-1",
            )
        )

    # --- 6. LSApplicationQueriesSchemes (URL scheme enumeration) ---
    schemes = info_plist.get("LSApplicationQueriesSchemes", [])
    if len(schemes) > LSA_SCHEMES_THRESHOLD:
        findings.append(
            Finding(
                rule_id="IOS-ATS-003h",
                title=f"Large LSApplicationQueriesSchemes list ({len(schemes)} schemes)",
                severity=Severity.INFO,
                description=(
                    "A large number of queried URL schemes may expose information about "
                    "installed apps and could be used for fingerprinting."
                ),
                evidence=", ".join(schemes[:LSA_SCHEMES_EVIDENCE_SAMPLE]),
                recommendation="Remove schemes that are not actively used by the app.",
                masvs="MASVS-NETWORK-1",
            )
        )

    return findings
