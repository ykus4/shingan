"""AND-NET-003: Network Security Config checks (Android equivalent of ATS).

Checks:
  - AND-NET-003a: cleartextTrafficPermitted=true (global)
  - AND-NET-003b: User certificates trusted as CA (debug/prod)
  - AND-NET-003c: No certificate pinning configured
  - AND-NET-003d: No network_security_config present (falls back to platform defaults)
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET

from shingan.core.binary import AndroidCheckContext
from shingan.core.models import Finding, Severity

logger = logging.getLogger(__name__)


def check(ctx: AndroidCheckContext) -> list[Finding]:
    findings: list[Finding] = []

    nsc_xml = _load_network_security_config(ctx)

    if nsc_xml is None:
        # No NSC present — check if manifest references one
        findings.append(
            Finding(
                rule_id="AND-NET-003d",
                title="No network_security_config.xml configured",
                severity=Severity.INFO,
                description=(
                    "The app does not define a `network_security_config` in AndroidManifest.xml. "
                    "It relies on platform defaults, which may allow cleartext traffic on older "
                    "Android versions (API < 28)."
                ),
                evidence="networkSecurityConfig not referenced in AndroidManifest",
                recommendation=(
                    "Add a `network_security_config.xml` to explicitly configure trusted CAs, "
                    "disable cleartext traffic, and optionally configure certificate pinning."
                ),
                masvs="MASVS-NETWORK-1",
            )
        )
        return findings

    # AND-NET-003a: cleartextTrafficPermitted
    root = nsc_xml
    base_config = root.find("base-config")
    if base_config is not None:
        cleartext = base_config.get("cleartextTrafficPermitted", "").lower()
        if cleartext == "true":
            findings.append(
                Finding(
                    rule_id="AND-NET-003a",
                    title="cleartextTrafficPermitted=true in network_security_config",
                    severity=Severity.HIGH,
                    description=(
                        "The base network security config permits cleartext (HTTP) traffic globally. "
                        "This exposes all network communication to interception."
                    ),
                    evidence='<base-config cleartextTrafficPermitted="true">',
                    recommendation=(
                        'Set `cleartextTrafficPermitted="false"` in the base-config. '
                        "Use domain-config exceptions only where absolutely necessary."
                    ),
                    masvs="MASVS-NETWORK-1",
                )
            )

    # AND-NET-003b: user certs trusted
    for trust_anchors in root.iter("trust-anchors"):
        for cert in trust_anchors.findall("certificates"):
            src = cert.get("src", "")
            overrides_pins = cert.get("overridePins", "false").lower()
            if src == "user":
                severity = Severity.MEDIUM
                findings.append(
                    Finding(
                        rule_id="AND-NET-003b",
                        title="User-installed CA certificates are trusted",
                        severity=severity,
                        description=(
                            "The network security config trusts user-installed CA certificates. "
                            "This makes the app vulnerable to MITM attacks by anyone who can "
                            "install a certificate on the device (e.g. corporate proxies, malware)."
                        ),
                        evidence=f'<certificates src="user" overridePins="{overrides_pins}">',
                        recommendation=(
                            'Remove `<certificates src="user">` from the trust-anchors in '
                            "production config. Restrict trusted CAs to the system store or "
                            "specific known CAs."
                        ),
                        masvs="MASVS-NETWORK-1",
                    )
                )

    # AND-NET-003c: no pinning
    pin_sets = list(root.iter("pin-set"))
    if not pin_sets:
        findings.append(
            Finding(
                rule_id="AND-NET-003c",
                title="No certificate pinning configured in network_security_config",
                severity=Severity.LOW,
                description=(
                    "The network security config does not define any `<pin-set>` entries. "
                    "Without pinning, the app trusts any certificate issued by a trusted CA, "
                    "which is vulnerable to rogue CA attacks."
                ),
                evidence="No <pin-set> found in network_security_config.xml",
                recommendation=(
                    "Add `<pin-set>` entries with the SHA-256 SPKI fingerprints of your "
                    "server certificates to enable certificate pinning."
                ),
                masvs="MASVS-NETWORK-2",
            )
        )

    return findings


def _load_network_security_config(ctx: AndroidCheckContext) -> ET.Element | None:
    """Parse network_security_config.xml from the extracted APK work directory."""
    # Try common locations
    candidates = [
        ctx.work_dir / "res" / "xml" / "network_security_config.xml",
        ctx.work_dir / "res" / "xml" / "network_security_config.XML",
    ]
    for path in candidates:
        if path.exists():
            try:
                return ET.parse(path).getroot()
            except ET.ParseError as exc:
                logger.debug("Failed to parse network_security_config.xml: %s", exc)
                return None

    # Also check if manifest references an NSC (the file may have a different name)
    apk = ctx.apk
    if apk is not None:
        try:
            nsc_ref = apk.get_attribute_value("application", "networkSecurityConfig")
            if nsc_ref:
                # nsc_ref is like "@xml/network_security_config"
                res_name = nsc_ref.lstrip("@xml/").lstrip("@")
                for res_dir in (ctx.work_dir / "res" / "xml").glob("*.xml"):
                    if res_dir.stem == res_name:
                        try:
                            return ET.parse(res_dir).getroot()
                        except ET.ParseError:
                            return None
        except Exception:
            pass

    return None
