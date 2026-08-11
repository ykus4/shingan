"""AND-NET-003: Network Security Config checks (Android equivalent of ATS).

Checks:
  - AND-NET-003a: cleartextTrafficPermitted=true (global)
  - AND-NET-003b: User certificates trusted as CA (debug/prod)
  - AND-NET-003c: No certificate pinning configured
  - AND-NET-003d: No network_security_config present (falls back to platform defaults)
"""

from __future__ import annotations

import logging
from pathlib import Path
from xml.etree.ElementTree import Element, ParseError

# network_security_config.xml comes from the APK under analysis, i.e. untrusted
# input. The stdlib ElementTree expands internal entities, so a crafted config
# can trigger exponential entity expansion ("billion laughs"). defusedxml
# refuses DTDs and entity declarations outright.
from defusedxml.ElementTree import parse as safe_xml_parse

from shingan.core.context import AndroidCheckContext
from shingan.core.models import Finding, Severity

logger = logging.getLogger(__name__)

#: Resource reference prefix used by `android:networkSecurityConfig`.
_XML_RES_PREFIX = "@xml/"


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


def _parse_xml(path: Path) -> Element | None:
    """Safely parse an XML resource from the APK, or None if it is unusable."""
    try:
        return safe_xml_parse(path).getroot()
    except (ParseError, OSError, ValueError) as exc:
        # defusedxml raises its own ValueError subclasses (EntitiesForbidden,
        # DTDForbidden) for hostile documents.
        logger.debug("Failed to parse XML resource %s: %s", path, exc)
        return None


def _load_network_security_config(ctx: AndroidCheckContext) -> Element | None:
    """Parse network_security_config.xml from the extracted APK work directory."""
    res_xml_dir = ctx.work_dir / "res" / "xml"

    for path in (
        res_xml_dir / "network_security_config.xml",
        res_xml_dir / "network_security_config.XML",
    ):
        if path.exists():
            return _parse_xml(path)

    # The manifest may point at a config under a different name.
    apk = ctx.apk
    if apk is None:
        return None

    try:
        nsc_ref = apk.get_attribute_value("application", "networkSecurityConfig")
    except Exception as exc:
        logger.debug("Could not read networkSecurityConfig attribute: %s", exc)
        return None

    if not nsc_ref:
        return None

    # str.lstrip() strips *characters*, not a prefix: lstrip("@xml/") turned
    # "@xml/my_config" into "y_config", so configs whose names began with any of
    # @, x, m, l or / were never found.
    res_name = nsc_ref.removeprefix(_XML_RES_PREFIX).removeprefix("@")
    for candidate in sorted(res_xml_dir.glob("*.xml")):
        if candidate.stem == res_name:
            return _parse_xml(candidate)

    logger.debug("Manifest references %s but no matching XML resource found", nsc_ref)
    return None
