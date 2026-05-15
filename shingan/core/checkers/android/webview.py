"""AND-WEB-017: WebView security checks (Android).

Checks for insecure WebView configurations:
  - AND-WEB-017a: setJavaScriptEnabled(true)
  - AND-WEB-017b: addJavascriptInterface (JS bridge exposure)
  - AND-WEB-017c: setAllowFileAccess / setAllowFileAccessFromFileURLs
  - AND-WEB-017d: setAllowUniversalAccessFromFileURLs
"""

from __future__ import annotations

from shingan.core.binary import AndroidCheckContext
from shingan.core.models import Finding, Severity


def check(ctx: AndroidCheckContext) -> list[Finding]:
    findings: list[Finding] = []
    corpus = ctx.dex_strings | ctx.strings

    # AND-WEB-017a: JavaScript enabled
    js_hits = [s for s in corpus if "setJavaScriptEnabled" in s]
    if js_hits:
        findings.append(
            Finding(
                rule_id="AND-WEB-017a",
                title="WebView.setJavaScriptEnabled(true) detected",
                severity=Severity.MEDIUM,
                description=(
                    "JavaScript is enabled in a WebView. If the WebView loads untrusted "
                    "or remote content, this significantly increases the risk of Cross-Site "
                    "Scripting (XSS) attacks that could access sensitive app data or the "
                    "JavaScript bridge."
                ),
                evidence="\n".join(sorted(set(js_hits))[:5]),
                recommendation=(
                    "Disable JavaScript unless strictly required. "
                    "If JavaScript is needed, load only trusted local content "
                    "or enforce a strict Content Security Policy."
                ),
                masvs="MASVS-PLATFORM-2",
            )
        )

    # AND-WEB-017b: JS bridge via addJavascriptInterface
    bridge_hits = [s for s in corpus if "addJavascriptInterface" in s]
    if bridge_hits:
        findings.append(
            Finding(
                rule_id="AND-WEB-017b",
                title="addJavascriptInterface (JS bridge) detected",
                severity=Severity.HIGH,
                description=(
                    "The app exposes a Java object to JavaScript via `addJavascriptInterface`. "
                    "On Android < 4.2 this allows arbitrary code execution. "
                    "On newer versions, only `@JavascriptInterface`-annotated methods are exposed, "
                    "but a compromised WebView can still call any annotated method."
                ),
                evidence="\n".join(sorted(set(bridge_hits))[:5]),
                recommendation=(
                    "Avoid addJavascriptInterface if possible. "
                    "If used, annotate only minimal methods with @JavascriptInterface, "
                    "validate all inputs, and load only trusted content in the WebView."
                ),
                masvs="MASVS-PLATFORM-2",
            )
        )

    # AND-WEB-017c: file access
    file_access_hits = [
        s
        for s in corpus
        if "setAllowFileAccess" in s or "setAllowFileAccessFromFileURLs" in s
    ]
    if file_access_hits:
        findings.append(
            Finding(
                rule_id="AND-WEB-017c",
                title="WebView file access enabled (setAllowFileAccess / setAllowFileAccessFromFileURLs)",
                severity=Severity.HIGH,
                description=(
                    "The WebView is configured to allow access to the local file system. "
                    "Combined with JavaScript, this can allow an attacker to read "
                    "arbitrary files from the app's private storage via a malicious web page."
                ),
                evidence="\n".join(sorted(set(file_access_hits))[:5]),
                recommendation=(
                    "Set `setAllowFileAccess(false)` and `setAllowFileAccessFromFileURLs(false)`. "
                    "These are disabled by default in Android 11+; ensure they are not explicitly enabled."
                ),
                masvs="MASVS-PLATFORM-2",
            )
        )

    # AND-WEB-017d: universal file access
    universal_hits = [s for s in corpus if "setAllowUniversalAccessFromFileURLs" in s]
    if universal_hits:
        findings.append(
            Finding(
                rule_id="AND-WEB-017d",
                title="WebView universal file access enabled (setAllowUniversalAccessFromFileURLs)",
                severity=Severity.HIGH,
                description=(
                    "The WebView allows `file://` pages to make cross-origin requests to any origin. "
                    "This is a severe misconfiguration that can allow exfiltration of arbitrary "
                    "local files to a remote attacker-controlled server."
                ),
                evidence="\n".join(sorted(set(universal_hits))[:5]),
                recommendation="Set `setAllowUniversalAccessFromFileURLs(false)` immediately.",
                masvs="MASVS-PLATFORM-2",
            )
        )

    return findings
