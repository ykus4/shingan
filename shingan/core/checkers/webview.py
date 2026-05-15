"""IOS-WEB-017: WebView security checks (iOS).

Checks for insecure WebView configurations:
  - IOS-WEB-017a: WKWebView with JavaScript enabled + sensitive API access
  - IOS-WEB-017b: UIWebView usage (deprecated, insecure)
  - IOS-WEB-017c: file:// access in WKWebView (allowFileAccessFromFileURLs)
  - IOS-WEB-017d: Universal links / URL scheme handling without validation
"""

from __future__ import annotations

from shingan.core.binary import CheckContext
from shingan.core.models import Finding, Severity

# Indicators of UIWebView (deprecated since iOS 12, insecure)
_UIWEBVIEW_INDICATORS = (
    "UIWebView",
    "UIWebViewDelegate",
    "webViewDidFinishLoad",
    "stringByEvaluatingJavaScriptFromString",
)

# Indicators of insecure WKWebView configurations
_INSECURE_WKWEBVIEW = (
    "allowFileAccessFromFileURLs",
    "allowUniversalAccessFromFileURLs",
    "WKUserContentController",  # JS bridge (informational — not inherently insecure)
)

# Native↔JS bridge indicators that warrant review
_JS_BRIDGE_INDICATORS = (
    "WKScriptMessageHandler",
    "addScriptMessageHandler",
    "evaluateJavaScript",
    "postMessage",
)


def check(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    corpus = ctx.all_text

    # IOS-WEB-017a: UIWebView usage
    uiwebview_hits = [
        s for s in corpus if any(ind in s for ind in _UIWEBVIEW_INDICATORS)
    ]
    if uiwebview_hits:
        findings.append(
            Finding(
                rule_id="IOS-WEB-017a",
                title="UIWebView usage detected (deprecated and insecure)",
                severity=Severity.HIGH,
                description=(
                    "UIWebView is deprecated since iOS 12 and removed from the App Store "
                    "review process as of April 2020. It lacks the security improvements "
                    "of WKWebView including process isolation and Content Security Policy support."
                ),
                evidence="\n".join(sorted(set(uiwebview_hits))[:5]),
                recommendation=(
                    "Replace all UIWebView usage with WKWebView. "
                    "UIWebView submissions are rejected by the App Store."
                ),
                masvs="MASVS-PLATFORM-2",
            )
        )

    # IOS-WEB-017b: insecure WKWebView configuration
    wkwebview_hits = [s for s in corpus if any(ind in s for ind in _INSECURE_WKWEBVIEW)]
    if wkwebview_hits:
        findings.append(
            Finding(
                rule_id="IOS-WEB-017b",
                title="Potentially insecure WKWebView configuration detected",
                severity=Severity.MEDIUM,
                description=(
                    "WKWebView configuration strings associated with file access or "
                    "cross-origin relaxation were found. "
                    "`allowFileAccessFromFileURLs` and `allowUniversalAccessFromFileURLs` "
                    "can enable path traversal and data exfiltration from local files."
                ),
                evidence="\n".join(sorted(set(wkwebview_hits))[:5]),
                recommendation=(
                    "Do not enable `allowFileAccessFromFileURLs` or "
                    "`allowUniversalAccessFromFileURLs` unless strictly necessary. "
                    "Validate all URLs loaded in WKWebView against an allowlist."
                ),
                masvs="MASVS-PLATFORM-2",
            )
        )

    # IOS-WEB-017c: JS bridge usage
    bridge_hits = [s for s in corpus if any(ind in s for ind in _JS_BRIDGE_INDICATORS)]
    if bridge_hits:
        findings.append(
            Finding(
                rule_id="IOS-WEB-017c",
                title="Native↔JavaScript bridge (WKScriptMessageHandler) detected",
                severity=Severity.LOW,
                description=(
                    "The app exposes a native↔JavaScript bridge via WKScriptMessageHandler "
                    "or evaluateJavaScript. If the WebView loads untrusted content, "
                    "this bridge can be abused to call native code from injected scripts."
                ),
                evidence="\n".join(sorted(set(bridge_hits))[:5]),
                recommendation=(
                    "Validate the origin of all messages received via the JS bridge. "
                    "Load only trusted, local HTML content or enforce a strict Content Security Policy. "
                    "Never expose sensitive native APIs through the bridge."
                ),
                masvs="MASVS-PLATFORM-2",
            )
        )

    return findings
