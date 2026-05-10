"""Report generation: JSON, SARIF, HTML."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from shingan.core.models import ScanResult, Severity

# SARIF severity mapping
_SARIF_LEVEL = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=indent)


def to_sarif(result: ScanResult) -> str:
    rules = {}
    for f in result.findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id.replace("-", "_"),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {"text": f.recommendation},
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(f.severity, "warning")
                },
            }

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "shingan",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/your-org/shingan",
                        "rules": list(rules.values()),
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "level": _SARIF_LEVEL.get(f.severity, "warning"),
                        "message": {
                            "text": f"{f.title}\n\n{f.description}\n\nEvidence:\n{f.evidence}\n\nRecommendation:\n{f.recommendation}"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": result.ipa_name,
                                        "uriBaseId": "%SRCROOT%",
                                    }
                                }
                            }
                        ],
                    }
                    for f in result.findings
                ],
            }
        ],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)


_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>shingan — {ipa_name}</title>
<style>
  :root {{
    --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3e;
    --text: #e2e8f0; --muted: #718096;
    --high: #fc8181; --medium: #f6ad55; --low: #68d391; --info: #76e4f7;
    --high-bg: #2d1515; --medium-bg: #2d1f0a; --low-bg: #0f2d1a; --info-bg: #0a1f2d;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'SF Mono', 'Fira Code', monospace; font-size: 14px; line-height: 1.6; }}
  header {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 20px 32px; }}
  header h1 {{ font-size: 20px; font-weight: 600; letter-spacing: 0.05em; }}
  header h1 span {{ color: var(--info); }}
  .meta {{ color: var(--muted); font-size: 12px; margin-top: 4px; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 32px; }}
  .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }}
  .summary-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px 20px; text-align: center; }}
  .summary-card .count {{ font-size: 32px; font-weight: 700; }}
  .summary-card .label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); margin-top: 4px; }}
  .high .count {{ color: var(--high); }} .medium .count {{ color: var(--medium); }}
  .low .count {{ color: var(--low); }} .info .count {{ color: var(--info); }}
  .section-title {{ font-size: 13px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted); margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }}
  .finding {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 12px; overflow: hidden; }}
  .finding-header {{ display: flex; align-items: center; gap: 12px; padding: 14px 18px; cursor: pointer; }}
  .finding-header:hover {{ background: rgba(255,255,255,0.03); }}
  .badge {{ font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; padding: 3px 8px; border-radius: 4px; }}
  .badge-high {{ background: var(--high-bg); color: var(--high); border: 1px solid var(--high); }}
  .badge-medium {{ background: var(--medium-bg); color: var(--medium); border: 1px solid var(--medium); }}
  .badge-low {{ background: var(--low-bg); color: var(--low); border: 1px solid var(--low); }}
  .badge-info {{ background: var(--info-bg); color: var(--info); border: 1px solid var(--info); }}
  .rule-id {{ color: var(--muted); font-size: 11px; }}
  .finding-title {{ flex: 1; font-size: 14px; }}
  .finding-body {{ padding: 0 18px 14px; border-top: 1px solid var(--border); display: none; }}
  .finding-body.open {{ display: block; }}
  .finding-body p {{ margin-top: 10px; color: var(--muted); font-family: -apple-system, sans-serif; font-size: 13px; }}
  .evidence {{ background: #0d1117; border: 1px solid var(--border); border-radius: 4px; padding: 12px; margin-top: 10px; font-size: 12px; white-space: pre-wrap; word-break: break-all; color: #a0aec0; max-height: 200px; overflow-y: auto; }}
  .rec {{ background: rgba(118, 228, 247, 0.05); border-left: 3px solid var(--info); padding: 10px 14px; margin-top: 10px; border-radius: 0 4px 4px 0; font-family: -apple-system, sans-serif; font-size: 13px; }}
  .diff-badge {{ font-size: 10px; padding: 2px 6px; border-radius: 4px; margin-left: 6px; }}
  .diff-new {{ background: #1a2d1a; color: #68d391; border: 1px solid #68d391; }}
  .diff-fixed {{ background: #2d1515; color: #fc8181; border: 1px solid #fc8181; text-decoration: line-through; opacity: 0.6; }}
  footer {{ text-align: center; padding: 32px; color: var(--muted); font-size: 11px; border-top: 1px solid var(--border); }}
</style>
</head>
<body>
<header>
  <h1>shin<span>gan</span> — IPA解析耐性チェッカー</h1>
  <div class="meta">{ipa_name} &nbsp;·&nbsp; {app_id} {app_version} ({build}) &nbsp;·&nbsp; {scanned_at}</div>
</header>
<div class="container">
  <div class="summary">
    <div class="summary-card high"><div class="count">{high}</div><div class="label">High</div></div>
    <div class="summary-card medium"><div class="count">{medium}</div><div class="label">Medium</div></div>
    <div class="summary-card low"><div class="count">{low}</div><div class="label">Low</div></div>
    <div class="summary-card info"><div class="count">{info_count}</div><div class="label">Info</div></div>
  </div>
  <div class="section-title">Findings ({total})</div>
  {findings_html}
</div>
<footer>Generated by shingan v0.1.0</footer>
<script>
  document.querySelectorAll('.finding-header').forEach(h => {{
    h.addEventListener('click', () => {{
      h.nextElementSibling.classList.toggle('open');
    }});
  }});
</script>
</body>
</html>
"""

_FINDING_TEMPLATE = """\
<div class="finding">
  <div class="finding-header">
    <span class="badge badge-{severity}">{severity_upper}</span>
    <span class="rule-id">{rule_id}</span>
    <span class="finding-title">{title}</span>
    {diff_badge}
  </div>
  <div class="finding-body">
    <p>{description}</p>
    <div class="evidence">{evidence}</div>
    <div class="rec">Recommendation: {recommendation}</div>
  </div>
</div>
"""


def to_html(result: ScanResult, diff_new: set[str] | None = None, diff_fixed: set[str] | None = None) -> str:
    summary = result.to_dict()["summary"]
    findings_parts = []
    for f in result.findings:
        fp = f.fingerprint()
        diff_badge = ""
        if diff_new and fp in diff_new:
            diff_badge = '<span class="diff-badge diff-new">NEW</span>'
        elif diff_fixed and fp in diff_fixed:
            diff_badge = '<span class="diff-badge diff-fixed">FIXED</span>'

        findings_parts.append(_FINDING_TEMPLATE.format(
            severity=f.severity.value,
            severity_upper=f.severity.value.upper(),
            rule_id=f.rule_id,
            title=f.title,
            description=f.description.replace("<", "&lt;").replace(">", "&gt;"),
            evidence=f.evidence.replace("<", "&lt;").replace(">", "&gt;"),
            recommendation=f.recommendation.replace("<", "&lt;").replace(">", "&gt;"),
            diff_badge=diff_badge,
        ))

    return _HTML_TEMPLATE.format(
        ipa_name=result.ipa_name,
        app_id=result.app_id,
        app_version=result.app_version,
        build=result.build,
        scanned_at=result.scanned_at,
        high=summary["high"],
        medium=summary["medium"],
        low=summary["low"],
        info_count=summary["info"],
        total=summary["total"],
        findings_html="\n".join(findings_parts),
    )


def write_report(
    result: ScanResult,
    output_dir: Path,
    formats: list[Literal["json", "sarif", "html"]] | None = None,
    diff_new: set[str] | None = None,
    diff_fixed: set[str] | None = None,
) -> dict[str, Path]:
    if formats is None:
        formats = ["json", "html"]
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    written = {}
    stem = result.scan_id[:8]
    if "json" in formats:
        p = output_dir / f"{stem}.json"
        p.write_text(to_json(result), encoding="utf-8")
        written["json"] = p
    if "sarif" in formats:
        p = output_dir / f"{stem}.sarif"
        p.write_text(to_sarif(result), encoding="utf-8")
        written["sarif"] = p
    if "html" in formats:
        p = output_dir / f"{stem}.html"
        p.write_text(to_html(result, diff_new=diff_new, diff_fixed=diff_fixed), encoding="utf-8")
        written["html"] = p
    return written
