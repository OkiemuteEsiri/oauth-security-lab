from __future__ import annotations

from collections import Counter
from .models import Finding


def render_markdown(findings: list[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    lines = [
        "# OAuth/OIDC Security Assessment",
        "",
        f"Total findings: **{len(findings)}**",
        "",
        f"- Critical: {counts['Critical']}",
        f"- High: {counts['High']}",
        f"- Medium: {counts['Medium']}",
        f"- Low: {counts['Low']}",
        "",
        "## Findings",
        "",
    ]
    for f in findings:
        lines.extend([
            f"### {f.severity} — {f.control} — `{f.client_id}`",
            "",
            f"**Risk score:** {f.risk_score}/100  ",
            f"**Finding ID:** `{f.finding_id}`  ",
            f"**Evidence:** {f.evidence}  ",
            f"**Impact:** {f.impact}  ",
            f"**Remediation:** {f.remediation}  ",
            f"**Validation:** {f.validation}",
        ])
        if f.mitre_attack:
            lines.append(f"**MITRE ATT&CK context:** {', '.join(f.mitre_attack)}")
        lines.append("")
    lines.extend([
        "## Interpretation",
        "",
        "This report evaluates synthetic or exported configuration metadata. ATT&CK mappings provide defensive threat-model context and are not evidence of compromise.",
        "",
    ])
    return "\n".join(lines)
