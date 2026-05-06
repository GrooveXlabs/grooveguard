"""Executive reporter for C-level summaries."""

from __future__ import annotations

from collections import defaultdict

from grooveguard.scanner import Finding, ScanResult


class ExecutiveReporter:
    """Generate a C-level executive summary with risk scoring."""

    _SEVERITY_WEIGHTS = {
        "CRITICAL": 25,
        "HIGH": 10,
        "MEDIUM": 4,
        "LOW": 1,
        "INFO": 0,
    }

    _CATEGORY_RECOMMENDATIONS = {
        "SEC": "Rotate all exposed secrets immediately and move them to a secure vault.",
        "DNG": "Restrict dangerous system capabilities and require explicit approval workflows.",
        "VAL": "Implement strict input validation at every untrusted entry point.",
        "SSRF": "Enforce an allow-list for outbound URLs and validate all user-supplied addresses.",
    }

    @staticmethod
    def generate(result: ScanResult) -> str:
        """Return an executive summary string for the scan result."""
        lines: list[str] = [
            "# Executive Security Summary",
            "",
            "## Risk Overview",
            "",
        ]

        risk_score = ExecutiveReporter._calculate_risk_score(result.findings)
        risk_label = ExecutiveReporter._risk_label(risk_score)

        lines.append(f"**Overall Risk Score:** {risk_score}/100 ({risk_label})")
        lines.append(f"**Files Scanned:** {result.files_scanned}")
        lines.append(f"**Total Findings:** {len(result.findings)}")
        lines.append("")

        # Severity breakdown
        severity_counts = defaultdict(int)
        for f in result.findings:
            severity_counts[f.severity] += 1

        lines.append("## Findings by Severity")
        lines.append("")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = severity_counts.get(sev, 0)
            if count:
                lines.append(f"- **{sev}:** {count}")
        if not severity_counts:
            lines.append("*No findings detected.*")
        lines.append("")

        # Category recommendations
        lines.append("## Strategic Recommendations")
        lines.append("")

        category_findings = defaultdict(list)
        for f in result.findings:
            prefix = f.rule_id.split("-")[0]
            category_findings[prefix].append(f)

        if not category_findings:
            lines.append("*No action items at this time.*")
        else:
            for cat in sorted(category_findings.keys()):
                rec = ExecutiveReporter._CATEGORY_RECOMMENDATIONS.get(
                    cat, "Review findings and apply security best practices."
                )
                lines.append(f"### {cat} ({len(category_findings[cat])} findings)")
                lines.append(rec)
                lines.append("")

        lines.append("---")
        lines.append("*This summary is intended for executive audiences and omits technical detail.*")

        return "\n".join(lines)

    @staticmethod
    def _calculate_risk_score(findings: list[Finding]) -> int:
        """Calculate a 0-100 risk score based on findings."""
        raw_score = sum(
            ExecutiveReporter._SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings
        )
        # Cap at 100
        return min(raw_score, 100)

    @staticmethod
    def _risk_label(score: int) -> str:
        if score >= 75:
            return "CRITICAL RISK"
        if score >= 50:
            return "HIGH RISK"
        if score >= 25:
            return "ELEVATED RISK"
        if score > 0:
            return "MODERATE RISK"
        return "LOW RISK"
