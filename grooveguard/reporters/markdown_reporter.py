"""Markdown reporter."""

from __future__ import annotations

from grooveguard.scanner import Finding, ScanResult


class MarkdownReporter:
    """Generate Markdown scan reports."""

    @staticmethod
    def generate(result: ScanResult) -> str:
        """Return a Markdown string for the scan result."""
        lines: list[str] = [
            "# GrooveGuard Scan Report",
            "",
            "## Summary",
            "",
            f"- **Files scanned:** {result.files_scanned}",
            f"- **Total findings:** {len(result.findings)}",
            f"- **Critical/High:** {result.has_critical_or_high}",
            f"- **Duration:** {result.duration_ms:.2f} ms",
            "",
            "## Findings",
            "",
        ]

        if not result.findings:
            lines.append("*No findings detected.*")
            return "\n".join(lines)

        for finding in result.findings:
            lines.extend(MarkdownReporter._format_finding(finding))

        return "\n".join(lines)

    @staticmethod
    def _format_finding(finding: Finding) -> list[str]:
        severity_label = {
            "CRITICAL": "[CRITICAL]",
            "HIGH": "[HIGH]",
            "MEDIUM": "[MEDIUM]",
            "LOW": "[LOW]",
            "INFO": "[INFO]",
        }.get(finding.severity, "[UNKNOWN]")

        return [
            f"### {severity_label} {finding.rule_id}: {finding.title}",
            "",
            f"- **Severity:** {finding.severity}",
            f"- **File:** `{finding.file}`",
            f"- **Line:** {finding.line}",
            f"- **Column:** {finding.column}",
            f"- **Message:** {finding.message}",
            "",
            "```python",
            finding.snippet,
            "```",
            "",
            "---",
            "",
        ]
