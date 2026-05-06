"""SARIF reporter for CI/CD integration."""

from __future__ import annotations

import json
from typing import Any

from grooveguard.scanner import ScanResult


class SARIFReporter:
    """Generate SARIF 2.1.0 scan reports."""

    @staticmethod
    def generate(result: ScanResult) -> str:
        """Return a SARIF JSON string for the scan result."""
        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        rule_ids: set[str] = set()

        for finding in result.findings:
            if finding.rule_id not in rule_ids:
                rules.append({
                    "id": finding.rule_id,
                    "name": finding.title,
                    "defaultConfiguration": {
                        "level": SARIFReporter._severity_to_level(finding.severity),
                    },
                })
                rule_ids.add(finding.rule_id)

            results.append({
                "ruleId": finding.rule_id,
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(finding.file)},
                            "region": {
                                "startLine": finding.line,
                                "startColumn": finding.column,
                                "snippet": {"text": finding.snippet},
                            },
                        }
                    }
                ],
            })

        sarif: dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "GrooveGuard",
                            "informationalUri": "https://github.com/example/grooveguard",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif, indent=2)

    @staticmethod
    def _severity_to_level(severity: str) -> str:
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }
        return mapping.get(severity, "warning")
