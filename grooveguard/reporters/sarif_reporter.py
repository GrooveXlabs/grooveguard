"""Enhanced SARIF reporter for CI/CD integration."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from grooveguard.scanner import ScanResult


class SARIFReporter:
    """Generate SARIF 2.1.0 scan reports with CWE taxonomy and fingerprints."""

    @staticmethod
    def generate(result: ScanResult) -> str:
        """Return a SARIF JSON string for the scan result."""
        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        rule_ids: set[str] = set()

        for finding in result.findings:
            if finding.rule_id not in rule_ids:
                rule_obj: dict[str, Any] = {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "defaultConfiguration": {
                        "level": SARIFReporter._severity_to_level(finding.severity),
                    },
                }
                if finding.cwe_id:
                    rule_obj["relationships"] = [
                        {
                            "target": {
                                "id": finding.cwe_id,
                                "index": 0,
                            },
                            "kinds": ["relevant"],
                        }
                    ]
                if finding.remediation:
                    rule_obj["help"] = {
                        "text": finding.remediation,
                    }
                rules.append(rule_obj)
                rule_ids.add(finding.rule_id)

            result_obj: dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": SARIFReporter._severity_to_level(finding.severity),
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
                "partialFingerprints": {
                    "primaryLocationLineHash": finding.fingerprint,
                },
            }

            if finding.cwe_id:
                result_obj["taxa"] = [
                    {
                        "id": finding.cwe_id,
                        "name": finding.cwe_name,
                    }
                ]

            if finding.git_author:
                result_obj["properties"] = {
                    "gitAuthor": finding.git_author,
                    "gitDate": finding.git_date,
                }

            results.append(result_obj)

        # Taxonomy for CWE
        taxonomies = []
        if any(f.cwe_id for f in result.findings):
            taxa = []
            seen_cwe: set[str] = set()
            for f in result.findings:
                if f.cwe_id and f.cwe_id not in seen_cwe:
                    taxa.append({
                        "id": f.cwe_id,
                        "name": f.cwe_name,
                        "shortDescription": {"text": f.cwe_name},
                    })
                    seen_cwe.add(f.cwe_id)
            taxonomies.append({
                "name": "CWE",
                "version": "4.12",
                "informationUri": "https://cwe.mitre.org/",
                "taxa": taxa,
            })

        sarif: dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "GrooveGuard",
                            "informationalUri": "https://github.com/GrooveXlabs/grooveguard",
                            "version": "1.0.0",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "taxonomies": taxonomies,
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
            "INFO": "none",
        }
        return mapping.get(severity, "warning")
