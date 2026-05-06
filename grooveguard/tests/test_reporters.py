"""Tests for output reporters."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from grooveguard.scanner import Finding, ScanResult
from grooveguard.reporters.executive_reporter import ExecutiveReporter
from grooveguard.reporters.json_reporter import JSONReporter
from grooveguard.reporters.markdown_reporter import MarkdownReporter
from grooveguard.reporters.remediation_reporter import RemediationReporter
from grooveguard.reporters.sarif_reporter import SARIFReporter


@pytest.fixture
def sample_result() -> ScanResult:
    return ScanResult(
        findings=[
            Finding(
                rule_id="SEC-001",
                title="Hardcoded API Key",
                severity="CRITICAL",
                message="API key found.",
                file=Path("server.py"),
                line=5,
                column=10,
                snippet="api_key = 'sk-abc'",
            ),
            Finding(
                rule_id="DNG-001",
                title="Shell Command Execution",
                severity="HIGH",
                message="os.system called.",
                file=Path("server.py"),
                line=12,
                column=0,
                snippet="os.system(cmd)",
            ),
        ],
        files_scanned=1,
        duration_ms=42.0,
    )


class TestJSONReporter:
    def test_generate(self, sample_result: ScanResult) -> None:
        output = JSONReporter.generate(sample_result)
        data = json.loads(output)
        assert data["summary"]["total_findings"] == 2
        assert data["summary"]["has_critical_or_high"] is True
        assert len(data["findings"]) == 2


class TestMarkdownReporter:
    def test_generate(self, sample_result: ScanResult) -> None:
        output = MarkdownReporter.generate(sample_result)
        assert "GrooveGuard Scan Report" in output
        assert "SEC-001" in output
        assert "DNG-001" in output
        assert "[CRITICAL]" in output

    def test_empty_findings(self) -> None:
        result = ScanResult(files_scanned=0, duration_ms=0.0)
        output = MarkdownReporter.generate(result)
        assert "No findings detected" in output


class TestSARIFReporter:
    def test_generate(self, sample_result: ScanResult) -> None:
        output = SARIFReporter.generate(sample_result)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        run = data["runs"][0]
        assert len(run["results"]) == 2
        assert len(run["tool"]["driver"]["rules"]) == 2

    def test_severity_mapping(self) -> None:
        assert SARIFReporter._severity_to_level("CRITICAL") == "error"
        assert SARIFReporter._severity_to_level("HIGH") == "error"
        assert SARIFReporter._severity_to_level("MEDIUM") == "warning"
        assert SARIFReporter._severity_to_level("LOW") == "note"
        assert SARIFReporter._severity_to_level("INFO") == "note"


class TestExecutiveReporter:
    def test_generate(self, sample_result: ScanResult) -> None:
        output = ExecutiveReporter.generate(sample_result)
        assert "Executive Security Summary" in output
        assert "Risk Score:" in output
        assert "ELEVATED RISK" in output
        assert "SEC" in output
        assert "DNG" in output
        assert "Strategic Recommendations" in output

    def test_risk_score_calculation(self) -> None:
        result = ScanResult(findings=[], files_scanned=0, duration_ms=0.0)
        assert ExecutiveReporter._calculate_risk_score(result.findings) == 0
        assert ExecutiveReporter._risk_label(0) == "LOW RISK"

        findings = [
            Finding("SEC-001", "T", "CRITICAL", "M", Path("x"), 1, 0),
            Finding("SEC-002", "T", "HIGH", "M", Path("x"), 2, 0),
        ]
        score = ExecutiveReporter._calculate_risk_score(findings)
        assert score == 35
        assert ExecutiveReporter._risk_label(score) == "ELEVATED RISK"

    def test_empty_findings(self) -> None:
        result = ScanResult(files_scanned=0, duration_ms=0.0)
        output = ExecutiveReporter.generate(result)
        assert "No findings detected" in output
        assert "No action items at this time" in output


class TestRemediationReporter:
    def test_generate(self, sample_result: ScanResult) -> None:
        output = RemediationReporter.generate(sample_result)
        assert "Remediation Guide" in output
        assert "SEC-001" in output
        assert "DNG-001" in output
        assert "Estimated Effort" in output
        assert "Before" in output
        assert "After" in output

    def test_empty_findings(self) -> None:
        result = ScanResult(files_scanned=0, duration_ms=0.0)
        output = RemediationReporter.generate(result)
        assert "No findings require remediation" in output

    def test_prioritization(self) -> None:
        findings = [
            Finding("DNG-001", "T", "MEDIUM", "M", Path("x"), 1, 0),
            Finding("SEC-001", "T", "CRITICAL", "M", Path("x"), 2, 0),
        ]
        result = ScanResult(findings=findings, files_scanned=1, duration_ms=1.0)
        output = RemediationReporter.generate(result)
        # CRITICAL should appear before MEDIUM
        assert output.index("SEC-001") < output.index("DNG-001")
