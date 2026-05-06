"""Tests for output reporters."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from grooveguard.scanner import Finding, ScanResult
from grooveguard.reporters.json_reporter import JSONReporter
from grooveguard.reporters.markdown_reporter import MarkdownReporter
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
