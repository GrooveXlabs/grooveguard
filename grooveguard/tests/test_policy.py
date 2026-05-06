"""Tests for the policy engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from grooveguard.policy import PolicyCheck, PolicyEngine
from grooveguard.scanner import Finding, ScanResult


def _make_finding(rule_id: str, severity: str, snippet: str = "") -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Test",
        severity=severity,
        message="Test message",
        file=Path("test.py"),
        line=1,
        column=0,
        snippet=snippet,
    )


class TestPolicyEngine:
    def test_available_policies(self) -> None:
        engine = PolicyEngine()
        policies = engine.get_available_policies()
        assert "owasp-llm" in policies
        assert "nist-ai" in policies
        assert "minimal" in policies

    def test_owasp_llm_passes_clean_scan(self) -> None:
        engine = PolicyEngine("owasp-llm")
        result = engine.evaluate(ScanResult())
        assert result.passed is True
        assert result.score == 100
        assert result.findings == []

    def test_owasp_llm_fails_on_missing_validation(self) -> None:
        engine = PolicyEngine("owasp-llm")
        scan = ScanResult(findings=[_make_finding("VAL-001", "HIGH")])
        result = engine.evaluate(scan)
        assert result.passed is False
        assert result.score == 75
        assert any(f.rule_id == "LLM01" for f in result.findings)

    def test_owasp_llm_fails_on_secrets(self) -> None:
        engine = PolicyEngine("owasp-llm")
        scan = ScanResult(findings=[_make_finding("SEC-001", "CRITICAL")])
        result = engine.evaluate(scan)
        assert result.passed is False
        assert result.score == 75
        assert any(f.rule_id == "LLM06" for f in result.findings)

    def test_owasp_llm_fails_on_excessive_agency(self) -> None:
        engine = PolicyEngine("owasp-llm")
        scan = ScanResult(findings=[_make_finding("DNG-003", "HIGH")])
        result = engine.evaluate(scan)
        assert result.passed is False
        # LLM02 and LLM08 both match DNG-003
        assert result.score == 50
        assert any(f.rule_id == "LLM08" for f in result.findings)
        assert any(f.rule_id == "LLM02" for f in result.findings)

    def test_nist_ai_passes_clean_scan(self) -> None:
        engine = PolicyEngine("nist-ai")
        result = engine.evaluate(ScanResult())
        assert result.passed is True
        assert result.score == 100

    def test_nist_ai_fails_on_critical(self) -> None:
        engine = PolicyEngine("nist-ai")
        scan = ScanResult(findings=[_make_finding("SEC-001", "CRITICAL")])
        result = engine.evaluate(scan)
        assert result.passed is False
        # NIST-GOV (CRITICAL), NIST-RISK (CRITICAL/HIGH) and NIST-MON (SEC) all fail
        assert result.score == 0
        assert any(f.rule_id == "NIST-GOV" for f in result.findings)
        assert any(f.rule_id == "NIST-RISK" for f in result.findings)
        assert any(f.rule_id == "NIST-MON" for f in result.findings)

    def test_minimal_fails_on_dangerous_tools(self) -> None:
        engine = PolicyEngine("minimal")
        scan = ScanResult(findings=[_make_finding("DNG-001", "HIGH")])
        result = engine.evaluate(scan)
        assert result.passed is False
        assert result.score == 50
        assert any(f.rule_id == "MIN-DNG" for f in result.findings)

    def test_custom_policy_from_yaml(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "policy.yaml"
        yaml_path.write_text("""
policy:
  name: "Custom No Shell"
  rules:
    - id: NO_SHELL
      title: "No shell execution allowed"
      severity: CRITICAL
      check: "ast"
      pattern: 'os\\.system'
""")
        engine = PolicyEngine()
        engine.load_custom_policy(yaml_path)
        assert "Custom No Shell" in engine.get_available_policies()

        # No matching findings -> pass
        result = engine.evaluate(ScanResult())
        assert result.passed is True

        scan = ScanResult(
            findings=[_make_finding("DNG-001", "CRITICAL", snippet="os.system('ls')")]
        )
        result = engine.evaluate(scan)
        assert result.passed is False
        assert result.score == 0
        assert any(f.rule_id == "NO_SHELL" for f in result.findings)

    def test_custom_policy_require_pattern(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "policy.yaml"
        yaml_path.write_text("""
policy:
  name: "Auth Check"
  rules:
    - id: REQUIRES_AUTH
      title: "All tools must validate auth"
      severity: HIGH
      check: "ast"
      pattern: "def .*tool.*:"
      require_pattern: "validate_auth"
""")
        engine = PolicyEngine()
        engine.load_custom_policy(yaml_path)

        # Match pattern but no required pattern in same file -> fail
        scan = ScanResult(
            findings=[
                Finding(
                    rule_id="MATCH",
                    title="Match",
                    severity="LOW",
                    message="match",
                    file=Path("server.py"),
                    line=1,
                    column=0,
                    snippet="def my_tool():",
                )
            ]
        )
        result = engine.evaluate(scan)
        assert result.passed is False
        assert any(f.rule_id == "REQUIRES_AUTH" for f in result.findings)

        # Now add required pattern finding in same file -> pass
        scan = ScanResult(
            findings=[
                Finding(
                    rule_id="MATCH",
                    title="Match",
                    severity="LOW",
                    message="match",
                    file=Path("server.py"),
                    line=1,
                    column=0,
                    snippet="def my_tool():",
                ),
                Finding(
                    rule_id="AUTH",
                    title="Auth",
                    severity="LOW",
                    message="auth",
                    file=Path("server.py"),
                    line=2,
                    column=0,
                    snippet="validate_auth()",
                ),
            ]
        )
        result = engine.evaluate(scan)
        assert result.passed is True
        assert result.score == 100
