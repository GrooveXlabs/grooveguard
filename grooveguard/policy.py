"""Organizational security policy engine for GrooveGuard."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from grooveguard.scanner import Finding, ScanResult
from grooveguard.utils import GrooveGuardError, load_yaml_safe


@dataclass
class PolicyCheck:
    """Result of evaluating a scan against a policy."""

    policy_id: str
    policy_name: str
    passed: bool
    score: int  # 0-100
    findings: list[Finding] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass
class _PolicyRule:
    """Internal representation of a single policy rule."""

    id: str
    title: str
    severity: str
    evaluate: Callable[[ScanResult], tuple[bool, list[Finding], str | None]]


@dataclass
class _PolicyDefinition:
    """Internal representation of a policy definition."""

    name: str
    rules: list[_PolicyRule]


def _get_matches(scan_result: ScanResult, rule_ids: set[str]) -> list[Finding]:
    """Return findings whose rule_id is in *rule_ids*."""
    return [f for f in scan_result.findings if f.rule_id in rule_ids]


def _first_file_info(findings: list[Finding]) -> tuple[Path, int, int, str]:
    """Return file/line/col/snippet from the first finding, or safe defaults."""
    if findings:
        f = findings[0]
        return f.file, f.line, f.column, f.snippet
    return Path("."), 0, 0, ""


def _make_builtin_policies() -> dict[str, _PolicyDefinition]:
    """Build the built-in policy definitions."""

    def llm01(scan_result: ScanResult) -> tuple[bool, list[Finding], str | None]:
        matches = _get_matches(scan_result, {"VAL-001"})
        if matches:
            file, line, col, snippet = _first_file_info(matches)
            return False, [
                Finding(
                    rule_id="LLM01",
                    title="Prompt Injection",
                    severity="HIGH",
                    message="Missing input validation on tool parameters detected.",
                    file=file,
                    line=line,
                    column=col,
                    snippet=snippet,
                )
            ], "Add input validation to all tool parameters."
        return True, [], None

    def llm02(scan_result: ScanResult) -> tuple[bool, list[Finding], str | None]:
        matches = _get_matches(scan_result, {"DNG-001", "DNG-002", "DNG-003"})
        if matches:
            file, line, col, snippet = _first_file_info(matches)
            return False, [
                Finding(
                    rule_id="LLM02",
                    title="Insecure Output Handling",
                    severity="HIGH",
                    message="Dangerous operations detected without output sanitization.",
                    file=file,
                    line=line,
                    column=col,
                    snippet=snippet,
                )
            ], "Sanitize outputs before returning them to users or downstream systems."
        return True, [], None

    def llm06(scan_result: ScanResult) -> tuple[bool, list[Finding], str | None]:
        matches = _get_matches(scan_result, {"SEC-001", "SEC-002", "SEC-003"})
        if matches:
            file, line, col, snippet = _first_file_info(matches)
            return False, [
                Finding(
                    rule_id="LLM06",
                    title="Sensitive Information Disclosure",
                    severity="CRITICAL",
                    message="Hardcoded secrets detected in codebase.",
                    file=file,
                    line=line,
                    column=col,
                    snippet=snippet,
                )
            ], "Remove hardcoded secrets and use environment variables or a secret manager."
        return True, [], None

    def llm08(scan_result: ScanResult) -> tuple[bool, list[Finding], str | None]:
        matches = _get_matches(scan_result, {"DNG-001", "DNG-003"})
        if matches:
            file, line, col, snippet = _first_file_info(matches)
            return False, [
                Finding(
                    rule_id="LLM08",
                    title="Excessive Agency",
                    severity="HIGH",
                    message="Overly powerful tools (shell execution, dangerous functions) detected.",
                    file=file,
                    line=line,
                    column=col,
                    snippet=snippet,
                )
            ], "Restrict tool capabilities to the minimum required scope."
        return True, [], None

    def nist_gov(scan_result: ScanResult) -> tuple[bool, list[Finding], str | None]:
        matches = [f for f in scan_result.findings if f.severity == "CRITICAL"]
        if matches:
            file, line, col, snippet = _first_file_info(matches)
            return False, [
                Finding(
                    rule_id="NIST-GOV",
                    title="Governance Documentation",
                    severity="HIGH",
                    message="Critical severity findings indicate missing governance controls.",
                    file=file,
                    line=line,
                    column=col,
                    snippet=snippet,
                )
            ], "Establish governance documentation and security policies."
        return True, [], None

    def nist_risk(scan_result: ScanResult) -> tuple[bool, list[Finding], str | None]:
        matches = [f for f in scan_result.findings if f.severity in ("CRITICAL", "HIGH")]
        if matches:
            file, line, col, snippet = _first_file_info(matches)
            return False, [
                Finding(
                    rule_id="NIST-RISK",
                    title="Risk Assessment",
                    severity="HIGH",
                    message="High or critical findings indicate inadequate risk assessment.",
                    file=file,
                    line=line,
                    column=col,
                    snippet=snippet,
                )
            ], "Perform a thorough risk assessment and document mitigations."
        return True, [], None

    def nist_mon(scan_result: ScanResult) -> tuple[bool, list[Finding], str | None]:
        matches = _get_matches(
            scan_result,
            {"SEC-001", "SEC-002", "SEC-003", "DNG-001", "DNG-002", "DNG-003"},
        )
        if matches:
            file, line, col, snippet = _first_file_info(matches)
            return False, [
                Finding(
                    rule_id="NIST-MON",
                    title="Monitoring and Logging",
                    severity="MEDIUM",
                    message="Secrets or dangerous tools detected, indicating insufficient monitoring.",
                    file=file,
                    line=line,
                    column=col,
                    snippet=snippet,
                )
            ], "Implement comprehensive logging and monitoring for sensitive operations."
        return True, [], None

    def min_sec(scan_result: ScanResult) -> tuple[bool, list[Finding], str | None]:
        matches = _get_matches(scan_result, {"SEC-001", "SEC-002", "SEC-003"})
        if matches:
            file, line, col, snippet = _first_file_info(matches)
            return False, [
                Finding(
                    rule_id="MIN-SEC",
                    title="Secrets Detection",
                    severity="CRITICAL",
                    message="Hardcoded secrets found in code.",
                    file=file,
                    line=line,
                    column=col,
                    snippet=snippet,
                )
            ], "Remove secrets from source code."
        return True, [], None

    def min_dng(scan_result: ScanResult) -> tuple[bool, list[Finding], str | None]:
        matches = _get_matches(scan_result, {"DNG-001", "DNG-002", "DNG-003"})
        if matches:
            file, line, col, snippet = _first_file_info(matches)
            return False, [
                Finding(
                    rule_id="MIN-DNG",
                    title="Dangerous Tools",
                    severity="HIGH",
                    message="Dangerous tool patterns detected.",
                    file=file,
                    line=line,
                    column=col,
                    snippet=snippet,
                )
            ], "Avoid dangerous operations or sandbox them strictly."
        return True, [], None

    return {
        "owasp-llm": _PolicyDefinition(
            name="OWASP Top 10 for LLM Applications",
            rules=[
                _PolicyRule(id="LLM01", title="Prompt Injection", severity="HIGH", evaluate=llm01),
                _PolicyRule(id="LLM02", title="Insecure Output Handling", severity="HIGH", evaluate=llm02),
                _PolicyRule(id="LLM06", title="Sensitive Information Disclosure", severity="CRITICAL", evaluate=llm06),
                _PolicyRule(id="LLM08", title="Excessive Agency", severity="HIGH", evaluate=llm08),
            ],
        ),
        "nist-ai": _PolicyDefinition(
            name="NIST AI Risk Management Framework",
            rules=[
                _PolicyRule(id="NIST-GOV", title="Governance Documentation", severity="HIGH", evaluate=nist_gov),
                _PolicyRule(id="NIST-RISK", title="Risk Assessment", severity="HIGH", evaluate=nist_risk),
                _PolicyRule(id="NIST-MON", title="Monitoring and Logging", severity="MEDIUM", evaluate=nist_mon),
            ],
        ),
        "minimal": _PolicyDefinition(
            name="Minimal Security Baseline",
            rules=[
                _PolicyRule(id="MIN-SEC", title="Secrets Detection", severity="CRITICAL", evaluate=min_sec),
                _PolicyRule(id="MIN-DNG", title="Dangerous Tools", severity="HIGH", evaluate=min_dng),
            ],
        ),
    }


class PolicyEngine:
    """Evaluate scan results against organizational security policies."""

    def __init__(self, policy_name: str = "owasp-llm"):
        self._builtins = _make_builtin_policies()
        self._custom: dict[str, _PolicyDefinition] = {}
        self.policy_name = policy_name

    def load_custom_policy(self, path: Path) -> None:
        """Load a custom policy from a YAML file and activate it."""
        data = load_yaml_safe(path)
        if not isinstance(data, dict):
            raise GrooveGuardError(
                f"Invalid policy YAML: expected mapping at root, got {type(data).__name__}"
            )
        policy_data = data.get("policy", {})
        if not isinstance(policy_data, dict):
            raise GrooveGuardError("Invalid policy YAML: missing 'policy' mapping.")
        name = policy_data.get("name", "custom")
        raw_rules = policy_data.get("rules", [])
        if not isinstance(raw_rules, list):
            raise GrooveGuardError("Invalid policy YAML: 'rules' must be a list.")

        rules: list[_PolicyRule] = []
        for idx, raw in enumerate(raw_rules):
            if not isinstance(raw, dict):
                continue
            rule_id = raw.get("id", f"CUSTOM-{idx:03d}")
            title = raw.get("title", "Custom Rule")
            severity = raw.get("severity", "MEDIUM")
            pattern = raw.get("pattern", "")
            require_pattern = raw.get("require_pattern", "")
            check_type = raw.get("check", "ast")

            if not pattern:
                continue

            compiled = re.compile(pattern)
            req_compiled = re.compile(require_pattern) if require_pattern else None

            def make_eval(
                rid: str = rule_id,
                t: str = title,
                sev: str = severity,
                comp: Any = compiled,
                req: Any = req_compiled,
            ) -> Callable[[ScanResult], tuple[bool, list[Finding], str | None]]:
                def _eval(scan_result: ScanResult) -> tuple[bool, list[Finding], str | None]:
                    matched_findings: list[Finding] = []
                    for finding in scan_result.findings:
                        text = f"{finding.rule_id} {finding.title} {finding.message} {finding.snippet}"
                        if comp.search(text):
                            matched_findings.append(finding)

                    if not matched_findings:
                        return True, [], None

                    if req is None:
                        file, line, col, snippet = _first_file_info(matched_findings)
                        return False, [
                            Finding(
                                rule_id=rid,
                                title=t,
                                severity=sev,
                                message=f"Custom policy violation: {t}",
                                file=file,
                                line=line,
                                column=col,
                                snippet=snippet,
                            )
                        ], f"Address custom rule: {t}"

                    # require_pattern: for each file that has a matched finding,
                    # require a finding in the same file that matches the required pattern.
                    failed_files: list[Path] = []
                    files_with_match = {f.file for f in matched_findings}
                    for file in files_with_match:
                        file_findings = [f for f in scan_result.findings if f.file == file]
                        has_req = any(
                            req.search(f"{f.rule_id} {f.title} {f.message} {f.snippet}")
                            for f in file_findings
                        )
                        if not has_req:
                            failed_files.append(file)

                    if failed_files:
                        first_file = failed_files[0]
                        first_finding = next(f for f in matched_findings if f.file == first_file)
                        return False, [
                            Finding(
                                rule_id=rid,
                                title=t,
                                severity=sev,
                                message=f"Custom policy violation: {t} in {first_file}",
                                file=first_file,
                                line=first_finding.line,
                                column=first_finding.column,
                                snippet=first_finding.snippet,
                            )
                        ], f"Ensure required pattern is present for {t}"
                    return True, [], None

                return _eval

            rules.append(
                _PolicyRule(id=rule_id, title=title, severity=severity, evaluate=make_eval())
            )

        definition = _PolicyDefinition(name=name, rules=rules)
        self._custom[name] = definition
        self.policy_name = name

    def evaluate(self, scan_result: ScanResult) -> PolicyCheck:
        """Evaluate a scan result against the current policy."""
        definition = self._get_policy_definition(self.policy_name)
        if definition is None:
            raise GrooveGuardError(f"Unknown policy: {self.policy_name}")

        total_rules = len(definition.rules)
        passed_rules = 0
        all_findings: list[Finding] = []
        recommendations: list[str] = []

        for rule in definition.rules:
            passed, findings, recommendation = rule.evaluate(scan_result)
            if passed:
                passed_rules += 1
            else:
                all_findings.extend(findings)
                if recommendation:
                    recommendations.append(recommendation)

        score = int((passed_rules / total_rules) * 100) if total_rules > 0 else 100
        passed = score == 100

        return PolicyCheck(
            policy_id=self.policy_name,
            policy_name=definition.name,
            passed=passed,
            score=score,
            findings=all_findings,
            recommendations=recommendations,
        )

    def get_available_policies(self) -> list[str]:
        """Return a list of available policy names."""
        return list(self._builtins.keys()) + list(self._custom.keys())

    def _get_policy_definition(self, name: str) -> _PolicyDefinition | None:
        if name in self._builtins:
            return self._builtins[name]
        return self._custom.get(name)
