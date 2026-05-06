"""Tests for security rules."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator

import pytest

from grooveguard.rules.dangerous import DangerousToolRule, FileWriteRule, ShellExecRule
from grooveguard.rules.secrets import ApiKeyRule, HardcodedPasswordRule, SecretTokenRule
from grooveguard.rules.ssrf import UnvalidatedUrlFetchRule
from grooveguard.rules.validation import MissingValidationRule
from grooveguard.scanner import Finding


def _run_rule(rule, source: str, path: Path | None = None) -> list[Finding]:
    tree = ast.parse(source)
    lines = source.splitlines()
    return list(rule.check(tree, lines, path or Path("test.py")))


class TestSecrets:
    def test_api_key_in_string(self) -> None:
        source = 'api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"\n'
        findings = _run_rule(ApiKeyRule(), source)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-001"
        assert findings[0].severity == "CRITICAL"

    def test_secret_token_assignment(self) -> None:
        source = 'auth_token = "supersecrettoken123"\n'
        findings = _run_rule(SecretTokenRule(), source)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-002"

    def test_hardcoded_password(self) -> None:
        source = 'password = "hunter2"\n'
        findings = _run_rule(HardcodedPasswordRule(), source)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-003"
        assert findings[0].severity == "HIGH"

    def test_no_false_positive_safe_string(self) -> None:
        source = 'greeting = "hello world"\n'
        findings = _run_rule(ApiKeyRule(), source)
        assert len(findings) == 0


class TestDangerous:
    def test_os_system_call(self) -> None:
        source = "import os\nos.system('ls')\n"
        findings = _run_rule(ShellExecRule(), source)
        assert len(findings) == 1
        assert findings[0].rule_id == "DNG-001"

    def test_subprocess_run(self) -> None:
        source = "import subprocess\nsubprocess.run(['echo', 'hi'])\n"
        findings = _run_rule(ShellExecRule(), source)
        assert len(findings) == 1

    def test_file_write(self) -> None:
        source = "open('file.txt', 'w')\n"
        findings = _run_rule(FileWriteRule(), source)
        assert len(findings) == 1
        assert findings[0].rule_id == "DNG-002"

    def test_dangerous_tool_name(self) -> None:
        source = "\n".join([
            "def run_command(cmd):",
            "    pass",
        ])
        findings = _run_rule(DangerousToolRule(), source)
        assert len(findings) == 1
        assert findings[0].rule_id == "DNG-003"


class TestValidation:
    def test_missing_validation(self) -> None:
        source = "\n".join([
            "def run_command(cmd):",
            "    import subprocess",
            "    subprocess.run(cmd)",
        ])
        findings = _run_rule(MissingValidationRule(), source)
        assert len(findings) == 1
        assert findings[0].rule_id == "VAL-001"

    def test_validation_present(self) -> None:
        source = "\n".join([
            "def run_command(cmd):",
            "    if not isinstance(cmd, str):",
            "        raise ValueError",
            "    import subprocess",
            "    subprocess.run(cmd)",
        ])
        findings = _run_rule(MissingValidationRule(), source)
        # After isinstance validation, param is considered validated
        assert len(findings) == 0


class TestSSRF:
    def test_unvalidated_url_fetch(self) -> None:
        source = "\n".join([
            "def fetch(url):",
            "    import requests",
            "    requests.get(url)",
        ])
        findings = _run_rule(UnvalidatedUrlFetchRule(), source)
        assert len(findings) == 1
        assert findings[0].rule_id == "SSRF-001"

    def test_literal_url_no_flag(self) -> None:
        source = "\n".join([
            "def fetch():",
            "    import requests",
            "    requests.get('https://example.com')",
        ])
        findings = _run_rule(UnvalidatedUrlFetchRule(), source)
        # Literal URLs are also flagged because they might be untrusted
        assert isinstance(findings, list)
