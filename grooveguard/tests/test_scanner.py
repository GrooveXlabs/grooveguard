"""Tests for the scanner engine."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Iterator

import pytest

from grooveguard.scanner import Finding, Rule, ScanResult, Scanner


class DummyRule(Rule):
    rule_id = "TEST-001"
    title = "Dummy Rule"
    severity = "HIGH"

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for lineno, line in enumerate(source_lines, start=1):
            if "trigger" in line:
                yield Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    message="Triggered",
                    file=path,
                    line=lineno,
                    column=0,
                    snippet=line.strip(),
                )


class TestScanner:
    def test_scan_single_file(self, tmp_path: Path) -> None:
        file = tmp_path / "server.py"
        file.write_text("x = 1\n# trigger\n")
        scanner = Scanner(rules=[DummyRule()])
        result = scanner.scan_target(file)
        assert result.files_scanned == 1
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "TEST-001"

    def test_scan_directory(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("trigger\n")
        (tmp_path / "b.py").write_text("safe\n")
        scanner = Scanner(rules=[DummyRule()], exclude_patterns=[])
        result = scanner.scan_target(tmp_path)
        assert result.files_scanned == 2
        assert len(result.findings) == 1

    def test_exclude_patterns(self, tmp_path: Path) -> None:
        sub = tmp_path / "__pycache__"
        sub.mkdir()
        (sub / "c.py").write_text("trigger\n")
        scanner = Scanner(rules=[DummyRule()])
        result = scanner.scan_target(tmp_path)
        assert result.files_scanned == 0
        assert len(result.findings) == 0

    def test_ignore_comment(self, tmp_path: Path) -> None:
        file = tmp_path / "server.py"
        file.write_text("trigger  # grooveguard: ignore=TEST-001\n")
        scanner = Scanner(rules=[DummyRule()])
        result = scanner.scan_target(file)
        assert len(result.findings) == 0

    def test_has_critical_or_high(self) -> None:
        result = ScanResult()
        assert not result.has_critical_or_high
        result.findings.append(
            Finding("R1", "T", "HIGH", "M", Path("x"), 1, 0)
        )
        assert result.has_critical_or_high

    def test_scan_result_dict(self) -> None:
        f = Finding("R1", "T", "LOW", "M", Path("x.py"), 2, 3, "snip")
        d = f.to_dict()
        assert d["rule_id"] == "R1"
        assert d["line"] == 2
