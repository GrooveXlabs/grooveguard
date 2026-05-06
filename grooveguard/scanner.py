"""Main scanner engine for GrooveGuard."""

from __future__ import annotations

import ast
import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from grooveguard.utils import calculate_file_hash, has_ignore_comment, normalize_path


@dataclass(frozen=True)
class Finding:
    """A single security finding."""

    rule_id: str
    title: str
    severity: str
    message: str
    file: Path
    line: int
    column: int
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "message": self.message,
            "file": str(self.file),
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
        }


@dataclass
class ScanResult:
    """Aggregated scan results."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    duration_ms: float = 0.0

    @property
    def has_critical_or_high(self) -> bool:
        return any(f.severity in ("CRITICAL", "HIGH") for f in self.findings)


class Rule:
    """Base class for security rules."""

    rule_id: str = "RULE-000"
    title: str = "Base Rule"
    severity: str = "INFO"

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        """Yield findings for the given AST and source lines."""
        yield from ()


class Scanner:
    """Orchestrates scanning of MCP server code."""

    def __init__(self, rules: list[Rule], exclude_patterns: list[str] | None = None):
        self.rules = rules
        self.exclude_patterns = exclude_patterns or ["*/.git/*", "*/__pycache__/*", "*/venv/*"]

    def scan_target(self, target: str | Path) -> ScanResult:
        """Scan a single file or directory.

        Args:
            target: Path to file or directory.

        Returns:
            ScanResult with findings.
        """
        import time

        start = time.perf_counter()
        path = normalize_path(str(target))
        findings: list[Finding] = []
        files_scanned = 0

        if path.is_file():
            findings.extend(self._scan_file(path))
            files_scanned = 1
        elif path.is_dir():
            for py_file in path.rglob("*.py"):
                if self._is_excluded(py_file):
                    continue
                findings.extend(self._scan_file(py_file))
                files_scanned += 1

        duration = (time.perf_counter() - start) * 1000
        return ScanResult(findings=findings, files_scanned=files_scanned, duration_ms=duration)

    def _is_excluded(self, path: Path) -> bool:
        str_path = str(path.as_posix())
        return any(fnmatch.fnmatch(str_path, pat) for pat in self.exclude_patterns)

    def _scan_file(self, path: Path) -> list[Finding]:
        """Scan a single Python file."""
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return []

        lines = source.splitlines()
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []

        findings: list[Finding] = []
        for rule in self.rules:
            for finding in rule.check(tree, lines, path):
                if finding.line > 0 and finding.line <= len(lines):
                    if has_ignore_comment(lines[finding.line - 1], finding.rule_id):
                        continue
                findings.append(finding)
        return findings
