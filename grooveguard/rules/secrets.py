"""Secret detection rules."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterator

from grooveguard.scanner import Finding, Rule


class ApiKeyRule(Rule):
    """Detect hardcoded API keys in string literals and assignments."""

    rule_id = "SEC-001"
    title = "Hardcoded API Key"
    severity = "CRITICAL"

    _PATTERNS = [
        re.compile(r"sk-[a-zA-Z0-9]{20,}", re.IGNORECASE),  # OpenAI-style
        re.compile(r"[a-zA-Z0-9]{32,}-[a-zA-Z0-9]{10,}", re.IGNORECASE),  # Generic
    ]

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                for pat in self._PATTERNS:
                    if pat.search(value):
                        line = getattr(node, "lineno", 1)
                        col = getattr(node, "col_offset", 0)
                        snippet = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                        yield Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            severity=self.severity,
                            message=f"Hardcoded API key detected: {snippet[:60]}...",
                            file=path,
                            line=line,
                            column=col,
                            snippet=snippet,
                        )
                        break


class SecretTokenRule(Rule):
    """Detect hardcoded secret tokens in assignments."""

    rule_id = "SEC-002"
    title = "Hardcoded Secret Token"
    severity = "CRITICAL"

    _KEYWORDS = ["secret", "token", "api_key", "apikey", "auth_token", "access_token"]

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id.lower()
                        if any(kw in name for kw in self._KEYWORDS):
                            if isinstance(node.value, ast.Constant) and isinstance(
                                node.value.value, str
                            ):
                                line = getattr(node, "lineno", 1)
                                col = getattr(node, "col_offset", 0)
                                snippet = (
                                    source_lines[line - 1].strip() if line <= len(source_lines) else ""
                                )
                                yield Finding(
                                    rule_id=self.rule_id,
                                    title=self.title,
                                    severity=self.severity,
                                    message=f"Hardcoded secret assigned to variable '{target.id}'.",
                                    file=path,
                                    line=line,
                                    column=col,
                                    snippet=snippet,
                                )


class HardcodedPasswordRule(Rule):
    """Detect hardcoded passwords."""

    rule_id = "SEC-003"
    title = "Hardcoded Password"
    severity = "HIGH"

    _KEYWORDS = ["password", "passwd", "pwd"]

    def check(self, tree: ast.AST, source_lines: list[str], path: Path) -> Iterator[Finding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id.lower()
                        if any(kw in name for kw in self._KEYWORDS):
                            if isinstance(node.value, ast.Constant) and isinstance(
                                node.value.value, str
                            ):
                                line = getattr(node, "lineno", 1)
                                col = getattr(node, "col_offset", 0)
                                snippet = (
                                    source_lines[line - 1].strip() if line <= len(source_lines) else ""
                                )
                                yield Finding(
                                    rule_id=self.rule_id,
                                    title=self.title,
                                    severity=self.severity,
                                    message=f"Hardcoded password assigned to variable '{target.id}'.",
                                    file=path,
                                    line=line,
                                    column=col,
                                    snippet=snippet,
                                )
